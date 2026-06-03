//! Mock 256-bit integer precompile for exercising value, op, and predicate nodes.
//!
//! Values are little-endian u32 limbs and arithmetic wraps mod `2^256`. The fixture also
//! contributes common constants through [`Precompile::init`] so registry bootstrapping is covered.

use alloc::{vec, vec::Vec};
use core::num::NonZeroU32;

use crate::{
    Felt, ZERO,
    deferred::{
        DataChunk, DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag, precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the mock uint precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Uint;

impl Uint {
    /// Stable precompile name used to derive the tag id.
    pub const NAME: &'static str = "uint256";

    /// Tag discriminants owned by this fixture.
    pub const VALUE_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const MUL_TAG_ID: u32 = 3;
    pub const EQ_TAG_ID: u32 = 4;

    /// Stable precompile id derived from the fixture name.
    pub fn id() -> Felt {
        precompile_id(&Uint)
    }

    /// Tag for a canonical uint value (`Data(1)`).
    pub fn value_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::VALUE_TAG_ID), ZERO, ZERO])
    }
    /// Tag for a wrapping-add op node.
    pub fn add_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO])
    }
    /// Tag for a wrapping-sub op node.
    pub fn sub_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO])
    }
    /// Tag for a wrapping-mul op node.
    pub fn mul_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO])
    }
    /// Tag for a uint equality predicate.
    pub fn eq_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO])
    }

    fn tag(args: [Felt; 3]) -> Tag {
        Tag::new(Self::id(), args).expect("uint precompile id is not framework-reserved")
    }

    /// Builds a canonical uint value from little-endian limbs.
    pub fn value_node(limbs: [u32; 8]) -> Node {
        Node::value(Self::value_tag(), limbs.map(Felt::from_u32))
            .expect("value tag is precompile-owned")
    }

    /// Extracts canonical little-endian limbs from a uint value.
    pub fn value_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        if node.tag() != Self::value_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        decode_limbs(node.payload().as_value()?)
    }

    /// Adds two little-endian uints modulo `2^256` for fixtures that share uint semantics.
    pub fn wrap_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        let mut carry: u64 = 0;
        for i in 0..8 {
            let s = a[i] as u64 + b[i] as u64 + carry;
            out[i] = s as u32;
            carry = s >> 32;
        }
        out
    }

    /// Subtracts two little-endian uints modulo `2^256`.
    pub fn wrap_sub(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        let mut borrow: i64 = 0;
        for i in 0..8 {
            let diff = a[i] as i64 - b[i] as i64 - borrow;
            out[i] = diff as u32;
            borrow = (diff >> 32) & 1;
        }
        out
    }

    /// Multiplies two little-endian uints modulo `2^256`.
    pub fn wrap_mul(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        for i in 0..8 {
            let mut carry: u64 = 0;
            for j in 0..(8 - i) {
                let cur = out[i + j] as u64 + a[i] as u64 * b[j] as u64 + carry;
                out[i + j] = cur as u32;
                carry = cur >> 32;
            }
        }
        out
    }
}

impl Precompile for Uint {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn init(&self) -> Vec<Node> {
        // ZERO, ONE, P_MINUS_1 — useful baseline constants.
        let mut one = [0u32; 8];
        one[0] = 1;
        vec![Self::value_node([0; 8]), Self::value_node(one), Self::value_node([u32::MAX; 8])]
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        // A value is `Data(1)` (8 raw u32 limbs); op-nodes and the eq predicate are `Join` over two
        // child digests.
        Some(match Discriminant::classify(args[0])? {
            Discriminant::Value => NodeType::Data(NonZeroU32::MIN),
            Discriminant::BinaryOp(_) | Discriminant::Eq => NodeType::Join,
        })
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        match UintNode::parse(args, payload)? {
            // Value canonicality is validated at evaluation-time, so a malformed value only errors
            // when used.
            UintNode::Value => Ok(Node::value(Self::tag(args), *payload.as_value()?)?),
            UintNode::BinaryOp { op, lhs, rhs } => {
                let a = value_limbs(&context.resolve(lhs)?)?;
                let b = value_limbs(&context.resolve(rhs)?)?;
                Ok(Self::value_node(op.apply(a, b)))
            },
            UintNode::Eq { lhs, rhs } => {
                if context.resolve(lhs)? != context.resolve(rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(Node::TRUE)
            },
        }
    }
}

// TYPED TAG / NODE
// ================================================================================================

/// Recognized local uint operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Value,
    BinaryOp(BinaryOp),
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Value),
            1 => Some(Self::BinaryOp(BinaryOp::Add)),
            2 => Some(Self::BinaryOp(BinaryOp::Sub)),
            3 => Some(Self::BinaryOp(BinaryOp::Mul)),
            4 => Some(Self::Eq),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinaryOp {
    Add,
    Sub,
    Mul,
}

impl BinaryOp {
    fn apply(self, a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        match self {
            Self::Add => Uint::wrap_add(a, b),
            Self::Sub => Uint::wrap_sub(a, b),
            Self::Mul => Uint::wrap_mul(a, b),
        }
    }
}

/// Parsed uint node ready for evaluation.
enum UintNode {
    Value,
    BinaryOp { op: BinaryOp, lhs: Digest, rhs: Digest },
    Eq { lhs: Digest, rhs: Digest },
}

impl UintNode {
    /// Parses a uint-owned tag and payload into the operation it represents.
    fn parse(args: [Felt; 3], payload: &Payload) -> Result<Self, PrecompileError> {
        let kind = Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)?;
        Ok(match kind {
            Discriminant::Value => {
                decode_limbs(payload.as_value()?)?;
                Self::Value
            },
            Discriminant::BinaryOp(op) => {
                let (lhs, rhs) = payload.as_join()?;
                Self::BinaryOp { op, lhs, rhs }
            },
            Discriminant::Eq => {
                let (lhs, rhs) = payload.as_join()?;
                Self::Eq { lhs, rhs }
            },
        })
    }
}

// HELPERS
// ================================================================================================

fn value_limbs(node: &Node) -> Result<[u32; 8], DeferredError> {
    if node.tag() != Uint::value_tag() {
        return Err(DeferredError::InvalidPayload);
    }
    decode_limbs(node.payload().as_value()?)
}

fn decode_limbs(felts: &DataChunk) -> Result<[u32; 8], DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in felts.iter().enumerate() {
        let v = felt.as_canonical_u64();
        if v > u32::MAX as u64 {
            return Err(DeferredError::InvalidPayload);
        }
        limbs[i] = v as u32;
    }
    Ok(limbs)
}
