//! `Uint` — 256-bit wrapping integer arithmetic as a first reference precompile.
//!
//! Semantics: operations are mod 2^256, limbs are u32 little-endian. Tags route through
//! [`PrecompileRegistry`] by id; a `sub` op joins `add`/`mul`, and the precompile pre-registers
//! `ZERO` / `ONE` / `P_MINUS_1` (`[u32::MAX; 8]`) leaves via [`Precompile::init`].
//!
//! [`PrecompileRegistry`]: miden_core::deferred::PrecompileRegistry

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredError, Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag,
        WitnessBuilder, precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `Uint` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Uint;

impl Uint {
    /// Precompile name — hashed into the id. Renaming breaks the schema for existing programs.
    pub const NAME: &'static str = "uint256";

    /// Discriminant indices.
    pub const LEAF_TAG_ID: u32 = 0;
    pub const ADD_TAG_ID: u32 = 1;
    pub const SUB_TAG_ID: u32 = 2;
    pub const MUL_TAG_ID: u32 = 3;
    pub const EQ_TAG_ID: u32 = 4;

    /// Derive the precompile id. Pure function over `Uint`'s metadata.
    pub fn id() -> Felt {
        precompile_id(&Uint)
    }

    /// Tag for a canonical Uint leaf.
    pub fn leaf_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::LEAF_TAG_ID), ZERO, ZERO],
        }
    }
    /// Tag for an `add` op node.
    pub fn add_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO],
        }
    }
    /// Tag for a `sub` op node.
    pub fn sub_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO],
        }
    }
    /// Tag for a `mul` op node.
    pub fn mul_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO],
        }
    }
    /// Tag for an equality predicate.
    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a canonical leaf node from u32 limbs (little-endian).
    pub fn leaf_node(limbs: [u32; 8]) -> Node {
        Node::leaf(Self::leaf_tag(), limbs.map(Felt::from_u32))
    }

    /// Extract `[u32; 8]` limbs from a canonical leaf node, erroring if it isn't a `Uint` leaf
    /// or if any limb is non-canonical (felt > `u32::MAX`).
    pub fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        if node.tag != Self::leaf_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        decode_limbs(node.payload.as_felts()?)
    }

    /// 256-bit wrapping add (mod 2^256). Limbs are little-endian u32. Exposed for consumers
    /// (e.g. [`super::Group`]) that want to perform arithmetic without going through `reduce`.
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

    /// 256-bit wrapping sub (mod 2^256). Limbs are little-endian u32.
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

    /// 256-bit schoolbook mul keeping the low 256 bits (mod 2^256). Limbs are little-endian u32.
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
        vec![Self::leaf_node([0; 8]), Self::leaf_node(one), Self::leaf_node([u32::MAX; 8])]
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        // Leaf is a `Value` (8 raw u32 limbs); op-nodes and the eq predicate are `Join`
        // (children encoded as `lhs_digest || rhs_digest`).
        Some(match Discriminant::classify(args[0])? {
            Discriminant::Leaf => NodeType::Value,
            Discriminant::BinaryOp(_) | Discriminant::Eq => NodeType::Join,
        })
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        match UintNode::parse(args, payload)? {
            // Leaf canonicality is checked at parse-time, deferred from register-time so that
            // malformed leaves are interned silently and only error out when used.
            UintNode::Leaf => Ok(Node::leaf(Tag::new(Self::id(), args), *payload.as_felts()?)),
            UintNode::BinaryOp { op, lhs, rhs } => {
                let a = leaf_limbs(&witness.resolve(lhs)?)?;
                let b = leaf_limbs(&witness.resolve(rhs)?)?;
                Ok(Self::leaf_node(op.apply(a, b)))
            },
            UintNode::Eq { lhs, rhs } => {
                if witness.resolve(lhs)? != witness.resolve(rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(Node::TRUE)
            },
        }
    }
}

// TYPED TAG / NODE
// ================================================================================================

/// Decoded view of a recognised `Uint` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Leaf,
    BinaryOp(BinaryOp),
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Leaf),
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

/// A `Uint` node with both tag and payload decoded.
enum UintNode {
    Leaf,
    BinaryOp { op: BinaryOp, lhs: Digest, rhs: Digest },
    Eq { lhs: Digest, rhs: Digest },
}

impl UintNode {
    /// `args[0]` is the discriminant; the registry already matched `Uint`'s id, and `Uint`
    /// ignores `args[1..3]`.
    fn parse(args: [Felt; 3], payload: &Payload) -> Result<Self, PrecompileError> {
        let kind = Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)?;
        Ok(match kind {
            Discriminant::Leaf => {
                decode_limbs(payload.as_felts()?)?;
                Self::Leaf
            },
            Discriminant::BinaryOp(op) => {
                let (lhs, rhs) = payload.join_children()?;
                Self::BinaryOp { op, lhs, rhs }
            },
            Discriminant::Eq => {
                let (lhs, rhs) = payload.join_children()?;
                Self::Eq { lhs, rhs }
            },
        })
    }
}

// HELPERS
// ================================================================================================

fn leaf_limbs(node: &Node) -> Result<[u32; 8], DeferredError> {
    if node.tag != Uint::leaf_tag() {
        return Err(DeferredError::InvalidPayload);
    }
    decode_limbs(node.payload.as_felts()?)
}

fn decode_limbs(felts: &[Felt; 8]) -> Result<[u32; 8], DeferredError> {
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

fn encode_limbs(limbs: [u32; 8]) -> Payload {
    Payload::new(limbs.map(Felt::from_u32))
}
