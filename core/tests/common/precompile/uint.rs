//! `Uint` — 256-bit wrapping integer arithmetic as a first reference precompile.
//!
//! Semantics: operations are mod 2^256, limbs are u32 little-endian. Tags route through
//! [`PrecompileSchema`] by id; a `sub` op joins `add`/`mul`, and the precompile pre-registers
//! `ZERO` / `ONE` / `P_MINUS_1` (`[u32::MAX; 8]`) leaves via [`Precompile::init`].
//!
//! [`PrecompileSchema`]: miden_core::deferred::PrecompileSchema

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredError, Digest, Node, NodeType, Payload, Precompile, PrecompileTag, Schema,
        SchemaError, TRUE_TAG, Tag, TagInfo, WitnessBuilder, precompile_id, true_node,
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
        [Self::id(), Felt::from_u32(Self::LEAF_TAG_ID), ZERO, ZERO]
    }
    /// Tag for an `add` op node.
    pub fn add_tag() -> Tag {
        [Self::id(), Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO]
    }
    /// Tag for a `sub` op node.
    pub fn sub_tag() -> Tag {
        [Self::id(), Felt::from_u32(Self::SUB_TAG_ID), ZERO, ZERO]
    }
    /// Tag for a `mul` op node.
    pub fn mul_tag() -> Tag {
        [Self::id(), Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO]
    }
    /// Tag for an equality predicate.
    pub fn eq_tag() -> Tag {
        [Self::id(), Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO]
    }

    /// Build a canonical leaf node from u32 limbs (little-endian).
    pub fn leaf_node(limbs: [u32; 8]) -> Node {
        Node::expression(Self::leaf_tag(), encode_limbs(limbs))
    }

    /// Extract `[u32; 8]` limbs from a canonical leaf node, erroring if it isn't a `Uint` leaf
    /// or if any limb is non-canonical (felt > `u32::MAX`).
    pub fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        if node.tag != Self::leaf_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        decode_limbs(node.expression_payload().ok_or(DeferredError::InvalidPayload)?)
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

    fn decode(&self, sub: PrecompileTag) -> Option<TagInfo> {
        let [disc, imm, reserved] = sub.0;
        if imm != ZERO || reserved != ZERO {
            return None;
        }
        let kind = Discriminant::classify(disc)?;
        // Leaf is a `Value` (8 raw u32 limbs); op-nodes and the eq predicate are `Binary`
        // (children encoded as `lhs_digest || rhs_digest`).
        let node_type = match kind {
            Discriminant::Leaf => NodeType::Value,
            Discriminant::BinaryOp(_) | Discriminant::Eq => NodeType::Binary,
        };
        let evaluates_to = match kind {
            Discriminant::Leaf | Discriminant::BinaryOp(_) => Self::leaf_tag(),
            Discriminant::Eq => TRUE_TAG,
        };
        Some(TagInfo { node_type, evaluates_to })
    }

    fn reduce(&self, node: &Node, witness: &mut WitnessBuilder<'_>) -> Result<Node, SchemaError> {
        match UintNode::parse(node)? {
            // Leaf canonicality is checked at parse-time, deferred from register-time so that
            // malformed leaves are interned silently and only error out when used.
            UintNode::Leaf => Ok(node.clone()),
            UintNode::BinaryOp { op, lhs, rhs } => {
                let a = leaf_limbs(&witness.resolve(lhs)?)?;
                let b = leaf_limbs(&witness.resolve(rhs)?)?;
                Ok(Self::leaf_node(op.apply(a, b)))
            },
            UintNode::Eq { lhs, rhs } => {
                if witness.resolve(lhs)? != witness.resolve(rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// Convenience: let callers use `Uint` directly as a single-precompile `Schema` in places where they
// don't need the composite. Equivalent to `PrecompileSchema::single(Uint)`, just cheaper.
impl Schema for Uint {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[0] != Self::id() {
            return Err(SchemaError::InvalidNode);
        }
        Precompile::decode(self, PrecompileTag([tag[1], tag[2], tag[3]]))
            .ok_or(SchemaError::InvalidNode)
    }

    fn reduce(&self, node: &Node, witness: &mut WitnessBuilder<'_>) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::id() {
            return Err(SchemaError::InvalidNode);
        }
        Precompile::reduce(self, node, witness)
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
    fn parse(node: &Node) -> Result<Self, SchemaError> {
        let tag = node.tag;
        if tag[0] != Uint::id() || tag[2] != ZERO || tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let kind = Discriminant::classify(tag[1]).ok_or(SchemaError::InvalidNode)?;
        let payload = node.expression_payload().ok_or(DeferredError::InvalidPayload)?;
        Ok(match kind {
            Discriminant::Leaf => {
                decode_limbs(payload)?;
                Self::Leaf
            },
            Discriminant::BinaryOp(op) => {
                let (lhs, rhs) = payload.binary_op_children();
                Self::BinaryOp { op, lhs, rhs }
            },
            Discriminant::Eq => {
                let (lhs, rhs) = payload.binary_op_children();
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
    decode_limbs(node.expression_payload().ok_or(DeferredError::InvalidPayload)?)
}

fn decode_limbs(payload: &Payload) -> Result<[u32; 8], DeferredError> {
    let mut limbs = [0u32; 8];
    for (i, felt) in payload.0.iter().enumerate() {
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
