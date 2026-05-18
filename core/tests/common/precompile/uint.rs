//! `Uint` — 256-bit wrapping integer arithmetic as a first reference precompile.
//!
//! Semantics: operations are mod 2^256, limbs are u32 little-endian. Tags route through
//! [`PrecompileSchema`] by `app_id`; a `sub` op joins `add`/`mul`, and the app pre-registers
//! `ZERO` / `ONE` / `P_MINUS_1` (`[u32::MAX; 8]`) leaves via [`App::init`].
//!
//! [`PrecompileSchema`]: miden_core::deferred::PrecompileSchema

use miden_core::{
    Felt, ZERO,
    deferred::{
        App, AppTag, DeferredError, DeferredState, Digest, Node, NodeType, Payload, ReduceCtx,
        Schema, SchemaError, TRUE_TAG, Tag, TagInfo, app_id_from, true_node,
    },
};

// FIELD OPS
// ================================================================================================

/// Small surface a 256-bit field app exposes to consumers (e.g. [`super::Group`]) that need to
/// mint and decode field leaves without going through the schema's `reduce`. Intentionally
/// minimal — extend as concrete cross-app needs arise.
pub trait FieldOps: App {
    /// Tag of a canonical field leaf.
    fn leaf_tag() -> Tag;
    /// Build a canonical field leaf node from `[u32; 8]` limbs (little-endian).
    fn leaf_node(limbs: [u32; 8]) -> Node;
    /// Decode `[u32; 8]` limbs from a canonical field leaf node. Errors if `node` is not a
    /// canonical leaf of this field app.
    fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError>;
    /// Wrapping 256-bit add (mod 2^256).
    fn wrap_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8];
    /// Wrapping 256-bit sub (mod 2^256).
    fn wrap_sub(a: [u32; 8], b: [u32; 8]) -> [u32; 8];
}

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `Uint` app.
#[derive(Debug, Default, Clone, Copy)]
pub struct Uint;

impl Uint {
    /// App name — hashed into `app_id`. Don't change without bumping [`Self::VERSION`].
    pub const NAME: &'static str = "uint256";
    /// App version — bump on incompatible discriminant changes.
    pub const VERSION: u32 = 1;
    /// Discriminant names — hashed into `app_id`; renaming changes the id.
    pub const DISCS: &'static [&'static str] = &["leaf", "add", "sub", "mul", "eq"];

    /// Discriminant indices, matching positions in [`Self::DISCS`].
    pub const D_LEAF: Felt = Felt::new_unchecked(0);
    pub const D_ADD: Felt = Felt::new_unchecked(1);
    pub const D_SUB: Felt = Felt::new_unchecked(2);
    pub const D_MUL: Felt = Felt::new_unchecked(3);
    pub const D_EQ: Felt = Felt::new_unchecked(4);

    /// Derive `app_id`. Pure function over `Uint`'s metadata.
    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    /// Tag for a canonical Uint leaf.
    pub fn leaf_tag() -> Tag {
        [Self::app_id(), Self::D_LEAF, ZERO, ZERO]
    }
    /// Tag for an `add` op node.
    pub fn add_tag() -> Tag {
        [Self::app_id(), Self::D_ADD, ZERO, ZERO]
    }
    /// Tag for a `sub` op node.
    pub fn sub_tag() -> Tag {
        [Self::app_id(), Self::D_SUB, ZERO, ZERO]
    }
    /// Tag for a `mul` op node.
    pub fn mul_tag() -> Tag {
        [Self::app_id(), Self::D_MUL, ZERO, ZERO]
    }
    /// Tag for an equality predicate.
    pub fn eq_tag() -> Tag {
        [Self::app_id(), Self::D_EQ, ZERO, ZERO]
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

impl FieldOps for Uint {
    fn leaf_tag() -> Tag {
        Self::leaf_tag()
    }
    fn leaf_node(limbs: [u32; 8]) -> Node {
        Self::leaf_node(limbs)
    }
    fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        Self::limbs_of(node)
    }
    fn wrap_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        Self::wrap_add(a, b)
    }
    fn wrap_sub(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        Self::wrap_sub(a, b)
    }
}

impl App for Uint {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn init(&self, state: &mut DeferredState) {
        // ZERO, ONE, P_MINUS_1 — useful baseline constants. Idempotent re-interns are safe.
        // Registered via the public `Schema` API (`Uint: Schema`) since `DeferredState::intern`
        // is crate-private to `miden-core`.
        state.register(self, Self::leaf_node([0; 8])).expect("uint ZERO const");
        let mut one = [0u32; 8];
        one[0] = 1;
        state.register(self, Self::leaf_node(one)).expect("uint ONE const");
        state
            .register(self, Self::leaf_node([u32::MAX; 8]))
            .expect("uint P_MINUS_1 const");
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let kind = Discriminant::classify(local.node_disc).ok_or(SchemaError::InvalidNode)?;
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
        Ok(TagInfo { node_type, evaluates_to })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        match UintNode::parse(node)? {
            // Leaf canonicality is checked at parse-time, deferred from register-time so that
            // malformed leaves are interned silently and only error out when used.
            UintNode::Leaf => Ok(node.clone()),
            UintNode::BinaryOp { op, lhs, rhs } => {
                let a = leaf_limbs(&ctx.resolve(lhs)?)?;
                let b = leaf_limbs(&ctx.resolve(rhs)?)?;
                Ok(Self::leaf_node(op.apply(a, b)))
            },
            UintNode::Eq { lhs, rhs } => {
                if ctx.resolve(lhs)? != ctx.resolve(rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// Convenience: let callers use `Uint` directly as a single-app `Schema` in places where they
// don't need the composite. Equivalent to `PrecompileSchema::single(Uint)`, just cheaper.
impl Schema for Uint {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[0] != Self::app_id() || tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        App::decode(self, AppTag { node_disc: tag[1], imm: tag[2] })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() {
            return Err(SchemaError::InvalidNode);
        }
        App::reduce(self, node, ctx)
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
        if tag[0] != Uint::app_id() || tag[2] != ZERO || tag[3] != ZERO {
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
