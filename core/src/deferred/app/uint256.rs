//! `Uint256` — 256-bit wrapping integer arithmetic as a first reference [`App`].
//!
//! Promotes the legacy `Field0Handler` to the multi-app substrate. Semantics are unchanged
//! (operations are mod 2^256, limbs are u32 little-endian); the differences from `Field0Handler`
//! are structural: tags route through [`super::PrecompileSchema`] by `app_id`, a `sub` op joins
//! `add`/`mul`, and the app pre-registers `ZERO` / `ONE` / `P_MINUS_1` (`[u32::MAX; 8]`) leaves
//! via [`App::init`].

use crate::{
    Felt, ZERO,
    deferred::{
        BodyShape, ChildResolver, DeferredError, DeferredState, Digest, Node, Payload, Schema,
        SchemaError, TRUE_TAG, Tag, TagInfo, true_node,
    },
};

use super::{App, AppTag, app_id_from};

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `Uint256` app.
#[derive(Debug, Default, Clone, Copy)]
pub struct Uint256;

impl Uint256 {
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

    /// Derive `app_id`. Pure function over `Uint256`'s metadata.
    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    /// Tag for a canonical Uint256 leaf.
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

    /// Extract `[u32; 8]` limbs from a canonical leaf node, erroring if it isn't a `Uint256` leaf
    /// or if any limb is non-canonical (felt > `u32::MAX`).
    pub fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        if node.tag != Self::leaf_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        decode_limbs(node.expression_payload().ok_or(DeferredError::InvalidPayload)?)
    }

    /// 256-bit wrapping add (mod 2^256). Limbs are little-endian u32. Exposed for consumers
    /// (e.g. future `MockGroup`) that want to perform arithmetic without going through `reduce`.
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

impl App for Uint256 {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn init(&self, state: &mut DeferredState) {
        // ZERO, ONE, P_MINUS_1 — useful baseline constants. Idempotent re-interns are safe.
        state.intern(Self::leaf_node([0; 8]));
        let mut one = [0u32; 8];
        one[0] = 1;
        state.intern(Self::leaf_node(one));
        state.intern(Self::leaf_node([u32::MAX; 8]));
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let body = BodyShape::Expression;
        let evaluates_to = match Discriminant::classify(local.node_disc)
            .ok_or(SchemaError::InvalidNode)?
        {
            Discriminant::Leaf | Discriminant::BinaryOp(_) => Self::leaf_tag(),
            Discriminant::Eq => TRUE_TAG,
        };
        Ok(TagInfo { body, evaluates_to })
    }

    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError> {
        match Uint256Node::parse(node)? {
            // Leaf canonicality is checked at parse-time, deferred from register-time so that
            // malformed leaves are interned silently and only error out when used.
            Uint256Node::Leaf => Ok(node.clone()),
            Uint256Node::BinaryOp { op, lhs, rhs } => {
                let a = leaf_limbs(&children.resolve(lhs)?)?;
                let b = leaf_limbs(&children.resolve(rhs)?)?;
                Ok(Self::leaf_node(op.apply(a, b)))
            },
            Uint256Node::Eq { lhs, rhs } => {
                if children.resolve(lhs)? != children.resolve(rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

// Convenience: let callers use `Uint256` directly as a single-app `Schema` in places where they
// don't need the composite. Equivalent to `PrecompileSchema::single(Uint256)`, just cheaper.
impl Schema for Uint256 {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[0] != Self::app_id() || tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        App::decode(self, AppTag { node_disc: tag[1], imm: tag[2] })
    }

    fn reduce(&self, node: &Node, children: &mut dyn ChildResolver) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() {
            return Err(SchemaError::InvalidNode);
        }
        App::reduce(self, node, children)
    }
}

// TYPED TAG / NODE
// ================================================================================================

/// Decoded view of a recognised `Uint256` tag.
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
            Self::Add => Uint256::wrap_add(a, b),
            Self::Sub => Uint256::wrap_sub(a, b),
            Self::Mul => Uint256::wrap_mul(a, b),
        }
    }
}

/// A `Uint256` node with both tag and payload decoded.
enum Uint256Node {
    Leaf,
    BinaryOp { op: BinaryOp, lhs: Digest, rhs: Digest },
    Eq { lhs: Digest, rhs: Digest },
}

impl Uint256Node {
    fn parse(node: &Node) -> Result<Self, SchemaError> {
        let tag = node.tag;
        if tag[0] != Uint256::app_id() || tag[2] != ZERO || tag[3] != ZERO {
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
    if node.tag != Uint256::leaf_tag() {
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_from_u32s(limbs: [u32; 8]) -> Node {
        Uint256::leaf_node(limbs)
    }

    fn leaf_from_low_u64(value: u64) -> Node {
        let mut limbs = [0u32; 8];
        limbs[0] = value as u32;
        limbs[1] = (value >> 32) as u32;
        leaf_from_u32s(limbs)
    }

    fn eval_binary(op: BinaryOp, lhs: Node, rhs: Node) -> Result<Node, DeferredError> {
        let a = leaf_limbs(&lhs)?;
        let b = leaf_limbs(&rhs)?;
        Ok(Uint256::leaf_node(op.apply(a, b)))
    }

    #[test]
    fn add_small_values() {
        let out = eval_binary(BinaryOp::Add, leaf_from_low_u64(3), leaf_from_low_u64(5)).unwrap();
        assert_eq!(out.tag, Uint256::leaf_tag());
        assert_eq!(out, leaf_from_low_u64(8));
    }

    #[test]
    fn add_propagates_carry_across_limbs() {
        let mut a_limbs = [0u32; 8];
        a_limbs[0] = u32::MAX;
        let mut b_limbs = [0u32; 8];
        b_limbs[0] = 1;
        let out =
            eval_binary(BinaryOp::Add, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        let mut expected = [0u32; 8];
        expected[1] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn add_wraps_at_2_to_256() {
        let max = leaf_from_u32s([u32::MAX; 8]);
        let one = leaf_from_low_u64(1);
        let out = eval_binary(BinaryOp::Add, max, one).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn sub_small_values() {
        let out = eval_binary(BinaryOp::Sub, leaf_from_low_u64(10), leaf_from_low_u64(3)).unwrap();
        assert_eq!(out, leaf_from_low_u64(7));
    }

    #[test]
    fn sub_borrows_across_limbs() {
        let mut a_limbs = [0u32; 8];
        a_limbs[1] = 1; // a = 2^32
        let mut b_limbs = [0u32; 8];
        b_limbs[0] = 1;
        let out =
            eval_binary(BinaryOp::Sub, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        // 2^32 - 1 = 0xffffffff in limb 0, zero elsewhere.
        let mut expected = [0u32; 8];
        expected[0] = u32::MAX;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn sub_wraps_below_zero() {
        let zero = leaf_from_low_u64(0);
        let one = leaf_from_low_u64(1);
        // 0 - 1 = 2^256 - 1 = [u32::MAX; 8].
        let out = eval_binary(BinaryOp::Sub, zero, one).unwrap();
        assert_eq!(out, leaf_from_u32s([u32::MAX; 8]));
    }

    #[test]
    fn mul_small_values() {
        let out = eval_binary(BinaryOp::Mul, leaf_from_low_u64(6), leaf_from_low_u64(7)).unwrap();
        assert_eq!(out, leaf_from_low_u64(42));
    }

    #[test]
    fn mul_propagates_across_limbs() {
        let mut a_limbs = [0u32; 8];
        a_limbs[1] = 1;
        let b_limbs = a_limbs;
        let out =
            eval_binary(BinaryOp::Mul, leaf_from_u32s(a_limbs), leaf_from_u32s(b_limbs)).unwrap();
        let mut expected = [0u32; 8];
        expected[2] = 1;
        assert_eq!(out, leaf_from_u32s(expected));
    }

    #[test]
    fn mul_truncates_overflow_above_2_to_256() {
        let mut a_limbs = [0u32; 8];
        a_limbs[7] = 1 << 31;
        let two = leaf_from_low_u64(2);
        let out = eval_binary(BinaryOp::Mul, leaf_from_u32s(a_limbs), two).unwrap();
        assert_eq!(out, leaf_from_u32s([0; 8]));
    }

    #[test]
    fn non_canonical_limb_errors() {
        let bad = Node::expression(
            Uint256::leaf_tag(),
            Payload::new([
                Felt::new_unchecked(1u64 << 32),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
                Felt::from_u32(0),
            ]),
        );
        let ok = leaf_from_low_u64(1);
        let err = eval_binary(BinaryOp::Add, bad, ok);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn non_leaf_operand_errors() {
        let a = Node::expression(Uint256::add_tag(), Payload::new([Felt::from_u32(0); 8]));
        let b = leaf_from_low_u64(1);
        let err = eval_binary(BinaryOp::Add, a, b);
        assert!(matches!(err, Err(DeferredError::InvalidPayload)));
    }

    #[test]
    fn app_id_is_stable_across_calls() {
        assert_eq!(Uint256::app_id(), Uint256::app_id());
    }

    #[test]
    fn boot_interns_zero_one_pminus1() {
        use super::super::PrecompileSchema;
        let schema = PrecompileSchema::single(Uint256);
        let mut state = DeferredState::new();
        schema.boot(&mut state);
        assert!(state.contains(&Uint256::leaf_node([0; 8]).digest()));
        let mut one = [0u32; 8];
        one[0] = 1;
        assert!(state.contains(&Uint256::leaf_node(one).digest()));
        assert!(state.contains(&Uint256::leaf_node([u32::MAX; 8]).digest()));
    }
}
