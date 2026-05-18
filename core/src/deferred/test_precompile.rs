//! Minimal `#[cfg(test)]` schema fixture for exercising the deferred engine
//! (`DeferredState` register/evaluate/log/rehydrate, composite dispatch) without leaning on
//! a reference *app*'s semantics.
//!
//! Deliberately tiny: an 8×`u32` little-endian value leaf, `add`/`mul` wrapping binary ops,
//! and an `eq` predicate. Not exported, not on any public / `testing` surface — engine
//! scaffolding only, the same category as `NoopSchema`'s `NeverCtx` and the composite's
//! `FakeApp`. Reference precompiles that exercise the *public* surface live in
//! `core/tests/common/precompile/` instead.

use crate::{
    Felt, ZERO,
    deferred::{
        DeferredError, Node, NodeType, Payload, Precompile, PrecompileTag, ReduceCtx, Schema,
        SchemaError, TRUE_TAG, Tag, TagInfo, precompile_id, true_node,
    },
};

/// Zero-sized handle for the engine test fixture.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct TestPrecompile;

impl TestPrecompile {
    const NAME: &'static str = "test_precompile";
    const VERSION: u32 = 1;

    const LEAF_TAG_ID: u32 = 0;
    const ADD_TAG_ID: u32 = 1;
    const MUL_TAG_ID: u32 = 2;
    const EQ_TAG_ID: u32 = 3;

    pub(crate) fn app_id() -> Felt {
        precompile_id(&TestPrecompile)
    }

    pub(crate) fn leaf_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::LEAF_TAG_ID), ZERO, ZERO]
    }
    pub(crate) fn add_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO]
    }
    pub(crate) fn mul_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO]
    }
    pub(crate) fn eq_tag() -> Tag {
        [Self::app_id(), Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO]
    }

    /// Build a canonical value leaf from `[u32; 8]` limbs (little-endian).
    pub(crate) fn leaf_node(limbs: [u32; 8]) -> Node {
        Node::expression(Self::leaf_tag(), Payload::new(limbs.map(Felt::from_u32)))
    }

    fn limbs_of(node: &Node) -> Result<[u32; 8], DeferredError> {
        if node.tag != Self::leaf_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        let payload = node.expression_payload().ok_or(DeferredError::InvalidPayload)?;
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

    fn wrap_add(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
        let mut out = [0u32; 8];
        let mut carry: u64 = 0;
        for i in 0..8 {
            let s = a[i] as u64 + b[i] as u64 + carry;
            out[i] = s as u32;
            carry = s >> 32;
        }
        out
    }

    fn wrap_mul(a: [u32; 8], b: [u32; 8]) -> [u32; 8] {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disc {
    Leaf,
    Add,
    Mul,
    Eq,
}

impl Disc {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Leaf),
            1 => Some(Self::Add),
            2 => Some(Self::Mul),
            3 => Some(Self::Eq),
            _ => None,
        }
    }
}

impl Precompile for TestPrecompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn version(&self) -> u32 {
        Self::VERSION
    }

    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, sub: PrecompileTag) -> Result<TagInfo, SchemaError> {
        let [disc, imm, reserved] = sub.0;
        if imm != ZERO || reserved != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let kind = Disc::classify(disc).ok_or(SchemaError::InvalidNode)?;
        let node_type = match kind {
            Disc::Leaf => NodeType::Value,
            Disc::Add | Disc::Mul | Disc::Eq => NodeType::Binary,
        };
        let evaluates_to = match kind {
            Disc::Leaf | Disc::Add | Disc::Mul => Self::leaf_tag(),
            Disc::Eq => TRUE_TAG,
        };
        Ok(TagInfo { node_type, evaluates_to })
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() || node.tag[2] != ZERO || node.tag[3] != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        let kind = Disc::classify(node.tag[1]).ok_or(SchemaError::InvalidNode)?;
        let payload = node.expression_payload().ok_or(SchemaError::InvalidNode)?;
        match kind {
            // Leaf canonicality is checked here, deferred from register-time.
            Disc::Leaf => {
                Self::limbs_of(node).map_err(SchemaError::from)?;
                Ok(node.clone())
            },
            Disc::Add | Disc::Mul => {
                let (lhs, rhs) = payload.binary_op_children();
                let a = Self::limbs_of(&ctx.resolve(lhs)?).map_err(SchemaError::from)?;
                let b = Self::limbs_of(&ctx.resolve(rhs)?).map_err(SchemaError::from)?;
                let out = match kind {
                    Disc::Add => Self::wrap_add(a, b),
                    Disc::Mul => Self::wrap_mul(a, b),
                    _ => unreachable!(),
                };
                Ok(Self::leaf_node(out))
            },
            Disc::Eq => {
                let (lhs, rhs) = payload.binary_op_children();
                if ctx.resolve(lhs)? != ctx.resolve(rhs)? {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}

/// Single-app convenience `Schema` so tests can use `&TestPrecompile` directly without the
/// `PrecompileSchema` composite.
impl Schema for TestPrecompile {
    fn decode(&self, tag: Tag) -> Result<TagInfo, SchemaError> {
        if tag[0] != Self::app_id() {
            return Err(SchemaError::InvalidNode);
        }
        Precompile::decode(self, PrecompileTag([tag[1], tag[2], tag[3]]))
    }

    fn reduce(&self, node: &Node, ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag[0] != Self::app_id() {
            return Err(SchemaError::InvalidNode);
        }
        Precompile::reduce(self, node, ctx)
    }
}
