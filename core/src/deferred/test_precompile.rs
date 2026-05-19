//! Minimal `#[cfg(test)]` precompile fixture for exercising the deferred engine
//! (`DeferredState` register/evaluate/log/rehydrate, registry dispatch) without leaning on a
//! reference precompile's semantics.
//!
//! Deliberately tiny: an 8×`u32` little-endian value leaf, `add`/`mul` wrapping binary ops, and
//! an `eq` predicate. Not exported, not on any public / `testing` surface — engine scaffolding
//! only. Reference precompiles that exercise the *public* surface live in
//! `core/tests/common/precompile/` instead.

use crate::{
    Felt, ZERO,
    deferred::{
        DeferredError, Node, NodeType, Payload, Precompile, PrecompileError, TRUE_TAG, Tag,
        TagInfo, WitnessBuilder, precompile_id, true_node,
    },
};

/// Zero-sized handle for the engine test fixture.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct TestPrecompile;

impl TestPrecompile {
    const NAME: &'static str = "test_precompile";

    const LEAF_TAG_ID: u32 = 0;
    const ADD_TAG_ID: u32 = 1;
    const MUL_TAG_ID: u32 = 2;
    const EQ_TAG_ID: u32 = 3;

    pub(crate) fn id() -> Felt {
        precompile_id(&TestPrecompile)
    }

    pub(crate) fn leaf_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::LEAF_TAG_ID), ZERO, ZERO],
        }
    }
    pub(crate) fn add_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::ADD_TAG_ID), ZERO, ZERO],
        }
    }
    pub(crate) fn mul_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::MUL_TAG_ID), ZERO, ZERO],
        }
    }
    pub(crate) fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
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

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, imm: [Felt; 3]) -> Option<TagInfo> {
        let [disc, immediate, reserved] = imm;
        if immediate != ZERO || reserved != ZERO {
            return None;
        }
        let kind = Disc::classify(disc)?;
        let node_type = match kind {
            Disc::Leaf => NodeType::Value,
            Disc::Add | Disc::Mul | Disc::Eq => NodeType::Binary,
        };
        let evaluates_to = match kind {
            Disc::Leaf | Disc::Add | Disc::Mul => Self::leaf_tag(),
            Disc::Eq => TRUE_TAG,
        };
        Some(TagInfo { node_type, evaluates_to })
    }

    fn reduce(
        &self,
        node: &Node,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        if node.tag.id != Self::id() || node.tag.imm[1] != ZERO || node.tag.imm[2] != ZERO {
            return Err(PrecompileError::InvalidNode);
        }
        let kind = Disc::classify(node.tag.imm[0]).ok_or(PrecompileError::InvalidNode)?;
        let payload = node.expression_payload().ok_or(PrecompileError::InvalidNode)?;
        match kind {
            // Leaf canonicality is checked here, deferred from register-time.
            Disc::Leaf => {
                Self::limbs_of(node).map_err(PrecompileError::from)?;
                Ok(node.clone())
            },
            Disc::Add | Disc::Mul => {
                let (lhs, rhs) = payload.binary_op_children();
                let a = Self::limbs_of(&witness.resolve(lhs)?).map_err(PrecompileError::from)?;
                let b = Self::limbs_of(&witness.resolve(rhs)?).map_err(PrecompileError::from)?;
                let out = match kind {
                    Disc::Add => Self::wrap_add(a, b),
                    Disc::Mul => Self::wrap_mul(a, b),
                    _ => unreachable!(),
                };
                Ok(Self::leaf_node(out))
            },
            Disc::Eq => {
                let (lhs, rhs) = payload.binary_op_children();
                if witness.resolve(lhs)? != witness.resolve(rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(true_node())
            },
        }
    }
}
