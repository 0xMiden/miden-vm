//! Minimal `#[cfg(test)]` precompile fixture for exercising the deferred engine
//! (`DeferredState` register/evaluate/log/rehydrate, registry dispatch). A value leaf carries
//! a single scalar `Felt` and binary ops are field-native `add`/`mul`/`eq` — the engine
//! doesn't care what arithmetic a precompile implements, so we use the cheapest one that
//! still produces predictable results for the tests.
//!
//! Not exported, not on any public / `testing` surface — engine scaffolding only. Reference
//! precompiles that exercise the *public* surface live in `core/tests/common/precompile/`.

use crate::{
    Felt, ZERO,
    deferred::{
        Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder, precompile_id,
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

    fn op_tag(disc: u32) -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(disc), ZERO, ZERO],
        }
    }

    pub(crate) fn leaf_tag() -> Tag {
        Self::op_tag(Self::LEAF_TAG_ID)
    }
    pub(crate) fn add_tag() -> Tag {
        Self::op_tag(Self::ADD_TAG_ID)
    }
    pub(crate) fn mul_tag() -> Tag {
        Self::op_tag(Self::MUL_TAG_ID)
    }
    pub(crate) fn eq_tag() -> Tag {
        Self::op_tag(Self::EQ_TAG_ID)
    }

    /// Build a canonical value leaf carrying a single `Felt` (other slots zero).
    pub(crate) fn leaf_node(value: Felt) -> Node {
        let mut felts = [ZERO; 8];
        felts[0] = value;
        Node::expression(Self::leaf_tag(), Payload::new(felts))
    }

    /// Extract the scalar value from a resolved leaf, rejecting non-leaf nodes.
    fn value_of(node: &Node) -> Result<Felt, PrecompileError> {
        if node.tag != Self::leaf_tag() {
            return Err(PrecompileError::InvalidNode);
        }
        Ok(node.payload.as_felts()?[0])
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

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        Some(match Disc::classify(args[0])? {
            Disc::Leaf => NodeType::Value,
            Disc::Add | Disc::Mul | Disc::Eq => NodeType::Join,
        })
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        match Disc::classify(args[0]).ok_or(PrecompileError::InvalidNode)? {
            Disc::Leaf => {
                Ok(Node::expression(Tag::new(Self::id(), args), Payload::new(*payload.as_felts()?)))
            },
            kind @ (Disc::Add | Disc::Mul) => {
                let (lhs, rhs) = payload.join_children()?;
                let a = Self::value_of(&witness.resolve(lhs)?)?;
                let b = Self::value_of(&witness.resolve(rhs)?)?;
                let out = if kind == Disc::Add { a + b } else { a * b };
                Ok(Self::leaf_node(out))
            },
            Disc::Eq => {
                let (lhs, rhs) = payload.join_children()?;
                if witness.resolve(lhs)? != witness.resolve(rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(Node::TRUE)
            },
        }
    }
}
