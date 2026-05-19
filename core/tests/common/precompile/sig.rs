//! `Sig` — single chunk-bodied predicate reference precompile that mirrors the legacy
//! "signature is an opaque chunk that evaluates to TRUE" pattern in the smallest possible form.
//!
//! A `verify` node is a chunk-bodied predicate carrying a fixed-size opaque payload
//! (`SIG_CHUNKS = 3` chunks, conceptually `sig || pk || msg`). The chunk count is hardcoded per
//! discriminant — no immediate. Reduce performs a stub check: succeeds iff the very first felt
//! of the first chunk is non-zero, mirroring the shape of "this signature isn't an all-zero
//! placeholder." Real `Ecdsa`/`Eddsa` precompiles would slot in by swapping the stub for a
//! non-native verification kernel.

use std::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Node, NodePayload, NodeType, Precompile, PrecompileError, TRUE_TAG, Tag, TagInfo,
        WitnessBuilder, precompile_id, true_node,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `Sig` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sig;

impl Sig {
    pub const NAME: &'static str = "mock_sig";

    pub const VERIFY_TAG_ID: u32 = 0;

    /// Number of 8-felt chunks in a mock signature blob. Hardcoded — there is no immediate, so
    /// the framework derives the chunk count from this constant at `decode` time.
    pub const SIG_CHUNKS: u32 = 3;

    pub fn id() -> Felt {
        precompile_id(&Sig)
    }

    pub fn verify_tag() -> Tag {
        Tag {
            id: Self::id(),
            imm: [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `verify` predicate node from `SIG_CHUNKS` 8-felt chunks.
    pub fn verify_node(chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::verify_tag(), chunks)
    }
}

impl Precompile for Sig {
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
        match Discriminant::classify(disc)? {
            Discriminant::Verify => Some(TagInfo {
                node_type: NodeType::Chunks(Self::SIG_CHUNKS),
                evaluates_to: TRUE_TAG,
            }),
        }
    }

    fn reduce(
        &self,
        node: &Node,
        _witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        if node.tag != Self::verify_tag() {
            return Err(PrecompileError::InvalidNode);
        }
        match &node.payload {
            NodePayload::Chunk(chunks) => {
                if chunks.len() != Self::SIG_CHUNKS as usize {
                    return Err(PrecompileError::InvalidNode);
                }
                // Stub check: signature passes iff the first felt of the first chunk is non-zero.
                // Stand-in for "this isn't a zeroed-out placeholder signature."
                if chunks[0][0] == ZERO {
                    return Err(PrecompileError::AssertionFailed);
                }
                Ok(true_node())
            },
            NodePayload::Expression(_) => Err(PrecompileError::InvalidNode),
        }
    }
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Verify,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Verify),
            _ => None,
        }
    }
}
