//! `Sig` — single chunk-bodied predicate reference precompile that mirrors the legacy
//! "signature is an opaque chunk that evaluates to TRUE" pattern in the smallest possible form.
//!
//! A `verify` node is a chunk-bodied predicate carrying a fixed-size opaque payload
//! (`SIG_CHUNKS = 3` chunks, conceptually `sig || pk || msg`). The chunk count is hardcoded per
//! discriminant — no immediate. Reduce performs a stub check: succeeds iff the very first felt
//! of the first chunk is non-zero, mirroring the shape of "this signature isn't an all-zero
//! placeholder." Real `Ecdsa`/`Eddsa` apps would slot in by swapping the stub for a non-native
//! verification kernel.

use std::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        App, AppTag, Node, NodePayload, NodeType, ReduceCtx, SchemaError, TRUE_TAG, Tag, TagInfo,
        app_id_from, true_node,
    },
};

// PUBLIC APP TYPE
// ================================================================================================

/// Zero-sized handle for the `Sig` app.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sig;

impl Sig {
    pub const NAME: &'static str = "mock_sig";
    pub const VERSION: u32 = 1;
    pub const DISCS: &'static [&'static str] = &["verify"];

    pub const D_VERIFY: Felt = Felt::new_unchecked(0);

    /// Number of 8-felt chunks in a mock signature blob. Hardcoded — there is no immediate, so
    /// the framework derives the chunk count from this constant at `decode` time.
    pub const SIG_CHUNKS: u32 = 3;

    pub fn app_id() -> Felt {
        app_id_from(Self::NAME, Self::VERSION, &[], Self::DISCS)
    }

    pub fn verify_tag() -> Tag {
        [Self::app_id(), Self::D_VERIFY, ZERO, ZERO]
    }

    /// Build a `verify` predicate node from `SIG_CHUNKS` 8-felt chunks.
    pub fn verify_node(chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::verify_tag(), chunks)
    }
}

impl App for Sig {
    fn id(&self) -> Felt {
        Self::app_id()
    }

    fn decode(&self, local: AppTag) -> Result<TagInfo, SchemaError> {
        if local.imm != ZERO {
            return Err(SchemaError::InvalidNode);
        }
        match Discriminant::classify(local.node_disc).ok_or(SchemaError::InvalidNode)? {
            Discriminant::Verify => Ok(TagInfo {
                node_type: NodeType::Chunks(Self::SIG_CHUNKS),
                evaluates_to: TRUE_TAG,
            }),
        }
    }

    fn reduce(&self, node: &Node, _ctx: &mut dyn ReduceCtx) -> Result<Node, SchemaError> {
        if node.tag != Self::verify_tag() {
            return Err(SchemaError::InvalidNode);
        }
        match &node.payload {
            NodePayload::Chunk(chunks) => {
                if chunks.len() != Self::SIG_CHUNKS as usize {
                    return Err(SchemaError::InvalidNode);
                }
                // Stub check: signature passes iff the first felt of the first chunk is non-zero.
                // Stand-in for "this isn't a zeroed-out placeholder signature."
                if chunks[0][0] == ZERO {
                    return Err(SchemaError::AssertionFailed);
                }
                Ok(true_node())
            },
            NodePayload::Expression(_) => Err(SchemaError::InvalidNode),
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
