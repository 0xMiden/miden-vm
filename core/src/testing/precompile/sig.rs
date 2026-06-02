//! Mock signature precompile for exercising fixed-size chunk predicates.
//!
//! `verify` treats its chunks as an opaque signature blob and succeeds only when the first felt is
//! non-zero. The stub keeps tests focused on chunk predicate plumbing, not signature math.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use crate::{
    Felt, ZERO,
    deferred::{
        DeferredContext, Node, NodeType, Payload, Precompile, PrecompileError, Tag, precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the mock signature precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sig;

impl Sig {
    pub const NAME: &'static str = "mock_sig";

    pub const VERIFY_TAG_ID: u32 = 0;

    /// Fixed chunk count for the opaque signature blob.
    pub const SIG_CHUNKS: u32 = 3;

    pub fn id() -> Felt {
        precompile_id(&Sig)
    }

    pub fn verify_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::VERIFY_TAG_ID), ZERO, ZERO],
        }
    }

    /// Builds a signature-verification predicate from fixed-size chunks.
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

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        match Discriminant::classify(args[0])? {
            Discriminant::Verify => Some(NodeType::Chunks(
                NonZeroU32::new(Self::SIG_CHUNKS).expect("SIG_CHUNKS is nonzero"),
            )),
        }
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        _context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        // `decode` already gated this; `Verify` is the only discriminant.
        Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)?;
        let chunks = payload.as_chunks()?;
        if chunks.len() != Self::SIG_CHUNKS as usize {
            return Err(PrecompileError::InvalidNode);
        }
        // Stub check: signature passes iff the first felt of the first chunk is non-zero.
        // Stand-in for "this isn't a zeroed-out placeholder signature."
        if chunks[0][0] == ZERO {
            return Err(PrecompileError::AssertionFailed);
        }
        Ok(Node::TRUE)
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
