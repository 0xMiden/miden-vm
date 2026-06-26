//! Mock hash precompile for exercising data-bodied deferred nodes.
//!
//! A `preimage` data node evaluates to a `digest` value by summing its data chunks coordinate-wise.
//! The intentionally simple hash keeps tests focused on framework behavior: precompile-level data
//! length validation, evaluation, and equality predicates.

use alloc::sync::Arc;

use crate::{
    Felt, ZERO,
    deferred::{
        DataChunk, DeferredContext, DeferredError, Digest, Node, NodeType, Payload, Precompile,
        PrecompileError, Tag, precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the mock hash precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Hash;

impl Hash {
    pub const NAME: &'static str = "mock_hash";

    pub const PREIMAGE_TAG_ID: u32 = 0;
    pub const DIGEST_TAG_ID: u32 = 1;
    pub const EQ_TAG_ID: u32 = 2;

    /// Bytes represented by one 8-felt data chunk in this fixture.
    pub const BYTES_PER_CHUNK: u32 = 32;

    pub fn id() -> Felt {
        precompile_id(Self::NAME)
    }

    /// Tag for a preimage whose byte length determines its data chunk count.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Self::tag([Felt::from_u32(Self::PREIMAGE_TAG_ID), Felt::from_u32(n_bytes), ZERO])
    }

    /// Tag for a canonical digest value.
    pub fn digest_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::DIGEST_TAG_ID), ZERO, ZERO])
    }

    /// Tag for a digest-equality predicate.
    pub fn eq_tag() -> Tag {
        Self::tag([Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO])
    }

    fn tag(args: [Felt; 3]) -> Tag {
        Tag::precompile(Self::id(), args)
            .expect("mock hash precompile id is not framework-reserved")
    }

    /// Builds a preimage node from data chunks whose count must match `n_bytes`.
    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[DataChunk]>>) -> Node {
        Node::try_data(Self::preimage_tag(n_bytes), chunks)
            .expect("preimage requires at least one data chunk")
    }

    /// Builds a canonical digest value.
    pub fn digest_node(felts: DataChunk) -> Node {
        Node::value(Self::digest_tag(), felts).expect("digest tag is precompile-owned")
    }

    /// Builds a predicate comparing two digest-producing nodes.
    pub fn eq_node(h_lhs: Digest, h_rhs: Digest) -> Node {
        Node::join(Self::eq_tag(), h_lhs, h_rhs).expect("eq tag is precompile-owned")
    }

    /// Extracts digest felts from a canonical digest value.
    pub fn digest_felts(node: &Node) -> Result<DataChunk, DeferredError> {
        Ok(*node.payload_for_tag(Self::digest_tag())?.as_value()?)
    }

    /// Deterministic mock hash used by tests instead of real cryptography.
    pub fn hash(chunks: &[DataChunk]) -> DataChunk {
        let mut acc = [ZERO; 8];
        for c in chunks {
            for (a, x) in acc.iter_mut().zip(c.iter()) {
                *a += *x;
            }
        }
        acc
    }

    /// Returns the data chunk count implied by a byte length.
    pub fn n_data_chunks(n_bytes: u32) -> u32 {
        n_bytes.div_ceil(Self::BYTES_PER_CHUNK)
    }
}

impl Precompile for Hash {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        match Discriminant::classify(args[0])? {
            Discriminant::Preimage => {
                // `args[1]` carries n_bytes; the data chunk count is derived semantically. A
                // zero-byte preimage derives zero chunks and remains invalid for this fixture.
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                NodeType::data_chunks(Self::n_data_chunks(n_bytes))
            },
            // Self-evaluating value carrying one 8-felt chunk of digest data.
            Discriminant::Digest => Some(NodeType::value()),
            // Binary predicate over two child digests.
            Discriminant::Eq => Some(NodeType::Join),
        }
    }

    fn evaluate(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        context: &mut DeferredContext<'_>,
    ) -> Result<Node, PrecompileError> {
        match Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)? {
            Discriminant::Preimage => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64())
                    .map_err(|_| PrecompileError::InvalidNode)?;
                let expected_chunks = Self::n_data_chunks(n_bytes) as usize;
                let chunks = payload.as_data()?;
                if expected_chunks == 0 || chunks.len() != expected_chunks {
                    return Err(PrecompileError::InvalidNode);
                }
                // Inline hash → canonical digest value. No minting needed: the digest IS the
                // canonical payload.
                Ok(Self::digest_node(Self::hash(chunks)))
            },
            Discriminant::Digest => Ok(Node::value(Self::tag(args), *payload.as_value()?)?),
            Discriminant::Eq => {
                let (h_lhs, h_rhs) = payload.as_join()?;
                context.ensure_equal(h_lhs, h_rhs)?;
                Ok(Node::TRUE)
            },
        }
    }
}

// TYPED DISCRIMINANT
// ================================================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discriminant {
    Preimage,
    Digest,
    Eq,
}

impl Discriminant {
    fn classify(disc: Felt) -> Option<Self> {
        match disc.as_canonical_u64() {
            0 => Some(Self::Preimage),
            1 => Some(Self::Digest),
            2 => Some(Self::Eq),
            _ => None,
        }
    }
}
