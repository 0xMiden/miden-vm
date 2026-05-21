//! `Hash` — chunk-bodied preimage → expression-bodied digest leaf reference precompile.
//!
//! Exercises chunk-bodied inputs and the chunk-to-expression reduction shape without
//! introducing a real hash implementation. The "hash" is a coordinate-wise sum of all preimage
//! chunks into an 8-felt accumulator — deterministic, trivially testable, definitely not
//! collision-resistant. A real `Keccak` / `Sha512` precompile would slot in by swapping the kernel.
//!
//! Tag layout (`Hash`-specific, opaque to the framework) — `Tag { id, args: [node_disc, n_bytes,
//! ZERO] }`:
//!
//! - `preimage` (disc 0) — chunk-bodied; `args[1] = n_bytes`; body is `Chunk(ceil(n_bytes / 32))`.
//!   Reduces to a `digest` leaf.
//! - `digest`   (disc 1) — expression-bodied (8-felt digest); self-evaluating.
//! - `eq`       (disc 2) — expression-bodied predicate over two child digests.

use std::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{
        DeferredError, Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag,
        WitnessBuilder, precompile_id,
    },
};

// PUBLIC PRECOMPILE TYPE
// ================================================================================================

/// Zero-sized handle for the `Hash` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Hash;

impl Hash {
    pub const NAME: &'static str = "mock_hash";

    pub const PREIMAGE_TAG_ID: u32 = 0;
    pub const DIGEST_TAG_ID: u32 = 1;
    pub const EQ_TAG_ID: u32 = 2;

    /// Bytes packed per 8-felt chunk: each felt carries a u32 (4 bytes) little-endian limb.
    pub const BYTES_PER_CHUNK: u32 = 32;

    pub fn id() -> Felt {
        precompile_id(&Hash)
    }

    /// Tag of a `preimage` chunk node for a `n_bytes`-byte payload.
    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::PREIMAGE_TAG_ID), Felt::from_u32(n_bytes), ZERO],
        }
    }

    /// Tag of a canonical `digest` leaf.
    pub fn digest_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::DIGEST_TAG_ID), ZERO, ZERO],
        }
    }

    /// Tag of an `eq` predicate node.
    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    /// Build a `preimage` chunk node from caller-supplied 8-felt chunks. The caller is
    /// responsible for zero-padding the last chunk to `BYTES_PER_CHUNK` and for matching
    /// `chunks.len() == ceil(n_bytes / BYTES_PER_CHUNK)`.
    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `digest` leaf from 8 felts.
    pub fn digest_node(felts: [Felt; 8]) -> Node {
        Node::expression(Self::digest_tag(), Payload::new(felts))
    }

    /// Build an `eq` predicate over two child digests.
    pub fn eq_node(h_lhs: Digest, h_rhs: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::join(h_lhs, h_rhs))
    }

    /// Decode `[Felt; 8]` digest contents from a canonical `digest` leaf. Errors if `node`
    /// isn't tagged as a `Hash` digest leaf.
    pub fn digest_felts(node: &Node) -> Result<[Felt; 8], DeferredError> {
        if node.tag != Self::digest_tag() {
            return Err(DeferredError::InvalidPayload);
        }
        Ok(*node.payload.as_felts()?)
    }

    /// Mock hash kernel: coordinate-wise sum of all chunks. Not collision-resistant; placeholder
    /// for a real non-native hash.
    pub fn hash(chunks: &[[Felt; 8]]) -> [Felt; 8] {
        let mut acc = [ZERO; 8];
        for c in chunks {
            for (a, x) in acc.iter_mut().zip(c.iter()) {
                *a += *x;
            }
        }
        acc
    }

    /// Number of 8-felt chunks needed to encode `n_bytes` of input.
    pub fn n_chunks(n_bytes: u32) -> u32 {
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
                // `args[1]` carries n_bytes; the chunk count is derived.
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::Chunks(Self::n_chunks(n_bytes)))
            },
            // Self-evaluating leaf carrying 8 raw felts of digest data.
            Discriminant::Digest => Some(NodeType::Value),
            // Binary predicate over two child digests.
            Discriminant::Eq => Some(NodeType::Join),
        }
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        match Discriminant::classify(args[0]).ok_or(PrecompileError::InvalidNode)? {
            Discriminant::Preimage => {
                // Inline hash → canonical digest leaf. No minting needed: the digest IS the
                // canonical payload.
                Ok(Self::digest_node(Self::hash(payload.as_chunks()?)))
            },
            Discriminant::Digest => {
                Ok(Node::expression(Tag::new(Self::id(), args), Payload::new(*payload.as_felts()?)))
            },
            Discriminant::Eq => {
                let (h_lhs, h_rhs) = payload.join_children()?;
                if witness.resolve(h_lhs)? != witness.resolve(h_rhs)? {
                    return Err(PrecompileError::AssertionFailed);
                }
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
