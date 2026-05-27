//! SHA-512 precompile.
//!
//! Tag layout — `Tag { id, args: [node_disc, arg1, ZERO] }`:
//!
//! - `preimage` (disc 0, chunk-bodied): `arg1 = n_bytes`; chunks carry the preimage. Reduces to a
//!   `digest` chunk leaf (16 felts = 2 chunks).
//! - `digest` (disc 1, `Chunks(2)` self-eval): 64-byte SHA-512 digest packed as 16 u32 felts.
//! - `eq` (disc 2, binary predicate): compares two `digest` children.

use alloc::sync::Arc;
use core::num::NonZeroU32;

use miden_core::{
    Felt, ZERO,
    deferred::{
        Digest, Node, NodeType, Payload, Precompile, PrecompileError, Tag, WitnessBuilder,
        precompile_id,
    },
};
use miden_crypto::hash::sha2::Sha512;

use super::codec::{bytes_to_felts, chunks_to_bytes, n_chunks};

/// Zero-sized handle for the `sha512` precompile.
#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512Precompile;

impl Sha512Precompile {
    /// Precompile name — hashed into `id`. Renaming breaks decoding for existing programs.
    pub const NAME: &'static str = "sha512";

    pub const PREIMAGE_TAG_ID: u32 = 0;
    pub const DIGEST_TAG_ID: u32 = 1;
    pub const EQ_TAG_ID: u32 = 2;

    pub fn id() -> Felt {
        precompile_id(&Sha512Precompile)
    }

    pub fn preimage_tag(n_bytes: u32) -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::PREIMAGE_TAG_ID), Felt::from_u32(n_bytes), ZERO],
        }
    }

    pub fn digest_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::DIGEST_TAG_ID), ZERO, ZERO],
        }
    }

    pub fn eq_tag() -> Tag {
        Tag {
            id: Self::id(),
            args: [Felt::from_u32(Self::EQ_TAG_ID), ZERO, ZERO],
        }
    }

    pub fn preimage_node(n_bytes: u32, chunks: impl Into<Arc<[[Felt; 8]]>>) -> Node {
        Node::chunk(Self::preimage_tag(n_bytes), chunks)
    }

    /// Build a canonical `digest` chunk leaf from the 16-felt u32-packed digest.
    pub fn digest_node(felts: [Felt; 16]) -> Node {
        let chunks = [core::array::from_fn(|i| felts[i]), core::array::from_fn(|i| felts[8 + i])];
        Node::chunk(Self::digest_tag(), chunks.to_vec())
    }

    pub fn eq_node(lhs: Digest, rhs: Digest) -> Node {
        Node::expression(Self::eq_tag(), Payload::join(lhs, rhs))
    }
}

impl Precompile for Sha512Precompile {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn id(&self) -> Felt {
        Self::id()
    }

    fn decode(&self, args: [Felt; 3]) -> Option<NodeType> {
        let disc = u32::try_from(args[0].as_canonical_u64()).ok()?;
        match disc {
            Self::PREIMAGE_TAG_ID => {
                let n_bytes = u32::try_from(args[1].as_canonical_u64()).ok()?;
                Some(NodeType::Chunks(n_chunks(n_bytes)))
            },
            // 64-byte SHA-512 digest packed as 16 u32 felts → 2 chunks of 8 felts.
            Self::DIGEST_TAG_ID => {
                Some(NodeType::Chunks(NonZeroU32::new(2).expect("2 is nonzero")))
            },
            Self::EQ_TAG_ID => Some(NodeType::Join),
            _ => None,
        }
    }

    fn reduce(
        &self,
        args: [Felt; 3],
        payload: &Payload,
        witness: &mut WitnessBuilder<'_>,
    ) -> Result<Node, PrecompileError> {
        let disc =
            u32::try_from(args[0].as_canonical_u64()).map_err(|_| PrecompileError::InvalidNode)?;
        match disc {
            Self::PREIMAGE_TAG_ID => reduce_preimage(args, payload),
            Self::DIGEST_TAG_ID => {
                // Chunk-bodied self-evaluating leaf. `decode` already pinned the chunk count to 2.
                let chunks = payload.as_chunks()?;
                Ok(Node::chunk(Tag::new(Self::id(), args), Arc::from(chunks)))
            },
            Self::EQ_TAG_ID => reduce_eq(payload, witness),
            _ => Err(PrecompileError::InvalidNode),
        }
    }
}

fn reduce_preimage(args: [Felt; 3], payload: &Payload) -> Result<Node, PrecompileError> {
    let n_bytes = u32::try_from(args[1].as_canonical_u64())
        .map_err(|_| PrecompileError::InvalidNode)? as usize;
    let bytes = chunks_to_bytes(payload.as_chunks()?, n_bytes)?;
    let digest_bytes = Sha512::hash(&bytes);
    Ok(Sha512Precompile::digest_node(bytes_to_felts::<16>(&digest_bytes)))
}

fn reduce_eq(payload: &Payload, witness: &mut WitnessBuilder<'_>) -> Result<Node, PrecompileError> {
    let (lhs_digest, rhs_digest) = payload.join_children()?;
    let lhs = witness.resolve(lhs_digest)?;
    let rhs = witness.resolve(rhs_digest)?;
    if lhs.tag != Sha512Precompile::digest_tag() || rhs.tag != Sha512Precompile::digest_tag() {
        return Err(PrecompileError::InvalidNode);
    }
    if lhs.payload.as_chunks()? != rhs.payload.as_chunks()? {
        return Err(PrecompileError::AssertionFailed);
    }
    Ok(Node::TRUE)
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{
        deferred::{DeferredState, PrecompileRegistry},
        utils::bytes_to_packed_u32_elements,
    };

    use super::*;

    #[test]
    fn decode_preimage_carries_n_bytes_in_args() {
        let info = Sha512Precompile
            .decode([Felt::from_u32(Sha512Precompile::PREIMAGE_TAG_ID), Felt::from_u32(100), ZERO])
            .unwrap();
        // 100 bytes → ceil(100/32) = 4 chunks.
        assert!(matches!(info, NodeType::Chunks(n) if n.get() == 4));
    }

    #[test]
    fn decode_digest_is_2_chunk_self_eval() {
        let info = Sha512Precompile
            .decode([Felt::from_u32(Sha512Precompile::DIGEST_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Chunks(n) if n.get() == 2));
    }

    #[test]
    fn decode_eq_is_binary_predicate() {
        let info = Sha512Precompile
            .decode([Felt::from_u32(Sha512Precompile::EQ_TAG_ID), ZERO, ZERO])
            .unwrap();
        assert!(matches!(info, NodeType::Join));
    }

    fn pack_chunks(bytes: &[u8]) -> Vec<[Felt; 8]> {
        let felts = bytes_to_packed_u32_elements(bytes);
        let n_chunks = felts.len().div_ceil(8);
        let mut padded = felts;
        padded.resize(n_chunks * 8, ZERO);
        padded.chunks_exact(8).map(|c| core::array::from_fn(|i| c[i])).collect()
    }

    fn fresh_state() -> (PrecompileRegistry, DeferredState) {
        (
            PrecompileRegistry::default().with_precompile(Sha512Precompile),
            DeferredState::new(),
        )
    }

    fn sha512_known(input: &[u8]) -> Node {
        let digest_bytes = Sha512::hash(input);
        Sha512Precompile::digest_node(bytes_to_felts::<16>(&digest_bytes))
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_empty() {
        let (precompiles, mut state) = fresh_state();
        let expected = sha512_known(&[]);
        // Empty input still needs one chunk (empty chunk bodies are banned); a 0-byte preimage is
        // a single zero chunk.
        let node = Sha512Precompile::preimage_node(0, vec![[ZERO; 8]]);
        let canonical = state.evaluate(&precompiles, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_short() {
        let (precompiles, mut state) = fresh_state();
        let bytes = b"hello world";
        let expected = sha512_known(bytes);
        let chunks = pack_chunks(bytes);
        let node = Sha512Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&precompiles, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn preimage_reduces_to_digest_leaf_multi_chunk() {
        let (precompiles, mut state) = fresh_state();
        let bytes: Vec<u8> = (0u8..100).collect();
        let expected = sha512_known(&bytes);
        let chunks = pack_chunks(&bytes);
        let node = Sha512Precompile::preimage_node(bytes.len() as u32, chunks);
        let canonical = state.evaluate(&precompiles, node).unwrap();
        assert_eq!(canonical, expected);
    }

    #[test]
    fn digest_leaf_is_self_evaluating() {
        let (precompiles, mut state) = fresh_state();
        let felts: [Felt; 16] = core::array::from_fn(|i| Felt::from_u32(i as u32));
        let leaf = Sha512Precompile::digest_node(felts);
        let leaf_digest = state.register(&precompiles, leaf.clone()).unwrap();
        let canonical =
            state.evaluate(&precompiles, state.get(&leaf_digest).unwrap().clone()).unwrap();
        assert_eq!(canonical, leaf);
    }

    #[test]
    fn eq_succeeds_on_matching_preimage_and_digest() {
        let (precompiles, mut state) = fresh_state();
        let bytes = b"some sha512 input";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&precompiles, Sha512Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let leaf_digest = state.register(&precompiles, sha512_known(bytes)).unwrap();
        let eq = Sha512Precompile::eq_node(preimage_digest, leaf_digest);
        let result = state.evaluate(&precompiles, eq).unwrap();
        assert!(result.is_true_node());
    }

    #[test]
    fn eq_fails_on_mismatched_digest_claim() {
        let (precompiles, mut state) = fresh_state();
        let bytes = b"a";
        let chunks = pack_chunks(bytes);
        let preimage_digest = state
            .register(&precompiles, Sha512Precompile::preimage_node(bytes.len() as u32, chunks))
            .unwrap();
        let wrong_leaf = Sha512Precompile::digest_node([Felt::from_u32(0xdead); 16]);
        let wrong_digest = state.register(&precompiles, wrong_leaf).unwrap();
        let eq = Sha512Precompile::eq_node(preimage_digest, wrong_digest);
        let err = state.evaluate(&precompiles, eq);
        assert!(matches!(err.unwrap_err().root(), PrecompileError::AssertionFailed));
    }
}
