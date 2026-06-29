//! Chunk chiplet bus messages.
//!
//! [`ChunkChainMsg`] — the per-invocation chain-binding tuple. Pairs
//! the chunk-side `chunk_seq_id_head` (chunk-chiplet's native index)
//! with the `perm_seq_id_head` (the Poseidon2 cycle where the chain's
//! `InCap` fires). Provided at every absorption-chain head; consumed
//! by hasher-orchestration chiplets (Keccak, …) to bind their
//! per-invocation `chunk_ptr_head = 4·chunk_seq_id_head` to the
//! matching P2 chain. Exposing the chunk-chiplet's native index
//! (rather than `chunk_ptr`) keeps the bus hasher-agnostic — the
//! consumer multiplies by its own lane width — and forbids
//! inter-chunk addresses by construction. See `docs/chiplets/chunk.md`.

use miden_core::field::Algebra;

use crate::logup::{Challenges, LookupMessage};
use crate::relations::BusId;

/// LogUp message for the [`ChunkChain`](BusId::ChunkChain) relation: a
/// 2-tuple `(chunk_seq_id_head, perm_seq_id_head)` binding the head of
/// one absorption chain.
///
/// Provided by the chunk chiplet with multiplicity `−act·is_head` at
/// each chain head; consumed by hasher-orchestration chiplets at their
/// per-invocation rows. Encoded as
/// `bus_prefix[ChunkChain] + β⁰·chunk_seq_id_head + β¹·perm_seq_id_head`.
#[derive(Debug, Clone)]
pub struct ChunkChainMsg<E> {
    pub chunk_seq_id_head: E,
    pub perm_seq_id_head: E,
}

impl<E, EF> LookupMessage<E, EF> for ChunkChainMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::ChunkChain as usize,
            [
                self.chunk_seq_id_head.clone(),
                self.perm_seq_id_head.clone(),
            ],
        )
    }
}
