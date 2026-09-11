//! `KeccakSponge` bus message.
//!
//! Per-invocation request tuple carrying:
//!
//! - `sponge_seq_id` — the sponge row at which the invocation's first block begins absorbing (= the
//!   sponge's row counter at that row). The transcript chiplet uses it to derive the digest address
//!   in the round chiplet's IP space.
//! - `chunk_ptr` — the chunk-tape base offset for this invocation (= the sponge's `chunk_ptr`
//!   cursor value at that row). Shared identifier with the chunk chiplet's per-invocation segment
//!   base; pins the sponge's `chunk_ptr` at the invocation start (the `chunk_ptr` chain is relaxed
//!   at invocation seams — see the design notes).
//! - `len_bytes` — the length of the input in bytes; flows directly into the sponge's
//!   `bytes_left_0` witness column on consume.
//!
//! Provided by the transcript chiplet (or whatever orchestrator
//! triggers Keccak), consumed by the sponge chiplet at the first row
//! of each invocation (`is_first_row_of_invocation = 1`).
//!
//! See the design notes for the role this message
//! plays in pinning the invocation's start, `chunk_ptr` base, and
//! `bytes_left_0`.

use miden_core::field::Algebra;

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// LogUp message for the per-invocation Keccak sponge request: a 3-tuple
/// `(sponge_seq_id, chunk_ptr, len_bytes)`.
///
/// Provided on [`BusId::KeccakSponge`]. Encoded as
/// `bus_prefix[KeccakSponge] + β⁰·sponge_seq_id + β¹·chunk_ptr +
/// β²·len_bytes`. Each invocation produces exactly one such tuple,
/// consumed by the sponge on the row where `sponge_seq_id` matches the
/// row counter.
#[derive(Debug, Clone)]
pub struct KeccakSpongeMsg<E> {
    pub sponge_seq_id: E,
    pub chunk_ptr: E,
    pub len_bytes: E,
}

impl<E, EF> LookupMessage<E, EF> for KeccakSpongeMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::KeccakSponge as usize,
            [self.sponge_seq_id.clone(), self.chunk_ptr.clone(), self.len_bytes.clone()],
        )
    }
}
