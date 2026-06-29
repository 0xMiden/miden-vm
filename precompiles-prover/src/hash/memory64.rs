//! 64-bit memory bus message.
//!
//! Inter-chiplet bus carrying tuples `(addr, lo, hi)` where:
//!
//! - `addr` is a felt-valued cell address.
//! - `lo, hi ∈ [0, 2^32)` are the 32-bit halves of a 64-bit cell value.
//!
//! Bus discipline: the LogUp bus balances *per* `(addr, lo, hi)` tuple
//! — each distinct encoded message is its own term in the running sum.
//! Two providers writing the same address with different values are
//! two independent bus entries.
//!
//! In the Keccak round chiplet, intra-permutation cells are used
//! single-assignment-style (one provide per IP at some multiplicity,
//! matching consumer reads). At permutation boundaries the sponge AIR
//! exploits the multiset semantics to overwrite state: consume
//! `(X, perm_N_out)` and provide `(X, perm_N_out ⊕ block)` at the
//! same `X`, two different bus entries each balancing independently.
//! See `docs/chiplets/keccak.md` for the boundary tuple math.
//!
//! The `64` suffix anticipates future memory buses with different word
//! widths; this one carries 64-bit values.

use miden_core::field::Algebra;

use crate::logup::{Challenges, LookupMessage};
use crate::relations::BusId;

/// Base address for the chunk chiplet's flat input-tape sub-namespace.
/// The chunk chiplet provides input lanes on
/// `[CHUNK_ADDR_BASE, CHUNK_ADDR_BASE + N)`; the consuming hasher
/// (currently the Keccak sponge, via its `chunk_ptr` cursor) reads
/// them back. Chosen well above any hasher IP range (Keccak sponge
/// IPs are `100 · sponge_seq_id ± O(p_idx)`, capped at ~2^39 for any
/// practical trace) to avoid bus collisions. Lives here, in the
/// shared memory-bus namespace map, so multiple hashers can carve out
/// their own input sub-namespaces without coupling to one another.
pub const CHUNK_ADDR_BASE: u64 = 1u64 << 48;

/// LogUp message for the 64-bit memory bus: a 3-tuple `(addr, lo, hi)`.
///
/// Provided on [`BusId::Memory64`]. Encoded as
/// `bus_prefix[Memory64] + β⁰·addr + β¹·lo + β²·hi`. Two messages
/// with the same `addr` but different `(lo, hi)` are distinct bus
/// entries.
#[derive(Debug, Clone)]
pub struct Memory64Msg<E> {
    pub addr: E,
    pub lo: E,
    pub hi: E,
}

impl<E, EF> LookupMessage<E, EF> for Memory64Msg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Memory64 as usize,
            [self.addr.clone(), self.lo.clone(), self.hi.clone()],
        )
    }
}
