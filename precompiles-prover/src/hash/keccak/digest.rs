//! `KeccakDigest` newtype — the 256-bit Keccak output as four 64-bit
//! lanes.
//!
//! Carried in-memory as `[u64; 4]` and lifted to its 8-felt
//! `(lo, hi)`-halves wire representation at the bus boundary via
//! [`KeccakDigest::to_felts`]. The 4-lane shape mirrors the Keccak
//! state's first 4 rate lanes (the digest portion); the 32-bit halves
//! match the Memory64 lane format used across the chiplets.

use miden_core::Felt;

use crate::utils::split_u64;

/// 256-bit Keccak digest as four 64-bit lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct KeccakDigest(pub [u64; 4]);

impl KeccakDigest {
    /// Extract the digest from a post-permutation Keccak state.
    pub fn from_state(state: &[u64; 25]) -> Self {
        Self([state[0], state[1], state[2], state[3]])
    }

    /// Lift to the 8-felt `(lo_0, hi_0, lo_1, hi_1, …, lo_3, hi_3)`
    /// wire format used by Memory64 reads + the digest-chunk P2 absorption.
    pub fn to_felts(self) -> [Felt; 8] {
        let mut out = [Felt::ZERO; 8];
        for (i, &lane) in self.0.iter().enumerate() {
            let [lo, hi] = split_u64(lane);
            out[2 * i] = lo;
            out[2 * i + 1] = hi;
        }
        out
    }

    /// Same as [`to_felts`](Self::to_felts) but as `[u32; 8]` — the
    /// raw u32 halves before lifting into the field. Used by
    /// `KeccakNodeRequires` to populate `KeccakNodeInvocation.d`.
    pub fn to_u32s(self) -> [u32; 8] {
        let mut out = [0u32; 8];
        for (i, &lane) in self.0.iter().enumerate() {
            out[2 * i] = lane as u32;
            out[2 * i + 1] = (lane >> 32) as u32;
        }
        out
    }
}
