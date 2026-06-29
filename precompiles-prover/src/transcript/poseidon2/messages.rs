//! LogUp messages for the Poseidon2 chiplet.
//!
//! Two messages, one per bus:
//! - [`Poseidon2InMsg`] (bus [`BusId::Poseidon2In`]) carries a 6-tuple
//!   `(perm_seq_id, tag, c0, c1, c2, c3)` with `tag ∈ {0, 1, 2}` selecting
//!   rate0 / rate1 / capacity. The chiplet provides three of these per
//!   active row 0 (chain heads emit all three; chain interiors omit cap).
//! - [`Poseidon2OutMsg`] (bus [`BusId::Poseidon2Out`]) carries a 5-tuple
//!   `(perm_seq_id, d0, d1, d2, d3)` for the post-permutation digest. The
//!   chiplet provides one per active row 15 of a chain-tail cycle.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// Tag value for the `rate0` chunk on [`BusId::Poseidon2In`].
pub const POSEIDON2_IN_TAG_RATE0: u8 = 0;
/// Tag value for the `rate1` chunk on [`BusId::Poseidon2In`].
pub const POSEIDON2_IN_TAG_RATE1: u8 = 1;
/// Tag value for the `capacity` chunk on [`BusId::Poseidon2In`].
pub const POSEIDON2_IN_TAG_CAP: u8 = 2;

/// LogUp message for the `Poseidon2In` relation: a 6-tuple
/// `(perm_seq_id, tag, c0, c1, c2, c3)` carrying one 4-felt chunk of the
/// Poseidon2 input state.
///
/// - `perm_seq_id` — sequential permutation identifier, unique per cycle.
/// - `tag` — chunk selector: `0 = rate0` (state[0..4]),
///   `1 = rate1` (state[4..8]), `2 = capacity` (state[8..12]).
/// - `c0..c3` — the four felts of the selected chunk.
///
/// Encoded as `bus_prefix[Poseidon2In] + β⁰·perm_seq_id + β¹·tag +
/// β²·c0 + β³·c1 + β⁴·c2 + β⁵·c3`.
#[derive(Debug, Clone)]
pub struct Poseidon2InMsg<E> {
    pub perm_seq_id: E,
    pub tag: E,
    pub c: [E; 4],
}

impl<E> Poseidon2InMsg<E>
where
    E: PrimeCharacteristicRing,
{
    /// Build an `InRate0` message.
    pub fn rate0(perm_seq_id: E, chunk: [E; 4]) -> Self {
        Self {
            perm_seq_id,
            tag: E::from_u8(POSEIDON2_IN_TAG_RATE0),
            c: chunk,
        }
    }

    /// Build an `InRate1` message.
    pub fn rate1(perm_seq_id: E, chunk: [E; 4]) -> Self {
        Self {
            perm_seq_id,
            tag: E::from_u8(POSEIDON2_IN_TAG_RATE1),
            c: chunk,
        }
    }

    /// Build an `InCap` message.
    pub fn cap(perm_seq_id: E, chunk: [E; 4]) -> Self {
        Self {
            perm_seq_id,
            tag: E::from_u8(POSEIDON2_IN_TAG_CAP),
            c: chunk,
        }
    }
}

impl<E, EF> LookupMessage<E, EF> for Poseidon2InMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [c0, c1, c2, c3] = self.c.clone();
        challenges.encode(
            BusId::Poseidon2In as usize,
            [self.perm_seq_id.clone(), self.tag.clone(), c0, c1, c2, c3],
        )
    }
}

/// LogUp message for the `Poseidon2Out` relation: a 5-tuple
/// `(perm_seq_id, d0, d1, d2, d3)` carrying the 4-felt digest output of a
/// Poseidon2 permutation.
///
/// The digest is the first 4 lanes of the post-permutation state
/// (`state[0..4]` at row 15 of the cycle). The trailing rate half and
/// post-permutation capacity are not exposed on the bus.
///
/// Encoded as `bus_prefix[Poseidon2Out] + β⁰·perm_seq_id + β¹·d0 + β²·d1 +
/// β³·d2 + β⁴·d3`.
#[derive(Debug, Clone)]
pub struct Poseidon2OutMsg<E> {
    pub perm_seq_id: E,
    pub digest: [E; 4],
}

impl<E, EF> LookupMessage<E, EF> for Poseidon2OutMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [d0, d1, d2, d3] = self.digest.clone();
        challenges.encode(
            BusId::Poseidon2Out as usize,
            [self.perm_seq_id.clone(), d0, d1, d2, d3],
        )
    }
}
