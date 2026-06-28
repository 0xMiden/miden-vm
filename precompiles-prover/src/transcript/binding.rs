//! The Binding bus & its value-tag registry.
//!
//! The transcript DAG is *evaluated* by propagating a typed value up
//! from each node to its parents over a single **self-referential**
//! LogUp bus: [`BusId::Binding`]. A node-evaluating chiplet *provides*
//! one [`BindingMsg`] per node it binds and *consumes* its children's
//! bindings; bus balance then means the DAG was evaluated consistently.
//! See [`docs/transcript-eval.md`](../../../docs/transcript-eval.md).
//!
//! A binding is `node_hash ↦ typed value`: `h` is the bus key, and the
//! [`ValueTag`] says what kind of value it is.

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// Typed value a node binds to on the [`Binding`](BusId::Binding) bus.
///
/// `#[repr(u8)]` lets a variant cast directly (`ValueTag::True as u8`)
/// to the felt the `kind` slot holds.
///
/// The pvm-design's `KeccakDigest` / `Chunks` value variants are
/// deliberately **absent**: a Keccak digest is terminal (only ever
/// consumed by a Keccak relation node), so the Keccak path fuses and
/// never puts a digest or chunks object on the Binding bus as a value.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValueTag {
    /// An assertion that holds. The transcript is exactly the `True`
    /// slice of the Binding bus.
    True = 0,
}

/// LogUp message for the [`Binding`](BusId::Binding) relation: a 7-tuple
/// `(h0, h1, h2, h3, kind, ptr, domain_id)` binding a node's 4-felt hash
/// to a typed value.
///
/// - `h` — the node's hash (`Poseidon2(preimage)[0..4]`), the bus key.
/// - `kind` — the [`ValueTag`] discriminant.
/// - `ptr` / `domain_id` — reserved for future value bindings and zero for `True`.
///
/// Encoded as `bus_prefix[Binding] + β⁰·h0 + β¹·h1 + β²·h2 + β³·h3 +
/// β⁴·kind + β⁵·ptr + β⁶·domain_id`.
#[derive(Debug, Clone)]
pub struct BindingMsg<E> {
    pub h: [E; 4],
    pub kind: E,
    pub ptr: E,
    pub domain_id: E,
}

impl<E> BindingMsg<E>
where
    E: PrimeCharacteristicRing,
{
    /// Bind a node hash to `True` (an assertion). `ptr` / `domain_id`
    /// are unused (`0`).
    pub fn truth(h: [E; 4]) -> Self {
        Self {
            h,
            kind: E::from_u8(ValueTag::True as u8),
            ptr: E::ZERO,
            domain_id: E::ZERO,
        }
    }
}

impl<E, EF> LookupMessage<E, EF> for BindingMsg<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &Challenges<EF>) -> EF {
        let [h0, h1, h2, h3] = self.h.clone();
        challenges.encode(
            BusId::Binding as usize,
            [h0, h1, h2, h3, self.kind.clone(), self.ptr.clone(), self.domain_id.clone()],
        )
    }
}
