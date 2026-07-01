//! The Binding bus & its value-tag registry.
//!
//! The transcript DAG is *evaluated* by propagating a typed value up
//! from each node to its parents over a single **self-referential**
//! LogUp bus: [`BusId::Binding`]. A node-evaluating chiplet *provides*
//! one [`BindingMsg`] per node it binds and *consumes* its children's
//! bindings; bus balance then means the DAG was evaluated consistently.
//! See [`docs/transcript-eval.md`](../../../docs/transcript-eval.md).
//!
//! A binding is `node_hash ↦ typed value`: `h` is the bus key, the
//! [`ValueTag`] says what kind of value it is, `ptr` is the canonical
//! handle for value-bindings, and `bound_ptr` names the modulus a uint
//! value lives under (both unused — zero — for `True`).

use miden_core::field::{Algebra, PrimeCharacteristicRing};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::BusId,
};

/// Typed value a node binds to on the [`Binding`](BusId::Binding) bus.
///
/// `#[repr(u8)]` lets a variant cast directly (`ValueTag::True as u8`)
/// to the felt the `value_tag` slot holds — mirroring
/// [`NodeTag`](super::nodes::NodeTag).
///
/// The pvm-design's `KeccakDigest` / `Chunks` value variants are
/// deliberately **absent**: a Keccak digest is terminal (only ever
/// consumed by a Keccak relation node), so the Keccak path fuses and
/// never puts a digest or chunks object on the Binding bus as a value —
/// see [`docs/transcript-eval.md`](../../../docs/transcript-eval.md)
/// §"Why Keccak fuses". `Uint` / `Group` are non-terminal and *do* need
/// value-bindings: `Uint` is live (transient uint leaves and the eval
/// chip's `UintOp` results); `Group` lands with the group chiplet.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ValueTag {
    /// An assertion that holds. The transcript is exactly the `True`
    /// slice of the Binding bus.
    True = 0,
    /// A uint value-binding (the uint chiplet).
    Uint = 1,
    /// A group-element value-binding (future group chiplet).
    Group = 2,
}

/// LogUp message for the [`Binding`](BusId::Binding) relation: a 7-tuple
/// `(h0, h1, h2, h3, value_tag, ptr, bound_ptr)` binding a node's 4-felt
/// hash to a typed value.
///
/// - `h` — the node's hash (`Poseidon2(preimage)[0..4]`), the bus key.
/// - `value_tag` — the [`ValueTag`] discriminant.
/// - `ptr` — canonical value handle for value-bindings; `0` for `True`.
/// - `bound_ptr` — for a `Uint` value, the ptr of the uint storing its modulus `p − 1`; `0` for
///   `True`.
///
/// Encoded as `bus_prefix[Binding] + β⁰·h0 + β¹·h1 + β²·h2 + β³·h3 +
/// β⁴·value_tag + β⁵·ptr + β⁶·bound_ptr`.
#[derive(Debug, Clone)]
pub struct BindingMsg<E> {
    pub h: [E; 4],
    pub value_tag: E,
    pub ptr: E,
    pub bound_ptr: E,
}

impl<E> BindingMsg<E>
where
    E: PrimeCharacteristicRing,
{
    /// Bind a node hash to `True` (an assertion). `ptr` / `bound_ptr`
    /// are unused (`0`).
    pub fn truth(h: [E; 4]) -> Self {
        Self {
            h,
            value_tag: E::from_u8(ValueTag::True as u8),
            ptr: E::ZERO,
            bound_ptr: E::ZERO,
        }
    }

    /// Bind a node hash to a `Uint` value interned at `ptr`, whose
    /// modulus `p − 1` is the uint stored at `bound_ptr`.
    pub fn uint(h: [E; 4], ptr: E, bound_ptr: E) -> Self {
        Self {
            h,
            value_tag: E::from_u8(ValueTag::Uint as u8),
            ptr,
            bound_ptr,
        }
    }

    /// Bind a node hash to a `Group` value — the stored curve point
    /// interned at `point_ptr`. Curve context is pinned by the node's EC
    /// relation plumbing (`EcCreate`, `EcBinOp`, or `EcMsm`), not this
    /// tuple, so no group handle rides the bus: `bound_ptr` is `0`, like
    /// `True`.
    pub fn group(h: [E; 4], point_ptr: E) -> Self {
        Self {
            h,
            value_tag: E::from_u8(ValueTag::Group as u8),
            ptr: point_ptr,
            bound_ptr: E::ZERO,
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
            [h0, h1, h2, h3, self.value_tag.clone(), self.ptr.clone(), self.bound_ptr.clone()],
        )
    }
}
