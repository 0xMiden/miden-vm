use alloc::{string::String, vec::Vec};

use miden_ace_codegen::{ceil_log2, factorial, order_from_tag, order_tag};

use crate::MidenAir;

/// Supported AIRs in instance order.
///
/// This order is used for per-AIR inputs and breaks proof-order ties when trace heights are equal.
pub const AIRS: [MidenAir; 3] =
    [MidenAir::Core, MidenAir::Chiplets, MidenAir::Poseidon2Permutation];

pub const MIDEN_AIR_COUNT: usize = AIRS.len();

/// Number of possible proof-order permutations.
pub const PROOF_ORDER_COUNT: usize = factorial(MIDEN_AIR_COUNT);
const _: () = assert!(PROOF_ORDER_COUNT <= u32::MAX as usize, "proof-order tags must fit in u32");

/// Smallest Merkle tree depth covering every proof-order tag.
pub const PROOF_ORDER_REGISTRY_DEPTH: usize = ceil_log2(PROOF_ORDER_COUNT);

/// Proof-order AIR permutation.
///
/// The proof stores AIR commitments in ascending `(log_trace_height, instance_index)` order. That
/// order can vary by statement, so the recursive verifier selects one ACE circuit from a small
/// registry. The registry key is `tag`, the Lehmer rank of the AIR permutation relative to
/// [`AIRS`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofOrder {
    airs: [MidenAir; MIDEN_AIR_COUNT],
    tag: u32,
}

impl ProofOrder {
    /// Construct a proof order from an explicit AIR permutation.
    ///
    /// Panics if an AIR is missing or duplicated.
    pub fn new(airs: [MidenAir; MIDEN_AIR_COUNT]) -> Self {
        assert_is_air_permutation(airs);
        let tag = lehmer_rank(airs);
        Self { airs, tag }
    }

    /// Construct a proof order from a slice containing every supported AIR exactly once.
    pub fn from_airs(airs: &[MidenAir]) -> Self {
        let Ok(airs) = airs.try_into() else {
            panic!("proof order must include every AIR exactly once");
        };
        Self::new(airs)
    }

    /// Return the canonical instance order from [`AIRS`].
    pub fn instance_order() -> Self {
        Self::new(AIRS)
    }

    /// Return every supported proof order, sorted by tag.
    pub fn variants() -> Vec<Self> {
        (0..PROOF_ORDER_COUNT).map(Self::from_rank).collect()
    }

    /// Decode a registry tag into a proof order.
    pub fn from_tag(tag: u32) -> Option<Self> {
        let rank = tag as usize;
        (rank < PROOF_ORDER_COUNT).then(|| Self::from_rank(rank))
    }

    /// Sort AIRs by trace height, using instance order as the tie-breaker.
    ///
    /// `log_heights` must be in [`AIRS`] order.
    pub fn from_instance_log_heights(log_heights: &[u8]) -> Self {
        assert_eq!(log_heights.len(), AIRS.len(), "one log height is required per AIR");

        let mut ordered: Vec<(MidenAir, u8)> =
            AIRS.iter().copied().zip(log_heights.iter().copied()).collect();
        ordered.sort_by_key(|(air, height)| (*height, air.instance_index()));

        let mut airs = [AIRS[0]; MIDEN_AIR_COUNT];
        for (dst, (air, _)) in airs.iter_mut().zip(ordered) {
            *dst = air;
        }
        Self::new(airs)
    }

    /// AIRs in the order used by the proof.
    pub fn airs(&self) -> &[MidenAir] {
        &self.airs
    }

    /// Registry tag for this proof order.
    pub fn tag(&self) -> u32 {
        self.tag
    }

    /// File stem for the generated ACE circuit for this order.
    pub fn file_stem(&self) -> String {
        let mut stem = String::from("constraints_eval_");
        for (i, air) in self.airs.iter().copied().enumerate() {
            if i > 0 {
                stem.push_str("_then_");
            }
            stem.push_str(air.file_token());
        }
        stem
    }

    /// Decode a Lehmer rank into its AIR permutation.
    fn from_rank(rank: usize) -> Self {
        debug_assert!(rank < PROOF_ORDER_COUNT);
        let tag = u32::try_from(rank).expect("proof-order tags fit in u32");
        let instance_order = order_from_tag(tag, MIDEN_AIR_COUNT).expect("rank is in range");
        let mut airs = [AIRS[0]; MIDEN_AIR_COUNT];
        for (slot, index) in airs.iter_mut().zip(instance_order) {
            *slot = AIRS[index];
        }
        Self { airs, tag }
    }
}

/// Assert that `airs` contains every supported AIR exactly once.
fn assert_is_air_permutation(airs: [MidenAir; MIDEN_AIR_COUNT]) {
    let mut seen = [false; MIDEN_AIR_COUNT];
    for air in &airs {
        let index = air.instance_index();
        assert!(!seen[index], "proof order contains duplicate AIR: {air:?}");
        seen[index] = true;
    }
}

/// Return the registry tag of an AIR permutation relative to [`AIRS`].
///
/// Delegates to the shared Lehmer ranking so this registry and the precompile VM registry
/// index their leaves by exactly the same rule.
fn lehmer_rank(airs: [MidenAir; MIDEN_AIR_COUNT]) -> u32 {
    let instance_order: Vec<usize> = airs.iter().map(|air| air.instance_index()).collect();
    order_tag(&instance_order)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `variants()` gets its tags from the decoder, so round-trip through `ProofOrder::new`
    /// to exercise the encoder independently.
    #[test]
    fn lehmer_encoder_inverts_the_decoder_for_every_tag() {
        for tag in 0..PROOF_ORDER_COUNT as u32 {
            let order = ProofOrder::from_tag(tag).expect("tag in range");
            let airs: [MidenAir; MIDEN_AIR_COUNT] =
                order.airs().try_into().expect("order holds one AIR per slot");
            assert_eq!(
                ProofOrder::new(airs).tag(),
                tag,
                "encoder does not invert the decoder at tag {tag}"
            );
        }
    }

    /// `AIRS` fixes proof-order tie-breaks, registry tags, and the relation digest. Pin it
    /// independently of `instance_index`; intentional changes require regenerated protocol
    /// constants and a breaking changelog entry.
    #[test]
    fn air_instance_order_is_protocol_pinned() {
        const PINNED: [MidenAir; MIDEN_AIR_COUNT] =
            [MidenAir::Core, MidenAir::Chiplets, MidenAir::Poseidon2Permutation];
        assert_eq!(
            AIRS, PINNED,
            "AIRS instance order moved; regenerate protocol constants for an intentional change"
        );
        for (index, air) in AIRS.iter().copied().enumerate() {
            assert_eq!(air.instance_index(), index);
        }
    }

    #[test]
    fn proof_order_constants_derive_from_air_count() {
        assert_eq!(PROOF_ORDER_COUNT, ProofOrder::variants().len());
        assert_eq!(PROOF_ORDER_REGISTRY_DEPTH, ceil_log2(PROOF_ORDER_COUNT));
    }

    #[test]
    fn proof_order_count_is_factorial() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(2), 2);
        assert_eq!(factorial(3), 6);
        assert_eq!(factorial(4), 24);
    }

    #[test]
    fn registry_depth_is_ceil_log2() {
        assert_eq!(ceil_log2(1), 0);
        assert_eq!(ceil_log2(2), 1);
        assert_eq!(ceil_log2(3), 2);
        assert_eq!(ceil_log2(6), 3);
        assert_eq!(ceil_log2(24), 5);
    }

    #[test]
    fn proof_order_tags_use_lehmer_rank() {
        let variants = ProofOrder::variants();

        assert_eq!(variants.len(), PROOF_ORDER_COUNT);
        assert_eq!(variants[0], ProofOrder::instance_order());
        for (tag, order) in variants.into_iter().enumerate() {
            assert_eq!(order.tag(), tag as u32);
            assert_eq!(ProofOrder::from_tag(tag as u32), Some(order));
        }
        assert_eq!(ProofOrder::from_tag(PROOF_ORDER_COUNT as u32), None);
    }

    #[test]
    fn proof_order_sorts_by_height_then_instance_index() {
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 9, 10]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::Poseidon2Permutation,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[9, 8, 10]),
            ProofOrder::from_airs(&[
                MidenAir::Chiplets,
                MidenAir::Core,
                MidenAir::Poseidon2Permutation,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 8, 8]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::Poseidon2Permutation,
            ])
        );
    }
}
