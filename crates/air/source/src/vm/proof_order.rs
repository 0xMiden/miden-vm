use miden_ace::factorial;

use crate::MidenAir;

/// Supported AIRs in instance order.
///
/// This order is used for per-AIR inputs and breaks proof-order ties when trace heights are equal.
pub const AIRS: [MidenAir; 4] = [
    MidenAir::Core,
    MidenAir::Chiplets,
    MidenAir::EidosCompression,
    MidenAir::And8Lookup,
];

pub const MIDEN_AIR_COUNT: usize = AIRS.len();

/// Number of possible proof-order permutations.
pub const PROOF_ORDER_COUNT: usize = factorial(MIDEN_AIR_COUNT);
const _: () = assert!(PROOF_ORDER_COUNT <= u32::MAX as usize, "proof-order tags must fit in u32");

/// Proof-order AIR permutation relative to this enum's independent [`AIRS`] contract.
pub type ProofOrder = miden_ace::ProofOrder<MidenAir, MIDEN_AIR_COUNT>;

impl miden_ace::ProofOrderAir<MIDEN_AIR_COUNT> for MidenAir {
    const INSTANCE_ORDER: [Self; MIDEN_AIR_COUNT] = AIRS;

    fn instance_index(self) -> usize {
        MidenAir::instance_index(self)
    }

    fn file_token(self) -> &'static str {
        MidenAir::file_token(self)
    }
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

    /// `AIRS` fixes proof-order tie-breaks and the relation digest. Pin it independently of
    /// `instance_index`; intentional changes require regenerated protocol constants and a
    /// breaking changelog entry.
    #[test]
    fn air_instance_order_is_protocol_pinned() {
        const PINNED: [MidenAir; MIDEN_AIR_COUNT] = [
            MidenAir::Core,
            MidenAir::Chiplets,
            MidenAir::EidosCompression,
            MidenAir::And8Lookup,
        ];
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
            ProofOrder::from_instance_log_heights(&[8, 9, 10, 11]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::EidosCompression,
                MidenAir::And8Lookup,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[9, 8, 10, 11]),
            ProofOrder::from_airs(&[
                MidenAir::Chiplets,
                MidenAir::Core,
                MidenAir::EidosCompression,
                MidenAir::And8Lookup,
            ])
        );
        assert_eq!(
            ProofOrder::from_instance_log_heights(&[8, 8, 8, 8]),
            ProofOrder::from_airs(&[
                MidenAir::Core,
                MidenAir::Chiplets,
                MidenAir::EidosCompression,
                MidenAir::And8Lookup,
            ])
        );
    }
}
