//! Concrete VM configuration and setup policy.

#[cfg(all(feature = "std", feature = "prover"))]
pub(crate) mod preprocessed;

pub mod ace;

pub mod config {
    pub use miden_air::vm::config::*;
    use miden_core::program::domain::STARK_TRANSCRIPT;
    pub use miden_stark::config::{
        Blake3Config, EidosConfig, EidosLmcs, KeccakConfig, MidenStarkConfig, RelationDigest,
        blake3_256_config, keccak_config, observe_protocol_params, relation_digest,
    };
    use miden_stark::pcs::PcsParams;

    /// Creates the Eidos configuration bound to the VM transcript domain.
    pub fn eidos_config(params: PcsParams, relation_digest: RelationDigest) -> EidosConfig {
        miden_stark::config::eidos_config(params, relation_digest, STARK_TRANSCRIPT)
    }

    #[cfg(test)]
    mod tests {
        use alloc::vec;

        use miden_air::vm::{MidenMultiAir, NUM_PUBLIC_VALUES, Statement};
        use miden_core::{Felt, field::QuadFelt};
        use miden_stark::{Preprocessed, StarkConfig, lmcs::Lmcs};
        const UPDATE_HINT: &str =
            "an intentional relation change must update the production pins and verifier root";
        /// The And8 setup commitment the given configuration builds from the canonical VM setup.
        fn canonical_setup_commitment<SC: StarkConfig<Felt, QuadFelt>>(
            config: &SC,
        ) -> <SC::Lmcs as Lmcs>::Commitment {
            let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
                MidenMultiAir::new(),
                vec![(0, vec![Felt::ZERO; NUM_PUBLIC_VALUES])],
                vec![],
            )
            .expect("canonical VM statement");
            Preprocessed::build(&statement, config).expect("fixed And8 setup").commitment()
        }

        /// Each pinned And8 setup commitment must be the one its configuration builds from the
        /// canonical VM setup.
        macro_rules! setup_commitment_matches_canonical_setup {
            ($test:ident, $config:ident, $pinned:ident, $repr:ty) => {
                #[test]
                fn $test() {
                    let config = super::$config(super::pcs_params(), super::RELATION_DIGEST);
                    assert_eq!(
                        <$repr>::from(canonical_setup_commitment(&config)),
                        super::$pinned,
                        "{} is stale; {UPDATE_HINT}",
                        stringify!($pinned)
                    );
                }
            };
        }

        setup_commitment_matches_canonical_setup!(
            blake3_setup_commitment_is_current,
            blake3_256_config,
            BLAKE3_PREPROCESSED_COMMITMENT,
            [u8; 32]
        );
        setup_commitment_matches_canonical_setup!(
            eidos_setup_commitment_is_current,
            eidos_config,
            EIDOS_PREPROCESSED_COMMITMENT,
            [u64; 4]
        );
        setup_commitment_matches_canonical_setup!(
            keccak_setup_commitment_is_current,
            keccak_config,
            KECCAK_PREPROCESSED_COMMITMENT,
            [u64; 4]
        );
    }
}

/// Supplies the canonical VM memory model and caller-selected byte limit.
pub fn proving_budget(limit_bytes: u64) -> miden_stark::memory::ProvingBudget<4> {
    crate::memory::canonical_budget(limit_bytes)
}
