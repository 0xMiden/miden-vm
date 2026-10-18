//! Process-lifetime caching of the chiplet stack's preprocessed bundle.
//!
//! `Preprocessed::build` LDEs and commits the fixed `BytePairLut` table — a
//! pure function of the selected chiplet list and the STARK config's
//! blowup/LMCS/DFT — yet both `prove_stark` and `verify_stark` rebuild it on
//! every call. Under `std`, each hash function's bundle is built once per process and reused
//! via `OnceLock`. Variants share its raw table and committed tree through lightweight AIR-slot
//! views. Without `std` (e.g. a `no_std` verifier target), every call rebuilds the selected bundle.

use alloc::vec;
use core::ops::Deref;

#[cfg(any(test, feature = "std"))]
use miden_air::precompile::ChipletAir;
use miden_air::precompile::{
    ChipletMultiAir, PvmAirVariant,
    logup::NUM_PUBLIC_VALUES,
    stark_config::{
        Blake3Config, EidosConfig, KeccakConfig, Poseidon2Config, RpoConfig, RpxConfig,
        blake3_256_config, eidos_config, keccak_config, poseidon2_config, precompile_pcs_params,
        rpo_config, rpx_config,
    },
};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{Preprocessed, StarkConfig, air::Statement, lmcs::Lmcs};

/// Either a process-cached (`std`) or freshly built (`no_std`) bundle;
/// callers dereference to the underlying [`Preprocessed`] either way.
pub enum PreprocessedHandle<'a, L>
where
    L: Lmcs<F = Felt>,
{
    // Only constructed when the `std` feature is enabled (see `cached_preprocessed!` below).
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    Cached(&'a Preprocessed<Felt, L>),
    // Only constructed when the `std` feature is disabled (see `cached_preprocessed!` below).
    #[cfg_attr(feature = "std", allow(dead_code))]
    Owned(Preprocessed<Felt, L>),
}

impl<L> Deref for PreprocessedHandle<'_, L>
where
    L: Lmcs<F = Felt>,
{
    type Target = Preprocessed<Felt, L>;

    fn deref(&self) -> &Preprocessed<Felt, L> {
        match self {
            Self::Cached(p) => p,
            Self::Owned(p) => p,
        }
    }
}

/// `Preprocessed::build` reads only the selected AIRs, so dummy public inputs suffice.
fn scratch_statement(variant: PvmAirVariant) -> Statement<Felt, QuadFelt, ChipletMultiAir> {
    Statement::new(
        ChipletMultiAir::with_variant(variant),
        vec![Felt::ZERO; NUM_PUBLIC_VALUES],
        vec![],
    )
    .expect("chiplet statement inputs are valid")
}

fn build<SC>(config: &SC, variant: PvmAirVariant) -> Preprocessed<Felt, SC::Lmcs>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    let statement = scratch_statement(variant);
    Preprocessed::build(&statement, config)
        .expect("chiplet stack always declares BytePairLut preprocessed columns")
}

/// Builds a bundle without caching it.
pub fn build_uncached<SC>(config: &SC) -> Preprocessed<Felt, SC::Lmcs>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    build_uncached_for(config, PvmAirVariant::ALL)
}

/// Builds the selected AIR variant's setup bundle without caching it.
pub fn build_uncached_for<SC>(config: &SC, variant: PvmAirVariant) -> Preprocessed<Felt, SC::Lmcs>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    build(config, variant)
}

#[cfg(any(test, feature = "std"))]
fn select_variant<L>(full: &Preprocessed<Felt, L>, variant: PvmAirVariant) -> Preprocessed<Felt, L>
where
    L: Lmcs<F = Felt>,
{
    let indices: vec::Vec<_> = ChipletAir::all()
        .iter()
        .enumerate()
        .filter_map(|(index, air)| air.is_in_variant(variant).then_some(index))
        .collect();
    full.select_airs(&indices).expect("every AIR variant retains BytePairLut")
}

macro_rules! cached_preprocessed {
    ($fn_name:ident, $variant_fn:ident, $config:ty, $config_fn:ident) => {
        pub fn $fn_name()
        -> PreprocessedHandle<'static, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs> {
            $variant_fn(PvmAirVariant::ALL)
        }

        pub fn $variant_fn(
            variant: PvmAirVariant,
        ) -> PreprocessedHandle<'static, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs> {
            #[cfg(feature = "std")]
            {
                static CACHE: [std::sync::OnceLock<
                    Preprocessed<Felt, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs>,
                >; PvmAirVariant::ALL_VARIANTS.len()] =
                    [const { std::sync::OnceLock::new() }; PvmAirVariant::ALL_VARIANTS.len()];
                let full = CACHE[PvmAirVariant::ALL.as_u8() as usize].get_or_init(|| {
                    let config = $config_fn(
                        precompile_pcs_params(),
                        miden_air::precompile::protocol::relation_digest(PvmAirVariant::ALL),
                    );
                    build(&config, PvmAirVariant::ALL)
                });
                if variant == PvmAirVariant::ALL {
                    PreprocessedHandle::Cached(full)
                } else {
                    PreprocessedHandle::Cached(
                        CACHE[variant.as_u8() as usize]
                            .get_or_init(|| select_variant(full, variant)),
                    )
                }
            }
            #[cfg(not(feature = "std"))]
            {
                let config = $config_fn(
                    precompile_pcs_params(),
                    miden_air::precompile::protocol::relation_digest(variant),
                );
                PreprocessedHandle::Owned(build(&config, variant))
            }
        }
    };
}

cached_preprocessed!(blake3, blake3_for, Blake3Config, blake3_256_config);
cached_preprocessed!(rpo, rpo_for, RpoConfig, rpo_config);
cached_preprocessed!(rpx, rpx_for, RpxConfig, rpx_config);
cached_preprocessed!(poseidon2, poseidon2_for, Poseidon2Config, poseidon2_config);
cached_preprocessed!(keccak, keccak_for, KeccakConfig, keccak_config);
cached_preprocessed!(eidos, eidos_for, EidosConfig, eidos_config);

#[cfg(test)]
mod tests {
    use miden_core::utils::RowMajorMatrix;
    use miden_stark::ProverInstance;
    use miden_stark::air::{BaseAir, LiftedAir, ProverStatement};
    use miden_stark::pcs::PcsParams;

    use super::*;

    /// Setup's per-AIR slots must follow the selected statement even when earlier AIRs disappear.
    #[test]
    fn variant_setup_uses_selected_air_order() {
        let params = PcsParams::new(1, 1, 3, 0, 0, 1, 0).expect("valid PCS params");
        let full_config = blake3_256_config(
            params,
            miden_air::precompile::protocol::relation_digest(PvmAirVariant::ALL),
        );
        let full = build_uncached(&full_config);
        for variant in PvmAirVariant::ALL_VARIANTS {
            let statement = scratch_statement(variant);
            let expected: vec::Vec<_> =
                ChipletAir::all().into_iter().filter(|air| air.is_in_variant(variant)).collect();
            assert_eq!(statement.airs(), expected.as_slice());
            let preprocessed_airs: vec::Vec<_> = statement
                .airs()
                .iter()
                .filter(|air| BaseAir::<Felt>::preprocessed_width(*air) != 0)
                .collect();
            assert_eq!(preprocessed_airs, [&ChipletAir::BytePairLut]);
            let config = blake3_256_config(
                params,
                miden_air::precompile::protocol::relation_digest(variant),
            );
            let bundle = select_variant(&full, variant);
            let traces = statement
                .airs()
                .iter()
                .map(|air| {
                    let height = if *air == ChipletAir::BytePairLut {
                        miden_air::precompile::primitives::byte_pair_lut::TRACE_HEIGHT
                    } else {
                        LiftedAir::<Felt, QuadFelt>::max_periodic_length(air)
                            .max(2)
                            .next_power_of_two()
                    };
                    let width = BaseAir::<Felt>::width(air);
                    RowMajorMatrix::new(vec![Felt::ZERO; height * width], width)
                })
                .collect();
            let prover_statement =
                ProverStatement::new(statement, traces).expect("valid trace shapes");
            ProverInstance::new(&config, prover_statement, Some(&bundle))
                .expect("setup slots and commitment dimensions must match the selected AIRs");
            // The BytePairLut data is fixed; removing AIR slots must retain its commitment.
            assert_eq!(full.commitment(), bundle.commitment());
        }
    }
}
