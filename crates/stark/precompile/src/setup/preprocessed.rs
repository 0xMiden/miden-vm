//! Process-lifetime caching of the chiplet stack's preprocessed bundle.
//!
//! `Preprocessed::build` LDEs and commits the fixed `BytePairLut` table — a
//! pure function of the fixed twelve-chiplet list and the STARK config's
//! blowup/LMCS/DFT. Under `std`, each hash function's bundle is built once per
//! process and reused via `OnceLock`; without `std` (e.g. a `no_std`
//! verifier target), every call rebuilds it, matching the pre-caching
//! behavior exactly.

use alloc::vec;
use core::ops::Deref;

use miden_air::precompile::{ChipletAir, ChipletMultiAir, policy::precompile_pcs_params};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    Preprocessed, StarkConfig,
    air::{BaseAir, Statement},
    config::{Blake3Config, KeccakConfig, blake3_256_config, keccak_config},
    lmcs::Lmcs,
};

use crate::setup::config::{EidosConfig, PRECOMPILE_RELATION_DIGEST, eidos_config};

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

/// The AIR list never varies across calls (the fixed twelve-chiplet stack), and
/// `Preprocessed::build` reads only `statement.airs()` — never the public
/// inputs — so a scratch statement with dummy public inputs builds the exact
/// same bundle as the real per-proof statement would.
fn scratch_statement() -> Statement<Felt, QuadFelt, ChipletMultiAir> {
    Statement::new(
        ChipletMultiAir::new(),
        vec![(
            ChipletAir::TRANSCRIPT_EVAL_INDEX,
            vec![Felt::ZERO; ChipletAir::TRANSCRIPT_EVAL.num_public_values()],
        )],
        vec![],
    )
    .expect("chiplet statement inputs are valid")
}

fn build<SC>(config: &SC) -> Preprocessed<Felt, SC::Lmcs>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    let statement = scratch_statement();
    Preprocessed::build(&statement, config)
        .expect("chiplet stack always declares BytePairLut preprocessed columns")
}

/// Builds a bundle without caching it.
pub fn build_uncached<SC>(config: &SC) -> Preprocessed<Felt, SC::Lmcs>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    build(config)
}

macro_rules! cached_preprocessed {
    ($fn_name:ident, $config:ty, $config_fn:ident) => {
        pub fn $fn_name()
        -> PreprocessedHandle<'static, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs> {
            let config = $config_fn(precompile_pcs_params(), PRECOMPILE_RELATION_DIGEST);
            #[cfg(feature = "std")]
            {
                static CACHE: std::sync::OnceLock<
                    Preprocessed<Felt, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs>,
                > = std::sync::OnceLock::new();
                PreprocessedHandle::Cached(CACHE.get_or_init(|| build(&config)))
            }
            #[cfg(not(feature = "std"))]
            {
                PreprocessedHandle::Owned(build(&config))
            }
        }
    };
}

cached_preprocessed!(blake3, Blake3Config, blake3_256_config);
cached_preprocessed!(keccak, KeccakConfig, keccak_config);
cached_preprocessed!(eidos, EidosConfig, eidos_config);

#[cfg(test)]
mod tests {
    #[test]
    fn eidos_setup_matches_the_accepted_pin() {
        assert_eq!(
            <[u64; 4]>::from(super::eidos().commitment()),
            miden_air::precompile::protocol::PVM_PREPROCESSED_COMMITMENT,
            "backend setup must reproduce the accepted AIR-owned commitment",
        );
    }
}
