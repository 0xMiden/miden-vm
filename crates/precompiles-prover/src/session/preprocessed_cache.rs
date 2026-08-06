//! Process-lifetime caching of the chiplet stack's preprocessed bundle.
//!
//! `Preprocessed::build` LDEs and commits the fixed `BytePairLut` table — a
//! pure function of the (fixed, 12-AIR) chiplet list and the STARK config's
//! blowup/LMCS/DFT — yet both `prove_stark` and `verify_stark` rebuild it on
//! every call. Under `std`, each hash function's bundle is built once per
//! process and reused via `OnceLock`; without `std` (e.g. a `no_std`
//! verifier target), every call rebuilds it, matching the pre-caching
//! behavior exactly.

use alloc::vec;
use core::ops::Deref;

use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::Statement;
use miden_lifted_stark::{Preprocessed, StarkConfig, lmcs::Lmcs};

use super::prove::ChipletMultiAir;
use crate::{
    logup::NUM_PUBLIC_VALUES,
    stark_config::{Blake3Config, KeccakConfig, Poseidon2Config, RpoConfig, RpxConfig},
};

/// Either a process-cached (`std`) or freshly built (`no_std`) bundle;
/// callers dereference to the underlying [`Preprocessed`] either way.
pub(super) enum PreprocessedHandle<'a, L>
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

/// The AIR list never varies across calls (the fixed 12-chiplet stack), and
/// `Preprocessed::build` reads only `statement.airs()` — never the public
/// inputs — so a scratch statement with dummy public inputs builds the exact
/// same bundle as the real per-proof statement would.
fn scratch_statement() -> Statement<Felt, QuadFelt, ChipletMultiAir> {
    Statement::new(ChipletMultiAir::new(), vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![])
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

macro_rules! cached_preprocessed {
    ($fn_name:ident, $config:ty) => {
        pub(super) fn $fn_name(
            config: &$config,
        ) -> PreprocessedHandle<'static, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs> {
            #[cfg(feature = "std")]
            {
                static CACHE: std::sync::OnceLock<
                    Preprocessed<Felt, <$config as StarkConfig<Felt, QuadFelt>>::Lmcs>,
                > = std::sync::OnceLock::new();
                PreprocessedHandle::Cached(CACHE.get_or_init(|| build(config)))
            }
            #[cfg(not(feature = "std"))]
            {
                PreprocessedHandle::Owned(build(config))
            }
        }
    };
}

cached_preprocessed!(blake3, Blake3Config);
cached_preprocessed!(rpo, RpoConfig);
cached_preprocessed!(rpx, RpxConfig);
cached_preprocessed!(poseidon2, Poseidon2Config);
cached_preprocessed!(keccak, KeccakConfig);
