//! Native Eidos commitment and challenger configuration for STARK benchmarks.

#![allow(dead_code, reason = "each benchmark uses a subset of the configuration helpers")]

pub use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    StarkConfig,
    config::{EidosConfig, eidos_config},
    pcs::PcsParams,
};

pub type Dft = p3_dft::Radix2DitParallel<Felt>;
pub type Lmcs = <EidosConfig as StarkConfig<Felt, QuadFelt>>::Lmcs;
pub type Challenger = <EidosConfig as StarkConfig<Felt, QuadFelt>>::Challenger;

pub fn config(params: PcsParams) -> EidosConfig {
    eidos_config(params, [Felt::ZERO; 4], miden_core::program::domain::STARK_TRANSCRIPT)
}

pub fn test_lmcs() -> Lmcs {
    config(miden_stark::testing::params::TEST_PCS_PARAMS).lmcs().clone()
}

pub fn test_challenger() -> Challenger {
    config(miden_stark::testing::params::TEST_PCS_PARAMS).challenger()
}
