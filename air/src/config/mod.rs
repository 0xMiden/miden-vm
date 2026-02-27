//! STARK configuration factories for different hash functions.
//!
//! This module provides factory functions that create [`GenericStarkConfig`] instances
//! for different hash functions (Blake3, Keccak, RPO256, Poseidon2, RPX256). Each config
//! bundles the PCS parameters, LMCS commitment scheme, and challenger for proving
//! and verification.
//!
//! The [`prove`] and [`verify`] free functions handle transcript management
//! (Fiat-Shamir seeding, serialization) on top of the upstream prover/verifier.

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use p3_challenger::CanObserve;
use p3_miden_lifted_air::{AirInstance, AuxBuilder, VarLenPublicInputs};
use p3_miden_lifted_fri::{
    PcsParams,
    deep::DeepParams,
    fri::{FriFold, FriParams},
};
pub use p3_miden_lifted_stark::{GenericStarkConfig, StarkConfig};
use serde::{Serialize, de::DeserializeOwned};

use crate::LiftedAir;

mod blake3;
mod keccak;
mod poseidon2;
mod rpo;
mod rpx;

pub use blake3::create_blake3_256_config;
pub use keccak::create_keccak_config;
pub use poseidon2::create_poseidon2_config;
pub use rpo::create_rpo_config;
pub use rpx::create_rpx_config;

// SHARED TYPES
// ================================================================================================

/// DFT implementation for polynomial operations.
pub type Dft = p3_dft::Radix2DitParallel<Felt>;

/// PCS parameters shared by all hash function configurations.
///
/// - FRI with 8x blowup (log_blowup = 3)
/// - Binary folding (arity 2)
/// - Final polynomial degree 2^7 = 128
/// - 16 bits of folding proof-of-work
/// - 27 query repetitions
pub const PCS_PARAMS: PcsParams = PcsParams {
    fri: FriParams {
        log_blowup: 3,
        fold: FriFold::ARITY_2,
        log_final_degree: 7,
        folding_pow_bits: 16,
    },
    deep: DeepParams { deep_pow_bits: 0 },
    num_queries: 27,
    query_pow_bits: 0,
};

// PROVE / VERIFY
// ================================================================================================

/// Generates a STARK proof for the given AIR, trace, and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// prover. Returns the serialized proof bytes.
pub fn prove<A, B, SC>(
    config: &SC,
    air: &A,
    trace: &RowMajorMatrix<Felt>,
    public_values: &[Felt],
    aux_builder: &B,
) -> Result<Vec<u8>, String>
where
    A: LiftedAir<Felt, QuadFelt>,
    B: AuxBuilder<Felt, QuadFelt>,
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as p3_miden_lmcs::Lmcs>::Commitment: Serialize,
{
    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    let mut channel = p3_miden_transcript::ProverTranscript::new(challenger);
    p3_miden_lifted_prover::prove_single::<_, QuadFelt, _, _, _, _>(
        config,
        air,
        trace,
        public_values,
        aux_builder,
        &mut channel,
    )
    .map_err(|e| e.to_string())?;
    bincode::serialize(&channel.into_data()).map_err(|e| e.to_string())
}

/// Verifies a STARK proof for the given AIR and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// verifier. Uses `verify_multi` to pass `var_len_public_inputs` for the
/// cross-AIR aux-finals identity check.
pub fn verify<A, SC>(
    config: &SC,
    air: &A,
    log_trace_height: usize,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    proof_bytes: &[u8],
) -> Result<(), String>
where
    A: LiftedAir<Felt, QuadFelt>,
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as p3_miden_lmcs::Lmcs>::Commitment: DeserializeOwned,
{
    let transcript_data: p3_miden_transcript::TranscriptData<
        Felt,
        <SC::Lmcs as p3_miden_lmcs::Lmcs>::Commitment,
    > = bincode::deserialize(proof_bytes).map_err(|e| e.to_string())?;
    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    let mut channel =
        p3_miden_transcript::VerifierTranscript::from_data(challenger, &transcript_data);
    let instance = AirInstance {
        log_trace_height,
        public_values,
        var_len_public_inputs,
    };
    p3_miden_lifted_verifier::verify_multi::<_, QuadFelt, _, _, _>(
        config,
        &[(air, instance)],
        &mut channel,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::Felt;
    use p3_air::{AirBuilder, BaseAir, BaseAirWithPublicValues};
    use p3_field::ExtensionField;
    use p3_matrix::{Matrix, dense::RowMajorMatrix};
    use p3_miden_lifted_air::{
        AirWithPeriodicColumns, EmptyAuxBuilder, LiftedAir, LiftedAirBuilder,
    };

    /// Trivial AIR: single column, constrain next == local (constant trace).
    struct ConstantAir;

    impl BaseAir<Felt> for ConstantAir {
        fn width(&self) -> usize {
            1
        }
    }
    impl BaseAirWithPublicValues<Felt> for ConstantAir {}
    impl AirWithPeriodicColumns<Felt> for ConstantAir {
        fn periodic_columns(&self) -> &[Vec<Felt>] {
            &[]
        }
    }
    impl<EF: ExtensionField<Felt>> LiftedAir<Felt, EF> for ConstantAir {
        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
            let main = builder.main();
            let local = main.row_slice(0).unwrap();
            let next = main.row_slice(1).unwrap();
            let diff: AB::Expr = next[0].clone().into() - local[0].clone().into();
            builder.when_transition().assert_zero(diff);
        }
    }

    fn constant_trace() -> RowMajorMatrix<Felt> {
        let trace_len = 256;
        let values: Vec<Felt> = vec![Felt::new(42); trace_len];
        RowMajorMatrix::new(values, 1)
    }

    #[test]
    fn test_poseidon2_prove_verify() {
        let trace = constant_trace();
        let air = ConstantAir;
        let pv: Vec<Felt> = vec![];
        let aux = EmptyAuxBuilder;

        let config = super::create_poseidon2_config();
        let proof = super::prove(&config, &air, &trace, &pv, &aux).expect("prove");

        let log_h = trace.height().trailing_zeros() as usize;
        super::verify(&config, &air, log_h, &pv, &[], &proof).expect("verify");
    }

    #[test]
    fn test_blake3_prove_verify() {
        let trace = constant_trace();
        let air = ConstantAir;
        let pv: Vec<Felt> = vec![];
        let aux = EmptyAuxBuilder;

        let config = super::create_blake3_256_config();
        let proof = super::prove(&config, &air, &trace, &pv, &aux).expect("prove");

        let log_h = trace.height().trailing_zeros() as usize;
        super::verify(&config, &air, log_h, &pv, &[], &proof).expect("verify");
    }

    #[test]
    fn test_keccak_prove_verify() {
        let trace = constant_trace();
        let air = ConstantAir;
        let pv: Vec<Felt> = vec![];
        let aux = EmptyAuxBuilder;

        let config = super::create_keccak_config();
        let proof = super::prove(&config, &air, &trace, &pv, &aux).expect("prove");

        let log_h = trace.height().trailing_zeros() as usize;
        super::verify(&config, &air, log_h, &pv, &[], &proof).expect("verify");
    }

    /// Blake3 LMCS + Keccak challenger: isolates whether the bug is in Blake3
    /// LMCS (ChainingHasher) or Blake3 challenger (SerializingChallenger64).
    #[test]
    fn test_blake3_lmcs_keccak_challenger() {
        use p3_blake3::Blake3;
        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_keccak::Keccak256Hash;
        use p3_miden_lifted_stark::GenericStarkConfig;
        use p3_miden_lmcs::LmcsConfig;
        use p3_miden_stateful_hasher::ChainingHasher;
        use p3_symmetric::CompressionFunctionFromHasher;

        type Sponge = ChainingHasher<Blake3>;
        type Compress = CompressionFunctionFromHasher<Blake3, 2, 32>;
        type LmcsType = LmcsConfig<Felt, u8, Sponge, Compress, 32, 32>;
        // Use Keccak challenger instead of Blake3 challenger
        type Ch = SerializingChallenger64<Felt, HashChallenger<u8, Keccak256Hash, 32>>;

        let sponge = Sponge::new(Blake3);
        let compress = Compress::new(Blake3);
        let lmcs = LmcsType::new(sponge, compress);
        let dft = super::Dft::default();
        let challenger = Ch::from_hasher(vec![], Keccak256Hash {});

        let config = GenericStarkConfig::new(super::PCS_PARAMS, lmcs, dft, challenger);

        let trace = constant_trace();
        let air = ConstantAir;
        let pv: Vec<Felt> = vec![];
        let aux = EmptyAuxBuilder;

        let proof = super::prove(&config, &air, &trace, &pv, &aux).expect("prove");

        let log_h = trace.height().trailing_zeros() as usize;
        super::verify(&config, &air, log_h, &pv, &[], &proof).expect("verify");
    }
}
