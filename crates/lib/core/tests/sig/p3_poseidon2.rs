//! Bench-only Plonky3 Poseidon2 proving path.
//!
//! This module is intentionally isolated so the unsafe adapter and manual
//! challenger seeding do not leak into production code paths.

use miden_air::{
    ProcessorAir,
    config::{RELATION_DIGEST, observe_var_len_public_inputs, pcs_params},
};
use miden_core::{Felt, WORD_SIZE, field::QuadFelt};
use miden_crypto::{
    field::Field as MidenField,
    stark::{
        GenericStarkConfig,
        challenger::{CanObserve, DuplexChallenger},
        dft::Radix2DitParallel,
        hasher::StatefulSponge,
        lmcs::LmcsConfig,
        matrix::{Matrix, RowMajorMatrix},
        symmetric::{CryptographicPermutation, Permutation, TruncatedPermutation},
    },
};
use miden_processor::{FastProcessor, trace::build_trace};
use miden_utils_testing::{AdviceInputs, StackInputs};
use p3_goldilocks::{
    Goldilocks as P3Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_12,
};
use p3_symmetric::Permutation as P3Permutation;

const P3_COMPRESSION_INPUTS: usize = 2;
const P3_SPONGE_WIDTH: usize = 12;
const P3_SPONGE_RATE: usize = 8;
const P3_DIGEST_WIDTH: usize = 4;

const P3_LOG_BLOWUP: u8 = 3;
const P3_LOG_FOLDING_ARITY: u8 = 2;
const P3_LOG_FINAL_DEGREE: u8 = 7;
const P3_NUM_QUERIES: usize = 27;
const P3_FOLDING_POW_BITS: usize = 16;
const P3_DEEP_POW_BITS: usize = 0;
const P3_QUERY_POW_BITS: usize = 0;

type PackedFelt = <Felt as MidenField>::Packing;
type AlgLmcs<P> = LmcsConfig<
    PackedFelt,
    PackedFelt,
    StatefulSponge<P, P3_SPONGE_WIDTH, P3_SPONGE_RATE, P3_DIGEST_WIDTH>,
    TruncatedPermutation<P, P3_COMPRESSION_INPUTS, P3_DIGEST_WIDTH, P3_SPONGE_WIDTH>,
    P3_SPONGE_WIDTH,
    P3_DIGEST_WIDTH,
>;
type AlgChallenger<P> = DuplexChallenger<Felt, P, P3_SPONGE_WIDTH, P3_SPONGE_RATE>;

#[derive(Clone)]
struct P3Poseidon2FeltPerm {
    perm: Poseidon2Goldilocks<P3_SPONGE_WIDTH>,
}

impl P3Poseidon2FeltPerm {
    fn new() -> Self {
        Self { perm: default_goldilocks_poseidon2_12() }
    }
}

impl Default for P3Poseidon2FeltPerm {
    fn default() -> Self {
        Self::new()
    }
}

impl Permutation<[Felt; P3_SPONGE_WIDTH]> for P3Poseidon2FeltPerm {
    fn permute_mut(&self, state: &mut [Felt; P3_SPONGE_WIDTH]) {
        let mut p3_state: [P3Goldilocks; P3_SPONGE_WIDTH] =
            core::array::from_fn(|i| state[i].into());
        P3Permutation::permute_mut(&self.perm, &mut p3_state);
        *state = core::array::from_fn(|i| p3_state[i].into());
    }
}

impl CryptographicPermutation<[Felt; P3_SPONGE_WIDTH]> for P3Poseidon2FeltPerm {}

fn seed_p3_sponge_state(
    log_trace_height: u64,
    perm: &P3Poseidon2FeltPerm,
) -> [Felt; P3_SPONGE_WIDTH] {
    let mut state = [Felt::ZERO; P3_SPONGE_WIDTH];
    let capacity_range = P3_SPONGE_RATE..P3_SPONGE_WIDTH;
    let sponge_capacity = P3_SPONGE_WIDTH - P3_SPONGE_RATE;

    assert_eq!(RELATION_DIGEST.len(), sponge_capacity);
    state[capacity_range].copy_from_slice(&RELATION_DIGEST);
    state[0] = Felt::new(P3_NUM_QUERIES as u64);
    state[1] = Felt::new(P3_QUERY_POW_BITS as u64);
    state[2] = Felt::new(P3_DEEP_POW_BITS as u64);
    state[3] = Felt::new(P3_FOLDING_POW_BITS as u64);
    state[4] = Felt::new(P3_LOG_BLOWUP as u64);
    state[5] = Felt::new(P3_LOG_FINAL_DEGREE as u64);
    state[6] = Felt::new(1_u64 << P3_LOG_FOLDING_ARITY);
    perm.permute_mut(&mut state);

    state[..P3_SPONGE_RATE].fill(Felt::ZERO);
    state[0] = Felt::new(log_trace_height);
    perm.permute_mut(&mut state);

    state[..P3_SPONGE_RATE].fill(Felt::ZERO);
    state
}

fn p3_poseidon2_config(
    params: miden_crypto::stark::fri::PcsParams,
) -> GenericStarkConfig<
    Felt,
    QuadFelt,
    AlgLmcs<P3Poseidon2FeltPerm>,
    Radix2DitParallel<Felt>,
    AlgChallenger<P3Poseidon2FeltPerm>,
> {
    // PackedFelt is scalar in miden-field, so reuse the scalar permutation for LMCS.
    let perm = P3Poseidon2FeltPerm::new();
    let lmcs =
        LmcsConfig::new(StatefulSponge::new(perm.clone()), TruncatedPermutation::new(perm.clone()));
    let challenger = DuplexChallenger::new(perm);
    GenericStarkConfig::new(params, lmcs, Radix2DitParallel::default(), challenger)
}

struct P3Poseidon2Harness {
    config: GenericStarkConfig<
        Felt,
        QuadFelt,
        AlgLmcs<P3Poseidon2FeltPerm>,
        Radix2DitParallel<Felt>,
        AlgChallenger<P3Poseidon2FeltPerm>,
    >,
    perm: P3Poseidon2FeltPerm,
}

impl P3Poseidon2Harness {
    fn new() -> Self {
        Self {
            config: p3_poseidon2_config(pcs_params()),
            perm: P3Poseidon2FeltPerm::new(),
        }
    }

    fn challenger(
        &self,
        log_trace_height: u64,
        public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
    ) -> AlgChallenger<P3Poseidon2FeltPerm> {
        let state = seed_p3_sponge_state(log_trace_height, &self.perm);
        let mut challenger = DuplexChallenger {
            sponge_state: state,
            input_buffer: vec![],
            output_buffer: vec![],
            permutation: self.perm.clone(),
        };
        challenger.observe_slice(public_values);
        observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);
        challenger
    }

    fn prove(
        &self,
        trace_matrix: &RowMajorMatrix<Felt>,
        public_values: &[Felt],
        var_len_public_inputs: &[&[Felt]],
        aux_builder: &miden_processor::trace::AuxTraceBuilders,
    ) -> Result<(), miden_processor::ExecutionError> {
        let log_trace_height = trace_matrix.height().ilog2() as u64;
        let challenger = self.challenger(log_trace_height, public_values, var_len_public_inputs);
        let _proof = miden_crypto::stark::prover::prove_single(
            &self.config,
            &ProcessorAir,
            trace_matrix,
            public_values,
            var_len_public_inputs,
            aux_builder,
            challenger,
        )
        .map_err(|e| miden_processor::ExecutionError::ProvingError(e.to_string()))?;
        Ok(())
    }
}

pub fn prove_program_with_p3_poseidon2(
    program: &miden_processor::Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut impl miden_processor::SyncHost,
) -> Result<(), miden_processor::ExecutionError> {
    let processor = FastProcessor::new(stack_inputs).with_advice(advice_inputs).with_tracing(true);
    let trace_inputs = processor.execute_trace_inputs_sync(program, host)?;
    let trace = build_trace(trace_inputs)?;

    let trace_matrix = trace.to_row_major_matrix();
    let (public_values, kernel_felts) = trace.public_inputs().to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];
    let aux_builder = trace.aux_trace_builders();

    let harness = P3Poseidon2Harness::new();
    harness.prove(&trace_matrix, &public_values, var_len_public_inputs, &aux_builder)
}
