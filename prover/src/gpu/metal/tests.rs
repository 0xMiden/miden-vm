use alloc::vec::Vec;

use gpu::metal::{DIGEST_SIZE, MetalExecutionProver};
use miden_air::{PartitionOptions, ProvingOptions, StarkField};
use miden_processor::{
    StackInputs, StackOutputs, Word,
    crypto::{Hasher, Rpo256, RpoRandomCoin, Rpx256},
    math::fft,
};
use winter_prover::{
    CompositionPolyTrace, ConstraintCommitment, TraceLde, crypto::Digest,
    math::fields::CubeExtension,
};

use crate::*;

const RATE: usize = Rpo256::RATE_RANGE.end - Rpo256::RATE_RANGE.start;

type CubeFelt = CubeExtension<Felt>;

// TESTS
// ================================================================================================

#[test]
fn rpo_build_trace_commitment_on_gpu_with_padding_matches_cpu() {
    build_trace_commitment_on_gpu_with_padding_matches_cpu::<RpoRandomCoin, Rpo256, Word>(
        HashFn::Rpo256,
    );
}

#[test]
fn rpx_build_trace_commitment_on_gpu_with_padding_matches_cpu() {
    build_trace_commitment_on_gpu_with_padding_matches_cpu::<RpxRandomCoin, Rpx256, Word>(
        HashFn::Rpx256,
    );
}

#[test]
fn rpo_build_trace_commitment_on_gpu_without_padding_matches_cpu() {
    build_trace_commitment_on_gpu_without_padding_matches_cpu::<RpoRandomCoin, Rpo256, Word>(
        HashFn::Rpo256,
    );
}

#[test]
fn rpx_build_trace_commitment_on_gpu_without_padding_matches_cpu() {
    build_trace_commitment_on_gpu_without_padding_matches_cpu::<RpxRandomCoin, Rpx256, Word>(
        HashFn::Rpx256,
    );
}

#[test]
fn rpo_build_constraint_commitment_on_gpu_with_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_with_padding_matches_cpu::<RpoRandomCoin, Rpo256, Word>(
        HashFn::Rpo256,
    );
}

#[test]
fn rpx_build_constraint_commitment_on_gpu_with_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_with_padding_matches_cpu::<RpxRandomCoin, Rpx256, Word>(
        HashFn::Rpx256,
    );
}

#[test]
fn rpo_build_constraint_commitment_on_gpu_without_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_without_padding_matches_cpu::<RpoRandomCoin, Rpo256, Word>(
        HashFn::Rpo256,
    );
}

#[test]
fn rpx_build_constraint_commitment_on_gpu_without_padding_matches_cpu() {
    build_constraint_commitment_on_gpu_without_padding_matches_cpu::<RpxRandomCoin, Rpx256, Word>(
        HashFn::Rpx256,
    );
}

// TEST FUNCTIONS
// ================================================================================================

fn build_trace_commitment_on_gpu_with_padding_matches_cpu<R, H, D>(hash_fn: HashFn)
where
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
{
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<H, R>(is_rpx);
    let gpu_prover = MetalExecutionProver::new(create_test_prover::<H, R>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let trace_info = get_trace_info(1, num_rows);
    let trace = gen_random_trace(num_rows, RATE + 1);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (cpu_trace_lde, cpu_polys) = cpu_prover.new_trace_lde::<CubeFelt>(
        &trace_info,
        &trace,
        &domain,
        PartitionOptions::default(),
    );
    let (gpu_trace_lde, gpu_polys) = gpu_prover.new_trace_lde::<CubeFelt>(
        &trace_info,
        &trace,
        &domain,
        PartitionOptions::default(),
    );

    assert_eq!(
        cpu_trace_lde.get_main_trace_commitment(),
        gpu_trace_lde.get_main_trace_commitment()
    );
    assert_eq!(
        cpu_polys.main_trace_polys().collect::<Vec<_>>(),
        gpu_polys.main_trace_polys().collect::<Vec<_>>()
    );
}

fn build_trace_commitment_on_gpu_without_padding_matches_cpu<R, H, D>(hash_fn: HashFn)
where
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
{
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<H, R>(is_rpx);
    let gpu_prover = MetalExecutionProver::new(create_test_prover::<H, R>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let trace_info = get_trace_info(1, num_rows);
    let trace = gen_random_trace(num_rows, RATE);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (cpu_trace_lde, cpu_polys) = cpu_prover.new_trace_lde::<CubeFelt>(
        &trace_info,
        &trace,
        &domain,
        PartitionOptions::default(),
    );
    let (gpu_trace_lde, gpu_polys) = gpu_prover.new_trace_lde::<CubeFelt>(
        &trace_info,
        &trace,
        &domain,
        PartitionOptions::default(),
    );

    assert_eq!(
        cpu_trace_lde.get_main_trace_commitment(),
        gpu_trace_lde.get_main_trace_commitment()
    );
    assert_eq!(
        cpu_polys.main_trace_polys().collect::<Vec<_>>(),
        gpu_polys.main_trace_polys().collect::<Vec<_>>()
    );
}

fn build_constraint_commitment_on_gpu_with_padding_matches_cpu<R, H, D>(hash_fn: HashFn)
where
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
{
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<H, R>(is_rpx);
    let gpu_prover = MetalExecutionProver::new(create_test_prover::<H, R>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let ce_blowup_factor = 2;
    let values = get_random_values::<CubeFelt>(num_rows * ce_blowup_factor);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (commitment_cpu, composition_poly_cpu) = cpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values.clone()),
        2,
        &domain,
        PartitionOptions::default(),
    );
    let (commitment_gpu, composition_poly_gpu) = gpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values),
        2,
        &domain,
        PartitionOptions::default(),
    );

    assert_eq!(commitment_cpu.commitment(), commitment_gpu.commitment());
    assert_ne!(0, composition_poly_cpu.data().num_base_cols() % RATE);
    assert_eq!(composition_poly_cpu.into_columns(), composition_poly_gpu.into_columns());
}

fn build_constraint_commitment_on_gpu_without_padding_matches_cpu<R, H, D>(hash_fn: HashFn)
where
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
    H: ElementHasher<BaseField = Felt> + Hasher<Digest = D> + Sync,
    D: Digest + for<'a> From<&'a [Felt; DIGEST_SIZE]>,
{
    let is_rpx = matches!(hash_fn, HashFn::Rpx256);

    let cpu_prover = create_test_prover::<H, R>(is_rpx);
    let gpu_prover = MetalExecutionProver::new(create_test_prover::<H, R>(is_rpx), hash_fn);
    let num_rows = 1 << 8;
    let ce_blowup_factor = 8;
    let values = get_random_values::<Felt>(num_rows * ce_blowup_factor);
    let domain = StarkDomain::from_twiddles(fft::get_twiddles(num_rows), 8, Felt::GENERATOR);

    let (commitment_cpu, composition_poly_cpu) = cpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values.clone()),
        8,
        &domain,
        PartitionOptions::default(),
    );
    let (commitment_gpu, composition_poly_gpu) = gpu_prover.build_constraint_commitment(
        CompositionPolyTrace::new(values),
        8,
        &domain,
        PartitionOptions::default(),
    );

    assert_eq!(commitment_cpu.commitment(), commitment_gpu.commitment());
    assert_eq!(0, composition_poly_cpu.data().num_base_cols() % RATE);
    assert_eq!(composition_poly_cpu.into_columns(), composition_poly_gpu.into_columns());
}

// HELPER FUNCTIONS
// ================================================================================================

fn gen_random_trace(num_rows: usize, num_cols: usize) -> ColMatrix<Felt> {
    ColMatrix::new((0..num_cols as u64).map(|col| vec![Felt::new(col); num_rows]).collect())
}

fn get_random_values<E: FieldElement>(num_rows: usize) -> Vec<E> {
    (0..num_rows).map(|i| E::from(i as u32)).collect()
}

fn get_trace_info(num_cols: usize, num_rows: usize) -> TraceInfo {
    TraceInfo::new(num_cols, num_rows)
}

fn create_test_prover<H, R>(use_rpx: bool) -> ExecutionProver<H, R>
where
    H: ElementHasher<BaseField = Felt> + Sync,
    R: RandomCoin<BaseField = Felt, Hasher = H> + Send,
{
    if use_rpx {
        ExecutionProver::new(
            ProvingOptions::with_128_bit_security(HashFunction::Rpx256),
            StackInputs::default(),
            StackOutputs::default(),
        )
    } else {
        ExecutionProver::new(
            ProvingOptions::with_128_bit_security(HashFunction::Rpo256),
            StackInputs::default(),
            StackOutputs::default(),
        )
    }
}
