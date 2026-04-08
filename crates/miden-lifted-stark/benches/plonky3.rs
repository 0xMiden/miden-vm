//! Plonky3 comparison benchmarks.
//!
//! All benchmarks that compare our lifted implementation against upstream Plonky3
//! abstractions (`TwoAdicFriPcs`, `MerkleTreeMmcs`) live here.
//!
//! ```bash
//! RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench plonky3 --features testing
//!
//! # Filter by benchmark group
//! cargo bench --bench plonky3 --features testing -- LMCS_vs_MMCS
//! cargo bench --bench plonky3 --features testing -- PCS_Open
//! cargo bench --bench plonky3 --features testing -- quotient_commit
//! ```

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_lifted_stark::{
    LiftedCoset, Lmcs, LmcsTree, log2_strict_u8,
    testing::{
        BENCH_PCS_PARAMS, LOG_HEIGHTS, PARALLEL_STR, QC_CONSTRAINT_DEGREE, QC_PCS_PARAMS,
        RELATIVE_SPECS, commit_quotient,
        configs::{
            goldilocks_blake3_192 as gl_blake3_192, goldilocks_keccak as gl_keccak,
            goldilocks_poseidon2 as gl,
        },
        generate_matrices_from_specs, open_with_channel, total_elements,
    },
};
use miden_stark_transcript::ProverTranscript;
use p3_blake3::Blake3;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{ExtensionMmcs, Mmcs, Pcs};
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{Field, coset::TwoAdicMultiplicativeCoset};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::KeccakF;
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, SerializingHasher};
use rand::{RngExt, SeedableRng, rngs::SmallRng};

// =============================================================================
// Workspace MMCS / PCS types (Goldilocks + Poseidon2)
// =============================================================================

type Poseidon2MmcsSponge = PaddingFreeSponge<gl::Perm, { gl::WIDTH }, { gl::RATE }, { gl::DIGEST }>;
type Poseidon2ValMmcs = MerkleTreeMmcs<
    gl::PackedFelt,
    gl::PackedFelt,
    Poseidon2MmcsSponge,
    gl::Compress,
    2,
    { gl::DIGEST },
>;
type Poseidon2ChallengeMmcs = ExtensionMmcs<gl::Felt, gl::QuadFelt, Poseidon2ValMmcs>;
type WorkspacePcs =
    TwoAdicFriPcs<gl::Felt, Radix2DitParallel<gl::Felt>, Poseidon2ValMmcs, Poseidon2ChallengeMmcs>;

fn gl_poseidon2_mmcs() -> Poseidon2ValMmcs {
    let perm = gl::create_perm();
    Poseidon2ValMmcs::new(Poseidon2MmcsSponge::new(perm.clone()), gl::Compress::new(perm), 0)
}

fn workspace_pcs(
    log_blowup: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    num_queries: usize,
) -> WorkspacePcs {
    let (perm, _, compress) = gl::test_components();
    let mmcs_sponge = Poseidon2MmcsSponge::new(perm);
    let mmcs = Poseidon2ValMmcs::new(mmcs_sponge, compress, 0);
    let challenge_mmcs = Poseidon2ChallengeMmcs::new(mmcs.clone());
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len,
        max_log_arity,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: challenge_mmcs,
    };
    WorkspacePcs::new(Radix2DitParallel::default(), mmcs, fri_params)
}

// =============================================================================
// Workspace MMCS types (Keccak, Blake3-192)
// =============================================================================

type KeccakMmcs = MerkleTreeMmcs<
    gl_keccak::Felt,
    u64,
    SerializingHasher<gl_keccak::KeccakMmcsSponge>,
    gl_keccak::Compress,
    2,
    { gl_keccak::DIGEST },
>;

fn gl_keccak_mmcs() -> KeccakMmcs {
    let inner = gl_keccak::KeccakMmcsSponge::new(KeccakF);
    KeccakMmcs::new(SerializingHasher::new(inner), gl_keccak::Compress::new(inner), 0)
}

type Blake3_192Mmcs = MerkleTreeMmcs<
    gl_blake3_192::Felt,
    u8,
    SerializingHasher<gl_blake3_192::Blake3_192>,
    gl_blake3_192::Compress,
    2,
    { gl_blake3_192::DIGEST },
>;

fn gl_blake3_192_mmcs() -> Blake3_192Mmcs {
    let inner = gl_blake3_192::Blake3_192::new(Blake3);
    Blake3_192Mmcs::new(SerializingHasher::new(inner), gl_blake3_192::Compress::new(inner), 0)
}

// =============================================================================
// LMCS vs MMCS commit
// =============================================================================

fn bench_hash<L: Lmcs<F = gl::Felt>, M: Mmcs<gl::Felt>>(
    c: &mut Criterion,
    lmcs: &L,
    mmcs: &M,
    hash_name: &str,
) {
    for &log_max_height in LOG_HEIGHTS {
        let n_leaves = 1usize << log_max_height;
        let group_name =
            format!("LMCS_vs_MMCS/{}/goldilocks/{}/{}", n_leaves, hash_name, PARALLEL_STR);
        let mut group = c.benchmark_group(&group_name);
        group.throughput(Throughput::Elements(total_elements(&generate_matrices_from_specs::<
            gl::Felt,
        >(
            RELATIVE_SPECS, log_max_height
        ))));

        let matrix_groups: Vec<Vec<RowMajorMatrix<gl::Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_max_height);

        group.bench_with_input(BenchmarkId::from_parameter("lmcs"), &matrix_groups, |b, groups| {
            b.iter(|| {
                for matrices in groups {
                    let tree = lmcs.build_tree(matrices.clone());
                    black_box(tree.root());
                }
            });
        });

        group.bench_with_input(BenchmarkId::from_parameter("mmcs"), &matrix_groups, |b, groups| {
            b.iter(|| {
                for matrices in groups {
                    black_box(mmcs.commit(matrices.clone()));
                }
            });
        });

        group.finish();
    }
}

fn bench_lmcs_vs_mmcs(c: &mut Criterion) {
    bench_hash(c, &gl::test_lmcs(), &gl_poseidon2_mmcs(), "poseidon2");
    bench_hash(c, &gl_keccak::test_lmcs(), &gl_keccak_mmcs(), "keccak");
    bench_hash(c, &gl_blake3_192::test_lmcs(), &gl_blake3_192_mmcs(), "blake3-192");
}

// =============================================================================
// PCS open comparison
// =============================================================================

fn bench_pcs_open(c: &mut Criterion) {
    let dft = Radix2DitParallel::<gl::Felt>::default();
    let shift = gl::Felt::GENERATOR;

    for &log_lde_height in LOG_HEIGHTS {
        let max_lde_size = 1usize << log_lde_height;
        let group_name = format!("PCS_Open/{}/goldilocks/poseidon2/{}", max_lde_size, PARALLEL_STR);
        let mut group = c.benchmark_group(&group_name);

        let matrix_groups: Vec<Vec<RowMajorMatrix<gl::Felt>>> =
            generate_matrices_from_specs(RELATIVE_SPECS, log_lde_height);
        group.throughput(Throughput::Elements(total_elements(&matrix_groups)));

        // --- Workspace TwoAdicFriPcs ---
        {
            let ws_pcs = workspace_pcs(
                BENCH_PCS_PARAMS.log_blowup() as usize,
                BENCH_PCS_PARAMS.log_final_degree() as usize,
                BENCH_PCS_PARAMS.log_folding_arity() as usize,
                BENCH_PCS_PARAMS.num_queries(),
            );

            let commits_and_data: Vec<_> = matrix_groups
                .iter()
                .map(|matrices| {
                    let domains_and_evals = matrices.iter().map(|m| {
                        let domain =
                            <WorkspacePcs as Pcs<gl::QuadFelt, gl::Challenger>>::natural_domain_for_degree(
                                &ws_pcs,
                                m.height(),
                            );
                        (domain, m.clone())
                    });
                    <WorkspacePcs as Pcs<gl::QuadFelt, gl::Challenger>>::commit(&ws_pcs, domains_and_evals)
                })
                .collect();

            let base_challenger = gl::test_challenger();

            group.bench_function(BenchmarkId::from_parameter("workspace"), |b| {
                b.iter(|| {
                    let mut challenger = base_challenger.clone();
                    for (commitment, _) in &commits_and_data {
                        challenger.observe(commitment.clone());
                    }
                    let z1: gl::QuadFelt = challenger.sample_algebra_element();
                    let z2: gl::QuadFelt = challenger.sample_algebra_element();

                    let data_and_points: Vec<_> = commits_and_data
                        .iter()
                        .enumerate()
                        .map(|(i, (_, prover_data))| {
                            let num_matrices = matrix_groups[i].len();
                            let points = if i < 2 {
                                vec![vec![z1, z2]; num_matrices]
                            } else {
                                vec![vec![z1]; num_matrices]
                            };
                            (prover_data, points)
                        })
                        .collect();

                    let (_openings, proof) =
                        <WorkspacePcs as Pcs<gl::QuadFelt, gl::Challenger>>::open(
                            &ws_pcs,
                            black_box(data_and_points),
                            &mut challenger,
                        );
                    black_box(proof)
                });
            });
        }

        // --- Lifted PCS (arity 2 and 4) ---
        {
            let lmcs = gl::test_lmcs();

            let mut all_lde_matrices: Vec<_> = matrix_groups
                .iter()
                .flat_map(|matrices| {
                    matrices.iter().map(|m| {
                        dft.coset_lde_batch(
                            m.clone(),
                            BENCH_PCS_PARAMS.log_blowup() as usize,
                            shift,
                        )
                    })
                })
                .collect();
            all_lde_matrices.sort_by_key(|m| m.height());

            let tree = lmcs.build_aligned_tree(all_lde_matrices);
            let commitment = tree.root();
            let log_lde_height = log2_strict_u8(tree.height());

            let base_challenger = gl::test_challenger();

            {
                group.bench_function(BenchmarkId::from_parameter("lifted"), |b| {
                    b.iter(|| {
                        let mut challenger = base_challenger.clone();
                        challenger.observe(commitment);
                        let z1: gl::QuadFelt = challenger.sample_algebra_element();
                        let z2: gl::QuadFelt = challenger.sample_algebra_element();
                        let mut channel = ProverTranscript::new(challenger);

                        let trace_trees: &[&_] = &[&tree];
                        open_with_channel::<gl::Felt, gl::QuadFelt, _, _, _, 2>(
                            &BENCH_PCS_PARAMS,
                            &lmcs,
                            log_lde_height,
                            [z1, z2],
                            trace_trees,
                            &mut channel,
                        );
                        black_box(channel.finalize())
                    });
                });
            }
        }

        group.finish();
    }
}

// =============================================================================
// Quotient commit comparison
// =============================================================================

type Dft = Radix2DitParallel<gl::Felt>;
type LiftedLmcs = gl::Lmcs;
type LiftedConfig =
    miden_lifted_stark::GenericStarkConfig<gl::Felt, gl::QuadFelt, LiftedLmcs, Dft, gl::Challenger>;

fn lifted_config() -> LiftedConfig {
    LiftedConfig::new(QC_PCS_PARAMS, gl::test_lmcs(), Dft::default(), gl::test_challenger())
}

fn random_quotient_evals(n: usize, d: usize, seed: u64) -> Vec<gl::QuadFelt> {
    let mut rng = SmallRng::seed_from_u64(seed);
    (0..n * d).map(|_| rng.random()).collect()
}

fn bench_quotient_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("quotient_commit");
    let log_d = log2_strict_u8(QC_CONSTRAINT_DEGREE);

    for log_n in [16u8, 17u8] {
        let n = 1usize << log_n;
        let b = 1usize << QC_PCS_PARAMS.log_blowup();
        let label = format!("N=2^{log_n}");

        // --- Lifted ---
        {
            let config = lifted_config();
            let coset = LiftedCoset::unlifted(log_n, QC_PCS_PARAMS.log_blowup());

            group.bench_function(BenchmarkId::new("lifted", &label), |bench| {
                bench.iter(|| {
                    let mut q_evals = random_quotient_evals(n, QC_CONSTRAINT_DEGREE, 42);
                    q_evals.reserve(n * b - n * QC_CONSTRAINT_DEGREE);
                    let committed = commit_quotient(&config, q_evals, &coset);
                    black_box(committed)
                });
            });
        }

        // --- Plonky3 PCS ---
        {
            let pcs = workspace_pcs(QC_PCS_PARAMS.log_blowup() as usize, 0, 1, 1);
            let quotient_domain =
                TwoAdicMultiplicativeCoset::new(gl::Felt::GENERATOR, (log_n + log_d) as usize)
                    .unwrap();

            group.bench_function(BenchmarkId::new("plonky3_pcs", &label), |bench| {
                bench.iter(|| {
                    let q_evals = random_quotient_evals(n, QC_CONSTRAINT_DEGREE, 42);
                    let q_flat = RowMajorMatrix::new_col(q_evals).flatten_to_base();
                    let (commitment, data) =
                        <WorkspacePcs as Pcs<gl::QuadFelt, gl::Challenger>>::commit_quotient(
                            &pcs,
                            quotient_domain,
                            q_flat,
                            QC_CONSTRAINT_DEGREE,
                        );
                    black_box((commitment, data))
                });
            });
        }
    }

    group.finish();
}

// =============================================================================
// Criterion groups
// =============================================================================

criterion_group! {
    name = merkle_commit;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_lmcs_vs_mmcs
}

criterion_group! {
    name = pcs_open;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(30))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_pcs_open, bench_quotient_commit
}

criterion_main!(merkle_commit, pcs_open);
