//! LMCS and Plonky3 MMCS commitment comparisons for Keccak and BLAKE3-192.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use miden_lifted_stark::testing::{
    LOG_HEIGHTS, Lmcs, LmcsTree, PARALLEL_STR, RELATIVE_SPECS, configs as gl,
    configs::{goldilocks_blake3_192 as gl_blake3_192, goldilocks_keccak as gl_keccak},
    generate_matrices_from_specs, total_elements,
};
use p3_blake3::Blake3;
use p3_commit::Mmcs;
use p3_keccak::KeccakF;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::SerializingHasher;

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
        let group_name = format!("LMCS_vs_MMCS/{n_leaves}/goldilocks/{hash_name}/{PARALLEL_STR}");
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
    bench_hash(c, &gl_keccak::test_lmcs(), &gl_keccak_mmcs(), "keccak");
    bench_hash(c, &gl_blake3_192::test_lmcs(), &gl_blake3_192_mmcs(), "blake3-192");
}

// =============================================================================
// Criterion groups
// =============================================================================

criterion_group! {
    name = mmcs_compare;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_secs(12))
        .warm_up_time(std::time::Duration::from_secs(3));
    targets = bench_lmcs_vs_mmcs
}

criterion_main!(mmcs_compare);
