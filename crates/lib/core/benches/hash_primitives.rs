use std::hint::black_box;

use criterion::{
    BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use miden_core_lib::CoreLibrary;

mod common;
use common::{compile, processor_inputs, push_word, word_from_u64};

const HASH_COUNTS: &[usize] = &[1, 8, 64, 256];
const MEM_PTR: u32 = 1000;

fn hash_primitives(c: &mut Criterion) {
    let core_lib = CoreLibrary::default();

    let mut group = c.benchmark_group("hash-primitives");
    group.sampling_mode(SamplingMode::Flat);

    for hash_count in HASH_COUNTS {
        group.throughput(Throughput::Elements(*hash_count as u64));

        let hmerge = compile(&core_lib, &merge_source(*hash_count, MergeKind::Hmerge));
        group.bench_with_input(
            BenchmarkId::new("hmerge-chain", hash_count),
            &hmerge,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute hmerge-chain"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let mtree_merge = compile(&core_lib, &merge_source(*hash_count, MergeKind::MtreeMerge));
        group.bench_with_input(
            BenchmarkId::new("mtree-merge-chain", hash_count),
            &mtree_merge,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute mtree-merge-chain"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let poseidon2_merge =
            compile(&core_lib, &merge_source(*hash_count, MergeKind::Poseidon2Merge));
        group.bench_with_input(
            BenchmarkId::new("poseidon2-merge-chain", hash_count),
            &poseidon2_merge,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute poseidon2-merge-chain"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let hash_double_words = compile(&core_lib, &hash_double_words_source(*hash_count));
        group.bench_with_input(
            BenchmarkId::new("hash-double-words-with-mem-init", hash_count),
            &hash_double_words,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute hash-double-words-with-mem-init"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

#[derive(Clone, Copy)]
enum MergeKind {
    Hmerge,
    MtreeMerge,
    Poseidon2Merge,
}

fn merge_source(hash_count: usize, kind: MergeKind) -> String {
    assert!(hash_count > 0);

    let import = match kind {
        MergeKind::Poseidon2Merge => "use miden::core::crypto::hashes::poseidon2\n",
        MergeKind::Hmerge | MergeKind::MtreeMerge => "",
    };
    let merge = match kind {
        MergeKind::Hmerge => "hmerge",
        MergeKind::MtreeMerge => "mtree_merge",
        MergeKind::Poseidon2Merge => "exec.poseidon2::merge",
    };

    let mut source = format!(
        "
        {import}
        begin
            {}
            {}
            {merge}
        ",
        push_word(word_from_u64(1)),
        push_word(word_from_u64(2)),
    );

    for _ in 1..hash_count {
        source.push_str(&format!(
            "
            dupw {merge}
            "
        ));
    }

    source.push_str(
        "
            dropw
        end
        ",
    );
    source
}

fn hash_double_words_source(double_word_count: usize) -> String {
    let end_ptr = MEM_PTR + (double_word_count as u32 * 8);
    let mut source = String::from(
        "
        use miden::core::crypto::hashes::poseidon2

        begin
        ",
    );

    for word_idx in 0..(double_word_count * 2) {
        let word = word_from_u64(word_idx as u64 + 1);
        source.push_str(&format!(
            "
            {} push.{} mem_storew_le dropw
            ",
            push_word(word),
            MEM_PTR + word_idx as u32 * 4,
        ));
    }

    source.push_str(&format!(
        "
            push.{end_ptr} push.{MEM_PTR}
            exec.poseidon2::hash_double_words
            dropw
        end
        "
    ));
    source
}

criterion_group!(hash_group, hash_primitives);
criterion_main!(hash_group);
