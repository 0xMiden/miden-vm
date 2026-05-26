use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_assembly::Assembler;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, FastProcessor, Felt, Program, StackInputs, Word, ZERO};

const MMR_PTR: u32 = 1000;
const MMR_SIZES: &[u32] = &[1_000, 1_023, 1_024, 50_000, 65_535, 65_536];

fn mmr_pack_and_root(c: &mut Criterion) {
    let core_lib = CoreLibrary::default();
    let mut group = c.benchmark_group("mmr-pack-root");
    group.sampling_mode(SamplingMode::Flat);

    for num_leaves in MMR_SIZES {
        let pack = compile(&core_lib, &mmr_source(*num_leaves, "pack"));
        group.bench_with_input(BenchmarkId::new("pack", num_leaves), &pack, |bench, program| {
            bench.iter_batched(
                || processor_inputs(&core_lib),
                |(mut host, processor)| {
                    black_box(processor.execute_sync(program, &mut host).expect("execute pack"));
                },
                BatchSize::SmallInput,
            );
        });

        let root = compile(&core_lib, &mmr_source(*num_leaves, "root"));
        group.bench_with_input(BenchmarkId::new("root", num_leaves), &root, |bench, program| {
            bench.iter_batched(
                || processor_inputs(&core_lib),
                |(mut host, processor)| {
                    black_box(processor.execute_sync(program, &mut host).expect("execute root"));
                },
                BatchSize::SmallInput,
            );
        });

        let root_with_len = compile(&core_lib, &mmr_source(*num_leaves, "root_with_len"));
        group.bench_with_input(
            BenchmarkId::new("root-with-len", num_leaves),
            &root_with_len,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute root_with_len"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn compile(core_lib: &CoreLibrary, source: &str) -> Program {
    Assembler::default()
        .with_static_library(core_lib.library())
        .expect("link core library")
        .assemble_program(source)
        .expect("assemble benchmark program")
}

fn processor_inputs(core_lib: &CoreLibrary) -> (DefaultHost, FastProcessor) {
    let mut host = DefaultHost::default();
    host.load_library(core_lib).expect("load core library host data");
    (host, FastProcessor::new(StackInputs::default()))
}

fn mmr_source(num_leaves: u32, proc_name: &str) -> String {
    let mut source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{num_leaves} push.{MMR_PTR} mem_store drop
        "
    );

    for peak_idx in 0..num_leaves.count_ones() {
        let peak = word_from_u64(peak_idx as u64 + 1);
        source.push_str(&format!(
            "
            {} push.{} mem_storew_le dropw
            ",
            push_word(peak),
            MMR_PTR + 4 + peak_idx * 4,
        ));
    }

    source.push_str(&format!(
        "
            push.{MMR_PTR} exec.mmr::{proc_name}
            swapw dropw
        end
        "
    ));

    source
}

fn push_word(word: Word) -> String {
    let [a, b, c, d]: [Felt; 4] = word.into();
    format!(
        "push.{}.{}.{}.{}",
        d.as_canonical_u64(),
        c.as_canonical_u64(),
        b.as_canonical_u64(),
        a.as_canonical_u64(),
    )
}

fn word_from_u64(value: u64) -> Word {
    [ZERO, ZERO, ZERO, Felt::new_unchecked(value)].into()
}

criterion_group!(mmr_group, mmr_pack_and_root);
criterion_main!(mmr_group);
