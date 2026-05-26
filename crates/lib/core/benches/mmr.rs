use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_core::crypto::hash::Poseidon2;
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, FastProcessor, Felt, StackInputs, Word, ZERO, advice::AdviceInputs,
};

mod common;
use common::{compile, processor_inputs, push_word, word_from_u64};

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

        let unpack_inputs = unpack_bench_inputs(*num_leaves);

        let unpack = compile(&core_lib, &unpack_source(unpack_inputs.hash, "unpack", None));
        group.bench_with_input(
            BenchmarkId::new("unpack", num_leaves),
            &(unpack, unpack_inputs.legacy_advice_map.clone()),
            |bench, (program, advice_map)| {
                bench.iter_batched(
                    || processor_inputs_with_advice(&core_lib, advice_map.clone()),
                    |(mut host, processor)| {
                        black_box(
                            processor.execute_sync(program, &mut host).expect("execute unpack"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let unpack_frontier = compile(
            &core_lib,
            &unpack_source(unpack_inputs.frontier_root, "unpack_frontier", Some(*num_leaves)),
        );
        group.bench_with_input(
            BenchmarkId::new("unpack-frontier", num_leaves),
            &(unpack_frontier, unpack_inputs.frontier_advice_map),
            |bench, (program, advice_map)| {
                bench.iter_batched(
                    || processor_inputs_with_advice(&core_lib, advice_map.clone()),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute unpack_frontier"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn processor_inputs_with_advice(
    core_lib: &CoreLibrary,
    advice_map: Vec<(Word, Vec<Felt>)>,
) -> (DefaultHost, FastProcessor) {
    let mut host = DefaultHost::default();
    host.load_library(core_lib).expect("load core library host data");
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default().with_map(advice_map),
        Default::default(),
    )
    .expect("processor advice inputs should fit advice map limits");
    (host, processor)
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

    source.push_str(&format!("\n            push.{MMR_PTR} exec.mmr::{proc_name}\n"));
    if proc_name == "root_with_len" {
        source.push_str("            movup.4 drop\n");
    }
    source.push_str(
        "
            swapw dropw
        end
        ",
    );

    source
}

fn unpack_source(commitment: Word, proc_name: &str, num_leaves: Option<u32>) -> String {
    let mut source = format!(
        "
        use miden::core::collections::mmr

        begin
            push.{MMR_PTR}
        "
    );
    if let Some(num_leaves) = num_leaves {
        source.push_str(&format!("            push.{num_leaves}\n"));
    }
    source.push_str(&format!(
        "
            {}
            exec.mmr::{proc_name}
        end
        ",
        push_word(commitment),
    ));

    source
}

struct UnpackBenchInputs {
    hash: Word,
    frontier_root: Word,
    legacy_advice_map: Vec<(Word, Vec<Felt>)>,
    frontier_advice_map: Vec<(Word, Vec<Felt>)>,
}

fn unpack_bench_inputs(num_leaves: u32) -> UnpackBenchInputs {
    let peak_count = num_leaves.count_ones() as usize;
    let peaks: Vec<Word> = (0..peak_count).map(|idx| word_from_u64(idx as u64 + 1)).collect();
    let mut padded_peaks = peaks.clone();
    padded_peaks.resize(padded_peak_count(peak_count), Word::default());

    let hash = Poseidon2::hash_elements(Word::words_as_elements(&padded_peaks));
    let frontier_root = mmr_frontier_root(num_leaves as usize, &peaks);

    let mut advice_value = Vec::with_capacity(Word::NUM_ELEMENTS + padded_peaks.len());
    advice_value.extend_from_slice(&[Felt::new_unchecked(num_leaves as u64), ZERO, ZERO, ZERO]);
    advice_value.extend_from_slice(Word::words_as_elements(&padded_peaks));

    UnpackBenchInputs {
        hash,
        frontier_root,
        legacy_advice_map: vec![(hash, advice_value.clone())],
        frontier_advice_map: vec![(frontier_root, advice_value)],
    }
}

fn padded_peak_count(peak_count: usize) -> usize {
    let peak_count = peak_count.max(16);
    if peak_count > 16 && peak_count % 2 == 1 {
        peak_count + 1
    } else {
        peak_count
    }
}

fn mmr_frontier_root(num_leaves: usize, peaks: &[Word]) -> Word {
    if num_leaves == 0 {
        return Word::default();
    }

    let mut bits = num_leaves;
    let mut peak_idx = peaks.len();
    let mut acc = Word::default();
    let mut empty = Word::default();

    while bits != 0 {
        if bits & 1 == 1 {
            peak_idx -= 1;
            acc = Poseidon2::merge(&[peaks[peak_idx], acc]);
        } else {
            acc = Poseidon2::merge(&[acc, empty]);
        }

        bits >>= 1;
        if bits != 0 {
            empty = Poseidon2::merge(&[empty, empty]);
        }
    }

    acc
}

criterion_group!(mmr_group, mmr_pack_and_root);
criterion_main!(mmr_group);
