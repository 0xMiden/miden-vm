use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_core::crypto::hash::Poseidon2;
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, EMPTY_WORD, FastProcessor, Felt, StackInputs, Word, ZERO, advice::AdviceInputs,
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

        let mmb_root = compile(&core_lib, &mmb_source(*num_leaves as usize, "mmb_root"));
        group.bench_with_input(
            BenchmarkId::new("mmb-root", num_leaves),
            &mmb_root,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor.execute_sync(program, &mut host).expect("execute mmb_root"),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        let mmb_root_with_len =
            compile(&core_lib, &mmb_source(*num_leaves as usize, "mmb_root_with_len"));
        group.bench_with_input(
            BenchmarkId::new("mmb-root-with-len", num_leaves),
            &mmb_root_with_len,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute mmb_root_with_len"),
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

fn mmb_recency(c: &mut Criterion) {
    let core_lib = CoreLibrary::default();
    let mut group = c.benchmark_group("mmb-recency");
    group.sampling_mode(SamplingMode::Flat);

    let mmb = TestMmb::from_len(65_536);
    let root = mmb.root();

    for recency in [1usize, 4, 16, 64, 128, 512, 1_024, 4_096, 16_384] {
        let position = mmb.len - recency;
        let proof = mmb.open(position);
        let program = compile(&core_lib, &mmb_verify_source(mmb.len, root, &proof));

        group.bench_with_input(
            BenchmarkId::new("mmb-verify", recency),
            &program,
            |bench, program| {
                bench.iter_batched(
                    || processor_inputs(&core_lib),
                    |(mut host, processor)| {
                        black_box(
                            processor
                                .execute_sync(program, &mut host)
                                .expect("execute mmb_verify_leaf"),
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
    let host = DefaultHost::default()
        .with_library(core_lib)
        .expect("load core library host data");
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

fn mmb_source(num_leaves: usize, proc_name: &str) -> String {
    let mmb = TestMmb::from_len(num_leaves);
    let mut source = format!(
        "
        use miden::core::collections::mmr

        begin
            {}
            push.{MMR_PTR} exec.mmr::{proc_name}
        ",
        mmb_memory_source(MMR_PTR, &mmb),
    );
    if proc_name == "mmb_root_with_len" {
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

struct TestMmb {
    len: usize,
    mountains: Vec<TestMountain>,
}

struct TestMountain {
    start: usize,
    height: u8,
    root: Word,
    node: Box<TestMmbNode>,
}

enum TestMmbNode {
    Leaf(Word),
    Inner {
        root: Word,
        left: Box<TestMmbNode>,
        right: Box<TestMmbNode>,
    },
}

struct TestMmbProof {
    position: usize,
    leaf: Word,
    siblings: Vec<TestMmbProofStep>,
}

struct TestMmbProofStep {
    is_right: bool,
    sibling: Word,
}

#[derive(Clone, Copy)]
struct ShapeMountain {
    height: usize,
}

enum FoldDomain {
    Range,
    Belt,
}

impl TestMmb {
    fn from_len(len: usize) -> Self {
        let mut mmb = Self { len: 0, mountains: Vec::new() };

        for idx in 0..len {
            mmb.append(word_from_u64(idx as u64 + 1));
        }

        mmb
    }

    fn append(&mut self, leaf: Word) {
        self.mountains.push(TestMountain::leaf(self.len, leaf));
        self.len += 1;

        if let Some(right_idx) = self.rightmost_mergeable_pair() {
            let right = self.mountains.remove(right_idx);
            let left = self.mountains.remove(right_idx - 1);
            self.mountains.insert(right_idx - 1, TestMountain::merge(left, right));
        }
    }

    fn root(&self) -> Word {
        let shape = shape_mountains(self.len);
        let peaks = self.mountains.iter().map(|mountain| mountain.root).collect::<Vec<_>>();
        bag_peaks(&shape, &peaks)
    }

    fn open(&self, position: usize) -> TestMmbProof {
        assert!(position < self.len);

        let (mountain_idx, mountain) = self
            .mountains
            .iter()
            .enumerate()
            .find(|(_, mountain)| {
                let end = mountain.start + mountain.size();
                (mountain.start..end).contains(&position)
            })
            .expect("position should be in one MMB mountain");

        let mut siblings = Vec::new();
        let leaf = mountain.open(position - mountain.start, &mut siblings);
        let shape = shape_mountains(self.len);
        let peaks = self.mountains.iter().map(|mountain| mountain.root).collect::<Vec<_>>();
        siblings.extend(bagging_path_nodes(&shape, &peaks, mountain_idx));

        TestMmbProof { position, leaf, siblings }
    }

    fn rightmost_mergeable_pair(&self) -> Option<usize> {
        self.mountains
            .windows(2)
            .enumerate()
            .rev()
            .find_map(|(idx, pair)| (pair[0].height == pair[1].height).then_some(idx + 1))
    }
}

impl TestMountain {
    fn leaf(start: usize, leaf: Word) -> Self {
        Self {
            start,
            height: 0,
            root: leaf,
            node: Box::new(TestMmbNode::Leaf(leaf)),
        }
    }

    fn merge(left: Self, right: Self) -> Self {
        assert_eq!(left.height, right.height);

        let root = Poseidon2::merge(&[left.root, right.root]);
        Self {
            start: left.start,
            height: left.height + 1,
            root,
            node: Box::new(TestMmbNode::Inner { root, left: left.node, right: right.node }),
        }
    }

    fn size(&self) -> usize {
        1 << self.height
    }

    fn open(&self, local_pos: usize, siblings: &mut Vec<TestMmbProofStep>) -> Word {
        self.node.open(self.height, local_pos, siblings)
    }
}

impl TestMmbNode {
    fn root(&self) -> Word {
        match self {
            Self::Leaf(root) | Self::Inner { root, .. } => *root,
        }
    }

    fn open(&self, height: u8, local_pos: usize, siblings: &mut Vec<TestMmbProofStep>) -> Word {
        match self {
            Self::Leaf(leaf) => {
                assert_eq!(height, 0);
                assert_eq!(local_pos, 0);
                *leaf
            },
            Self::Inner { left, right, .. } => {
                let half = 1 << (height - 1);
                if local_pos < half {
                    let leaf = left.open(height - 1, local_pos, siblings);
                    siblings.push(TestMmbProofStep::mountain(true, right.root()));
                    leaf
                } else {
                    let leaf = right.open(height - 1, local_pos - half, siblings);
                    siblings.push(TestMmbProofStep::mountain(false, left.root()));
                    leaf
                }
            },
        }
    }
}

impl TestMmbProofStep {
    fn mountain(is_right: bool, sibling: Word) -> Self {
        Self { is_right, sibling }
    }

    fn range(is_right: bool, sibling: Word) -> Self {
        Self { is_right, sibling }
    }

    fn belt(is_right: bool, sibling: Word) -> Self {
        Self { is_right, sibling }
    }
}

impl FoldDomain {
    fn merge(&self, left: Word, right: Word) -> Word {
        match self {
            Self::Range => Poseidon2::merge(&[left, right]),
            Self::Belt => Poseidon2::merge(&[left, right]),
        }
    }
}

fn shape_mountains(num_leaves: usize) -> Vec<ShapeMountain> {
    if num_leaves == 0 {
        return Vec::new();
    }

    let width = floor_log2(num_leaves + 1);
    (0..width)
        .rev()
        .map(|pos| ShapeMountain {
            height: pos + (((num_leaves + 1) >> pos) & 1),
        })
        .collect()
}

fn shape_ranges(mountains: &[ShapeMountain]) -> Vec<std::ops::Range<usize>> {
    if mountains.is_empty() {
        return Vec::new();
    }

    let mut ranges = Vec::new();
    let mut start = 0;
    for idx in 0..mountains.len() - 1 {
        if shape_range_split_after(mountains, idx) {
            ranges.push(start..idx + 1);
            start = idx + 1;
        }
    }
    ranges.push(start..mountains.len());
    ranges
}

fn shape_range_split_after(mountains: &[ShapeMountain], idx: usize) -> bool {
    let left = mountains[idx].height;
    let right = mountains[idx + 1].height;
    left == right + 2 || (idx > 0 && mountains[idx - 1].height == left)
}

fn bag_peaks(shape: &[ShapeMountain], peaks: &[Word]) -> Word {
    let range_roots = shape_ranges(shape)
        .into_iter()
        .map(|range| bag_range(&shape[range.clone()], &peaks[range]))
        .collect::<Vec<_>>();
    bag_belt(&range_roots)
}

fn bag_range(mountains: &[ShapeMountain], peaks: &[Word]) -> Word {
    mountains.iter().zip(peaks).fold(EMPTY_WORD, |acc, (mountain, peak)| {
        let _ = mountain;
        FoldDomain::Range.merge(acc, *peak)
    })
}

fn bag_belt(range_roots: &[Word]) -> Word {
    range_roots
        .iter()
        .fold(EMPTY_WORD, |acc, root| FoldDomain::Belt.merge(acc, *root))
}

fn bagging_path_nodes(
    shape: &[ShapeMountain],
    peaks: &[Word],
    mountain_idx: usize,
) -> Vec<TestMmbProofStep> {
    let ranges = shape_ranges(shape);
    let range_idx = ranges
        .iter()
        .position(|range| range.contains(&mountain_idx))
        .expect("mountain index should belong to a range");
    let range = ranges[range_idx].clone();
    let mut nodes = Vec::new();

    let left_root = bag_range(&shape[range.start..mountain_idx], &peaks[range.start..mountain_idx]);
    nodes.push(TestMmbProofStep::range(false, left_root));

    for &peak in &peaks[mountain_idx + 1..range.end] {
        nodes.push(TestMmbProofStep::range(true, peak));
    }

    let left_range_roots = ranges[..range_idx]
        .iter()
        .map(|range| bag_range(&shape[range.clone()], &peaks[range.clone()]))
        .collect::<Vec<_>>();
    nodes.push(TestMmbProofStep::belt(false, bag_belt(&left_range_roots)));

    for range in &ranges[range_idx + 1..] {
        nodes.push(TestMmbProofStep::belt(
            true,
            bag_range(&shape[range.clone()], &peaks[range.clone()]),
        ));
    }

    nodes
}

fn floor_log2(value: usize) -> usize {
    assert_ne!(value, 0);
    usize::BITS as usize - 1 - value.leading_zeros() as usize
}

fn mmb_memory_source(mmb_ptr: u32, mmb: &TestMmb) -> String {
    let mut source = format!("push.{} push.{mmb_ptr} mem_store drop\n", mmb.len);

    for (idx, mountain) in mmb.mountains.iter().enumerate() {
        source.push_str(&format!(
            "{} push.{} mem_storew_le dropw\n",
            push_word(mountain.root),
            mmb_ptr + 4 + idx as u32 * 4,
        ));
    }

    source
}

fn mmb_verify_source(num_leaves: usize, root: Word, proof: &TestMmbProof) -> String {
    const PROOF_PTR: u32 = 2000;

    format!(
        "
        use miden::core::collections::mmr

        begin
            {}
            push.{num_leaves}
            {}
            push.{PROOF_PTR}
            exec.mmr::mmb_verify_leaf
        end
        ",
        mmb_proof_memory_source(PROOF_PTR, proof),
        push_word(root),
    )
}

fn mmb_proof_memory_source(proof_ptr: u32, proof: &TestMmbProof) -> String {
    let mut source = format!(
        "
        push.{} push.{proof_ptr} mem_store drop
        push.{} push.{} mem_store drop
        {} push.{} mem_storew_le dropw
        ",
        proof.siblings.len(),
        proof.position,
        proof_ptr + 1,
        push_word(proof.leaf),
        proof_ptr + 4,
    );

    for (idx, step) in proof.siblings.iter().enumerate() {
        let entry = proof_ptr + 8 + idx as u32 * 8;
        source.push_str(&format!(
            "
            push.{} push.{entry} mem_store drop
            {} push.{} mem_storew_le dropw
            ",
            u8::from(step.is_right),
            push_word(step.sibling),
            entry + 4,
        ));
    }

    source
}

criterion_group!(mmr_group, mmr_pack_and_root, mmb_recency);
criterion_main!(mmr_group);
