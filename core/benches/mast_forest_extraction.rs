//! Benchmark sparse extraction against replay-builder finalization and dense rebuilding.
//!
//! Criterion reports elapsed time. Comparisons with replay and dense rebuilding also report
//! allocation calls and requested bytes per operation. All timings exclude fixture construction.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    sync::Arc,
};

use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use miden_core::{
    Felt,
    mast::{
        BasicBlockNodeBuilder, CallNodeBuilder, DenseMastForestBuilder, JoinNodeBuilder,
        MastForest, MastForestContributor, MastNodeExt, MastNodeId, SparseMastForest,
        SparseMastForestBuilder, VisitKind,
    },
    operations::Operation,
};

#[derive(Clone, Copy, Default)]
struct AllocationStats {
    allocation_calls: usize,
    reallocation_calls: usize,
    requested_bytes: usize,
}

thread_local! {
    static ALLOCATION_STATS: Cell<Option<AllocationStats>> = const { Cell::new(None) };
}

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record_allocation(requested_bytes: usize, is_reallocation: bool) {
    let _ = ALLOCATION_STATS.try_with(|stats| {
        let Some(mut current) = stats.get() else {
            return;
        };
        if is_reallocation {
            current.reallocation_calls += 1;
        } else {
            current.allocation_calls += 1;
        }
        current.requested_bytes = current.requested_bytes.saturating_add(requested_bytes);
        stats.set(Some(current));
    });
}

// SAFETY: every allocation and deallocation is forwarded to the system allocator unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size(), false);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size(), false);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation(new_size, true);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

struct ExtractionFixture {
    source: Arc<MastForest>,
    roots: Vec<MastNodeId>,
    reachable: Vec<MastNodeId>,
}

impl ExtractionFixture {
    fn new(source: MastForest, roots: Vec<MastNodeId>) -> Self {
        let reachable = collect_reachable(&source, &roots);
        Self {
            source: Arc::new(source),
            roots,
            reachable,
        }
    }
}

fn collect_reachable(source: &MastForest, roots: &[MastNodeId]) -> Vec<MastNodeId> {
    let mut reachable = BTreeSet::new();
    let mut unvisited = roots.to_vec();
    while let Some(node_id) = unvisited.pop() {
        if !reachable.insert(node_id) {
            continue;
        }
        source
            .get_node_by_id(node_id)
            .expect("benchmark roots and children must exist")
            .append_children_to(&mut unvisited);
    }
    reachable.into_iter().collect()
}

fn direct_extraction(fixture: &ExtractionFixture) -> SparseMastForest {
    SparseMastForest::from_procedure_roots(fixture.source.as_ref(), &fixture.roots)
        .expect("benchmark roots must be exported")
}

fn replay_builder_extraction(fixture: &ExtractionFixture) -> SparseMastForest {
    let mut builder = SparseMastForestBuilder::new(Arc::clone(&fixture.source));
    for &node_id in &fixture.reachable {
        builder.record_visit(node_id, VisitKind::FullVisit);
    }
    builder.finalize()
}

fn dense_rebuild(fixture: &ExtractionFixture) -> MastForest {
    let mut builder = DenseMastForestBuilder::new();
    let mut remapping = BTreeMap::new();

    for &source_id in &fixture.reachable {
        let node_builder = fixture.source[source_id]
            .clone()
            .to_builder(fixture.source.as_ref())
            .remap_children(&remapping);
        let rebuilt_id = builder.push_node(node_builder).expect("benchmark graph must rebuild");
        remapping.insert(source_id, rebuilt_id);
    }
    for root in &fixture.roots {
        builder.mark_root(remapping[root]);
    }

    builder.build().expect("benchmark graph must finalize")
}

fn measure_allocations<T>(operation: impl FnOnce() -> T) -> AllocationStats {
    ALLOCATION_STATS.with(|stats| {
        assert!(stats.replace(Some(AllocationStats::default())).is_none());
    });
    drop(black_box(operation()));
    ALLOCATION_STATS.with(|stats| stats.replace(None).expect("allocation counter must be active"))
}

fn register_operation<T>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    group_name: &str,
    parameter: &str,
    method: &str,
    fixture: &ExtractionFixture,
    operation: fn(&ExtractionFixture) -> T,
) {
    let stats = measure_allocations(|| operation(fixture));
    println!(
        "allocation_stats group={group_name} case={parameter} method={method} allocations={} reallocations={} requested_bytes={}",
        stats.allocation_calls, stats.reallocation_calls, stats.requested_bytes
    );

    group.bench_with_input(BenchmarkId::new(method, parameter), fixture, |b, fixture| {
        b.iter(|| black_box(operation(fixture)));
    });
}

fn bench_fixture(
    group: &mut BenchmarkGroup<'_, WallTime>,
    group_name: &str,
    parameter: String,
    fixture: &ExtractionFixture,
) {
    group.throughput(Throughput::Elements(fixture.reachable.len() as u64));
    register_operation(group, group_name, &parameter, "direct_sparse", fixture, direct_extraction);
    register_operation(
        group,
        group_name,
        &parameter,
        "replay_builder",
        fixture,
        replay_builder_extraction,
    );
    register_operation(group, group_name, &parameter, "dense_rebuild", fixture, dense_rebuild);
}

fn append_block(forest: &mut MastForest, seed: u64, operation_count: usize) -> MastNodeId {
    let operations = (0..operation_count)
        .map(|offset| {
            let value = Felt::new(seed.wrapping_add(offset as u64))
                .expect("benchmark seeds must fit the base field");
            Operation::Push(value)
        })
        .collect();
    BasicBlockNodeBuilder::new(operations)
        .add_to_forest(forest)
        .expect("benchmark block must be valid")
}

fn append_call_chain(
    forest: &mut MastForest,
    depth: usize,
    seed: u64,
    operation_count: usize,
) -> MastNodeId {
    let mut root = append_block(forest, seed, operation_count);
    for _ in 0..depth {
        root = CallNodeBuilder::new(root)
            .add_to_forest(forest)
            .expect("benchmark call must be valid");
    }
    root
}

fn source_size_fixture(source_nodes: usize) -> ExtractionFixture {
    const REACHABLE_NODES: usize = 32;

    let mut source = MastForest::new();
    for seed in 0..source_nodes.saturating_sub(REACHABLE_NODES) {
        append_block(&mut source, seed as u64, 1);
    }
    let root = append_call_chain(&mut source, REACHABLE_NODES - 1, 1_000_000, 1);
    source.make_root(root);
    ExtractionFixture::new(source, vec![root])
}

fn call_chain_fixture(reachable_nodes: usize) -> ExtractionFixture {
    let mut source = MastForest::new();
    let root = append_call_chain(&mut source, reachable_nodes - 1, 2_000_000, 1);
    source.make_root(root);
    ExtractionFixture::new(source, vec![root])
}

fn selected_roots_fixture(root_count: usize) -> ExtractionFixture {
    const NODES_PER_ROOT: usize = 16;

    let mut source = MastForest::new();
    let mut roots = Vec::with_capacity(root_count);
    for root_index in 0..root_count {
        let root =
            append_call_chain(&mut source, NODES_PER_ROOT - 1, 3_000_000 + root_index as u64, 1);
        source.make_root(root);
        roots.push(root);
    }
    ExtractionFixture::new(source, roots)
}

fn shared_descendants_fixture(root_count: usize) -> ExtractionFixture {
    let mut source = MastForest::new();
    let shared = append_call_chain(&mut source, 31, 4_000_000, 1);
    let mut roots = Vec::with_capacity(root_count);
    for root_index in 0..root_count {
        let leaf = append_block(&mut source, 5_000_000 + root_index as u64, 1);
        let root = JoinNodeBuilder::new([shared, leaf])
            .add_to_forest(&mut source)
            .expect("benchmark join must be valid");
        source.make_root(root);
        roots.push(root);
    }
    ExtractionFixture::new(source, roots)
}

fn large_payload_fixture(operation_count: usize) -> ExtractionFixture {
    let mut source = MastForest::new();
    let root = append_block(&mut source, 6_000_000, operation_count);
    source.make_root(root);
    ExtractionFixture::new(source, vec![root])
}

fn bench_source_size(c: &mut Criterion) {
    const GROUP: &str = "mast_forest_extraction/source_size";
    let mut group = c.benchmark_group(GROUP);
    for source_nodes in [64, 256, 1_024, 4_096, 16_384] {
        let fixture = source_size_fixture(source_nodes);
        bench_fixture(&mut group, GROUP, format!("source_nodes={source_nodes}"), &fixture);
    }
    group.finish();
}

fn bench_reachable_size(c: &mut Criterion) {
    const GROUP: &str = "mast_forest_extraction/reachable_size";
    let mut group = c.benchmark_group(GROUP);
    for reachable_nodes in [8, 64, 512, 4_096] {
        let fixture = call_chain_fixture(reachable_nodes);
        bench_fixture(&mut group, GROUP, format!("reachable_nodes={reachable_nodes}"), &fixture);
    }
    group.finish();
}

fn bench_selected_roots(c: &mut Criterion) {
    const GROUP: &str = "mast_forest_extraction/selected_roots";
    let mut group = c.benchmark_group(GROUP);
    for root_count in [1, 4, 16, 64] {
        let fixture = selected_roots_fixture(root_count);
        bench_fixture(&mut group, GROUP, format!("roots={root_count}"), &fixture);
    }
    group.finish();
}

fn bench_shared_descendants(c: &mut Criterion) {
    const GROUP: &str = "mast_forest_extraction/shared_descendants";
    let mut group = c.benchmark_group(GROUP);
    for root_count in [2, 8, 32, 128] {
        let fixture = shared_descendants_fixture(root_count);
        bench_fixture(&mut group, GROUP, format!("roots={root_count}"), &fixture);
    }
    group.finish();
}

fn bench_large_payloads(c: &mut Criterion) {
    const GROUP: &str = "mast_forest_extraction/large_payloads";
    let mut group = c.benchmark_group(GROUP);
    for operation_count in [8, 64, 512, 4_096] {
        let fixture = large_payload_fixture(operation_count);
        bench_fixture(&mut group, GROUP, format!("operations={operation_count}"), &fixture);
    }
    group.finish();
}

/// Times single-leaf extraction as the source root count grows. For procedures with equal
/// digests, it measures the cost of adding dense conversion when bodies are copied or pruned.
fn bench_procedure_boundaries(c: &mut Criterion) {
    let mut group = c.benchmark_group("mast_forest_extraction/procedure_boundaries");
    for count in [16, 1_024, 16_384] {
        let mut builder = DenseMastForestBuilder::new();
        for i in 0..count {
            let root = builder
                .push_node(BasicBlockNodeBuilder::new(vec![Operation::Push(Felt::from_u32(i))]))
                .unwrap();
            builder.mark_root(root);
        }
        let source = builder.build().unwrap();
        let roots = source.procedure_roots();
        for (case, root) in [("first_leaf", roots[0]), ("last_leaf", roots[roots.len() - 1])] {
            group.bench_function(BenchmarkId::new(case, count), |b| {
                b.iter(|| {
                    SparseMastForest::from_procedure_roots_with_externals(&source, &[root], |_| {
                        false
                    })
                    .unwrap()
                });
            });
        }
    }

    // These procedures differ in their assertion codes but have the same digest. Sparse
    // extraction retains the source IDs, while dense conversion selects one body.
    let mut builder = DenseMastForestBuilder::new();
    let mut level = Vec::new();
    for code in 0..64 {
        let mut id = builder
            .push_node(BasicBlockNodeBuilder::new(vec![Operation::Assert(Felt::from_u32(code))]))
            .unwrap();
        for _ in 1..32 {
            id = builder.push_node(CallNodeBuilder::new(id)).unwrap();
        }
        builder.mark_root(id);
        level.push(id);
    }
    while level.len() > 1 {
        let (pairs, _) = level.as_chunks::<2>();
        level = pairs
            .iter()
            .map(|&pair| builder.push_node(JoinNodeBuilder::new(pair)).unwrap())
            .collect();
    }
    let root = level[0];
    builder.mark_root(root);
    let (source, ids) = builder.build_with_id_map().unwrap();
    let roots = [ids.get(root).unwrap()];
    for (case, known) in [("known", true), ("unknown", false)] {
        let extract = || {
            SparseMastForest::from_procedure_roots_with_externals(&source, &roots, |_| known)
                .unwrap()
        };
        group.bench_function(BenchmarkId::new("aliases_sparse", case), |b| b.iter(extract));
        group.bench_function(BenchmarkId::new("aliases_sparse_then_dense", case), |b| {
            b.iter(|| extract().to_mast_forest_with_externals().unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_source_size,
    bench_reachable_size,
    bench_selected_roots,
    bench_shared_descendants,
    bench_large_payloads,
    bench_procedure_boundaries,
);
criterion_main!(benches);
