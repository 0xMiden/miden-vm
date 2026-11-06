//! SMT construction, batch insertion, and batch updates.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use criterion::{
    BatchSize, BenchmarkGroup, Criterion, criterion_group, criterion_main, measurement::WallTime,
};
use miden_crypto::{EMPTY_WORD, Felt, ONE, Word, hash::eidos::Eidos, merkle::smt::Smt};

fn parameter(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(value) => value.parse().unwrap_or_else(|_| panic!("{name} must be a positive integer")),
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => panic!("invalid {name}: {error}"),
    }
}

fn bench_batch(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    tree: &mut Smt,
    entries: &[(Word, Word)],
) {
    let original_root = tree.root();
    let mutations = tree.compute_mutations(entries.iter().copied()).unwrap();
    let reverse = tree.apply_mutations_with_reversion(mutations).unwrap();
    let updated_root = tree.root();
    assert_ne!(original_root, updated_root);
    tree.apply_mutations(reverse.clone()).unwrap();

    group.bench_function(name, |b| {
        b.iter_custom(|iterations| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iterations {
                let start = Instant::now();
                let mutations = tree.compute_mutations(black_box(entries.iter().copied())).unwrap();
                tree.apply_mutations(mutations).unwrap();
                elapsed += start.elapsed();

                // Restore the tree outside the timed section so each iteration does the same work.
                assert_eq!(tree.root(), updated_root);
                tree.apply_mutations(reverse.clone()).unwrap();
                assert_eq!(tree.root(), original_root);
            }
            elapsed
        });
    });
}

fn smt_summary(c: &mut Criterion) {
    let size = parameter("SMT_BENCH_SIZE", 1_000_000);
    let batch_size = parameter("SMT_BENCH_BATCH_SIZE", 1_000);
    assert!(size > 0 && batch_size > 0 && batch_size <= size);
    let total = size.checked_add(batch_size).expect("SMT benchmark size overflow");
    let entries: Vec<_> = (0..total)
        .map(|i| {
            let index = u64::try_from(i).unwrap();
            (
                Eidos::hash(&index.to_le_bytes()),
                Word::new([ONE, ONE, ONE, Felt::new(index).expect("index must fit in the field")]),
            )
        })
        .collect();
    let (initial, inserted) = entries.split_at(size);
    let mode = if cfg!(feature = "concurrent") {
        "concurrent"
    } else {
        "sequential"
    };
    let mut group = c.benchmark_group(format!("smt-summary/{mode}/{size}/{batch_size}"));

    group.bench_function("construction", |b| {
        b.iter_batched(
            || initial.to_vec(),
            |entries| Smt::with_entries(black_box(entries)).unwrap(),
            BatchSize::PerIteration,
        );
    });

    let mut tree = Smt::with_entries(initial.iter().copied()).unwrap();
    assert_eq!(tree.num_entries(), size);
    eprintln!("SMT benchmark root: {:?}", tree.root());
    bench_batch(&mut group, "insert", &mut tree, inserted);

    let updates: Vec<_> = initial[..batch_size]
        .iter()
        .enumerate()
        .map(|(i, &(key, _))| {
            let value = if i % 5 == 0 {
                EMPTY_WORD
            } else {
                Word::new([Felt::from(2u8), ONE, ONE, Felt::new(i as u64).unwrap()])
            };
            (key, value)
        })
        .collect();
    bench_batch(&mut group, "update", &mut tree, &updates);
    group.finish();
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default().sample_size(10).measurement_time(Duration::from_secs(5));
    targets = smt_summary
}
criterion_main!(benchmarks);
