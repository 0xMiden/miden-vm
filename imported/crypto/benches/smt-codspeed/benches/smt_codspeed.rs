use std::{hint::black_box, time::Duration};

use criterion::{
    BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use miden_crypto::{
    Felt, ONE, Word,
    merkle::smt::{
        LargeSmt, LeafIndex, MemoryStorage, RocksDbConfig, RocksDbStorage, SimpleSmt, Smt,
    },
};

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<usize>()
                .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn env_duration_millis(name: &str, default: u64) -> Duration {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<u64>()
                .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}"));
            assert!(value > 0, "{name} must be greater than zero");
            Duration::from_millis(value)
        },
        Err(_) => Duration::from_millis(default),
    }
}

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(env_usize("CRYPTO_SMT_SAMPLE_SIZE", 10))
        .measurement_time(env_duration_millis("CRYPTO_SMT_MEASUREMENT_TIME_MILLIS", 1_000))
        .warm_up_time(env_duration_millis("CRYPTO_SMT_WARM_UP_TIME_MILLIS", 250))
}

fn configure_group<M: criterion::measurement::Measurement>(
    group: &mut criterion::BenchmarkGroup<M>,
) {
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(env_usize("CRYPTO_SMT_SAMPLE_SIZE", 10))
        .measurement_time(env_duration_millis("CRYPTO_SMT_MEASUREMENT_TIME_MILLIS", 1_000))
        .warm_up_time(env_duration_millis("CRYPTO_SMT_WARM_UP_TIME_MILLIS", 250));
}

fn word(seed: u64) -> Word {
    Word::new([
        Felt::new_unchecked(seed),
        ONE,
        Felt::new_unchecked(seed.wrapping_mul(17)),
        Felt::new_unchecked(seed.wrapping_mul(65_537)),
    ])
}

fn value(seed: u64) -> Word {
    Word::new([
        Felt::new_unchecked(seed.wrapping_add(1)),
        Felt::new_unchecked(seed.wrapping_add(2)),
        Felt::new_unchecked(seed.wrapping_add(3)),
        Felt::new_unchecked(seed.wrapping_add(4)),
    ])
}

fn entries(count: usize, offset: u64) -> Vec<(Word, Word)> {
    (0..count as u64).map(|i| (word(offset + i), value(offset + i))).collect()
}

fn simple_entries(count: usize) -> Vec<(u64, Word)> {
    (0..count as u64).map(|i| (i, value(i))).collect()
}

fn keys(count: usize, offset: u64) -> Vec<Word> {
    (0..count as u64).map(|i| word(offset + i)).collect()
}

fn smt_benches(c: &mut Criterion) {
    let mut construction = c.benchmark_group("smt/construction");
    configure_group(&mut construction);
    for size in [256, 4_096] {
        construction.throughput(Throughput::Elements(size as u64));
        construction.bench_function(BenchmarkId::new("Smt::with_entries", size), |bench| {
            bench.iter_batched(
                || entries(size, 0),
                |entries| black_box(Smt::with_entries(entries).unwrap()),
                BatchSize::LargeInput,
            );
        });
        construction.bench_function(BenchmarkId::new("SimpleSmt::with_leaves", size), |bench| {
            bench.iter_batched(
                || simple_entries(size),
                |entries| black_box(SimpleSmt::<32>::with_leaves(entries).unwrap()),
                BatchSize::LargeInput,
            );
        });
    }
    construction.finish();

    let smt = Smt::with_entries(entries(4_096, 0)).unwrap();
    let open_keys = keys(32, 0);
    let mut reads = c.benchmark_group("smt/read");
    configure_group(&mut reads);
    reads.throughput(Throughput::Elements(open_keys.len() as u64));
    reads.bench_function("Smt::open/32", |bench| {
        bench.iter(|| {
            for key in &open_keys {
                black_box(smt.open(key));
            }
        });
    });

    let simple_smt = SimpleSmt::<32>::with_leaves(simple_entries(4_096)).unwrap();
    let simple_keys: Vec<_> = (0..32).map(|i| LeafIndex::<32>::new(i).unwrap()).collect();
    reads.bench_function("SimpleSmt::open/32", |bench| {
        bench.iter(|| {
            for key in &simple_keys {
                black_box(simple_smt.open(key));
            }
        });
    });
    reads.finish();

    let mut mutations = c.benchmark_group("smt/mutations");
    configure_group(&mut mutations);
    for size in [32, 256] {
        mutations.throughput(Throughput::Elements(size as u64));
        mutations.bench_function(BenchmarkId::new("Smt::compute_mutations", size), |bench| {
            let smt = Smt::with_entries(entries(4_096, 0)).unwrap();
            let updates = entries(size, 10_000);
            bench.iter(|| black_box(smt.compute_mutations(updates.clone()).unwrap()));
        });
        mutations.bench_function(BenchmarkId::new("Smt::apply_mutations", size), |bench| {
            bench.iter_batched(
                || {
                    let smt = Smt::with_entries(entries(4_096, 0)).unwrap();
                    let mutations = smt.compute_mutations(entries(size, 10_000)).unwrap();
                    (smt, mutations)
                },
                |(mut smt, mutations)| {
                    smt.apply_mutations(mutations).unwrap();
                    black_box(())
                },
                BatchSize::LargeInput,
            );
        });
    }
    mutations.finish();
}

fn large_smt_memory_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_smt/memory");
    configure_group(&mut group);

    group.bench_function("open/32", |bench| {
        let smt = LargeSmt::with_entries(MemoryStorage::new(), entries(4_096, 0)).unwrap();
        let open_keys = keys(32, 0);
        bench.iter(|| {
            for key in &open_keys {
                black_box(smt.open(key));
            }
        });
    });

    for size in [128, 1_024] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(BenchmarkId::new("compute_mutations", size), |bench| {
            let smt = LargeSmt::with_entries(MemoryStorage::new(), entries(4_096, 0)).unwrap();
            let updates = entries(size, 10_000);
            bench.iter(|| black_box(smt.compute_mutations(updates.clone()).unwrap()));
        });
        group.bench_function(BenchmarkId::new("apply_mutations", size), |bench| {
            bench.iter_batched(
                || {
                    let smt =
                        LargeSmt::with_entries(MemoryStorage::new(), entries(4_096, 0)).unwrap();
                    let mutations = smt.compute_mutations(entries(size, 10_000)).unwrap();
                    (smt, mutations)
                },
                |(mut smt, mutations)| {
                    smt.apply_mutations(mutations).unwrap();
                    black_box(())
                },
                BatchSize::LargeInput,
            );
        });
        group.bench_function(BenchmarkId::new("insert_batch/populated", size), |bench| {
            bench.iter_batched(
                || {
                    let smt =
                        LargeSmt::with_entries(MemoryStorage::new(), entries(4_096, 0)).unwrap();
                    let batch = entries(size, 10_000);
                    (smt, batch)
                },
                |(mut smt, batch)| black_box(smt.insert_batch(batch).unwrap()),
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn rocksdb_smt(entries_count: usize) -> (tempfile::TempDir, LargeSmt<RocksDbStorage>) {
    let temp_dir = tempfile::TempDir::new().unwrap();
    let storage = RocksDbStorage::open(RocksDbConfig::new(temp_dir.path())).unwrap();
    let smt = LargeSmt::with_entries(storage, entries(entries_count, 0)).unwrap();
    (temp_dir, smt)
}

fn large_smt_rocksdb_benches(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_smt/rocksdb");
    configure_group(&mut group);

    group.bench_function("open/32", |bench| {
        let (_temp_dir, smt) = rocksdb_smt(4_096);
        let open_keys = keys(32, 0);
        bench.iter(|| {
            for key in &open_keys {
                black_box(smt.open(key));
            }
        });
    });

    for size in [128, 1_024] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(BenchmarkId::new("compute_mutations", size), |bench| {
            let (_temp_dir, smt) = rocksdb_smt(4_096);
            let updates = entries(size, 10_000);
            bench.iter(|| black_box(smt.compute_mutations(updates.clone()).unwrap()));
        });
        group.bench_function(BenchmarkId::new("apply_mutations", size), |bench| {
            bench.iter_batched(
                || {
                    let (temp_dir, smt) = rocksdb_smt(4_096);
                    let mutations = smt.compute_mutations(entries(size, 10_000)).unwrap();
                    (temp_dir, smt, mutations)
                },
                |(_temp_dir, mut smt, mutations)| {
                    smt.apply_mutations(mutations).unwrap();
                    black_box(())
                },
                BatchSize::LargeInput,
            );
        });
        group.bench_function(BenchmarkId::new("insert_batch/populated", size), |bench| {
            bench.iter_batched(
                || {
                    let (temp_dir, smt) = rocksdb_smt(4_096);
                    let batch = entries(size, 10_000);
                    (temp_dir, smt, batch)
                },
                |(_temp_dir, mut smt, batch)| black_box(smt.insert_batch(batch).unwrap()),
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = smt_benches, large_smt_memory_benches, large_smt_rocksdb_benches
}
criterion_main!(benches);
