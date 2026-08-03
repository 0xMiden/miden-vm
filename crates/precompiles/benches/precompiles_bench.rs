use std::{hint::black_box, time::Duration};

use codspeed_criterion_compat as criterion;
use criterion::{Criterion, SamplingMode, criterion_group, criterion_main};
use miden_vm::HashFunction;

#[path = "precompiles_bench/support.rs"]
mod support;

use support::{
    DEFAULT_ECDSAS, DEFAULT_KECCAKS, PrecompileFixture, PrecompileWorkload, prove_once_with_hash,
    verify_once,
};

const PROOF_HASHES: [(&str, HashFunction); 2] =
    [("blake3", HashFunction::Blake3_256), ("poseidon2", HashFunction::Poseidon2)];

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).map_or(default, |raw| {
        raw.parse().unwrap_or_else(|err| panic!("{name} must be numeric: {err}"))
    })
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).map_or(default, |raw| {
        raw.parse().unwrap_or_else(|err| panic!("{name} must be numeric: {err}"))
    })
}

fn precompiles_bench(c: &mut Criterion) {
    let sample_size = env_usize("PRECOMPILE_BENCH_SAMPLE_SIZE", 10);
    assert!(sample_size >= 10, "PRECOMPILE_BENCH_SAMPLE_SIZE must be at least 10");

    let workload = PrecompileWorkload {
        keccaks: env_usize("PRECOMPILE_BENCH_KECCAKS", DEFAULT_KECCAKS),
        ecdsas: env_usize("PRECOMPILE_BENCH_ECDSAS", DEFAULT_ECDSAS),
    };
    let fixture = PrecompileFixture::generate(workload);

    let mut group = c.benchmark_group(format!(
        "precompiles/ecdsa{}_keccak{}",
        workload.ecdsas, workload.keccaks,
    ));
    group.sample_size(sample_size);
    group.measurement_time(Duration::from_secs(env_u64("PRECOMPILE_BENCH_MEASUREMENT_SECS", 60)));
    group.warm_up_time(Duration::from_secs(env_u64("PRECOMPILE_BENCH_WARM_UP_SECS", 1)));
    group.sampling_mode(SamplingMode::Flat);

    for (name, proof_hash) in PROOF_HASHES {
        let (stack_outputs, proof) = prove_once_with_hash(&fixture, proof_hash);
        verify_once(&fixture, stack_outputs, proof);

        group.bench_function(format!("{name}/prove"), |b| {
            b.iter_custom(|iterations| {
                let mut total = Duration::ZERO;
                for _ in 0..iterations {
                    let started_at = std::time::Instant::now();
                    black_box(prove_once_with_hash(&fixture, proof_hash));
                    total += started_at.elapsed();
                }
                total
            });
        });
    }

    group.finish();
}

criterion_group!(benches, precompiles_bench);
criterion_main!(benches);
