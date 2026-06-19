use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_vm_blake3_bench::{
    BENCH_GROUP, Blake3Fixture, build_trace, execute_trace_inputs, prove_and_verify_once,
    prove_span_duration, prove_trace, repo_root_from_manifest,
};

const ALL_AXES: [&str; 4] =
    ["execute_trace_inputs_sync", "build_trace", "prove_trace_sync", "e2e_prove"];
const PROOF_AXES: [&str; 2] = ["e2e_prove", "prove_trace_sync"];
const LIGHT_AXES: [&str; 2] = ["execute_trace_inputs_sync", "build_trace"];

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<usize>()
                .unwrap_or_else(|err| panic!("{name} must be numeric: {err}"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => {
            let value =
                raw.parse::<u64>().unwrap_or_else(|err| panic!("{name} must be numeric: {err}"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn resolve_axes() -> Vec<&'static str> {
    let Some(raw) =
        std::env::var("BLAKE3_BENCH_AXES").ok().filter(|value| !value.trim().is_empty())
    else {
        return ALL_AXES.to_vec();
    };

    let mut requested = Vec::new();
    for axis in raw.split(',').map(str::trim).filter(|axis| !axis.is_empty()) {
        match axis {
            "all" => requested.extend(ALL_AXES),
            "e2e_prove" | "prove" | "prove_program_sync" => requested.push("e2e_prove"),
            "execute_trace_inputs_sync" => requested.push("execute_trace_inputs_sync"),
            "prove_trace_sync" => requested.push("prove_trace_sync"),
            "build_trace" => requested.push("build_trace"),
            _ => panic!(
                "unsupported BLAKE3_BENCH_AXES value `{axis}`; supported values: {}",
                ALL_AXES.join(", ")
            ),
        }
    }
    ALL_AXES.into_iter().filter(|axis| requested.contains(axis)).collect()
}

fn has_axis(axes: &[&str], axis: &str) -> bool {
    axes.contains(&axis)
}

fn blake3_bench(c: &mut Criterion) {
    let axes = resolve_axes();
    let proof_sample_size =
        env_usize("BLAKE3_PROOF_SAMPLE_SIZE", env_usize("BLAKE3_SAMPLE_SIZE", 10));
    let light_sample_size = env_usize("BLAKE3_LIGHT_SAMPLE_SIZE", 100);
    let measurement_time_secs = env_u64("BLAKE3_MEASUREMENT_TIME_SECS", 1);
    let warm_up_time_secs = env_u64("BLAKE3_WARM_UP_TIME_SECS", 1);
    assert!(!axes.is_empty(), "BLAKE3_BENCH_AXES did not select any axes");
    println!("\n=== Blake3 axes: {}", axes.join(", "));
    println!(
        "=== Criterion: proof_sample_size={proof_sample_size} light_sample_size={light_sample_size} measurement_time={measurement_time_secs}s warm_up={warm_up_time_secs}s"
    );

    let fixture = Blake3Fixture::load_from_repo(&repo_root_from_manifest());

    if PROOF_AXES.iter().any(|axis| has_axis(&axes, axis)) {
        prove_and_verify_once(&fixture);

        let mut group = c.benchmark_group(BENCH_GROUP);
        configure_group(&mut group, proof_sample_size, measurement_time_secs, warm_up_time_secs);

        if has_axis(&axes, "e2e_prove") {
            group.bench_function("e2e_prove", |b| {
                b.iter_custom(|iterations| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iterations {
                        total += black_box(prove_span_duration(&fixture));
                    }
                    total
                });
            });
        }

        if has_axis(&axes, "prove_trace_sync") {
            group.bench_function("prove_trace_sync", |b| {
                b.iter_batched(
                    || execute_trace_inputs(&fixture),
                    |trace_inputs| black_box(prove_trace(trace_inputs)),
                    BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }

    if LIGHT_AXES.iter().any(|axis| has_axis(&axes, axis)) {
        let mut group = c.benchmark_group(BENCH_GROUP);
        configure_group(&mut group, light_sample_size, measurement_time_secs, warm_up_time_secs);

        if has_axis(&axes, "execute_trace_inputs_sync") {
            group.bench_function("execute_trace_inputs_sync", |b| {
                b.iter_batched(
                    || fixture.clone(),
                    |fixture| black_box(execute_trace_inputs(&fixture)),
                    BatchSize::SmallInput,
                );
            });
        }

        if has_axis(&axes, "build_trace") {
            group.bench_function("build_trace", |b| {
                b.iter_batched(
                    || execute_trace_inputs(&fixture),
                    |trace_inputs| black_box(build_trace(trace_inputs)),
                    BatchSize::SmallInput,
                );
            });
        }

        group.finish();
    }
}

fn configure_group(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    sample_size: usize,
    measurement_time_secs: u64,
    warm_up_time_secs: u64,
) {
    group.sample_size(sample_size);
    group.measurement_time(Duration::from_secs(measurement_time_secs));
    group.warm_up_time(Duration::from_secs(warm_up_time_secs));
    group.sampling_mode(SamplingMode::Flat);
}

criterion_group!(benches, blake3_bench);
criterion_main!(benches);
