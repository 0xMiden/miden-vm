//! Synthetic VM benchmark driven by row-count snapshots.
//!
//! Each run calibrates snippet costs against the VM, selects producer scenarios, and synthesizes
//! their workloads. All four independently padded AIR heights must match before timing the
//! `exec`, `trace_prep`, `prove`, and `verify` axes.
//!
//! Env vars:
//! - `SYNTH_SNAPSHOT`: path to a single producer JSON; if set, only this file is benched. Otherwise
//!   every `snapshots/*.json` in the manifest dir is used.
//! - `SYNTH_SCENARIO`: if set, restrict to scenarios whose slugified key contains this slugified
//!   substring (case- and separator-insensitive; `"P2ID"`, `"p2id"`, `"P2ID note"`, and
//!   `"p2id-note"` all match `"consume single P2ID note"`). Without a filter, selects the six
//!   default Falcon/ECDSA P2ID scenarios.
//! - `SYNTH_BENCH_AXES`: comma-separated axes to run. Supported values are `exec`, `trace_prep`,
//!   `prove`, `verify`, and `all`. Defaults to all axes.
//! - `SYNTH_HASH_LDE_BLOCKS`: enable blockwise LDE hashing with `1`; defaults to `0`.
//! - `SYNTH_SAMPLE_SIZE`: Criterion sample size. Defaults to 30.
//! - `SYNTH_MEASUREMENT_TIME_SECS`: Criterion measurement time per benchmark. Defaults to 30.
//! - `SYNTH_WARM_UP_TIME_SECS`: Criterion warm-up time per benchmark. Defaults to 1.
//! - `SYNTH_MASM_WRITE`: if set, write the emitted MASM to
//!   `target/synthetic_bench_<producer-stem>__<scenario-slug>.masm`.

use std::{collections::BTreeSet, hint::black_box, path::PathBuf, time::Duration};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_core::program::ExecutionClaim;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
};
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, Program, ProgramInfo, Prover, StackOutputs, Verifier,
    prove_sync,
};
use miden_vm_synthetic_bench::{
    calibrator::{Calibration, calibrate},
    snapshot::{DEFAULT_SCENARIOS, TraceSnapshot},
    snippets::SNIPPETS,
    workload::{load_scenarios, slugify, synthesize},
};

/// Hash function used for STARK `prove` and `verify` axes.
const BENCH_HASH: HashFunction = HashFunction::Eidos;
const ALL_AXES: [&str; 4] = ["exec", "trace_prep", "prove", "verify"];

fn resolve_bench_axes() -> BTreeSet<&'static str> {
    let Some(raw) = std::env::var("SYNTH_BENCH_AXES").ok().filter(|s| !s.trim().is_empty()) else {
        return ALL_AXES.into_iter().collect();
    };

    let mut axes = BTreeSet::new();
    for axis in raw.split(',').map(str::trim).filter(|axis| !axis.is_empty()) {
        match axis {
            "all" => axes.extend(ALL_AXES),
            "exec" => {
                axes.insert("exec");
            },
            "trace_prep" => {
                axes.insert("trace_prep");
            },
            "prove" => {
                axes.insert("prove");
            },
            "verify" => {
                axes.insert("verify");
            },
            _ => panic!(
                "unsupported SYNTH_BENCH_AXES value `{axis}`; supported values: {}",
                ALL_AXES.join(", ")
            ),
        }
    }
    assert!(!axes.is_empty(), "SYNTH_BENCH_AXES did not select any benchmark axes");
    axes
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<usize>()
                .unwrap_or_else(|e| panic!("{name} must be a positive integer: {e}"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<u64>()
                .unwrap_or_else(|e| panic!("{name} must be a positive integer: {e}"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

/// Builds the per-iteration inputs shared by the `exec` and `trace_prep` axes.
fn processor_inputs(program: &Program) -> (DefaultHost, Program, FastProcessor) {
    let host = DefaultHost::default();
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor advice inputs should fit advice map limits");
    (host, program.clone(), processor)
}

fn execute_and_prove(
    prover: &Prover,
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    host: &mut DefaultHost,
) -> (StackOutputs, ExecutionProof) {
    prove_sync(prover, program, stack_inputs, advice_inputs, host, ExecutionOptions::default())
        .expect("execute and prove program")
}

fn synthetic_bench(c: &mut Criterion) {
    let axes = resolve_bench_axes();
    let sample_size = env_usize("SYNTH_SAMPLE_SIZE", 30);
    let measurement_time_secs = env_u64("SYNTH_MEASUREMENT_TIME_SECS", 30);
    let warm_up_time_secs = env_u64("SYNTH_WARM_UP_TIME_SECS", 1);
    println!("\n=== benchmark axes: {}", axes.iter().copied().collect::<Vec<_>>().join(", "));
    println!(
        "=== criterion: sample_size={sample_size} measurement_time={measurement_time_secs}s warm_up={warm_up_time_secs}s"
    );

    let calibration = calibrate().expect("failed to calibrate snippets");
    println!("\n=== calibration (rows/iter)");
    for snippet in SNIPPETS {
        let cost = calibration[snippet.name];
        println!(
            "    {:<18} core={:7.3} eidos_compression={:6.3} bitwise={:6.3} chiplets={:6.3} memory={:6.3}",
            snippet.name,
            cost.core,
            cost.eidos_compression,
            cost.bitwise,
            cost.chiplets,
            cost.memory,
        );
    }

    for scenario in load_scenarios(DEFAULT_SCENARIOS) {
        bench_one_scenario(
            c,
            &calibration,
            &scenario.producer,
            &scenario.name,
            &slugify(&scenario.name),
            &scenario.snapshot,
            &axes,
            sample_size,
            measurement_time_secs,
            warm_up_time_secs,
        );
    }
}

fn bench_one_scenario(
    c: &mut Criterion,
    calibration: &Calibration,
    producer_stem: &str,
    scenario_key: &str,
    scenario_slug: &str,
    snapshot: &TraceSnapshot,
    axes: &BTreeSet<&'static str>,
    sample_size: usize,
    measurement_time_secs: u64,
    warm_up_time_secs: u64,
) {
    let hash_lde_blocks = match std::env::var("SYNTH_HASH_LDE_BLOCKS") {
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        Err(std::env::VarError::NotPresent) => false,
        _ => panic!("SYNTH_HASH_LDE_BLOCKS must be 0 or 1"),
    };
    let prover = Prover::new().with_hash_fn(BENCH_HASH).with_hash_lde_blocks(hash_lde_blocks);
    println!("BENCH_SYNTH_CONFIG hash_lde_blocks={}", u8::from(hash_lde_blocks));
    println!("\n=== scenario: {producer_stem} / {scenario_key}");
    println!("    provenance: {}", snapshot.provenance.label());
    println!(
        "    trace:   core={} chiplets={} eidos_compression={} and8={} (padded_total={})",
        snapshot.trace.core_rows,
        snapshot.trace.chiplets_rows,
        snapshot.trace.eidos_compression_rows,
        snapshot.trace.byte_pair_lookup_rows,
        snapshot.trace.padded_total(),
    );
    println!(
        "    shape:   hasher={} bitwise={} memory={} kernel_rom={} ace={}",
        snapshot.shape.hasher_rows,
        snapshot.shape.bitwise_rows,
        snapshot.shape.memory_rows,
        snapshot.shape.kernel_rom_rows,
        snapshot.shape.ace_rows,
    );
    if snapshot.shape.substituted_rows() > 0 {
        println!(
            "    note:    {} rows (ace={} + kernel_rom={}) combined with advisory memory rows",
            snapshot.shape.substituted_rows(),
            snapshot.shape.ace_rows,
            snapshot.shape.kernel_rom_rows,
        );
    }

    let synthesized = synthesize(calibration, snapshot);
    let plan = &synthesized.plan;

    println!("\n=== plan");
    for snippet in SNIPPETS {
        println!("    {:<14} iters={}", snippet.name, plan.iters(snippet.name),);
    }

    let source = synthesized.source;
    if std::env::var("SYNTH_MASM_WRITE").is_ok() {
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("synthetic_bench_{producer_stem}__{scenario_slug}.masm"));
        std::fs::create_dir_all(out.parent().expect("parent"))
            .expect("create target dir for MASM dump");
        std::fs::write(&out, &source).expect("write MASM dump");
        println!("\n=== wrote MASM dump to {}", out.display());
    }

    println!("\n=== verification\n{}", synthesized.report);

    let program = Assembler::default()
        .assemble_program("program", &source)
        .expect("assemble emitted program")
        .unwrap_program();

    let mut group = c.benchmark_group(format!("{producer_stem}/{scenario_slug}"));
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(sample_size)
        .warm_up_time(Duration::from_secs(warm_up_time_secs))
        .measurement_time(Duration::from_secs(measurement_time_secs));

    // Four axes per scenario:
    //   exec       -- FastProcessor::execute_sync (no trace data)
    //   trace_prep -- FastProcessor::execute_for_proving_sync (post-execution witness creation)
    //   prove      -- configured prove_sync with overlapped trace construction
    //   verify     -- Verifier::new().verify against a proof generated once outside the timed loop
    if axes.contains("exec") {
        group.bench_function("exec", |b| {
            b.iter_batched_ref(
                || {
                    let (host, program, processor) = processor_inputs(&program);
                    (host, program, Some(processor))
                },
                |(host, program, processor)| {
                    black_box(processor.take().unwrap().execute_sync(program, host).expect("exec"))
                },
                BatchSize::PerIteration,
            );
        });
    }

    if axes.contains("trace_prep") {
        group.bench_function("trace_prep", |b| {
            b.iter_batched_ref(
                || {
                    let (host, program, processor) = processor_inputs(&program);
                    (host, program, Some(processor))
                },
                |(host, program, processor)| {
                    black_box(
                        processor
                            .take()
                            .unwrap()
                            .execute_for_proving_sync(program, host)
                            .expect("trace_prep"),
                    )
                },
                BatchSize::PerIteration,
            );
        });
    }

    if axes.contains("prove") {
        group.bench_function("prove", |b| {
            b.iter_batched_ref(
                || {
                    let host = DefaultHost::default();
                    let stack = StackInputs::default();
                    let advice = AdviceInputs::default();
                    (host, program.clone(), Some(stack), Some(advice))
                },
                |(host, program, stack, advice)| {
                    black_box(execute_and_prove(
                        &prover,
                        program,
                        stack.take().unwrap(),
                        advice.take().unwrap(),
                        host,
                    ))
                },
                BatchSize::PerIteration,
            );
        });
    }

    if axes.contains("verify") {
        let mut host = DefaultHost::default();
        let (stack_outputs, proof) = execute_and_prove(
            &prover,
            &program,
            StackInputs::default(),
            AdviceInputs::default(),
            &mut host,
        );
        let claim = ExecutionClaim::from_program_info(
            ProgramInfo::from(program.clone()),
            StackInputs::default(),
            stack_outputs,
        );
        group.bench_function("verify", |b| {
            b.iter(|| {
                let outcome = Verifier::new().verify(&claim, &proof).expect("verify");
                assert!(outcome.is_complete());
                black_box(outcome.vm_security_parameters().conjectured_security_level())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, synthetic_bench);
criterion_main!(benches);
