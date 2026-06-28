//! Synthetic VM benchmark driven by row-count snapshots.
//!
//! Pipeline each bench run:
//!   1. Calibrate each snippet's per-iteration cost against the current VM (shared across all
//!      snapshots in this run).
//!   2. For each producer JSON (every `snapshots/*.json`, or the single file in `SYNTH_SNAPSHOT`),
//!      load every scenario it contains and: solve for per-snippet iteration counts, emit the
//!      resulting MASM program, check it lands in the scenario's padded-trace bracket, and run four
//!      Criterion benches per scenario -- `exec`, `trace_prep`, `prove`, `verify`.
//!
//! Env vars:
//! - `SYNTH_SNAPSHOT`: path to a single producer JSON; if set, only this file is benched. Otherwise
//!   every `snapshots/*.json` in the manifest dir is used.
//! - `SYNTH_SCENARIO`: if set, restrict to scenarios whose slugified key contains this slugified
//!   substring (case- and separator-insensitive; `"P2ID"`, `"p2id"`, `"P2ID note"`, and
//!   `"p2id-note"` all match `"consume single P2ID note"`).
//! - `SYNTH_BENCH_AXES`: comma-separated axes to run. Supported values are `exec`, `trace_prep`,
//!   `prove`, `verify`, and `all`. Defaults to all axes.
//! - `SYNTH_SAMPLE_SIZE`: Criterion sample size. Defaults to 30.
//! - `SYNTH_MEASUREMENT_TIME_SECS`: Criterion measurement time per benchmark. Defaults to 30.
//! - `SYNTH_WARM_UP_TIME_SECS`: Criterion warm-up time per benchmark. Defaults to 1.
//! - `SYNTH_MASM_WRITE`: if set, write the emitted MASM to
//!   `target/synthetic_bench_<producer-stem>__<scenario-slug>.masm`.

use std::{
    cell::RefCell, collections::BTreeSet, hint::black_box, path::PathBuf, rc::Rc, time::Duration,
};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
};
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, Program, ProgramInfo, ProvingOptions, StackOutputs,
    prove_sync,
};
use miden_vm_synthetic_bench::{
    calibrator::{Calibration, calibrate, measure_program},
    snapshot::TraceSnapshot,
    snippets::{SNIPPETS, memory_max_iters},
    solver::{Plan, emit, solve},
    verifier::VerificationReport,
};

/// Hash function used for STARK `prove` and `verify` axes.
const BENCH_HASH: HashFunction = HashFunction::Eidos;
const ALL_AXES: [&str; 4] = ["exec", "trace_prep", "prove", "verify"];
type ProofFixture = (StackOutputs, ExecutionProof);

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

fn resolve_snapshot_paths() -> Vec<PathBuf> {
    if let Ok(explicit) = std::env::var("SYNTH_SNAPSHOT") {
        return vec![PathBuf::from(explicit)];
    }
    let snapshots_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("snapshots");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&snapshots_dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", snapshots_dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no snapshots found under {}", snapshots_dir.display());
    paths
}

/// Lower-case ASCII slug; non-alphanumerics collapse to single `-` separators.
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_dash = true;
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
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
            "    {:<14} core={:7.3} hasher={:6.3} bitwise={:6.3} memory={:6.3}",
            snippet.name, cost.core, cost.hasher, cost.bitwise, cost.memory,
        );
    }

    // Slugify the filter so substring-matching is case- and separator-insensitive
    // (`SYNTH_SCENARIO=P2ID` matches `consume-single-p2id-note` etc.).
    let scenario_filter = std::env::var("SYNTH_SCENARIO").ok().map(|s| slugify(&s));
    let mut benched_anything = false;
    for path in resolve_snapshot_paths() {
        let producer_stem =
            path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown").to_string();
        let mut scenarios = TraceSnapshot::load_all(&path)
            .unwrap_or_else(|e| panic!("failed to load snapshot at {}: {e}", path.display()));
        scenarios.sort_by_key(|(_, snap)| snap.trace.chiplets_rows);
        for (scenario_key, snapshot) in scenarios {
            let scenario_slug = slugify(&scenario_key);
            if let Some(filter) = &scenario_filter
                && !scenario_slug.contains(filter.as_str())
            {
                continue;
            }
            bench_one_scenario(
                c,
                &calibration,
                &producer_stem,
                &scenario_key,
                &scenario_slug,
                &snapshot,
                &axes,
                sample_size,
                measurement_time_secs,
                warm_up_time_secs,
            );
            benched_anything = true;
        }
    }
    assert!(benched_anything, "no scenarios matched (filter: {scenario_filter:?})");
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
    println!("\n=== scenario: {producer_stem} / {scenario_key}");
    println!(
        "    trace:   core={} chiplets={} blakeg={}",
        snapshot.trace.core_rows,
        snapshot.trace.chiplets_rows,
        snapshot.trace.blakeg_compression_rows,
    );
    println!(
        "    padded:  core={} chiplets={} blakeg={}",
        snapshot.trace.padded_core(),
        snapshot.trace.padded_chiplets(),
        snapshot.trace.padded_blakeg_compression(),
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
            "    note:    {} rows (ace={} + kernel_rom={}) folded into memory target",
            snapshot.shape.substituted_rows(),
            snapshot.shape.ace_rows,
            snapshot.shape.kernel_rom_rows,
        );
    }

    let target_shape = snapshot.shape();
    let plan = solve(calibration, &target_shape);
    assert_counters_fit(&plan);

    println!("\n=== plan");
    for snippet in SNIPPETS {
        println!("    {:<14} iters={}", snippet.name, plan.iters(snippet.name),);
    }

    let source = emit(&plan);
    if std::env::var("SYNTH_MASM_WRITE").is_ok() {
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("synthetic_bench_{producer_stem}__{scenario_slug}.masm"));
        std::fs::create_dir_all(out.parent().expect("parent"))
            .expect("create target dir for MASM dump");
        std::fs::write(&out, &source).expect("write MASM dump");
        println!("\n=== wrote MASM dump to {}", out.display());
    }

    let actual = measure_program(&source).expect("measure emitted program");
    let report = VerificationReport::new(target_shape, actual);
    println!("\n=== verification\n{report}");
    assert!(
        report.brackets_match(),
        "emitted program lands in a different padded-trace bracket than the scenario target",
    );

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
    //   trace_prep -- FastProcessor::execute_trace_inputs_sync (the input to prove_from_trace_sync)
    //   prove      -- prove_sync (= trace_prep + STARK prove)
    //   verify     -- miden_vm::verify against a proof generated once outside the timed loop
    if axes.contains("exec") {
        group.bench_function("exec", |b| {
            b.iter_batched(
                || processor_inputs(&program),
                |(mut host, program, processor)| {
                    black_box(processor.execute_sync(&program, &mut host).expect("exec"));
                },
                BatchSize::SmallInput,
            );
        });
    }

    if axes.contains("trace_prep") {
        group.bench_function("trace_prep", |b| {
            b.iter_batched(
                || processor_inputs(&program),
                |(mut host, program, processor)| {
                    black_box(
                        processor
                            .execute_trace_inputs_sync(&program, &mut host)
                            .expect("trace_prep"),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }

    let cached_proof: Rc<RefCell<Option<ProofFixture>>> = Rc::default();
    if axes.contains("prove") {
        let cached_proof = Rc::clone(&cached_proof);
        group.bench_function("prove", |b| {
            b.iter_batched(
                || {
                    let host = DefaultHost::default();
                    let stack = StackInputs::default();
                    let advice = AdviceInputs::default();
                    (host, program.clone(), stack, advice)
                },
                |(mut host, program, stack, advice)| {
                    let proof = prove_sync(
                        &program,
                        stack,
                        advice,
                        &mut host,
                        ExecutionOptions::default(),
                        ProvingOptions::new(BENCH_HASH),
                    )
                    .expect("prove");
                    let mut cached = cached_proof.borrow_mut();
                    if cached.is_none() {
                        *cached = Some(proof.clone());
                    }
                    black_box(proof);
                },
                BatchSize::SmallInput,
            );
        });
    }

    if axes.contains("verify") {
        // Reuse a proof from the `prove` axis when it ran for this scenario. This keeps prove time
        // out of the verify measurement without forcing an extra proof in all-axes runs.
        let program_info = ProgramInfo::from(program.clone());
        let (stack_outputs, proof) = cached_proof.borrow().clone().unwrap_or_else(|| {
            let mut host = DefaultHost::default();
            prove_sync(
                &program,
                StackInputs::default(),
                AdviceInputs::default(),
                &mut host,
                ExecutionOptions::default(),
                ProvingOptions::new(BENCH_HASH),
            )
            .expect("prove for verify setup")
        });
        group.bench_function("verify", |b| {
            b.iter_batched(
                || (program_info.clone(), StackInputs::default(), stack_outputs, proof.clone()),
                |(program_info, stack_inputs, stack_outputs, proof)| {
                    black_box(
                        miden_vm::verify(program_info, stack_inputs, stack_outputs, proof)
                            .expect("verify"),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

/// Panic if the memory snippet's address counter would overflow `u32::MAX`.
fn assert_counters_fit(plan: &Plan) {
    let memory = plan.iters("memory");
    assert!(
        memory <= memory_max_iters(),
        "memory iters ({}) would overflow its u32 address counter (max {}); \
         revisit the banded-address start constants",
        memory,
        memory_max_iters(),
    );
}

criterion_group!(benches, synthetic_bench);
criterion_main!(benches);
