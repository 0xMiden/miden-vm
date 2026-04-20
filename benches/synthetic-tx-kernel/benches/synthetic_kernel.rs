//! Synthetic transaction-kernel benchmark.
//!
//! Pipeline each bench run:
//!   1. Calibrate each snippet's per-iteration cost against the current VM (shared across all
//!      snapshots in this run).
//!   2. For each snapshot JSON (every `snapshots/*.json`, or the single file in `SYNTH_SNAPSHOT`):
//!      solve for per-snippet iteration counts, emit the resulting MASM program, verify it lands in
//!      the snapshot's padded-trace bracket, and run `execute` + `execute_and_prove` Criterion
//!      benches.
//!
//! Env vars:
//! - `SYNTH_SNAPSHOT`: path to a single snapshot JSON; if set, only this snapshot is benched.
//!   Otherwise every `snapshots/*.json` in the manifest dir is used.
//! - `SYNTH_MASM_WRITE`: if set, write the emitted MASM to
//!   `target/synthetic_kernel_<snapshot-stem>.masm`.

use std::{hint::black_box, path::PathBuf, time::Duration};

use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
};
use miden_synthetic_tx_kernel::{
    calibrator::{Calibration, calibrate, measure_program},
    snapshot::{TraceShape, TraceSnapshot},
    snippets::{SNIPPETS, memory_max_iters, u32arith_max_iters},
    solver::{Plan, emit, solve},
    verifier::VerificationReport,
};
use miden_vm::{Assembler, ProvingOptions, prove_sync};

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

fn synthetic_transaction_kernel(c: &mut Criterion) {
    let calibration = calibrate().expect("failed to calibrate snippets");
    println!("\n=== calibration (rows/iter)");
    for snippet in SNIPPETS {
        let cost = calibration[snippet.name];
        println!(
            "    {:<14} core={:7.3} hasher={:6.3} bitwise={:6.3} memory={:6.3} range={:6.3}",
            snippet.name, cost.core, cost.hasher, cost.bitwise, cost.memory, cost.range,
        );
    }

    for path in resolve_snapshot_paths() {
        bench_one_snapshot(c, &calibration, &path);
    }
}

fn bench_one_snapshot(c: &mut Criterion, calibration: &Calibration, snapshot_path: &PathBuf) {
    let snapshot = TraceSnapshot::load(snapshot_path)
        .unwrap_or_else(|e| panic!("failed to load snapshot at {}: {e}", snapshot_path.display()));

    println!("\n=== snapshot: {}", snapshot_path.display());
    println!("    source:  {}", snapshot.source);
    println!("    vm_ver:  {}", snapshot.miden_vm_version);

    let local_vm_version = env!("CARGO_PKG_VERSION");
    if !versions_align(&snapshot.miden_vm_version, local_vm_version) {
        println!(
            "    warning: snapshot captured against miden-vm {}, consumer is running {}",
            snapshot.miden_vm_version, local_vm_version,
        );
    }
    println!(
        "    trace:   core={} chiplets={} range={} (padded_total={})",
        snapshot.trace.core_rows,
        snapshot.trace.chiplets_rows,
        snapshot.trace.range_rows,
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
            "    note:    {} rows (ace={} + kernel_rom={}) folded into memory target",
            snapshot.shape.substituted_rows(),
            snapshot.shape.ace_rows,
            snapshot.shape.kernel_rom_rows,
        );
    }

    let target_shape = snapshot.shape();
    let mut plan = solve(calibration, &target_shape);
    range_correction_pass(&mut plan, &target_shape);
    assert_counters_fit(&plan);

    println!("\n=== plan");
    for snippet in SNIPPETS {
        println!("    {:<14} iters={}", snippet.name, plan.iters(snippet.name),);
    }

    let snapshot_stem = snapshot_path.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");

    let source = emit(&plan);
    if std::env::var("SYNTH_MASM_WRITE").is_ok() {
        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("synthetic_kernel_{snapshot_stem}.masm"));
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
        "emitted program lands in a different padded-trace bracket than the snapshot",
    );

    let program = Assembler::default()
        .assemble_program(&source)
        .expect("assemble emitted program");

    let mut group = c.benchmark_group(format!("synthetic_transaction_kernel/{snapshot_stem}"));
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(10)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(10));

    group.bench_function("execute", |b| {
        b.iter_batched(
            || {
                let host = DefaultHost::default();
                let processor = FastProcessor::new_with_options(
                    StackInputs::default(),
                    AdviceInputs::default(),
                    ExecutionOptions::default(),
                );
                (host, program.clone(), processor)
            },
            |(mut host, program, processor)| {
                black_box(processor.execute_sync(&program, &mut host).expect("execute"));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("execute_and_prove", |b| {
        b.iter_batched(
            || {
                let host = DefaultHost::default();
                let stack = StackInputs::default();
                let advice = AdviceInputs::default();
                (host, program.clone(), stack, advice)
            },
            |(mut host, program, stack, advice)| {
                black_box(
                    prove_sync(
                        &program,
                        stack,
                        advice,
                        &mut host,
                        ExecutionOptions::default(),
                        ProvingOptions::default(),
                    )
                    .expect("prove"),
                );
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Returns true when snapshot and local versions agree on `major.minor`. Patch differences are
/// ignored.
fn versions_align(snapshot: &str, local: &str) -> bool {
    let mut s = snapshot.split('.');
    let mut l = local.split('.');
    (s.next(), s.next()) == (l.next(), l.next())
}

/// Panic if any snippet's plan iteration count would overflow its counter beyond `u32::MAX` (which
/// would trip `u32assert2` or a memory op at runtime). Cheap safeguard in case a snapshot with
/// unusually large range or memory targets gets fed in.
fn assert_counters_fit(plan: &Plan) {
    let u32arith = plan.iters("u32arith");
    assert!(
        u32arith <= u32arith_max_iters(),
        "u32arith iters ({}) would overflow its u32 counter (max {}); \
         revisit the banded-counter start constants",
        u32arith,
        u32arith_max_iters(),
    );
    let memory = plan.iters("memory");
    assert!(
        memory <= memory_max_iters(),
        "memory iters ({}) would overflow its u32 address counter (max {}); \
         revisit the banded-address start constants",
        memory,
        memory_max_iters(),
    );
}

// RANGE CORRECTION PASS
// ------------------------------------------------------------------------
//
// Range's trace length is not perfectly linear under composition, so the primary solver can leave
// a few-percent residual. This pass closes it by measuring marginal rates and applying a combo of
// `+u32arith -hasher -decoder_pad` that lifts range while keeping core and chiplets approximately
// fixed. Memory is deliberately left alone so the emitted memory-chiplet workload stays
// representative.

#[derive(Debug, Clone, Copy)]
struct MarginalRates {
    core: f64,
    chiplets: f64,
    range: f64,
}

const CORRECTION_PROBE_DELTA: u64 = 256;
const CORRECTION_TOLERANCE: f64 = 0.01;
const CORRECTION_MAX_PASSES: usize = 2;

fn measure_plan(plan: &Plan) -> TraceShape {
    let source = emit(plan);
    measure_program(&source).expect("measure emitted plan")
}

fn measure_marginal(
    base_plan: &Plan,
    base_shape: TraceShape,
    snippet: &'static str,
    delta: u64,
) -> MarginalRates {
    let mut probe = base_plan.clone();
    probe.add(snippet, delta);
    let shape = measure_plan(&probe);
    let d = delta as f64;
    MarginalRates {
        core: (shape.totals.core_rows as f64 - base_shape.totals.core_rows as f64) / d,
        chiplets: (shape.totals.chiplets_rows as f64 - base_shape.totals.chiplets_rows as f64) / d,
        range: (shape.totals.range_rows as f64 - base_shape.totals.range_rows as f64) / d,
    }
}

/// Solve for `(add_u32arith, sub_hasher, sub_pad)` that lifts range by `range_residual` while
/// holding core and chiplets approximately fixed. Returns `None` if the 2x2 system for the two
/// subtractions is degenerate, any coefficient comes out negative, or the net range gain is
/// non-positive.
fn solve_range_correction(
    range_residual: f64,
    u32arith: MarginalRates,
    hasher: MarginalRates,
    decoder_pad: MarginalRates,
) -> Option<(u64, u64, u64)> {
    if range_residual <= 0.0 {
        return None;
    }
    // Solve per unit of u32arith:
    //   hasher.core * y     + decoder_pad.core * z     = u32arith.core
    //   hasher.chiplets * y + decoder_pad.chiplets * z = u32arith.chiplets
    let det = hasher.core * decoder_pad.chiplets - decoder_pad.core * hasher.chiplets;
    if det.abs() < 1e-9 {
        return None;
    }
    let y_per_x =
        (u32arith.core * decoder_pad.chiplets - decoder_pad.core * u32arith.chiplets) / det;
    let z_per_x = (hasher.core * u32arith.chiplets - u32arith.core * hasher.chiplets) / det;
    if y_per_x < 0.0 || z_per_x < 0.0 {
        return None;
    }
    let net_range_per_x = u32arith.range - hasher.range * y_per_x - decoder_pad.range * z_per_x;
    if net_range_per_x <= 0.0 {
        return None;
    }
    let x = (range_residual / net_range_per_x).round();
    if x <= 0.0 {
        return None;
    }
    Some((x as u64, (x * y_per_x).round() as u64, (x * z_per_x).round() as u64))
}

fn range_correction_pass(plan: &mut Plan, target: &TraceShape) {
    let target_range = target.totals.range_rows;
    if target_range == 0 {
        return;
    }
    let tolerance = (target_range as f64 * CORRECTION_TOLERANCE) as u64;
    for pass in 0..CORRECTION_MAX_PASSES {
        let actual = measure_plan(plan);
        let actual_range = actual.totals.range_rows;
        let residual = target_range as i64 - actual_range as i64;
        println!(
            "\n=== range correction pass {}: target={} actual={} residual={}",
            pass + 1,
            target_range,
            actual_range,
            residual,
        );
        if residual <= tolerance as i64 {
            // Already within band, or overshoot (residual <= 0).
            return;
        }

        let u32arith = measure_marginal(plan, actual, "u32arith", CORRECTION_PROBE_DELTA);
        let hasher = measure_marginal(plan, actual, "hasher", CORRECTION_PROBE_DELTA);
        let decoder_pad = measure_marginal(plan, actual, "decoder_pad", CORRECTION_PROBE_DELTA);

        match solve_range_correction(residual as f64, u32arith, hasher, decoder_pad) {
            Some((add_u32arith, sub_hasher, sub_pad)) => {
                let sub_hasher = sub_hasher.min(plan.iters("hasher"));
                let sub_pad = sub_pad.min(plan.iters("decoder_pad"));
                println!(
                    "    applying: +u32arith {add_u32arith}  -hasher {sub_hasher}  -decoder_pad {sub_pad}"
                );
                plan.add("u32arith", add_u32arith);
                plan.sub_saturating("hasher", sub_hasher);
                plan.sub_saturating("decoder_pad", sub_pad);
            },
            None => {
                println!("    no valid local correction found");
                return;
            },
        }
    }
}

criterion_group!(benches, synthetic_transaction_kernel);
criterion_main!(benches);
