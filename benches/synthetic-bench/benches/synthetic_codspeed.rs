//! Native CodSpeed harness for the synthetic VM benchmark.
//!
//! This mirrors `synthetic_bench`, but each selected axis is measured once by CodSpeed instead of
//! going through Criterion's sampling loop. When both `prove` and `verify` are selected, the proof
//! produced by the measured `prove` axis is reused for `verify` setup.

use std::{collections::BTreeSet, path::PathBuf};

use codspeed::codspeed::{CodSpeed, black_box, display_native_harness};
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
};
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, Program, ProgramInfo, ProvingOptions, StackOutputs,
    prove_sync,
};
use miden_vm_synthetic_bench::{
    calibrator::{Calibration, calibrate, measure_program},
    snapshot::{TraceShape, TraceSnapshot},
    snippets::{SNIPPETS, memory_max_iters, u32arith_max_iters},
    solver::{Plan, emit, solve},
    verifier::VerificationReport,
};

const BENCH_HASH: HashFunction = HashFunction::Poseidon2;
const ALL_AXES: [&str; 4] = ["exec", "trace_prep", "prove", "verify"];
type ProofFixture = (StackOutputs, ExecutionProof);

fn main() {
    display_native_harness();
    let mut codspeed = CodSpeed::new();
    synthetic_bench(&mut codspeed);
}

fn synthetic_bench(codspeed: &mut CodSpeed) {
    let axes = resolve_bench_axes();
    println!("\n=== benchmark axes: {}", axes.iter().copied().collect::<Vec<_>>().join(", "));

    let calibration = calibrate().expect("failed to calibrate snippets");
    println!("\n=== calibration (rows/iter)");
    for snippet in SNIPPETS {
        let cost = calibration[snippet.name];
        println!(
            "    {:<14} core={:7.3} hasher={:6.3} bitwise={:6.3} memory={:6.3} range={:6.3}",
            snippet.name, cost.core, cost.hasher, cost.bitwise, cost.memory, cost.range,
        );
    }

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
                codspeed,
                &calibration,
                &producer_stem,
                &scenario_key,
                &scenario_slug,
                &snapshot,
                &axes,
            );
            benched_anything = true;
        }
    }
    assert!(benched_anything, "no scenarios matched (filter: {scenario_filter:?})");
}

fn bench_one_scenario(
    codspeed: &mut CodSpeed,
    calibration: &Calibration,
    producer_stem: &str,
    scenario_key: &str,
    scenario_slug: &str,
    snapshot: &TraceSnapshot,
    axes: &BTreeSet<&'static str>,
) {
    println!("\n=== scenario: {producer_stem} / {scenario_key}");
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
        println!("    {:<14} iters={}", snippet.name, plan.iters(snippet.name));
    }

    let source = emit(&plan);
    let actual = measure_program(&source).expect("measure emitted program");
    let report = VerificationReport::new(target_shape, actual);
    println!("\n=== verification\n{report}");
    assert!(
        report.brackets_match(),
        "emitted program lands in a different padded-trace bracket than the scenario target",
    );

    let program = Assembler::default()
        .assemble_program(&source)
        .expect("assemble emitted program");
    let prefix = format!("{producer_stem}/{scenario_slug}");

    if axes.contains("exec") {
        let (mut host, program, processor) = processor_inputs(&program);
        measure(codspeed, &format!("{prefix}/exec"), || {
            black_box(processor.execute_sync(&program, &mut host).expect("exec"));
        });
    }

    if axes.contains("trace_prep") {
        let (mut host, program, processor) = processor_inputs(&program);
        measure(codspeed, &format!("{prefix}/trace_prep"), || {
            black_box(
                processor.execute_trace_inputs_sync(&program, &mut host).expect("trace_prep"),
            );
        });
    }

    let proof_fixture = if axes.contains("prove") {
        Some(measure(codspeed, &format!("{prefix}/prove"), || prove_once(&program)))
    } else {
        None
    };

    if axes.contains("verify") {
        let (stack_outputs, proof) = proof_fixture.unwrap_or_else(|| prove_once(&program));
        let program_info = ProgramInfo::from(program.clone());
        measure(codspeed, &format!("{prefix}/verify"), || {
            black_box(
                miden_vm::verify(program_info, StackInputs::default(), stack_outputs, proof)
                    .expect("verify"),
            );
        });
    }
}

fn measure<T>(codspeed: &mut CodSpeed, name: &str, f: impl FnOnce() -> T) -> T {
    codspeed.start_benchmark(name);
    let output = black_box(f());
    codspeed.end_benchmark();
    output
}

fn prove_once(program: &Program) -> ProofFixture {
    let mut host = DefaultHost::default();
    black_box(
        prove_sync(
            program,
            StackInputs::default(),
            AdviceInputs::default(),
            &mut host,
            ExecutionOptions::default(),
            ProvingOptions::new(BENCH_HASH),
        )
        .expect("prove"),
    )
}

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

fn solve_range_correction(
    range_residual: f64,
    u32arith: MarginalRates,
    hasher: MarginalRates,
    decoder_pad: MarginalRates,
) -> Option<(u64, u64, u64)> {
    if range_residual <= 0.0 {
        return None;
    }
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
