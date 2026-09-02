//! Trace and proving measurements for recursive benchmark cases.

use std::{hint::black_box, time::Instant};

use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, trace::TraceLenSummary};
use miden_vm::{
    ExecutionProof, ExecutionWitness, HashFunction, Prover, StackInputs, StackOutputs, VmTrace,
    prove_sync, trace::build_trace,
};

use super::{RecursionCase, config::ProofComposition, recursive_host};

pub(super) struct TraceShape {
    core_rows: usize,
    byte_pair_lookup_rows: usize,
    chiplets_rows: usize,
    eidos_compression_rows: usize,
    hash_chiplet_rows: usize,
    bitwise_rows: usize,
    memory_rows: usize,
    ace_rows: usize,
    kernel_rows: usize,
    max_trace_rows: usize,
    max_padded_rows: usize,
}

pub(super) struct CaseTraceShape {
    composition: ProofComposition,
    trace: TraceShape,
}

struct ProveSummary {
    composition: ProofComposition,
    runs: usize,
    avg_ms: f64,
    median_ms: f64,
    min_ms: f64,
    max_ms: f64,
    avg_proof_bytes: f64,
}

pub(super) fn trace_shape_summary_for(summary: &TraceLenSummary) -> TraceShape {
    let chiplets = summary.chiplets();
    let max_trace_rows = summary
        .core_rows()
        .max(summary.chiplets_rows())
        .max(summary.eidos_compression_rows())
        .max(summary.byte_pair_lookup_rows());
    let max_padded_rows = summary
        .core_height()
        .max(summary.chiplets_height())
        .max(summary.eidos_compression_height())
        .max(summary.byte_pair_lookup_rows());

    TraceShape {
        core_rows: summary.core_rows(),
        byte_pair_lookup_rows: summary.byte_pair_lookup_rows(),
        chiplets_rows: summary.chiplets_rows(),
        eidos_compression_rows: summary.eidos_compression_rows(),
        hash_chiplet_rows: chiplets.hash_chiplet_len(),
        bitwise_rows: chiplets.bitwise_chiplet_len(),
        memory_rows: chiplets.memory_chiplet_len(),
        ace_rows: chiplets.ace_chiplet_len(),
        kernel_rows: chiplets.kernel_rom_len(),
        max_trace_rows,
        max_padded_rows,
    }
}

pub(super) fn execute_trace_inputs(case: RecursionCase, mut host: DefaultHost) -> ExecutionWitness {
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        case.advice_inputs,
        ExecutionOptions::default(),
    )
    .expect("recursive verifier advice should fit provider limits");
    processor
        .execute_for_proving_sync(&case.program, &mut host)
        .expect("execute recursive verifier")
}

pub(super) fn execute_recursive_case(
    (case, host): (RecursionCase, DefaultHost),
) -> ExecutionWitness {
    execute_trace_inputs(case, host)
}

pub(super) fn build_trace_case(witness: ExecutionWitness) -> VmTrace {
    let (vm_witness, _) = witness.into_parts();
    build_trace(vm_witness).expect("build recursive verifier trace")
}

pub(super) fn execute_and_build_case((case, host): (RecursionCase, DefaultHost)) -> VmTrace {
    build_trace_case(execute_trace_inputs(case, host))
}

pub(super) fn prove_recursive_case(
    (case, mut host, hash_fn): (RecursionCase, DefaultHost, HashFunction),
) -> (StackOutputs, ExecutionProof) {
    prove_sync(
        &Prover::new().with_hash_fn(hash_fn),
        &case.program,
        StackInputs::default(),
        case.advice_inputs,
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("prove recursive verifier")
}

fn prove_recursive_once(case: &RecursionCase, hash_fn: HashFunction) -> (f64, usize) {
    let advice_inputs = case.advice_inputs.clone();
    let mut host = recursive_host();
    let start = Instant::now();
    let (_, proof) = prove_sync(
        &Prover::new().with_hash_fn(hash_fn),
        &case.program,
        StackInputs::default(),
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
    )
    .expect("prove recursive verifier");
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    let proof_bytes = proof.to_bytes().len();
    black_box(proof);
    (elapsed_ms, proof_bytes)
}

fn prove_summary(composition: ProofComposition, samples: &[(f64, usize)]) -> ProveSummary {
    assert!(!samples.is_empty(), "prove summary requires at least one sample");

    let runs = samples.len();
    let mut elapsed = samples.iter().map(|(elapsed_ms, _)| *elapsed_ms).collect::<Vec<_>>();
    elapsed.sort_by(f64::total_cmp);

    let median_ms = if runs.is_multiple_of(2) {
        let upper = runs / 2;
        (elapsed[upper - 1] + elapsed[upper]) / 2.0
    } else {
        elapsed[runs / 2]
    };
    let avg_ms = elapsed.iter().sum::<f64>() / runs as f64;
    let avg_proof_bytes =
        samples.iter().map(|(_, proof_bytes)| *proof_bytes as f64).sum::<f64>() / runs as f64;

    ProveSummary {
        composition,
        runs,
        avg_ms,
        median_ms,
        min_ms: elapsed[0],
        max_ms: elapsed[runs - 1],
        avg_proof_bytes,
    }
}

pub(super) fn profile_prove_round_robin(
    cases: &[RecursionCase],
    hash_fn: HashFunction,
    warmups: usize,
    runs: usize,
) {
    assert!(!cases.is_empty(), "round-robin profiling requires at least one case");

    for warmup_round in 0..warmups {
        for offset in 0..cases.len() {
            let case = &cases[(warmup_round + offset) % cases.len()];
            let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
            eprintln!(
                "recursive_profile warmup {}/{warmups}/{}: {:.3} ms proof_bytes={}",
                warmup_round + 1,
                case.composition.label(),
                elapsed_ms,
                proof_bytes,
            );
        }
    }

    let mut samples = vec![Vec::with_capacity(runs); cases.len()];
    for run_round in 0..runs {
        for offset in 0..cases.len() {
            let case_index = (run_round + offset) % cases.len();
            let case = &cases[case_index];
            let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
            samples[case_index].push((elapsed_ms, proof_bytes));
            eprintln!(
                "recursive_profile run {}/{runs}/{}: {:.3} ms proof_bytes={}",
                run_round + 1,
                case.composition.label(),
                elapsed_ms,
                proof_bytes,
            );
            println!(
                "BENCH_RECURSION_PROOF {} run={} prove_ms={:.3} proof_bytes={}",
                case.composition.machine_fields(),
                run_round + 1,
                elapsed_ms,
                proof_bytes,
            );
        }
    }

    let summaries = cases
        .iter()
        .zip(samples)
        .map(|(case, samples)| prove_summary(case.composition, &samples))
        .collect::<Vec<_>>();
    print_prove_summary(&summaries);
}

fn print_prove_summary(summaries: &[ProveSummary]) {
    println!("\n=== recursive proving summary");
    println!("| MVM proofs | PVM proofs | median_s | avg_s | min_s | max_s | avg_proof_bytes |");
    println!("|---:|---:|---:|---:|---:|---:|---:|");
    for summary in summaries {
        println!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.0} |",
            summary.composition.mvm_count(),
            summary.composition.pvm_count(),
            summary.median_ms / 1_000.0,
            summary.avg_ms / 1_000.0,
            summary.min_ms / 1_000.0,
            summary.max_ms / 1_000.0,
            summary.avg_proof_bytes,
        );
        println!(
            "BENCH_RECURSION_PROOF_SUMMARY {} runs={} avg_ms={:.3} median_ms={:.3} \
             min_ms={:.3} max_ms={:.3} avg_proof_bytes={:.0}",
            summary.composition.machine_fields(),
            summary.runs,
            summary.avg_ms,
            summary.median_ms,
            summary.min_ms,
            summary.max_ms,
            summary.avg_proof_bytes,
        );
    }
}

fn trace_shape_summary(case: &RecursionCase) -> TraceShape {
    let trace = build_trace_case(execute_trace_inputs(case.clone(), recursive_host()));
    trace_shape_summary_for(trace.trace_len_summary())
}

pub(super) fn print_case_shape(case: &RecursionCase) -> CaseTraceShape {
    let trace = trace_shape_summary(case);

    println!(
        "    {} core={} and8={} chiplets={} eidos_compression={} hash_ctrl={} max_trace={} max_padded={}",
        case.composition.label(),
        trace.core_rows,
        trace.byte_pair_lookup_rows,
        trace.chiplets_rows,
        trace.eidos_compression_rows,
        trace.hash_chiplet_rows,
        trace.max_trace_rows,
        trace.max_padded_rows,
    );
    let record = format!("BENCH_RECURSION_SHAPE {}", case.composition.machine_fields());
    print_bench_shape(&record, &trace);
    CaseTraceShape { composition: case.composition, trace }
}

pub(super) fn print_bench_shape(record: &str, shape: &TraceShape) {
    // This is a machine-readable schema consumed by benchmark parsers.
    println!(
        concat!(
            "{} ",
            "core_rows={} byte_pair_lookup_rows={} chiplets_rows={} eidos_compression_rows={} ",
            "hash_chiplet_rows={} bitwise_rows={} memory_rows={} ace_rows={} kernel_rows={} ",
            "native_hash_rows={} and8_lookup_rows={} max_trace_rows={} max_padded_rows={}"
        ),
        record,
        shape.core_rows,
        shape.byte_pair_lookup_rows,
        shape.chiplets_rows,
        shape.eidos_compression_rows,
        shape.hash_chiplet_rows,
        shape.bitwise_rows,
        shape.memory_rows,
        shape.ace_rows,
        shape.kernel_rows,
        shape.eidos_compression_rows,
        shape.byte_pair_lookup_rows,
        shape.max_trace_rows,
        shape.max_padded_rows,
    );
}

pub(super) fn print_trace_shape_summary(shapes: &[CaseTraceShape]) {
    println!("\n=== recursive trace summary");
    println!(
        "| MVM proofs | PVM proofs | core | and8 | chiplets | EidosCompression | hash | bitwise | memory | ace | kernel | max_trace | padded |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for case in shapes {
        let shape = &case.trace;
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            case.composition.mvm_count(),
            case.composition.pvm_count(),
            shape.core_rows,
            shape.byte_pair_lookup_rows,
            shape.chiplets_rows,
            shape.eidos_compression_rows,
            shape.hash_chiplet_rows,
            shape.bitwise_rows,
            shape.memory_rows,
            shape.ace_rows,
            shape.kernel_rows,
            shape.max_trace_rows,
            shape.max_padded_rows,
        );
    }
}
