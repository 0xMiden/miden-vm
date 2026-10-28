//! Homogeneous protocol-shaped MVM batches with one PVM proof of an ECDSA verification per MVM.
//!
//! `SYNTH_SNAPSHOT` and `SYNTH_SCENARIO` select measured protocol workloads through the same
//! calibration and synthesis pipeline as `synthetic_bench`. Each case contains distinct proofs
//! of one Falcon or ECDSA P2ID workload. Each ECDSA verification includes its Keccak prehash.
//! Inner proofs use Eidos and are prepared before timing.
//! Without a scenario filter, runs the two-note consumption workloads for Falcon and ECDSA.
//!
//! `RECURSION_PROOF_COUNTS` selects counts from 3 through 7 (default: all five).
//! `RECURSION_PROFILE_ONLY` prints trace shapes without Criterion timing.
//! `RECURSION_PROFILE_PROVE` records repeated outer proving measurements with rotating case order;
//! `RECURSION_PROFILE_PROVE_REPEATS` and `RECURSION_PROFILE_PROVE_WARMUPS` default to 1.
//! Verified inner proofs are cached in `target/recursive-bench-cache/{tx,pvm}`, respecting
//! `CARGO_TARGET_DIR`. `RECURSION_BENCH_TX_PROOF_CACHE_DIR` and
//! `RECURSION_BENCH_PVM_PROOF_CACHE_DIR` override these paths, relative to the workspace root.
//! `RECURSION_MASM_WRITE` dumps recursive verifier programs under this package's `target/`.
//! `RECURSION_BENCH_STACK` defaults to `0,1`; its first value varies between inner proofs.
//! `RECURSION_SAMPLE_SIZE`, `RECURSION_WARM_UP_TIME_SECS`, and `RECURSION_MEASUREMENT_TIME_SECS`
//! control Criterion timing. All outer proofs use Eidos.

use std::{fmt::Write as _, path::PathBuf, time::Duration};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_assembly::Linkage;
use miden_core::Word;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, advice::AdviceInputs};
use miden_vm::{Assembler, Program};
use miden_vm_synthetic_bench::{
    calibrator::calibrate,
    snapshot::DEFAULT_SCENARIOS,
    workload::{load_scenarios, slugify, synthesize},
};

#[path = "recursive_verify/cache_key.rs"]
mod cache_key;
#[path = "recursive_verify/config.rs"]
mod config;
#[path = "recursive_verify/fixtures.rs"]
mod fixtures;
#[path = "recursive_verify/measurements.rs"]
mod measurements;

use config::{BenchConfig, ProofComposition, env_u64, env_usize, env_usize_allow_zero};
use fixtures::{
    RecursiveProofAdvice, TxProofFixture, load_pvm_advice, load_tx_fixtures, recursive_proof_advice,
};
use measurements::{
    build_trace_case, execute_and_build_case, execute_recursive_case, execute_trace_inputs,
    print_case_shape, print_trace_shape_summary, profile_prove_round_robin, prove_recursive_case,
};

#[derive(Clone)]
struct RecursionCase {
    scenario: String,
    composition: ProofComposition,
    program: Program,
    advice_inputs: AdviceInputs,
}

fn push_word_masm(source: &mut String, word: Word) {
    // MASM pushes the last literal first, leaving the word's first element on top.
    for value in word.into_elements().into_iter().rev() {
        writeln!(source, "push.{}", value.as_canonical_u64())
            .expect("write recursive verifier call source");
    }
}

/// MASM for one `exec.vm::verify_proof` call.
///
/// The generated program appends one block like this per inner transaction proof.
fn vm_verify_proof_call_masm(claim_commitment: Word) -> String {
    let mut source = String::new();
    push_word_masm(&mut source, claim_commitment);
    writeln!(
        source,
        "
        dupw
        procref.vm::verify_proof exec.sys::build_proof_request_key
        adv.push_mapval dropw
        exec.vm::verify_proof
        # => [security_descriptor(12), D, padding(16)]
        dropw dropw dropw dropw
        ",
    )
    .expect("write recursive verifier call source");
    source
}

/// MASM for one `exec.pvm::verify_proof` call.
fn verify_pvm_proof_call_masm(claim_commitment: Word) -> String {
    let mut source = String::new();
    push_word_masm(&mut source, claim_commitment);
    writeln!(
        source,
        "
        dupw
        procref.pvm::verify_proof exec.sys::build_proof_request_key
        adv.push_mapval dropw
        exec.pvm::verify_proof
        # => [security_descriptor(12), padding(16)]
        dropw dropw dropw
        ",
    )
    .expect("write PVM verifier call source");
    source
}

/// Full MASM program used by the benchmark.
///
/// `verify_calls` contains the MVM calls followed by exactly one PVM call.
fn recursive_verifier_program_masm(verify_calls: &str) -> String {
    format!(
        "
        use miden::core::sys
        use miden::core::sys::vm
        use miden::core::sys::pvm

        begin
            {verify_calls}
        end
        "
    )
}

fn assemble_recursive_program(source: &str) -> Program {
    let core_lib = CoreLibrary::default();
    Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("link core library")
        .assemble_program("recursive_verifier", source)
        .expect("assemble recursive verifier")
        .unwrap_program()
}

fn dump_recursive_program_source(scenario: &str, composition: ProofComposition, source: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target").join(format!(
        "recursive_verify_{}_{}_mvm_1_pvm.masm",
        slugify(scenario),
        composition.mvm_count()
    ));
    std::fs::create_dir_all(path.parent().expect("recursive MASM dump parent"))
        .expect("create recursive MASM directory");
    std::fs::write(&path, source).expect("write recursive MASM");
    println!(
        "BENCH_RECURSION_MASM scenario={scenario} {} path={}",
        composition.machine_fields(),
        path.display()
    );
}

fn build_recursive_verifier_case(
    fixtures: &[TxProofFixture],
    composition: ProofComposition,
    pvm_advice: &RecursiveProofAdvice,
    scenario: &str,
    write_recursive_masm: bool,
) -> RecursionCase {
    assert!(
        fixtures.len() >= composition.mvm_count(),
        "recursion case requires {} MVM fixtures",
        composition.mvm_count()
    );
    let mut verify_calls = String::new();
    let mut advice_inputs = AdviceInputs::default();
    let mvm_verifier_root = CoreLibrary::default().vm_recursive_verifier_root();

    for fixture in fixtures.iter().take(composition.mvm_count()) {
        let proof_advice = recursive_proof_advice(fixture, mvm_verifier_root);
        verify_calls.push_str(&vm_verify_proof_call_masm(proof_advice.claim_commitment));
        advice_inputs.extend(proof_advice.advice_inputs);
    }
    verify_calls.push_str(&verify_pvm_proof_call_masm(pvm_advice.claim_commitment));
    advice_inputs.extend(pvm_advice.advice_inputs.clone());
    let source = recursive_verifier_program_masm(&verify_calls);
    if write_recursive_masm {
        dump_recursive_program_source(scenario, composition, &source);
    }
    println!(
        "BENCH_RECURSION_PROGRAM scenario={scenario} {} source_bytes={}",
        composition.machine_fields(),
        source.len(),
    );

    RecursionCase {
        scenario: scenario.to_string(),
        composition,
        program: assemble_recursive_program(&source),
        advice_inputs,
    }
}

fn recursive_host() -> DefaultHost {
    let core_lib = CoreLibrary::default();
    let mut host = DefaultHost::default();
    host.load_library(&core_lib).expect("load core library");
    host
}

fn bench_recursive_verify(c: &mut Criterion) {
    let config = BenchConfig::from_env();
    let prover = config.outer_prover();
    let max_proof_count = config
        .compositions()
        .iter()
        .map(|composition| composition.mvm_count())
        .max()
        .expect("proof compositions");
    let mut scenarios = load_scenarios(&[
        "consume two P2ID notes with Falcon signing",
        "consume two P2ID notes with ECDSA signing",
    ]);
    scenarios.retain(|scenario| DEFAULT_SCENARIOS.contains(&scenario.name.as_str()));
    assert!(!scenarios.is_empty(), "recursion requires a Falcon or ECDSA P2ID scenario");
    let calibration = calibrate().expect("calibrate synthetic workloads");
    let pvm_fixtures: Vec<_> = config
        .compositions()
        .iter()
        .map(|&composition| (composition, load_pvm_advice(&config, composition.mvm_count())))
        .collect();
    let mut cases = Vec::new();
    for scenario in scenarios {
        let slug = format!("{}/{}", scenario.producer, slugify(&scenario.name));
        let generated = synthesize(&calibration, &scenario.snapshot);
        println!("\n=== recursive MVM workload: {slug}\n{}", generated.report);
        let fixtures = load_tx_fixtures(&config, max_proof_count, &generated.source, &slug);
        for (composition, pvm_advice) in &pvm_fixtures {
            cases.push(build_recursive_verifier_case(
                &fixtures,
                *composition,
                pvm_advice,
                &slug,
                config.write_recursive_masm(),
            ));
        }
    }

    println!("\n=== recursive verifier trace shapes");
    let shapes = cases.iter().map(print_case_shape).collect::<Vec<_>>();
    print_trace_shape_summary(&shapes);
    if std::env::var_os("RECURSION_PROFILE_ONLY").is_some() {
        return;
    }
    if std::env::var_os("RECURSION_PROFILE_PROVE").is_some() {
        let runs = env_usize("RECURSION_PROFILE_PROVE_REPEATS", 1);
        let warmups = env_usize_allow_zero("RECURSION_PROFILE_PROVE_WARMUPS", 1);
        profile_prove_round_robin(&prover, &cases, warmups, runs);
        return;
    }

    let mut group = c.benchmark_group("recursive_verify");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(env_usize("RECURSION_SAMPLE_SIZE", 10))
        .warm_up_time(Duration::from_secs(env_u64("RECURSION_WARM_UP_TIME_SECS", 1)))
        .measurement_time(Duration::from_secs(env_u64("RECURSION_MEASUREMENT_TIME_SECS", 10)));

    for case in cases {
        let label = case.composition.label();
        group.bench_function(BenchmarkId::new(format!("execute/{label}"), &case.scenario), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_recursive_case,
                BatchSize::PerIteration,
            );
        });

        group.bench_function(
            BenchmarkId::new(format!("build_trace/{label}"), &case.scenario),
            |b| {
                b.iter_batched(
                    || execute_trace_inputs(case.clone(), recursive_host()),
                    build_trace_case,
                    BatchSize::PerIteration,
                );
            },
        );

        group.bench_function(BenchmarkId::new(format!("total/{label}"), &case.scenario), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_and_build_case,
                BatchSize::PerIteration,
            );
        });

        group.bench_function(BenchmarkId::new(format!("prove/{label}"), &case.scenario), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                |input| prove_recursive_case(&prover, input),
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_recursive_verify);
criterion_main!(benches);
