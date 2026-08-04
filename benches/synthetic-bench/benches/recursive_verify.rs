//! Recursive-verifier benchmark for synthetic transaction proofs and an optional PVM proof.
//!
//! This benchmark separates inner-proof generation from recursive verification. Inner proofs are
//! generated before timing, then the timed program verifies the configured MVM proofs and,
//! optionally, one PVM proof.
//!
//! For each requested composition, setup builds one recursive-verifier program and one advice
//! provider. Every proof stream is stored in the advice map under
//! `proof_request_key(verifier_root, claim_commitment)`, matching the production request flow.
//!
//! Env vars:
//! - `RECURSION_BENCH_MASM`: path to a synthetic transaction MASM fixture. If unset, this bench is
//!   skipped so `cargo bench -p miden-vm-synthetic-bench` keeps working out of the box. Relative
//!   paths may be relative to either the workspace root or this bench crate.
//! - `RECURSION_BENCH_STACK`: comma-separated stack inputs for the first transaction proof. The
//!   first value is incremented per proof so the benchmark verifies distinct proofs. Defaults to
//!   `0,1`.
//! - `RECURSION_BENCH_HASH`: outer-proof STARK hash function. Inner proofs use Poseidon2, as
//!   required by the recursive verifier. Defaults to `poseidon2`.
//! - `RECURSION_PROOF_COUNTS`: comma-separated proof counts. Defaults to `2,3,4,5,6,7,8`.
//! - `RECURSION_PVM_COMPARISON`: benchmark `4 MVM + 1 PVM`, `7 MVM`, `5 MVM + 1 PVM`, and `8 MVM`,
//!   in that order. `RECURSION_PROOF_COUNTS` must be unset. The PVM proof covers the canonical
//!   100-Keccak/4-ECDSA workload independently of the synthetic MVM fixtures.
//! - `RECURSION_PROFILE_ONLY`: if set, print trace shapes and skip Criterion timing.
//! - `RECURSION_PROFILE_PROVE`: if set, run repeated proving outside Criterion and print
//!   `BENCH_RECURSION_PROOF` lines.
//! - `RECURSION_PROFILE_PROVE_REPEATS`: number of proving measurements for profile mode. Defaults
//!   to `1`.
//! - `RECURSION_PROFILE_PROVE_WARMUPS`: number of proving warmup rounds for profile mode. Defaults
//!   to `1`; every round visits every case.
//! - `RECURSION_MASM_WRITE`: if set, dump generated recursive verifier MASM programs to `target/`.
//! - `RECURSION_BENCH_TX_PROOF_CACHE_DIR`: optional transaction proof cache directory. Relative
//!   paths are resolved from the workspace root.
//! - `RECURSION_BENCH_PVM_PROOF_CACHE_DIR`: optional canonical PVM proof cache directory. Relative
//!   paths are resolved from the workspace root.
//! - `RECURSION_SAMPLE_SIZE`, `RECURSION_WARM_UP_TIME_SECS`, `RECURSION_MEASUREMENT_TIME_SECS`:
//!   Criterion timing knobs.

use std::{fmt::Write as _, path::PathBuf, time::Duration};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_assembly::Linkage;
use miden_core::Word;
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, advice::AdviceInputs};
use miden_vm::{Assembler, Program};

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

/// MASM for one `exec.vm::verify_vm_proof` call.
///
/// The generated program appends one block like this per inner transaction proof.
fn verify_vm_proof_call_masm(claim_commitment: Word) -> String {
    let mut source = String::new();
    push_word_masm(&mut source, claim_commitment);
    writeln!(
        source,
        "
        dupw
        procref.vm::verify_vm_proof exec.sys::build_proof_request_key
        adv.push_mapval dropw
        exec.vm::verify_vm_proof
        # => [D, num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
        dropw dropw
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
        # => [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]
        dropw
        ",
    )
    .expect("write PVM verifier call source");
    source
}

/// Full MASM program used by the benchmark.
///
/// `verify_calls` contains the MVM calls followed by the optional PVM call.
fn recursive_verifier_program_masm(verify_calls: &str, include_pvm: bool) -> String {
    let pvm_import = if include_pvm { "use miden::core::sys::pvm" } else { "" };
    format!(
        "
        use miden::core::sys
        use miden::core::sys::vm
        {pvm_import}

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

fn dump_recursive_program_source(composition: ProofComposition, source: &str) {
    let file_stem = if composition.is_mixed() {
        format!(
            "recursive_verify_{}_mvm_{}_pvm",
            composition.mvm_count(),
            composition.pvm_count()
        )
    } else {
        format!("recursive_verify_{}_proofs", composition.mvm_count())
    };
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("{file_stem}.masm"));
    std::fs::create_dir_all(path.parent().expect("recursive MASM dump parent"))
        .unwrap_or_else(|err| panic!("create MASM dump dir {}: {err}", path.display()));
    std::fs::write(&path, source)
        .unwrap_or_else(|err| panic!("write recursive MASM {}: {err}", path.display()));
    if composition.is_mixed() {
        println!(
            "BENCH_MIXED_RECURSION_MASM mvm_proofs={} pvm_proofs={} path={}",
            composition.mvm_count(),
            composition.pvm_count(),
            path.display(),
        );
    } else {
        println!(
            "BENCH_RECURSION_MASM proofs={} path={}",
            composition.mvm_count(),
            path.display()
        );
    }
}

fn build_recursive_verifier_case(
    fixtures: &[TxProofFixture],
    composition: ProofComposition,
    pvm_advice: Option<&RecursiveProofAdvice>,
    write_recursive_masm: bool,
) -> RecursionCase {
    assert!(
        fixtures.len() >= composition.mvm_count(),
        "recursion case requires {} MVM fixtures",
        composition.mvm_count()
    );
    assert_eq!(
        composition.pvm_count(),
        usize::from(pvm_advice.is_some()),
        "proof composition must match the supplied PVM advice"
    );
    let mut verify_calls = String::new();
    let mut advice_inputs = AdviceInputs::default();
    let mvm_verifier_root = CoreLibrary::default().recursive_verifier_root();

    for fixture in fixtures.iter().take(composition.mvm_count()) {
        let proof_advice = recursive_proof_advice(fixture, mvm_verifier_root);
        verify_calls.push_str(&verify_vm_proof_call_masm(proof_advice.claim_commitment));
        advice_inputs.extend(proof_advice.advice_inputs);
    }
    if let Some(pvm_advice) = pvm_advice {
        verify_calls.push_str(&verify_pvm_proof_call_masm(pvm_advice.claim_commitment));
        advice_inputs.extend(pvm_advice.advice_inputs.clone());
    }

    let source = recursive_verifier_program_masm(&verify_calls, pvm_advice.is_some());
    if write_recursive_masm {
        dump_recursive_program_source(composition, &source);
    }
    println!(
        "BENCH_RECURSION_PROGRAM {} source_bytes={}",
        composition.machine_fields(),
        source.len(),
    );

    RecursionCase {
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
    let Some(config) = BenchConfig::from_env() else {
        eprintln!(
            "skipping recursive_verify: set RECURSION_BENCH_MASM to a synthetic MASM fixture"
        );
        return;
    };
    let max_proof_count = config
        .compositions()
        .iter()
        .map(|composition| composition.mvm_count())
        .max()
        .expect("missing proof compositions");
    let fixtures = load_tx_fixtures(&config, max_proof_count);
    let pvm_advice = if config.requires_pvm() {
        Some(load_pvm_advice(&config))
    } else {
        None
    };
    let cases = config
        .compositions()
        .iter()
        .copied()
        .map(|composition| {
            let case_pvm_advice = composition
                .is_mixed()
                .then(|| pvm_advice.as_ref().expect("PVM comparison advice must be prepared"));
            build_recursive_verifier_case(
                &fixtures,
                composition,
                case_pvm_advice,
                config.write_recursive_masm(),
            )
        })
        .collect::<Vec<_>>();

    println!("\n=== recursive verifier trace shapes");
    let shapes = cases.iter().map(print_case_shape).collect::<Vec<_>>();
    print_trace_shape_summary(&shapes);
    if std::env::var_os("RECURSION_PROFILE_ONLY").is_some() {
        return;
    }
    if std::env::var_os("RECURSION_PROFILE_PROVE").is_some() {
        let runs = env_usize("RECURSION_PROFILE_PROVE_REPEATS", 1);
        let warmups = env_usize_allow_zero("RECURSION_PROFILE_PROVE_WARMUPS", 1);
        profile_prove_round_robin(&cases, config.outer_hash_fn(), warmups, runs);
        return;
    }

    let group_name = if config.requires_pvm() {
        "pvm_recursive_comparison"
    } else {
        "recursive_verify"
    };
    let mut group = c.benchmark_group(group_name);
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(env_usize("RECURSION_SAMPLE_SIZE", 10))
        .warm_up_time(Duration::from_secs(env_u64("RECURSION_WARM_UP_TIME_SECS", 1)))
        .measurement_time(Duration::from_secs(env_u64("RECURSION_MEASUREMENT_TIME_SECS", 10)));

    for case in cases {
        let label = case.composition.label();
        group.bench_function(format!("execute/{label}"), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_recursive_case,
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("build_trace/{label}"), |b| {
            b.iter_batched(
                || execute_trace_inputs(case.clone(), recursive_host()),
                build_trace_case,
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("total/{label}"), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_and_build_case,
                BatchSize::PerIteration,
            );
        });

        group.bench_function(format!("prove/{label}"), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host(), config.outer_hash_fn()),
                prove_recursive_case,
                BatchSize::PerIteration,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_recursive_verify);
criterion_main!(benches);
