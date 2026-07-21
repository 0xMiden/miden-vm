//! Benchmark and profiling helpers for the signature verifier.
//!
//! Restored from the `miden-signature-poc` branch and ported to `next`:
//! - proving goes through the standard `prove_sync` pipeline with the
//!   Poseidon2 proof hash (the recursion-friendly configuration);
//! - the old "p3 prove-only" hasher path was dropped together with the
//!   `p3_poseidon2` test module it depended on.

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, Word, proof::HashFunction};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, HostLibrary, Program};
use miden_utils_testing::{
    AdviceInputs, ProvingOptions, StackInputs, crypto::MerkleStore, prove_sync,
    stack_inputs_from_ints,
};

use super::{
    fixtures::{SigFixture, build_fixture_with_message, extend_advice_map_with_sig_proof},
    test_message,
};

struct BatchFixture {
    stack: Vec<u64>,
    advice: Vec<u64>,
    store: MerkleStore,
    advice_map: Vec<(Word, Vec<Felt>)>,
}

fn build_same_msg_batch_fixture(num_signatures: usize) -> BatchFixture {
    let message = test_message(1000);
    let mut fixtures: Vec<SigFixture> = Vec::with_capacity(num_signatures);
    for i in 0..num_signatures {
        let seed = format!("sig-batch-bench-signer-{i}");
        fixtures.push(build_fixture_with_message(seed.as_bytes(), message));
    }

    let mut stack = Vec::new();
    let mut advice = Vec::new();
    let mut store = MerkleStore::new();
    let mut advice_map: Vec<(Word, Vec<Felt>)> = Vec::new();

    for (i, fixture) in fixtures.iter().enumerate() {
        let msg = &fixture.data.initial_stack[4..8];
        if i == 0 {
            stack.extend_from_slice(msg);
        } else {
            assert_eq!(msg, &stack[0..4], "all signers must use the same message");
        }

        // Push pk words onto the advice stack; proofs live in the advice map.
        advice.extend_from_slice(&fixture.data.initial_stack[0..4]);

        store.extend(fixture.data.store.inner_nodes());
        advice_map.extend(fixture.data.advice_map.clone());
        extend_advice_map_with_sig_proof(&mut advice_map, &fixture.data);
    }

    BatchFixture { stack, advice, store, advice_map }
}

/// One shared message; per signer: load pk from the advice stack, restore the
/// shared msg (each verification overwrites the msg slot), verify from map.
fn build_shared_message_program(num_signatures: usize) -> Program {
    let source = format!(
        "use miden::core::sig
         use miden::core::sig::constants
         begin
             exec.constants::sig_msg_ptr mem_storew_le
             dropw
             repeat.{num_signatures}
                 padw adv_loadw
                 padw exec.constants::sig_msg_ptr mem_loadw_le
                 swapw
                 exec.sig::verify_signature_from_map
             end
         end"
    );
    let core_lib = CoreLibrary::default();
    Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("failed to load core library")
        .assemble_program("program", source)
        .expect("failed to assemble signature batch benchmark program")
        .unwrap_program()
}

fn build_sig_host() -> DefaultHost {
    let core_lib = CoreLibrary::default();
    let host_lib = HostLibrary {
        mast_forest: core_lib.mast_forest().clone(),
        package_debug_info: Ok(None),
        handlers: core_lib.handlers(),
    };
    DefaultHost::default()
        .with_library(host_lib)
        .expect("failed to load core library into host")
}

fn batch_inputs(fixture: &BatchFixture) -> (StackInputs, AdviceInputs) {
    let stack_inputs = stack_inputs_from_ints(fixture.stack.iter().copied());
    let advice_inputs = AdviceInputs::default()
        .with_stack_values(fixture.advice.clone())
        .expect("failed to set advice stack")
        .with_merkle_store(fixture.store.clone())
        .with_map(fixture.advice_map.clone());
    (stack_inputs, advice_inputs)
}

struct BenchParams {
    min_k: u32,
    max_k: u32,
    runs: usize,
}

impl BenchParams {
    fn from_env() -> Self {
        let min_k = std::env::var("SIG_BATCH_BENCH_MIN_K")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let max_k = std::env::var("SIG_BATCH_BENCH_MAX_K")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);
        let runs = std::env::var("SIG_BATCH_BENCH_RUNS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(3);

        assert!(min_k <= max_k, "SIG_BATCH_BENCH_MIN_K must be <= SIG_BATCH_BENCH_MAX_K");
        assert!(runs > 0, "SIG_BATCH_BENCH_RUNS must be > 0");

        Self { min_k, max_k, runs }
    }
}

/// Benchmarks proof generation time for shared-message batch verification over 2^k signatures.
///
/// Manual run:
///   SIG_BATCH_BENCH_MIN_K=0 SIG_BATCH_BENCH_MAX_K=5 SIG_BATCH_BENCH_RUNS=3 \
///   cargo test --release -p miden-core-lib --features concurrent \
///     bench_prove_sig_batch_shared_message -- --ignored --nocapture
#[test]
#[ignore = "run manually - proving benchmark sweep for signature batch verifier"]
fn bench_prove_sig_batch_shared_message() {
    use std::time::Instant;

    let params = BenchParams::from_env();
    eprintln!("\n=== Signature Batch Proving Benchmark (shared message) ===");
    eprintln!("k range: [{}, {}], runs per k: {}", params.min_k, params.max_k, params.runs);
    eprintln!("proof hash: Rpo256 (recursion-friendly)");
    eprintln!("-----------------------------------------------------------");

    for k in params.min_k..=params.max_k {
        let num_signatures = 1usize << k;
        let t_setup = Instant::now();
        let fixture = build_same_msg_batch_fixture(num_signatures);
        let program = build_shared_message_program(num_signatures);
        let setup_secs = t_setup.elapsed().as_secs_f64();

        // Execute once (no proving) to report the VM cost of the batch.
        let (stack_inputs, advice_inputs) = batch_inputs(&fixture);
        let mut host = build_sig_host();
        let t_exec = Instant::now();
        let processor = miden_processor::FastProcessor::new_with_options(
            stack_inputs,
            advice_inputs,
            ExecutionOptions::default(),
        )
        .expect("processor init failed");
        let trace_inputs = processor
            .execute_trace_inputs_sync(&program, &mut host)
            .expect("batch execution failed");
        let trace = miden_processor::trace::build_trace(trace_inputs).expect("trace build failed");
        let exec_secs = t_exec.elapsed().as_secs_f64();
        let trace_len = trace.get_trace_len();

        eprintln!(
            "2^{k}={} sigs | trace len {} = 2^{} ({:.0} rows/sig) | execute+trace={:.3}s",
            num_signatures,
            trace_len,
            trace_len.trailing_zeros(),
            trace_len as f64 / num_signatures as f64,
            exec_secs,
        );
        eprintln!("  trace summary: {:?}", trace.trace_len_summary());

        let mut prove_secs = Vec::with_capacity(params.runs);
        for run_idx in 0..params.runs {
            let (stack_inputs, advice_inputs) = batch_inputs(&fixture);
            let mut host = build_sig_host();

            let options = ProvingOptions::new(HashFunction::Rpo256);
            let t_prove = Instant::now();
            let _ = prove_sync(
                &program,
                stack_inputs,
                advice_inputs,
                &mut host,
                ExecutionOptions::default(),
                options,
            )
            .expect("failed to generate proof");
            let secs = t_prove.elapsed().as_secs_f64();
            prove_secs.push(secs);
            eprintln!("2^{k} run {}/{}: {:.3}s", run_idx + 1, params.runs, secs);
        }

        let total: f64 = prove_secs.iter().sum();
        let avg = total / params.runs as f64;
        let min = prove_secs.iter().copied().fold(f64::INFINITY, f64::min);
        let max = prove_secs.iter().copied().fold(0.0, f64::max);
        let sigs_per_sec = num_signatures as f64 / avg;

        eprintln!(
            "2^{k}={} sigs | setup={:.3}s | prove avg={:.3}s min={:.3}s max={:.3}s | throughput={:.2} sig/s",
            num_signatures, setup_secs, avg, min, max, sigs_per_sec,
        );
        eprintln!("-----------------------------------------------------------");
    }
}
