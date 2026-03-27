//! Benchmark and profiling helpers for the signature verifier.

use miden_assembly::Assembler;
use miden_core::{Felt, Word};
use miden_core_lib::CoreLibrary;
use miden_processor::DefaultHost;
use miden_utils_testing::{AdviceInputs, StackInputs, crypto::MerkleStore};

use super::{
    fixtures::{SigFixture, build_fixture_with_message, extend_advice_map_with_sig_proof},
    p3_poseidon2, test_message,
};

struct BatchFixture {
    stack: Vec<u64>,
    advice: Vec<u64>,
    store: MerkleStore,
    advice_map: Vec<(Word, Vec<Felt>)>,
}

fn build_same_msg_batch_fixture(num_signatures: usize) -> BatchFixture {
    assert!(
        num_signatures.is_power_of_two() && num_signatures <= 32,
        "num_signatures must be a power of two <= 32"
    );

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

fn build_shared_message_program(num_signatures: usize) -> miden_processor::Program {
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
    Assembler::default()
        .with_dynamic_library(CoreLibrary::default())
        .expect("failed to load core library")
        .assemble_program(source)
        .expect("failed to assemble signature batch benchmark program")
}

fn build_sig_host() -> DefaultHost {
    let mut host = DefaultHost::default();
    let core_lib = CoreLibrary::default();
    host.load_library(core_lib.library().mast_forest())
        .expect("failed to load core library into host");
    for (event, handler) in core_lib.handlers() {
        host.register_handler(event, handler)
            .expect("failed to register core library handler");
    }
    host
}

enum BenchHasher {
    P3,
    Miden,
}

impl BenchHasher {
    fn from_env() -> Self {
        match std::env::var("SIG_BATCH_BENCH_HASHER")
            .unwrap_or_else(|_| "p3".to_string())
            .to_lowercase()
            .as_str()
        {
            "p3" | "plonky3" => Self::P3,
            "miden" | "miden-crypto" => Self::Miden,
            other => panic!("unknown SIG_BATCH_BENCH_HASHER: {other}"),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::P3 => "Poseidon2 (p3, prove-only)",
            Self::Miden => "Poseidon2 (miden-crypto)",
        }
    }

    fn prove(
        &self,
        program: &miden_processor::Program,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        host: &mut DefaultHost,
    ) -> Result<(), miden_processor::ExecutionError> {
        match self {
            Self::P3 => p3_poseidon2::prove_program_with_p3_poseidon2(
                program,
                stack_inputs,
                advice_inputs,
                host,
            ),
            Self::Miden => {
                use miden_core::proof::HashFunction;
                use miden_utils_testing::{ProvingOptions, prove_sync};

                let options = ProvingOptions::new(HashFunction::Poseidon2);
                let _ = prove_sync(program, stack_inputs, advice_inputs, host, options)
                    .expect("failed to generate proof");
                Ok(())
            },
        }
    }
}

struct BenchParams {
    min_k: u32,
    max_k: u32,
    runs: usize,
    hasher: BenchHasher,
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

        Self {
            min_k,
            max_k,
            runs,
            hasher: BenchHasher::from_env(),
        }
    }
}

/// Benchmarks proof generation time for shared-message batch verification over 2^k signatures.
///
/// Manual run:
///   SIG_BATCH_BENCH_MIN_K=0 SIG_BATCH_BENCH_MAX_K=5 SIG_BATCH_BENCH_RUNS=3 \
///   cargo test --release -p miden-core-lib --features miden-prover/concurrent \
///     bench_prove_sig_batch_shared_message -- --ignored --nocapture
#[test]
#[ignore = "run manually - proving benchmark sweep for signature batch verifier"]
fn bench_prove_sig_batch_shared_message() {
    use std::time::Instant;

    let params = BenchParams::from_env();
    eprintln!("\n=== Signature Batch Proving Benchmark (shared message) ===");
    eprintln!("k range: [{}, {}], runs per k: {}", params.min_k, params.max_k, params.runs);
    eprintln!("hasher: {}", params.hasher.label());
    eprintln!("-----------------------------------------------------------");

    for k in params.min_k..=params.max_k {
        let num_signatures = 1usize << k;
        let t_setup = Instant::now();
        let fixture = build_same_msg_batch_fixture(num_signatures);
        let program = build_shared_message_program(num_signatures);
        let setup_secs = t_setup.elapsed().as_secs_f64();

        let mut prove_secs = Vec::with_capacity(params.runs);
        for run_idx in 0..params.runs {
            let stack_inputs = StackInputs::try_from_ints(fixture.stack.clone())
                .expect("failed to set stack inputs");
            let advice_inputs = AdviceInputs::default()
                .with_stack_values(fixture.advice.clone())
                .expect("failed to set advice stack")
                .with_merkle_store(fixture.store.clone())
                .with_map(fixture.advice_map.clone());

            let mut host = build_sig_host();

            let t_prove = Instant::now();
            params
                .hasher
                .prove(&program, stack_inputs, advice_inputs, &mut host)
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
            "2^{k}={} sigs | setup={:.3}s | prove avg={:.3}s min={:.3}s max={:.3}s | throughput={:.2} sig/s | advice_stack={} advice_map={}",
            num_signatures,
            setup_secs,
            avg,
            min,
            max,
            sigs_per_sec,
            fixture.advice.len(),
            fixture.advice_map.len(),
        );
        eprintln!("-----------------------------------------------------------");
    }
}
