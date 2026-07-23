//! Recursive-verifier benchmark for synthetic transaction proofs.
//!
//! This benchmark separates the transaction proof from the recursive verifier cost:
//! transaction proofs are generated before timing, then the timed program verifies
//! the configured number of proofs via `exec.vm::verify_proof`.
//!
//! For each requested proof count, the setup builds one recursive-verifier program and one advice
//! provider. The program contains one verifier call per inner proof. The advice stack segments for
//! those proofs are concatenated in the same order, so each call consumes the segment generated for
//! it and leaves the next segment at the top of the advice stack.
//!
//! Env vars:
//! - `RECURSION_BENCH_MASM`: path to a synthetic transaction MASM fixture. If unset, this bench is
//!   skipped so `cargo bench -p miden-vm-synthetic-bench` keeps working out of the box. Relative
//!   paths may be relative to either the workspace root or this bench crate.
//! - `RECURSION_BENCH_STACK`: comma-separated stack inputs for the first transaction proof. The
//!   first value is incremented per proof so the benchmark verifies distinct proofs. Defaults to
//!   `0,1`.
//! - `RECURSION_BENCH_HASH`: STARK hash function. Defaults to `poseidon2`.
//! - `RECURSION_PROOF_COUNTS`: comma-separated proof counts. Defaults to `2,3,4,5,6,7,8`.
//! - `RECURSION_PROFILE_ONLY`: if set, print trace shapes and skip Criterion timing.
//! - `RECURSION_PROFILE_PROVE`: if set, run repeated proving outside Criterion and print
//!   `BENCH_RECURSION_PROOF` lines.
//! - `RECURSION_PROFILE_PROVE_REPEATS`: number of proving measurements for profile mode. Defaults
//!   to `1`.
//! - `RECURSION_PROFILE_PROVE_WARMUPS`: number of proving warmups for profile mode. Defaults to
//!   `0`.
//! - `RECURSION_MASM_WRITE`: if set, dump generated recursive verifier MASM programs to `target/`.
//! - `RECURSION_BENCH_TX_PROOF_CACHE_DIR`: optional transaction proof cache directory.
//! - `RECURSION_SAMPLE_SIZE`, `RECURSION_WARM_UP_TIME_SECS`, `RECURSION_MEASUREMENT_TIME_SECS`:
//!   Criterion timing knobs.

use std::{
    collections::HashSet,
    fmt::Write as _,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_assembly::Linkage;
use miden_core::{
    Felt,
    crypto::hash::Blake3_256,
    deferred::TRUE_DIGEST,
    field::QuotientMap,
    serde::{Deserializable, Serializable},
    utils::to_hex,
};
use miden_core_lib::CoreLibrary;
use miden_processor::{
    DefaultHost, ExecutionOptions, FastProcessor, advice::AdviceInputs, trace::TraceLenSummary,
};
use miden_prover::{PublicInputs, prove_sync};
use miden_utils_testing::recursive_verifier::generate_advice_inputs;
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, Program, ProgramInfo, ProvingOptions, StackInputs,
    StackOutputs, TraceBuildInputs, trace::build_trace,
};

const DEFAULT_PROOF_COUNTS: [usize; 7] = [2, 3, 4, 5, 6, 7, 8];
const KERNEL_DIGEST_PTR: u64 = 0;
const STACK_IO_PTR: u64 = 4096;
const STACK_IO_VALUE_COUNT: u64 = 32;
const TX_PROOF_CACHE_KEY_VERSION: &[u8] = b"miden-synthetic-recursive-tx-proof-cache-v1";

struct TxProofFixture {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
}

struct RecursiveProofAdvice {
    initial_stack: Vec<u64>,
    advice_inputs: AdviceInputs,
}

#[derive(Clone)]
struct RecursionCase {
    proof_count: usize,
    program: Program,
    advice_inputs: AdviceInputs,
}

struct TraceShapeSummary {
    proof_count: usize,
    core_rows: usize,
    range_rows: usize,
    chiplets_rows: usize,
    poseidon2_permutation_rows: usize,
    hash_chiplet_rows: usize,
    bitwise_rows: usize,
    memory_rows: usize,
    ace_rows: usize,
    kernel_rows: usize,
    max_trace_rows: usize,
    max_padded_rows: usize,
}

struct ProveSummary {
    proof_count: usize,
    runs: usize,
    avg_ms: f64,
    median_ms: f64,
    min_ms: f64,
    max_ms: f64,
    avg_proof_bytes: f64,
}

struct BenchConfig {
    hash_fn: HashFunction,
    proof_counts: Vec<usize>,
    tx_masm_path: PathBuf,
    tx_proof_cache_dir: Option<PathBuf>,
    write_recursive_masm: bool,
    base_stack_values: Vec<u64>,
}

impl BenchConfig {
    fn from_env() -> Option<Self> {
        let tx_masm_path = env_path("RECURSION_BENCH_MASM")?;
        let tx_masm_path = resolve_masm_path(tx_masm_path);
        let hash_name =
            std::env::var("RECURSION_BENCH_HASH").unwrap_or_else(|_| "poseidon2".to_string());
        let hash_fn = HashFunction::try_from(hash_name.as_str())
            .unwrap_or_else(|_| panic!("unsupported RECURSION_BENCH_HASH={hash_name:?}"));
        let base_stack_values = stack_values_from_env("RECURSION_BENCH_STACK", "0,1");
        assert!(
            !base_stack_values.is_empty(),
            "RECURSION_BENCH_STACK must contain at least one value"
        );

        Some(Self {
            hash_fn,
            proof_counts: proof_counts_from_env(),
            tx_masm_path,
            tx_proof_cache_dir: env_path("RECURSION_BENCH_TX_PROOF_CACHE_DIR"),
            write_recursive_masm: std::env::var_os("RECURSION_MASM_WRITE").is_some(),
            base_stack_values,
        })
    }

    fn stack_values_for_proof(&self, proof_index: usize) -> Vec<u64> {
        let mut values = self.base_stack_values.clone();
        values[0] = values[0]
            .checked_add(proof_index as u64)
            .expect("distinct stack input overflow");
        values
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn resolve_masm_path(path: PathBuf) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().and_then(Path::parent).expect("workspace root");
    let requested = path.display().to_string();

    let candidates = if path.is_absolute() {
        vec![path]
    } else {
        vec![path.clone(), manifest_dir.join(&path), workspace_root.join(&path)]
    };

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("RECURSION_BENCH_MASM must point to a MASM file: {requested}"))
}

fn proof_counts_from_env() -> Vec<usize> {
    let Some(raw) = std::env::var("RECURSION_PROOF_COUNTS").ok().filter(|s| !s.trim().is_empty())
    else {
        return DEFAULT_PROOF_COUNTS.to_vec();
    };

    let mut counts = Vec::new();
    let mut seen = HashSet::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let value = entry.parse::<usize>().expect("RECURSION_PROOF_COUNTS entries must be usize");
        assert!(value > 0, "RECURSION_PROOF_COUNTS entries must be non-zero");
        assert!(seen.insert(value), "duplicate RECURSION_PROOF_COUNTS entry: {value}");
        counts.push(value);
    }

    assert!(!counts.is_empty(), "RECURSION_PROOF_COUNTS did not select any proof counts");
    counts
}

fn stack_values_from_env(name: &str, default: &str) -> Vec<u64> {
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    if raw.trim().is_empty() {
        return Vec::new();
    }

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap_or_else(|_| panic!("{name} entries must be u64")))
        .collect()
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().unwrap_or_else(|_| panic!("{name} must be a usize"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn env_usize_allow_zero(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => raw.parse::<usize>().unwrap_or_else(|_| panic!("{name} must be a usize")),
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<u64>().unwrap_or_else(|_| panic!("{name} must be a u64"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

fn stack_inputs(values: &[u64]) -> StackInputs {
    if values.is_empty() {
        return StackInputs::default();
    }

    let values: Vec<_> = values
        .iter()
        .copied()
        .map(|value| {
            Felt::from_canonical_checked(value)
                .unwrap_or_else(|| panic!("invalid RECURSION_BENCH_STACK value {value}"))
        })
        .collect();
    StackInputs::new(&values).expect("invalid RECURSION_BENCH_STACK")
}

fn tx_proof_cache_key(
    program_info: &ProgramInfo,
    stack_values: &[u64],
    hash_fn: HashFunction,
) -> String {
    let mut program_bytes = Vec::new();
    program_bytes.extend_from_slice(&program_info.program_hash().as_bytes());
    for digest in program_info.kernel_procedures() {
        program_bytes.extend_from_slice(&digest.as_bytes());
    }

    let mut stack_bytes = Vec::with_capacity(stack_values.len() * 8);
    for value in stack_values {
        stack_bytes.extend_from_slice(&value.to_le_bytes());
    }
    let hash_fn_byte = [hash_fn as u8];
    let digest: [u8; 32] = Blake3_256::hash_iter(
        [
            TX_PROOF_CACHE_KEY_VERSION,
            env!("CARGO_PKG_VERSION").as_bytes(),
            program_bytes.as_slice(),
            stack_bytes.as_slice(),
            hash_fn_byte.as_slice(),
        ]
        .into_iter(),
    )
    .into();
    to_hex(digest)
}

fn tx_proof_cache_paths(
    cache_dir: &Path,
    proof_index: usize,
    cache_key: &str,
) -> (PathBuf, PathBuf) {
    (
        cache_dir.join(format!("proof-{proof_index}-{cache_key}.bin")),
        cache_dir.join(format!("outputs-{proof_index}-{cache_key}.bin")),
    )
}

fn load_cached_tx_proof(
    cache_dir: &Path,
    proof_index: usize,
    cache_key: &str,
    hash_fn: HashFunction,
) -> Option<(StackOutputs, ExecutionProof)> {
    let (proof_path, outputs_path) = tx_proof_cache_paths(cache_dir, proof_index, cache_key);
    if !proof_path.is_file() || !outputs_path.is_file() {
        return None;
    }

    let proof_bytes = match std::fs::read(&proof_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("ignoring unreadable cached proof {}: {err}", proof_path.display());
            return None;
        },
    };
    let proof = match ExecutionProof::from_bytes(&proof_bytes) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("ignoring undecodable cached proof {}: {err}", proof_path.display());
            return None;
        },
    };
    assert_eq!(proof.hash_fn(), hash_fn, "cached transaction proof hash function mismatch");

    let output_bytes = match std::fs::read(&outputs_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("ignoring unreadable cached outputs {}: {err}", outputs_path.display());
            return None;
        },
    };
    let stack_outputs = match StackOutputs::read_from_bytes(&output_bytes) {
        Ok(stack_outputs) => stack_outputs,
        Err(err) => {
            eprintln!("ignoring undecodable cached outputs {}: {err}", outputs_path.display());
            return None;
        },
    };

    Some((stack_outputs, proof))
}

fn store_cached_tx_proof(
    cache_dir: &Path,
    proof_index: usize,
    cache_key: &str,
    stack_outputs: &StackOutputs,
    proof: &ExecutionProof,
) {
    std::fs::create_dir_all(cache_dir)
        .unwrap_or_else(|err| panic!("create proof cache {}: {err}", cache_dir.display()));
    let (proof_path, outputs_path) = tx_proof_cache_paths(cache_dir, proof_index, cache_key);

    std::fs::write(&proof_path, proof.to_bytes())
        .unwrap_or_else(|err| panic!("write cached proof {}: {err}", proof_path.display()));

    let mut output_bytes = Vec::new();
    stack_outputs.write_into(&mut output_bytes);
    std::fs::write(&outputs_path, output_bytes)
        .unwrap_or_else(|err| panic!("write cached outputs {}: {err}", outputs_path.display()));
}

fn hex_prefix(bytes: &[u8]) -> String {
    to_hex(&bytes[..bytes.len().min(16)])
}

fn trace_shape_summary_for(proof_count: usize, summary: &TraceLenSummary) -> TraceShapeSummary {
    let chiplets = summary.chiplets_trace_len();

    TraceShapeSummary {
        proof_count,
        core_rows: summary.core_trace_len(),
        range_rows: summary.range_trace_len(),
        chiplets_rows: chiplets.trace_len(),
        poseidon2_permutation_rows: summary.poseidon2_permutation_trace_len(),
        hash_chiplet_rows: chiplets.hash_chiplet_len(),
        bitwise_rows: chiplets.bitwise_chiplet_len(),
        memory_rows: chiplets.memory_chiplet_len(),
        ace_rows: chiplets.ace_chiplet_len(),
        kernel_rows: chiplets.kernel_rom_len(),
        max_trace_rows: summary.trace_len(),
        max_padded_rows: summary.padded_trace_len(),
    }
}

fn print_tx_fixture_shape(
    program: &Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    proof_index: usize,
) {
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("transaction fixture advice should fit provider limits");
    let mut host = recursive_host();
    let trace_inputs = processor
        .execute_trace_inputs_sync(program, &mut host)
        .expect("execute transaction fixture");
    let trace = build_trace(trace_inputs).expect("build transaction fixture trace");
    let summary = trace.trace_len_summary();
    let record = format!("BENCH_TX_SHAPE index={proof_index}");
    let shape = trace_shape_summary_for(proof_index, summary);
    print_bench_shape(&record, &shape);
}

fn load_tx_fixtures(config: &BenchConfig, proof_count: usize) -> Vec<TxProofFixture> {
    let source = std::fs::read_to_string(&config.tx_masm_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", config.tx_masm_path.display()));
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("link core library")
        .assemble_program("tx_fixture", source.as_str())
        .expect("assemble transaction fixture")
        .unwrap_program();
    let program_info = ProgramInfo::from(program.clone());

    println!(
        "\n=== transaction proof fixtures\n    masm={} hash={:?} proof_cache={}",
        config.tx_masm_path.display(),
        config.hash_fn,
        config
            .tx_proof_cache_dir
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
    );

    let mut seen_proofs = HashSet::with_capacity(proof_count);
    (0..proof_count)
        .map(|proof_index| {
            let stack_values = config.stack_values_for_proof(proof_index);
            let stack_inputs = stack_inputs(&stack_values);
            let advice_inputs = AdviceInputs::default();
            let proof_cache_key = tx_proof_cache_key(&program_info, &stack_values, config.hash_fn);
            print_tx_fixture_shape(&program, stack_inputs, advice_inputs.clone(), proof_index);

            let (stack_outputs, proof, proof_cache_status) = if let Some((stack_outputs, proof)) =
                config.tx_proof_cache_dir.as_deref().and_then(|cache_dir| {
                    load_cached_tx_proof(
                        cache_dir,
                        proof_index,
                        proof_cache_key.as_str(),
                        config.hash_fn,
                    )
                }) {
                (stack_outputs, proof, "hit")
            } else {
                let mut host = recursive_host();
                let (stack_outputs, proof) = prove_sync(
                    &program,
                    stack_inputs,
                    advice_inputs,
                    &mut host,
                    ExecutionOptions::default(),
                    ProvingOptions::new(config.hash_fn),
                )
                .expect("prove transaction fixture");
                if let Some(cache_dir) = config.tx_proof_cache_dir.as_deref() {
                    store_cached_tx_proof(
                        cache_dir,
                        proof_index,
                        proof_cache_key.as_str(),
                        &stack_outputs,
                        &proof,
                    );
                }
                (stack_outputs, proof, "miss")
            };
            let deferred_entries =
                proof.settlement().expect("prover packages carry evidence").entries.len();
            assert_eq!(
                deferred_entries, 0,
                "recursive_verify fixture at proof index {proof_index} emits deferred proof data; \
                 this benchmark expects precompile-free fixtures"
            );
            let proof_bytes = proof.to_bytes();
            let proof_bytes_len = proof_bytes.len();
            let proof_digest: [u8; 32] = Blake3_256::hash(&proof_bytes).into();
            let proof_prefix = hex_prefix(&proof_bytes);
            assert!(
                seen_proofs.insert(proof_bytes),
                "recursive benchmark generated duplicate transaction proof at index {proof_index}"
            );

            let proof_digest_hex = to_hex(proof_digest);
            println!(
                "    proof={proof_index} stack={stack_values:?} proof_bytes={proof_bytes_len} \
                 deferred_entries={deferred_entries}",
            );
            println!(
                "BENCH_TX_PROOF index={proof_index} stack={stack_values:?} \
                 proof_bytes={proof_bytes_len} deferred_entries={deferred_entries} \
                 proof_cache={proof_cache_status} proof_digest={proof_digest_hex} \
                 proof_prefix={proof_prefix}",
            );

            TxProofFixture {
                program_info: program_info.clone(),
                stack_inputs,
                stack_outputs,
                proof,
            }
        })
        .collect()
}

/// MASM for one `exec.vm::verify_proof` call.
///
/// The generated program appends one block like this per inner transaction proof.
fn verify_proof_call_masm(initial_stack: &[u64]) -> String {
    let mut source = String::new();
    // `initial_stack[0]` must be on top when `verify_proof` starts.
    for value in initial_stack.iter().rev() {
        writeln!(source, "push.{value}").expect("write recursive verifier call source");
    }
    writeln!(
        source,
        "
        # Copy 4 * num_kernel_digests felts from advice into the kernel region.
        dup.1 mul.4 push.{KERNEL_DIGEST_PTR}
        exec.copy_advice_to_mem

        # Copy stack inputs and outputs into the stack i/o region.
        push.{STACK_IO_VALUE_COUNT} push.{STACK_IO_PTR}
        exec.copy_advice_to_mem

        exec.vm::verify_proof
        "
    )
    .expect("write recursive verifier call source");
    source
}

/// Full MASM program used by the benchmark.
///
/// `verify_calls` is a sequence of `exec.vm::verify_proof` calls, one per inner proof.
fn recursive_verifier_program_masm(verify_calls: &str) -> String {
    format!(
        "
        use miden::core::sys::vm

        # Copy `count` felts from advice into memory starting at `dst`.
        # `count` must be a multiple of 4.
        #   Input:  [dst, count, ...]
        #   Output: [...]
        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                # [dst, count, ...]
                padw adv_loadw
                # [w0, w1, w2, w3, dst, count, ...]
                dup.4 mem_storew_le dropw
                # [dst, count, ...]
                add.4
                # [dst + 4, count, ...]
                swap sub.4 swap
                # [dst + 4, count - 4, ...]
                dup.1 push.0 neq
            end
            drop drop
        end

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

fn dump_recursive_program_source(proof_count: usize, source: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("recursive_verify_{proof_count}_proofs.masm"));
    std::fs::create_dir_all(path.parent().expect("recursive MASM dump parent"))
        .unwrap_or_else(|err| panic!("create MASM dump dir {}: {err}", path.display()));
    std::fs::write(&path, source)
        .unwrap_or_else(|err| panic!("write recursive MASM {}: {err}", path.display()));
    println!("BENCH_RECURSION_MASM proofs={proof_count} path={}", path.display());
}

/// Build the advice provider consumed by one recursive verifier call.
///
/// `generate_advice_inputs` parses the inner STARK proof and returns the exact advice stack,
/// Merkle store, and advice-map entries expected by `exec.vm::verify_proof`.
/// The stack is ordered so its first element is the next value consumed by the VM.
fn recursive_proof_advice(fixture: &TxProofFixture) -> RecursiveProofAdvice {
    let pub_inputs = PublicInputs::new(
        fixture.program_info.clone(),
        fixture.stack_inputs,
        fixture.stack_outputs,
        TRUE_DIGEST,
    );
    let verifier_inputs =
        generate_advice_inputs(fixture.proof.stark_proof(), pub_inputs).expect("recursive advice");

    let advice_inputs = AdviceInputs::default()
        .with_stack_values(verifier_inputs.advice_stack)
        .expect("recursive advice stack values must be canonical")
        .with_merkle_store(verifier_inputs.store)
        .with_map(verifier_inputs.advice_map);

    RecursiveProofAdvice {
        initial_stack: verifier_inputs.initial_stack,
        advice_inputs,
    }
}

fn build_recursive_verifier_case(
    fixtures: &[TxProofFixture],
    proof_count: usize,
    write_recursive_masm: bool,
) -> RecursionCase {
    let mut verify_calls = String::new();
    let mut advice_inputs = AdviceInputs::default();

    for fixture in fixtures.iter().take(proof_count) {
        let proof_advice = recursive_proof_advice(fixture);
        // MASM calls and advice segments are appended in lockstep. There is a single advice
        // provider for the outer program; after one verifier call consumes its segment, the next
        // segment is at the top of the same advice stack.
        verify_calls.push_str(&verify_proof_call_masm(&proof_advice.initial_stack));
        advice_inputs.extend(proof_advice.advice_inputs);
    }

    let source = recursive_verifier_program_masm(&verify_calls);
    if write_recursive_masm {
        dump_recursive_program_source(proof_count, &source);
    }
    println!("BENCH_RECURSION_PROGRAM proofs={} source_bytes={}", proof_count, source.len(),);

    RecursionCase {
        proof_count,
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

fn execute_trace_inputs(case: RecursionCase, mut host: DefaultHost) -> TraceBuildInputs {
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        case.advice_inputs,
        ExecutionOptions::default(),
    )
    .expect("recursive verifier advice should fit provider limits");
    processor
        .execute_trace_inputs_sync(&case.program, &mut host)
        .expect("execute recursive verifier")
}

fn execute_recursive_case((case, host): (RecursionCase, DefaultHost)) {
    let trace_inputs = execute_trace_inputs(case, host);
    black_box(trace_inputs);
}

fn build_trace_case(trace_inputs: TraceBuildInputs) {
    let trace = build_trace(trace_inputs).expect("build recursive verifier trace");
    black_box(trace);
}

fn execute_and_build_case((case, host): (RecursionCase, DefaultHost)) {
    let trace_inputs = execute_trace_inputs(case, host);
    build_trace_case(trace_inputs);
}

fn prove_recursive_case((case, mut host, hash_fn): (RecursionCase, DefaultHost, HashFunction)) {
    let proof = prove_sync(
        &case.program,
        StackInputs::default(),
        case.advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::new(hash_fn),
    )
    .expect("prove recursive verifier");
    black_box(proof);
}

fn prove_recursive_once(case: &RecursionCase, hash_fn: HashFunction) -> (f64, usize) {
    let advice_inputs = case.advice_inputs.clone();
    let start = Instant::now();
    let mut host = recursive_host();
    let (_, proof) = prove_sync(
        &case.program,
        StackInputs::default(),
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::new(hash_fn),
    )
    .expect("prove recursive verifier");
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    let proof_bytes = proof.to_bytes().len();
    black_box(proof);
    (elapsed_ms, proof_bytes)
}

fn prove_summary(proof_count: usize, samples: &[(f64, usize)]) -> ProveSummary {
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
        proof_count,
        runs,
        avg_ms,
        median_ms,
        min_ms: elapsed[0],
        max_ms: elapsed[runs - 1],
        avg_proof_bytes,
    }
}

fn profile_prove_repeated(
    case: &RecursionCase,
    hash_fn: HashFunction,
    warmups: usize,
    runs: usize,
) -> ProveSummary {
    for warmup_idx in 1..=warmups {
        let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
        eprintln!(
            "recursive_profile warmup {warmup_idx}/{warmups}/{} proofs: {:.3} ms proof_bytes={}",
            case.proof_count, elapsed_ms, proof_bytes,
        );
    }

    let mut samples = Vec::with_capacity(runs);
    for run_idx in 1..=runs {
        let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
        samples.push((elapsed_ms, proof_bytes));
        eprintln!(
            "recursive_profile run {run_idx}/{runs}/{} proofs: {:.3} ms proof_bytes={}",
            case.proof_count, elapsed_ms, proof_bytes,
        );
        println!(
            "BENCH_RECURSION_PROOF proofs={} run={} prove_ms={:.3} proof_bytes={}",
            case.proof_count, run_idx, elapsed_ms, proof_bytes,
        );
    }
    prove_summary(case.proof_count, &samples)
}

fn print_prove_summary(summaries: &[ProveSummary]) {
    println!("\n=== recursive proving summary");
    println!("| proofs | avg_s | median_s | min_s | max_s | avg_proof_bytes |");
    println!("|---:|---:|---:|---:|---:|---:|");
    for summary in summaries {
        println!(
            "| {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.0} |",
            summary.proof_count,
            summary.avg_ms / 1_000.0,
            summary.median_ms / 1_000.0,
            summary.min_ms / 1_000.0,
            summary.max_ms / 1_000.0,
            summary.avg_proof_bytes,
        );
        println!(
            "BENCH_RECURSION_PROOF_SUMMARY proofs={} runs={} avg_ms={:.3} median_ms={:.3} min_ms={:.3} max_ms={:.3} avg_proof_bytes={:.0}",
            summary.proof_count,
            summary.runs,
            summary.avg_ms,
            summary.median_ms,
            summary.min_ms,
            summary.max_ms,
            summary.avg_proof_bytes,
        );
    }
}

fn trace_shape_summary(case: &RecursionCase) -> TraceShapeSummary {
    let processor = FastProcessor::new_with_options(
        StackInputs::default(),
        case.advice_inputs.clone(),
        ExecutionOptions::default(),
    )
    .expect("recursive verifier advice should fit provider limits");
    let mut host = recursive_host();
    let trace_inputs = processor
        .execute_trace_inputs_sync(&case.program, &mut host)
        .expect("execute recursive verifier");
    let trace = build_trace(trace_inputs).expect("build recursive verifier trace");
    let summary = trace.trace_len_summary();
    trace_shape_summary_for(case.proof_count, summary)
}

fn print_case_shape(case: &RecursionCase) -> TraceShapeSummary {
    let shape = trace_shape_summary(case);

    println!(
        "    proofs={} core={} range={} chiplets={} poseidon2_perm={} hash_ctrl={} max_trace={} max_padded={}",
        shape.proof_count,
        shape.core_rows,
        shape.range_rows,
        shape.chiplets_rows,
        shape.poseidon2_permutation_rows,
        shape.hash_chiplet_rows,
        shape.max_trace_rows,
        shape.max_padded_rows,
    );
    let record = format!("BENCH_RECURSION_SHAPE proofs={}", shape.proof_count);
    print_bench_shape(&record, &shape);
    shape
}

fn print_bench_shape(record: &str, shape: &TraceShapeSummary) {
    // This is a machine-readable schema consumed by benchmark parsers.
    println!(
        concat!(
            "{} ",
            "core_rows={} range_rows={} chiplets_rows={} poseidon2_permutation_rows={} ",
            "hash_chiplet_rows={} bitwise_rows={} memory_rows={} ace_rows={} kernel_rows={} ",
            "native_hash_rows=0 and8_lookup_rows=0 max_trace_rows={} max_padded_rows={}"
        ),
        record,
        shape.core_rows,
        shape.range_rows,
        shape.chiplets_rows,
        shape.poseidon2_permutation_rows,
        shape.hash_chiplet_rows,
        shape.bitwise_rows,
        shape.memory_rows,
        shape.ace_rows,
        shape.kernel_rows,
        shape.max_trace_rows,
        shape.max_padded_rows,
    );
}

fn print_trace_shape_summary(shapes: &[TraceShapeSummary]) {
    println!("\n=== recursive trace summary");
    println!(
        "| proofs | core | range | chiplets | poseidon2_perm | hash | bitwise | memory | ace | kernel | max_trace | padded |"
    );
    println!("|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
    for shape in shapes {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            shape.proof_count,
            shape.core_rows,
            shape.range_rows,
            shape.chiplets_rows,
            shape.poseidon2_permutation_rows,
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

fn bench_recursive_verify(c: &mut Criterion) {
    let Some(config) = BenchConfig::from_env() else {
        eprintln!(
            "skipping recursive_verify: set RECURSION_BENCH_MASM to a synthetic MASM fixture"
        );
        return;
    };
    let max_proof_count = config.proof_counts.iter().copied().max().expect("missing proof counts");
    let fixtures = load_tx_fixtures(&config, max_proof_count);
    let cases = config
        .proof_counts
        .iter()
        .copied()
        .map(|proof_count| {
            build_recursive_verifier_case(&fixtures, proof_count, config.write_recursive_masm)
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
        let warmups = env_usize_allow_zero("RECURSION_PROFILE_PROVE_WARMUPS", 0);
        let mut summaries = Vec::with_capacity(cases.len());
        for case in &cases {
            summaries.push(profile_prove_repeated(case, config.hash_fn, warmups, runs));
        }
        print_prove_summary(&summaries);
        return;
    }

    let mut group = c.benchmark_group("recursive_verify");
    group
        .sampling_mode(SamplingMode::Flat)
        .sample_size(env_usize("RECURSION_SAMPLE_SIZE", 10))
        .warm_up_time(Duration::from_secs(env_u64("RECURSION_WARM_UP_TIME_SECS", 1)))
        .measurement_time(Duration::from_secs(env_u64("RECURSION_MEASUREMENT_TIME_SECS", 10)));

    for case in cases {
        group.bench_function(format!("execute/{} proofs", case.proof_count), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_recursive_case,
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("build_trace/{} proofs", case.proof_count), |b| {
            b.iter_batched(
                || execute_trace_inputs(case.clone(), recursive_host()),
                build_trace_case,
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("total/{} proofs", case.proof_count), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host()),
                execute_and_build_case,
                BatchSize::SmallInput,
            );
        });

        group.bench_function(format!("prove/{} proofs", case.proof_count), |b| {
            b.iter_batched(
                || (case.clone(), recursive_host(), config.hash_fn),
                prove_recursive_case,
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_recursive_verify);
criterion_main!(benches);
