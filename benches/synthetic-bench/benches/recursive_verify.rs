//! Recursive-verifier benchmark for synthetic transaction proofs.
//!
//! This benchmark separates the transaction proof from the recursive verifier cost:
//! transaction proofs are generated before timing, then the timed program verifies
//! the configured number of proofs via `exec.vm::verify_proof`.

use std::{
    collections::HashSet,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use codspeed_criterion_compat as criterion;
use criterion::{BatchSize, Criterion, SamplingMode, criterion_group, criterion_main};
use miden_core::{
    Felt,
    precompile::PrecompileTranscriptState,
    serde::{Deserializable, Serializable},
};
use miden_core_lib::CoreLibrary;
use miden_processor::{DefaultHost, ExecutionOptions, FastProcessor, advice::AdviceInputs};
use miden_prover::{PublicInputs, prove_sync};
use miden_utils_testing::recursive_verifier::generate_advice_inputs;
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, Program, ProgramInfo, ProvingOptions, StackInputs,
    StackOutputs, TraceBuildInputs, assembly::Linkage, trace::build_trace,
};

const DEFAULT_PROOF_COUNTS: [usize; 3] = [2, 4, 6];

#[derive(Clone)]
struct TxProofFixture {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
}

struct RecursionInputs {
    initial_stack: Vec<u64>,
    advice_inputs: AdviceInputs,
}

#[derive(Clone)]
struct RecursionCase {
    proof_count: usize,
    program: Program,
    advice_inputs: AdviceInputs,
}

fn bench_hash() -> HashFunction {
    let hash_name = std::env::var("RECURSION_BENCH_HASH").unwrap_or_else(|_| "eidos".to_string());
    HashFunction::try_from(hash_name.as_str())
        .unwrap_or_else(|_| panic!("unsupported RECURSION_BENCH_HASH={hash_name:?}"))
}

fn proof_counts() -> Vec<usize> {
    let Some(raw) = std::env::var("RECURSION_PROOF_COUNTS").ok().filter(|s| !s.trim().is_empty())
    else {
        return DEFAULT_PROOF_COUNTS.to_vec();
    };

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            let value = s.parse::<usize>().expect("RECURSION_PROOF_COUNTS entries must be usize");
            assert!(value > 0, "RECURSION_PROOF_COUNTS entries must be non-zero");
            value
        })
        .collect()
}

fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => raw.parse::<usize>().unwrap_or_else(|_| panic!("{name} must be a usize")),
        Err(_) => default,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => raw.parse::<u64>().unwrap_or_else(|_| panic!("{name} must be a u64")),
        Err(_) => default,
    }
}

fn base_stack_values() -> Vec<u64> {
    let raw = std::env::var("RECURSION_BENCH_STACK").unwrap_or_else(|_| "0,1".to_string());
    if raw.trim().is_empty() {
        return Vec::new();
    }

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().expect("RECURSION_BENCH_STACK entries must be u64"))
        .collect()
}

fn use_distinct_stack_inputs() -> bool {
    std::env::var("RECURSION_BENCH_DISTINCT_STACKS")
        .map(|raw| !matches!(raw.as_str(), "0" | "false" | "False" | "FALSE"))
        .unwrap_or(true)
}

fn stack_values_for_proof(proof_index: usize) -> Vec<u64> {
    let mut values = base_stack_values();
    if use_distinct_stack_inputs() && !values.is_empty() {
        values[0] = values[0]
            .checked_add(proof_index as u64)
            .expect("distinct stack input overflow");
    }
    values
}

fn stack_inputs(values: &[u64]) -> StackInputs {
    if values.is_empty() {
        return StackInputs::default();
    }

    let values = values
        .iter()
        .copied()
        .map(|value| Felt::new(value).expect("RECURSION_BENCH_STACK value must be canonical"))
        .collect::<Vec<_>>();
    StackInputs::new(&values).expect("invalid RECURSION_BENCH_STACK")
}

fn masm_path() -> PathBuf {
    std::env::var("RECURSION_BENCH_MASM")
        .map(PathBuf::from)
        .expect("RECURSION_BENCH_MASM must point to the synthetic transaction MASM fixture")
}

fn proof_cache_load_dir() -> Option<PathBuf> {
    non_empty_env_path("RECURSION_TX_PROOF_LOAD_DIR")
}

fn proof_cache_save_dir() -> Option<PathBuf> {
    non_empty_env_path("RECURSION_TX_PROOF_SAVE_DIR")
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(name)?;
    if raw.is_empty() {
        return None;
    }
    Some(PathBuf::from(raw))
}

fn hex_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let prefix_len = bytes.len().min(16);
    let mut out = String::with_capacity(prefix_len * 2);
    for &byte in &bytes[..prefix_len] {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

struct ProofCachePaths {
    program_info: PathBuf,
    stack_inputs: PathBuf,
    proof: PathBuf,
    stack_outputs: PathBuf,
}

impl ProofCachePaths {
    fn new(dir: &Path, proof_index: usize) -> Self {
        Self {
            program_info: dir.join("program-info.bin"),
            stack_inputs: dir.join(format!("stack-inputs-{proof_index}.bin")),
            proof: dir.join(format!("proof-{proof_index}.bin")),
            stack_outputs: dir.join(format!("stack-outputs-{proof_index}.bin")),
        }
    }
}

fn load_cached_tx_fixture(
    dir: &Path,
    program_info: ProgramInfo,
    hash_fn: HashFunction,
    proof_index: usize,
    expected_stack_inputs: StackInputs,
) -> TxProofFixture {
    let paths = ProofCachePaths::new(dir, proof_index);
    let program_info_bytes = std::fs::read(&paths.program_info).unwrap_or_else(|err| {
        panic!("read cached program info {}: {err}", paths.program_info.display())
    });
    let stack_inputs_bytes = std::fs::read(&paths.stack_inputs).unwrap_or_else(|err| {
        panic!("read cached stack inputs {}: {err}", paths.stack_inputs.display())
    });
    let proof_bytes = std::fs::read(&paths.proof)
        .unwrap_or_else(|err| panic!("read cached proof {}: {err}", paths.proof.display()));
    let stack_outputs_bytes = std::fs::read(&paths.stack_outputs).unwrap_or_else(|err| {
        panic!("read cached stack outputs {}: {err}", paths.stack_outputs.display())
    });
    let cached_program_info =
        ProgramInfo::read_from_bytes(&program_info_bytes).unwrap_or_else(|err| {
            panic!("decode cached program info {}: {err}", paths.program_info.display())
        });
    let stack_inputs = StackInputs::read_from_bytes(&stack_inputs_bytes).unwrap_or_else(|err| {
        panic!("decode cached stack inputs {}: {err}", paths.stack_inputs.display())
    });
    let proof = ExecutionProof::from_bytes(&proof_bytes)
        .unwrap_or_else(|err| panic!("decode cached proof {}: {err}", paths.proof.display()));
    let stack_outputs = StackOutputs::read_from_bytes(&stack_outputs_bytes).unwrap_or_else(|err| {
        panic!("decode cached stack outputs {}: {err}", paths.stack_outputs.display())
    });

    assert_eq!(
        proof.hash_fn(),
        hash_fn,
        "cached transaction proof hash does not match requested recursive benchmark hash"
    );
    assert_eq!(
        cached_program_info, program_info,
        "cached transaction proof program does not match this benchmark invocation"
    );
    assert_eq!(
        stack_inputs, expected_stack_inputs,
        "cached transaction proof stack inputs do not match this benchmark invocation"
    );

    TxProofFixture {
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
    }
}

fn save_cached_tx_fixture(dir: &Path, proof_index: usize, fixture: &TxProofFixture) {
    std::fs::create_dir_all(dir)
        .unwrap_or_else(|err| panic!("create proof cache dir {}: {err}", dir.display()));
    let paths = ProofCachePaths::new(dir, proof_index);

    let mut program_info_bytes = Vec::new();
    let mut stack_inputs_bytes = Vec::new();
    let mut stack_outputs_bytes = Vec::new();
    fixture.program_info.write_into(&mut program_info_bytes);
    fixture.stack_inputs.write_into(&mut stack_inputs_bytes);
    fixture.stack_outputs.write_into(&mut stack_outputs_bytes);

    std::fs::write(&paths.program_info, program_info_bytes).unwrap_or_else(|err| {
        panic!("write cached program info {}: {err}", paths.program_info.display())
    });
    std::fs::write(&paths.stack_inputs, stack_inputs_bytes).unwrap_or_else(|err| {
        panic!("write cached stack inputs {}: {err}", paths.stack_inputs.display())
    });
    std::fs::write(&paths.proof, fixture.proof.to_bytes())
        .unwrap_or_else(|err| panic!("write cached proof {}: {err}", paths.proof.display()));
    std::fs::write(&paths.stack_outputs, stack_outputs_bytes).unwrap_or_else(|err| {
        panic!("write cached stack outputs {}: {err}", paths.stack_outputs.display())
    });
}

fn load_tx_fixtures(hash_fn: HashFunction, proof_count: usize) -> Vec<TxProofFixture> {
    let path = masm_path();
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let program = Assembler::default()
        .assemble_program("transaction-fixture", source.as_str())
        .expect("assemble transaction fixture")
        .unwrap_program();
    let program_info = ProgramInfo::from(program.clone());
    let load_dir = proof_cache_load_dir();
    let save_dir = proof_cache_save_dir();

    println!("\n=== transaction proof fixtures\n    masm={} hash={hash_fn:?}", path.display());
    if let Some(dir) = &load_dir {
        println!("    proof_cache_load={}", dir.display());
    }
    if let Some(dir) = &save_dir {
        println!("    proof_cache_save={}", dir.display());
    }

    let mut seen_proofs = HashSet::with_capacity(proof_count);
    (0..proof_count)
        .map(|proof_index| {
            let stack_values = stack_values_for_proof(proof_index);
            let stack_inputs = stack_inputs(&stack_values);
            let fixture = if let Some(dir) = &load_dir {
                load_cached_tx_fixture(
                    dir,
                    program_info.clone(),
                    hash_fn,
                    proof_index,
                    stack_inputs,
                )
            } else {
                let mut host = DefaultHost::default();
                let (stack_outputs, proof) = prove_sync(
                    &program,
                    stack_inputs,
                    AdviceInputs::default(),
                    &mut host,
                    ExecutionOptions::default(),
                    ProvingOptions::new(hash_fn),
                )
                .expect("prove transaction fixture");

                TxProofFixture {
                    program_info: program_info.clone(),
                    stack_inputs,
                    stack_outputs,
                    proof,
                }
            };
            if let Some(dir) = &save_dir {
                save_cached_tx_fixture(dir, proof_index, &fixture);
            }

            let proof = &fixture.proof;
            let proof_bytes = proof.to_bytes();
            assert!(
                seen_proofs.insert(proof_bytes.clone()),
                "recursive benchmark generated duplicate transaction proof at index {proof_index}"
            );

            println!(
                "    proof={} stack={stack_values:?} proof_bytes={} pc_requests={}",
                proof_index,
                proof_bytes.len(),
                proof.precompile_requests().len(),
            );
            println!(
                "BENCH_TX_PROOF index={} stack={:?} proof_bytes={} pc_requests={} proof_prefix={}",
                proof_index,
                stack_values,
                proof_bytes.len(),
                proof.precompile_requests().len(),
                hex_prefix(&proof_bytes),
            );

            fixture
        })
        .collect()
}

fn verifier_call(initial_stack: &[u64]) -> String {
    let mut source = String::new();
    for value in initial_stack.iter().rev() {
        source.push_str(&format!("push.{value}\n"));
    }
    source.push_str("exec.vm::verify_proof\n");
    source
}

fn recursive_program(body: &str) -> Program {
    let source = format!(
        "
        use miden::core::sys::vm

        begin
            {body}
        end
        "
    );

    let core_lib = CoreLibrary::default();
    Assembler::default()
        .with_package(core_lib.package(), Linkage::Static)
        .expect("link core library")
        .assemble_program("recursive-verifier", source.as_str())
        .expect("assemble recursive verifier")
        .unwrap_program()
}

fn recursion_inputs(fixture: &TxProofFixture) -> RecursionInputs {
    let pub_inputs = PublicInputs::new(
        fixture.program_info.clone(),
        fixture.stack_inputs,
        fixture.stack_outputs,
        PrecompileTranscriptState::default(),
    );
    let verifier_inputs =
        generate_advice_inputs(fixture.proof.stark_proof(), pub_inputs).expect("recursive advice");

    let advice_inputs = AdviceInputs::default()
        .with_stack_values(verifier_inputs.advice_stack)
        .expect("recursive advice stack values must be canonical")
        .with_merkle_store(verifier_inputs.store)
        .with_map(verifier_inputs.advice_map);

    RecursionInputs {
        initial_stack: verifier_inputs.initial_stack,
        advice_inputs,
    }
}

fn build_case(fixtures: &[TxProofFixture], proof_count: usize) -> RecursionCase {
    let mut body = String::new();
    let mut advice_inputs = AdviceInputs::default();

    for fixture in fixtures.iter().take(proof_count) {
        let inputs = recursion_inputs(fixture);
        body.push_str(&verifier_call(&inputs.initial_stack));
        advice_inputs.extend(inputs.advice_inputs);
    }

    RecursionCase {
        proof_count,
        program: recursive_program(&body),
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
    let proof = prove_recursive(&case.program, case.advice_inputs, hash_fn, &mut host);
    black_box(proof);
}

fn prove_recursive(
    program: &Program,
    advice_inputs: AdviceInputs,
    hash_fn: HashFunction,
    host: &mut DefaultHost,
) -> ExecutionProof {
    let (_, proof) = prove_sync(
        program,
        StackInputs::default(),
        advice_inputs,
        host,
        ExecutionOptions::default(),
        ProvingOptions::new(hash_fn),
    )
    .expect("prove recursive verifier");
    proof
}

fn prove_recursive_once(case: &RecursionCase, hash_fn: HashFunction) -> (f64, usize) {
    let advice_inputs = case.advice_inputs.clone();
    let start = Instant::now();
    let mut host = recursive_host();
    let proof = prove_recursive(&case.program, advice_inputs, hash_fn, &mut host);
    let elapsed_ms = start.elapsed().as_secs_f64() * 1_000.0;
    let proof_bytes = proof.to_bytes().len();
    black_box(proof);
    (elapsed_ms, proof_bytes)
}

fn profile_prove_once(case: RecursionCase, hash_fn: HashFunction) {
    let (elapsed_ms, proof_bytes) = prove_recursive_once(&case, hash_fn);
    eprintln!(
        "recursive_profile prove_once/{} proofs: {:.3} ms proof_bytes={}",
        case.proof_count, elapsed_ms, proof_bytes,
    );
    println!(
        "BENCH_RECURSION_PROOF proofs={} prove_ms={:.3} proof_bytes={}",
        case.proof_count, elapsed_ms, proof_bytes,
    );
}

fn profile_prove_repeated(
    case: &RecursionCase,
    hash_fn: HashFunction,
    warmups: usize,
    runs: usize,
) {
    for warmup_idx in 1..=warmups {
        let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
        eprintln!(
            "recursive_profile warmup {warmup_idx}/{warmups}/{} proofs: {:.3} ms proof_bytes={}",
            case.proof_count, elapsed_ms, proof_bytes,
        );
    }

    for run_idx in 1..=runs {
        let (elapsed_ms, proof_bytes) = prove_recursive_once(case, hash_fn);
        eprintln!(
            "recursive_profile run {run_idx}/{runs}/{} proofs: {:.3} ms proof_bytes={}",
            case.proof_count, elapsed_ms, proof_bytes,
        );
        println!(
            "BENCH_RECURSION_PROOF proofs={} run={} prove_ms={:.3} proof_bytes={}",
            case.proof_count, run_idx, elapsed_ms, proof_bytes,
        );
    }
}

fn print_case_shape(case: &RecursionCase) {
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
    let chiplets = summary.chiplets();
    let max_trace_rows = summary
        .core_rows()
        .max(summary.chiplets_rows())
        .max(summary.blakeg_compression_rows())
        .max(summary.byte_pair_lookup_rows());
    let max_padded_rows = summary
        .core_height()
        .max(summary.chiplets_height())
        .max(summary.blakeg_compression_height())
        .max(summary.byte_pair_lookup_rows());

    println!(
        "    proofs={} core={} range={} chiplets={} hash_ctrl={} max_trace={} max_padded={}",
        case.proof_count,
        summary.core_rows(),
        0,
        chiplets.trace_len(),
        chiplets.hash_chiplet_len(),
        max_trace_rows,
        max_padded_rows,
    );
    println!(
        concat!(
            "BENCH_RECURSION_SHAPE proofs={} ",
            "core_rows={} range_rows={} chiplets_rows={} ",
            "hash_chiplet_rows={} bitwise_rows={} memory_rows={} ace_rows={} kernel_rows={} ",
            "native_hash_rows={} and8_lookup_rows={} max_trace_rows={} max_padded_rows={}"
        ),
        case.proof_count,
        summary.core_rows(),
        0,
        chiplets.trace_len(),
        chiplets.hash_chiplet_len(),
        chiplets.bitwise_chiplet_len(),
        chiplets.memory_chiplet_len(),
        chiplets.ace_chiplet_len(),
        chiplets.kernel_rom_len(),
        summary.blakeg_compression_rows(),
        summary.byte_pair_lookup_rows(),
        max_trace_rows,
        max_padded_rows,
    );
}

fn bench_recursive_verify(c: &mut Criterion) {
    let hash_fn = bench_hash();
    let proof_counts = proof_counts();
    let max_proof_count = proof_counts.iter().copied().max().expect("missing proof counts");
    let fixtures = load_tx_fixtures(hash_fn, max_proof_count);
    let cases = proof_counts
        .into_iter()
        .map(|proof_count| build_case(&fixtures, proof_count))
        .collect::<Vec<_>>();

    println!("\n=== recursive verifier trace shapes");
    for case in &cases {
        print_case_shape(case);
    }
    if std::env::var_os("RECURSION_PROFILE_ONLY").is_some() {
        return;
    }
    if std::env::var_os("RECURSION_PROFILE_PROVE").is_some()
        || std::env::var_os("RECURSION_PROFILE_PROVE_ONCE").is_some()
    {
        let runs = env_usize("RECURSION_PROFILE_PROVE_REPEATS", 1);
        let warmups = env_usize("RECURSION_PROFILE_PROVE_WARMUPS", 0);
        for case in &cases {
            if runs == 1 && warmups == 0 {
                profile_prove_once(case.clone(), hash_fn);
            } else {
                profile_prove_repeated(case, hash_fn, warmups, runs);
            }
        }
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
                || (case.clone(), recursive_host(), hash_fn),
                prove_recursive_case,
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

criterion_group!(benches, bench_recursive_verify);
criterion_main!(benches);
