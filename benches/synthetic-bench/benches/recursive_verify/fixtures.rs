//! Cached transaction and PVM proof fixtures consumed by recursive benchmark cases.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use miden_assembly::Linkage;
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    crypto::hash::Blake3_256,
    deferred::DeferredState,
    field::QuotientMap,
    program::ExecutionClaim,
    proof::PrecompileProof,
    serde::{Deserializable, Serializable},
    utils::to_hex,
};
use miden_core_lib::CoreLibrary;
use miden_precompiles_verifier::masm_verifier::PvmRecursiveVerifierInputs;
use miden_processor::{ExecutionOptions, FastProcessor};
use miden_verifier::{Verifier, recursive::RecursiveVerifierInputs};
use miden_vm::{
    Assembler, ExecutionProof, HashFunction, PrecompileWitness, ProgramInfo, Prover, StackInputs,
    StackOutputs, internal::InputFile, prove_sync, trace::build_trace,
};

use super::{
    config::{BenchConfig, workspace_root},
    measurements::print_bench_shape,
    recursive_host,
};

const TX_PROOF_CACHE_KEY_VERSION: &[u8] = b"miden-synthetic-recursive-tx-proof-cache-v2";
const PVM_PROOF_CACHE_KEY_VERSION: &[u8] = b"miden-synthetic-recursive-pvm-proof-cache-v3";
const INNER_PROOF_HASH: HashFunction = HashFunction::Poseidon2;
const PVM_WORKLOAD_CONTENT_DIGEST: [u8; 32] = [
    0x60, 0xf6, 0xb0, 0x95, 0xf9, 0xd0, 0xae, 0x76, 0xd1, 0xaf, 0xf3, 0x18, 0x9b, 0xca, 0x21, 0x2d,
    0x6b, 0xcd, 0xda, 0xe9, 0x33, 0x55, 0x1c, 0x26, 0x76, 0x67, 0x02, 0xa4, 0xc0, 0x95, 0xcd, 0x28,
];

pub(super) struct TxProofFixture {
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
}

pub(super) struct RecursiveProofAdvice {
    pub(super) claim_commitment: Word,
    pub(super) advice_inputs: AdviceInputs,
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
    program_info: &ProgramInfo,
    stack_inputs: StackInputs,
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
    let proof = match ExecutionProof::read_from_bytes(&proof_bytes) {
        Ok(proof) => proof,
        Err(err) => {
            eprintln!("ignoring undecodable cached proof {}: {err}", proof_path.display());
            return None;
        },
    };
    let vm_proof = match &proof {
        ExecutionProof::Complete { vm, precompile: None } => vm,
        ExecutionProof::Complete { precompile: Some(_), .. } | ExecutionProof::Deferred { .. } => {
            eprintln!(
                "ignoring cached transaction proof with precompile data {}",
                proof_path.display()
            );
            return None;
        },
    };
    if vm_proof.proof.hash_fn() != hash_fn {
        eprintln!(
            "ignoring cached transaction proof with the wrong hash function {}",
            proof_path.display()
        );
        return None;
    }

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

    let claim =
        ExecutionClaim::from_program_info(program_info.clone(), stack_inputs, stack_outputs);
    if let Err(err) = Verifier::new().verify(&claim, &proof) {
        eprintln!("ignoring invalid cached transaction proof {}: {err}", proof_path.display());
        return None;
    }

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

fn canonical_pvm_workload_path() -> PathBuf {
    workspace_root()
        .join("miden-vm/masm-examples/precompiles/deferred_ecdsa4_keccak100")
        .join("deferred_ecdsa4_keccak100.masm")
}

fn pvm_proof_cache_key(workload_path: &Path) -> String {
    let workload_source = std::fs::read(workload_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", workload_path.display()));
    let inputs_path = workload_path.with_extension("inputs");
    let workload_inputs = std::fs::read(&inputs_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", inputs_path.display()));
    let content_digest: [u8; 32] =
        Blake3_256::hash_iter([workload_source.as_slice(), workload_inputs.as_slice()].into_iter())
            .into();
    assert_eq!(
        content_digest, PVM_WORKLOAD_CONTENT_DIGEST,
        "canonical PVM benchmark workload changed; review its 100-Keccak/4-ECDSA identity before \
         updating PVM_WORKLOAD_CONTENT_DIGEST",
    );
    let digest: [u8; 32] = Blake3_256::hash_iter(
        [
            PVM_PROOF_CACHE_KEY_VERSION,
            env!("CARGO_PKG_VERSION").as_bytes(),
            workload_source.as_slice(),
            workload_inputs.as_slice(),
        ]
        .into_iter(),
    )
    .into();
    to_hex(digest)
}

fn pvm_proof_cache_path(cache_dir: &Path, cache_key: &str) -> PathBuf {
    cache_dir.join(format!("pvm-{cache_key}.bin"))
}

fn load_cached_pvm_proof(
    cache_dir: &Path,
    cache_key: &str,
    expected_root: Word,
) -> Option<PrecompileProof> {
    let path = pvm_proof_cache_path(cache_dir, cache_key);
    if !path.is_file() {
        return None;
    }

    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("ignoring unreadable cached PVM proof {}: {err}", path.display());
            return None;
        },
    };
    let proof = match PrecompileProof::read_from_bytes(&bytes) {
        Ok(proof) if proof.to_bytes() == bytes => proof,
        Ok(_) => {
            eprintln!("ignoring non-canonical cached PVM proof {}", path.display());
            return None;
        },
        Err(err) => {
            eprintln!("ignoring undecodable cached PVM proof {}: {err}", path.display());
            return None;
        },
    };
    if proof.proof.hash_fn() != HashFunction::Poseidon2 {
        eprintln!("ignoring cached PVM proof with the wrong hash function {}", path.display());
        return None;
    }
    if proof.roots.as_slice() != [expected_root] {
        eprintln!("ignoring cached PVM proof for a stale deferred root {}", path.display());
        return None;
    }
    if let Err(err) = Verifier::new().verify_precompile(&proof, expected_root) {
        eprintln!("ignoring stale or invalid cached PVM proof {}: {err}", path.display());
        return None;
    }

    Some(proof)
}

fn store_cached_pvm_proof(cache_dir: &Path, cache_key: &str, proof: &PrecompileProof) {
    std::fs::create_dir_all(cache_dir)
        .unwrap_or_else(|err| panic!("create proof cache {}: {err}", cache_dir.display()));
    let path = pvm_proof_cache_path(cache_dir, cache_key);
    std::fs::write(&path, proof.to_bytes())
        .unwrap_or_else(|err| panic!("write cached PVM proof {}: {err}", path.display()));
}

fn execute_pvm_workload(workload_path: &Path) -> DeferredState {
    let source = std::fs::read_to_string(workload_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", workload_path.display()));
    let input_file = InputFile::read(&None, workload_path)
        .unwrap_or_else(|err| panic!("read {} inputs: {err}", workload_path.display()));
    let stack_values = input_file
        .operand_stack
        .iter()
        .map(|value| {
            value.parse::<u64>().unwrap_or_else(|_| {
                panic!("PVM workload operand stack value must be a u64: {value}")
            })
        })
        .collect::<Vec<_>>();
    let stack_inputs = stack_inputs(&stack_values);
    let advice_inputs = input_file
        .parse_advice_inputs()
        .unwrap_or_else(|err| panic!("parse {} inputs: {err}", workload_path.display()));
    let core_lib = CoreLibrary::default();
    let program = Assembler::default()
        .with_package(core_lib.package(), Linkage::Dynamic)
        .expect("link core library")
        .assemble_program("pvm_workload", source.as_str())
        .expect("assemble canonical PVM workload")
        .unwrap_program();
    let mut host = recursive_host();

    let output =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("construct processor for canonical PVM workload")
            .execute_sync(&program, &mut host)
            .expect("execute canonical PVM workload");
    output.deferred_state
}

fn generate_pvm_proof(deferred_state: &DeferredState) -> PrecompileProof {
    eprintln!("proving canonical deferred state with Poseidon2...");
    let witness = PrecompileWitness::new(deferred_state.clone())
        .expect("canonical workload must produce a precompile witness");
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Poseidon2)
        .prove_precompile(&witness)
        .expect("prove canonical deferred state");
    Verifier::new()
        .verify_precompile(&proof, deferred_state.root())
        .expect("verify generated PVM proof natively");
    proof
}

fn load_pvm_proof(config: &BenchConfig) -> PrecompileProof {
    let workload_path = canonical_pvm_workload_path();
    let cache_key = pvm_proof_cache_key(&workload_path);
    eprintln!("executing canonical 100-Keccak/4-ECDSA workload...");
    let deferred_state = execute_pvm_workload(&workload_path);
    let cached = config.pvm_proof_cache_dir().and_then(|cache_dir| {
        load_cached_pvm_proof(cache_dir, cache_key.as_str(), deferred_state.root())
    });
    let (proof, cache_status) = if let Some(proof) = cached {
        (proof, "hit")
    } else {
        let proof = generate_pvm_proof(&deferred_state);
        if let Some(cache_dir) = config.pvm_proof_cache_dir() {
            store_cached_pvm_proof(cache_dir, cache_key.as_str(), &proof);
        }
        (
            proof,
            if config.pvm_proof_cache_dir().is_some() {
                "miss"
            } else {
                "disabled"
            },
        )
    };

    let proof_bytes = proof.proof.bytes();
    let proof_digest: [u8; 32] = Blake3_256::hash(proof_bytes).into();
    println!(
        "\n=== PVM proof fixture\n    workload={} proof_bytes={} proof_cache={}",
        workload_path.display(),
        proof_bytes.len(),
        cache_status,
    );
    println!(
        "BENCH_PVM_PROOF workload=100_keccak_4_ecdsa proof_bytes={} proof_cache={} \
         proof_digest={} proof_prefix={}",
        proof_bytes.len(),
        cache_status,
        to_hex(proof_digest),
        hex_prefix(proof_bytes),
    );
    proof
}

fn hex_prefix(bytes: &[u8]) -> String {
    to_hex(&bytes[..bytes.len().min(16)])
}

fn print_tx_fixture_shape(
    program: &miden_vm::Program,
    stack_inputs: StackInputs,
    advice_inputs: AdviceInputs,
    proof_index: usize,
) {
    let processor =
        FastProcessor::new_with_options(stack_inputs, advice_inputs, ExecutionOptions::default())
            .expect("transaction fixture advice should fit provider limits");
    let mut host = recursive_host();
    let witness = processor
        .execute_for_proving_sync(program, &mut host)
        .expect("execute transaction fixture");
    let (vm_witness, _) = witness.into_parts();
    let trace = build_trace(vm_witness).expect("build transaction fixture trace");
    let summary = trace.trace_len_summary();
    let record = format!("BENCH_TX_SHAPE index={proof_index}");
    print_bench_shape(&record, summary);
}

pub(super) fn load_tx_fixtures(config: &BenchConfig, proof_count: usize) -> Vec<TxProofFixture> {
    let source = std::fs::read_to_string(config.tx_masm_path())
        .unwrap_or_else(|err| panic!("read {}: {err}", config.tx_masm_path().display()));
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
        config.tx_masm_path().display(),
        INNER_PROOF_HASH,
        config
            .tx_proof_cache_dir()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "disabled".to_string()),
    );

    let mut seen_proofs = HashSet::with_capacity(proof_count);
    (0..proof_count)
        .map(|proof_index| {
            let stack_values = config.stack_values_for_proof(proof_index);
            let stack_inputs = stack_inputs(&stack_values);
            let advice_inputs = AdviceInputs::default();
            let proof_cache_key =
                tx_proof_cache_key(&program_info, &stack_values, INNER_PROOF_HASH);
            print_tx_fixture_shape(&program, stack_inputs, advice_inputs.clone(), proof_index);

            let (stack_outputs, proof, proof_cache_status) = if let Some((stack_outputs, proof)) =
                config.tx_proof_cache_dir().and_then(|cache_dir| {
                    load_cached_tx_proof(
                        cache_dir,
                        proof_index,
                        proof_cache_key.as_str(),
                        INNER_PROOF_HASH,
                        &program_info,
                        stack_inputs,
                    )
                }) {
                (stack_outputs, proof, "hit")
            } else {
                let mut host = recursive_host();
                let (stack_outputs, proof) = prove_sync(
                    &Prover::new().with_hash_fn(INNER_PROOF_HASH),
                    &program,
                    stack_inputs,
                    advice_inputs,
                    &mut host,
                    ExecutionOptions::default(),
                )
                .expect("prove transaction fixture");
                if let Some(cache_dir) = config.tx_proof_cache_dir() {
                    store_cached_tx_proof(
                        cache_dir,
                        proof_index,
                        proof_cache_key.as_str(),
                        &stack_outputs,
                        &proof,
                    );
                }
                // Preserve the existing machine-output schema: an absent cache is reported as a
                // miss because a proof was generated during this run.
                (stack_outputs, proof, "miss")
            };
            assert!(
                matches!(&proof, ExecutionProof::Complete { precompile: None, .. }),
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
                 deferred_entries=0",
            );
            println!(
                "BENCH_TX_PROOF index={proof_index} stack={stack_values:?} \
                 proof_bytes={proof_bytes_len} deferred_entries=0 \
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

pub(super) fn recursive_proof_advice(
    fixture: &TxProofFixture,
    verifier_root: Word,
) -> RecursiveProofAdvice {
    let claim = ExecutionClaim::from_program_info(
        fixture.program_info.clone(),
        fixture.stack_inputs,
        fixture.stack_outputs,
    );
    let (advice_inputs, claim_commitment) =
        RecursiveVerifierInputs::for_request(verifier_root, &fixture.proof, &claim)
            .expect("build MVM recursive request package")
            .into_parts();

    RecursiveProofAdvice { claim_commitment, advice_inputs }
}

pub(super) fn load_pvm_advice(config: &BenchConfig) -> RecursiveProofAdvice {
    let proof = load_pvm_proof(config);
    let verifier_root = CoreLibrary::default().pvm_recursive_verifier_root();
    let inputs = PvmRecursiveVerifierInputs::for_request(verifier_root, &proof)
        .expect("build PVM recursive advice");
    let (advice_inputs, claim_commitment) = inputs.into_parts();

    RecursiveProofAdvice { claim_commitment, advice_inputs }
}
