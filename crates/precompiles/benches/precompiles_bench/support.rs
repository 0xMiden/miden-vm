use miden_core::{Felt, program::ExecutionClaim};
use miden_core_lib::CoreLibrary;
use miden_vm::{
    Assembler, DefaultHost, ExecutionOptions, ExecutionProof, FastProcessor, HashFunction, Program,
    Prover, StackInputs, StackOutputs, Verifier, advice::AdviceInputs,
};

use self::input_generation::generate_advice_inputs;

#[path = "input_generation.rs"]
pub mod input_generation;
pub use input_generation::{
    DEFAULT_ECDSA_P256S, DEFAULT_ECDSAS, DEFAULT_EDDSAS, DEFAULT_KECCAKS, DEFAULT_SHA256_1KIB,
    DEFAULT_SHA256_64B, PrecompileWorkload,
};

#[derive(Clone)]
pub struct PrecompileFixture {
    pub program: Program,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
}

impl PrecompileFixture {
    pub fn generate(workload: PrecompileWorkload) -> Self {
        let source = generate_program_source(workload);
        let core_lib = CoreLibrary::default();
        let program = Assembler::default()
            .with_package(core_lib.package(), miden_vm::assembly::Linkage::Dynamic)
            .expect("failed to link core library")
            .assemble_program("precompile_workload", source.as_str())
            .expect("failed to assemble precompile benchmark program")
            .unwrap_program();

        Self {
            program,
            stack_inputs: generate_stack_inputs(workload),
            advice_inputs: generate_advice_inputs(workload),
        }
    }
}

fn generate_stack_inputs(workload: PrecompileWorkload) -> StackInputs {
    assert!(u32::try_from(workload.keccaks).is_ok(), "Keccak workload count must fit in u32");
    StackInputs::new(&[Felt::new_unchecked(workload.keccaks as u64)])
        .expect("single Keccak count should fit on the operand stack")
}

/// Word-aligned scratch addresses for the fixed-size SHA-256 message buffers. The two sizes never
/// overlap, and each buffer is fully overwritten by its own adv_pipe chunks on every iteration.
const SHA256_64B_MEM_PTR: u32 = 4096;
const SHA256_1KIB_MEM_PTR: u32 = 8192;

fn generate_program_source(workload: PrecompileWorkload) -> String {
    format!(
        r#"use miden::core::crypto::dsa::ecdsa_k256_keccak
use miden::core::crypto::dsa::ecdsa_p256_sha256
use miden::core::crypto::dsa::eddsa_25519_sha512
use miden::core::crypto::hashes::keccak256
use miden::core::precompiles::hashes::sha256

begin
    # Input: [num_keccaks]
    # Hash the same rolling 8-limb state recursively.
    padw padw
    # => [STATE_U32[8], num_keccaks]
    dup.8 neq.0
    while.true
        # => [STATE_U32[8], num_keccaks_left]
        exec.keccak256::hash
        # => [NEXT_STATE_U32[8], num_keccaks_left]
        movup.8 sub.1 movdn.8
        # => [NEXT_STATE_U32[8], num_keccaks_left - 1]
        dup.8 neq.0
    end
    dropw dropw drop

    # ECDSA fixtures stay in advice because generating valid signatures is host-side work.
    repeat.{ecdsas}
        padw adv_loadw
        padw adv_loadw
        exec.ecdsa_k256_keccak::verify
    end
    repeat.{eddsas}
        padw adv_loadw
        padw adv_loadw
        exec.eddsa_25519_sha512::verify
    end
    repeat.{ecdsa_p256s}
        padw adv_loadw
        padw adv_loadw
        exec.ecdsa_p256_sha256::verify
    end

    # SHA-256 fixtures pipe their message bytes from advice into a fixed scratch buffer; the
    # precompile's event handler supplies the digest by hashing that buffer.
    repeat.{sha256_64bs}
        push.{sha256_64b_ptr}
        repeat.2
            padw padw padw adv_pipe dropw dropw dropw
        end
        drop
        push.{sha256_64b_ptr} push.64 push.{sha256_64b_ptr}
        exec.sha256::hash_bytes_mem
    end
    repeat.{sha256_1kibs}
        push.{sha256_1kib_ptr}
        repeat.32
            padw padw padw adv_pipe dropw dropw dropw
        end
        drop
        push.{sha256_1kib_ptr} push.1024 push.{sha256_1kib_ptr}
        exec.sha256::hash_bytes_mem
    end
end
"#,
        ecdsas = workload.ecdsas,
        eddsas = workload.eddsas,
        ecdsa_p256s = workload.ecdsa_p256s,
        sha256_64bs = workload.sha256_64b,
        sha256_1kibs = workload.sha256_1kib,
        sha256_64b_ptr = SHA256_64B_MEM_PTR,
        sha256_1kib_ptr = SHA256_1KIB_MEM_PTR,
    )
}

pub fn execution_options() -> ExecutionOptions {
    ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .expect("precompile benchmark execution options should be valid")
}

pub fn prove_once_with_hash(
    fixture: &PrecompileFixture,
    hash_fn: HashFunction,
) -> (StackOutputs, ExecutionProof) {
    let mut host = DefaultHost::default()
        .with_library(&CoreLibrary::default())
        .expect("failed to load core library into host");
    let witness = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        execution_options(),
    )
    .expect("failed to initialize precompile benchmark processor")
    .execute_for_proving_sync(&fixture.program, &mut host)
    .expect("failed to execute precompile benchmark");
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new()
        .with_hash_fn(hash_fn)
        .prove_full(witness)
        .expect("failed to prove precompile benchmark");
    (stack_outputs, proof)
}

pub fn verify_once(
    fixture: &PrecompileFixture,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) {
    let claim = ExecutionClaim::from_program_info(
        fixture.program.to_info(),
        fixture.stack_inputs,
        stack_outputs,
    );
    let outcome = Verifier::new()
        .verify(&claim, &proof)
        .expect("failed to verify precompile benchmark proof");
    assert!(outcome.is_complete(), "prove_full must settle all precompile work");
}
