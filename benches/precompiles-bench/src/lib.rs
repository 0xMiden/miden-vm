//! Reproducible precompile workloads shared by PVM and recursive benchmarks.

use miden_core::{Felt, Word, deferred::PrecompileWitness, program::ExecutionClaim};
use miden_core_lib::CoreLibrary;
use miden_vm::{
    Assembler, DefaultHost, ExecutionOptions, ExecutionProof, FastProcessor, HashFunction,
    PrecompileLimits, Program, Prover, StackInputs, StackOutputs, Verifier, advice::AdviceInputs,
    default_execution_precompile_limits, default_verification_precompile_limits,
};

use self::input_generation::generate_advice_inputs;

mod input_generation;
pub use input_generation::PrecompileWorkload;

pub struct PrecompileFixture {
    pub program: Program,
    pub stack_inputs: StackInputs,
    pub advice_inputs: AdviceInputs,
    /// Admission limits for exporting and proving this fixture's deferred witness.
    pub verification_limits: PrecompileLimits,
    execution_options: ExecutionOptions,
}

impl PrecompileFixture {
    pub fn generate(workload: PrecompileWorkload) -> Self {
        let verification_limits = workload.limits(default_verification_precompile_limits());
        let execution_options = execution_options()
            .with_execution_precompile_limits(
                workload.limits(default_execution_precompile_limits()),
            )
            .with_verification_precompile_limits(verification_limits.clone());
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
            verification_limits,
            execution_options,
        }
    }

    /// Executes the fixture and returns its portable deferred witness and execution root.
    pub fn precompile_witness(&self) -> (PrecompileWitness, Word) {
        let mut host = DefaultHost::default()
            .with_library(&CoreLibrary::default())
            .expect("load precompile workload library");
        let output = FastProcessor::new_with_options(
            self.stack_inputs,
            self.advice_inputs.clone(),
            self.execution_options.clone(),
        )
        .expect("construct precompile workload processor")
        .execute_sync(&self.program, &mut host)
        .expect("execute precompile workload");
        let root = output.precompile_root();
        let witness = output.precompile_witness.expect("workload must authenticate deferred work");
        (witness, root)
    }
}

fn generate_stack_inputs(workload: PrecompileWorkload) -> StackInputs {
    assert!(u32::try_from(workload.keccaks).is_ok(), "Keccak workload count must fit in u32");
    StackInputs::new(&[Felt::new_unchecked(workload.keccaks as u64)])
        .expect("single Keccak count should fit on the operand stack")
}

// Word-aligned scratch buffers, fully overwritten by advice before each message is hashed.
const SHA256_64B_MEM_PTR: u32 = 4096;
const SHA256_1KIB_MEM_PTR: u32 = 8192;

fn generate_program_source(workload: PrecompileWorkload) -> String {
    use std::fmt::Write;

    let mut source = String::from(
        r#"use miden::core::crypto::dsa::ecdsa_k256_keccak
        use miden::core::crypto::dsa::ecdsa_p256_sha256
        use miden::core::crypto::dsa::eddsa_25519_sha512
        use miden::core::crypto::hashes::keccak256
        use miden::core::precompiles::hashes::sha256
        begin
            # Keep the rolling Keccak state above the remaining call count.
            padw padw
            dup.8 neq.0
            while.true
                exec.keccak256::hash
                movup.8 sub.1 movdn.8
                dup.8 neq.0
            end
            dropw dropw drop
"#,
    );
    for (count, procedure) in [
        (workload.ecdsas, "ecdsa_k256_keccak"),
        (workload.eddsas, "eddsa_25519_sha512"),
        (workload.ecdsa_p256s, "ecdsa_p256_sha256"),
    ] {
        if count != 0 {
            writeln!(
                source,
                "repeat.{count} padw adv_loadw padw adv_loadw exec.{procedure}::verify end"
            )
            .expect("write signature workload");
        }
    }
    for (count, len, ptr) in [
        (workload.sha256_64b, 64, SHA256_64B_MEM_PTR),
        (workload.sha256_1kib, 1024, SHA256_1KIB_MEM_PTR),
    ] {
        if count != 0 {
            let chunks = len / 32;
            writeln!(
                source,
                "repeat.{count}
                    push.{ptr}
                    repeat.{chunks} padw padw padw adv_pipe dropw dropw dropw end
                    drop
                    push.{ptr} push.{len} push.{ptr}
                    exec.sha256::hash_bytes_mem
                 end",
            )
            .expect("write SHA-256 workload");
        }
    }
    source.push_str("end\n");
    source
}

fn execution_options() -> ExecutionOptions {
    ExecutionOptions::new(
        Some(ExecutionOptions::MAX_CYCLES),
        64,
        ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
    )
    .expect("precompile benchmark execution options should be valid")
}

pub fn prove_once(fixture: &PrecompileFixture) -> (StackOutputs, ExecutionProof) {
    let mut host = DefaultHost::default()
        .with_library(&CoreLibrary::default())
        .expect("failed to load core library into host");
    let witness = FastProcessor::new_with_options(
        fixture.stack_inputs,
        fixture.advice_inputs.clone(),
        fixture.execution_options.clone(),
    )
    .expect("failed to initialize precompile benchmark processor")
    .execute_for_proving_sync(&fixture.program, &mut host)
    .expect("failed to execute precompile benchmark");
    let stack_outputs = *witness.claim().stack_outputs();
    let proof = Prover::new()
        .with_hash_fn(HashFunction::Eidos)
        .with_verification_precompile_limits(fixture.verification_limits.clone())
        .prove_full(witness)
        .expect("failed to prove precompile benchmark");
    (stack_outputs, proof)
}

pub fn verify_once(
    fixture: &PrecompileFixture,
    stack_outputs: StackOutputs,
    proof: &ExecutionProof,
) {
    let claim = ExecutionClaim::from_program_info(
        fixture.program.to_info(),
        fixture.stack_inputs,
        stack_outputs,
    );
    let outcome = Verifier::new()
        .verify(&claim, proof)
        .expect("failed to verify precompile benchmark proof");
    assert!(outcome.is_complete(), "prove_full must settle all precompile work");
}

/// Default precompile workloads, including their combined workload.
pub fn benchmark_workloads() -> [(&'static str, PrecompileWorkload); 7] {
    let mixed = PrecompileWorkload::default();
    let empty = PrecompileWorkload {
        keccaks: 0,
        ecdsas: 0,
        eddsas: 0,
        ecdsa_p256s: 0,
        sha256_64b: 0,
        sha256_1kib: 0,
    };
    [
        ("keccak", PrecompileWorkload { keccaks: mixed.keccaks, ..empty }),
        ("ecdsa_k256", PrecompileWorkload { ecdsas: mixed.ecdsas, ..empty }),
        ("eddsa_25519", PrecompileWorkload { eddsas: mixed.eddsas, ..empty }),
        ("ecdsa_p256", PrecompileWorkload { ecdsa_p256s: mixed.ecdsa_p256s, ..empty }),
        ("sha256_64b", PrecompileWorkload { sha256_64b: mixed.sha256_64b, ..empty }),
        ("sha256_1kib", PrecompileWorkload { sha256_1kib: mixed.sha256_1kib, ..empty }),
        ("mixed", mixed),
    ]
}

#[cfg(test)]
mod tests {
    use miden_core::program::domain::Keccak256PrecompileDomain;
    use miden_crypto::hash::eidos::EidosDomain;
    use miden_vm::PrecompileWitnessEntry;

    use super::*;

    #[test]
    fn workloads_preserve_keccak_counts_and_lengths() {
        let custom = PrecompileWorkload {
            keccaks: 300,
            ecdsas: 2,
            eddsas: 0,
            ecdsa_p256s: 0,
            sha256_64b: 0,
            sha256_1kib: 0,
        };
        for (name, workload) in benchmark_workloads().into_iter().chain([("custom", custom)]) {
            let fixture = PrecompileFixture::generate(workload);
            let (witness, _) = fixture.precompile_witness();
            assert!(!witness.entries().is_empty(), "{name} has no deferred work");

            let mut keccaks = 0;
            for entry in witness.entries() {
                let frame = match entry {
                    PrecompileWitnessEntry::Data { frame, .. }
                    | PrecompileWitnessEntry::Join { frame, .. }
                    | PrecompileWitnessEntry::PairList { frame, .. } => frame,
                };
                if frame.domain() == Keccak256PrecompileDomain::TAG {
                    assert_eq!(frame.params()[1], 32, "{name} Keccak inputs must be 32 bytes");
                    keccaks += 1;
                }
            }
            assert_eq!(
                keccaks,
                workload.keccaks + workload.ecdsas,
                "{name} must include the requested Keccaks and one prehash per ECDSA",
            );
            miden_precompile_stark::prover::testing::import(
                vec![witness],
                &fixture.verification_limits,
            )
            .unwrap_or_else(|error| panic!("{name} witness import failed: {error}"));
        }
    }
}
