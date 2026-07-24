//! Integration tests for the prove/verify flow with different hash functions.

use alloc::sync::Arc;

use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{program::ExecutionClaim, proof::ExecutionProof};
use miden_core_lib::CoreLibrary;
use miden_processor::ExecutionOptions;
use miden_prover::{
    AdviceInputs, ProgramInfo, ProvingOptions, StackInputs, StackOutputs, prove_sync,
};
use miden_utils_testing::{recursive_verifier::generate_advice_inputs, stack_inputs_from_ints};
use miden_verifier::{VerificationError, settle, verify, verify_unsettled};
use miden_vm::{DefaultHost, HashFunction};

fn assert_prove_verify(
    source: &str,
    hash_fn: HashFunction,
    hash_name: &str,
    print_stack_outputs: bool,
    verify_recursively: bool,
) {
    let program = Assembler::default()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();
    let stack_inputs = stack_inputs_from_ints([0, 1]);
    let advice_inputs = AdviceInputs::default();
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    let options = ProvingOptions::with_96_bit_security(hash_fn);

    println!("Proving with {hash_name}...");
    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .expect("Proving failed");

    println!("Proof generated successfully!");
    if print_stack_outputs {
        println!("Stack outputs: {stack_outputs:?}");
    }

    if verify_recursively {
        assert_recursive_verify(program.to_info(), stack_inputs, stack_outputs, &proof);
    }

    println!("Verifying proof...");
    let claim = ExecutionClaim::new(program.into(), stack_inputs, stack_outputs);
    let security_level = verify(proof, claim).expect("Verification failed");

    println!("Verification successful! Security level: {security_level}");
}

fn assert_recursive_verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: &ExecutionProof,
) {
    let claim = ExecutionClaim::new(program_info, stack_inputs, stack_outputs);
    let verifier_inputs = generate_advice_inputs(proof, &claim)
        .expect("recursive verifier advice construction failed");

    let source = "
        use miden::core::sys
        use miden::core::sys::vm

        # Copy `count` felts (a multiple of 4) from the advice tape into memory starting at `dst`.
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
                # [dst+4, count, ...]
                swap sub.4 swap
                # [dst+4, count-4, ...]
                dup.1 push.0 neq
            end
            drop drop
        end

        begin
            # Initial stack: [claim_ptr, kernel_ptr, num_kernel_digests].

            # Copy kernel digests (4·num_kernel_digests felts) from advice into the witness
            # region (kernel_ptr = 0).
            dup.2 mul.4 push.0
            exec.copy_advice_to_mem

            # Copy the program digest into the claim region (claim_ptr = 4096), then the
            # stack i/o (32 felts) into its I/O section (+8).
            push.4 push.4096
            exec.copy_advice_to_mem
            push.32 push.4104
            exec.copy_advice_to_mem

            exec.vm::verify_vm_proof
            # => [D] — keep the obligation as the program's output; truncate the residue.
            exec.sys::truncate_stack
        end
    ";

    let mut test = crate::build_test!(
        source,
        &verifier_inputs.initial_stack,
        &verifier_inputs.advice_stack(),
        verifier_inputs.store,
        verifier_inputs.advice_map
    );
    test.libraries.push(CoreLibrary::default().package());
    test.execute().expect("recursive verifier execution failed");
}

#[test]
fn test_blake3_256_prove_verify() {
    // Compute many Fibonacci iterations to generate a trace >= 2048 rows
    let source = "
        begin
            repeat.1000
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3_256", false, false);
}

#[test]
fn test_keccak_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Keccak, "Keccak", true, false);
}

#[test]
fn test_rpo_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpo256, "RPO", true, false);
}

#[test]
fn test_poseidon2_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true, true);
}

/// Sanity test that the multi-AIR Rust prover + Rust verifier work end-to-end with Poseidon2,
/// independent of the MASM recursive verifier path.
#[test]
fn test_poseidon2_prove_verify_rust_only() {
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", true, false);
}

/// Equal-heights regression: tiny program where every AIR lands at MIN_TRACE_LEN.
/// Catches mistakes in the MASM `air_order` reconstruction's tie-break rule.
#[test]
fn test_equal_heights_recursive() {
    let source = "
        begin
            push.1 drop
        end
    ";
    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", false, true);
}

/// Hash-heavy program where chiplets grow beyond the core trace. Regression for per-AIR-height
/// boundary handling on the sliced core trace.
#[test]
fn test_hash_heavy_divergent_heights() {
    let source = "
        begin
            padw padw padw
            repeat.20
                hperm
            end
            dropw dropw dropw
        end
    ";
    assert_prove_verify(source, HashFunction::Blake3_256, "Blake3", false, false);
}

/// Exercises the MASM recursive verifier when the Poseidon2 permutation AIR is taller than the
/// core trace.
#[test]
fn test_hash_heavy_divergent_heights_recursive() {
    let source = "
        begin
            padw padw padw
            repeat.20
                hperm
            end
            dropw dropw dropw
        end
    ";
    assert_prove_verify(source, HashFunction::Poseidon2, "Poseidon2", false, true);
}

/// Test end-to-end proving and verification with RPX
#[test]
fn test_rpx_prove_verify() {
    // Compute 150th Fibonacci number to generate a longer trace
    let source = "
        begin
            repeat.149
                swap dup.1 add
            end
        end
    ";

    assert_prove_verify(source, HashFunction::Rpx256, "RPX", true, false);
}

// ================================================================================================
// FAST PROCESSOR + PARALLEL TRACE GENERATION TESTS
// ================================================================================================

mod fast_parallel {
    use alloc::sync::Arc;

    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::{
        program::ExecutionClaim,
        proof::{ExecutionProof, HashFunction},
    };
    use miden_processor::{
        DefaultHost, ExecutionOptions, FastProcessor, StackInputs, advice::AdviceInputs,
        trace::build_trace,
    };
    use miden_prover::{
        ProvingOptions, TraceProvingInputs, config, prove_from_trace_sync, prove_stark,
    };
    use miden_verifier::verify;
    use miden_vm::{Program, TraceBuildInputs};

    /// Default fragment size for parallel trace generation
    const FRAGMENT_SIZE: usize = 1024;

    fn parallel_execution_options() -> ExecutionOptions {
        ExecutionOptions::default()
            .with_core_trace_fragment_size(FRAGMENT_SIZE)
            .unwrap()
    }

    fn execute_parallel_trace_inputs(
        program: &Program,
        stack_inputs: StackInputs,
        advice_inputs: AdviceInputs,
        host: &mut DefaultHost,
    ) -> TraceBuildInputs {
        FastProcessor::new_with_options(stack_inputs, advice_inputs, parallel_execution_options())
            .expect("processor should initialize with built-in precompiles")
            .execute_trace_inputs_sync(program, host)
            .expect("Fast processor execution failed")
    }

    fn default_source_manager_host() -> DefaultHost {
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()))
    }

    /// Test that proves and verifies using the fast processor + parallel trace generation path.
    /// This verifies the complete code path works end-to-end.
    ///
    /// Note: We only test one hash function here since
    /// `test_trace_equivalence_slow_vs_fast_parallel` verifies trace equivalence, and the slow
    /// processor tests already cover all hash functions.
    #[test]
    fn test_fast_parallel_prove_verify() {
        // Use a program with enough iterations to generate a meaningful trace
        let source = "
            begin
                repeat.500
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = miden_utils_testing::stack_inputs_from_ints([0, 1]);
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let fast_stack_outputs = *trace_inputs.stack_outputs();

        // Build trace using parallel trace generation
        let trace = build_trace(trace_inputs).unwrap();

        // Build public inputs
        let (public_values, aux_inputs) = trace.public_inputs().to_air_inputs();

        // Per-AIR matrices for prove_multi.
        let (core_matrix, chiplets_matrix, poseidon2_matrix) = trace.to_air_matrices();

        // Generate proof using Blake3_256
        let blake3_config = config::blake3_256_config(config::pcs_params());
        let proof_bytes = prove_stark(
            &blake3_config,
            core_matrix,
            chiplets_matrix,
            poseidon2_matrix,
            &public_values,
            &aux_inputs,
        )
        .expect("Proving failed");

        let deferred_root = trace.deferred_state().root();
        let deferred_wire = trace
            .deferred_state()
            .to_wire()
            .expect("deferred state should serialize to wire");

        let proof = ExecutionProof::new(
            proof_bytes,
            HashFunction::Blake3_256,
            deferred_root,
            Some(deferred_wire),
        );

        // Verify the proof
        let claim = ExecutionClaim::new(program.into(), stack_inputs, fast_stack_outputs);
        verify(proof, claim).expect("Verification failed");
    }

    #[test]
    fn test_prove_from_trace_sync() {
        let source = "
            begin
                repeat.128
                    swap dup.1 add
                end
            end
        ";

        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = miden_utils_testing::stack_inputs_from_ints([0, 1]);
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        let claim = ExecutionClaim::new(program.into(), stack_inputs, stack_outputs);
        verify(proof, claim).expect("Verification failed");
    }

    #[test]
    fn test_prove_from_trace_sync_preserves_deferred_wire() {
        let source = "begin log_deferred end";
        let program = Assembler::default()
            .assemble_program("program", source)
            .unwrap()
            .unwrap_program();
        let stack_inputs = StackInputs::default();
        let advice_inputs = AdviceInputs::default();
        let mut host = default_source_manager_host();
        let trace_inputs =
            execute_parallel_trace_inputs(&program, stack_inputs, advice_inputs, &mut host);
        let expected_wire = trace_inputs
            .deferred_state()
            .to_wire()
            .expect("deferred state should serialize to wire");
        assert!(
            !expected_wire.entries.is_empty(),
            "log_deferred should advance the deferred root"
        );

        let (stack_outputs, proof) = prove_from_trace_sync(TraceProvingInputs::new(
            trace_inputs,
            ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
        ))
        .expect("prove_from_trace_sync failed");

        assert_eq!(proof.settlement(), Some(&expected_wire));
        let claim = ExecutionClaim::new(program.into(), stack_inputs, stack_outputs);
        verify(proof, claim).expect("Verification failed");
    }
}

/// Proves a trivial program and returns the claim/proof pair for API-surface tests.
fn prove_fixture() -> (ExecutionClaim, ExecutionProof) {
    let program = Assembler::default()
        .assemble_program("program", "begin push.1 push.2 add swap drop end")
        .unwrap()
        .unwrap_program();
    let stack_inputs = stack_inputs_from_ints([0, 1]);
    let mut host =
        DefaultHost::default().with_source_manager(Arc::new(DefaultSourceManager::default()));
    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        AdviceInputs::default(),
        &mut host,
        ExecutionOptions::default(),
        ProvingOptions::with_96_bit_security(HashFunction::Blake3_256),
    )
    .expect("Proving failed");
    (ExecutionClaim::new(program.into(), stack_inputs, stack_outputs), proof)
}

/// `verify` must refuse a package without settlement evidence; the same package verifies
/// through `verify_unsettled` + `settle`.
#[test]
fn test_unsettled_obligation_flow() {
    let (claim, proof) = prove_fixture();

    // strip the settlement evidence: a pass-through package
    let wire = proof.settlement().expect("prover packages carry evidence").clone();
    let mut pass_through = proof.clone();
    pass_through.settlement = None;

    assert!(matches!(
        verify(pass_through.clone(), claim.clone()),
        Err(VerificationError::MissingSettlementEvidence)
    ));

    // the unsettled path returns the obligation, which settles against the evidence
    let (_, pending) = verify_unsettled(pass_through, claim.clone()).expect("STARK should verify");
    settle(pending, &wire, miden_verifier::DEFAULT_MAX_DEFERRED_ELEMENTS)
        .expect("evidence should discharge the obligation");

    // the settled path accepts the full package
    verify(proof, claim).expect("settled verification should pass");
}

/// The deferred root is statement-bound: a tampered root must fail STARK verification.
#[test]
fn test_deferred_root_is_statement_bound() {
    let (claim, mut proof) = prove_fixture();
    proof.deferred_root =
        miden_core::chiplets::hasher::hash_elements(&[miden_core::Felt::new_unchecked(42)]);
    assert!(verify_unsettled(proof, claim).is_err());
}
