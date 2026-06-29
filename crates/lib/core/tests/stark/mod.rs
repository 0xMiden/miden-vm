use std::{array, sync::Arc};

use miden_air::PublicInputs;
use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE, Word,
    events::{EventId, EventName},
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    precompile::{
        PrecompileCommitment, PrecompileError, PrecompileRequest, PrecompileTranscriptState,
        PrecompileVerifier, PrecompileVerifierRegistry,
    },
    proof::HashFunction,
};
use miden_core_lib::CoreLibrary;
use miden_mast_package::Package;
use miden_processor::{
    DefaultHost, ExecutionOptions, ProcessorState, Program, ProgramInfo,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};
use miden_utils_testing::{
    AdviceInputs, ProvingOptions, prove_sync,
    recursive_verifier::{VerifierData, generate_advice_inputs},
    stack_inputs_from_ints,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_large() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, inputs, None);
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_even() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_EVEN_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_odd() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_ODD_NUM_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_single() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    );
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_log_precompile_transcript() {
    let data = generate_recursive_verifier_data_with_log_precompile();
    run_recursive_verifier(&data);
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> VerifierData {
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel = context.parse_kernel(source_file!(&context, kernel)).unwrap();
                let kernel_lib = Assembler::new(context.source_manager())
                    .assemble_kernel("kernel", kernel, None)
                    .map(Arc::<Package>::from)
                    .unwrap();
                let assembler =
                    Assembler::with_kernel(context.source_manager(), kernel_lib.clone()).unwrap();
                let program: Program =
                    assembler.assemble_program("program", source).unwrap().unwrap_program();
                (program, Some(kernel_lib))
            },
            None => {
                let program: Program = Assembler::default()
                    .assemble_program("program", source)
                    .unwrap()
                    .unwrap_program();
                (program, None)
            },
        }
    };
    let stack_inputs = stack_inputs_from_ints(stack_inputs);
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    if let Some(ref kernel_lib) = kernel_lib {
        host.load_library(kernel_lib.mast_forest()).unwrap();
    }

    let options = ProvingOptions::new(HashFunction::Poseidon2);

    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .unwrap();

    let program_info = ProgramInfo::from(program);

    // build public inputs and generate the advice data needed for recursive proof verification
    let pub_inputs = PublicInputs::new(
        program_info,
        stack_inputs,
        stack_outputs,
        PrecompileTranscriptState::default(),
    );
    let (_, proof_bytes, _precompile_requests) = proof.into_parts();
    generate_advice_inputs(&proof_bytes, pub_inputs).unwrap()
}

fn generate_recursive_verifier_data_with_log_precompile() -> VerifierData {
    const EVENT_NAME: EventName = EventName::new("test::stark::log_precompile");

    let event_id = EventId::from_name(EVENT_NAME);
    let calldata = vec![1u8, 2, 3, 4];
    let tag = Word::from([
        event_id.as_felt(),
        Felt::new_unchecked(1),
        Felt::new_unchecked(0),
        Felt::new_unchecked(7),
    ]);
    let comm = Word::from([
        Felt::new_unchecked(43),
        Felt::new_unchecked(62),
        Felt::new_unchecked(24),
        Felt::new_unchecked(1),
    ]);
    let commitment = PrecompileCommitment::new(tag, comm);
    let source = format!(
        "
            use miden::core::sys

            begin
                emit.event(\"{EVENT_NAME}\")

                push.{tag} push.{comm}
                exec.sys::log_precompile_request

                repeat.320
                    swap dup.1 add
                end
                u32split drop
            end
        ",
    );

    let core_lib = CoreLibrary::default();
    let program: Program = Assembler::default()
        .with_package(core_lib.package(), miden_assembly::Linkage::Dynamic)
        .unwrap()
        .assemble_program("program", source)
        .unwrap()
        .unwrap_program();
    let stack_inputs = stack_inputs_from_ints(fib_stack_inputs());
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    host.load_library(&core_lib).unwrap();
    host.register_handler(EVENT_NAME, Arc::new(DummyLogPrecompileHandler { event_id, calldata }))
        .unwrap();

    let options = ProvingOptions::new(HashFunction::Poseidon2);
    let (stack_outputs, proof) = prove_sync(
        &program,
        stack_inputs,
        advice_inputs,
        &mut host,
        ExecutionOptions::default(),
        options,
    )
    .unwrap();
    assert_eq!(proof.precompile_requests().len(), 1);

    let verifier_registry = PrecompileVerifierRegistry::new()
        .with_verifier(&EVENT_NAME, Arc::new(DummyLogPrecompileVerifier { commitment }));
    let transcript = verifier_registry.requests_transcript(proof.precompile_requests()).unwrap();
    assert_ne!(transcript.state(), PrecompileTranscriptState::default());

    let pub_inputs = PublicInputs::new(
        ProgramInfo::from(program),
        stack_inputs,
        stack_outputs,
        transcript.state(),
    );
    generate_advice_inputs(proof.stark_proof(), pub_inputs).unwrap()
}

#[derive(Clone)]
struct DummyLogPrecompileHandler {
    event_id: EventId,
    calldata: Vec<u8>,
}

impl EventHandler for DummyLogPrecompileHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(vec![AdviceMutation::extend_precompile_requests([PrecompileRequest::new(
            self.event_id,
            self.calldata.clone(),
        )])])
    }
}

#[derive(Clone)]
struct DummyLogPrecompileVerifier {
    commitment: PrecompileCommitment,
}

impl PrecompileVerifier for DummyLogPrecompileVerifier {
    fn verify(&self, _calldata: &[u8]) -> Result<PrecompileCommitment, PrecompileError> {
        Ok(self.commitment)
    }
}

/// Run the recursive verifier MASM program with the given VerifierData.
fn run_recursive_verifier(data: &VerifierData) {
    let source = "
        use miden::core::sys::vm
        begin
            exec.vm::verify_proof
        end
        ";
    let test = build_test!(
        source,
        &data.initial_stack,
        &data.advice_stack,
        data.store.clone(),
        data.advice_map.clone()
    );
    let (output, _host) = test.execute_for_output().expect("recursive verifier execution failed");

    // Cross-check: extract READ section, sanity-check values, evaluate circuit in Rust.
    ace_read_check::cross_check_ace_circuit(&output);
}

// EXAMPLE PROGRAMS
// ================================================================================================

/// repeat.320 -> log_trace_height=10 -> FRI remainder degree < 64 -> verify_64 path
const EXAMPLE_FIB_SMALL: &str = "begin
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

/// repeat.400 -> log_trace_height=11 -> FRI remainder degree < 128 -> verify_128 path
const EXAMPLE_FIB_LARGE: &str = "begin
        repeat.400
            swap dup.1 add
        end
        u32split drop
    end";

/// Like EXAMPLE_FIB_SMALL but with a syscall, for kernel-aware tests.
const EXAMPLE_FIB_KERNEL_SMALL: &str = "begin
        syscall.foo
        repeat.320
            swap dup.1 add
        end
        u32split drop
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

// VARIABLE LENGTH PUBLIC INPUTS TESTS
// ================================================================================================

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
// 255 = MAX_AUX_INPUTS / WORD_SIZE is the maximum the Rust `Statement` accepts.
#[case(255)]
fn variable_length_public_inputs(#[case] num_kernel_proc_digests: usize) {
    let initial_stack = vec![];

    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate fixed-length public inputs
    let input_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let output_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());

    let mut fixed_length_public_inputs = input_operand_stack.to_vec();
    fixed_length_public_inputs.extend_from_slice(&output_operand_stack);
    fixed_length_public_inputs.extend_from_slice(&program_digest);
    fixed_length_public_inputs.resize(fixed_length_public_inputs.len().next_multiple_of(8), 0);

    // 2) Generate the variable-length public inputs (kernel procedure digests)
    let kernel_procedures_digests =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);

    // 3) Generate the auxiliary randomness
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // 4) Build the advice stack
    let mut advice_stack = fixed_length_public_inputs.clone();
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    // 5) Compute the expected reduced value
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);

    let reduced_value = reduce_kernel_procedures_digests(&kernel_procedures_digests, alpha, beta);
    let coeffs: &[Felt] = reduced_value.as_basis_coefficients_slice();

    // 6) Run process_public_inputs and verify the reduced value in memory
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs

        begin
            push.10 exec.constants::set_core_trace_length_log
            push.10 exec.constants::set_chiplets_trace_length_log
            push.10 exec.constants::set_trace_length_log
            push.4.3.2.1 exec.constants::relation_digest_ptr mem_storew_le dropw
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
        ";

    let test = build_test!(source, &initial_stack, &advice_stack);
    let (output, _host) = test.execute_for_output().expect("execution failed");

    use miden_processor::ContextId;
    let ctx = ContextId::root();

    // Read reduced kernel value from var_len_ptr (in ACE READ section).
    // Must match `VARIABLE_LEN_PUBLIC_INPUTS_ADDRESS_PTR` in
    // `crates/lib/core/asm/stark/constants.masm`.
    let var_len_addr_ptr = 3223322670_u32;
    let var_len_ptr = output
        .memory
        .read_element(ctx, Felt::from_u32(var_len_addr_ptr))
        .unwrap()
        .as_canonical_u64() as u32;
    let masm_0 = output.memory.read_element(ctx, Felt::from_u32(var_len_ptr)).unwrap();
    let masm_1 = output.memory.read_element(ctx, Felt::from_u32(var_len_ptr + 1)).unwrap();

    assert_eq!(
        masm_0.as_canonical_u64(),
        coeffs[0].as_canonical_u64(),
        "kernel_reduced coord 0 mismatch (nk={num_kernel_proc_digests})"
    );
    assert_eq!(
        masm_1.as_canonical_u64(),
        coeffs[1].as_canonical_u64(),
        "kernel_reduced coord 1 mismatch (nk={num_kernel_proc_digests})"
    );
}

/// The recursive verifier must reject statements the Rust `Statement::new` refuses:
/// `aux_inputs.len() = WORD_SIZE * num_kernel_proc_digests` must not exceed
/// `MultiAir::max_aux_inputs()`. 256 kernel digests (1024 felts > MAX_AUX_INPUTS = 1020) is one
/// over the limit, so `process_public_inputs` must fail rather than absorb an out-of-range length.
#[test]
fn rejects_too_many_kernel_proc_digests() {
    let initial_stack = vec![10_u64, 10, 1, 2, 3, 4];

    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let input_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let output_operand_stack: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let mut fixed_length_public_inputs = input_operand_stack.to_vec();
    fixed_length_public_inputs.extend_from_slice(&output_operand_stack);
    fixed_length_public_inputs.extend_from_slice(&program_digest);
    fixed_length_public_inputs.resize(fixed_length_public_inputs.len().next_multiple_of(8), 0);

    let num_kernel_proc_digests = 256; // one over the maximum (255)
    let kernel_procedures_digests =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    let mut advice_stack = fixed_length_public_inputs;
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs

        begin
            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs
        end
        ";

    let test = build_test!(source, &initial_stack, &advice_stack);
    assert!(
        test.execute_for_output().is_err(),
        "verifier accepted {num_kernel_proc_digests} kernel digests, exceeding max_aux_inputs"
    );
}

// HELPERS
// ===============================================================================================

/// Generates a vector with a specific number of kernel procedures digests given a `Rng`.
///
/// The digests are padded to the next multiple of 8 and are reversed. This is done in order to
/// make reducing these, in the recursive verifier, faster using Horner evaluation.
fn generate_kernel_procedures_digests<R: Rng>(
    rng: &mut R,
    num_kernel_proc_digests: usize,
) -> Vec<u64> {
    let num_elements_kernel_proc_digests = num_kernel_proc_digests * 2 * WORD_SIZE;

    let mut kernel_proc_digests: Vec<u64> = Vec::with_capacity(num_elements_kernel_proc_digests);

    (0..num_kernel_proc_digests).for_each(|_| {
        let digest: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u64());
        let mut digest = digest.to_vec();
        digest.resize(WORD_SIZE * 2, 0);
        digest.reverse();
        kernel_proc_digests.extend_from_slice(&digest);
    });

    kernel_proc_digests
}

fn reduce_kernel_procedures_digests(
    kernel_procedures_digests: &[u64],
    alpha: QuadFelt,
    beta: QuadFelt,
) -> QuadFelt {
    // kernel_corr = Σ_i 1 / term_i  (MASM: chiplet removes, boundary adds — no negation).
    kernel_procedures_digests
        .chunks(2 * WORD_SIZE)
        .map(|digest| reduce_digest(digest, alpha, beta))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        })
}

fn reduce_digest(digest: &[u64], alpha: QuadFelt, beta: QuadFelt) -> QuadFelt {
    // gamma = beta^MAX_MESSAGE_WIDTH = beta^16
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    // KERNEL_ROM_INIT = 0, so bus_prefix = alpha + (0+1) * gamma = alpha + gamma
    let bus_prefix = alpha + gamma;
    // Horner evaluation matches MASM `horner_eval_base` over the 8-element reversed digest.
    bus_prefix
        + digest.iter().fold(QuadFelt::ZERO, |acc, coef| {
            acc * beta + QuadFelt::from(Felt::new_unchecked(*coef))
        })
}

// CONSTANTS
// ===============================================================================================

const KERNEL_SINGLE_PROC: &str = r#"
        pub proc foo
            add
        end"#;

const KERNEL_EVEN_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end"#;

const KERNEL_ODD_NUM_PROC: &str = r#"
        pub proc foo
            add
        end
        pub proc bar
            div
        end
        pub proc baz
            mul
        end"#;
