use std::array;

use miden_air::PublicInputs;
use miden_assembly::Assembler;
use miden_core::{
    Felt, WORD_SIZE,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    precompile::PrecompileTranscriptState,
    proof::HashFunction,
};
use miden_processor::{DefaultHost, ExecutionOptions, Program, ProgramInfo};
use miden_utils_testing::{AdviceInputs, ProvingOptions, StackInputs, prove_sync};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use rstest::rstest;
use verifier_recursive::{VerifierData, VerifierError, generate_advice_inputs};

mod ace_circuit;
mod ace_read_check;
mod batch_query_gen;
mod verifier_recursive;

// RECURSIVE VERIFIER TESTS
// ================================================================================================

#[test]
fn stark_verifier_e2f4_small() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, inputs, None).unwrap();
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_large() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(EXAMPLE_FIB_LARGE, inputs, None).unwrap();
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_even() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_EVEN_NUM_PROC),
    )
    .unwrap();
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_odd() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_ODD_NUM_PROC),
    )
    .unwrap();
    run_recursive_verifier(&data);
}

#[test]
fn stark_verifier_e2f4_with_kernel_single() {
    let inputs = fib_stack_inputs();
    let data = generate_recursive_verifier_data(
        EXAMPLE_FIB_KERNEL_SMALL,
        inputs,
        Some(KERNEL_SINGLE_PROC),
    )
    .unwrap();
    run_recursive_verifier(&data);
}

// Helper function for recursive verification
pub fn generate_recursive_verifier_data(
    source: &str,
    stack_inputs: Vec<u64>,
    kernel: Option<&str>,
) -> Result<VerifierData, VerifierError> {
    let (program, kernel_lib) = {
        match kernel {
            Some(kernel) => {
                let context = miden_assembly::testing::TestContext::new();
                let kernel_lib =
                    Assembler::new(context.source_manager()).assemble_kernel(kernel).unwrap();
                let assembler =
                    Assembler::with_kernel(context.source_manager(), kernel_lib.clone());
                let program: Program = assembler.assemble_program(source).unwrap();
                (program, Some(kernel_lib))
            },
            None => {
                let program: Program = Assembler::default().assemble_program(source).unwrap();
                (program, None)
            },
        }
    };
    let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
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
    let data = generate_advice_inputs(&proof_bytes, pub_inputs).unwrap();
    Ok(data)
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

// OUTER LOGUP BOUNDARY CORRECTION TESTS
// ================================================================================================

#[rstest]
#[case(0)]
#[case(1)]
#[case(3)]
#[case(8)]
fn outer_logup_correction(#[case] num_kernel_proc_digests: usize) {
    // Validates that MASM's `process_public_inputs` computes
    //   c_total = c_kr + 1/d_bh + 1/d_lp_init − 1/d_lp_final
    // and stores it at C_TOTAL_PTR.
    //
    // Advice ordering (matching `verifier_recursive::build_advice`):
    //   α/β (4) | N | kernel_digests canonical (4N) | program_digest (4) |
    //   transcript_state (4) | stack_inputs (16) | stack_outputs (16).

    let log_trace_length = 10_u64;
    let rd = [1_u64, 2, 3, 4];
    let initial_stack = vec![log_trace_length, rd[0], rd[1], rd[2], rd[3]];

    let seed = [7_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Fixed-length public inputs (stack i/o only).
    let stack_inputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let stack_outputs: [u64; 16] = array::from_fn(|_| rng.next_u64());

    // 2) VLPI canonical digests (program_digest, transcript_state, kernel_digests).
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let transcript_state: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let kernel_procedures_digests =
        generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);

    // 3) Aux randomness [β0, β1, α0, α1].
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // 4) Build advice stack in MASM consumption order: α/β | num_kernel + kernel_digests canonical
    //    | program_digest | transcript_state | stack_io.
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&auxiliary_rand_values);
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_procedures_digests);
    advice_stack.extend_from_slice(&program_digest);
    advice_stack.extend_from_slice(&transcript_state);
    advice_stack.extend_from_slice(&stack_inputs);
    advice_stack.extend_from_slice(&stack_outputs);

    // 5) Rust reference: mirror `Challenges::encode` (bus_prefix = α + (BusId+1), payload at
    //    β^1..β^K, no γ-shift) and the boundary identity from `emit_miden_boundary`.
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);

    let expected = expected_outer_logup(
        &program_digest,
        &transcript_state,
        &kernel_procedures_digests,
        alpha,
        beta,
    );
    let expected_coeffs: &[Felt] = expected.as_basis_coefficients_slice();

    // 6) Run process_public_inputs and read c_total from C_TOTAL_PTR.
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
    let (output, _host) = test.execute_for_output().expect("execution failed");

    use miden_processor::ContextId;
    let ctx = ContextId::root();

    // C_TOTAL_PTR (see stark/constants.masm). c_total stored as 2 contiguous felts.
    let c_total_ptr = 3223322760_u32;
    let masm_0 = output.memory.read_element(ctx, Felt::from_u32(c_total_ptr)).unwrap();
    let masm_1 = output.memory.read_element(ctx, Felt::from_u32(c_total_ptr + 1)).unwrap();

    assert_eq!(
        masm_0.as_canonical_u64(),
        expected_coeffs[0].as_canonical_u64(),
        "c_total coord 0 mismatch (nk={num_kernel_proc_digests})"
    );
    assert_eq!(
        masm_1.as_canonical_u64(),
        expected_coeffs[1].as_canonical_u64(),
        "c_total coord 1 mismatch (nk={num_kernel_proc_digests})"
    );
}

// HELPERS
// ===============================================================================================

/// Rust reference for the outer LogUp boundary correction; mirrors `emit_miden_boundary` and
/// `Challenges::encode`. Each denominator is `(α + BusId + 1) + β · horner4(payload, β)` with
/// BusIds: KernelRomInit = 0, BlockHashTable = 1, LogPrecompileTranscript = 2.
fn expected_outer_logup(
    program_digest: &[u64; 4],
    transcript_state: &[u64; 4],
    kernel_digests_canonical: &[u64],
    alpha: QuadFelt,
    beta: QuadFelt,
) -> QuadFelt {
    let bp_kernel_rom_init = alpha + QuadFelt::from(Felt::new_unchecked(1));
    let bp_block_hash = alpha + QuadFelt::from(Felt::new_unchecked(2));
    let bp_log_precompile = alpha + QuadFelt::from(Felt::new_unchecked(3));

    // β · horner4(payload, β) over a canonical 4-felt digest.
    let beta_shifted_horner = |payload: &[u64; 4]| -> QuadFelt {
        let h: QuadFelt = payload
            .iter()
            .rev()
            .fold(QuadFelt::ZERO, |acc, p| acc * beta + QuadFelt::from(Felt::new_unchecked(*p)));
        beta * h
    };

    let d_bh = bp_block_hash + beta_shifted_horner(program_digest);
    let d_lp_init = bp_log_precompile;
    let d_lp_final = bp_log_precompile + beta_shifted_horner(transcript_state);

    let c_kr = reduce_kernel_procedures_digests(kernel_digests_canonical, bp_kernel_rom_init, beta);
    c_kr + d_bh.try_inverse().expect("d_bh zero") + d_lp_init.try_inverse().expect("d_lp_init zero")
        - d_lp_final.try_inverse().expect("d_lp_final zero")
}

/// Generates a vector with a specific number of kernel procedures digests given a `Rng`.
///
/// Each digest is emitted as 4 canonical felts. The MASM verifier appends a zero word to each
/// digest in-place to form the 8-felt sponge block.
fn generate_kernel_procedures_digests<R: Rng>(
    rng: &mut R,
    num_kernel_proc_digests: usize,
) -> Vec<u64> {
    let mut kernel_proc_digests: Vec<u64> = Vec::with_capacity(num_kernel_proc_digests * WORD_SIZE);

    (0..num_kernel_proc_digests).for_each(|_| {
        let digest: [u64; WORD_SIZE] = array::from_fn(|_| rng.next_u64());
        kernel_proc_digests.extend_from_slice(&digest);
    });

    kernel_proc_digests
}

/// Reduces all kernel digests (each given as 4 canonical felts) into
/// `Σ_i 1 / ((α + 1) + β · horner4(d_i, β))`.
fn reduce_kernel_procedures_digests(
    kernel_digests_canonical: &[u64],
    bus_prefix: QuadFelt,
    beta: QuadFelt,
) -> QuadFelt {
    kernel_digests_canonical
        .chunks(WORD_SIZE)
        .map(|digest| reduce_digest(digest, bus_prefix, beta))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        })
}

/// Computes `term = bus_prefix + β · horner4(d, β)` for a single 4-felt canonical digest.
fn reduce_digest(digest: &[u64], bus_prefix: QuadFelt, beta: QuadFelt) -> QuadFelt {
    // Horner from highest-degree coefficient down: acc = d0 + d1·β + d2·β² + d3·β³.
    let h = digest.iter().rev().fold(QuadFelt::ZERO, |acc, coef| {
        acc * beta + QuadFelt::from(Felt::new_unchecked(*coef))
    });
    // Multiply by β to shift payload to β^1..β^4 (matches `Challenges::encode`).
    bus_prefix + beta * h
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
