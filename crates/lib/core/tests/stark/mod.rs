use std::{array, sync::Arc};

use miden_air::PublicInputs;
use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    precompile::PrecompileTranscriptState,
    proof::HashFunction,
};
use miden_mast_package::Package;
use miden_processor::{DefaultHost, ExecutionOptions, Program, ProgramInfo};
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
    // init_seed expects [log(core_trace_length), log(chiplets_trace_length), rd0, rd1, rd2, rd3,
    // ...]; relation digest values are arbitrary here.
    let initial_stack = vec![10_u64, 10, 1, 2, 3, 4];

    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate the public inputs.
    let stack_inputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let stack_outputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let transcript_state: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let kernel_digest_felts = generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // 2) Build the advice stack in `process_public_inputs` consumption order: [aux_rand(4), N,
    //    digests(4N), program_digest(4), transcript_state(4), stack_inputs(16), stack_outputs(16)].
    let mut advice_stack = auxiliary_rand_values.to_vec();
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_digest_felts);
    advice_stack.extend_from_slice(&program_digest);
    advice_stack.extend_from_slice(&transcript_state);
    advice_stack.extend_from_slice(&stack_inputs);
    advice_stack.extend_from_slice(&stack_outputs);

    // 3) Run process_public_inputs.
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
    let read_elem = |addr: u32| -> u64 {
        output
            .memory
            .read_element(ctx, Felt::from_u32(addr))
            .unwrap()
            .as_canonical_u64()
    };

    // Must match `REDUCED_INPUTS_ADDRESS_PTR` / `PUBLIC_INPUTS_ADDRESS_PTR` / `C_TOTAL_PTR`
    // in `crates/lib/core/asm/stark/constants.masm`.
    let reduced_ptr = read_elem(3223322670) as u32;
    let pi_ptr = read_elem(3223322671) as u32;
    let c_total_ptr = 3223322704_u32;

    // 4) kernel_H at reduced_inputs+0..4 must match the Rust mirror; the pad word at +4..8 must be
    //    zero.
    let digest_felts: Vec<Felt> =
        kernel_digest_felts.iter().map(|&v| Felt::new_unchecked(v)).collect();
    let expected_kernel_h = miden_air::hash_kernel_digests(&digest_felts);
    for (i, expected) in expected_kernel_h.iter().enumerate() {
        assert_eq!(
            read_elem(reduced_ptr + i as u32),
            expected.as_canonical_u64(),
            "kernel_H felt {i} mismatch (nk={num_kernel_proc_digests})"
        );
    }
    for i in 4..8 {
        assert_eq!(read_elem(reduced_ptr + i), 0, "kernel_H pad felt {i} must be zero");
    }

    // 5) program_digest / transcript_state pass through to reduced_inputs+8..16.
    for (i, &v) in program_digest.iter().chain(transcript_state.iter()).enumerate() {
        assert_eq!(
            read_elem(reduced_ptr + 8 + i as u32),
            v,
            "reduced-inputs window felt {i} mismatch"
        );
    }

    // 6) FLPI region holds the stack i/o as EF elements ([val, 0] per slot).
    for (i, &v) in stack_inputs.iter().chain(stack_outputs.iter()).enumerate() {
        assert_eq!(read_elem(pi_ptr + 2 * i as u32), v, "FLPI slot {i} value mismatch");
        assert_eq!(read_elem(pi_ptr + 2 * i as u32 + 1), 0, "FLPI slot {i} high coord");
    }

    // 7) Verify the outer-LogUp boundary correction c_total at C_TOTAL_PTR:
    //
    //     c_total = Σ_i 1 / ((α + γ) + msg(kernel_digest_i))
    //             + 1 / ((α + 2γ) + msg(program_digest))
    //             + 1 / (α + 3γ)
    //             − 1 / ((α + 3γ) + msg(transcript_state))
    //
    // with γ = β^16 and msg(w) = Σ w_i·β^i, mirroring `MidenMultiAir::eval_external`.
    let beta = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[0]),
        Felt::new_unchecked(auxiliary_rand_values[1]),
    ]);
    let alpha = QuadFelt::new([
        Felt::new_unchecked(auxiliary_rand_values[2]),
        Felt::new_unchecked(auxiliary_rand_values[3]),
    ]);
    let gamma = (0..16).fold(QuadFelt::ONE, |acc, _| acc * beta);
    let msg = |felts: &[u64]| -> QuadFelt {
        felts
            .iter()
            .rev()
            .fold(QuadFelt::ZERO, |acc, m| acc * beta + QuadFelt::from(Felt::new_unchecked(*m)))
    };

    let kernel_corr = kernel_digest_felts
        .chunks_exact(WORD_SIZE)
        .map(|digest| alpha + gamma + msg(digest))
        .fold(QuadFelt::ZERO, |acc, term| {
            acc + term.try_inverse().expect("zero kernel ROM denominator")
        });
    let d_bh = alpha + gamma.double() + msg(&program_digest);
    let prefix_lp = alpha + gamma * QuadFelt::from_u8(3);
    let d_lpf = prefix_lp + msg(&transcript_state);
    let expected_c_total = kernel_corr
        + d_bh.try_inverse().expect("zero block-hash denominator")
        + prefix_lp.try_inverse().expect("zero log-precompile init denominator")
        - d_lpf.try_inverse().expect("zero log-precompile final denominator");
    let expected: &[Felt] = expected_c_total.as_basis_coefficients_slice();

    assert_eq!(
        read_elem(c_total_ptr),
        expected[0].as_canonical_u64(),
        "c_total coord 0 mismatch (nk={num_kernel_proc_digests})"
    );
    assert_eq!(
        read_elem(c_total_ptr + 1),
        expected[1].as_canonical_u64(),
        "c_total coord 1 mismatch (nk={num_kernel_proc_digests})"
    );
}

/// The recursive verifier must reject statements the Rust `Statement::new` refuses:
/// `aux_inputs.len() = WORD_SIZE * num_kernel_proc_digests` must not exceed
/// `MultiAir::max_aux_inputs()`. 256 kernel digests (1024 felts > MAX_AUX_INPUTS = 1020) is one
/// over the limit, so `process_public_inputs` must fail rather than absorb an out-of-range
/// digest list.
#[test]
fn rejects_too_many_kernel_proc_digests() {
    let initial_stack = vec![10_u64, 10, 1, 2, 3, 4];

    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let num_kernel_proc_digests = 256; // one over the maximum (255)
    let kernel_digest_felts = generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    let mut advice_stack = auxiliary_rand_values.to_vec();
    advice_stack.push(num_kernel_proc_digests as u64);
    advice_stack.extend_from_slice(&kernel_digest_felts);

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

/// Generates a vector with a specific number of kernel procedures digests given a `Rng`,
/// as 4 canonical felts per digest (the advice format `stream_kernel_digests` consumes).
fn generate_kernel_procedures_digests<R: Rng>(
    rng: &mut R,
    num_kernel_proc_digests: usize,
) -> Vec<u64> {
    (0..num_kernel_proc_digests * WORD_SIZE).map(|_| rng.next_u64()).collect()
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
