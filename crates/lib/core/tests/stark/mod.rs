use std::{array, sync::Arc};

use miden_air::PublicInputs;
use miden_assembly::{Assembler, testing::source_file};
use miden_core::{
    Felt, WORD_SIZE,
    deferred::{DeferredState, PrecompileRegistry, TRUE_DIGEST},
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    proof::{DeferredProof, HashFunction},
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

#[test]
fn stark_verifier_e2f4_with_deferred_root() {
    let data = generate_recursive_verifier_data(EXAMPLE_LOG_DEFERRED, fib_stack_inputs(), None);
    run_recursive_verifier(&data);
}

#[test]
fn folding_reseed_helper_matches_reference_sampler() {
    fn source(use_combined_helper: bool) -> String {
        let sample = if use_combined_helper {
            "
            push.41.31.29.23 push.17
            exec.random_coin::reseed_check_folding_pow_and_sample_alpha
            "
        } else {
            "
            push.41.31.29.23 push.17
            exec.random_coin::reseed_with_felt
            exec.constants::get_folding_pow_bits
            exec.random_coin::sample_bits
            assertz
            exec.random_coin::sample_ext
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.0 exec.constants::set_folding_pow_bits
                push.109.113.127.131 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.0 exec.constants::random_coin_output_len_ptr mem_store

                {sample}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
                exec.sys::truncate_stack
            end
            "
        )
    }

    let (reference, _) = build_test!(&source(false), &[])
        .execute_for_output()
        .expect("reference sampler should execute");
    let (combined, _) = build_test!(&source(true), &[])
        .execute_for_output()
        .expect("combined sampler should execute");

    assert_eq!(
        combined.stack.get_num_elements(15),
        reference.stack.get_num_elements(15),
        "combined FRI reseed helper diverged from reference sampler"
    );
    assert_eq!(combined.stack.get_element(12), Some(Felt::from_u32(5)));
}

#[test]
fn word_observe_helpers_match_scalar_observe() {
    fn source(use_word_helpers: bool) -> String {
        let observe = if use_word_helpers {
            "
            push.11.7.5.3
            exec.random_coin::observe_word
            push.23.19.17.13
            exec.random_coin::observe_word_and_flush_buffer
            "
        } else {
            "
            push.3 exec.random_coin::observe_felt
            push.5 exec.random_coin::observe_felt
            push.7 exec.random_coin::observe_felt
            push.11 exec.random_coin::observe_felt
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            push.19 exec.random_coin::observe_felt
            push.23 exec.random_coin::observe_felt
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.8 exec.constants::random_coin_output_len_ptr mem_store

                {observe}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
                exec.sys::truncate_stack
            end
            "
        )
    }

    let (reference, _) = build_test!(&source(false), &[])
        .execute_for_output()
        .expect("scalar observe path should execute");
    let (optimized, _) = build_test!(&source(true), &[])
        .execute_for_output()
        .expect("word observe path should execute");

    assert_eq!(
        optimized.stack.get_num_elements(13),
        reference.stack.get_num_elements(13),
        "word observe helpers changed random coin state"
    );
    assert_eq!(optimized.stack.get_element(12), Some(Felt::from_u32(8)));
}

#[test]
fn observe_word_and_flush_buffer_matches_scalar_observe() {
    fn source(prefix_len: usize, use_word_helper: bool) -> String {
        let prefix = (0..prefix_len)
            .map(|idx| format!("push.{} exec.random_coin::observe_felt", idx + 1))
            .collect::<Vec<_>>()
            .join("\n");
        let observe = if use_word_helper {
            "
            push.23.19.17.13
            exec.random_coin::observe_word_and_flush_buffer
            "
        } else {
            "
            push.13 exec.random_coin::observe_felt
            push.17 exec.random_coin::observe_felt
            push.19 exec.random_coin::observe_felt
            push.23 exec.random_coin::observe_felt
            exec.random_coin::flush_buffer
            "
        };

        format!(
            "
            use miden::core::sys
            use miden::core::stark::constants
            use miden::core::stark::random_coin

            begin
                push.101.103.107.109 exec.constants::c_ptr mem_storew_le dropw
                push.0 exec.constants::random_coin_input_len_ptr mem_store
                push.8 exec.constants::random_coin_output_len_ptr mem_store

                {prefix}
                {observe}

                exec.constants::random_coin_output_len_ptr mem_load
                exec.random_coin::load_random_coin_state
                exec.sys::truncate_stack
            end
            "
        )
    }

    for prefix_len in [0, 3, 4, 6] {
        let (reference, _) = build_test!(&source(prefix_len, false), &[])
            .execute_for_output()
            .expect("scalar observe path should execute");
        let (optimized, _) = build_test!(&source(prefix_len, true), &[])
            .execute_for_output()
            .expect("word observe path should execute");

        assert_eq!(
            optimized.stack.get_num_elements(13),
            reference.stack.get_num_elements(13),
            "word observe-and-flush helper changed random coin state with prefix_len={prefix_len}"
        );
        assert_eq!(optimized.stack.get_element(12), Some(Felt::from_u32(8)));
    }
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

    // These programs are deferred-free, so an empty registry is intentional; still resolve the
    // proof-carried deferred root instead of assuming TRUE.
    let stark_proof = proof.miden_proof();
    let deferred_proof = proof.deferred_proof();
    let final_deferred_root = match deferred_proof {
        DeferredProof::Empty => TRUE_DIGEST,
        DeferredProof::Wire(wire) => {
            DeferredState::from_wire(Arc::new(PrecompileRegistry::new()), wire, usize::MAX)
                .unwrap()
                .root()
        },
        DeferredProof::Stark { .. } => {
            panic!("recursive verifier does not support deferred STARK proofs")
        },
    };
    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, final_deferred_root);

    generate_advice_inputs(stark_proof.bytes(), pub_inputs).unwrap()
}

/// Run the recursive verifier MASM program with the given VerifierData.
fn run_recursive_verifier(data: &VerifierData) {
    let source = "
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
            # Initial stack: [kernel_ptr, num_kernel_digests, stack_io_ptr, PROG0..3].

            # Copy kernel digests (4·num_kernel_digests felts) from advice into the caller region
            # (kernel_ptr = 0). Build [dst=0, count=4N].
            dup.1 mul.4 push.0
            exec.copy_advice_to_mem

            # Copy stack i/o (32 felts) from advice into the caller region (stack_io_ptr = 4096).
            # Build [dst=4096, count=32].
            push.32 push.4096
            exec.copy_advice_to_mem

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

const EXAMPLE_LOG_DEFERRED: &str = "begin
        log_deferred
        dropw dropw dropw
    end";

fn fib_stack_inputs() -> Vec<u64> {
    let mut inputs = vec![0_u64; 16];
    inputs[15] = 0;
    inputs[14] = 1;
    inputs
}

// REDUCED INPUTS TESTS
// ================================================================================================

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(8)]
// 255 = KernelDescriptor::MAX_NUM_PROCEDURES, the maximum number of kernel procedures a Statement
// accepts.
#[case(255)]
fn reduced_inputs_and_outer_logup_boundary(#[case] num_kernel_proc_digests: usize) {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    // 1) Generate the statement inputs.
    let stack_inputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let stack_outputs: [u64; 16] = array::from_fn(|_| rng.next_u64());
    let program_digest: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let deferred_root: [u64; 4] = array::from_fn(|_| rng.next_u64());
    let kernel_digest_felts = generate_kernel_procedures_digests(&mut rng, num_kernel_proc_digests);
    let auxiliary_rand_values: [u64; 4] = array::from_fn(|_| rng.next_u64());

    // Caller-owned memory regions (must match the MASM constants below): kernel digests at 0,
    // stack i/o at 4096.
    const KERNEL_PTR: u64 = 0;
    const STACK_IO_PTR: u64 = 4096;

    // 2) Initial operand stack: `stage_reduced_inputs` operands.
    let mut initial_stack = vec![KERNEL_PTR, num_kernel_proc_digests as u64, STACK_IO_PTR];
    initial_stack.extend_from_slice(&program_digest);

    // 3) Build the advice stack: kernel digests (4N) and stack i/o (32) for the marshalling, then
    //    deferred root for `stage_reduced_inputs`, then the aux randomness consumed by the test
    //    prologue that drives `compute_outer_logup_correction`.
    let mut advice_stack = Vec::new();
    advice_stack.extend_from_slice(&kernel_digest_felts);
    advice_stack.extend_from_slice(&stack_inputs);
    advice_stack.extend_from_slice(&stack_outputs);
    advice_stack.extend_from_slice(&deferred_root);
    advice_stack.extend_from_slice(&auxiliary_rand_values);

    // 4) Marshal the caller regions, stage the reduced-inputs block, run process_public_inputs,
    //    then emulate step II: place the aux randomness at AUX_RAND_ELEM_PTR (where
    //    `generate_aux_randomness` samples it) and compute `c_total`.
    let source = "
        use miden::core::stark::random_coin
        use miden::core::stark::constants
        use miden::core::sys::vm::public_inputs

        proc copy_advice_to_mem
            dup.1 push.0 neq
            while.true
                padw adv_loadw
                dup.4 mem_storew_le dropw
                add.4
                swap sub.4 swap
                dup.1 push.0 neq
            end
            drop drop
        end

        begin
            dup.1 mul.4 push.0
            exec.copy_advice_to_mem
            push.32 push.4096
            exec.copy_advice_to_mem

            exec.public_inputs::stage_reduced_inputs

            push.10 exec.constants::set_core_trace_length_log
            push.10 exec.constants::set_chiplets_trace_length_log
            push.10 exec.constants::set_poseidon2_permutation_trace_length_log
            push.10 exec.constants::set_trace_length_log
            push.4.3.2.1 exec.constants::relation_digest_ptr mem_storew_le dropw

            exec.random_coin::init_seed
            exec.public_inputs::process_public_inputs

            padw adv_loadw exec.constants::aux_rand_elem_ptr mem_storew_le dropw
            exec.public_inputs::compute_outer_logup_correction
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

    // 4) kernel_H at reduced_inputs+0..4 must match the Rust mirror.
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

    // 5) program_digest / deferred_root pass through to reduced_inputs+4..12; the trailing pad word
    //    at +12..16 must be zero.
    for (i, &v) in program_digest.iter().chain(deferred_root.iter()).enumerate() {
        assert_eq!(
            read_elem(reduced_ptr + 4 + i as u32),
            v,
            "reduced-inputs window felt {i} mismatch"
        );
    }
    for i in 12..16 {
        assert_eq!(read_elem(reduced_ptr + i), 0, "reduced-inputs pad felt {i} must be zero");
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
    //             − 1 / ((α + 3γ) + msg(deferred_root))
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
    let d_lpf = prefix_lp + msg(&deferred_root);
    let expected_c_total = kernel_corr
        + d_bh.try_inverse().expect("zero block-hash denominator")
        + prefix_lp.try_inverse().expect("zero log-deferred init denominator")
        - d_lpf.try_inverse().expect("zero log-deferred final denominator");
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

/// The recursive verifier must reject statements with more kernel-procedure digests than a
/// `KernelDescriptor` can contain. 256 digests is one over the maximum, so
/// `stage_reduced_inputs` must fail on the digest-count bound before reading caller memory or
/// advice.
#[test]
fn rejects_too_many_kernel_proc_digests() {
    let num_kernel_proc_digests = 256_u64; // one over the maximum (255)

    // Operands: [kernel_ptr, N, stack_io_ptr, PROG0..3]. The bound on N is the first check in
    // `stage_reduced_inputs`, so no caller memory or advice is needed.
    let initial_stack = vec![0_u64, num_kernel_proc_digests, 4096, 1, 2, 3, 4];

    let source = "
        use miden::core::sys::vm::public_inputs

        begin
            exec.public_inputs::stage_reduced_inputs
        end
        ";

    let test = build_test!(source, &initial_stack);
    assert!(
        test.execute_for_output().is_err(),
        "verifier accepted {num_kernel_proc_digests} kernel digests, exceeding max_aux_inputs"
    );
}

#[test]
fn quotient_recomposition_constants_match_derivation() {
    // The quotient recomposition constants in `asm/stark/constants.masm` are precomputed for the
    // fixed blowup factor. Re-derive them from `BLOWUP_FACTOR_LOG` and the field so that changing
    // the blowup without regenerating the constants fails here instead of shipping stale values.

    // Goldilocks two-adicity: p - 1 = 2^32 * (2^32 - 1), so the largest power-of-two subgroup has
    // order 2^32.
    const TWO_ADICITY: u32 = 32;
    // Goldilocks multiplicative generator.
    const GENERATOR: u32 = 7;

    let masm =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/asm/stark/constants.masm"))
            .expect("read constants.masm");
    let masm_const = |name: &str| -> u64 {
        masm.lines()
            .find_map(|line| {
                let (lhs, rhs) = line.trim().strip_prefix("const ")?.split_once('=')?;
                if lhs.trim() != name {
                    return None;
                }
                Some(rhs.split_whitespace().next()?.parse().expect("parse const value"))
            })
            .unwrap_or_else(|| panic!("const {name} not found in constants.masm"))
    };

    let blowup_log = masm_const("BLOWUP_FACTOR_LOG") as u32;
    let root_unity = Felt::new(masm_const("ROOT_UNITY")).unwrap();
    let shift_ratio = Felt::new(masm_const("QUOTIENT_SHIFT_RATIO")).unwrap();
    let first_shift = Felt::new(masm_const("QUOTIENT_FIRST_SHIFT")).unwrap();
    let first_weight = Felt::new(masm_const("QUOTIENT_FIRST_WEIGHT")).unwrap();

    // With log_lde = log_trace + BLOWUP_FACTOR_LOG, both lde_g^N and offset^N collapse to one
    // exponent that is independent of the trace length N = 2^log_trace.
    let exp = 1u64 << (TWO_ADICITY - blowup_log);
    let blowup = 1u32 << blowup_log;

    // f = lde_g^N: the primitive 2^BLOWUP_FACTOR_LOG-th root of unity.
    assert_eq!(root_unity.exp_u64(exp), shift_ratio, "QUOTIENT_SHIFT_RATIO is stale");

    // s0 = offset^N with offset = GENERATOR^(2^(TWO_ADICITY - log_lde)).
    let s0 = Felt::from_u32(GENERATOR).exp_u64(exp);
    assert_eq!(s0, first_shift, "QUOTIENT_FIRST_SHIFT is stale");

    // First barycentric weight = 1 / (BLOWUP_FACTOR * s0^(BLOWUP_FACTOR - 1)); check it as a
    // reciprocal to avoid an explicit field inversion.
    let denom = Felt::from_u32(blowup) * s0.exp_u64((blowup - 1) as u64);
    assert_eq!((first_weight * denom).as_canonical_u64(), 1, "QUOTIENT_FIRST_WEIGHT is stale");
}

// HELPERS
// ===============================================================================================

/// Generates kernel-procedure digest felts: 4 canonical felts per digest.
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
