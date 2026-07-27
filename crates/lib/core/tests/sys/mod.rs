#[cfg(feature = "arbitrary")]
use miden_utils_testing::{MIN_STACK_DEPTH, proptest::prelude::*, rand::rand_vector};

#[test]
fn truncate_stack() {
    let source = "use miden::core::sys begin repeat.12 push.0 end exec.sys::truncate_stack end";
    // Input [1, 2, ..., 16] -> stack with 1 at top
    // After 12 push.0 and truncate: [0, 0, ..., 0, 1, 2, 3, 4]
    build_test!(source, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .expect_stack(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
}

#[test]
fn stage_rejects_digest_count_over_bound() {
    // `stage_boundary_inputs` takes the digest count `N` as an operand and asserts it fits
    // `Kernel::MAX_NUM_PROCEDURES` (`N < 256`). The bound is its first check, so no caller memory
    // or advice is required.
    //
    // Operands: [claim_ptr, kernel_ptr, N].
    let source = "
        use miden::core::sys::vm::public_inputs
        begin
            exec.public_inputs::stage_boundary_inputs
        end
    ";

    let num_kernel_proc_digests = 256_u64; // one over the maximum (255)
    let initial_stack = vec![4096_u64, 0, num_kernel_proc_digests];

    let test = build_test!(source, &initial_stack);
    expect_assert_error_message!(test);
}

#[cfg(feature = "arbitrary")]
proptest! {
    #[test]
    fn truncate_stack_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..100) {
        let push_values = rand_vector::<u64>(n);
        let mut source_vec = vec!["use miden::core::sys".to_string(), "begin".to_string()];
        for value in push_values.iter() {
            source_vec.push(format!("push.{value}"));
        }
        source_vec.push("exec.sys::truncate_stack".to_string());
        source_vec.push("end".to_string());
        let source = source_vec.join(" ");
        let mut expected_values: Vec<u64> = push_values.iter().rev().copied().collect();
        expected_values.extend(test_values.iter());
        expected_values.truncate(MIN_STACK_DEPTH);
        build_test!(&source, &test_values).prop_expect_stack(&expected_values)?;
    }
}

// EXECUTION CLAIM CROSS-TESTS
// ================================================================================================

/// The MASM `sys::vm::claim::claim_commitment` procedure must agree with the native
/// `ExecutionClaim::commitment` on the same claim region (same encoding, same domain tag, same
/// capacity layout).
#[test]
fn masm_claim_commitment_matches_native() {
    use miden_core::{
        Felt, Word,
        program::{ExecutionClaim, KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
    };

    let word = |a: u64, b: u64, c: u64, d: u64| -> Word {
        [
            Felt::new_unchecked(a),
            Felt::new_unchecked(b),
            Felt::new_unchecked(c),
            Felt::new_unchecked(d),
        ]
        .into()
    };

    let kernel =
        KernelDescriptor::from_hashes(vec![word(11, 12, 13, 14), word(21, 22, 23, 24)]).unwrap();
    let program_info = ProgramInfo::new(word(1, 2, 3, 4), kernel);
    let stack_inputs =
        StackInputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(6), Felt::new_unchecked(7)])
            .unwrap();
    let stack_outputs =
        StackOutputs::new(&[Felt::new_unchecked(8), Felt::new_unchecked(9)]).unwrap();
    let claim = ExecutionClaim::from_program_info(program_info, stack_inputs, stack_outputs);

    // stage the canonical 40-felt encoding into a claim region at CLAIM_PTR
    const CLAIM_PTR: u64 = 1000;
    let elements = claim.to_elements();
    let mut store_ops = String::new();
    for (i, chunk) in elements.chunks(4).enumerate() {
        // `push.e3.e2.e1.e0.addr mem_storew_le` stores [e0, e1, e2, e3] at addr..addr+4
        store_ops.push_str(&format!(
            "push.{}.{}.{}.{}.{} mem_storew_le dropw\n",
            chunk[3].as_canonical_u64(),
            chunk[2].as_canonical_u64(),
            chunk[1].as_canonical_u64(),
            chunk[0].as_canonical_u64(),
            CLAIM_PTR + 4 * i as u64,
        ));
    }

    let source = format!(
        "
        use miden::core::sys
        use miden::core::sys::vm::claim

        begin
            {store_ops}
            push.{CLAIM_PTR}
            exec.claim::claim_commitment
            exec.sys::truncate_stack
        end
        "
    );

    let mut expected: Vec<u64> =
        claim.commitment().as_elements().iter().map(Felt::as_canonical_u64).collect();
    expected.resize(16, 0);
    build_test!(source.as_str(), &[]).expect_stack(&expected);
}

/// The MASM `poseidon2::hash_elements_in_domain` must agree with the native implementation for
/// rate-aligned, unaligned, and empty inputs, exercising the kernel commitment's domain.
#[test]
fn hash_elements_in_domain_matches_native() {
    use miden_core::{Felt, chiplets::hasher};

    for num_elements in [0usize, 5, 8, 11, 16, 40] {
        let values: Vec<u64> = (1..=num_elements as u64).collect();
        let felts: Vec<Felt> = values.iter().map(|&v| Felt::new_unchecked(v)).collect();
        let domain = miden_core::program::KERNEL_DOMAIN_TAG;

        const PTR: u64 = 1000;
        let mut store_ops = String::new();
        let mut padded = values.clone();
        padded.resize(values.len().next_multiple_of(4).max(4), 0);
        for (i, chunk) in padded.chunks(4).enumerate() {
            store_ops.push_str(&format!(
                "push.{}.{}.{}.{}.{} mem_storew_le dropw\n",
                chunk[3],
                chunk[2],
                chunk[1],
                chunk[0],
                PTR + 4 * i as u64,
            ));
        }

        let source = format!(
            "
            use miden::core::sys
            use miden::core::crypto::hashes::poseidon2

            begin
                {store_ops}
                push.{domain_int}
                push.{num_elements}
                push.{PTR}
                exec.poseidon2::hash_elements_in_domain
                exec.sys::truncate_stack
            end
            ",
            domain_int = domain.as_canonical_u64(),
        );

        let mut expected: Vec<u64> = hasher::hash_elements_in_domain(&felts, domain)
            .as_elements()
            .iter()
            .map(Felt::as_canonical_u64)
            .collect();
        expected.resize(16, 0);
        build_test!(source.as_str(), &[]).expect_stack(&expected);
    }
}

/// The MASM `sys::vm::claim::request_key` must agree with the native `request_key` on the same
/// (verifier_root, claim_commitment) pair.
#[test]
fn masm_request_key_matches_native() {
    use miden_core::{Felt, Word, program::request_key};

    let word = |a: u64, b: u64, c: u64, d: u64| -> Word {
        [
            Felt::new_unchecked(a),
            Felt::new_unchecked(b),
            Felt::new_unchecked(c),
            Felt::new_unchecked(d),
        ]
        .into()
    };
    let verifier_root = word(101, 102, 103, 104);
    let claim_commitment = word(201, 202, 203, 204);

    // Push CLAIM_COMMITMENT then VERIFIER_ROOT so VERIFIER_ROOT ends on top (word 0).
    let push = |w: Word| -> String {
        let e = w.as_elements();
        format!(
            "push.{}.{}.{}.{}",
            e[3].as_canonical_u64(),
            e[2].as_canonical_u64(),
            e[1].as_canonical_u64(),
            e[0].as_canonical_u64()
        )
    };
    let source = format!(
        "
        use miden::core::sys
        use miden::core::sys::vm::claim

        begin
            {}
            {}
            exec.claim::request_key
            exec.sys::truncate_stack
        end
        ",
        push(claim_commitment),
        push(verifier_root),
    );

    let mut expected: Vec<u64> = request_key(verifier_root, claim_commitment)
        .as_elements()
        .iter()
        .map(Felt::as_canonical_u64)
        .collect();
    expected.resize(16, 0);
    build_test!(source.as_str(), &[]).expect_stack(&expected);
}

/// End-to-end request round-trip: the host registers a package stream under
/// `request_key(verifier_root, claim_commitment)`, and a consumer that holds only those two
/// words computes the same key and retrieves the stream with `adv.push_mapval`. Proves the
/// host helper and the MASM `request_key` address the same advice-map entry.
#[test]
fn request_round_trip_retrieves_registered_package() {
    use miden_core::{Felt, Word};
    use miden_utils_testing::recursive_verifier::request_key;

    let word = |a: u64, b: u64, c: u64, d: u64| -> Word {
        [
            Felt::new_unchecked(a),
            Felt::new_unchecked(b),
            Felt::new_unchecked(c),
            Felt::new_unchecked(d),
        ]
        .into()
    };
    let verifier_root = word(11, 12, 13, 14);
    let claim_commitment = word(21, 22, 23, 24);
    let stream: [Felt; 4] = [
        Felt::new_unchecked(100),
        Felt::new_unchecked(200),
        Felt::new_unchecked(300),
        Felt::new_unchecked(400),
    ];

    let key = request_key(verifier_root, claim_commitment);
    let values: Vec<Felt> = stream.to_vec();

    let push = |w: Word| -> String {
        let e = w.as_elements();
        format!(
            "push.{}.{}.{}.{}",
            e[3].as_canonical_u64(),
            e[2].as_canonical_u64(),
            e[1].as_canonical_u64(),
            e[0].as_canonical_u64()
        )
    };
    // Consumer holds (claim_commitment, verifier_root) from its own inputs; pushes them in the
    // request_key contract order (verifier on top), derives the key, fetches the stream, and
    // reads the four values back onto the operand stack.
    let source = format!(
        "
        use miden::core::sys
        use miden::core::sys::vm::claim

        begin
            {}
            {}
            exec.claim::request_key
            adv.push_mapval
            drop drop drop drop
            adv_push adv_push adv_push adv_push
            exec.sys::truncate_stack
        end
        ",
        push(claim_commitment),
        push(verifier_root),
    );

    // Map value the host registered under the request key.
    let advice_map = vec![(key, values)];
    let mut expected: Vec<u64> = stream.iter().map(Felt::as_canonical_u64).collect();
    expected.reverse(); // four adv_push results, top-first
    expected.resize(16, 0);
    build_test!(
        source.as_str(),
        &[],
        Vec::<u64>::new(),
        miden_utils_testing::crypto::MerkleStore::new(),
        advice_map
    )
    .expect_stack(&expected);
}

/// The MASM `sys::vm::conjectured_security_level` procedure must agree with the native
/// `miden_air::config::conjectured_security_level` on every input in the verifier's domain:
/// `num_queries` is effectively a `u8` (the generic verifier bounds it to `<= 150`) and
/// `query_pow_bits < 32`. One VM run evaluates the whole grid, storing the MASM level for
/// `(nq, pow)` at address `nq * POW_BOUND + pow`; the host then checks every cell against the
/// native value. This includes the calibration points (27, 16) -> 95 and (27, 17) -> 96.
#[test]
fn masm_conjectured_security_level_matches_native() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    const NQ_BOUND: u64 = 256;
    const POW_BOUND: u64 = 32;

    let source = format!(
        "
        use miden::core::sys::vm
        use miden::core::stark::constants

        begin
            push.0
            dup push.{NQ_BOUND} u32lt
            while.true
                # => [nq]
                push.0
                dup push.{POW_BOUND} u32lt
                while.true
                    # => [pow, nq]
                    dup.1 exec.constants::set_number_queries
                    dup exec.constants::set_query_pow_bits
                    exec.vm::conjectured_security_level
                    # => [level, pow, nq]
                    dup.2 push.{POW_BOUND} mul dup.2 add
                    # => [nq*POW_BOUND + pow, level, pow, nq]
                    mem_store
                    # => [pow, nq]
                    add.1
                    dup push.{POW_BOUND} u32lt
                end
                drop
                add.1
                dup push.{NQ_BOUND} u32lt
            end
            drop
        end
        "
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("estimator sweep execution failed");

    let ctx = ContextId::root();
    for nq in 0..NQ_BOUND {
        for pow in 0..POW_BOUND {
            let addr = (nq * POW_BOUND + pow) as u32;
            let masm = output
                .memory
                .read_element(ctx, Felt::new_unchecked(u64::from(addr)))
                .expect("every swept address is written")
                .as_canonical_u64();
            let native =
                u64::from(miden_air::config::conjectured_security_level(nq as u32, pow as u32));
            assert_eq!(masm, native, "mismatch at num_queries={nq}, query_pow_bits={pow}");
        }
    }
}

/// The security-level threshold the canonical `verify_vm_proof` wrapper applies
/// (`u32lt.TARGET assertz` over the attained level) must reject a below-target level and accept
/// an at-target one. This exercises the real estimator and threshold pattern; a full end-to-end
/// wrapper rejection would need a reduced-query proof, which the standard prover does not emit.
#[test]
fn security_level_threshold_rejects_below_target() {
    // Must match `CONJECTURED_SECURITY_TARGET` in `sys/vm/mod.masm`.
    const TARGET: u64 = 96;

    let source = format!(
        "
        use miden::core::sys::vm
        use miden::core::stark::constants

        begin
            exec.constants::set_number_queries
            exec.constants::set_query_pow_bits
            exec.vm::conjectured_security_level
            u32lt.{TARGET} assertz
        end
        "
    );

    // (22 queries, 16 pow) grades to 80 < 96: the threshold assert must fail.
    let below = build_test!(source.as_str(), &[22_u64, 16]);
    assert!(below.execute_for_output().is_err(), "a below-target level must be rejected");

    // (27 queries, 17 pow) grades to exactly 96: the threshold assert must pass.
    let at = build_test!(source.as_str(), &[27_u64, 17]);
    at.execute_for_output().expect("an at-target level must be accepted");
}
