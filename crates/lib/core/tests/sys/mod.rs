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

    let mut marked_rate_block = vec![0; 8];
    marked_rate_block[0] = 1;
    let cases = [
        vec![],
        vec![0; 8],
        marked_rate_block,
        (1..=5).collect(),
        (1..=8).collect(),
        (1..=11).collect(),
        (1..=16).collect(),
        (1..=40).collect(),
    ];

    for values in cases {
        let num_elements = values.len();
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

#[test]
fn element_hash_procedures_reject_non_u32_length() {
    use miden_processor::{ExecutionError, operation::OperationError};

    const NON_U32_LENGTH: u64 = u32::MAX as u64 + 1;
    const PTR: u64 = 1000;
    const ERROR_MSG: &str = "num_elements must fit in a u32";
    let expected_error_code = miden_core::mast::error_code_from_msg(ERROR_MSG);

    let invocations = [
        format!("push.0 push.{NON_U32_LENGTH} push.{PTR} exec.poseidon2::prepare_hasher_state"),
        format!("push.{NON_U32_LENGTH} push.{PTR} exec.poseidon2::hash_elements"),
        format!("push.1 push.{NON_U32_LENGTH} push.{PTR} exec.poseidon2::hash_elements_in_domain"),
        format!("push.{NON_U32_LENGTH} push.{PTR} exec.poseidon2::pad_and_hash_elements"),
    ];

    for invocation in invocations {
        let source = format!("use miden::core::crypto::hashes::poseidon2 begin {invocation} end");
        let test = build_test!(source.as_str(), &[]);
        let err = test.execute().expect_err("a non-u32 length must be rejected");
        match err {
            ExecutionError::OperationError {
                err: OperationError::U32AssertionFailed { err_code, .. },
                ..
            } => assert_eq!(err_code, expected_error_code),
            err => panic!("expected a u32 assertion failure, got {err:?}"),
        }
    }
}

/// The MASM `sys::build_proof_request_key` must agree with the native `proof_request_key` on the
/// same `(verifier_root, claim_commitment)` pair.
#[test]
fn masm_build_proof_request_key_matches_native() {
    use miden_core::{Felt, Word, program::proof_request_key};

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
        begin
            {}
            {}
            exec.sys::build_proof_request_key
            exec.sys::truncate_stack
        end
        ",
        push(claim_commitment),
        push(verifier_root),
    );

    let mut expected: Vec<u64> = proof_request_key(verifier_root, claim_commitment)
        .as_elements()
        .iter()
        .map(Felt::as_canonical_u64)
        .collect();
    expected.resize(16, 0);
    build_test!(source.as_str(), &[]).expect_stack(&expected);
}

/// End-to-end request round-trip: the host registers a package stream under
/// `proof_request_key(verifier_root, claim_commitment)`, and a consumer that holds only those
/// two words computes the same key and retrieves the stream with `adv.push_mapval`. Proves the
/// host helper and the MASM `build_proof_request_key` address the same advice-map entry.
#[test]
fn proof_request_round_trip_retrieves_registered_package() {
    use miden_core::{Felt, Word};
    use miden_utils_testing::recursive_verifier::proof_request_key;

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

    let key = proof_request_key(verifier_root, claim_commitment);
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
    // proof_request_key contract order (verifier on top), derives the key, fetches the stream, and
    // reads the four values back onto the operand stack.
    let source = format!(
        "
        use miden::core::sys
        begin
            {}
            dupw
            {}
            exec.sys::build_proof_request_key
            adv.push_mapval dropw
            {}
            assert_eqw
            adv_push adv_push adv_push adv_push
            exec.sys::truncate_stack
        end
        ",
        push(claim_commitment),
        push(verifier_root),
        push(claim_commitment),
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

/// The MASM `sys::vm::compute_conjectured_security_level` procedure must agree with the native
/// `miden_air::security::conjectured_security_level` on the swept inputs below. The two
/// implementations share no code — one is fixed-point Rust, the other hand-written integer MASM
/// over precomputed round bases — so this comparison is what establishes that a proof's computed
/// security level agrees whether it is verified natively or recursively.
///
/// The domain has six axes; this covers four two-dimensional slices of it, not the whole domain:
/// the query parameters against each other at the maximum trace height, where the height-bearing
/// rounds are largest and any underflow would surface; each grinding site against every supported
/// height; and the kernel procedure count (the lookup round's boundary correction) against every
/// supported height, its own trace-height-scaled term. Every round's calculation executes on every
/// swept input, but comparing only the returned minimum establishes exact arithmetic solely for
/// whichever round determines it under that slice's other axes — held fixed at the deployed
/// preset, so the lookup and query rounds are the ones actually checked here; a wrong composition,
/// out-of-domain, or folding literal would move no swept output. One VM run evaluates each grid,
/// storing the MASM level for `(outer, inner)` at address `outer * inner_bound + inner`; the host
/// then checks every cell.
#[test]
fn masm_compute_conjectured_security_level_matches_native() {
    use Axis::{Fixed, Inner, Outer};

    // `num_queries` is effectively a `u8` — the generic verifier bounds it to `<= 150` — and
    // grinding bit counts are below 32.
    const NQ_BOUND: u64 = 256;
    const POW_BOUND: u64 = 32;
    // Heights the verifier accepts, per `assert_shape_log`.
    const LOG_HEIGHT_MIN: u64 = 6;
    const LOG_HEIGHT_SPAN: u64 = 24;
    // Matches `KernelDescriptor::MAX_NUM_PROCEDURES`.
    const NUM_KERNEL_PROCEDURES_BOUND: u64 = 256;

    // The deployed preset, held fixed on whichever axes a sweep is not varying. Kernel procedure
    // count is held at its maximum off the dedicated sweep, to combine the boundary correction's
    // largest magnitude with the other axes' extremes.
    const QUERIES: u64 = 27;
    const QUERY_POW: u64 = 17;
    const DEEP_POW: u64 = 12;
    const FOLDING_POW: u64 = 4;
    const MAX_HEIGHT: u64 = LOG_HEIGHT_MIN + LOG_HEIGHT_SPAN - 1;
    const MAX_KERNEL_PROCEDURES: u64 = NUM_KERNEL_PROCEDURES_BOUND - 1;

    // Query count against query grinding, at the maximum supported height.
    sweep(
        NQ_BOUND,
        POW_BOUND,
        [
            Outer(0),
            Inner(0),
            Fixed(DEEP_POW),
            Fixed(FOLDING_POW),
            Fixed(MAX_HEIGHT),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // DEEP grinding against trace height.
    sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Inner(0),
            Fixed(FOLDING_POW),
            Outer(LOG_HEIGHT_MIN),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // Folding grinding against trace height.
    sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Fixed(DEEP_POW),
            Inner(0),
            Outer(LOG_HEIGHT_MIN),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // Kernel procedure count against trace height: the lookup round's boundary correction.
    sweep(
        LOG_HEIGHT_SPAN,
        NUM_KERNEL_PROCEDURES_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Fixed(DEEP_POW),
            Fixed(FOLDING_POW),
            Outer(LOG_HEIGHT_MIN),
            Inner(0),
        ],
    );
}

/// How one estimator input is supplied across a [`sweep`]: held at a constant, or taken from a
/// loop counter shifted by an offset.
#[derive(Copy, Clone)]
enum Axis {
    Fixed(u64),
    Inner(u64),
    Outer(u64),
}

impl Axis {
    /// MASM that pushes this input, given how deep the two loop counters currently sit.
    fn push(self, inner_depth: usize) -> String {
        match self {
            Self::Fixed(value) => format!("push.{value}"),
            Self::Inner(0) => format!("dup.{inner_depth}"),
            Self::Inner(offset) => format!("dup.{inner_depth} add.{offset}"),
            Self::Outer(0) => format!("dup.{}", inner_depth + 1),
            Self::Outer(offset) => format!("dup.{} add.{offset}", inner_depth + 1),
        }
    }

    /// The value this input takes at a given grid cell.
    fn value(self, outer: u64, inner: u64) -> u32 {
        let raw = match self {
            Self::Fixed(value) => value,
            Self::Inner(offset) => inner + offset,
            Self::Outer(offset) => outer + offset,
        };
        raw as u32
    }
}

/// Runs the estimator over an `outer_bound × inner_bound` grid in one VM execution and checks
/// every cell against the native implementation.
///
/// `axes` supplies the procedure's six inputs in call order. They are pushed deepest-first, so
/// each push sinks the loop counters one slot further and the `dup` depths shift accordingly.
fn sweep(outer_bound: u64, inner_bound: u64, axes: [Axis; 6]) {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let push_args = (0..6)
        .rev()
        .map(|position| axes[position].push(5 - position))
        .collect::<Vec<_>>()
        .join(" ");

    let source = format!(
        "
        use miden::core::sys::vm

        begin
            push.0
            dup push.{outer_bound} u32lt
            while.true
                # => [outer]
                push.0
                dup push.{inner_bound} u32lt
                while.true
                    # => [inner, outer]
                    {push_args}
                    # => [num_queries, query_pow, deep_pow, folding_pow, log_height,
                    #     num_kernel_procedures, inner, outer]
                    exec.vm::compute_conjectured_security_level
                    # => [level, inner, outer]
                    dup.2 push.{inner_bound} mul dup.2 add
                    # => [outer*inner_bound + inner, level, inner, outer]
                    mem_store
                    # => [inner, outer]
                    add.1
                    dup push.{inner_bound} u32lt
                end
                drop
                add.1
                dup push.{outer_bound} u32lt
            end
            drop
        end
        "
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("estimator sweep execution failed");

    let ctx = ContextId::root();
    for outer in 0..outer_bound {
        for inner in 0..inner_bound {
            let addr = (outer * inner_bound + inner) as u32;
            let masm = output
                .memory
                .read_element(ctx, Felt::new_unchecked(u64::from(addr)))
                .expect("every swept address is written")
                .as_canonical_u64();
            let native = u64::from(miden_air::security::conjectured_security_level(
                axes[0].value(outer, inner),
                axes[1].value(outer, inner),
                axes[2].value(outer, inner),
                axes[3].value(outer, inner),
                axes[4].value(outer, inner),
                axes[5].value(outer, inner),
            ));
            assert_eq!(
                masm,
                native,
                "mismatch at inputs {:?}",
                axes.map(|axis| axis.value(outer, inner))
            );
        }
    }
}

/// The estimator must trap on a log trace height outside `assert_shape_log`'s range rather than
/// compute a level from it: a consumer that `call`s `verify_vm_proof` instead of `exec`ing it
/// reads its own context's zeroed height slot, which would report six bits the proof has not
/// earned.
#[test]
fn security_level_rejects_an_out_of_range_trace_height() {
    let source = "
        use miden::core::sys::vm

        begin
            exec.vm::compute_conjectured_security_level
        end
        ";

    for log_height in [0_u64, 5, 30] {
        let test = build_test!(source, &[27_u64, 17, 12, 4, log_height, 0]);
        assert!(
            test.execute_for_output().is_err(),
            "log trace height {log_height} is outside the verifier's range and must be rejected"
        );
    }
}

/// A consumer's acceptance threshold (`u32lt.TARGET assertz` over the estimator's level) must
/// reject a below-target level and accept an at-target one. This exercises the estimator and
/// threshold in isolation; the stark e2e consumer tests apply the same threshold after a real
/// verification but cannot reach the reject arm, because the standard prover does not emit
/// reduced-query proofs.
#[test]
fn security_level_threshold_rejects_below_target() {
    // Same target as the stark e2e consumer program.
    const TARGET: u64 = 96;

    let source = format!(
        "
        use miden::core::sys::vm

        begin
            # Stack: the parameters returned by `verify_vm_proof`, then the proof's maximum AIR
            # log trace height, which the consumer reads from verifier-owned memory.
            exec.vm::compute_conjectured_security_level
            u32lt.{TARGET} assertz
        end
        "
    );

    // The deployed preset at a height below the lookup/query crossover computes to exactly the
    // target: the threshold assert must pass.
    let at = build_test!(source.as_str(), &[27_u64, 17, 12, 4, 20, 0]);
    at.execute_for_output().expect("an at-target level must be accepted");

    // Fewer queries and less grinding computes a level below the target: the threshold assert
    // must fail.
    let below = build_test!(source.as_str(), &[22_u64, 16, 12, 4, 20, 0]);
    assert!(below.execute_for_output().is_err(), "a below-target level must be rejected");

    // The same preset at the maximum supported height falls below the target on the lookup round
    // alone — the reason the computed level cannot be a property of the parameters by themselves.
    let tall = build_test!(source.as_str(), &[27_u64, 17, 12, 4, 29, 0]);
    assert!(tall.execute_for_output().is_err(), "a below-target level must be rejected");
}

/// The naive query-only estimate stays in `stark::utils` for the PVM settlement flow, which
/// has no round-budget mirror yet; this pins it until it gains one.
///
/// The MASM `stark::utils::conjectured_security_level` procedure must agree with the native
/// `miden_air::config::conjectured_security_level` on every input in the verifier's domain:
/// `num_queries` is effectively a `u8` (the generic verifier bounds it to `<= 150`) and
/// `query_pow_bits < 32`. One VM run evaluates the whole grid, storing the MASM level for
/// `(nq, pow)` at address `nq * POW_BOUND + pow`; the host then checks every cell against the
/// native value. This includes the calibration points
/// (27, 16) -> 95 and (27, 17) -> 96.
#[test]
fn masm_naive_query_estimate_matches_native() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    const NQ_BOUND: u64 = 256;
    const POW_BOUND: u64 = 32;

    let source = format!(
        "
        use miden::core::stark::utils

        begin
            push.0
            dup push.{NQ_BOUND} u32lt
            while.true
                # => [nq]
                push.0
                dup push.{POW_BOUND} u32lt
                while.true
                    # => [pow, nq]
                    dup dup.2
                    # => [nq, pow, pow, nq]
                    exec.utils::conjectured_security_level
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
