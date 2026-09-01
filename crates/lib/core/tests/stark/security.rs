//! Tests for the common MVM/PVM recursive security estimator.

use super::{
    EXAMPLE_FIB_SMALL, fib_stack_inputs, generate_recursive_verifier_data, verify_vm_proof_program,
};
use crate::support::security::{
    LOG_HEIGHT_MAX, MVM_LOG_HEIGHT_MIN, NUM_QUERIES_MAX, NUM_QUERIES_MIN, POW_BITS_MAX,
    PVM_LOG_HEIGHT_MIN,
};

#[test]
fn verify_vm_proof_rejects_oversized_num_queries() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    data.proof_stream[0] = NUM_QUERIES_MAX + 1;

    let source = verify_vm_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store,
        data.advice_map
    );
    expect_assert_error_code_from_msg!(test, "num_queries must be at most 150");
}

/// The common MASM security estimator, when given the MVM descriptor, must agree with the native
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
fn generic_security_estimator_matches_vm_native() {
    use Axis::{Fixed, Inner, Outer};
    use miden_core::program::KernelDescriptor;

    const NQ_SPAN: u64 = NUM_QUERIES_MAX - NUM_QUERIES_MIN + 1;
    const POW_BOUND: u64 = POW_BITS_MAX + 1;
    const LOG_HEIGHT_SPAN: u64 = LOG_HEIGHT_MAX - MVM_LOG_HEIGHT_MIN + 1;
    const NUM_KERNEL_PROCEDURES_BOUND: u64 = KernelDescriptor::MAX_NUM_PROCEDURES as u64 + 1;

    // The deployed preset, held fixed on whichever axes a sweep is not varying. Kernel procedure
    // count is held at its maximum off the dedicated sweep, to combine the boundary correction's
    // largest magnitude with the other axes' extremes.
    const QUERIES: u64 = 27;
    const QUERY_POW: u64 = 17;
    const DEEP_POW: u64 = 12;
    const FOLDING_POW: u64 = 4;
    const MAX_HEIGHT: u64 = LOG_HEIGHT_MAX;
    const MAX_KERNEL_PROCEDURES: u64 = NUM_KERNEL_PROCEDURES_BOUND - 1;

    // Query count against query grinding, at the maximum supported height.
    vm_sweep(
        NQ_SPAN,
        POW_BOUND,
        [
            Outer(NUM_QUERIES_MIN),
            Inner(0),
            Fixed(DEEP_POW),
            Fixed(FOLDING_POW),
            Fixed(MAX_HEIGHT),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // DEEP grinding against trace height.
    vm_sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Inner(0),
            Fixed(FOLDING_POW),
            Outer(MVM_LOG_HEIGHT_MIN),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // Folding grinding against trace height.
    vm_sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Fixed(DEEP_POW),
            Inner(0),
            Outer(MVM_LOG_HEIGHT_MIN),
            Fixed(MAX_KERNEL_PROCEDURES),
        ],
    );

    // Kernel procedure count against trace height: the lookup round's boundary correction.
    vm_sweep(
        LOG_HEIGHT_SPAN,
        NUM_KERNEL_PROCEDURES_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Fixed(DEEP_POW),
            Fixed(FOLDING_POW),
            Outer(MVM_LOG_HEIGHT_MIN),
            Inner(0),
        ],
    );
}

/// How one estimator input is supplied across [`vm_sweep`] or [`pvm_sweep`]: held at a constant, or
/// taken from a loop counter shifted by an offset.
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
fn vm_sweep(outer_bound: u64, inner_bound: u64, axes: [Axis; 6]) {
    use miden_air::security;
    use miden_core::Felt;
    use miden_processor::ContextId;

    let push_args = (0..6)
        .rev()
        .map(|position| axes[position].push(5 - position))
        .collect::<Vec<_>>()
        .join(" ");

    let source = format!(
        "
        use miden::core::stark::security

        proc estimate_vm
            # Insert the MVM fields around the six varying inputs.
            push.{lookup_pow_bits} movdn.2
            push.{lookup_base} movdn.6
            push.{composition_base} movdn.7
            push.{ood_base} movdn.8
            push.{deep_base} movdn.9
            push.{fractions_per_row} movdn.10
            movup.11 add.{core_boundary_terms} movdn.11
            exec.security::compute_conjectured_security_level
        end

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
                    exec.estimate_vm
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
        ",
        lookup_pow_bits = security::LOOKUP_POW_BITS,
        lookup_base = security::LOOKUP_BASE,
        composition_base = security::COMPOSITION_TERM,
        ood_base = security::OOD_BASE,
        deep_base = security::DEEP_BASE,
        fractions_per_row = security::AIR_SHAPE.lookup.fractions_per_row,
        core_boundary_terms = security::CORE_BOUNDARY_LOOKUP_TERMS,
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

#[derive(Copy, Clone)]
struct SecurityDescriptor {
    num_queries: u64,
    query_pow_bits: u64,
    lookup_pow_bits: u64,
    deep_pow_bits: u64,
    folding_pow_bits: u64,
    log_max_height: u64,
    lookup_base_fp: u64,
    composition_base_fp: u64,
    ood_base_fp: u64,
    deep_base_fp: u64,
    lookup_fractions_per_row: u64,
    num_lookup_boundary_terms: u64,
}

impl SecurityDescriptor {
    fn into_stack(self) -> [u64; 12] {
        [
            self.num_queries,
            self.query_pow_bits,
            self.lookup_pow_bits,
            self.deep_pow_bits,
            self.folding_pow_bits,
            self.log_max_height,
            self.lookup_base_fp,
            self.composition_base_fp,
            self.ood_base_fp,
            self.deep_base_fp,
            self.lookup_fractions_per_row,
            self.num_lookup_boundary_terms,
        ]
    }
}

fn vm_security_descriptor(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
) -> [u64; 12] {
    use miden_air::security;

    SecurityDescriptor {
        num_queries: u64::from(num_queries),
        query_pow_bits: u64::from(query_pow_bits),
        lookup_pow_bits: u64::from(security::LOOKUP_POW_BITS),
        deep_pow_bits: u64::from(deep_pow_bits),
        folding_pow_bits: u64::from(folding_pow_bits),
        log_max_height: u64::from(log_max_height),
        lookup_base_fp: security::LOOKUP_BASE,
        composition_base_fp: security::COMPOSITION_TERM,
        ood_base_fp: security::OOD_BASE,
        deep_base_fp: security::DEEP_BASE,
        lookup_fractions_per_row: u64::from(security::AIR_SHAPE.lookup.fractions_per_row),
        num_lookup_boundary_terms: u64::from(
            security::CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
        ),
    }
    .into_stack()
}

fn pvm_security_descriptor(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
) -> [u64; 12] {
    use miden_precompiles_air::security;

    SecurityDescriptor {
        num_queries: u64::from(num_queries),
        query_pow_bits: u64::from(query_pow_bits),
        lookup_pow_bits: u64::from(security::LOOKUP_POW_BITS),
        deep_pow_bits: u64::from(deep_pow_bits),
        folding_pow_bits: u64::from(folding_pow_bits),
        log_max_height: u64::from(log_max_height),
        lookup_base_fp: security::LOOKUP_BASE,
        composition_base_fp: security::COMPOSITION_TERM,
        ood_base_fp: security::OOD_BASE,
        deep_base_fp: security::DEEP_BASE,
        lookup_fractions_per_row: u64::from(security::AIR_SHAPE.lookup.fractions_per_row),
        num_lookup_boundary_terms: u64::from(security::FIXED_BOUNDARY_LOOKUP_TERMS),
    }
    .into_stack()
}

/// Synthetic descriptors below are not proof configurations. They make one term bind at a time so
/// a wrong stack index in the common estimator cannot hide behind the lookup/query minimum reached
/// by every real MVM and PVM descriptor.
#[test]
fn common_security_estimator_wires_every_round_and_cap() {
    use miden_air::security;

    let fp_one = security::FIXED_POINT_ONE;
    let cap = security::SECURITY_CAP;
    let baseline = SecurityDescriptor {
        num_queries: 40,
        query_pow_bits: 31,
        lookup_pow_bits: 0,
        deep_pow_bits: 31,
        folding_pow_bits: 31,
        log_max_height: 2,
        lookup_base_fp: cap + 4 * fp_one,
        composition_base_fp: cap,
        ood_base_fp: cap + 2 * fp_one,
        deep_base_fp: cap,
        lookup_fractions_per_row: 7,
        num_lookup_boundary_terms: 0,
    };

    let cases = [
        (
            "query",
            SecurityDescriptor {
                num_queries: 1,
                query_pow_bits: 0,
                ..baseline
            },
            2,
        ),
        (
            "lookup with boundary correction",
            SecurityDescriptor {
                // At height 6 the base contributes 70 bits before the maximum MVM correction.
                log_max_height: 6,
                lookup_base_fp: 76 * fp_one,
                lookup_fractions_per_row: 28,
                num_lookup_boundary_terms: 258,
                ..baseline
            },
            69,
        ),
        (
            "composition",
            SecurityDescriptor {
                composition_base_fp: 71 * fp_one,
                ..baseline
            },
            71,
        ),
        (
            "out of domain",
            SecurityDescriptor {
                // The OOD round subtracts the two-bit log height.
                ood_base_fp: 74 * fp_one,
                ..baseline
            },
            72,
        ),
        (
            "DEEP",
            SecurityDescriptor {
                deep_pow_bits: 0,
                deep_base_fp: 73 * fp_one,
                ..baseline
            },
            73,
        ),
        (
            "folding",
            SecurityDescriptor {
                // FOLDING_BASE_FP minus a two-bit log height truncates to 120 bits.
                folding_pow_bits: 0,
                ..baseline
            },
            120,
        ),
        ("collision cap", baseline, 127),
        (
            "lookup cap before boundary correction",
            SecurityDescriptor {
                // One bit above the cap, then a sub-bit correction, must truncate to 126.
                lookup_base_fp: cap + 3 * fp_one,
                num_lookup_boundary_terms: 1,
                ..baseline
            },
            126,
        ),
    ];

    let source = "
        use miden::core::stark::security
        begin
            exec.security::compute_conjectured_security_level
        end
    ";
    for (binding_term, descriptor, expected_level) in cases {
        let (output, _) = build_test!(source, &descriptor.into_stack())
            .execute_for_output()
            .unwrap_or_else(|err| panic!("{binding_term} wiring probe failed: {err}"));
        let actual = output.stack.get_num_elements(1)[0].as_canonical_u64();
        assert_eq!(actual, expected_level, "{binding_term} round is wired incorrectly");
    }
}

#[test]
fn common_security_estimator_preserves_the_caller_stack() {
    use miden_air::security;
    use miden_core::Felt;

    let descriptor = vm_security_descriptor(27, 17, 12, 4, 22, 255);
    let caller_values = [91_001, 91_002, 91_003, 91_004];
    let mut inputs = descriptor.to_vec();
    inputs.extend(caller_values);

    let source = "
        use miden::core::stark::security
        begin
            exec.security::compute_conjectured_security_level
        end
    ";
    let expected_level = u64::from(security::conjectured_security_level(27, 17, 12, 4, 22, 255));
    let mut expected = vec![expected_level];
    expected.extend(caller_values);
    let trace = build_test!(source, &inputs).execute().expect("the estimator must execute");
    let actual: Vec<u64> = trace
        .last_stack_state()
        .get_num_elements(expected.len())
        .iter()
        .map(Felt::as_canonical_u64)
        .collect();
    assert_eq!(actual, expected, "the estimator changed caller-owned stack values");

    let max_stack_depth = (0..trace.length())
        .map(|row| trace.main_trace().stack_depth(row.into()).as_canonical_u64())
        .max()
        .expect("the execution trace is non-empty");
    // The descriptor and four caller values start at depth 16. Keep transient use bounded to
    // eight more elements so future rewrites cannot introduce data-dependent stack growth.
    assert!(max_stack_depth <= 24, "estimator stack depth grew to {max_stack_depth}");
}

#[derive(Copy, Clone)]
struct RecursiveEstimatorEnvelope {
    relation: &'static str,
    min_log_height: u64,
    max_log_height: u64,
    lookup_pow_bits: u64,
    lookup_base: u64,
    composition_term: u64,
    ood_base: u64,
    deep_base: u64,
    fractions_per_row: u64,
    max_boundary_terms: u64,
}

/// Checks the monotonic extrema of every u32 operation over one verifier's accepted envelope.
fn assert_estimator_u32_envelope(envelope: RecursiveEstimatorEnvelope) {
    use miden_air::security;

    let u32_max = u64::from(u32::MAX);
    let assert_u32 = |name: &str, value: u64| {
        assert!(value <= u32_max, "{} {name} exceeds u32: {value}", envelope.relation);
    };

    assert!(envelope.min_log_height <= envelope.max_log_height);
    assert!(envelope.fractions_per_row > 0);
    assert!(envelope.max_boundary_terms > 0);
    assert!(envelope.lookup_pow_bits <= POW_BITS_MAX);

    for (name, value) in [
        ("fixed-point one", security::FIXED_POINT_ONE),
        ("bits per query", security::BITS_PER_QUERY),
        ("security cap", security::SECURITY_CAP),
        ("folding base", security::FOLDING_BASE),
        ("log2(e)", security::LOG2_E),
        ("lookup base", envelope.lookup_base),
        ("composition term", envelope.composition_term),
        ("OOD base", envelope.ood_base),
        ("DEEP base", envelope.deep_base),
        ("lookup fractions per row", envelope.fractions_per_row),
        ("lookup boundary terms", envelope.max_boundary_terms),
    ] {
        assert_u32(name, value);
    }

    let max_grinding = POW_BITS_MAX
        .checked_mul(security::FIXED_POINT_ONE)
        .expect("the fixed-point grinding term must fit u64");
    assert_u32("maximum fixed-point grinding term", max_grinding);

    let max_query_level = NUM_QUERIES_MAX
        .checked_mul(security::BITS_PER_QUERY)
        .and_then(|value| value.checked_add(max_grinding))
        .expect("the query term must fit u64");
    assert_u32("maximum query term", max_query_level);

    let lookup_grinding = envelope
        .lookup_pow_bits
        .checked_mul(security::FIXED_POINT_ONE)
        .expect("the lookup grinding term must fit u64");
    let boundary_numerator = envelope
        .max_boundary_terms
        .checked_mul(security::LOG2_E)
        .expect("the lookup boundary numerator must fit u64");
    assert_u32("lookup boundary numerator", boundary_numerator);

    let boundary_step = boundary_numerator.div_ceil(envelope.fractions_per_row);
    assert_u32("first lookup boundary quotient", boundary_step);

    for log_height in envelope.min_log_height..=envelope.max_log_height {
        let log_height_fp = log_height
            .checked_mul(security::FIXED_POINT_ONE)
            .expect("the fixed-point log height must fit u64");
        assert_u32("fixed-point log height", log_height_fp);

        let shift = u32::try_from(log_height).expect("a verifier height must fit u32");
        let domain_size = 1u64.checked_shl(shift).expect("the trace domain must fit u64");
        assert_u32("trace domain size", domain_size);

        let boundary_correction = boundary_step.div_ceil(domain_size);
        assert_u32("lookup boundary correction", boundary_correction);

        let lookup_before_correction = envelope
            .lookup_base
            .checked_sub(log_height_fp)
            .and_then(|value| value.checked_add(lookup_grinding))
            .expect("the lookup term must not underflow or overflow");
        assert_u32("lookup term before boundary correction", lookup_before_correction);
        let capped_lookup = lookup_before_correction.min(security::SECURITY_CAP);
        let lookup = capped_lookup
            .checked_sub(boundary_correction)
            .expect("the lookup boundary correction must not exceed the capped lookup term");
        assert_u32("lookup term", lookup);

        let ood = envelope
            .ood_base
            .checked_sub(log_height_fp)
            .expect("the OOD term must not underflow");
        assert_u32("OOD term", ood);

        let deep = envelope
            .deep_base
            .checked_add(max_grinding)
            .expect("the DEEP term must fit u64");
        assert_u32("maximum DEEP term", deep);

        let folding = security::FOLDING_BASE
            .checked_sub(log_height_fp)
            .and_then(|value| value.checked_add(max_grinding))
            .expect("the folding term must not underflow or overflow");
        assert_u32("maximum folding term", folding);
    }
}

#[test]
fn recursive_verifier_ranges_fit_security_estimator_u32_envelope() {
    use miden_air::security as vm;
    use miden_core::program::KernelDescriptor;
    use miden_precompiles_air::{primitives::byte_pair_lut::TRACE_HEIGHT, security as pvm};

    assert_eq!(PVM_LOG_HEIGHT_MIN, TRACE_HEIGHT.ilog2() as u64);
    assert_eq!(vm::FIXED_POINT_FRACTIONAL_BITS, pvm::FIXED_POINT_FRACTIONAL_BITS);
    assert_eq!(vm::FIXED_POINT_ONE, pvm::FIXED_POINT_ONE);
    assert_eq!(vm::BITS_PER_QUERY, pvm::BITS_PER_QUERY);
    assert_eq!(vm::SECURITY_CAP, pvm::SECURITY_CAP);
    assert_eq!(vm::FOLDING_BASE, pvm::FOLDING_BASE);
    assert_eq!(vm::LOG2_E, pvm::LOG2_E);

    assert_estimator_u32_envelope(RecursiveEstimatorEnvelope {
        relation: "MVM",
        min_log_height: MVM_LOG_HEIGHT_MIN,
        max_log_height: LOG_HEIGHT_MAX,
        lookup_pow_bits: u64::from(vm::LOOKUP_POW_BITS),
        lookup_base: vm::LOOKUP_BASE,
        composition_term: vm::COMPOSITION_TERM,
        ood_base: vm::OOD_BASE,
        deep_base: vm::DEEP_BASE,
        fractions_per_row: vm::AIR_SHAPE.lookup.fractions_per_row.into(),
        max_boundary_terms: u64::from(vm::CORE_BOUNDARY_LOOKUP_TERMS)
            + KernelDescriptor::MAX_NUM_PROCEDURES as u64,
    });
    assert_estimator_u32_envelope(RecursiveEstimatorEnvelope {
        relation: "PVM",
        min_log_height: PVM_LOG_HEIGHT_MIN,
        max_log_height: LOG_HEIGHT_MAX,
        lookup_pow_bits: u64::from(pvm::LOOKUP_POW_BITS),
        lookup_base: pvm::LOOKUP_BASE,
        composition_term: pvm::COMPOSITION_TERM,
        ood_base: pvm::OOD_BASE,
        deep_base: pvm::DEEP_BASE,
        fractions_per_row: pvm::AIR_SHAPE.lookup.fractions_per_row.into(),
        max_boundary_terms: u64::from(pvm::FIXED_BOUNDARY_LOOKUP_TERMS),
    });
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
        use miden::core::stark::security

        begin
            exec.security::compute_conjectured_security_level
            u32lt.{TARGET} assertz
        end
        "
    );

    // The deployed preset at a height below the lookup/query crossover computes to exactly the
    // target: the threshold assert must pass.
    let at = build_test!(source.as_str(), &vm_security_descriptor(27, 17, 12, 4, 20, 0));
    at.execute_for_output().expect("an at-target level must be accepted");

    // Fewer queries and less grinding computes a level below the target: the threshold assert
    // must fail.
    let below = build_test!(source.as_str(), &vm_security_descriptor(22, 16, 12, 4, 20, 0));
    assert!(below.execute_for_output().is_err(), "a below-target level must be rejected");

    // The same preset at the maximum supported height falls below the target on the lookup round
    // alone — the reason the computed level cannot be a property of the parameters by themselves.
    let tall = build_test!(source.as_str(), &vm_security_descriptor(27, 17, 12, 4, 29, 0));
    assert!(tall.execute_for_output().is_err(), "a below-target level must be rejected");
}

/// The common MASM security estimator, when given the PVM descriptor, must agree with the native
/// PVM round budget. As on the VM side, the constant-drift test checks every algebraic-round
/// literal; this output sweep checks the complete computation over slices of its input domain.
#[test]
fn generic_security_estimator_matches_pvm_native() {
    use Axis::{Fixed, Inner, Outer};
    use miden_precompiles_air::primitives::byte_pair_lut::TRACE_HEIGHT;

    const NQ_SPAN: u64 = NUM_QUERIES_MAX - NUM_QUERIES_MIN + 1;
    const POW_BOUND: u64 = POW_BITS_MAX + 1;
    const LOG_HEIGHT_SPAN: u64 = LOG_HEIGHT_MAX - PVM_LOG_HEIGHT_MIN + 1;

    assert_eq!(TRACE_HEIGHT.ilog2() as u64, PVM_LOG_HEIGHT_MIN);

    const QUERIES: u64 = 27;
    const QUERY_POW: u64 = 17;
    const DEEP_POW: u64 = 12;
    const FOLDING_POW: u64 = 4;
    const MAX_HEIGHT: u64 = LOG_HEIGHT_MAX;

    // Query count against query grinding, at the maximum supported height.
    pvm_sweep(
        NQ_SPAN,
        POW_BOUND,
        [
            Outer(NUM_QUERIES_MIN),
            Inner(0),
            Fixed(DEEP_POW),
            Fixed(FOLDING_POW),
            Fixed(MAX_HEIGHT),
        ],
    );

    // DEEP grinding against every supported PVM maximum trace height.
    pvm_sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Inner(0),
            Fixed(FOLDING_POW),
            Outer(PVM_LOG_HEIGHT_MIN),
        ],
    );

    // Folding grinding against every supported PVM maximum trace height.
    pvm_sweep(
        LOG_HEIGHT_SPAN,
        POW_BOUND,
        [
            Fixed(QUERIES),
            Fixed(QUERY_POW),
            Fixed(DEEP_POW),
            Inner(0),
            Outer(PVM_LOG_HEIGHT_MIN),
        ],
    );
}

#[test]
fn generic_security_estimator_matches_vm_and_pvm_reference_vectors() {
    use miden_air::security as vm_security;
    use miden_precompiles_air::security as pvm_security;

    let source = "
        use miden::core::stark::security

        begin
            exec.security::compute_conjectured_security_level
        end
        ";

    let vm_params = vm_security_descriptor(27, 17, 12, 4, 22, 255);
    let vm_expected = vm_security::conjectured_security_level(27, 17, 12, 4, 22, 255);
    build_test!(source, &vm_params).expect_stack(&[u64::from(vm_expected)]);

    let pvm_params = pvm_security_descriptor(27, 17, 12, 4, 19);
    let pvm_params_native = miden_precompiles_air::security::protocol_params(
        &miden_precompiles_air::stark_config::precompile_pcs_params(),
    );
    let pvm_expected = pvm_security::security_report(&pvm_params_native, 19).security_level();
    build_test!(source, &pvm_params).expect_stack(&[u64::from(pvm_expected)]);
}

/// Runs the PVM estimator over an `outer_bound × inner_bound` grid in one VM execution and checks
/// every cell against the native PVM implementation.
fn pvm_sweep(outer_bound: u64, inner_bound: u64, axes: [Axis; 5]) {
    use miden_core::Felt;
    use miden_precompiles_air::{security, stark_config::precompile_pcs_params};
    use miden_processor::ContextId;

    let push_args = (0..5)
        .rev()
        .map(|position| axes[position].push(4 - position))
        .collect::<Vec<_>>()
        .join(" ");

    let source = format!(
        "
        use miden::core::stark::security

        proc estimate_pvm
            # Insert the PVM fields around the five varying inputs.
            push.{lookup_pow_bits} movdn.2
            push.{lookup_base} movdn.6
            push.{composition_base} movdn.7
            push.{ood_base} movdn.8
            push.{deep_base} movdn.9
            push.{fractions_per_row} movdn.10
            push.{boundary_terms} movdn.11
            exec.security::compute_conjectured_security_level
        end

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
                    # => [num_queries, query_pow, deep_pow, folding_pow, log_height, inner, outer]
                    exec.estimate_pvm
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
        ",
        lookup_pow_bits = security::LOOKUP_POW_BITS,
        lookup_base = security::LOOKUP_BASE,
        composition_base = security::COMPOSITION_TERM,
        ood_base = security::OOD_BASE,
        deep_base = security::DEEP_BASE,
        fractions_per_row = security::AIR_SHAPE.lookup.fractions_per_row,
        boundary_terms = security::FIXED_BOUNDARY_LOOKUP_TERMS,
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("PVM estimator sweep execution failed");
    let pcs_params = precompile_pcs_params();

    let ctx = ContextId::root();
    for outer in 0..outer_bound {
        for inner in 0..inner_bound {
            let addr = (outer * inner_bound + inner) as u32;
            let masm = output
                .memory
                .read_element(ctx, Felt::new_unchecked(u64::from(addr)))
                .expect("every swept address is written")
                .as_canonical_u64();

            let mut params = security::protocol_params(&pcs_params);
            params.num_queries = axes[0].value(outer, inner);
            params.query_pow_bits = axes[1].value(outer, inner);
            params.deep_pow_bits = axes[2].value(outer, inner);
            params.folding_pow_bits = axes[3].value(outer, inner);
            let log_height = axes[4].value(outer, inner);
            let native = u64::from(security::security_report(&params, log_height).security_level());

            assert_eq!(
                masm,
                native,
                "PVM mismatch at inputs {:?}",
                axes.map(|axis| axis.value(outer, inner))
            );
        }
    }
}

/// A common 96-bit policy accepts the deployed PVM preset at height 16, but rejects it once the
/// lookup round lowers the conjectured level to 95 bits at height 20.
#[test]
fn pvm_security_level_threshold_rejects_a_tall_trace() {
    let source = "
        use miden::core::stark::security

        begin
            exec.security::compute_conjectured_security_level
            u32lt.96 assertz
        end
        ";

    let at_target = build_test!(source, &pvm_security_descriptor(27, 17, 12, 4, 16));
    at_target.execute_for_output().expect("a 96-bit PVM proof must be accepted");

    let below_target = build_test!(source, &pvm_security_descriptor(27, 17, 12, 4, 20));
    assert!(
        below_target.execute_for_output().is_err(),
        "a 95-bit PVM proof must be rejected"
    );
}

/// The legacy query-only estimate remains in `stark::utils` for callers that explicitly need it.
///
/// The MASM `stark::utils::conjectured_security_level` procedure must agree with the native
/// `miden_air::config::conjectured_security_level` on every input in the verifier's domain:
/// `num_queries` is in `7..=150` and `query_pow_bits` is in `0..=31`. One VM run evaluates the
/// whole grid, storing the MASM level for `(nq_offset, pow)` at address
/// `nq_offset * POW_BOUND + pow`; the host then checks every cell against the native value. This
/// includes the calibration points (27, 16) -> 95 and (27, 17) -> 96.
#[test]
fn masm_naive_query_estimate_matches_native() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    const NQ_SPAN: u64 = NUM_QUERIES_MAX - NUM_QUERIES_MIN + 1;
    const POW_BOUND: u64 = POW_BITS_MAX + 1;

    let source = format!(
        "
        use miden::core::stark::utils

        begin
            push.0
            dup push.{NQ_SPAN} u32lt
            while.true
                # => [nq_offset]
                push.0
                dup push.{POW_BOUND} u32lt
                while.true
                    # => [pow, nq_offset]
                    dup dup.2 add.{NUM_QUERIES_MIN}
                    # => [nq, pow, pow, nq_offset]
                    exec.utils::conjectured_security_level
                    # => [level, pow, nq_offset]
                    dup.2 push.{POW_BOUND} mul dup.2 add
                    # => [nq_offset*POW_BOUND + pow, level, pow, nq_offset]
                    mem_store
                    # => [pow, nq_offset]
                    add.1
                    dup push.{POW_BOUND} u32lt
                end
                drop
                add.1
                dup push.{NQ_SPAN} u32lt
            end
            drop
        end
        "
    );

    let test = build_test!(source.as_str(), &[]);
    let (output, _host) = test.execute_for_output().expect("estimator sweep execution failed");

    let ctx = ContextId::root();
    for nq_offset in 0..NQ_SPAN {
        for pow in 0..POW_BOUND {
            let addr = (nq_offset * POW_BOUND + pow) as u32;
            let masm = output
                .memory
                .read_element(ctx, Felt::new_unchecked(u64::from(addr)))
                .expect("every swept address is written")
                .as_canonical_u64();
            let nq = nq_offset + NUM_QUERIES_MIN;
            let native =
                u64::from(miden_air::config::conjectured_security_level(nq as u32, pow as u32));
            assert_eq!(masm, native, "mismatch at num_queries={nq}, query_pow_bits={pow}");
        }
    }
}
