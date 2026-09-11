//! Tests for the common MVM/PVM recursive security estimator.

use super::{
    EXAMPLE_FIB_SMALL, fib_stack_inputs, generate_recursive_verifier_data, vm_verify_proof_program,
};
use crate::support::security::{
    LOG_HEIGHT_MAX, MVM_LOG_HEIGHT_MIN, NUM_QUERIES_MAX, POW_BITS_MAX, PVM_LOG_HEIGHT_MIN,
};

#[test]
fn vm_verify_proof_rejects_oversized_num_queries() {
    let mut data = generate_recursive_verifier_data(EXAMPLE_FIB_SMALL, fib_stack_inputs(), None);
    data.proof_stream[0] = NUM_QUERIES_MAX + 1;

    let source = vm_verify_proof_program();
    let test = build_test!(
        source.as_str(),
        &data.initial_stack(),
        data.advice_stack(),
        data.store,
        data.advice_map
    );
    expect_assert_error_code_from_msg!(test, "num_queries must be at most 150");
}

/// The MVM lookup round must agree with the native estimator at every supported trace height and
/// kernel size. Query inputs are maximized so lookup determines the returned minimum at every
/// cell. The common query calculation is covered separately over its complete input domain.
#[test]
fn vm_lookup_round_matches_native_exhaustively() {
    use Axis::{Fixed, Inner, Outer};
    use miden_core::program::KernelDescriptor;

    const LOG_HEIGHT_SPAN: u64 = LOG_HEIGHT_MAX - MVM_LOG_HEIGHT_MIN + 1;
    const NUM_KERNEL_PROCEDURES_BOUND: u64 = KernelDescriptor::MAX_NUM_PROCEDURES as u64 + 1;

    vm_sweep(
        LOG_HEIGHT_SPAN,
        NUM_KERNEL_PROCEDURES_BOUND,
        [
            Fixed(NUM_QUERIES_MAX),
            Fixed(POW_BITS_MAX),
            Fixed(0),
            Fixed(0),
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

fn run_sweep_grid(adapter: &str, push_args: &str, outer_bound: u64, inner_bound: u64) -> Vec<u64> {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let source = format!(
        "
        use miden::core::stark::security

        {adapter}

        begin
            push.0
            dup push.{outer_bound} u32lt
            while.true
                push.0
                dup push.{inner_bound} u32lt
                while.true
                    {push_args}
                    exec.estimate
                    dup.2 push.{inner_bound} mul dup.2 add
                    mem_store
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

    let (output, _) = build_test!(source.as_str(), &[])
        .execute_for_output()
        .expect("estimator sweep execution failed");
    let ctx = ContextId::root();

    (0..outer_bound * inner_bound)
        .map(|address| {
            output
                .memory
                .read_element(ctx, Felt::new_unchecked(address))
                .expect("every swept address is written")
                .as_canonical_u64()
        })
        .collect()
}

/// Runs the estimator over an `outer_bound` by `inner_bound` grid in one VM execution and checks
/// every cell against the native implementation.
///
/// `axes` supplies the procedure's six inputs in call order. They are pushed deepest-first, so
/// each push sinks the loop counters one slot further and the `dup` depths shift accordingly.
fn vm_sweep(outer_bound: u64, inner_bound: u64, axes: [Axis; 6]) {
    use miden_air::security;

    let push_args = (0..6)
        .rev()
        .map(|position| axes[position].push(5 - position))
        .collect::<Vec<_>>()
        .join(" ");

    let adapter = format!(
        "
        proc estimate
            movup.5 add.{core_boundary_terms}
            movup.5 swap
            push.{fractions_per_row} swap
            push.{max_message_width}
            push.{num_deep_terms}
            push.{max_constraint_degree}
            push.{num_composed_constraints}
            push.{lookup_pow_bits}
            exec.security::compute_conjectured_security_level
        end
        ",
        lookup_pow_bits = security::LOOKUP_POW_BITS,
        max_message_width = security::AIR_SHAPE.lookup.max_message_width,
        num_composed_constraints = security::AIR_SHAPE.num_composed_constraints,
        max_constraint_degree = security::AIR_SHAPE.max_constraint_degree,
        num_deep_terms = security::AIR_SHAPE.num_deep_terms.unwrap(),
        fractions_per_row = security::AIR_SHAPE.lookup.fractions_per_row,
        core_boundary_terms = security::CORE_BOUNDARY_LOOKUP_TERMS,
    );
    let levels = run_sweep_grid(&adapter, &push_args, outer_bound, inner_bound);
    for outer in 0..outer_bound {
        for inner in 0..inner_bound {
            let masm = levels[(outer * inner_bound + inner) as usize];
            let native = u64::from(security::conjectured_security_level(
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
    lookup_pow_bits: u64,
    num_composed_constraints: u64,
    max_constraint_degree: u64,
    num_deep_terms: u64,
    max_message_width: u64,
    num_lookup_boundary_terms: u64,
    lookup_fractions_per_row: u64,
    log_max_height: u64,
    num_queries: u64,
    query_pow_bits: u64,
    deep_pow_bits: u64,
    folding_pow_bits: u64,
}

impl SecurityDescriptor {
    fn from_stack(fields: [u64; 12]) -> Self {
        Self {
            lookup_pow_bits: fields[0],
            num_composed_constraints: fields[1],
            max_constraint_degree: fields[2],
            num_deep_terms: fields[3],
            max_message_width: fields[4],
            num_lookup_boundary_terms: fields[5],
            lookup_fractions_per_row: fields[6],
            log_max_height: fields[7],
            num_queries: fields[8],
            query_pow_bits: fields[9],
            deep_pow_bits: fields[10],
            folding_pow_bits: fields[11],
        }
    }

    fn into_stack(self) -> [u64; 12] {
        [
            self.lookup_pow_bits,
            self.num_composed_constraints,
            self.max_constraint_degree,
            self.num_deep_terms,
            self.max_message_width,
            self.num_lookup_boundary_terms,
            self.lookup_fractions_per_row,
            self.log_max_height,
            self.num_queries,
            self.query_pow_bits,
            self.deep_pow_bits,
            self.folding_pow_bits,
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
        max_message_width: u64::from(security::AIR_SHAPE.lookup.max_message_width),
        num_composed_constraints: u64::from(security::AIR_SHAPE.num_composed_constraints),
        max_constraint_degree: u64::from(security::AIR_SHAPE.max_constraint_degree),
        num_deep_terms: u64::from(security::AIR_SHAPE.num_deep_terms.unwrap()),
        lookup_fractions_per_row: u64::from(security::AIR_SHAPE.lookup.fractions_per_row),
        num_lookup_boundary_terms: u64::from(
            security::CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
        ),
    }
    .into_stack()
}

/// Computes the native whole-bit level for a synthetic descriptor.
///
/// The MVM constructor supplies the shared PCS, field, and commitment settings. Every value carried
/// by the descriptor is then replaced with the synthetic test value.
fn native_level(descriptor: &SecurityDescriptor) -> u64 {
    use miden_air::{config, security};

    let mut params = security::proof_security_parameters(
        &config::pcs_params(),
        descriptor.log_max_height as u32,
        0,
        security::COMMITMENT_ALIGNMENT,
        128,
    );
    params.protocol_params.num_queries = descriptor.num_queries as u32;
    params.protocol_params.query_pow_bits = descriptor.query_pow_bits as u32;
    params.protocol_params.lookup_pow_bits = descriptor.lookup_pow_bits as u32;
    params.protocol_params.deep_pow_bits = descriptor.deep_pow_bits as u32;
    params.protocol_params.folding_pow_bits = descriptor.folding_pow_bits as u32;
    params.air_shape.num_composed_constraints = descriptor.num_composed_constraints as u32;
    params.air_shape.max_constraint_degree = descriptor.max_constraint_degree as u32;
    params.air_shape.num_deep_terms = Some(descriptor.num_deep_terms as u32);
    params.air_shape.lookup.fractions_per_row = descriptor.lookup_fractions_per_row as u32;
    params.air_shape.lookup.max_message_width = descriptor.max_message_width as u32;
    params.num_lookup_boundary_terms = descriptor.num_lookup_boundary_terms as u32;
    u64::from(params.conjectured_security_report().security_level())
}

fn run_estimator(descriptor: SecurityDescriptor) -> Result<u64, miden_processor::ExecutionError> {
    let source = "
        use miden::core::stark::security

        begin
            exec.security::compute_conjectured_security_level
        end
        ";
    build_test!(source, &descriptor.into_stack())
        .execute_for_output()
        .map(|(output, _)| output.stack.get_num_elements(1)[0].as_canonical_u64())
}

/// Exercises each branch used to compute the query and lookup terms.
///
/// These descriptors are synthetic, but all of them satisfy the estimator's input bounds. Each
/// comment derives the expected result, which is also checked against the native estimator. The
/// tests for the input bounds and native dominance calculation cover the five terms omitted by the
/// MASM procedure.
#[test]
fn common_security_estimator_wires_each_computed_round() {
    let baseline = SecurityDescriptor {
        num_queries: 150,
        query_pow_bits: 31,
        lookup_pow_bits: 0,
        deep_pow_bits: 31,
        folding_pow_bits: 31,
        log_max_height: 6,
        max_message_width: 255,
        num_composed_constraints: 1,
        max_constraint_degree: 0,
        num_deep_terms: 1,
        lookup_fractions_per_row: 1,
        num_lookup_boundary_terms: 0,
    };

    let cases = [
        // floor(7 * 193381 / 65536) + 0 = 20.
        (
            "query",
            SecurityDescriptor {
                num_queries: 7,
                query_pow_bits: 0,
                ..baseline
            },
            20,
        ),
        // A = 257 (the envelope floor): base = 127 - 9 - 6 = 112 and slack recovery fires. The
        // omitted rounds are at their least secure accepted values: composition and DEEP are 114
        // bits, OOD is 118 bits, and folding is 116 bits. Lookup remains the minimum at 113.
        (
            "dominated-round envelope corner",
            SecurityDescriptor {
                deep_pow_bits: 0,
                folding_pow_bits: 0,
                num_composed_constraints: 8192,
                max_constraint_degree: 9,
                num_deep_terms: 8192,
                ..baseline
            },
            113,
        ),
        // The MVM lookup shape at height 22: A = 504, b = 1477 + 11 = 1488, R = 1, so the slack
        // bound recovers the fractional bit exactly: 127 - 9 - 22 - 0 + 1 = 97.
        (
            "lookup with slack recovery",
            SecurityDescriptor {
                log_max_height: 22,
                max_message_width: 16,
                lookup_fractions_per_row: 28,
                num_lookup_boundary_terms: 258,
                ..baseline
            },
            97,
        ),
        // A synthetic envelope corner on the MVM lookup shape (deployed boundary terms reach
        // only 258): R = 216_110 = 3 * 65536 + 19_502, so r_w = 3 and the 1,488-unit slack
        // cannot cover the remainder: 127 - 9 - 6 - 3 + 0. The recovery is not universal on
        // this shape; it depends on the remainder.
        (
            "lookup with whole-bit correction and no recovery",
            SecurityDescriptor {
                max_message_width: 16,
                lookup_fractions_per_row: 28,
                num_lookup_boundary_terms: 4096,
                ..baseline
            },
            109,
        ),
        // The largest correction allowed by the envelope, combined with its largest coefficient:
        // A = 65_536 and R = 6_051_072 = 92 * 65_536 + 21_760 at height 6. Since A is a power of
        // two, no slack is recovered: 127 - 16 - 6 - 92.
        (
            "lookup at the correction bound",
            SecurityDescriptor {
                max_message_width: 65_534,
                lookup_fractions_per_row: 1,
                num_lookup_boundary_terms: 4096,
                ..baseline
            },
            13,
        ),
    ];

    for (binding_term, descriptor, expected_level) in cases {
        let actual = run_estimator(descriptor)
            .unwrap_or_else(|err| panic!("{binding_term} wiring probe failed: {err}"));
        assert_eq!(actual, expected_level, "unexpected result for {binding_term}");
        assert_eq!(
            native_level(&descriptor),
            expected_level,
            "{binding_term} probe expectation drifted from the native estimator"
        );
    }
}

/// Checks the conservative lookup approximation on shapes not produced by either verifier.
///
/// For some synthetic shapes, the lower bound on the logarithmic slack is too small to determine
/// whether the native calculation adds a fractional bit. The first three cases pin examples where
/// MASM returns exactly one bit less. The following grid checks that MASM never returns more than
/// the native estimator and never differs by more than one bit. Each grid point is checked against
/// the estimator's `base >= 2` requirement before execution. Unsupported inputs are tested
/// separately by `estimator_envelope_violations_trap`.
#[test]
fn slack_bound_never_overstates_and_loses_at_most_one_bit() {
    let case = |h, width, frac, boundary| SecurityDescriptor {
        num_queries: 150,
        query_pow_bits: 31,
        lookup_pow_bits: 0,
        deep_pow_bits: 31,
        folding_pow_bits: 31,
        log_max_height: h,
        max_message_width: width,
        num_composed_constraints: 1,
        max_constraint_degree: 0,
        num_deep_terms: 1,
        lookup_fractions_per_row: frac,
        num_lookup_boundary_terms: boundary,
    };

    for (descriptor, expected) in [
        (case(6, 8, 28, 1000), 112),
        (case(7, 8, 28, 2048), 111),
        (case(8, 8, 28, 4096), 110),
    ] {
        let actual = run_estimator(descriptor).expect("supported descriptor must execute");
        assert_eq!(actual, expected, "conservative test case changed");
        assert_eq!(
            native_level(&descriptor) - actual,
            1,
            "conservative test case must remain one bit below native"
        );
    }

    for h in [6, 17, 29] {
        for (width, frac) in
            [(255, 1), (16, 28), (18, 247), (30, 2048), (126, 512), (5, 9361), (98, 100)]
        {
            for boundary in [0, 1, 258, 4096] {
                let descriptor = case(h, width, frac, boundary);
                let coefficient = (width + 2) * frac;
                let q = u64::from(64 - (coefficient - 1).leading_zeros());
                let r_w = correction_fp(boundary, frac, h) >> 16;
                assert!(
                    127 - q - h >= r_w + 2,
                    "grid design error: h={h} width={width} frac={frac} boundary={boundary} is \
                     outside the estimator envelope"
                );
                let actual = run_estimator(descriptor).unwrap_or_else(|err| {
                    panic!("band case h={h} width={width} frac={frac} boundary={boundary}: {err}")
                });
                let native = native_level(&descriptor);
                assert!(
                    actual <= native,
                    "estimator overstates security at h={h} width={width} frac={frac} \
                     boundary={boundary}: {actual} > {native}"
                );
                assert!(
                    native - actual <= 1,
                    "estimator drifts more than one bit at h={h} width={width} frac={frac} \
                     boundary={boundary}: {actual} vs {native}"
                );
            }
        }
    }
}

/// Checks that each unsupported-input condition is rejected.
///
/// The arithmetic and the proof that five native terms may be omitted both rely on these bounds.
/// Returning a level outside them would make one of those arguments invalid.
#[test]
fn estimator_envelope_violations_trap() {
    let baseline = SecurityDescriptor {
        num_queries: 27,
        query_pow_bits: 17,
        lookup_pow_bits: 0,
        deep_pow_bits: 12,
        folding_pow_bits: 4,
        log_max_height: 22,
        max_message_width: 16,
        num_composed_constraints: 427,
        max_constraint_degree: 9,
        num_deep_terms: 138,
        lookup_fractions_per_row: 28,
        num_lookup_boundary_terms: 258,
    };
    assert!(run_estimator(baseline).is_ok(), "the baseline must be accepted");

    let cases = [
        ("lookup grinding", SecurityDescriptor { lookup_pow_bits: 1, ..baseline }),
        ("query count", SecurityDescriptor { num_queries: 151, ..baseline }),
        ("query grinding", SecurityDescriptor { query_pow_bits: 32, ..baseline }),
        ("DEEP grinding", SecurityDescriptor { deep_pow_bits: 32, ..baseline }),
        ("folding grinding", SecurityDescriptor { folding_pow_bits: 32, ..baseline }),
        ("trace height floor", SecurityDescriptor { log_max_height: 5, ..baseline }),
        ("trace height ceiling", SecurityDescriptor { log_max_height: 30, ..baseline }),
        (
            "constraint degree",
            SecurityDescriptor { max_constraint_degree: 10, ..baseline },
        ),
        (
            "zero composed constraints",
            SecurityDescriptor { num_composed_constraints: 0, ..baseline },
        ),
        (
            "composed constraints ceiling",
            SecurityDescriptor {
                num_composed_constraints: 8193,
                ..baseline
            },
        ),
        ("zero DEEP terms", SecurityDescriptor { num_deep_terms: 0, ..baseline }),
        ("DEEP terms ceiling", SecurityDescriptor { num_deep_terms: 8193, ..baseline }),
        (
            "boundary terms",
            SecurityDescriptor {
                num_lookup_boundary_terms: 4097,
                ..baseline
            },
        ),
        (
            "lookup coefficient floor",
            SecurityDescriptor {
                max_message_width: 254,
                lookup_fractions_per_row: 1,
                ..baseline
            },
        ),
        (
            "lookup message-width factor",
            SecurityDescriptor {
                max_message_width: 65535,
                lookup_fractions_per_row: 1,
                ..baseline
            },
        ),
        (
            "lookup fractions factor",
            SecurityDescriptor {
                lookup_fractions_per_row: 65537,
                ..baseline
            },
        ),
        (
            "lookup coefficient product",
            SecurityDescriptor {
                max_message_width: 254,
                lookup_fractions_per_row: 257,
                ..baseline
            },
        ),
        (
            "zero lookup coefficient",
            SecurityDescriptor { lookup_fractions_per_row: 0, ..baseline },
        ),
    ];
    for (bound, descriptor) in cases {
        assert!(run_estimator(descriptor).is_err(), "{bound} violation must trap");
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
}

/// Q16 lookup-boundary correction, mirroring `lookup_boundary_correction` in the estimator.
/// Used to place synthetic descriptors provably inside the envelope before executing them.
fn correction_fp(boundary: u64, frac: u64, h: u64) -> u64 {
    use miden_air::security as vm;
    if boundary == 0 {
        return 0;
    }
    (boundary * vm::LOG2_E).div_ceil(frac).div_ceil(1 << h)
}

/// Checks requirements shared by the MVM and PVM descriptors.
///
/// The verifier-specific drift tests check each AIR shape against the estimator's bounds. This
/// test checks that both relations use the same PCS constants, that the largest intermediate
/// values fit in u32, and that the lookup subtraction remains valid for both deployed shapes.
#[test]
fn recursive_verifier_ranges_fit_security_estimator_envelope() {
    use miden_air::security as vm;
    use miden_precompiles_air::{primitives::byte_pair_lut::TRACE_HEIGHT, security as pvm};

    assert_eq!(PVM_LOG_HEIGHT_MIN, TRACE_HEIGHT.ilog2() as u64);
    assert_eq!(vm::FIXED_POINT_FRACTIONAL_BITS, pvm::FIXED_POINT_FRACTIONAL_BITS);
    assert_eq!(vm::FIXED_POINT_ONE, pvm::FIXED_POINT_ONE);
    assert_eq!(vm::BITS_PER_QUERY, pvm::BITS_PER_QUERY);
    assert_eq!(vm::SECURITY_CAP, pvm::SECURITY_CAP);
    assert_eq!(vm::FOLDING_BASE, pvm::FOLDING_BASE);
    assert_eq!(vm::LOG2_E, pvm::LOG2_E);

    // u32 extremes of the estimator's arithmetic over its asserted envelope: the query product at
    // 150 queries, the correction numerator at 4,096 boundary terms, and the two slack products
    // at the largest gap a 65,536-bounded coefficient allows (g < 32,768, t1 < LOG2_E / 2).
    let u32_max = u64::from(u32::MAX);
    assert!(NUM_QUERIES_MAX * vm::BITS_PER_QUERY <= u32_max);
    assert!(4_096 * vm::LOG2_E <= u32_max);
    assert!(vm::LOG2_E * 32_767 <= u32_max);
    assert!((vm::LOG2_E / 2) * 32_767 <= u32_max);

    // A deliberately conservative check combines the maximum accepted height with the largest
    // correction, which occurs at the minimum accepted height. No reachable proof can have both
    // effects at once, so this lower-bounds the lookup base for each deployed relation.
    for (name, width, frac, boundary, h_min) in [
        (
            "MVM",
            u64::from(vm::AIR_SHAPE.lookup.max_message_width),
            u64::from(vm::AIR_SHAPE.lookup.fractions_per_row),
            u64::from(vm::CORE_BOUNDARY_LOOKUP_TERMS)
                + miden_core::program::KernelDescriptor::MAX_NUM_PROCEDURES as u64,
            MVM_LOG_HEIGHT_MIN,
        ),
        (
            "PVM",
            u64::from(pvm::AIR_SHAPE.lookup.max_message_width),
            u64::from(pvm::AIR_SHAPE.lookup.fractions_per_row),
            u64::from(pvm::FIXED_BOUNDARY_LOOKUP_TERMS),
            PVM_LOG_HEIGHT_MIN,
        ),
    ] {
        let coefficient = (width + 2) * frac;
        let q = u64::from(64 - (coefficient - 1).leading_zeros());
        let r_w = correction_fp(boundary, frac, h_min) >> 16;
        let field_whole_bits = vm::CHALLENGE_FIELD_BITS >> vm::FIXED_POINT_FRACTIONAL_BITS;
        let base = field_whole_bits - q - LOG_HEIGHT_MAX - r_w;
        assert!(base >= 2, "{name} lookup base leaves fewer than two bits for the correction");
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
    // alone. This is why the computed level cannot be a property of the parameters by themselves.
    let tall = build_test!(source.as_str(), &vm_security_descriptor(27, 17, 12, 4, 29, 0));
    assert!(tall.execute_for_output().is_err(), "a below-target level must be rejected");
}

/// The PVM lookup round must agree with the native estimator at every supported trace height.
/// Query inputs are maximized so lookup determines the returned minimum at every height.
#[test]
fn pvm_lookup_round_matches_native_exhaustively() {
    use Axis::{Fixed, Outer};
    use miden_precompiles_air::primitives::byte_pair_lut::TRACE_HEIGHT;

    const LOG_HEIGHT_SPAN: u64 = LOG_HEIGHT_MAX - PVM_LOG_HEIGHT_MIN + 1;

    assert_eq!(TRACE_HEIGHT.ilog2() as u64, PVM_LOG_HEIGHT_MIN);

    pvm_sweep(
        LOG_HEIGHT_SPAN,
        1,
        [
            Fixed(NUM_QUERIES_MAX),
            Fixed(POW_BITS_MAX),
            Fixed(0),
            Fixed(0),
            Outer(PVM_LOG_HEIGHT_MIN),
        ],
    );
}

#[test]
fn security_estimator_root_matches_procref() {
    use miden_core::Felt;
    use miden_processor::ContextId;

    let source = "
        begin
            procref.::miden::core::stark::security::compute_conjectured_security_level
            mem_storew_le.0 dropw
        end
    ";
    let expected: [u64; 4] = miden_core_lib::CoreLibrary::default()
        .conjectured_security_estimator_root()
        .into();
    let (output, _) = build_test!(source, &[])
        .execute_for_output()
        .expect("the estimator procref must execute");
    let actual = core::array::from_fn(|address| {
        output
            .memory
            .read_element(ContextId::root(), Felt::from_u32(address as u32))
            .expect("the procref word was stored")
            .as_canonical_u64()
    });

    assert_eq!(actual, expected);
}

/// Runs the PVM estimator over an `outer_bound × inner_bound` grid in one VM execution and checks
/// every cell against the native PVM implementation.
fn pvm_sweep(outer_bound: u64, inner_bound: u64, axes: [Axis; 5]) {
    use miden_precompiles_air::{security, stark_config::precompile_pcs_params};

    let push_args = (0..5)
        .rev()
        .map(|position| axes[position].push(4 - position))
        .collect::<Vec<_>>()
        .join(" ");

    let adapter = format!(
        "
        proc estimate
            movup.4
            push.{fractions_per_row}
            push.{boundary_terms}
            push.{max_message_width}
            push.{num_deep_terms}
            push.{max_constraint_degree}
            push.{num_composed_constraints}
            push.{lookup_pow_bits}
            exec.security::compute_conjectured_security_level
        end
        ",
        lookup_pow_bits = security::LOOKUP_POW_BITS,
        max_message_width = security::AIR_SHAPE.lookup.max_message_width,
        num_composed_constraints = security::AIR_SHAPE.num_composed_constraints,
        max_constraint_degree = security::AIR_SHAPE.max_constraint_degree,
        num_deep_terms = security::AIR_SHAPE.num_deep_terms.unwrap(),
        fractions_per_row = security::AIR_SHAPE.lookup.fractions_per_row,
        boundary_terms = security::FIXED_BOUNDARY_LOOKUP_TERMS,
    );
    let levels = run_sweep_grid(&adapter, &push_args, outer_bound, inner_bound);
    let pcs_params = precompile_pcs_params();

    for outer in 0..outer_bound {
        for inner in 0..inner_bound {
            let masm = levels[(outer * inner_bound + inner) as usize];

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

/// Runs the estimator over a grid of synthetic descriptors in one VM execution, varying two
/// descriptor fields, and checks every cell's returned minimum against the native estimator.
///
/// Field indices follow the descriptor order (0 = `lookup_pow_bits` .. 11 =
/// `folding_pow_bits`). Fields are pushed deepest-first, so when descriptor index `i`
/// is pushed, `11 - i` values already sit above the loop counters.
fn synthetic_sweep(
    template: SecurityDescriptor,
    (outer_field, outer_start, outer_bound): (usize, u64, u64),
    (inner_field, inner_start, inner_bound): (usize, u64, u64),
) {
    let fields = template.into_stack();
    let push_args = (0..12)
        .rev()
        .map(|i| {
            let depth = 11 - i;
            if i == outer_field {
                Axis::Outer(outer_start).push(depth)
            } else if i == inner_field {
                Axis::Inner(inner_start).push(depth)
            } else {
                format!("push.{}", fields[i])
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let adapter = "
        proc estimate
            exec.security::compute_conjectured_security_level
        end
    ";
    let levels = run_sweep_grid(adapter, &push_args, outer_bound, inner_bound);
    for outer in 0..outer_bound {
        for inner in 0..inner_bound {
            let mut descriptor_fields = fields;
            descriptor_fields[outer_field] = outer_start + outer;
            descriptor_fields[inner_field] = inner_start + inner;
            let descriptor = SecurityDescriptor::from_stack(descriptor_fields);

            let masm = levels[(outer * inner_bound + inner) as usize];
            assert_eq!(
                masm,
                native_level(&descriptor),
                "synthetic mismatch at outer field {outer_field} = {}, inner field \
                 {inner_field} = {}",
                outer_start + outer,
                inner_start + inner,
            );
        }
    }
}

/// Returns a synthetic shape whose lookup term has the largest value allowed by the estimator.
///
/// The coefficient and height use their lower bounds and there is no boundary correction, giving
/// a 113-bit lookup term. This lets the query term determine the result over as much of its input
/// range as the estimator permits.
fn minimal_synthetic_shape() -> SecurityDescriptor {
    SecurityDescriptor {
        num_queries: NUM_QUERIES_MAX,
        query_pow_bits: POW_BITS_MAX,
        lookup_pow_bits: 0,
        deep_pow_bits: POW_BITS_MAX,
        folding_pow_bits: POW_BITS_MAX,
        log_max_height: 6,
        max_message_width: 255,
        num_composed_constraints: 1,
        max_constraint_degree: 0,
        num_deep_terms: 1,
        lookup_fractions_per_row: 1,
        num_lookup_boundary_terms: 0,
    }
}

/// Every query count the estimator accepts against every grinding value, covering the complete
/// 151 x 32 domain on the minimal shape. The query term binds wherever it lies below the 113-bit
/// lookup ceiling; above it the lookup term bounds both implementations identically, so minimum
/// parity is checked at every cell.
#[test]
fn synthetic_query_grid_matches_native_exhaustively() {
    synthetic_sweep(
        minimal_synthetic_shape(),
        (8, 0, NUM_QUERIES_MAX + 1),
        (9, 0, POW_BITS_MAX + 1),
    );
}
