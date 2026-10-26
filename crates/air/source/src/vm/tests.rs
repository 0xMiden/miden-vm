//! VM shape, statement-binding, and kernel-boundary regression tests.

use alloc::{string::ToString, vec::Vec};

use miden_core::{
    WORD_SIZE, Word,
    field::{PrimeCharacteristicRing, QuadFelt},
    program::{KernelDescriptor, MIN_STACK_DEPTH, ProgramInfo, StackInputs, StackOutputs},
};
use miden_stark::lookup::Challenges;
use p3_challenger::CanObserve;

use super::{
    inputs::AUX_KERNEL_DIGESTS,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    *,
};

#[test]
fn core_shape_and_degree_match_design() {
    let air = MidenAir::CORE;
    let symbolic = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);

    assert_eq!(air.width(), 48);
    assert_eq!(constraints::columns::NUM_DECODER_COLS, 23);
    assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
    assert_eq!(symbolic, ConstraintDegrees { base: 9, ext: 9 });
    assert_eq!(
        LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
        symbolic,
        "Core's declared degree must match its handwritten constraints",
    );
    assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 3);
}

#[test]
fn and8_lookup_shape_and_degree_match_design() {
    let air = MidenAir::AND8_LOOKUP;

    assert_eq!(air.width(), 7);
    assert_eq!(air.preprocessed_width(), 5);
    assert_eq!(LiftedAir::<Felt, QuadFelt>::aux_width(&air), 4);
    assert_eq!(constraints::lookup::and8_lookup_air::AND8_LOOKUP_COLUMN_SHAPE, [1, 2, 2, 2],);
    assert_eq!(
        LiftedAir::<Felt, QuadFelt>::constraint_degree(&air),
        ConstraintDegrees { base: 0, ext: 3 }
    );
    assert_eq!(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air), 1);
}

#[test]
fn eval_external_weights_normalized_sums_by_trace_length() {
    let raw_challenges = [QuadFelt::from_u32(7), QuadFelt::from_u32(11)];
    let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
    let aux_inputs = vec![Felt::ZERO; AUX_KERNEL_DIGESTS];
    let normalized_sums = [
        QuadFelt::from_u32(13),
        QuadFelt::from_u32(17),
        QuadFelt::from_u32(19),
        QuadFelt::from_u32(23),
    ];
    let core_values = [normalized_sums[0]];
    let chiplets_values = [normalized_sums[1]];
    let eidos_compression_values = [normalized_sums[2]];
    let and8_values = [normalized_sums[3]];
    let aux_values: [&[QuadFelt]; MIDEN_AIR_COUNT] =
        [&core_values, &chiplets_values, &eidos_compression_values, &and8_values];
    let log_trace_heights = [6, 9, 7, 16];

    let lookup_challenges = Challenges::new(
        raw_challenges[0],
        raw_challenges[1],
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let mut boundary_correction = QuadFelt::ZERO;
    for air in AIRS {
        boundary_correction += air.boundary_correction(&lookup_challenges, &aux_inputs).unwrap();
    }

    let result = statement::eval_external(
        &raw_challenges,
        &air_inputs,
        &aux_inputs,
        &aux_values,
        &log_trace_heights,
    )
    .unwrap();

    let weighted_sum = normalized_sums
        .iter()
        .zip(log_trace_heights)
        .map(|(&value, log_height)| value * Felt::new_unchecked(1_u64 << u32::from(log_height)))
        .sum::<QuadFelt>();
    assert_eq!(result, vec![weighted_sum + boundary_correction]);
}

#[test]
fn eval_external_rejects_partial_kernel_digest() {
    let challenges =
        [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
    let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
    let mut aux_inputs = vec![Felt::ZERO; AUX_KERNEL_DIGESTS];
    aux_inputs.push(Felt::ONE);
    let zero = QuadFelt::from(Felt::ZERO);
    let core_aux = [zero];
    let chiplets_aux = [zero];
    let eidos_compression_aux = [zero];
    let and8_aux = [zero];
    let aux_values = [
        core_aux.as_slice(),
        chiplets_aux.as_slice(),
        eidos_compression_aux.as_slice(),
        and8_aux.as_slice(),
    ];

    let err = statement::eval_external(
        &challenges,
        &air_inputs,
        &aux_inputs,
        &aux_values,
        &[8, 8, 8, 16],
    )
    .unwrap_err();

    assert!(err.to_string().contains("kernel digest felts length 1 is not a multiple of 4"));
}

#[test]
fn eval_external_rejects_too_many_kernel_digests() {
    let challenges =
        [QuadFelt::from(Felt::new_unchecked(3)), QuadFelt::from(Felt::new_unchecked(5))];
    let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];
    let max_aux_inputs = AUX_KERNEL_DIGESTS + KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE;
    let actual_aux_inputs = max_aux_inputs + WORD_SIZE;
    let aux_inputs = vec![Felt::ZERO; actual_aux_inputs];
    let zero = QuadFelt::from(Felt::ZERO);
    let core_aux = [zero];
    let chiplets_aux = [zero];
    let eidos_compression_aux = [zero];
    let and8_aux = [zero];
    let aux_values = [
        core_aux.as_slice(),
        chiplets_aux.as_slice(),
        eidos_compression_aux.as_slice(),
        and8_aux.as_slice(),
    ];

    let err = statement::eval_external(
        &challenges,
        &air_inputs,
        &aux_inputs,
        &aux_values,
        &[8, 8, 8, 16],
    )
    .unwrap_err();

    assert!(err.to_string().contains(&format!(
        "aux_inputs length {actual_aux_inputs} exceeds maximum {max_aux_inputs}"
    )));
}

#[test]
fn hash_kernel_digests_matches_kernel_descriptor_commitment() {
    // The transcript-side helper and `KernelDescriptor::commitment` are two computations of
    // the same normative value; this pins them together (including the empty kernel).
    use miden_core::Word;

    let word = |a: u64| -> Word {
        [Felt::new_unchecked(a), Felt::new_unchecked(a + 1), Felt::ZERO, Felt::ONE].into()
    };
    for procs in [vec![], vec![word(10)], vec![word(10), word(20), word(30)]] {
        let descriptor = KernelDescriptor::from_hashes(procs).unwrap();
        let flattened: Vec<Felt> =
            descriptor.proc_hashes().iter().flat_map(|w| w.as_elements().to_vec()).collect();
        assert_eq!(
            Word::new(hash_kernel_digests(&flattened)),
            descriptor.commitment(),
            "hash_kernel_digests diverged from KernelDescriptor::commitment"
        );
    }
}

#[test]
#[should_panic(expected = "kernel digest felts exceed KernelDescriptor::MAX_NUM_PROCEDURES")]
fn hash_kernel_digests_rejects_too_many_digest_felts() {
    let kernel_felts = vec![Felt::ZERO; (KernelDescriptor::MAX_NUM_PROCEDURES + 1) * WORD_SIZE];

    let _ = hash_kernel_digests(&kernel_felts);
}

#[test]
fn observe_matches_execution_claim_commitment() {
    // The transcript's statement block must open with exactly
    // `ExecutionClaim::commitment()` for the same statement, followed by the deferred
    // root — pinning `observe`'s inline claim encoding to the canonical one.
    use miden_core::program::ExecutionClaim;

    #[derive(Default)]
    struct FeltSink {
        observed: Vec<Felt>,
    }
    impl CanObserve<Felt> for FeltSink {
        fn observe(&mut self, value: Felt) {
            self.observed.push(value);
        }
    }

    let word = |a: u64| -> Word {
        [
            Felt::new_unchecked(a),
            Felt::new_unchecked(a + 1),
            Felt::new_unchecked(a + 2),
            Felt::new_unchecked(a + 3),
        ]
        .into()
    };
    let kernel = KernelDescriptor::from_hashes(vec![word(50), word(60)]).unwrap();
    let program_hash = word(1);
    let stack_inputs = StackInputs::new(&[Felt::new_unchecked(5), Felt::new_unchecked(6)]).unwrap();
    let stack_outputs = StackOutputs::new(&[Felt::new_unchecked(7)]).unwrap();
    let deferred_root = word(90);

    let claim = ExecutionClaim::from_program_info(
        ProgramInfo::new(program_hash, kernel.clone()),
        stack_inputs,
        stack_outputs,
    );

    // air_inputs = I ‖ O; aux_inputs = P ‖ D ‖ kernel digest felts.
    let mut air_inputs = [Felt::ZERO; NUM_PUBLIC_VALUES];
    air_inputs[0..MIN_STACK_DEPTH].copy_from_slice(&stack_inputs[..]);
    air_inputs[MIN_STACK_DEPTH..].copy_from_slice(&stack_outputs[..]);
    let air_inputs = [air_inputs.to_vec(), vec![], vec![], vec![]];
    let mut aux_inputs: Vec<Felt> = Vec::new();
    aux_inputs.extend(program_hash.as_elements());
    aux_inputs.extend(deferred_root.as_elements());
    aux_inputs.extend(Word::words_as_elements(kernel.proc_hashes()));

    let mut sink = FeltSink::default();
    statement::observe(&mut sink, &air_inputs, &aux_inputs, &[10, 10, 10, 16]);

    let mut expected: Vec<Felt> = claim.commitment().as_elements().to_vec();
    expected.extend(deferred_root.as_elements());
    assert_eq!(sink.observed, expected, "observe must emit [CLAIM_HASH | D]");
}

#[test]
#[should_panic(expected = "aux inputs shorter than the fixed program-hash + deferred-root prefix")]
fn observe_rejects_short_aux_inputs() {
    #[derive(Default)]
    struct FeltSink {
        observed: Vec<Felt>,
    }

    impl CanObserve<Felt> for FeltSink {
        fn observe(&mut self, value: Felt) {
            self.observed.push(value);
        }
    }

    let mut challenger = FeltSink::default();
    let air_inputs = [vec![Felt::ZERO; NUM_PUBLIC_VALUES], vec![], vec![], vec![]];

    statement::observe(&mut challenger, &air_inputs, &[], &[8, 8, 8, 16]);
}
