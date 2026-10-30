//! Tests and cross-checks for the MASM recursive verifier's ACE input vector.
//!
//! The check extracts the flat ACE input vector from memory, verifies its structural and selector
//! invariants, and evaluates the same ACE circuit in Rust.

use miden_ace::{
    InputKey, InputLayout,
    compiler::{AceConfig, LayoutKind},
};
use miden_air::vm::{MIDEN_AIR_COUNT, config};
use miden_air_definitions::compiler::vm::build_canonical_multi_air_ace_circuit;
use miden_core::{
    Felt,
    field::{BasedVectorSpace, PrimeCharacteristicRing, QuadFelt, TwoAdicField},
};
use miden_core_lib::CoreLibrary;
use miden_crypto::field::Field;
use miden_processor::{ContextId, DefaultHost, ExecutionOptions, FastProcessor, StackInputs};
use miden_stark::{quotient_recomposition_inputs, testing::canonical_domain};
use miden_utils_testing::Test;
use rstest::rstest;

use super::{
    vm_layout_const,
    vm_scatter_bench::{RowGeometry, expected_frame_memory, proof_order},
};
use crate::helpers::{masm_store_felts, read_memory_felt, stark_constant};

pub(super) fn assert_proof_stream_read_sections(
    read: &impl Fn(u32) -> Felt,
    proof_stream: &[u64],
    claim: &[u64],
) {
    const MAIN_OFFSET: usize = 11;
    const AUX_COMMIT_OFFSET: usize = 15;
    const AUX_VALUES_OFFSET: usize = 19;
    const QUOTIENT_COMMIT_OFFSET: usize = 27;
    const OOD_OFFSET: usize = 33;
    let ood_evaluations_ptr = vm_layout_const("OOD_EVALUATIONS_PTR");
    let aux_bus_boundary_ptr = vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    let ood_felts = usize::try_from(aux_bus_boundary_ptr - ood_evaluations_ptr)
        .expect("OOD frame size fits usize");

    let public_ptr = read(stark_constant("PUBLIC_INPUTS_ADDRESS_PTR")).as_canonical_u64() as u32;
    for i in 0..32 {
        assert_eq!(
            read(public_ptr + 2 * i as u32),
            Felt::new_unchecked(claim[8 + i]),
            "public input {i} differs from the authenticated claim"
        );
        assert_eq!(
            read(public_ptr + 2 * i as u32 + 1),
            Felt::ZERO,
            "public input {i} has a nonzero extension coordinate"
        );
    }

    for (memory, stream) in [
        (stark_constant("MAIN_TRACE_COM_PTR"), MAIN_OFFSET),
        (stark_constant("AUX_TRACE_COM_PTR"), AUX_COMMIT_OFFSET),
        (stark_constant("COMPOSITION_POLY_COM_PTR"), QUOTIENT_COMMIT_OFFSET),
    ] {
        for i in 0..4 {
            assert_eq!(
                read(memory + i as u32),
                Felt::new_unchecked(proof_stream[stream + i]),
                "commitment stream mismatch at memory {memory}, limb {i}"
            );
        }
    }
    // The proof submits both the boundary values and the trace segments in the height-sorted
    // proof order, and the verifier scatters them to the canonical addresses the ACE circuit
    // reads. Both oracles below are computed from the wire stream through that permutation, so
    // a scatter that dropped, duplicated, or mis-targeted a segment fails here.
    let order = proof_order(&staged_log_heights(read));

    for (position, &air) in order.iter().enumerate() {
        for coordinate in 0..2 {
            assert_eq!(
                read(aux_bus_boundary_ptr + (2 * air + coordinate) as u32),
                Felt::new_unchecked(proof_stream[AUX_VALUES_OFFSET + 2 * position + coordinate]),
                "aux-boundary value from proof position {position} is not at AIR {air}"
            );
        }
    }

    let geometry = RowGeometry::vm();
    assert_eq!(
        ood_felts,
        2 * geometry.row_felts() as usize,
        "the OOD region no longer holds exactly the two-row frame"
    );
    let wire: Vec<Felt> = proof_stream[OOD_OFFSET..OOD_OFFSET + ood_felts]
        .iter()
        .map(|value| Felt::new_unchecked(*value))
        .collect();
    let expected = expected_frame_memory(&geometry, &order, &wire);
    for (i, expected) in expected.iter().enumerate() {
        assert_eq!(
            read(ood_evaluations_ptr + i as u32).as_canonical_u64(),
            *expected,
            "OOD felt {i} is not the value the scatter must place there"
        );
    }
}

/// The per-AIR log heights `load_air_context` staged, in canonical instance order.
fn staged_log_heights(read: &impl Fn(u32) -> Felt) -> Vec<u64> {
    (0..MIDEN_AIR_COUNT as u32)
        .map(|air| read(stark_constant("LOG_AIR_TRACE_LENGTHS_PTR") + air).as_canonical_u64())
        .collect()
}

#[test]
fn ace_read_pointers_match_masm_layout() {
    let aux_rand_elem_ptr = vm_layout_const("AUX_RAND_ELEM_PTR");
    let ood_evaluations_ptr = vm_layout_const("OOD_EVALUATIONS_PTR");
    let aux_bus_boundary_ptr = vm_layout_const("AUX_BUS_BOUNDARY_PTR");
    let auxiliary_ace_inputs_ptr = vm_layout_const("AUXILIARY_ACE_INPUTS_PTR");
    let ace_circuit_stream_ptr = vm_layout_const("ACE_CIRCUIT_STREAM_PTR");
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };
    let circuit = build_canonical_multi_air_ace_circuit(config).expect("canonical ACE circuit");
    let layout = circuit.layout();

    let beta = layout.index(InputKey::AuxRandBeta).expect("aux randomness beta");
    let alpha = layout.index(InputKey::AuxRandAlpha).expect("aux randomness alpha");
    let preprocessed_curr = layout
        .index(InputKey::Preprocessed { offset: 0, index: 0 })
        .expect("preprocessed curr");
    let aux_bus = layout.index(InputKey::AuxBusBoundary(0)).expect("aux bus boundary");
    let stark_vars = layout.index(InputKey::Alpha).expect("stark vars");

    assert_eq!(alpha, beta + 1);
    assert_eq!(ood_evaluations_ptr - aux_rand_elem_ptr, 2 * (preprocessed_curr - beta) as u32);
    assert_eq!(
        aux_bus_boundary_ptr - ood_evaluations_ptr,
        2 * (aux_bus - preprocessed_curr) as u32
    );
    assert_eq!(
        auxiliary_ace_inputs_ptr - aux_bus_boundary_ptr,
        2 * (stark_vars - aux_bus) as u32
    );
    assert_eq!(
        ace_circuit_stream_ptr - auxiliary_ace_inputs_ptr,
        2 * (layout.total_inputs - stark_vars) as u32,
        "ACE inputs and circuit constants must be contiguous"
    );
}

// EXTRACTION
// ================================================================================================

/// Extract the ACE READ section from MASM memory into a flat input vector.
///
/// Each pair of consecutive base felts forms one extension field element.
/// The returned vector has `layout.total_inputs` entries.
fn extract_ace_inputs(read: &impl Fn(u32) -> Felt, layout: &InputLayout) -> Vec<QuadFelt> {
    let pi_ptr = read(stark_constant("PUBLIC_INPUTS_ADDRESS_PTR")).as_canonical_u64() as u32;
    let aux_rand_elem_ptr = vm_layout_const("AUX_RAND_ELEM_PTR");

    assert!(
        pi_ptr < aux_rand_elem_ptr,
        "pi_ptr ({pi_ptr}) >= AUX_RAND_ELEM_PTR ({aux_rand_elem_ptr})"
    );

    (0..layout.total_inputs)
        .map(|i| {
            let addr = pi_ptr + (i as u32) * 2;
            let c0 = read(addr);
            let c1 = read(addr + 1);
            QuadFelt::new([c0, c1])
        })
        .collect()
}

/// The proof order the verifier staged.
///
/// `stage_proof_order_maps` derives `pos_by_id` and `id_by_pos` from the transcript-bound per-AIR
/// heights. Scatter staging, boundary placement, and fold-coefficient staging read those maps.
/// This helper checks both maps against the Rust ordering before extracting the ACE inputs.
fn extract_order(read: &impl Fn(u32) -> Felt) -> Vec<usize> {
    let order = proof_order(&staged_log_heights(read));

    let positions_ptr = vm_layout_const("PROOF_ORDER_POSITIONS_PTR");
    let ids_ptr = vm_layout_const("PROOF_ORDER_IDS_PTR");
    for (position, &id) in order.iter().enumerate() {
        assert_eq!(
            read(positions_ptr + id as u32).as_canonical_u64(),
            position as u64,
            "staged pos_by_id[{id}] disagrees with the Rust ranking of the staged heights"
        );
        assert_eq!(
            read(ids_ptr + position as u32).as_canonical_u64(),
            id as u64,
            "staged id_by_pos[{position}] disagrees with the Rust ranking of the staged heights"
        );
    }
    order
}

// INPUT CHECKS
// ================================================================================================

/// Assert critical Fiat-Shamir-derived values are non-zero.
fn sanity_check_ace_inputs(read: &impl Fn(u32) -> Felt, inputs: &[QuadFelt], layout: &InputLayout) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };
    let read_quad = |addr| QuadFelt::new([read(addr), read(addr + 1)]);

    // Fiat-Shamir challenges
    assert!(!get(InputKey::Alpha).is_zero(), "alpha is zero");
    assert!(!get(InputKey::AuxRandBeta).is_zero(), "beta is zero");
    assert!(
        !read_quad(stark_constant("CONSTRAINT_COMPOSITION_COEFS_PTR") + 2).is_zero(),
        "multi-AIR fold beta is zero"
    );

    // Vanishing polynomial
    assert!(
        !(get(InputKey::ZPowN) - QuadFelt::ONE).is_zero(),
        "z^N - 1 = 0 -- OOD point is on the trace domain"
    );

    // Quotient recomposition
    assert!(!get(InputKey::Weight0).is_zero(), "weight0 is zero");
    assert!(!get(InputKey::F).is_zero(), "f is zero");
    assert!(!get(InputKey::S0).is_zero(), "s0 is zero");
    assert_eq!(
        get(InputKey::Alpha),
        read_quad(stark_constant("CONSTRAINT_COMPOSITION_COEFS_PTR"))
    );
    assert_eq!(get(InputKey::Reserved), QuadFelt::ZERO);
    assert_eq!(
        get(InputKey::Weight0),
        QuadFelt::from(Felt::new_unchecked(8_868_329_529_835_627_796))
    );
    assert_eq!(
        get(InputKey::F),
        QuadFelt::from(Felt::new_unchecked(18_446_744_069_397_807_105))
    );
    assert_eq!(
        get(InputKey::S0),
        QuadFelt::from(Felt::new_unchecked(5_473_358_340_599_679_662))
    );
    let trace_length = read(stark_constant("TRACE_LENGTH_PTR")).as_canonical_u64();
    let old_f = read(stark_constant("LDE_DOMAIN_GENERATOR_PTR")).exp_u64(trace_length);
    let old_s0 = read(stark_constant("DOMAIN_OFFSET_PTR")).exp_u64(trace_length);
    let old_weight0 = (Felt::from_u8(8) * old_s0.exp_u64(7)).try_inverse().expect("nonzero weight");
    assert_eq!(get(InputKey::F), QuadFelt::from(old_f), "fixed f differs from runtime domain");
    assert_eq!(
        get(InputKey::S0),
        QuadFelt::from(old_s0),
        "fixed s0 differs from runtime domain"
    );
    assert_eq!(
        get(InputKey::Weight0),
        QuadFelt::from(old_weight0),
        "fixed weight0 differs from runtime domain"
    );

    let z_pow_n = read_quad(stark_constant("OOD_POINT_PTR"));
    let z = read_quad(stark_constant("OOD_POINT_PTR") + 2);
    let max_log = read(stark_constant("LOG_TRACE_LENGTH_PTR")).as_canonical_u64() as usize;
    let z_k = (5..max_log).fold(z, |value, _| value * value);
    assert_eq!(get(InputKey::ZPowN), z_pow_n);
    assert_eq!(get(InputKey::ZK), z_k);

    // OOD frame should have at least some non-zero values
    assert!(
        (0..layout.counts.width)
            .any(|col| !get(InputKey::Main { offset: 0, index: col }).is_zero()),
        "all main trace OOD values at current row are zero"
    );
}

/// Reconstruct every per-AIR selector from `z` and the recorded trace heights.
///
/// This oracle does not share the MASM inversion schedule, so swapped or incorrectly reconstructed
/// inverses fail before the circuit cross-evaluation.
fn assert_air_selectors_match_trace_metadata(
    read: &impl Fn(u32) -> Felt,
    inputs: &[QuadFelt],
    layout: &InputLayout,
) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };
    let read = |addr| read(addr);
    let z = QuadFelt::new([
        read(stark_constant("OOD_POINT_PTR") + 2),
        read(stark_constant("OOD_POINT_PTR") + 3),
    ]);
    let max_log = read(stark_constant("LOG_TRACE_LENGTH_PTR")).as_canonical_u64() as u32;

    for air in 0..MIDEN_AIR_COUNT {
        let log_height = read(stark_constant("LOG_AIR_TRACE_LENGTHS_PTR") + air as u32)
            .as_canonical_u64() as u32;
        assert!(log_height <= max_log, "AIR {air} height exceeds the maximum height");
        let z_lift = (log_height..max_log).fold(z, |value, _| value * value);
        let vanishing = z_lift.exp_u64(1_u64 << log_height) - QuadFelt::ONE;
        let generator_inv = Felt::two_adic_generator(log_height as usize).inverse();
        let transition = z_lift - QuadFelt::from(generator_inv);

        assert_eq!(
            get(InputKey::IsFirstAir(air)),
            vanishing / (z_lift - QuadFelt::ONE),
            "AIR {air} first-row selector mismatch"
        );
        assert_eq!(
            get(InputKey::IsLastAir(air)),
            vanishing / transition,
            "AIR {air} last-row selector mismatch"
        );
        assert_eq!(
            get(InputKey::IsTransitionAir(air)),
            transition,
            "AIR {air} transition selector mismatch"
        );
    }
}

/// Each AIR's staged fold coefficient must be `beta^(n - 1 - pos)`, with `pos` that AIR's
/// position in the height-sorted proof order.
///
/// These slots are what carry the proof order into an otherwise order-invariant circuit: the
/// AIR opened last folds with `beta^0` and the one opened first with `beta^(n - 1)`. Keying the
/// exponent by instance index instead would agree only for the identity order, which most e2e
/// fixtures are not.
fn assert_fold_coefficients_match_the_proof_order(
    read: &impl Fn(u32) -> Felt,
    order: &[usize],
    inputs: &[QuadFelt],
    layout: &InputLayout,
) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };
    let beta = QuadFelt::new([
        read(stark_constant("CONSTRAINT_COMPOSITION_COEFS_PTR") + 2),
        read(stark_constant("CONSTRAINT_COMPOSITION_COEFS_PTR") + 3),
    ]);

    for (position, &air) in order.iter().enumerate() {
        let exponent = (MIDEN_AIR_COUNT - 1 - position) as u64;
        assert_eq!(
            get(InputKey::MultiAirFoldCoeff(air)),
            beta.exp_u64(exponent),
            "AIR {air} at proof position {position} has the wrong fold coefficient",
        );
    }
}

// CROSS-EVALUATION
// ================================================================================================

/// Runs an MVM verifier fixture and checks what it left in the verifier's context: the proof
/// stream sections it read into memory, the fold coefficients against the proof order its staged
/// heights induce, and the ACE inputs, which are cross-evaluated in Rust.
///
/// The fixture's trace handlers run as usual, so callers can still observe the verifier's stack
/// at return.
pub(super) fn execute_and_check(test: &Test, proof_stream: &[u64], claim: &[u64]) -> Vec<usize> {
    let (processor, ctx) = execute_verifier(test);
    let read = |addr| processor.memory().read_element(ctx, Felt::from_u32(addr)).unwrap();

    assert_proof_stream_read_sections(&read, proof_stream, claim);

    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
    };

    let order = extract_order(&read);
    let circuit = build_canonical_multi_air_ace_circuit(config).expect("canonical ace circuit");
    let layout = circuit.layout();

    let inputs = extract_ace_inputs(&read, layout);
    assert_eq!(inputs.len(), layout.total_inputs, "extracted input count mismatch");

    sanity_check_ace_inputs(&read, &inputs, layout);
    assert_air_selectors_match_trace_metadata(&read, &inputs, layout);
    assert_fold_coefficients_match_the_proof_order(&read, &order, &inputs, layout);

    let result = circuit.eval(&inputs).expect("ACE eval failed");
    assert!(
        result.is_zero(),
        "ACE cross-evaluation is non-zero: {result:?}\n\
         proof order: {order:?}\n\
         MASM verifier populated the READ section incorrectly."
    );

    order
}

/// Runs a fixture with one verifier call and returns the processor and verifier's private context.
pub(super) fn execute_verifier(test: &Test) -> (FastProcessor, ContextId) {
    let (program, ..) = test.compile().expect("the verifier fixture must assemble");
    let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
    for (event, handler) in &test.trace_handlers {
        host.register_trace_handler(event.clone(), handler.clone()).unwrap();
    }
    let mut processor = FastProcessor::new_with_options(
        test.stack_inputs,
        test.advice_inputs.clone(),
        ExecutionOptions::default(),
    )
    .unwrap();
    let mut verifier_context = None;
    let mut resume = Some(processor.get_initial_resume_context(&program).unwrap());
    while let Some(next) = resume {
        resume = processor.step_sync(&mut host, next).expect("recursive verification failed");
        let ctx = processor.state().ctx();
        // The verifier is the first child context in these fixtures.
        if !ctx.is_root() {
            verifier_context.get_or_insert(ctx);
        }
    }

    let ctx = verifier_context.expect("the verifier must enter an isolated context");
    (processor, ctx)
}

#[rstest]
#[case::relocated(1_024, 4_096, 1)]
#[case::consecutive(16_384, 2_048, 3)]
#[case::in_place(8_192, 8_192, 1)]
fn base_to_extension_copy_preserves_values_and_caller(
    #[case] src: u32,
    #[case] dst: u32,
    #[case] blocks: u32,
) {
    const GUARD: u64 = 0xcafe;
    let values: Vec<_> = (0..8 * blocks)
        .map(|i| match i % 3 {
            0 => Felt::ZERO,
            1 => Felt::from_u32(i + 1),
            _ => -Felt::from_u32(i + 1),
        })
        .collect();
    let source = format!(
        "
        use {{ZERO_WORD_PTR}} from miden::core::stark::constants
        use miden::core::stark::public_inputs
        begin
            padw mem_storew_le.ZERO_WORD_PTR dropw
            {stores}
            push.{GUARD} mem_store.{before}
            push.{GUARD} mem_store.{after}
            push.{dst}.{src}
            push.112.111.110.109.108.107.106.105.104.103.102.101
            repeat.{blocks} exec.public_inputs::copy_base_to_extension_double_word end
            dropw dropw dropw
            push.{src_end} assert_eq
            push.{after} assert_eq
        end
        ",
        stores = masm_store_felts(&values, src),
        before = dst - 1,
        after = dst + 16 * blocks,
        src_end = src + 8 * blocks,
    );
    let caller: [u64; 16] = core::array::from_fn(|i| 501 + i as u64);
    let (output, _) = build_test!(&source, &caller).execute_for_output().unwrap();

    for (i, value) in values.into_iter().enumerate() {
        let address = dst + 2 * i as u32;
        assert_eq!(read_memory_felt(&output, address), value);
        assert_eq!(read_memory_felt(&output, address + 1), Felt::ZERO);
    }
    for address in [dst - 1, dst + 16 * blocks] {
        assert_eq!(read_memory_felt(&output, address), Felt::new_unchecked(GUARD));
    }
    assert_eq!(output.stack.get_num_elements(16), caller.map(Felt::new_unchecked));
}

#[rstest]
#[case::short_cycle(false)]
#[case::full_trace_cycle(true)]
fn lifted_selectors_match_native_domains_at_every_supported_height(#[case] full_trace_cycle: bool) {
    const HEIGHTS_PTR: u32 = 100_000;
    const STARK_VARS_PTR: u32 = 100_100;
    const FIRST_SELECTOR_OFFSET: u32 = 20;
    const SELECTOR_STRIDE: u32 = 6;

    let log_blowup = config::pcs_params().log_blowup();
    let max_log_height = Felt::TWO_ADICITY as u8 - log_blowup;
    let z = QuadFelt::new([Felt::from_u32(7), Felt::from_u32(11)]);
    let quotient = quotient_recomposition_inputs::<Felt>(log_blowup, log_blowup).unwrap();

    // Include the minimum domain, the fixed byte-pair domain, and the largest supported domain.
    // Each batch includes a zero lift and every smaller supported height in descending order.
    for max_log in [6, 16, max_log_height] {
        let cycle_log = if full_trace_cycle { max_log } else { 5 };
        let heights: Vec<_> = (6..=max_log).rev().collect();
        let domain = canonical_domain::<Felt>(max_log, log_blowup);
        let z_n = z.exp_power_of_2(max_log as usize);
        let ood: Vec<_> = z_n
            .as_basis_coefficients_slice()
            .iter()
            .chain(z.as_basis_coefficients_slice())
            .copied()
            .collect();
        let source = format!(
            "
            use miden::core::stark::constraints_eval_inputs
            use {{LOG_TRACE_LENGTH_PTR, TRACE_DOMAIN_GENERATOR_PTR}}
                from miden::core::stark::constants
            begin
                push.{max_log} mem_store.LOG_TRACE_LENGTH_PTR
                push.{generator} mem_store.TRACE_DOMAIN_GENERATOR_PTR
                {ood_stores}
                {height_stores}
                push.{ratio}.{shift}.{weight}.{STARK_VARS_PTR}.{HEIGHTS_PTR}.{num_airs}.{cycle_log}
                exec.constraints_eval_inputs::set_up_auxiliary_inputs_ace
            end
            ",
            generator = Felt::two_adic_generator(max_log as usize),
            ood_stores = masm_store_felts(&ood, stark_constant("OOD_POINT_PTR")),
            height_stores = masm_store_felts(
                &heights.iter().copied().map(Felt::from_u8).collect::<Vec<_>>(),
                HEIGHTS_PTR,
            ),
            ratio = quotient.shift_ratio,
            shift = quotient.first_shift,
            weight = quotient.first_weight,
            num_airs = heights.len(),
        );
        let (program, ..) = build_test!(source, &[]).compile().unwrap();
        let mut host = DefaultHost::default().with_library(&CoreLibrary::default()).unwrap();
        // A zero squaring count must skip the loop instead of underflowing its counter.
        let options = ExecutionOptions::new(
            Some(1 << 16),
            64,
            ExecutionOptions::DEFAULT_CORE_TRACE_FRAGMENT_SIZE,
        )
        .unwrap();
        let output = FastProcessor::new(StackInputs::default())
            .with_options(options)
            .unwrap()
            .execute_sync(&program, &mut host)
            .unwrap();
        let z_k = QuadFelt::new([
            read_memory_felt(&output, STARK_VARS_PTR + 4),
            read_memory_felt(&output, STARK_VARS_PTR + 5),
        ]);
        assert_eq!(
            z_k,
            z.exp_power_of_2((max_log - cycle_log) as usize),
            "maximum {max_log}, cycle {cycle_log}",
        );
        for (air, &height) in heights.iter().enumerate() {
            let expected = domain.try_sub_domain(height).unwrap().selectors_at(z);
            for (slot, selector) in
                [expected.is_first_row, expected.is_last_row, expected.is_transition]
                    .into_iter()
                    .enumerate()
            {
                let ptr = STARK_VARS_PTR
                    + FIRST_SELECTOR_OFFSET
                    + SELECTOR_STRIDE * air as u32
                    + 2 * slot as u32;
                let actual = QuadFelt::new([
                    read_memory_felt(&output, ptr),
                    read_memory_felt(&output, ptr + 1),
                ]);
                assert_eq!(actual, selector, "height {height}, maximum {max_log}, selector {slot}");
            }
        }
    }
}
