//! Cross-checks the ACE READ section produced by the MASM recursive verifier.
//!
//! The check extracts the flat ACE input vector from memory, verifies its structural and selector
//! invariants, and evaluates the same ACE circuit in Rust.

use miden_ace_codegen::{AceConfig, InputKey, InputLayout, LayoutKind};
use miden_air::{MIDEN_AIR_COUNT, ProofOrder, ace::build_multi_air_ace_circuit_for_order};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt, TwoAdicField},
};
use miden_crypto::field::Field;
use miden_processor::ExecutionOutput;

use super::vm_layout_const;
use crate::helpers::read_memory_felt;

// MASM MEMORY LAYOUT
// ================================================================================================

const TRACE_LENGTH_LOG_PTR: u32 = 3223322634;
const TRACE_LENGTH_PTR: u32 = 3223322632;
const LDE_DOMAIN_GEN_PTR: u32 = 3223322626;
const DOMAIN_OFFSET_PTR: u32 = 3223322635;
const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322638;
const ORDER_TAG_PTR: u32 = 3223322639;
const MAIN_TRACE_COM_PTR: u32 = 3223322640;
const AUX_TRACE_COM_PTR: u32 = 3223322644;
const COMPOSITION_POLY_COM_PTR: u32 = 3223322648;
const COMPOSITION_COEF_PTR: u32 = 3223322704;
const Z_PTR: u32 = 3223322652;
const AIR_TRACE_LENGTH_LOGS_PTR: u32 = 3223322744;
pub fn assert_proof_stream_read_sections(
    output: &ExecutionOutput,
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

    let public_ptr = read_memory_felt(output, PUBLIC_INPUTS_ADDRESS_PTR).as_canonical_u64() as u32;
    for i in 0..32 {
        assert_eq!(
            read_memory_felt(output, public_ptr + 2 * i as u32),
            Felt::new_unchecked(claim[8 + i]),
            "public input {i} differs from the authenticated claim"
        );
        assert_eq!(
            read_memory_felt(output, public_ptr + 2 * i as u32 + 1),
            Felt::ZERO,
            "public input {i} has a nonzero extension coordinate"
        );
    }

    for (memory, stream) in [
        (MAIN_TRACE_COM_PTR, MAIN_OFFSET),
        (AUX_TRACE_COM_PTR, AUX_COMMIT_OFFSET),
        (COMPOSITION_POLY_COM_PTR, QUOTIENT_COMMIT_OFFSET),
    ] {
        for i in 0..4 {
            assert_eq!(
                read_memory_felt(output, memory + i as u32),
                Felt::new_unchecked(proof_stream[stream + i]),
                "commitment stream mismatch at memory {memory}, limb {i}"
            );
        }
    }
    for i in 0..8 {
        assert_eq!(
            read_memory_felt(output, aux_bus_boundary_ptr + i as u32),
            Felt::new_unchecked(proof_stream[AUX_VALUES_OFFSET + i]),
            "aux-boundary stream mismatch at felt {i}"
        );
    }
    for i in 0..ood_felts {
        assert_eq!(
            read_memory_felt(output, ood_evaluations_ptr + i as u32),
            Felt::new_unchecked(proof_stream[OOD_OFFSET + i]),
            "OOD stream mismatch at felt {i}"
        );
    }
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
        num_airs: MIDEN_AIR_COUNT,
    };
    let circuit = build_multi_air_ace_circuit_for_order(config, &ProofOrder::instance_order())
        .expect("multi-AIR ACE circuit");
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
fn extract_ace_inputs(output: &ExecutionOutput, layout: &InputLayout) -> Vec<QuadFelt> {
    let pi_ptr = read_memory_felt(output, PUBLIC_INPUTS_ADDRESS_PTR).as_canonical_u64() as u32;
    let aux_rand_elem_ptr = vm_layout_const("AUX_RAND_ELEM_PTR");

    assert!(
        pi_ptr < aux_rand_elem_ptr,
        "pi_ptr ({pi_ptr}) >= AUX_RAND_ELEM_PTR ({aux_rand_elem_ptr})"
    );

    (0..layout.total_inputs)
        .map(|i| {
            let addr = pi_ptr + (i as u32) * 2;
            let c0 = read_memory_felt(output, addr);
            let c1 = read_memory_felt(output, addr + 1);
            QuadFelt::new([c0, c1])
        })
        .collect()
}

fn extract_order(output: &ExecutionOutput) -> ProofOrder {
    let tag = read_memory_felt(output, ORDER_TAG_PTR).as_canonical_u64();
    ProofOrder::from_tag(tag as u32)
        .unwrap_or_else(|| panic!("invalid order tag in recursive verifier memory: {tag}"))
}

// INPUT CHECKS
// ================================================================================================

/// Assert critical Fiat-Shamir-derived values are non-zero.
fn sanity_check_ace_inputs(output: &ExecutionOutput, inputs: &[QuadFelt], layout: &InputLayout) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };
    let read_quad =
        |addr| QuadFelt::new([read_memory_felt(output, addr), read_memory_felt(output, addr + 1)]);

    // Fiat-Shamir challenges
    assert!(!get(InputKey::Alpha).is_zero(), "alpha is zero");
    assert!(!get(InputKey::AuxRandBeta).is_zero(), "beta is zero");
    assert!(!get(InputKey::MultiAirFoldBeta).is_zero(), "multi-AIR fold beta is zero");

    // Vanishing polynomial
    assert!(
        !(get(InputKey::ZPowN) - QuadFelt::ONE).is_zero(),
        "z^N - 1 = 0 -- OOD point is on the trace domain"
    );

    // Selector polynomials
    assert!(!get(InputKey::IsFirst).is_zero(), "is_first is zero");
    assert!(!get(InputKey::IsLast).is_zero(), "is_last is zero");
    assert!(!get(InputKey::IsTransition).is_zero(), "is_transition is zero");

    // Quotient recomposition
    assert!(!get(InputKey::Weight0).is_zero(), "weight0 is zero");
    assert!(!get(InputKey::F).is_zero(), "f is zero");
    assert!(!get(InputKey::S0).is_zero(), "s0 is zero");
    assert_eq!(get(InputKey::Alpha), read_quad(COMPOSITION_COEF_PTR));
    assert_eq!(get(InputKey::MultiAirFoldBeta), read_quad(COMPOSITION_COEF_PTR + 2));
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
    let trace_length = read_memory_felt(output, TRACE_LENGTH_PTR).as_canonical_u64();
    let old_f = read_memory_felt(output, LDE_DOMAIN_GEN_PTR).exp_u64(trace_length);
    let old_s0 = read_memory_felt(output, DOMAIN_OFFSET_PTR).exp_u64(trace_length);
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

    let z_pow_n = read_quad(Z_PTR);
    let z = read_quad(Z_PTR + 2);
    let max_log = read_memory_felt(output, TRACE_LENGTH_LOG_PTR).as_canonical_u64() as usize;
    let z_k = (5..max_log).fold(z, |value, _| value * value);
    let vanishing = z_pow_n - QuadFelt::ONE;
    let generator_inv = Felt::two_adic_generator(max_log).inverse();
    let transition = z - QuadFelt::from(generator_inv);
    assert_eq!(get(InputKey::ZPowN), z_pow_n);
    assert_eq!(get(InputKey::ZK), z_k);
    assert_eq!(get(InputKey::IsFirst), vanishing / (z - QuadFelt::ONE));
    assert_eq!(get(InputKey::IsLast), vanishing / transition);
    assert_eq!(get(InputKey::IsTransition), transition);

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
    output: &ExecutionOutput,
    inputs: &[QuadFelt],
    layout: &InputLayout,
) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };
    let read = |addr| read_memory_felt(output, addr);
    let z = QuadFelt::new([read(Z_PTR + 2), read(Z_PTR + 3)]);
    let max_log = read(TRACE_LENGTH_LOG_PTR).as_canonical_u64() as u32;

    for air in 0..MIDEN_AIR_COUNT {
        let log_height = read(AIR_TRACE_LENGTH_LOGS_PTR + air as u32).as_canonical_u64() as u32;
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

// CROSS-EVALUATION
// ================================================================================================

/// Evaluate the Rust ACE circuit against the READ section left in MASM memory.
pub fn cross_check_ace_circuit(output: &ExecutionOutput) -> ProofOrder {
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    let order = extract_order(output);
    let log_heights: Vec<u8> = (0..MIDEN_AIR_COUNT)
        .map(|air| {
            read_memory_felt(output, AIR_TRACE_LENGTH_LOGS_PTR + air as u32).as_canonical_u64()
                as u8
        })
        .collect();
    assert_eq!(
        order,
        ProofOrder::from_instance_log_heights(&log_heights),
        "order tag does not match the staged instance heights"
    );
    let circuit =
        build_multi_air_ace_circuit_for_order(config, &order).expect("multi-AIR ace circuit");
    let layout = circuit.layout();

    let inputs = extract_ace_inputs(output, layout);
    assert_eq!(inputs.len(), layout.total_inputs, "extracted input count mismatch");

    sanity_check_ace_inputs(output, &inputs, layout);
    assert_air_selectors_match_trace_metadata(output, &inputs, layout);

    let result = circuit.eval(&inputs).expect("ACE eval failed");
    assert!(
        result.is_zero(),
        "ACE cross-evaluation is non-zero: {result:?}\n\
         proof order: {order:?}\n\
         MASM verifier populated the READ section incorrectly."
    );

    order
}
