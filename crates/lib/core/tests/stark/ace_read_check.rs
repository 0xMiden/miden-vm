//! Cross-checks the ACE READ section produced by the MASM recursive verifier.
//!
//! The check extracts the flat ACE input vector from memory, verifies basic invariants, and
//! evaluates the same ACE circuit in Rust.

use miden_ace_codegen::{AceConfig, InputKey, InputLayout, LayoutKind};
use miden_air::{MIDEN_AIR_COUNT, ProofOrder, ace::build_multi_air_ace_circuit_for_order};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::field::Field;
use miden_processor::{ContextId, ExecutionOutput};

// MASM CONSTANTS (must match crates/lib/core/asm/stark/constants.masm)
// ================================================================================================

const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322671;
const ORDER_TAG_PTR: u32 = 3223322764;
const AUX_RAND_ELEM_PTR: u32 = 3225419776;
const OOD_EVALUATIONS_PTR: u32 = 3225419784;
const AUX_BUS_BOUNDARY_PTR: u32 = 3225420328;
const AUXILIARY_ACE_INPUTS_PTR: u32 = 3225420336;
const ACE_CIRCUIT_STREAM_PTR: u32 = 3225420376;

fn recursive_verifier_layout() -> InputLayout {
    let config = AceConfig {
        num_quotient_chunks: 8,
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    };

    build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &ProofOrder::instance_order())
        .expect("multi-AIR ace circuit")
        .layout()
        .clone()
}

#[test]
fn ace_read_pointers_match_masm_layout() {
    let layout = recursive_verifier_layout();

    let beta = layout.index(InputKey::AuxRandBeta).expect("aux randomness beta");
    let alpha = layout.index(InputKey::AuxRandAlpha).expect("aux randomness alpha");
    let main_curr = layout.index(InputKey::Main { offset: 0, index: 0 }).expect("main curr");
    let aux_bus = layout.index(InputKey::AuxBusBoundary(0)).expect("aux bus boundary");
    let stark_vars = layout.index(InputKey::Alpha).expect("stark vars");

    assert_eq!(alpha, beta + 1);
    assert_eq!(OOD_EVALUATIONS_PTR - AUX_RAND_ELEM_PTR, 2 * (main_curr - beta) as u32);
    assert_eq!(AUX_BUS_BOUNDARY_PTR - OOD_EVALUATIONS_PTR, 2 * (aux_bus - main_curr) as u32);
    assert_eq!(
        AUXILIARY_ACE_INPUTS_PTR - AUX_BUS_BOUNDARY_PTR,
        2 * (stark_vars - aux_bus) as u32
    );
    assert_eq!(
        ACE_CIRCUIT_STREAM_PTR - AUXILIARY_ACE_INPUTS_PTR,
        2 * (layout.total_inputs - stark_vars) as u32
    );
}

// EXTRACTION
// ================================================================================================

/// Extract the ACE READ section from MASM memory into a flat input vector.
///
/// Each pair of consecutive base felts forms one extension field element.
/// The returned vector has `layout.total_inputs` entries.
fn extract_ace_inputs(output: &ExecutionOutput, layout: &InputLayout) -> Vec<QuadFelt> {
    let ctx = ContextId::root();

    let pi_ptr = output
        .memory
        .read_element(ctx, Felt::from_u32(PUBLIC_INPUTS_ADDRESS_PTR))
        .expect("PUBLIC_INPUTS_ADDRESS_PTR not found in memory")
        .as_canonical_u64() as u32;

    assert!(
        pi_ptr < AUX_RAND_ELEM_PTR,
        "pi_ptr ({pi_ptr}) >= AUX_RAND_ELEM_PTR ({AUX_RAND_ELEM_PTR})"
    );

    (0..layout.total_inputs)
        .map(|i| {
            let addr = pi_ptr + (i as u32) * 2;
            let c0 = output.memory.read_element(ctx, Felt::from_u32(addr)).expect("read c0");
            let c1 = output.memory.read_element(ctx, Felt::from_u32(addr + 1)).expect("read c1");
            QuadFelt::new([c0, c1])
        })
        .collect()
}

fn extract_order(output: &ExecutionOutput) -> ProofOrder {
    let ctx = ContextId::root();
    let tag = output
        .memory
        .read_element(ctx, Felt::from_u32(ORDER_TAG_PTR))
        .expect("ORDER_TAG_PTR not found in memory")
        .as_canonical_u64();
    ProofOrder::from_tag(tag as u32)
        .unwrap_or_else(|| panic!("invalid order tag in recursive verifier memory: {tag}"))
}

// SANITY CHECKS
// ================================================================================================

/// Assert critical Fiat-Shamir-derived values are non-zero.
fn sanity_check_ace_inputs(inputs: &[QuadFelt], layout: &InputLayout) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };

    // Fiat-Shamir challenges
    assert!(!get(InputKey::Alpha).is_zero(), "alpha is zero");
    assert!(!get(InputKey::AuxRandBeta).is_zero(), "beta is zero");

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

    // OOD frame should have at least some non-zero values
    assert!(
        (0..layout.counts.width)
            .any(|col| !get(InputKey::Main { offset: 0, index: col }).is_zero()),
        "all main trace OOD values at current row are zero"
    );
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
    let circuit = build_multi_air_ace_circuit_for_order::<QuadFelt>(config, &order)
        .expect("multi-AIR ace circuit");
    let layout = circuit.layout();

    let inputs = extract_ace_inputs(output, layout);
    assert_eq!(inputs.len(), layout.total_inputs, "extracted input count mismatch");

    sanity_check_ace_inputs(&inputs, layout);

    let result = circuit.eval(&inputs).expect("ACE eval failed");
    assert!(
        result.is_zero(),
        "ACE cross-evaluation is non-zero: {result:?}\n\
         MASM verifier populated the READ section incorrectly."
    );

    order
}
