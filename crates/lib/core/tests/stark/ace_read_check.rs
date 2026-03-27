//! ACE READ section extraction and cross-validation.
//!
//! After the recursive verifier executes in MASM, this module:
//! 1. Extracts the ACE READ section from MASM memory into a flat `Vec<QuadFelt>`.
//! 2. Runs structural sanity checks on critical values (non-zero challenges, etc.).
//! 3. Evaluates the ACE circuit in Rust and asserts the result is zero.
//!
//! This catches bugs in the MASM verifier's input preparation (wrong values, wrong
//! memory slots, missing absorptions) that would silently break soundness.

use miden_ace_codegen::{AceConfig, InputKey, InputLayout, LayoutKind};
use miden_air::{ProcessorAir, ace::build_batched_ace_circuit};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::field::Field;
use miden_processor::{ContextId, ExecutionOutput};

// MASM CONSTANTS (must match crates/lib/core/asm/stark/constants.masm)
// ================================================================================================

const PUBLIC_INPUTS_ADDRESS_PTR: u32 = 3223322667;
const AUX_RAND_ELEM_PTR: u32 = 3225419776;

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

// SANITY CHECKS
// ================================================================================================

/// Assert critical Fiat-Shamir-derived values are non-zero.
fn sanity_check_ace_inputs(inputs: &[QuadFelt], layout: &InputLayout) {
    let get = |key: InputKey| -> QuadFelt { inputs[layout.index(key).expect("missing key")] };

    // Fiat-Shamir challenges
    assert!(!get(InputKey::Alpha).is_zero(), "alpha is zero");
    assert!(!get(InputKey::AuxRandBeta).is_zero(), "beta is zero");
    assert!(!get(InputKey::Gamma).is_zero(), "gamma is zero");

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

/// Build the ACE circuit, extract inputs from MASM memory, run sanity checks,
/// and verify the Rust evaluation matches (result is zero).
pub fn cross_check_ace_circuit(output: &ExecutionOutput) {
    let config = AceConfig {
        num_quotient_chunks: 8,
        num_vlpi_groups: 1,
        layout: LayoutKind::Masm,
        quotient_extension: false,
        quotient_segment_len: 0,
    };

    let batch_config = miden_air::ace::reduced_aux_batch_config();
    let circuit = build_batched_ace_circuit::<_, QuadFelt>(&ProcessorAir, config, &batch_config)
        .expect("ace circuit");
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
}
