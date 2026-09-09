use alloc::vec::Vec;

use miden_ace_codegen::{AceConfig, AceError, InputLayout, LayoutKind};
use miden_core::{Felt, Word, field::QuadFelt};

use super::multi_air::build_canonical_multi_air_ace_circuit;
use crate::{AIRS, MIDEN_AIR_COUNT};

/// Number of quotient chunks the recursive verifier and its ACE circuit consume.
///
/// This is the symbolic derivation used by the lifted-STARK prover and verifier. The MASM
/// quotient-recomposition inputs depend on this value rather than the numerically equal blowup
/// factor.
fn recursive_verifier_num_quotient_chunks() -> usize {
    let max_log_quotient_degree = AIRS
        .iter()
        .map(miden_crypto::stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings used by the recursive verifier's MASM evaluator.
fn recursive_verifier_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: recursive_verifier_num_quotient_chunks(),
        layout: LayoutKind::Masm,
        num_airs: MIDEN_AIR_COUNT,
    }
}

/// Encoded recursive-verifier ACE circuit and the metadata consumed by MASM.
///
/// One fixed circuit topology serves every proof order. The MASM verifier's ingest scatter and
/// fold-coefficient staging supply the order-specific data positions and coefficients. The stream
/// is a single `adv_pipe`-aligned segment with one digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveAceCircuit {
    /// Number of ACE READ variables.
    pub num_inputs: usize,
    /// Number of ACE EVAL rows.
    pub num_eval_gates: usize,
    /// Encoded instruction stream length in base-field elements.
    pub stream_len: usize,
    /// Eidos digest of the full instruction stream: the advice-map key and the value pinned by
    /// the compiled-in circuit digest.
    pub commitment: Word,
    /// Encoded ACE instruction stream consumed by `eval_circuit`.
    pub instructions: Vec<Felt>,
}

/// Builds and encodes the order-invariant recursive-verifier ACE circuit.
///
/// The circuit does not depend on the proof order. Callers that need repeated access should use
/// [`shared_recursive_circuit`] rather than rebuild it for each proof.
pub fn build_recursive_verifier_ace_circuit() -> Result<RecursiveAceCircuit, AceError> {
    let circuit = build_canonical_multi_air_ace_circuit(recursive_verifier_ace_config())?;
    let encoded = circuit.to_ace()?;
    let instructions = encoded.instructions();
    let stream_len = encoded.size_in_felt();
    if stream_len != instructions.len() {
        return Err(AceError::InvalidInputLayout {
            message: format!(
                "ACE circuit stream length ({stream_len}) does not match instruction count ({})",
                instructions.len()
            ),
        });
    }
    if !stream_len.is_multiple_of(8) {
        return Err(AceError::InvalidInputLayout {
            message: "ACE circuit stream must be 8-felt aligned for adv_pipe".into(),
        });
    }

    let commitment = encoded.circuit_hash();

    Ok(RecursiveAceCircuit {
        num_inputs: encoded.num_vars(),
        num_eval_gates: encoded.num_eval_rows(),
        stream_len,
        commitment,
        instructions: instructions.to_vec(),
    })
}

/// ACE READ layout of the circuit the recursive verifier evaluates.
///
/// The layout fixes where every input region starts, so the regeneration tool derives the MASM
/// memory map from it rather than restating the region sizes.
pub fn recursive_verifier_input_layout() -> Result<InputLayout, AceError> {
    Ok(build_canonical_multi_air_ace_circuit(recursive_verifier_ace_config())?
        .layout()
        .clone())
}

/// Returns the process-wide canonical circuit shared by every proof order.
#[cfg(feature = "std")]
pub fn shared_recursive_circuit() -> &'static RecursiveAceCircuit {
    static CIRCUIT: std::sync::OnceLock<RecursiveAceCircuit> = std::sync::OnceLock::new();
    CIRCUIT.get_or_init(|| {
        build_recursive_verifier_ace_circuit().expect("recursive-verifier ACE circuit must build")
    })
}
