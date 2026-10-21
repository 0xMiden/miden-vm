//! Optional ACE circuit construction for the authored precompile relation.
//!
//! The stable [`ChipletAir::all`] instance order determines canonical circuit layout.
//! The cross-chiplet LogUp identity remains an external statement assertion.

use miden_ace::{
    AceCircuit, AceConfig, AceError, LayoutKind, build_canonical_multi_air_ace_circuit,
};
use miden_core::{Felt, field::QuadFelt};

use super::ChipletAir;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Per-AIR trace regions are padded to this width before concatenation, matching the LMCS wire
/// alignment used by the commitment scheme.
const LMCS_ALIGNMENT: usize = 8;

/// Number of quotient chunks the precompile relation commits to.
///
/// The lifted STARK verifier derives this quantity symbolically from the AIRs. Deriving it through
/// the same implementation keeps the ACE circuit's READ layout coupled to the proof protocol.
fn num_quotient_chunks() -> usize {
    let max_log_quotient_degree = ChipletAir::all()
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, ChipletAir>)
        .max()
        .expect("the chiplet stack is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings for the precompile chiplet relation.
fn precompile_ace_config() -> AceConfig {
    AceConfig {
        num_quotient_chunks: num_quotient_chunks(),
        layout: LayoutKind::Masm,
    }
}

/// Builds the canonical (order-invariant) precompile chiplet ACE circuit.
///
/// Every chiplet's trace regions sit at its [`ChipletAir::all`] offset and every chiplet reads its
/// fold coefficient from a dedicated slot, so one circuit serves every proof ordering. The caller
/// lands each proof-ordered trace segment on its canonical address and stages the chiplet at proof
/// position `k` with the coefficient `beta^(NUM_CHIPLETS - 1 - k)`.
pub fn build_canonical_precompile_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    let airs = ChipletAir::all();
    build_canonical_multi_air_ace_circuit(&airs, precompile_ace_config(), LMCS_ALIGNMENT)
}

// RECURSIVE VERIFIER CIRCUIT
// ================================================================================================

pub use miden_ace::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// Repeated verification can cache this deterministic circuit in the proof backend.
pub fn build_pvm_recursive_verifier_ace_circuit() -> Result<PvmRecursiveAceCircuit, AceError> {
    let encoded = build_canonical_precompile_ace_circuit()?.to_ace()?;
    encoded.try_into()
}
