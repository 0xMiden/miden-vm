//! ACE circuit policy for the precompile chiplet multi-AIR proof.
//!
//! The relation uses [`Air::all`] as its stable instance order and canonical ACE fold order,
//! and aligns each per-AIR trace region to eight base-field elements. The lifted STARK proof
//! commits traces in ascending height order, which varies per workload, but one order-invariant
//! circuit serves every ordering: the verifier lands each proof-ordered segment at the canonical
//! address the circuit reads it from and stages each chiplet's fold coefficient by proof position.
//!
//! The cross-chiplet LogUp identity enforced by `ChipletMultiAir::eval_external` remains an
//! external multi-AIR assertion.

use miden_ace::{AceCircuit, AceConfig, LayoutKind, build_canonical_multi_air_ace_circuit};
use miden_core::{Felt, field::QuadFelt};

use super::{Air, PvmAirVariant};
use alloc::vec::Vec;

// MULTI-AIR ACE CIRCUIT
// ================================================================================================

/// Per-AIR trace regions are padded to this width before concatenation, matching the LMCS wire
/// alignment used by the commitment scheme.
const LMCS_ALIGNMENT: usize = 8;

/// Number of quotient chunks the precompile relation commits to.
///
/// The lifted STARK verifier derives this quantity symbolically from the AIRs. Deriving it through
/// the same implementation keeps the ACE circuit's READ layout coupled to the proof protocol.
fn num_quotient_chunks(airs: &[Air]) -> usize {
    let max_log_quotient_degree = airs
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, Air>)
        .max()
        .expect("the chiplet stack is non-empty");
    1usize << max_log_quotient_degree
}

/// ACE codegen settings for the precompile chiplet relation.
fn precompile_ace_config(airs: &[Air]) -> AceConfig {
    AceConfig {
        num_quotient_chunks: num_quotient_chunks(airs),
        layout: LayoutKind::Masm,
    }
}

/// Builds the canonical (order-invariant) precompile chiplet ACE circuit.
///
/// Every chiplet's trace regions sit at its [`Air::all`] offset and every chiplet reads its
/// fold coefficient from a dedicated slot, so one circuit serves every proof ordering. The caller
/// lands each proof-ordered trace segment on its canonical address and stages the chiplet at proof
/// position `k` with the coefficient `beta^(NUM_CHIPLETS - 1 - k)`.
pub fn build_canonical_precompile_ace_circuit() -> AceCircuit<QuadFelt> {
    build_canonical_precompile_ace_circuit_for(PvmAirVariant::ALL)
}

/// Compiles the exact selected relation in canonical order.
pub fn build_canonical_precompile_ace_circuit_for(variant: PvmAirVariant) -> AceCircuit<QuadFelt> {
    let airs: Vec<_> = Air::all().into_iter().filter(|air| air.is_in_variant(variant)).collect();
    build_canonical_precompile_ace_circuit_from_airs(&airs)
}

pub(crate) fn build_canonical_precompile_ace_circuit_from_airs(
    airs: &[Air],
) -> AceCircuit<QuadFelt> {
    build_canonical_multi_air_ace_circuit(airs, precompile_ace_config(airs), LMCS_ALIGNMENT)
}

// RECURSIVE VERIFIER CIRCUIT
// ================================================================================================

pub use miden_ace::RecursiveAceCircuit as PvmRecursiveAceCircuit;

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// This is an explicit tooling operation. Production advice loads the staged canonical stream.
pub fn build_pvm_recursive_verifier_ace_circuit() -> PvmRecursiveAceCircuit {
    miden_ace::CompiledCircuit::from_circuit(build_canonical_precompile_ace_circuit()).into()
}
