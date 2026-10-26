//! Symbolic capture, circuit construction, and compiled geometry for the precompile relation.

use alloc::vec::Vec;

use miden_ace::{
    AceError,
    compiler::{AceCircuit, CapturedAir, CompiledRelation, LayoutKind},
};
use miden_core::field::QuadFelt;
use p3_security::budget::{AirShape, LookupShape};

use crate::{
    precompiles::{
        ChipletAir, ace::PvmRecursiveAceCircuit, geometry::fractions_per_row_of, relation::AIRS,
        relations::MAX_MESSAGE_WIDTH,
    },
    shared::geometry::NUM_OOD_POINTS,
};

/// One symbolic capture of each AIR, shared by the compiler backends.
pub struct CapturedPvmRelation {
    airs: Vec<CapturedAir>,
}

impl CapturedPvmRelation {
    pub fn airs(&self) -> &[CapturedAir] {
        &self.airs
    }

    pub fn new() -> Result<Self, AceError> {
        Ok(Self {
            airs: AIRS.iter().map(CapturedAir::new).collect::<Result<_, _>>()?,
        })
    }

    pub fn compile(&self) -> Result<CompiledRelation<'_>, AceError> {
        let airs: Vec<_> = self.airs.iter().collect();
        CompiledRelation::from_captured(&airs, crate::precompiles::ace::LMCS_ALIGNMENT)
    }
}

/// Builds the canonical precompile chiplet ACE circuit.
pub fn build_canonical_precompile_ace_circuit() -> Result<AceCircuit<QuadFelt>, AceError> {
    CapturedPvmRelation::new()?.compile()?.build_circuit(LayoutKind::Masm)
}

/// Builds and encodes the order-invariant PVM recursive-verifier ACE circuit.
///
/// Callers needing the circuit for multiple proofs should cache the encoded result.
pub fn build_pvm_recursive_verifier_ace_circuit() -> Result<PvmRecursiveAceCircuit, AceError> {
    let encoded = build_canonical_precompile_ace_circuit()?.to_ace()?;
    encoded.try_into()
}

/// Security shape from the same captured relation used for evaluators and ACE generation.
pub fn air_shape(relation: &CompiledRelation<'_>) -> AirShape {
    let geometry = relation.geometry();
    assert_eq!(geometry.airs.len(), crate::precompiles::NUM_CHIPLETS);
    let fractions_per_row: usize = ChipletAir::all().into_iter().map(fractions_per_row_of).sum();
    AirShape {
        num_composed_constraints: (geometry.num_constraints + geometry.airs.len() - 1) as u32,
        max_constraint_degree: geometry.max_constraint_degree as u32,
        num_quotient_chunks: geometry.num_quotient_chunks as u32,
        max_combo: NUM_OOD_POINTS,
        num_deep_terms: Some(geometry.committed_width() as u32 + NUM_OOD_POINTS),
        lookup: Some(LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MAX_MESSAGE_WIDTH as u32,
        }),
    }
}
