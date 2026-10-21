//! Canonical AIR order and protocol policy of the precompile relation.

use alloc::{format, vec::Vec};

#[cfg(feature = "compiler")]
use miden_ace_codegen::{AceError, CapturedAir, CompiledRelation};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, ReductionError};

use crate::precompiles::{ChipletAir, NUM_CHIPLETS, fixed, policy};

/// Canonical AIR identity and proof instance order.
pub const AIRS: [ChipletAir; NUM_CHIPLETS] = [
    ChipletAir::ChunkNodeSponge,
    ChipletAir::EidosCompression,
    ChipletAir::KeccakRound,
    ChipletAir::BytePairLut,
    ChipletAir::TranscriptEval,
    ChipletAir::UintStoreMul,
    ChipletAir::UintAdd,
    ChipletAir::EcPointStoreGroups,
    ChipletAir::EcGroupAdd,
    ChipletAir::EcMsm,
    ChipletAir::Sha512,
    ChipletAir::Sha256,
];

pub fn protocol() -> RelationProtocol {
    let airs = &AIRS;
    let num_public_values = airs[0].num_public_values();
    assert!(airs.iter().all(|air| air.num_public_values() == num_public_values));
    RelationProtocol {
        protocol_id: policy::PROTOCOL_ID,
        num_public_values,
        max_aux_inputs: 0,
        num_aux_inputs: 0,
        heights: airs
            .iter()
            .map(|air| {
                air.fixed_log_height().map(HeightRule::Fixed).unwrap_or_else(|| {
                    let preprocessed_height =
                        air.preprocessed_trace().map_or(0, |trace| trace.height());
                    HeightRule::Minimum(
                        air.max_periodic_length().max(preprocessed_height).max(2).ilog2(),
                    )
                })
            })
            .collect(),
        max_periodic_log: airs
            .iter()
            .map(|air| air.max_periodic_length().max(1).ilog2())
            .max()
            .unwrap_or(0),
        boundary: AuxBoundaryPlan::for_airs(airs),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightRule {
    Minimum(u32),
    Fixed(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuxBoundaryReduction {
    TraceLengthWeightedSum,
}

#[derive(Clone, Debug)]
pub struct AuxBoundaryPlan {
    pub values_per_air: Vec<usize>,
    pub reduction: AuxBoundaryReduction,
    pub fixed_boundary_terms: usize,
}

impl AuxBoundaryPlan {
    pub fn for_airs(airs: &[ChipletAir]) -> Self {
        Self {
            values_per_air: airs.iter().map(LiftedAir::<Felt, QuadFelt>::num_aux_values).collect(),
            reduction: AuxBoundaryReduction::TraceLengthWeightedSum,
            fixed_boundary_terms: fixed::fixed_uintval_msgs().count()
                + fixed::fixed_ecgroup_msgs().count(),
        }
    }

    /// Reduce normalized committed LogUp residues using their committed trace lengths.
    pub fn reduce(
        &self,
        values: &[&[QuadFelt]],
        log_heights: &[u8],
    ) -> Result<QuadFelt, ReductionError> {
        if values.len() != self.values_per_air.len() || log_heights.len() != values.len() {
            return Err("auxiliary boundary AIR count mismatch".into());
        }
        let mut sum = QuadFelt::ZERO;
        for (index, ((values, &expected), &log_height)) in
            values.iter().zip(&self.values_per_air).zip(log_heights).enumerate()
        {
            if values.len() != expected {
                return Err(format!(
                    "AIR {index} expects {expected} auxiliary boundary values, got {}",
                    values.len()
                )
                .into());
            }
            let length = 1u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
                ReductionError::from(format!(
                    "AIR {index} log trace height {log_height} does not fit in u64"
                ))
            })?;
            match self.reduction {
                AuxBoundaryReduction::TraceLengthWeightedSum => {
                    sum += values.iter().copied().sum::<QuadFelt>() * Felt::new_unchecked(length);
                },
            }
        }
        Ok(sum)
    }
}

#[derive(Clone, Debug)]
pub struct RelationProtocol {
    pub protocol_id: u64,
    pub num_public_values: usize,
    pub max_aux_inputs: usize,
    pub num_aux_inputs: usize,
    pub heights: Vec<HeightRule>,
    pub max_periodic_log: u32,
    pub boundary: AuxBoundaryPlan,
}

/// One symbolic capture of each AIR, shared by the compiler backends.
#[cfg(feature = "compiler")]
pub struct CapturedPvmRelation {
    airs: Vec<CapturedAir>,
}

#[cfg(feature = "compiler")]
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
