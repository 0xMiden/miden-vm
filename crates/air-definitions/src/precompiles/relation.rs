//! Canonical AIR order and protocol policy of the precompile relation.

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt, utils::Matrix};
use miden_lifted_air::{BaseAir, LiftedAir};

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
    let num_public_values = airs.iter().map(BaseAir::num_public_values).sum();
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
