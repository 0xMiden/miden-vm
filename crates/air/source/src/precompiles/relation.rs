//! Canonical AIR order and height rules of the precompile relation.

use alloc::vec::Vec;

use miden_stark::air::LiftedAir;

use crate::precompiles::{ChipletAir, NUM_CHIPLETS};

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
    RelationProtocol {
        heights: airs
            .iter()
            .map(|air| {
                air.log_preprocessed_height()
                    .map(|log_height| HeightRule::Fixed(u32::from(log_height)))
                    .unwrap_or_else(|| {
                        HeightRule::Minimum(air.max_periodic_length().max(2).ilog2())
                    })
            })
            .collect(),
        max_periodic_log: airs
            .iter()
            .map(|air| air.max_periodic_length().max(1).ilog2())
            .max()
            .unwrap_or(0),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeightRule {
    Minimum(u32),
    Fixed(u32),
}

#[derive(Clone, Debug)]
pub struct RelationProtocol {
    pub heights: Vec<HeightRule>,
    pub max_periodic_log: u32,
}
