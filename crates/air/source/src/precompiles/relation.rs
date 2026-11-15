//! Canonical AIR order and height rules of the precompile relation.

use alloc::vec::Vec;

use miden_stark::air::native::LiftedAir;

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
    let mut heights = Vec::with_capacity(AIRS.len());
    let mut max_periodic_log = 0;
    for air in &AIRS {
        let spec = air.spec();
        let period = spec.max_periodic_length();
        heights.push(
            spec.preprocessed
                .map(|fixed| HeightRule::Fixed(u32::from(fixed.log_height)))
                .unwrap_or_else(|| HeightRule::Minimum(period.max(2).ilog2())),
        );
        max_periodic_log = max_periodic_log.max(period.max(1).ilog2());
    }
    RelationProtocol { heights, max_periodic_log }
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
