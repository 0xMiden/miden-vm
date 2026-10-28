//! Canonical AIR order and protocol policy of the precompile relation.

use alloc::vec::Vec;

#[cfg(feature = "compiler")]
use miden_ace_codegen::{AceError, CapturedAir, CompiledRelation};
use miden_core::utils::Matrix;
use miden_lifted_air::{BaseAir, LiftedAir};

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
