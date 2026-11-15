//! Production precompile AIR adapters and build-generated evaluation.

use alloc::vec::Vec;
use miden_air_definitions::precompiles as definitions;
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{MultiAir, ReductionError};

/// Number of AIR instances in the precompile relation.
pub const NUM_CHIPLETS: usize = definitions::NUM_CHIPLETS;

/// Production evaluator for an authored precompile AIR.
///
/// Constraint evaluation and degrees use build-generated code. Trace metadata and
/// auxiliary-trace construction delegate to the authored definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChipletAir(pub definitions::ChipletAir);

impl ChipletAir {
    pub const CHUNK_NODE_SPONGE: Self = Self(definitions::ChipletAir::ChunkNodeSponge);
    pub const EIDOS_COMPRESSION: Self = Self(definitions::ChipletAir::EidosCompression);
    pub const KECCAK_ROUND: Self = Self(definitions::ChipletAir::KeccakRound);
    pub const BYTE_PAIR_LUT: Self = Self(definitions::ChipletAir::BytePairLut);
    pub const TRANSCRIPT_EVAL: Self = Self(definitions::ChipletAir::TranscriptEval);
    pub const UINT_STORE_MUL: Self = Self(definitions::ChipletAir::UintStoreMul);
    pub const UINT_ADD: Self = Self(definitions::ChipletAir::UintAdd);
    pub const EC_POINT_STORE_GROUPS: Self = Self(definitions::ChipletAir::EcPointStoreGroups);
    pub const EC_GROUP_ADD: Self = Self(definitions::ChipletAir::EcGroupAdd);
    pub const EC_MSM: Self = Self(definitions::ChipletAir::EcMsm);
    pub const SHA512: Self = Self(definitions::ChipletAir::Sha512);
    pub const SHA256: Self = Self(definitions::ChipletAir::Sha256);

    pub const TRANSCRIPT_EVAL_INDEX: usize = definitions::ChipletAir::TRANSCRIPT_EVAL_INDEX;

    pub fn definition(&self) -> definitions::ChipletAir {
        self.0
    }

    /// The twelve AIRs in canonical prover trace order.
    pub fn all() -> [ChipletAir; NUM_CHIPLETS] {
        definitions::ChipletAir::all().map(Self)
    }
}

#[derive(Clone, Debug)]
pub struct ChipletMultiAir {
    airs: Vec<ChipletAir>,
}
impl ChipletMultiAir {
    pub fn new() -> Self {
        let authored = definitions::ChipletAir::all();
        let airs = authored.map(ChipletAir).to_vec();
        Self { airs }
    }
}
impl Default for ChipletMultiAir {
    fn default() -> Self {
        Self::new()
    }
}
impl MultiAir<Felt, QuadFelt> for ChipletMultiAir {
    type Air = ChipletAir;
    fn airs(&self) -> &[ChipletAir] {
        &self.airs
    }
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        definitions::statement::eval_external(
            challenges, air_inputs, aux_inputs, aux_values, heights,
        )
    }
}
