//! Production precompile AIR adapters and build-generated evaluation.

use alloc::vec::Vec;

use miden_air_definitions::precompiles::{self as definitions, ChipletAir as Source};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{MultiAir, ReductionError};

use crate::kernel::define_dispatch;

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

#[allow(clippy::eq_op)]
mod evaluators {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_evaluators.rs"));
}

mod descriptors {
    include!(concat!(env!("OUT_DIR"), "/pvm_native_descriptors.rs"));
}

define_dispatch!(ChipletAir, Source, PvmPrepared;
    ChunkNodeSponge => (CHUNK_NODE_SPONGE_DESCRIPTOR, descriptor_chunk_node_sponge, CHUNK_NODE_SPONGE_GEOMETRY, precompute_chunk_node_sponge, eval_chunk_node_sponge, CHUNK_NODE_SPONGE_PREPARED_TERMS),
    EidosCompression => (EIDOS_DESCRIPTOR, descriptor_eidos_compression, EIDOS_COMPRESSION_GEOMETRY, precompute_eidos_compression, eval_eidos_compression, EIDOS_COMPRESSION_PREPARED_TERMS),
    KeccakRound => (KECCAK_ROUND_DESCRIPTOR, descriptor_keccak_round, KECCAK_ROUND_GEOMETRY, precompute_keccak_round, eval_keccak_round, KECCAK_ROUND_PREPARED_TERMS),
    BytePairLut => (BYTE_PAIR_LUT_DESCRIPTOR, descriptor_byte_pair_lut, BYTE_PAIR_LUT_GEOMETRY, precompute_byte_pair_lut, eval_byte_pair_lut, BYTE_PAIR_LUT_PREPARED_TERMS),
    TranscriptEval => (TRANSCRIPT_DESCRIPTOR, descriptor_transcript_eval, TRANSCRIPT_EVAL_GEOMETRY, precompute_transcript_eval, eval_transcript_eval, TRANSCRIPT_EVAL_PREPARED_TERMS),
    UintStoreMul => (UINT_STORE_MUL_DESCRIPTOR, descriptor_uint_store_mul, UINT_STORE_MUL_GEOMETRY, precompute_uint_store_mul, eval_uint_store_mul, UINT_STORE_MUL_PREPARED_TERMS),
    UintAdd => (UINT_ADD_DESCRIPTOR, descriptor_uint_add, UINT_ADD_GEOMETRY, precompute_uint_add, eval_uint_add, UINT_ADD_PREPARED_TERMS),
    EcPointStoreGroups => (EC_POINT_STORE_GROUPS_DESCRIPTOR, descriptor_ec_point_store_groups, EC_POINT_STORE_GROUPS_GEOMETRY, precompute_ec_point_store_groups, eval_ec_point_store_groups, EC_POINT_STORE_GROUPS_PREPARED_TERMS),
    EcGroupAdd => (EC_GROUP_ADD_DESCRIPTOR, descriptor_ec_group_add, EC_GROUP_ADD_GEOMETRY, precompute_ec_group_add, eval_ec_group_add, EC_GROUP_ADD_PREPARED_TERMS),
    EcMsm => (EC_MSM_DESCRIPTOR, descriptor_ec_msm, EC_MSM_GEOMETRY, precompute_ec_msm, eval_ec_msm, EC_MSM_PREPARED_TERMS),
    Sha512 => (SHA512_DESCRIPTOR, descriptor_sha512, SHA512_GEOMETRY, precompute_sha512, eval_sha512, SHA512_PREPARED_TERMS),
    Sha256 => (SHA256_DESCRIPTOR, descriptor_sha256, SHA256_GEOMETRY, precompute_sha256, eval_sha256, SHA256_PREPARED_TERMS),
);
