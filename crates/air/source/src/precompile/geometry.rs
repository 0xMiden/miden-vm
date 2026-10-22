#[cfg(feature = "compiler")]
use miden_ace::CompiledRelation;
use miden_core::{Felt, field::QuadFelt};
use p3_security::budget::{AirShape, LookupShape};

use crate::precompile::{
    ChipletAir,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    logup::{LookupAir, ProverLookupBuilder},
    primitives::byte_pair_lut::BytePairLutAir,
    relations::MAX_MESSAGE_WIDTH,
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};
#[cfg(feature = "compiler")]
use crate::shared::geometry::NUM_OOD_POINTS;

/// Derive the full member's security shape for tooling and differential validation.
pub fn derive_air_shape() -> AirShape {
    let airs = ChipletAir::all();
    crate::shared::geometry::derive_air_shape(
        &airs,
        LookupShape {
            fractions_per_row: airs.iter().cloned().map(fractions_per_row_of).sum::<usize>() as u32,
            max_message_width: MAX_MESSAGE_WIDTH as u32,
        },
        crate::precompile::ace::LMCS_ALIGNMENT,
    )
}

/// Security shape from the same captured relation used for evaluators and ACE generation.
#[cfg(feature = "compiler")]
pub fn air_shape(relation: &CompiledRelation<'_>) -> AirShape {
    let geometry = relation.geometry();
    assert_eq!(geometry.airs.len(), crate::precompile::NUM_CHIPLETS);
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

fn fractions_per_row_of(air: ChipletAir) -> usize {
    type ShapeBuilder<'a> = ProverLookupBuilder<'a, Felt, QuadFelt>;

    fn shape_of<A>(air: A) -> usize
    where
        A: for<'a> LookupAir<ShapeBuilder<'a>>,
    {
        LookupAir::<ShapeBuilder<'_>>::column_shape(&air).iter().sum()
    }

    match air {
        ChipletAir::ChunkNodeSponge => shape_of(ChunkNodeSpongeAir),
        ChipletAir::EidosCompression => shape_of(EidosCompressionAir),
        ChipletAir::KeccakRound => shape_of(KeccakRoundAir),
        ChipletAir::BytePairLut => shape_of(BytePairLutAir),
        ChipletAir::TranscriptEval => shape_of(TranscriptEvalAir),
        ChipletAir::UintStoreMul => shape_of(UintStoreMulAir),
        ChipletAir::UintAdd => shape_of(UintAddAir),
        ChipletAir::EcPointStoreGroups => shape_of(EcPointStoreGroupsAir),
        ChipletAir::EcGroupAdd => shape_of(EcGroupAddAir),
        ChipletAir::EcMsm => shape_of(EcMsmAir),
        ChipletAir::Sha512 => shape_of(Sha512Air),
        ChipletAir::Sha256 => shape_of(Sha256Air),
    }
}
