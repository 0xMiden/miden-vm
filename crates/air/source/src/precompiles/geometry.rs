use miden_core::{Felt, field::QuadFelt};
use miden_stark::lookup::{LookupAir, ProverLookupBuilder};
use p3_security::budget::{AirShape, LookupShape};

use crate::precompiles::{
    ChipletAir,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    primitives::byte_pair_lut::BytePairLutAir,
    relations::MAX_MESSAGE_WIDTH,
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Derive the full member's security shape for tooling and differential validation.
pub fn derive_air_shape() -> AirShape {
    let airs = ChipletAir::all();
    crate::shared::geometry::derive_air_shape(
        &airs,
        LookupShape {
            fractions_per_row: airs.iter().cloned().map(fractions_per_row_of).sum::<usize>() as u32,
            max_message_width: MAX_MESSAGE_WIDTH as u32,
        },
        crate::precompiles::ace::LMCS_ALIGNMENT,
    )
}

pub(crate) fn fractions_per_row_of(air: ChipletAir) -> usize {
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
