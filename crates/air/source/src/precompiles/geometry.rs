use {
    miden_core::Felt,
    miden_core::field::QuadFelt,
};
use {
    miden_stark::lookup::LookupAir,
    miden_stark::lookup::ProverLookupBuilder,
};
use {
    p3_security::budget::AirShape,
    p3_security::budget::LookupShape,
};

use {
    crate::precompiles::ChipletAir,
    crate::precompiles::ec::add::EcGroupAddAir,
    crate::precompiles::ec::msm::EcMsmAir,
    crate::precompiles::ec::point_store_groups::EcPointStoreGroupsAir,
    crate::precompiles::hash::chunk_node_sponge::ChunkNodeSpongeAir,
    crate::precompiles::hash::keccak::round::KeccakRoundAir,
    crate::precompiles::hash::sha256::Sha256Air,
    crate::precompiles::hash::sha512::Sha512Air,
    crate::precompiles::primitives::byte_pair_lut::BytePairLutAir,
    crate::precompiles::relations::MAX_MESSAGE_WIDTH,
    crate::precompiles::transcript::eidos::EidosCompressionAir,
    crate::precompiles::transcript::eval::TranscriptEvalAir,
    crate::precompiles::uint::add::UintAddAir,
    crate::precompiles::uint::store_mul::UintStoreMulAir,
};

/// Derive the full member's security shape for tooling and differential validation.
pub fn derive_air_shape() -> AirShape {
    let airs = ChipletAir::all();
    crate::shared::geometry::derive_air_shape(
        &airs,
        lookup_shape(),
        crate::precompiles::ace::LMCS_ALIGNMENT,
    )
}

pub(crate) fn lookup_shape() -> LookupShape {
    LookupShape {
        fractions_per_row: ChipletAir::all().into_iter().map(fractions_per_row_of).sum::<usize>()
            as u32,
        max_message_width: MAX_MESSAGE_WIDTH as u32,
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
