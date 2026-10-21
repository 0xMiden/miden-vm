use alloc::{borrow::Cow, vec::Vec};

use miden_air_definitions::precompiles as definitions;
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::air::{
    BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, MultiAir, ReductionError,
};

#[allow(clippy::eq_op)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/pvm_evaluators.rs"));
}
/// Number of AIR instances in the precompile relation.
pub const NUM_CHIPLETS: usize = definitions::NUM_CHIPLETS;

/// The twelve chiplet AIRs wrapped into one enum.
///
/// Variant order is the canonical proof instance order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChipletAir {
    ChunkNodeSponge,
    EidosCompression,
    KeccakRound,
    BytePairLut,
    TranscriptEval,
    UintStoreMul,
    UintAdd,
    EcPointStoreGroups,
    EcGroupAdd,
    EcMsm,
    Sha512,
    Sha256,
}

impl ChipletAir {
    pub const TRANSCRIPT_EVAL_INDEX: usize = definitions::ChipletAir::TRANSCRIPT_EVAL_INDEX;

    pub fn definition(&self) -> definitions::ChipletAir {
        match self {
            Self::ChunkNodeSponge => definitions::ChipletAir::ChunkNodeSponge,
            Self::EidosCompression => definitions::ChipletAir::EidosCompression,
            Self::KeccakRound => definitions::ChipletAir::KeccakRound,
            Self::BytePairLut => definitions::ChipletAir::BytePairLut,
            Self::TranscriptEval => definitions::ChipletAir::TranscriptEval,
            Self::UintStoreMul => definitions::ChipletAir::UintStoreMul,
            Self::UintAdd => definitions::ChipletAir::UintAdd,
            Self::EcPointStoreGroups => definitions::ChipletAir::EcPointStoreGroups,
            Self::EcGroupAdd => definitions::ChipletAir::EcGroupAdd,
            Self::EcMsm => definitions::ChipletAir::EcMsm,
            Self::Sha512 => definitions::ChipletAir::Sha512,
            Self::Sha256 => definitions::ChipletAir::Sha256,
        }
    }
}
impl ChipletAir {
    /// The twelve AIRs in canonical prover trace order.
    pub fn all() -> [ChipletAir; NUM_CHIPLETS] {
        definitions::ChipletAir::all().map(Self::from_definition)
    }
    pub fn from_definition(air: definitions::ChipletAir) -> Self {
        match air {
            definitions::ChipletAir::ChunkNodeSponge => Self::ChunkNodeSponge,
            definitions::ChipletAir::EidosCompression => Self::EidosCompression,
            definitions::ChipletAir::KeccakRound => Self::KeccakRound,
            definitions::ChipletAir::BytePairLut => Self::BytePairLut,
            definitions::ChipletAir::TranscriptEval => Self::TranscriptEval,
            definitions::ChipletAir::UintStoreMul => Self::UintStoreMul,
            definitions::ChipletAir::UintAdd => Self::UintAdd,
            definitions::ChipletAir::EcPointStoreGroups => Self::EcPointStoreGroups,
            definitions::ChipletAir::EcGroupAdd => Self::EcGroupAdd,
            definitions::ChipletAir::EcMsm => Self::EcMsm,
            definitions::ChipletAir::Sha512 => Self::Sha512,
            definitions::ChipletAir::Sha256 => Self::Sha256,
        }
    }
    /// The fixed log2 trace height of this instance, if the relation pins one.
    ///
    /// `BytePairLut` commits its main and preprocessed traces at
    /// [`crate::precompiles::primitives::byte_pair_lut::TRACE_HEIGHT`], so its proof shapes must
    /// carry exactly that height; every other instance ranges above its derived minimum.
    pub fn fixed_log_height(&self) -> Option<u32> {
        self.definition().fixed_log_height()
    }
}

impl BaseAir<Felt> for ChipletAir {
    fn width(&self) -> usize {
        self.definition().width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.definition().preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.definition().preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.definition().num_public_values()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.definition().periodic_columns().into_owned().into()
    }
}

mod degrees {
    use miden_stark::air::ConstraintDegrees;

    use super::ChipletAir;

    include!(concat!(env!("OUT_DIR"), "/pvm_degrees.rs"));
}
impl LiftedAir<Felt, QuadFelt> for ChipletAir {
    fn constraint_degree(&self) -> ConstraintDegrees {
        degrees::generated_degrees(self)
    }

    fn max_periodic_length(&self) -> usize {
        self.definition().max_periodic_length()
    }

    fn num_randomness(&self) -> usize {
        self.definition().num_randomness()
    }
    fn aux_width(&self) -> usize {
        self.definition().aux_width()
    }
    fn num_aux_values(&self) -> usize {
        self.definition().num_aux_values()
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.definition().build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.definition().build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            Self::ChunkNodeSponge => generated::eval_chunk_node_sponge(builder),
            Self::EidosCompression => generated::eval_eidos_compression(builder),
            Self::KeccakRound => generated::eval_keccak_round(builder),
            Self::BytePairLut => generated::eval_byte_pair_lut(builder),
            Self::TranscriptEval => generated::eval_transcript_eval(builder),
            Self::UintStoreMul => generated::eval_uint_store_mul(builder),
            Self::UintAdd => generated::eval_uint_add(builder),
            Self::EcPointStoreGroups => generated::eval_ec_point_store_groups(builder),
            Self::EcGroupAdd => generated::eval_ec_group_add(builder),
            Self::EcMsm => generated::eval_ec_msm(builder),
            Self::Sha512 => generated::eval_sha512(builder),
            Self::Sha256 => generated::eval_sha256(builder),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChipletMultiAir {
    airs: Vec<ChipletAir>,
    definition: definitions::ChipletMultiAir,
}
impl ChipletMultiAir {
    pub fn new() -> Self {
        let definition = definitions::ChipletMultiAir::new();
        let airs = definition.airs().iter().copied().map(ChipletAir::from_definition).collect();
        Self { airs, definition }
    }

    fn definition(&self) -> &definitions::ChipletMultiAir {
        &self.definition
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
    fn max_aux_inputs(&self) -> usize {
        self.definition().max_aux_inputs()
    }
    fn observe<C: p3_challenger::CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        heights: &[u8],
    ) {
        self.definition().observe(challenger, air_inputs, aux_inputs, heights)
    }
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        air_inputs: &[Vec<Felt>],
        aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        self.definition()
            .eval_external(challenges, air_inputs, aux_inputs, aux_values, heights)
    }
}
