//! Production precompile relation. This first version deliberately delegates equation dispatch to
//! authored source while keeping production type identity and statement ownership independent.

use alloc::{borrow::Cow, vec::Vec};

use miden_air_source::precompile as source;
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::{
    air::{
        BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, MultiAir as MultiAirTrait,
        ReductionError,
    },
    challenger::CanObserve,
};
pub use source::*;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Air {
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

impl Air {
    pub const fn source(self) -> source::Air {
        match self {
            Self::ChunkNodeSponge => source::Air::ChunkNodeSponge,
            Self::EidosCompression => source::Air::EidosCompression,
            Self::KeccakRound => source::Air::KeccakRound,
            Self::BytePairLut => source::Air::BytePairLut,
            Self::TranscriptEval => source::Air::TranscriptEval,
            Self::UintStoreMul => source::Air::UintStoreMul,
            Self::UintAdd => source::Air::UintAdd,
            Self::EcPointStoreGroups => source::Air::EcPointStoreGroups,
            Self::EcGroupAdd => source::Air::EcGroupAdd,
            Self::EcMsm => source::Air::EcMsm,
            Self::Sha512 => source::Air::Sha512,
            Self::Sha256 => source::Air::Sha256,
        }
    }
    pub fn all() -> [Air; NUM_CHIPLETS] {
        [
            Air::ChunkNodeSponge,
            Air::EidosCompression,
            Air::KeccakRound,
            Air::BytePairLut,
            Air::TranscriptEval,
            Air::UintStoreMul,
            Air::UintAdd,
            Air::EcPointStoreGroups,
            Air::EcGroupAdd,
            Air::EcMsm,
            Air::Sha512,
            Air::Sha256,
        ]
    }
    pub fn fixed_log_height(&self) -> Option<u32> {
        self.source().fixed_log_height()
    }
}

impl From<source::Air> for Air {
    fn from(air: source::Air) -> Self {
        match air {
            source::Air::ChunkNodeSponge => Self::ChunkNodeSponge,
            source::Air::EidosCompression => Self::EidosCompression,
            source::Air::KeccakRound => Self::KeccakRound,
            source::Air::BytePairLut => Self::BytePairLut,
            source::Air::TranscriptEval => Self::TranscriptEval,
            source::Air::UintStoreMul => Self::UintStoreMul,
            source::Air::UintAdd => Self::UintAdd,
            source::Air::EcPointStoreGroups => Self::EcPointStoreGroups,
            source::Air::EcGroupAdd => Self::EcGroupAdd,
            source::Air::EcMsm => Self::EcMsm,
            source::Air::Sha512 => Self::Sha512,
            source::Air::Sha256 => Self::Sha256,
        }
    }
}
impl From<Air> for source::Air {
    fn from(air: Air) -> Self {
        air.source()
    }
}

impl BaseAir<Felt> for Air {
    fn width(&self) -> usize {
        self.source().width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.source().preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.source().preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.source().num_public_values()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(self.source().periodic_columns().into_owned())
    }
}

impl LiftedAir<Felt, QuadFelt> for Air {
    fn max_periodic_length(&self) -> usize {
        self.source().max_periodic_length()
    }
    fn num_randomness(&self) -> usize {
        self.source().num_randomness()
    }
    fn aux_width(&self) -> usize {
        self.source().aux_width()
    }
    fn num_aux_values(&self) -> usize {
        self.source().num_aux_values()
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.source().build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.source().build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }
    fn constraint_degree(&self) -> ConstraintDegrees {
        self.source().constraint_degree()
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        <source::Air as LiftedAir<Felt, QuadFelt>>::eval(&self.source(), builder)
    }
}

#[derive(Clone, Debug)]
pub struct MultiAir {
    airs: Vec<Air>,
}
impl MultiAir {
    pub fn new() -> Self {
        Self { airs: Air::all().to_vec() }
    }
}
impl Default for MultiAir {
    fn default() -> Self {
        Self::new()
    }
}
impl MultiAirTrait<Felt, QuadFelt> for MultiAir {
    type Air = Air;
    fn airs(&self) -> &[Air] {
        &self.airs
    }
    fn num_air_inputs(&self) -> usize {
        source::MultiAir::new().num_air_inputs()
    }
    fn max_aux_inputs(&self) -> usize {
        source::MultiAir::new().max_aux_inputs()
    }
    fn observe<C: CanObserve<Felt>>(
        &self,
        challenger: &mut C,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        log_trace_heights: &[u8],
    ) {
        source::MultiAir::new().observe(challenger, air_inputs, aux_inputs, log_trace_heights);
    }
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        source::MultiAir::new().eval_external(
            challenges,
            air_inputs,
            aux_inputs,
            aux_values,
            log_trace_heights,
        )
    }
}

pub use self::{Air as ChipletAir, MultiAir as ChipletMultiAir};
/// Transitional enum paths preserve production identity for existing direct consumers.
pub mod air {
    pub use super::{Air, Air as ChipletAir, MultiAir, MultiAir as ChipletMultiAir, NUM_CHIPLETS};
}

pub mod protocol;
pub mod stark_config;
pub use protocol::PVM_RELATION_DIGEST;
pub mod artifacts;

pub mod ace_constants;
