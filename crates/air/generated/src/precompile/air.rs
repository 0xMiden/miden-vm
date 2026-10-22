use alloc::{borrow::Cow, vec::Vec};

use miden_air_source::precompile as definitions;
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

    /// The fixed log2 trace height of this instance, if the relation pins one.
    ///
    /// `BytePairLut` commits its main and preprocessed traces at
    /// [`crate::precompile::primitives::byte_pair_lut::TRACE_HEIGHT`], so its proof shapes must
    /// carry exactly that height; every other instance ranges above its derived minimum.
    pub fn fixed_log_height(&self) -> Option<u32> {
        self.0.fixed_log_height()
    }
}

impl BaseAir<Felt> for ChipletAir {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        self.0.preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        self.0.periodic_columns()
    }
}

include!(concat!(env!("OUT_DIR"), "/pvm_degrees.rs"));
impl LiftedAir<Felt, QuadFelt> for ChipletAir {
    fn constraint_degree(&self) -> ConstraintDegrees {
        generated_degrees(*self)
    }

    fn max_periodic_length(&self) -> usize {
        self.0.max_periodic_length()
    }

    fn num_randomness(&self) -> usize {
        self.0.num_randomness()
    }
    fn aux_width(&self) -> usize {
        self.0.aux_width()
    }
    fn num_aux_values(&self) -> usize {
        self.0.num_aux_values()
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.0.build_aux_trace(main, air_inputs, aux_inputs, challenges)
    }
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        self.0.build_aux_trace_with_preprocessed(
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges,
        )
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self.0 {
            definitions::ChipletAir::ChunkNodeSponge => generated::eval_chunk_node_sponge(builder),
            definitions::ChipletAir::EidosCompression => generated::eval_eidos_compression(builder),
            definitions::ChipletAir::KeccakRound => generated::eval_keccak_round(builder),
            definitions::ChipletAir::BytePairLut => generated::eval_byte_pair_lut(builder),
            definitions::ChipletAir::TranscriptEval => generated::eval_transcript_eval(builder),
            definitions::ChipletAir::UintStoreMul => generated::eval_uint_store_mul(builder),
            definitions::ChipletAir::UintAdd => generated::eval_uint_add(builder),
            definitions::ChipletAir::EcPointStoreGroups => {
                generated::eval_ec_point_store_groups(builder)
            },
            definitions::ChipletAir::EcGroupAdd => generated::eval_ec_group_add(builder),
            definitions::ChipletAir::EcMsm => generated::eval_ec_msm(builder),
            definitions::ChipletAir::Sha512 => generated::eval_sha512(builder),
            definitions::ChipletAir::Sha256 => generated::eval_sha256(builder),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChipletMultiAir {
    airs: Vec<ChipletAir>,
    boundary: definitions::relation::AuxBoundaryPlan,
}
impl ChipletMultiAir {
    pub fn new() -> Self {
        let authored = definitions::ChipletAir::all();
        let boundary = definitions::relation::AuxBoundaryPlan::for_airs(&authored);
        let airs = authored.map(ChipletAir).to_vec();
        Self { airs, boundary }
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
            &self.boundary,
            challenges,
            air_inputs,
            aux_inputs,
            aux_values,
            heights,
        )
    }
}
