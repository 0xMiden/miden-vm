//! Authored AIRs and stable instance order for the chiplet stack.
//!
//! [`ChipletAir`] wraps the twelve heterogeneous AIRs into one enum. Each AIR commits a
//! normalized residue; [`super::statement`] supplies the trace-length-weighted external closure.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::precompile::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    primitives::byte_pair_lut::{self, BytePairLutAir},
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Number of AIR instances in the precompile relation.
pub const NUM_CHIPLETS: usize = 12;

/// The twelve chiplet AIRs wrapped into one enum.
///
/// Variant order is the canonical proof instance order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
macro_rules! delegate {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            ChipletAir::ChunkNodeSponge => ChunkNodeSpongeAir.$method($($arg),*),
            ChipletAir::EidosCompression => EidosCompressionAir.$method($($arg),*),
            ChipletAir::KeccakRound => KeccakRoundAir.$method($($arg),*),
            ChipletAir::BytePairLut => BytePairLutAir.$method($($arg),*),
            ChipletAir::TranscriptEval => TranscriptEvalAir.$method($($arg),*),
            ChipletAir::UintStoreMul => UintStoreMulAir.$method($($arg),*),
            ChipletAir::UintAdd => UintAddAir.$method($($arg),*),
            ChipletAir::EcPointStoreGroups => EcPointStoreGroupsAir.$method($($arg),*),
            ChipletAir::EcGroupAdd => EcGroupAddAir.$method($($arg),*),
            ChipletAir::EcMsm => EcMsmAir.$method($($arg),*),
            ChipletAir::Sha512 => Sha512Air.$method($($arg),*),
            ChipletAir::Sha256 => Sha256Air.$method($($arg),*),
        }
    };
}

fn eval_lifted<A, AB>(air: &A, builder: &mut AB)
where
    A: LiftedAir<Felt, QuadFelt>,
    AB: LiftedAirBuilder<F = Felt>,
{
    <A as LiftedAir<Felt, QuadFelt>>::eval::<AB>(air, builder);
}

impl ChipletAir {
    /// Stable generated evaluator name, independent of canonical proof order.
    pub const fn file_token(&self) -> &'static str {
        match self {
            Self::ChunkNodeSponge => "chunk_node_sponge",
            Self::EidosCompression => "eidos_compression",
            Self::KeccakRound => "keccak_round",
            Self::BytePairLut => "byte_pair_lut",
            Self::TranscriptEval => "transcript_eval",
            Self::UintStoreMul => "uint_store_mul",
            Self::UintAdd => "uint_add",
            Self::EcPointStoreGroups => "ec_point_store_groups",
            Self::EcGroupAdd => "ec_group_add",
            Self::EcMsm => "ec_msm",
            Self::Sha512 => "sha512",
            Self::Sha256 => "sha256",
        }
    }
    /// Instance index of the AIR that reads the public transcript root.
    pub const TRANSCRIPT_EVAL_INDEX: usize = 4;

    /// The twelve AIRs in canonical prover trace order.
    pub fn all() -> [ChipletAir; NUM_CHIPLETS] {
        crate::precompile::relation::AIRS
    }

    /// The fixed log2 trace height of this instance, if the relation pins one.
    ///
    /// `BytePairLut` commits its main and preprocessed traces at
    /// [`byte_pair_lut::TRACE_HEIGHT`], so its proof shapes must carry exactly that height;
    /// every other instance ranges above its derived minimum.
    pub fn fixed_log_height(&self) -> Option<u32> {
        match self {
            ChipletAir::BytePairLut => Some(byte_pair_lut::TRACE_HEIGHT.ilog2()),
            _ => None,
        }
    }
}

impl BaseAir<Felt> for ChipletAir {
    fn width(&self) -> usize {
        delegate!(self, width)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        delegate!(self, preprocessed_trace)
    }
    fn preprocessed_width(&self) -> usize {
        delegate!(self, preprocessed_width)
    }
    fn num_public_values(&self) -> usize {
        delegate!(self, num_public_values)
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        delegate!(self, periodic_columns)
    }
}

impl LiftedAir<Felt, QuadFelt> for ChipletAir {
    fn max_periodic_length(&self) -> usize {
        delegate!(self, max_periodic_length)
    }

    fn num_randomness(&self) -> usize {
        delegate!(self, num_randomness)
    }
    fn aux_width(&self) -> usize {
        delegate!(self, aux_width)
    }
    fn num_aux_values(&self) -> usize {
        delegate!(self, num_aux_values)
    }
    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        delegate!(self, build_aux_trace, main, air_inputs, aux_inputs, challenges)
    }
    fn build_aux_trace_with_preprocessed(
        &self,
        main: &RowMajorMatrix<Felt>,
        preprocessed: Option<&RowMajorMatrix<Felt>>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        delegate!(
            self,
            build_aux_trace_with_preprocessed,
            main,
            preprocessed,
            air_inputs,
            aux_inputs,
            challenges
        )
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            ChipletAir::ChunkNodeSponge => eval_lifted(&ChunkNodeSpongeAir, builder),
            ChipletAir::EidosCompression => eval_lifted(&EidosCompressionAir, builder),
            ChipletAir::KeccakRound => eval_lifted(&KeccakRoundAir, builder),
            ChipletAir::BytePairLut => eval_lifted(&BytePairLutAir, builder),
            ChipletAir::TranscriptEval => eval_lifted(&TranscriptEvalAir, builder),
            ChipletAir::UintStoreMul => eval_lifted(&UintStoreMulAir, builder),
            ChipletAir::UintAdd => eval_lifted(&UintAddAir, builder),
            ChipletAir::EcPointStoreGroups => eval_lifted(&EcPointStoreGroupsAir, builder),
            ChipletAir::EcGroupAdd => eval_lifted(&EcGroupAddAir, builder),
            ChipletAir::EcMsm => eval_lifted(&EcMsmAir, builder),
            ChipletAir::Sha512 => eval_lifted(&Sha512Air, builder),
            ChipletAir::Sha256 => eval_lifted(&Sha256Air, builder),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_chiplet_preserves_its_degree_and_quotient_budget() {
        use miden_stark::air::ConstraintDegrees;
        let expected = [
            (5, 5, 2),
            (3, 3, 1),
            (2, 5, 2),
            (0, 3, 1),
            (3, 3, 1),
            (3, 3, 1),
            (3, 3, 1),
            (2, 3, 1),
            (3, 3, 1),
            (3, 3, 1),
            (5, 5, 2),
            (5, 5, 2),
        ];
        for (air, (base, ext, log_quotient)) in ChipletAir::all().into_iter().zip(expected) {
            let derived = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
            assert_eq!(derived, ConstraintDegrees { base, ext }, "{air:?}");
            assert_eq!(air.constraint_degree(), derived, "{air:?}: declared degree");
            assert_eq!(
                miden_stark::log_quotient_degree::<Felt, QuadFelt, _>(&air),
                log_quotient,
                "{air:?}: quotient factor"
            );
        }
    }

}
