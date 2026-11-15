//! Authored AIRs and stable instance order for the chiplet stack.
//!
//! [`ChipletAir`] wraps the twelve heterogeneous AIRs into one enum. Each AIR commits a
//! normalized residue; [`super::statement`] supplies the trace-length-weighted external closure.

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::{air::native, lookup::native as native_lookup};

use crate::precompiles::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    primitives::byte_pair_lut::BytePairLutAir,
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
// One concrete source per branch lets each native capability keep its own trait bounds and
// witness error. The expression is checked for every variant; no dynamic source object is used.
macro_rules! with_source {
    ($self:ident, |$air:ident| $body:expr) => {
        match $self {
            ChipletAir::ChunkNodeSponge => {
                let $air = &ChunkNodeSpongeAir;
                $body
            },
            ChipletAir::EidosCompression => {
                let $air = &EidosCompressionAir;
                $body
            },
            ChipletAir::KeccakRound => {
                let $air = &KeccakRoundAir;
                $body
            },
            ChipletAir::BytePairLut => {
                let $air = &BytePairLutAir;
                $body
            },
            ChipletAir::TranscriptEval => {
                let $air = &TranscriptEvalAir;
                $body
            },
            ChipletAir::UintStoreMul => {
                let $air = &UintStoreMulAir;
                $body
            },
            ChipletAir::UintAdd => {
                let $air = &UintAddAir;
                $body
            },
            ChipletAir::EcPointStoreGroups => {
                let $air = &EcPointStoreGroupsAir;
                $body
            },
            ChipletAir::EcGroupAdd => {
                let $air = &EcGroupAddAir;
                $body
            },
            ChipletAir::EcMsm => {
                let $air = &EcMsmAir;
                $body
            },
            ChipletAir::Sha512 => {
                let $air = &Sha512Air;
                $body
            },
            ChipletAir::Sha256 => {
                let $air = &Sha256Air;
                $body
            },
        }
    };
}

impl native::LiftedAir for ChipletAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        with_source!(self, |air| native::LiftedAir::spec(air))
    }

    fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
        with_source!(self, |air| native::LiftedAir::build_preprocessed_trace(air))
    }

    fn eval<B: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, B>,
        inputs: native::Inputs<'_, B>,
        sink: &mut B,
    ) {
        with_source!(self, |air| native::LiftedAir::eval(air, frame, inputs, sink));
    }
}

impl native::ProverAir<QuadFelt> for ChipletAir {
    type Error = crate::shared::WitnessError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        with_source!(self, |air| native::ProverAir::build_aux_trace(air, inputs)
            .map_err(Into::into))
    }
}

impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB> for ChipletAir {
    fn column_shape(&self) -> &[usize] {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::column_shape(air))
    }

    fn max_message_width(&self) -> usize {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::max_message_width(air))
    }

    fn num_bus_ids(&self) -> usize {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::num_bus_ids(air))
    }

    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::eval(air, frame, builder));
    }

    fn eval_boundary<B: miden_stark::lookup::BoundaryBuilder<F = Felt>>(&self, boundary: &mut B) {
        with_source!(self, |air| native_lookup::LookupAir::<LB>::eval_boundary(air, boundary));
    }
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
        crate::precompiles::relation::AIRS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_chiplet_preserves_its_degree_and_quotient_budget() {
        use miden_stark::air::native::{AirKernel, ConstraintDegrees, DirectKernel};
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
            let kernel = DirectKernel::new(air).expect("precompile source descriptor");
            let derived = kernel.descriptor().analysis().raw_degrees();
            assert_eq!(derived, ConstraintDegrees { base, ext }, "{air:?}");
            assert_eq!(
                miden_stark::log_quotient_degree(&kernel).unwrap(),
                log_quotient,
                "{air:?}: quotient factor"
            );
        }
    }
}
