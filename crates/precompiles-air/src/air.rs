//! Multi-AIR relation for the chiplet stack.
//!
//! [`ChipletAir`] wraps the ten heterogeneous AIRs into one enum (the
//! `MultiAir::Air` type); [`ChipletMultiAir`] owns them and closes the
//! cross-chiplet LogUp identity — `Σ σ = 0` — in
//! [`MultiAir::eval_external`].

use alloc::{borrow::Cow, vec, vec::Vec};

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder, MultiAir, ReductionError};

use crate::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    fixed::{fixed_ecgroup_msgs, fixed_uintval_msgs},
    hash::{chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir},
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice, sigma_sum},
    primitives::byte_pair_lut::{self, BytePairLutAir},
    transcript::{eval::TranscriptEvalAir, poseidon2::Poseidon2Air},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Number of AIR instances in the precompile relation.
pub const NUM_CHIPLETS: usize = 10;

/// The ten chiplet AIRs wrapped into one enum.
///
/// Variant order is the canonical proof instance order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChipletAir {
    ChunkNodeSponge,
    Poseidon2,
    KeccakRound,
    BytePairLut,
    TranscriptEval,
    UintStoreMul,
    UintAdd,
    EcPointStoreGroups,
    EcGroupAdd,
    EcMsm,
}

macro_rules! delegate {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            ChipletAir::ChunkNodeSponge => ChunkNodeSpongeAir.$method($($arg),*),
            ChipletAir::Poseidon2 => Poseidon2Air.$method($($arg),*),
            ChipletAir::KeccakRound => KeccakRoundAir.$method($($arg),*),
            ChipletAir::BytePairLut => BytePairLutAir.$method($($arg),*),
            ChipletAir::TranscriptEval => TranscriptEvalAir.$method($($arg),*),
            ChipletAir::UintStoreMul => UintStoreMulAir.$method($($arg),*),
            ChipletAir::UintAdd => UintAddAir.$method($($arg),*),
            ChipletAir::EcPointStoreGroups => EcPointStoreGroupsAir.$method($($arg),*),
            ChipletAir::EcGroupAdd => EcGroupAddAir.$method($($arg),*),
            ChipletAir::EcMsm => EcMsmAir.$method($($arg),*),
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
    /// The ten AIRs in canonical prover trace order.
    pub fn all() -> [ChipletAir; NUM_CHIPLETS] {
        [
            ChipletAir::ChunkNodeSponge,
            ChipletAir::Poseidon2,
            ChipletAir::KeccakRound,
            ChipletAir::BytePairLut,
            ChipletAir::TranscriptEval,
            ChipletAir::UintStoreMul,
            ChipletAir::UintAdd,
            ChipletAir::EcPointStoreGroups,
            ChipletAir::EcGroupAdd,
            ChipletAir::EcMsm,
        ]
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
        Cow::Owned(delegate!(self, periodic_columns).into_owned())
    }
}

impl LiftedAir<Felt, QuadFelt> for ChipletAir {
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
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        match self {
            ChipletAir::ChunkNodeSponge => eval_lifted(&ChunkNodeSpongeAir, builder),
            ChipletAir::Poseidon2 => eval_lifted(&Poseidon2Air, builder),
            ChipletAir::KeccakRound => eval_lifted(&KeccakRoundAir, builder),
            ChipletAir::BytePairLut => eval_lifted(&BytePairLutAir, builder),
            ChipletAir::TranscriptEval => eval_lifted(&TranscriptEvalAir, builder),
            ChipletAir::UintStoreMul => eval_lifted(&UintStoreMulAir, builder),
            ChipletAir::UintAdd => eval_lifted(&UintAddAir, builder),
            ChipletAir::EcPointStoreGroups => eval_lifted(&EcPointStoreGroupsAir, builder),
            ChipletAir::EcGroupAdd => eval_lifted(&EcGroupAddAir, builder),
            ChipletAir::EcMsm => eval_lifted(&EcMsmAir, builder),
        }
    }
}

/// The chiplet stack as a [`MultiAir`]: owns the ten AIRs (in canonical
/// order) and closes the cross-chiplet LogUp identity — `Σ σ = 0` over
/// every AIR's committed residue — in [`eval_external`](Self::eval_external).
#[derive(Debug, Clone)]
pub struct ChipletMultiAir {
    airs: Vec<ChipletAir>,
}

impl ChipletMultiAir {
    pub fn new() -> Self {
        Self { airs: ChipletAir::all().to_vec() }
    }
}

impl Default for ChipletMultiAir {
    fn default() -> Self {
        Self::new()
    }
}

fn fixed_boundary_correction(challenges: &[QuadFelt]) -> Result<QuadFelt, ReductionError> {
    let lookup_challenges = lookup_challenges_from_slice(challenges);
    Ok(boundary_correction(
        &lookup_challenges,
        fixed_uintval_msgs(),
        "fixed UintVal boundary denominator was zero",
    )? + boundary_correction(
        &lookup_challenges,
        fixed_ecgroup_msgs(),
        "fixed EcGroup boundary denominator was zero",
    )?)
}

fn boundary_correction<M>(
    challenges: &Challenges<QuadFelt>,
    messages: impl IntoIterator<Item = M>,
    zero_denominator: &'static str,
) -> Result<QuadFelt, ReductionError>
where
    M: LookupMessage<Felt, QuadFelt>,
{
    let mut correction = QuadFelt::ZERO;
    for msg in messages {
        let Some(inv) = msg.encode(challenges).try_inverse() else {
            return Err(zero_denominator.into());
        };
        correction += inv;
    }
    Ok(correction)
}

impl MultiAir<Felt, QuadFelt> for ChipletMultiAir {
    type Air = ChipletAir;

    fn airs(&self) -> &[ChipletAir] {
        &self.airs
    }

    /// The cross-chiplet σ identity: the sum of every AIR's committed
    /// σ residue must vanish (a single assertion). `aux_values[i]` is AIR
    /// `i`'s exposed permutation values — exactly one, its σ.
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        _log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        Ok(vec![sigma_sum(aux_values) + fixed_boundary_correction(challenges)?])
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::PrimeCharacteristicRing;

    use super::*;

    /// The external assertion is part of the production relation but excluded from the ACE
    /// circuit digest. This test guards its cardinality; raw bus-balance tests cover the
    /// underlying lookup semantics independently.
    #[test]
    fn chiplet_multi_air_exposes_the_sigma_closure() {
        let challenges = [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ];
        let aux_values: [[QuadFelt; 1]; NUM_CHIPLETS] = core::array::from_fn(|i| {
            [QuadFelt::new([Felt::from((i + 1) as u32), Felt::from((2 * i + 1) as u32)])]
        });
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(<[QuadFelt; 1]>::as_slice).collect();

        let assertions = ChipletMultiAir::new()
            .eval_external(&challenges, &[], &[], &aux_refs, &[])
            .expect("fixed boundary denominators are non-zero for the fixture");

        assert_eq!(assertions.len(), 1, "the relation exposes exactly one external assertion");
        assert_ne!(assertions[0], QuadFelt::ZERO, "the closure fixture must be non-vacuous");
    }

    /// The chiplet instance order fixes proof-order tie-breaks, registry tags, and the
    /// relation digest. Intentional changes require regenerated protocol constants and a
    /// breaking changelog entry.
    #[test]
    fn chiplet_instance_order_is_protocol_pinned() {
        let pinned = [
            ChipletAir::ChunkNodeSponge,
            ChipletAir::Poseidon2,
            ChipletAir::KeccakRound,
            ChipletAir::BytePairLut,
            ChipletAir::TranscriptEval,
            ChipletAir::UintStoreMul,
            ChipletAir::UintAdd,
            ChipletAir::EcPointStoreGroups,
            ChipletAir::EcGroupAdd,
            ChipletAir::EcMsm,
        ];
        assert_eq!(
            ChipletAir::all(),
            pinned,
            "chiplet instance order moved; regenerate the PVM ACE registry for an intentional \
             protocol break"
        );
    }
}
