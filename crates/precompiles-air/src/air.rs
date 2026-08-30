//! Multi-AIR relation for the chiplet stack.
//!
//! [`ChipletAir`] wraps the ten heterogeneous AIRs into one enum (the
//! `MultiAir::Air` type); [`ChipletMultiAir`] owns them and closes the
//! cross-chiplet LogUp identity in [`MultiAir::eval_external`]. Each AIR commits a normalized
//! residue, so the external assertion weights it by that AIR's trace length.

use alloc::{format, vec, vec::Vec};

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
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice},
    primitives::byte_pair_lut::{self, BytePairLutAir},
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
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
    EidosCompression,
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
            ChipletAir::EidosCompression => EidosCompressionAir.$method($($arg),*),
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
            ChipletAir::EidosCompression,
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
    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        delegate!(self, periodic_columns)
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
            ChipletAir::EidosCompression => eval_lifted(&EidosCompressionAir, builder),
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

/// The chiplet stack as a [`MultiAir`].
///
/// It owns the ten AIRs in canonical order and closes the cross-chiplet LogUp identity in
/// [`eval_external`](Self::eval_external), weighting each normalized residue by its trace length.
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

    /// Cross-chiplet LogUp closure. Every AIR exposes one centered residue
    /// `sigma_prime_i = sigma_i / n_i`; therefore `sum_i(n_i * sigma_prime_i)` plus the fixed
    /// boundary correction must vanish.
    fn eval_external(
        &self,
        challenges: &[QuadFelt],
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        aux_values: &[&[QuadFelt]],
        log_trace_heights: &[u8],
    ) -> Result<Vec<QuadFelt>, ReductionError> {
        if aux_values.len() != self.airs.len() {
            return Err(format!(
                "expected aux values for {} AIRs, got {}",
                self.airs.len(),
                aux_values.len()
            )
            .into());
        }
        if log_trace_heights.len() != self.airs.len() {
            return Err(format!(
                "expected log heights for {} AIRs, got {}",
                self.airs.len(),
                log_trace_heights.len()
            )
            .into());
        }
        if challenges.len() != crate::logup::NUM_RANDOMNESS {
            return Err(format!(
                "expected {} aux trace challenges, got {}",
                crate::logup::NUM_RANDOMNESS,
                challenges.len()
            )
            .into());
        }
        if air_inputs.len() != crate::logup::NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {} public values, got {}",
                crate::logup::NUM_PUBLIC_VALUES,
                air_inputs.len()
            )
            .into());
        }
        if !aux_inputs.is_empty() {
            return Err(format!("expected no auxiliary inputs, got {}", aux_inputs.len()).into());
        }

        let mut weighted_aux_sum = QuadFelt::ZERO;
        for ((air, values), &log_height) in self.airs.iter().zip(aux_values).zip(log_trace_heights)
        {
            let expected = air.num_aux_values();
            if values.len() != expected {
                return Err(format!(
                    "{air:?} expects {expected} aux boundary values, got {}",
                    values.len()
                )
                .into());
            }

            let trace_length = 1_u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
                ReductionError::from(format!(
                    "{air:?} log trace height {log_height} does not fit in u64"
                ))
            })?;
            weighted_aux_sum +=
                values.iter().copied().sum::<QuadFelt>() * Felt::new_unchecked(trace_length);
        }
        Ok(vec![weighted_aux_sum + fixed_boundary_correction(challenges)?])
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::PrimeCharacteristicRing;

    use super::*;

    /// The external assertion is part of the production relation but excluded from the ACE
    /// circuit digest. This test guards its weighting; raw bus-balance tests cover the underlying
    /// lookup semantics independently.
    #[test]
    fn chiplet_multi_air_weights_every_normalized_sum_by_trace_length() {
        let challenges = [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ];
        let multi_air = ChipletMultiAir::new();
        let aux_values: Vec<Vec<QuadFelt>> = multi_air
            .airs()
            .iter()
            .enumerate()
            .map(|(i, air)| {
                (0..air.num_aux_values())
                    .map(|j| {
                        QuadFelt::new([
                            Felt::from((i + j + 1) as u32),
                            Felt::from((2 * i + j + 1) as u32),
                        ])
                    })
                    .collect()
            })
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();

        // BytePairLut is fixed at 2^16; every other entry satisfies its AIR's minimum height.
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13];
        let assertions = multi_air
            .eval_external(
                &challenges,
                &[Felt::ZERO; crate::logup::NUM_PUBLIC_VALUES],
                &[],
                &aux_refs,
                &log_heights,
            )
            .expect("fixed boundary denominators are non-zero for the fixture");

        assert_eq!(assertions.len(), 1, "the relation exposes exactly one external assertion");
        let expected_weighted_sum = aux_values
            .iter()
            .zip(log_heights)
            .map(|(values, log_height)| {
                values.iter().copied().sum::<QuadFelt>()
                    * Felt::new_unchecked(1_u64 << u32::from(log_height))
            })
            .sum::<QuadFelt>();
        assert_eq!(
            assertions[0],
            expected_weighted_sum + fixed_boundary_correction(&challenges).unwrap(),
        );
    }

    #[test]
    fn chiplet_multi_air_rejects_malformed_external_inputs() {
        let multi_air = ChipletMultiAir::new();
        let challenges = [QuadFelt::ONE; crate::logup::NUM_RANDOMNESS];
        let air_inputs = [Felt::ZERO; crate::logup::NUM_PUBLIC_VALUES];
        let aux_values: Vec<Vec<QuadFelt>> = multi_air
            .airs()
            .iter()
            .map(|air| vec![QuadFelt::ZERO; air.num_aux_values()])
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13];
        let rejects = |case: &str,
                       challenges: &[QuadFelt],
                       air_inputs: &[Felt],
                       aux_inputs: &[Felt],
                       aux_values: &[&[QuadFelt]],
                       log_heights: &[u8]| {
            assert!(
                multi_air
                    .eval_external(challenges, air_inputs, aux_inputs, aux_values, log_heights)
                    .is_err(),
                "{case} must be rejected",
            );
        };

        rejects(
            "missing AIR values",
            &challenges,
            &air_inputs,
            &[],
            &aux_refs[..NUM_CHIPLETS - 1],
            &log_heights,
        );
        rejects(
            "missing log height",
            &challenges,
            &air_inputs,
            &[],
            &aux_refs,
            &log_heights[..NUM_CHIPLETS - 1],
        );
        rejects(
            "missing challenge",
            &challenges[..crate::logup::NUM_RANDOMNESS - 1],
            &air_inputs,
            &[],
            &aux_refs,
            &log_heights,
        );
        rejects(
            "missing public value",
            &challenges,
            &air_inputs[..crate::logup::NUM_PUBLIC_VALUES - 1],
            &[],
            &aux_refs,
            &log_heights,
        );
        rejects(
            "unexpected auxiliary input",
            &challenges,
            &air_inputs,
            &[Felt::ZERO],
            &aux_refs,
            &log_heights,
        );

        let mut malformed_values = aux_values.clone();
        malformed_values[0].push(QuadFelt::ZERO);
        let malformed_refs: Vec<&[QuadFelt]> = malformed_values.iter().map(Vec::as_slice).collect();
        rejects(
            "wrong AIR value width",
            &challenges,
            &air_inputs,
            &[],
            &malformed_refs,
            &log_heights,
        );

        let mut oversized_height = log_heights;
        oversized_height[0] = u64::BITS as u8;
        rejects(
            "oversized log height",
            &challenges,
            &air_inputs,
            &[],
            &aux_refs,
            &oversized_height,
        );
    }

    /// The chiplet instance order fixes proof-order tie-breaks, registry tags, and the
    /// relation digest. Intentional changes require regenerated protocol constants and a
    /// breaking changelog entry.
    #[test]
    fn chiplet_instance_order_is_protocol_pinned() {
        let pinned = [
            ChipletAir::ChunkNodeSponge,
            ChipletAir::EidosCompression,
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
