//! Multi-AIR relation for the chiplet stack.
//!
//! [`Air`] wraps the twelve heterogeneous AIRs into one enum (the
//! `MultiAir::Air` type); [`MultiAir`] owns them and closes the
//! cross-chiplet LogUp identity in [`MultiAir::eval_external`]. Each AIR commits a normalized
//! residue, so the external assertion weights it by that AIR's trace length.

use alloc::{borrow::Cow, format, vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::PvmAirVariant,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{
    BaseAir, LiftedAir, LiftedAirBuilder, MultiAir as MultiAirTrait, ReductionError,
};

use crate::precompile::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    fixed::{fixed_ecgroup_msgs, fixed_uintval_msgs},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice},
    primitives::byte_pair_lut::{self, BytePairLutAir},
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Number of AIR instances in the precompile relation.
pub const NUM_CHIPLETS: usize = 12;

/// The twelve chiplet AIRs wrapped into one enum.
///
/// Variant order is the canonical proof instance order.
#[derive(Clone, Debug, Eq, PartialEq)]
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

macro_rules! delegate {
    ($self:ident, $method:ident $(, $arg:expr)*) => {
        match $self {
            Air::ChunkNodeSponge => ChunkNodeSpongeAir.$method($($arg),*),
            Air::EidosCompression => EidosCompressionAir.$method($($arg),*),
            Air::KeccakRound => KeccakRoundAir.$method($($arg),*),
            Air::BytePairLut => BytePairLutAir.$method($($arg),*),
            Air::TranscriptEval => TranscriptEvalAir.$method($($arg),*),
            Air::UintStoreMul => UintStoreMulAir.$method($($arg),*),
            Air::UintAdd => UintAddAir.$method($($arg),*),
            Air::EcPointStoreGroups => EcPointStoreGroupsAir.$method($($arg),*),
            Air::EcGroupAdd => EcGroupAddAir.$method($($arg),*),
            Air::EcMsm => EcMsmAir.$method($($arg),*),
            Air::Sha512 => Sha512Air.$method($($arg),*),
            Air::Sha256 => Sha256Air.$method($($arg),*),
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

impl Air {
    /// The twelve AIRs in canonical prover trace order.
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

    /// Returns whether this AIR belongs to the selected optional hash subset.
    pub const fn is_in_variant(&self, variant: PvmAirVariant) -> bool {
        match self {
            Self::ChunkNodeSponge | Self::KeccakRound => variant.contains(PvmAirVariant::KECCAK),
            Self::Sha256 => variant.contains(PvmAirVariant::SHA256),
            Self::Sha512 => variant.contains(PvmAirVariant::SHA512),
            _ => true,
        }
    }

    /// The fixed log2 trace height of this instance, if the relation pins one.
    ///
    /// `BytePairLut` commits its main and preprocessed traces at
    /// [`byte_pair_lut::TRACE_HEIGHT`], so its proof shapes must carry exactly that height;
    /// every other instance ranges above its derived minimum.
    pub fn fixed_log_height(&self) -> Option<u32> {
        match self {
            Air::BytePairLut => Some(byte_pair_lut::TRACE_HEIGHT.ilog2()),
            _ => None,
        }
    }
}

impl BaseAir<Felt> for Air {
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

impl LiftedAir<Felt, QuadFelt> for Air {
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
            Air::ChunkNodeSponge => eval_lifted(&ChunkNodeSpongeAir, builder),
            Air::EidosCompression => eval_lifted(&EidosCompressionAir, builder),
            Air::KeccakRound => eval_lifted(&KeccakRoundAir, builder),
            Air::BytePairLut => eval_lifted(&BytePairLutAir, builder),
            Air::TranscriptEval => eval_lifted(&TranscriptEvalAir, builder),
            Air::UintStoreMul => eval_lifted(&UintStoreMulAir, builder),
            Air::UintAdd => eval_lifted(&UintAddAir, builder),
            Air::EcPointStoreGroups => eval_lifted(&EcPointStoreGroupsAir, builder),
            Air::EcGroupAdd => eval_lifted(&EcGroupAddAir, builder),
            Air::EcMsm => eval_lifted(&EcMsmAir, builder),
            Air::Sha512 => eval_lifted(&Sha512Air, builder),
            Air::Sha256 => eval_lifted(&Sha256Air, builder),
        }
    }
}

/// The chiplet stack as a [`MultiAir`].
///
/// It owns the selected AIRs in canonical order and closes the cross-chiplet LogUp identity in
/// [`eval_external`](Self::eval_external), weighting each normalized residue by its trace length.
#[derive(Debug, Clone)]
pub struct MultiAir {
    airs: Vec<Air>,
}

impl MultiAir {
    pub fn new() -> Self {
        Self::with_variant(PvmAirVariant::ALL)
    }

    /// Builds the relation with only the selected optional hash AIRs.
    pub fn with_variant(variant: PvmAirVariant) -> Self {
        Self {
            airs: Air::all().into_iter().filter(|air| air.is_in_variant(variant)).collect(),
        }
    }
}

impl Default for MultiAir {
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

impl MultiAirTrait<Felt, QuadFelt> for MultiAir {
    type Air = Air;

    fn airs(&self) -> &[Air] {
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
        if challenges.len() != crate::precompile::logup::NUM_RANDOMNESS {
            return Err(format!(
                "expected {} aux trace challenges, got {}",
                crate::precompile::logup::NUM_RANDOMNESS,
                challenges.len()
            )
            .into());
        }
        if air_inputs.len() != crate::precompile::logup::NUM_PUBLIC_VALUES {
            return Err(format!(
                "expected {} public values, got {}",
                crate::precompile::logup::NUM_PUBLIC_VALUES,
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

// Transitional paths for source-local trace helpers.
pub use Air as ChipletAir;
pub use MultiAir as ChipletMultiAir;

/// `LookupAir` is generic over its builder, so reading a shape means naming one; the choice does
/// not affect the result, since the shapes are per-AIR constants.
pub(crate) fn lookup_shape(air: Air) -> (usize, usize) {
    use super::logup::{LookupAir, ProverLookupBuilder};
    type ShapeBuilder<'a> = ProverLookupBuilder<'a, Felt, QuadFelt>;

    fn shape_of<A>(air: A) -> (usize, usize)
    where
        A: for<'a> LookupAir<ShapeBuilder<'a>>,
    {
        (
            LookupAir::<ShapeBuilder<'_>>::column_shape(&air).iter().sum(),
            LookupAir::<ShapeBuilder<'_>>::max_message_width(&air),
        )
    }

    match air {
        Air::ChunkNodeSponge => shape_of(ChunkNodeSpongeAir),
        Air::EidosCompression => shape_of(EidosCompressionAir),
        Air::KeccakRound => shape_of(KeccakRoundAir),
        Air::BytePairLut => shape_of(BytePairLutAir),
        Air::TranscriptEval => shape_of(TranscriptEvalAir),
        Air::UintStoreMul => shape_of(UintStoreMulAir),
        Air::UintAdd => shape_of(UintAddAir),
        Air::EcPointStoreGroups => shape_of(EcPointStoreGroupsAir),
        Air::EcGroupAdd => shape_of(EcGroupAddAir),
        Air::EcMsm => shape_of(EcMsmAir),
        Air::Sha512 => shape_of(Sha512Air),
        Air::Sha256 => shape_of(Sha256Air),
    }
}

#[cfg(test)]
mod tests {
    use miden_core::field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn variants_preserve_required_airs_and_canonical_order() {
        let required = [
            Air::EidosCompression,
            Air::BytePairLut,
            Air::TranscriptEval,
            Air::UintStoreMul,
            Air::UintAdd,
            Air::EcPointStoreGroups,
            Air::EcGroupAdd,
            Air::EcMsm,
        ];
        let optional = [
            (1, Air::ChunkNodeSponge),
            (1, Air::KeccakRound),
            (2, Air::Sha256),
            (4, Air::Sha512),
        ];
        for (bits, variant) in PvmAirVariant::ALL_VARIANTS.into_iter().enumerate() {
            let multi_air = MultiAir::with_variant(variant);
            assert_eq!(multi_air.airs().len(), 8 + bits.count_ones() as usize + (bits & 1));
            for air in &required {
                assert!(air.is_in_variant(variant));
                assert!(multi_air.airs().contains(air));
            }
            for (bit, air) in &optional {
                let enabled = bits & bit != 0;
                assert_eq!(air.is_in_variant(variant), enabled);
                assert_eq!(multi_air.airs().contains(air), enabled);
            }
            let positions: Vec<_> = multi_air
                .airs()
                .iter()
                .map(|air| Air::all().iter().position(|item| item == air).unwrap())
                .collect();
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        }
        assert_eq!(MultiAir::new().airs(), Air::all());
    }

    /// The external assertion is part of the production relation but excluded from the ACE
    /// circuit digest. This test guards its weighting; raw bus-balance tests cover the underlying
    /// lookup semantics independently.
    #[test]
    fn chiplet_multi_air_weights_every_normalized_sum_by_trace_length() {
        let challenges = [
            QuadFelt::new([Felt::from(3u32), Felt::from(5u32)]),
            QuadFelt::new([Felt::from(7u32), Felt::from(11u32)]),
        ];
        let multi_air = MultiAir::new();
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
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
        let assertions = multi_air
            .eval_external(
                &challenges,
                &[Felt::ZERO; crate::precompile::logup::NUM_PUBLIC_VALUES],
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
        let multi_air = MultiAir::new();
        let challenges = [QuadFelt::ONE; crate::precompile::logup::NUM_RANDOMNESS];
        let air_inputs = [Felt::ZERO; crate::precompile::logup::NUM_PUBLIC_VALUES];
        let aux_values: Vec<Vec<QuadFelt>> = multi_air
            .airs()
            .iter()
            .map(|air| vec![QuadFelt::ZERO; air.num_aux_values()])
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
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
            &challenges[..crate::precompile::logup::NUM_RANDOMNESS - 1],
            &air_inputs,
            &[],
            &aux_refs,
            &log_heights,
        );
        rejects(
            "missing public value",
            &challenges,
            &air_inputs[..crate::precompile::logup::NUM_PUBLIC_VALUES - 1],
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

    /// The chiplet instance order fixes proof-order tie-breaks and the relation digest.
    /// Intentional changes require regenerated protocol constants and a breaking changelog entry.
    #[test]
    fn chiplet_instance_order_is_protocol_pinned() {
        let pinned = [
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
        ];
        assert_eq!(
            Air::all(),
            pinned,
            "chiplet instance order moved; run `make regenerate-constraints` for an intentional \
             protocol break"
        );
    }
}
