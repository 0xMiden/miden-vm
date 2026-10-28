//! Authored external LogUp closure for the precompile relation.
//!
//! Every per-AIR slice follows the canonical instance order in [`AIRS`]. Statement observation
//! uses the generic STARK public-input encoding; this module supplies the external assertion.

use alloc::{format, vec, vec::Vec};

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::air::{BaseAir, LiftedAir, ReductionError};

use super::{
    fixed::{fixed_ecgroup_msgs, fixed_uintval_msgs},
    logup::{Challenges, LookupMessage, lookup_challenges_from_slice},
    relation::AIRS,
};

/// Cross-chiplet LogUp closure. Every AIR exposes one centered residue
/// `sigma_prime_i = sigma_i / n_i`; therefore `sum_i(n_i * sigma_prime_i)` plus the fixed
/// boundary correction must vanish.
pub fn eval_external(
    challenges: &[QuadFelt],
    air_inputs: &[Vec<Felt>],
    aux_inputs: &[Felt],
    aux_values: &[&[QuadFelt]],
    log_trace_heights: &[u8],
) -> Result<Vec<QuadFelt>, ReductionError> {
    if aux_values.len() != AIRS.len() {
        return Err(format!(
            "expected aux values for {} AIRs, got {}",
            AIRS.len(),
            aux_values.len()
        )
        .into());
    }
    if log_trace_heights.len() != AIRS.len() {
        return Err(format!(
            "expected log heights for {} AIRs, got {}",
            AIRS.len(),
            log_trace_heights.len()
        )
        .into());
    }
    if challenges.len() != crate::precompiles::logup::NUM_RANDOMNESS {
        return Err(format!(
            "expected {} aux trace challenges, got {}",
            crate::precompiles::logup::NUM_RANDOMNESS,
            challenges.len()
        )
        .into());
    }
    if air_inputs.len() != AIRS.len()
        || AIRS
            .iter()
            .zip(air_inputs)
            .any(|(air, inputs)| inputs.len() != air.num_public_values())
    {
        return Err("public-input shape does not match the AIRs".into());
    }
    if !aux_inputs.is_empty() {
        return Err(format!("expected no auxiliary inputs, got {}", aux_inputs.len()).into());
    }

    let mut weighted_aux_sum = QuadFelt::ZERO;
    for (index, ((air, values), &log_height)) in
        AIRS.iter().zip(aux_values).zip(log_trace_heights).enumerate()
    {
        let expected = air.num_aux_values();
        if values.len() != expected {
            return Err(format!(
                "AIR {index} expects {expected} auxiliary boundary values, got {}",
                values.len()
            )
            .into());
        }
        let length = 1u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
            ReductionError::from(format!(
                "AIR {index} log trace height {log_height} does not fit in u64"
            ))
        })?;
        weighted_aux_sum += values.iter().copied().sum::<QuadFelt>() * Felt::new_unchecked(length);
    }
    Ok(vec![weighted_aux_sum + fixed_boundary_correction(challenges)?])
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

#[cfg(test)]
mod tests {
    use miden_core::field::PrimeCharacteristicRing;
    use miden_stark::air::LiftedAir;

    use super::*;
    use crate::precompiles::{ChipletAir, NUM_CHIPLETS};

    #[test]
    fn declared_relation_preserves_order_and_height_rules() {
        assert_eq!(AIRS, ChipletAir::all());
        let protocol = crate::precompiles::relation::protocol();
        assert_eq!(protocol.heights[3], crate::precompiles::relation::HeightRule::Fixed(16));
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
        let aux_values: Vec<Vec<QuadFelt>> = AIRS
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
        let assertions = eval_external(
            &challenges,
            &AIRS
                .iter()
                .map(|air| vec![Felt::ZERO; air.num_public_values()])
                .collect::<Vec<_>>(),
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
        let challenges = [QuadFelt::ONE; crate::precompiles::logup::NUM_RANDOMNESS];
        let air_inputs: Vec<_> =
            AIRS.iter().map(|air| vec![Felt::ZERO; air.num_public_values()]).collect();
        let aux_values: Vec<Vec<QuadFelt>> =
            AIRS.iter().map(|air| vec![QuadFelt::ZERO; air.num_aux_values()]).collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
        let rejects = |case: &str,
                       challenges: &[QuadFelt],
                       air_inputs: &[Vec<Felt>],
                       aux_inputs: &[Felt],
                       aux_values: &[&[QuadFelt]],
                       log_heights: &[u8]| {
            assert!(
                eval_external(challenges, air_inputs, aux_inputs, aux_values, log_heights).is_err(),
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
            &challenges[..crate::precompiles::logup::NUM_RANDOMNESS - 1],
            &air_inputs,
            &[],
            &aux_refs,
            &log_heights,
        );
        let mut missing_public_value = air_inputs.clone();
        missing_public_value[ChipletAir::TRANSCRIPT_EVAL_INDEX].pop();
        rejects(
            "missing public value",
            &challenges,
            &missing_public_value,
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
    /// Intentional changes require a protocol-version bump and a breaking changelog entry.
    #[test]
    fn chiplet_instance_order_is_protocol_pinned() {
        assert_eq!(
            ChipletAir::all()[ChipletAir::TRANSCRIPT_EVAL_INDEX],
            ChipletAir::TranscriptEval
        );
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
            ChipletAir::Sha512,
            ChipletAir::Sha256,
        ];
        assert_eq!(
            ChipletAir::all(),
            pinned,
            "chiplet instance order moved; review the protocol-version bump for an intentional \
             protocol break"
        );
    }
}
