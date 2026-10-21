//! Multi-AIR statement for the precompile chiplet stack.
//!
//! The authored AIRs and stable instance order live in [`miden_air_source::precompile`].
//! [`ChipletMultiAir`] closes the cross-chiplet LogUp identity in
//! [`MultiAir::eval_external`], weighting each normalized residue by its trace length.

use alloc::{format, vec, vec::Vec};

use miden_air_source::precompile::{ChipletAir, fixed::fixed_boundary_correction, logup};
use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::air::{BaseAir, LiftedAir, MultiAir, ReductionError};

/// The chiplet stack as a [`MultiAir`].
///
/// It owns the twelve AIRs in canonical order and closes the cross-chiplet LogUp identity in
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
        air_inputs: &[Vec<Felt>],
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
        if challenges.len() != logup::NUM_RANDOMNESS {
            return Err(format!(
                "expected {} aux trace challenges, got {}",
                logup::NUM_RANDOMNESS,
                challenges.len()
            )
            .into());
        }
        if air_inputs.len() != self.airs.len()
            || self
                .airs
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
    use miden_air_source::precompile::NUM_CHIPLETS;
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
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
        let assertions = multi_air
            .eval_external(
                &challenges,
                &multi_air
                    .airs()
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
        let multi_air = ChipletMultiAir::new();
        let challenges = [QuadFelt::ONE; logup::NUM_RANDOMNESS];
        let air_inputs: Vec<_> = multi_air
            .airs()
            .iter()
            .map(|air| vec![Felt::ZERO; air.num_public_values()])
            .collect();
        let aux_values: Vec<Vec<QuadFelt>> = multi_air
            .airs()
            .iter()
            .map(|air| vec![QuadFelt::ZERO; air.num_aux_values()])
            .collect();
        let aux_refs: Vec<&[QuadFelt]> = aux_values.iter().map(Vec::as_slice).collect();
        let log_heights: [u8; NUM_CHIPLETS] = [8, 16, 7, 16, 5, 9, 10, 11, 12, 13, 14, 15];
        let rejects = |case: &str,
                       challenges: &[QuadFelt],
                       air_inputs: &[Vec<Felt>],
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
            &challenges[..logup::NUM_RANDOMNESS - 1],
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
}
