//! Runtime validation of caller-supplied instance data.
//!
//! These checks run from inside `prove` and `verify` and surface as typed
//! errors. They validate only untrusted runtime inputs (slice lengths,
//! trace dimensions); AIR *structural* correctness is a separate, trusted
//! contract — see [`crate::debug`] for the panic-based helpers that
//! enforce it from tests / setup.

extern crate alloc;

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::Matrix;
use thiserror::Error;

use crate::{BaseAir, Instance, LiftedAir, ProverInstance};

/// Errors surfaced by the runtime instance validators.
#[derive(Debug, Error)]
pub enum InstanceError {
    #[error("AIR {air}: num_public_values() = {expected}, but air_inputs().len() = {actual}")]
    PublicValuesLengthMismatch {
        air: usize,
        expected: usize,
        actual: usize,
    },

    #[error("aux_inputs().len() = {actual} exceeds max_aux_inputs() = {max}")]
    AuxInputsTooLong { actual: usize, max: usize },

    #[error("airs().len() = {airs} does not match traces().len() = {traces}")]
    TraceCountMismatch { airs: usize, traces: usize },

    #[error(
        "too many instances ({count}); the per-proof limit is {max} = u8::MAX + 1",
        max = u8::MAX as usize + 1
    )]
    TooManyInstances { count: usize },

    #[error("AIR {air}: trace width = {actual}, but air.width() = {expected}")]
    TraceWidthMismatch {
        air: usize,
        expected: usize,
        actual: usize,
    },

    #[error("AIR {air}: trace height = {height} is not a power of two")]
    TraceHeightNotPowerOfTwo { air: usize, height: usize },

    #[error(
        "AIR {air}: trace height = {trace_height} is less than max periodic column \
         length {max_period}"
    )]
    TraceHeightBelowPeriod {
        air: usize,
        trace_height: usize,
        max_period: usize,
    },
}

/// Core inputs check — no trace shape.
///
/// Verifies:
/// - per AIR: `air.num_public_values() == air_inputs.len()`
/// - globally: `aux_inputs.len() <= max_aux_inputs`
pub fn validate_inputs<F, EF, A>(
    airs: &[&A],
    air_inputs: &[F],
    aux_inputs: &[F],
    max_aux_inputs: usize,
) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    for (idx, air) in airs.iter().enumerate() {
        let expected = air.num_public_values();
        if expected != air_inputs.len() {
            return Err(InstanceError::PublicValuesLengthMismatch {
                air: idx,
                expected,
                actual: air_inputs.len(),
            });
        }
    }
    if aux_inputs.len() > max_aux_inputs {
        return Err(InstanceError::AuxInputsTooLong {
            actual: aux_inputs.len(),
            max: max_aux_inputs,
        });
    }
    Ok(())
}

/// Forwarding entry point: pulls the four slices off `instance` and calls
/// [`validate_inputs`].
pub fn validate_instance<F, EF, I>(instance: &I) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    I: Instance<F, EF>,
{
    validate_inputs::<F, EF, _>(
        instance.airs(),
        instance.air_inputs(),
        instance.aux_inputs(),
        instance.max_aux_inputs(),
    )
}

/// Validate `instance` against a set of per-AIR `log_heights` (instance order).
///
/// Used by both the prover (computed from `traces[i].height()`) and the
/// verifier (read off the proof). Verifies:
/// - [`validate_instance`]
/// - `airs.len() == log_heights.len()` (else [`InstanceError::TraceCountMismatch`])
/// - per AIR: `(1 << log_h) >= max periodic column length`
pub fn validate_with_heights<F, EF, I>(
    instance: &I,
    log_heights: &[u8],
) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    I: Instance<F, EF>,
{
    validate_instance(instance)?;
    let airs = instance.airs();
    if airs.len() != log_heights.len() {
        return Err(InstanceError::TraceCountMismatch {
            airs: airs.len(),
            traces: log_heights.len(),
        });
    }
    for (idx, (&air, &log_h)) in airs.iter().zip(log_heights.iter()).enumerate() {
        let trace_height = 1usize << log_h as usize;
        let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
        if trace_height < max_period {
            return Err(InstanceError::TraceHeightBelowPeriod {
                air: idx,
                trace_height,
                max_period,
            });
        }
    }
    Ok(())
}

/// Prover-only superset: full trace-shape validation.
///
/// Verifies, in order:
/// - `traces.len() <= u8::MAX + 1`
/// - per trace: `height.is_power_of_two()`
/// - [`validate_with_heights`] against the derived per-AIR log heights
/// - per AIR: `trace.width() == air.width()`
pub fn validate_prover_instance<F, EF, P>(pi: &P) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    P: ProverInstance<F, EF>,
{
    let traces = pi.traces();
    let max_instances = u8::MAX as usize + 1;
    if traces.len() > max_instances {
        return Err(InstanceError::TooManyInstances { count: traces.len() });
    }

    let mut log_heights: Vec<u8> = Vec::with_capacity(traces.len());
    for (idx, trace) in traces.iter().enumerate() {
        let h = trace.height();
        if !h.is_power_of_two() {
            return Err(InstanceError::TraceHeightNotPowerOfTwo { air: idx, height: h });
        }
        log_heights.push(h.trailing_zeros() as u8);
    }

    let instance = pi.instance();
    validate_with_heights(instance, &log_heights)?;

    // Width check requires the per-trace iteration; runs after
    // `validate_with_heights` so the count mismatch error type comes from
    // there, not from a divergent loop bound.
    let airs = instance.airs();
    debug_assert_eq!(airs.len(), traces.len(), "validate_with_heights enforces this");
    for (idx, (&air, &trace)) in airs.iter().zip(traces.iter()).enumerate() {
        if trace.width() != air.width() {
            return Err(InstanceError::TraceWidthMismatch {
                air: idx,
                expected: air.width(),
                actual: trace.width(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::LiftedAirBuilder;

    type F = Goldilocks;
    type EF = Goldilocks;

    #[derive(Clone)]
    struct DummyAir {
        width: usize,
        aux_width: usize,
        num_pv: usize,
        periodic: Vec<Vec<F>>,
    }

    impl DummyAir {
        fn new(width: usize, aux_width: usize, num_pv: usize) -> Self {
            Self {
                width,
                aux_width,
                num_pv,
                periodic: Vec::new(),
            }
        }
        fn with_periodic(mut self, period: usize) -> Self {
            self.periodic.push(vec![F::ZERO; period]);
            self
        }
    }

    impl BaseAir<F> for DummyAir {
        fn width(&self) -> usize {
            self.width
        }
        fn num_public_values(&self) -> usize {
            self.num_pv
        }
    }

    impl LiftedAir<F, EF> for DummyAir {
        fn periodic_columns(&self) -> Vec<Vec<F>> {
            self.periodic.clone()
        }
        fn num_randomness(&self) -> usize {
            0
        }
        fn aux_width(&self) -> usize {
            self.aux_width
        }
        fn num_aux_values(&self) -> usize {
            0
        }
        fn eval<AB: LiftedAirBuilder<F = F>>(&self, _builder: &mut AB) {}
    }

    struct DummyInstance<'a> {
        airs: Vec<&'a DummyAir>,
        air_inputs: Vec<F>,
        aux_inputs: Vec<F>,
        max_aux_inputs: usize,
    }

    impl<'a> Instance<F, EF> for DummyInstance<'a> {
        type Air = DummyAir;
        fn airs(&self) -> &[&Self::Air] {
            &self.airs
        }
        fn air_inputs(&self) -> &[F] {
            &self.air_inputs
        }
        fn aux_inputs(&self) -> &[F] {
            &self.aux_inputs
        }
        fn max_aux_inputs(&self) -> usize {
            self.max_aux_inputs
        }
    }

    struct DummyProver<'a> {
        instance: DummyInstance<'a>,
        traces: Vec<&'a RowMajorMatrix<F>>,
    }

    impl<'a> ProverInstance<F, EF> for DummyProver<'a> {
        type Instance = DummyInstance<'a>;
        fn instance(&self) -> &Self::Instance {
            &self.instance
        }
        fn traces(&self) -> &[&RowMajorMatrix<F>] {
            &self.traces
        }
        fn build_aux_traces(&self, _challenges: &[EF]) -> (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>) {
            unreachable!()
        }
    }

    fn pv(n: usize) -> Vec<F> {
        (0..n).map(|i| F::from_u64(i as u64)).collect()
    }

    fn trace(width: usize, height: usize) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(vec![F::ZERO; width * height], width)
    }

    // ---------- validate_inputs ----------

    #[test]
    fn validate_inputs_ok() {
        let air = DummyAir::new(1, 1, 2);
        let airs = vec![&air];
        validate_inputs::<F, EF, _>(&airs, &pv(2), &[], 0).unwrap();
    }

    #[test]
    fn validate_inputs_public_values_length_mismatch() {
        let air = DummyAir::new(1, 1, 2);
        let air_short = DummyAir::new(1, 1, 1);
        let airs = vec![&air, &air_short];
        let err = validate_inputs::<F, EF, _>(&airs, &pv(2), &[], 0).unwrap_err();
        assert!(matches!(
            err,
            InstanceError::PublicValuesLengthMismatch { air: 1, expected: 1, actual: 2 }
        ));
    }

    #[test]
    fn validate_inputs_aux_inputs_too_long() {
        let air = DummyAir::new(1, 1, 0);
        let airs = vec![&air];
        let err = validate_inputs::<F, EF, _>(&airs, &[], &pv(3), 2).unwrap_err();
        assert!(matches!(err, InstanceError::AuxInputsTooLong { actual: 3, max: 2 }));
    }

    // ---------- validate_with_heights ----------

    #[test]
    fn validate_with_heights_trace_count_mismatch() {
        let air = DummyAir::new(1, 1, 0);
        let instance = DummyInstance {
            airs: vec![&air],
            air_inputs: vec![],
            aux_inputs: vec![],
            max_aux_inputs: 0,
        };
        let err = validate_with_heights(&instance, &[3, 2]).unwrap_err();
        assert!(matches!(err, InstanceError::TraceCountMismatch { airs: 1, traces: 2 }));
    }

    #[test]
    fn validate_with_heights_trace_height_below_period() {
        let air = DummyAir::new(1, 1, 0).with_periodic(8);
        let instance = DummyInstance {
            airs: vec![&air],
            air_inputs: vec![],
            aux_inputs: vec![],
            max_aux_inputs: 0,
        };
        // log_h = 1 → trace_height = 2 < max_period = 8
        let err = validate_with_heights(&instance, &[1]).unwrap_err();
        assert!(matches!(
            err,
            InstanceError::TraceHeightBelowPeriod { air: 0, trace_height: 2, max_period: 8 }
        ));
    }

    // ---------- validate_prover_instance ----------

    #[test]
    fn validate_prover_instance_height_not_power_of_two() {
        let air = DummyAir::new(1, 1, 0);
        let t = trace(1, 3); // height 3 is not a power of two
        let pi = DummyProver {
            instance: DummyInstance {
                airs: vec![&air],
                air_inputs: vec![],
                aux_inputs: vec![],
                max_aux_inputs: 0,
            },
            traces: vec![&t],
        };
        let err = validate_prover_instance(&pi).unwrap_err();
        assert!(matches!(err, InstanceError::TraceHeightNotPowerOfTwo { air: 0, height: 3 }));
    }

    #[test]
    fn validate_prover_instance_width_mismatch() {
        let air = DummyAir::new(2, 1, 0); // declares width 2
        let t = trace(1, 4); // actual width 1
        let pi = DummyProver {
            instance: DummyInstance {
                airs: vec![&air],
                air_inputs: vec![],
                aux_inputs: vec![],
                max_aux_inputs: 0,
            },
            traces: vec![&t],
        };
        let err = validate_prover_instance(&pi).unwrap_err();
        assert!(matches!(
            err,
            InstanceError::TraceWidthMismatch { air: 0, expected: 2, actual: 1 }
        ));
    }

    #[test]
    fn validate_prover_instance_trace_count_mismatch() {
        let air = DummyAir::new(1, 1, 0);
        let t = trace(1, 4);
        let pi = DummyProver {
            instance: DummyInstance {
                airs: vec![&air, &air],
                air_inputs: vec![],
                aux_inputs: vec![],
                max_aux_inputs: 0,
            },
            traces: vec![&t],
        };
        let err = validate_prover_instance(&pi).unwrap_err();
        assert!(matches!(err, InstanceError::TraceCountMismatch { airs: 2, traces: 1 }));
    }
}
