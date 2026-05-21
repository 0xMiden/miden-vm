//! Runtime validation of caller-supplied statement data.
//!
//! Two free functions, both called from the validating constructors on
//! [`Statement`](crate::Statement) and
//! [`ProverStatement`](crate::ProverStatement). Construction is the trust
//! boundary: holding a `Statement` / `ProverStatement` is a type-level
//! guarantee these checks have passed.
//!
//! - [`validate_inputs`] — inputs class: per-AIR `num_public_values == air_inputs.len()` and
//!   `aux_inputs.len() ≤ MultiAir::max_aux_inputs`.
//! - [`validate_prover_traces`] — trace shape: count, power-of-two heights, ≤ `u8::MAX + 1`
//!   instances, width matches each AIR, height ≥ max periodic column length.
//!
//! AIR *structural* correctness (no preprocessed trace, positive aux width,
//! power-of-two periodic columns) is a trusted contract — see
//! [`crate::debug`] for the panic-based helpers that enforce it from tests.

extern crate alloc;

use alloc::vec::Vec;

use p3_field::{ExtensionField, Field};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use thiserror::Error;

use crate::{BaseAir, LiftedAir, MultiAir, Statement};

/// Errors surfaced by the runtime statement validators.
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

/// Inputs-class check: per-AIR `num_public_values == air_inputs.len()` and
/// `aux_inputs.len() ≤ multi_air.max_aux_inputs()`.
///
/// Called from [`Statement::new`](crate::Statement::new); usually you go
/// through that rather than calling this directly.
pub fn validate_inputs<F, EF, MA>(
    multi_air: &MA,
    air_inputs: &[F],
    aux_inputs: &[F],
) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    for (idx, air) in multi_air.airs().iter().enumerate() {
        let expected = air.num_public_values();
        if expected != air_inputs.len() {
            return Err(InstanceError::PublicValuesLengthMismatch {
                air: idx,
                expected,
                actual: air_inputs.len(),
            });
        }
    }
    let max = multi_air.max_aux_inputs();
    if aux_inputs.len() > max {
        return Err(InstanceError::AuxInputsTooLong { actual: aux_inputs.len(), max });
    }
    Ok(())
}

/// Verifier-side trace-shape check on proof-supplied log heights.
///
/// Verifies, in order:
/// - `log_heights.len() == statement.airs().len()`
/// - per AIR: `(1 << log_h) ≥ max periodic column length`
///
/// `(1 << log_h)` must not overflow; callers should run
/// `TraceOrder::from_log_heights` first to bound `log_h` within the host's
/// `usize` width.
pub fn validate_log_heights<F, EF, MA>(
    statement: &Statement<F, EF, MA>,
    log_heights: &[u8],
) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let airs = statement.airs();
    if airs.len() != log_heights.len() {
        return Err(InstanceError::TraceCountMismatch {
            airs: airs.len(),
            traces: log_heights.len(),
        });
    }
    for (idx, (air, &log_h)) in airs.iter().zip(log_heights.iter()).enumerate() {
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

/// Trace-shape check.
///
/// Verifies, in order:
/// - `traces.len() ≤ u8::MAX + 1`
/// - `traces.len() == statement.airs().len()`
/// - per trace: `height.is_power_of_two()`
/// - per AIR: `trace.height() ≥ max periodic column length`
/// - per AIR: `trace.width() == air.width()`
///
/// Called from [`ProverStatement::new`](crate::ProverStatement::new);
/// usually you go through that rather than calling this directly.
pub fn validate_prover_traces<F, EF, MA>(
    statement: &Statement<F, EF, MA>,
    traces: &[RowMajorMatrix<F>],
) -> Result<(), InstanceError>
where
    F: Field,
    EF: ExtensionField<F>,
    MA: MultiAir<F, EF>,
{
    let max_instances = u8::MAX as usize + 1;
    if traces.len() > max_instances {
        return Err(InstanceError::TooManyInstances { count: traces.len() });
    }
    let airs = statement.airs();
    if airs.len() != traces.len() {
        return Err(InstanceError::TraceCountMismatch { airs: airs.len(), traces: traces.len() });
    }
    for (idx, trace) in traces.iter().enumerate() {
        let h = trace.height();
        if !h.is_power_of_two() {
            return Err(InstanceError::TraceHeightNotPowerOfTwo { air: idx, height: h });
        }
    }
    for (idx, (air, trace)) in airs.iter().zip(traces.iter()).enumerate() {
        let trace_height = trace.height();
        let max_period = air.periodic_columns().iter().map(Vec::len).max().unwrap_or(0);
        if trace_height < max_period {
            return Err(InstanceError::TraceHeightBelowPeriod {
                air: idx,
                trace_height,
                max_period,
            });
        }
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
    use crate::{LiftedAirBuilder, ProverStatement};

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

    /// `MultiAir` carrying its AIRs and a tunable aux-inputs budget for tests.
    struct DummyMa {
        airs: Vec<DummyAir>,
        max_aux_inputs: usize,
    }

    impl DummyMa {
        fn new(airs: Vec<DummyAir>) -> Self {
            Self { airs, max_aux_inputs: 0 }
        }
        fn with_max_aux_inputs(airs: Vec<DummyAir>, max_aux_inputs: usize) -> Self {
            Self { airs, max_aux_inputs }
        }
    }

    impl MultiAir<F, EF> for DummyMa {
        type Air = DummyAir;

        fn airs(&self) -> &[Self::Air] {
            &self.airs
        }

        fn max_aux_inputs(&self) -> usize {
            self.max_aux_inputs
        }

        fn build_aux_traces(
            &self,
            _traces: &[&RowMajorMatrix<F>],
            _air_inputs: &[F],
            _aux_inputs: &[F],
            _challenges: &[EF],
        ) -> (Vec<RowMajorMatrix<EF>>, Vec<Vec<EF>>) {
            unreachable!("not exercised by validator tests")
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
        let ma = DummyMa::new(vec![DummyAir::new(1, 1, 2)]);
        validate_inputs::<F, EF, DummyMa>(&ma, &pv(2), &[]).unwrap();
    }

    #[test]
    fn validate_inputs_public_values_length_mismatch() {
        let ma = DummyMa::new(vec![DummyAir::new(1, 1, 2), DummyAir::new(1, 1, 1)]);
        let err = validate_inputs::<F, EF, DummyMa>(&ma, &pv(2), &[]).unwrap_err();
        assert!(matches!(
            err,
            InstanceError::PublicValuesLengthMismatch { air: 1, expected: 1, actual: 2 }
        ));
    }

    #[test]
    fn validate_inputs_aux_inputs_too_long() {
        let ma = DummyMa::with_max_aux_inputs(vec![DummyAir::new(1, 1, 0)], 2);
        let err = validate_inputs::<F, EF, DummyMa>(&ma, &[], &pv(3)).unwrap_err();
        assert!(matches!(err, InstanceError::AuxInputsTooLong { actual: 3, max: 2 }));
    }

    // ---------- validate_prover_traces (via ProverStatement::new) ----------

    #[test]
    fn prover_statement_height_not_power_of_two() {
        let statement = Statement::<F, EF, DummyMa>::new(
            DummyMa::new(vec![DummyAir::new(1, 1, 0)]),
            vec![],
            vec![],
        )
        .unwrap();
        let err = ProverStatement::new(statement, vec![trace(1, 3)]).err().unwrap();
        assert!(matches!(err, InstanceError::TraceHeightNotPowerOfTwo { air: 0, height: 3 }));
    }

    #[test]
    fn prover_statement_width_mismatch() {
        let statement = Statement::<F, EF, DummyMa>::new(
            DummyMa::new(vec![DummyAir::new(2, 1, 0)]),
            vec![],
            vec![],
        )
        .unwrap();
        let err = ProverStatement::new(statement, vec![trace(1, 4)]).err().unwrap();
        assert!(matches!(
            err,
            InstanceError::TraceWidthMismatch { air: 0, expected: 2, actual: 1 }
        ));
    }

    #[test]
    fn prover_statement_trace_count_mismatch() {
        let statement = Statement::<F, EF, DummyMa>::new(
            DummyMa::new(vec![DummyAir::new(1, 1, 0), DummyAir::new(1, 1, 0)]),
            vec![],
            vec![],
        )
        .unwrap();
        let err = ProverStatement::new(statement, vec![trace(1, 4)]).err().unwrap();
        assert!(matches!(err, InstanceError::TraceCountMismatch { airs: 2, traces: 1 }));
    }

    #[test]
    fn prover_statement_trace_height_below_period() {
        let statement = Statement::<F, EF, DummyMa>::new(
            DummyMa::new(vec![DummyAir::new(1, 1, 0).with_periodic(8)]),
            vec![],
            vec![],
        )
        .unwrap();
        let err = ProverStatement::new(statement, vec![trace(1, 2)]).err().unwrap();
        assert!(matches!(
            err,
            InstanceError::TraceHeightBelowPeriod { air: 0, trace_height: 2, max_period: 8 }
        ));
    }
}
