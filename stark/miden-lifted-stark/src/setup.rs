//! Stark-layer compatibility checks.
//!
//! [`validate_compatible`] enforces the AIR ↔ PCS-parameters runtime
//! contract; today the only such check is the per-AIR
//! `log_quotient_degree(air) <= params.log_blowup()` bound.
//!
//! Panic-based wrappers live in [`crate::debug`] and forward to the same
//! body.

extern crate alloc;

use miden_lifted_air::LiftedAir;
use p3_field::{ExtensionField, Field};
use thiserror::Error;

use crate::{domain::log_quotient_degree, pcs::params::PcsParams};

/// Errors from AIR ↔ PCS parameter compatibility checks.
#[derive(Debug, Error)]
pub enum CompatError {
    #[error("AIR {air}: log_quotient_degree {log_quotient} > log_blowup {log_blowup}")]
    ConstraintDegreeTooHigh {
        air: usize,
        log_quotient: u8,
        log_blowup: u8,
    },
}

/// Verify every AIR's quotient degree fits within the PCS blowup.
///
/// Runs [`log_quotient_degree`] per AIR and returns
/// [`CompatError::ConstraintDegreeTooHigh`] for the first violation. The
/// clamping inside `log_quotient_degree` means degenerate (linear) AIRs
/// land at `log_quotient_degree = 1`, which always fits a positive
/// `log_blowup`.
pub fn validate_compatible<F, EF, A>(airs: &[A], params: &PcsParams) -> Result<(), CompatError>
where
    F: Field,
    EF: ExtensionField<F>,
    A: LiftedAir<F, EF>,
{
    let log_blowup = params.log_blowup();
    for (idx, air) in airs.iter().enumerate() {
        let lq = log_quotient_degree::<F, EF, _>(air);
        if lq > log_blowup {
            return Err(CompatError::ConstraintDegreeTooHigh {
                air: idx,
                log_quotient: lq,
                log_blowup,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

    use super::*;
    use crate::{
        StarkConfig,
        testing::configs::goldilocks_poseidon2::{Felt, QuadFelt, test_config},
    };

    /// AIR whose constraints have artificially-high degree (`local[0]^k` in
    /// a transition constraint pushes the symbolic degree past the blowup
    /// for large enough `k`).
    #[derive(Clone, Copy)]
    struct HighDegreeAir {
        exponent: u64,
    }

    impl BaseAir<Felt> for HighDegreeAir {
        fn width(&self) -> usize {
            1
        }
    }

    impl LiftedAir<Felt, QuadFelt> for HighDegreeAir {
        fn num_randomness(&self) -> usize {
            0
        }
        fn aux_width(&self) -> usize {
            1
        }
        fn num_aux_values(&self) -> usize {
            0
        }
        fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
            use miden_lifted_air::{AirBuilder, WindowAccess};
            let main = builder.main();
            let (local, next) = (main.current_slice().to_vec(), main.next_slice().to_vec());
            let x: AB::Expr = local[0].into();
            let mut acc: AB::Expr = x.clone();
            for _ in 1..self.exponent {
                acc = acc * x.clone();
            }
            builder.when_transition().assert_eq(next[0].into(), acc);

            // Trivial aux to satisfy aux_width > 0.
            let aux = builder.permutation();
            let aux_local = aux.current_slice().to_vec();
            let aux_expr: AB::ExprEF = aux_local[0].into();
            builder.assert_zero_ext(aux_expr);
        }
    }

    #[test]
    fn validate_compatible_ok_for_linear_air() {
        // Linear constraint → log_quotient_degree clamps to 1 ≤ log_blowup.
        let air = HighDegreeAir { exponent: 1 };
        let airs: Vec<HighDegreeAir> = vec![air];
        let config = test_config();
        validate_compatible::<Felt, QuadFelt, _>(&airs, config.pcs()).unwrap();
    }

    #[test]
    fn validate_compatible_rejects_overlarge_degree() {
        // log_blowup is 3 in test_config; a high-power AIR exceeds it.
        let air = HighDegreeAir { exponent: 1_000 };
        let airs: Vec<HighDegreeAir> = vec![air];
        let config = test_config();
        let err = validate_compatible::<Felt, QuadFelt, _>(&airs, config.pcs()).unwrap_err();
        match err {
            CompatError::ConstraintDegreeTooHigh { air, log_quotient, log_blowup } => {
                assert_eq!(air, 0);
                assert!(
                    log_quotient > log_blowup,
                    "expected lq > lb, got {log_quotient} vs {log_blowup}"
                );
            },
        }
    }
}
