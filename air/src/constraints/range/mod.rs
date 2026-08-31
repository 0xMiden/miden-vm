//! Range Checker Main Trace Constraints
//!
//! This module contains main trace constraints for the range checker component:
//! - Boundary constraints: V[0] = 0, V[last] = 65535
//! - Transition constraint: V column changes by powers of 3 or stays constant (for padding)
//!
//! Bus constraints for the range checker are in `bus`.

pub mod columns;

use miden_crypto::stark::air::AirBuilder;

use crate::{CoreCols, MidenAirBuilder, constraints::constants::*};

// ENTRY POINTS
// ================================================================================================

/// Enforces range checker main-trace constraints.
pub fn enforce_main<AB>(builder: &mut AB, local: &CoreCols<AB::Var>, next: &CoreCols<AB::Var>)
where
    AB: MidenAirBuilder,
{
    let v = local.range.value;
    let v_next = next.range.value;

    // Range checker boundaries: V[0] = 0, V[last] = 2^16 - 1
    {
        builder.when_first_row().assert_zero(v);
        builder.when_last_row().assert_eq(v, TWO_POW_16_MINUS_1);
    }

    // Transition constraint for the V column (degree 9).
    // V must change by one of: {0, 1, 3, 9, 27, 81, 243, 729, 2187}
    // - 0 allows V to stay constant during padding rows
    // - Others are powers of 3: {3^0, 3^1, 3^2, 3^3, 3^4, 3^5, 3^6, 3^7}
    {
        let change_v = v_next - v;
        builder.when_transition().assert_zero(
            change_v.clone()
                * (change_v.clone() - F_1)
                * (change_v.clone() - F_3)
                * (change_v.clone() - F_9)
                * (change_v.clone() - F_27)
                * (change_v.clone() - F_81)
                * (change_v.clone() - F_243)
                * (change_v.clone() - F_729)
                * (change_v - F_2187),
        );
    }
}

#[cfg(test)]
mod tests {
    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };

    use super::enforce_main;
    use crate::{CoreCols, constraints::stack::test_utils::ConstraintEvalBuilder};

    enum RowKind {
        First,
        Last,
        Transition,
    }

    fn constraints_hold(value: Felt, next_value: Felt, row_kind: RowKind) -> bool {
        let mut local = CoreCols::default();
        local.range.value = value;
        let mut next = CoreCols::default();
        next.range.value = next_value;

        let (first_row, last_row, transition) = match row_kind {
            RowKind::First => (true, false, false),
            RowKind::Last => (false, true, false),
            RowKind::Transition => (false, false, true),
        };
        let mut builder =
            ConstraintEvalBuilder::new().with_row_flags(first_row, last_row, transition);
        enforce_main(&mut builder, &local, &next);
        builder.evaluations.into_iter().all(|value| value == QuadFelt::ZERO)
    }

    #[test]
    fn range_boundary_constraints_enforce_zero_and_u16_max() {
        assert!(
            constraints_hold(Felt::ZERO, Felt::ZERO, RowKind::First),
            "the first-row value zero should be accepted"
        );
        assert!(
            !constraints_hold(Felt::ONE, Felt::ZERO, RowKind::First),
            "the first-row value one should be rejected"
        );

        assert!(
            constraints_hold(Felt::from_u16(u16::MAX), Felt::ZERO, RowKind::Last),
            "the last-row value u16::MAX should be accepted"
        );
        assert!(
            !constraints_hold(Felt::from_u16(u16::MAX - 1), Felt::ZERO, RowKind::Last),
            "the last-row value immediately below u16::MAX should be rejected"
        );
    }

    #[test]
    fn range_transition_constraint_accepts_allowed_steps() {
        for change in [0_u64, 1, 3, 9, 27, 81, 243, 729, 2187] {
            assert!(
                constraints_hold(
                    Felt::from_u16(100),
                    Felt::from_u16(100) + Felt::new_unchecked(change),
                    RowKind::Transition,
                ),
                "allowed transition step {change} should be accepted"
            );
        }
    }

    #[test]
    fn range_transition_constraint_rejects_disallowed_steps() {
        for change in [Felt::from_u8(2), Felt::from_u16(2188), Felt::NEG_ONE] {
            assert!(
                !constraints_hold(
                    Felt::from_u16(100),
                    Felt::from_u16(100) + change,
                    RowKind::Transition,
                ),
                "disallowed transition step {change} should be rejected"
            );
        }
    }
}
