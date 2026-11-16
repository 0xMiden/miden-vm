//! Stack constraints module.
//!
//! This module exposes the general stack transition, stack ops, stack arith/u32, stack crypto,
//! and stack overflow constraints.

pub mod columns;
pub mod crypto;
pub mod general;
pub mod ops;
pub mod overflow;
pub mod stack_arith;

use miden_stark::air::Frame;

use crate::vm::{CoreCols, NativeMidenAirBuilder, constraints::op_flags::OpFlags};

// ENTRY POINTS
// ================================================================================================

/// Enforces stack main-trace constraints for this group.
pub fn enforce_main<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &CoreCols<AB::Expr>,
    next: &CoreCols<AB::Expr>,
    op_flags: &OpFlags<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    general::enforce_main(frame, builder, local, next, op_flags);
    overflow::enforce_main(frame, builder, local, next, op_flags);
    ops::enforce_main(builder, local, next, op_flags);
    crypto::enforce_main(builder, local, next, op_flags);
    stack_arith::enforce_main(builder, local, next, op_flags);
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use core::borrow::Borrow;

    use miden_core::{Felt, field::QuadFelt};
    use miden_stark::air::{
        AirSpec, Assertion, capture_from_spec,
        symbolic::{BaseInput, ExprView, RowOffset},
    };

    use super::enforce_main;
    use crate::vm::{
        CoreCols,
        constraints::{
            columns::{NUM_CORE_COLS, NUM_DECODER_COLS, NUM_SYSTEM_COLS},
            op_flags::OpFlags,
        },
    };

    /// Every ordinary helper is instantiated with native non-Copy expression cells. This subset
    /// deliberately has no lookup declaration and is not a complete Core source registration.
    #[test]
    fn native_stack_retains_base_classes_and_horner_component_order() {
        let spec = AirSpec {
            main_width: NUM_CORE_COLS,
            aux_width: 0,
            num_public_values: 0,
            num_challenges: 0,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        };
        let captured = capture_from_spec::<Felt, QuadFelt>(spec, |frame, _, sink| {
            let local: &CoreCols<_> = frame.main.current.borrow();
            let next: &CoreCols<_> = frame.main.next.borrow();
            let flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
            enforce_main(frame, sink, local, next, &flags);
        })
        .unwrap();
        // General16, overflow10, ops18, crypto53, arithmetic44. These include all assertions gated
        // by a zero selector; extension arithmetic still emits separate base components.
        assert_eq!(captured.assertions.len(), 141);
        assert_eq!(captured.descriptor.analysis().counts().base, 141);
        assert_eq!(captured.descriptor.analysis().counts().ext, 0);

        // Crypto begins after general/overflow/ops; AEAD16 and Merkle2 precede Hornerbase. Its
        // equalities are tmp0.c0/c1, tmp1.c0/c1, then the next accumulator.c0/c1.
        let horner_start = 16 + 10 + 18 + 16 + 2;
        let decoder_hasher = NUM_SYSTEM_COLS + 1 + 7;
        let stack = NUM_SYSTEM_COLS + NUM_DECODER_COLS;
        let expected = [
            (RowOffset::Current, decoder_hasher + 6),
            (RowOffset::Current, decoder_hasher + 7),
            (RowOffset::Current, decoder_hasher + 4),
            (RowOffset::Current, decoder_hasher + 5),
            (RowOffset::Next, stack + 14),
            (RowOffset::Next, stack + 15),
        ];
        for (ordinal, (offset, index)) in expected.into_iter().enumerate() {
            let Assertion::Base(expression) = &captured.assertions[horner_start + ordinal] else {
                panic!("Horner equality must remain a gated base assertion");
            };
            let ExprView::Mul { y: difference, .. } = expression.as_ref().view() else {
                panic!("Horner equality must retain its gate");
            };
            let ExprView::Sum { values } = difference.view() else {
                panic!("Horner equality must retain its lhs-minus-rhs construction");
            };
            assert_eq!(values.len(), 2);
            assert!(matches!(values.get(1).unwrap().view(), ExprView::Neg { .. }));
            assert!(matches!(values.get(0).unwrap().view(), ExprView::BaseInput(
                BaseInput::Main { row: actual_row, column: actual_column }
            ) if actual_row == offset && actual_column == index));
        }
    }
}
