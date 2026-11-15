//! Public input boundary constraints.
//!
//! Enforces that the stack trace entries match the claimed public inputs:
//! - First row: stack[0..16] == stack_inputs[0..16]
//! - Last row:  stack[0..16] == stack_outputs[0..16]

use miden_stark::air::native::{Frame, Inputs, LiftedAirBuilder};
use p3_field::Dup;

use crate::vm::{CoreCols, NativeMidenAirBuilder};

// CONSTANTS
// ================================================================================================

const STACK_DEPTH: usize = 16;

/// Number of public values consumed by the stack boundary (stack_inputs + stack_outputs).
const PUBLIC_LEN: usize = STACK_DEPTH + STACK_DEPTH;

// ENTRY POINTS
// ================================================================================================

/// Enforces public input boundary constraints for the stack.
///
/// - First row: `stack[i] == stack_inputs[i]` for i in 0..16
/// - Last row:  `stack[i] == stack_outputs[i]` for i in 0..16
pub fn enforce_main<AB>(
    frame: &Frame<'_, AB>,
    inputs: Inputs<'_, AB>,
    builder: &mut AB,
    local: &CoreCols<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    let pv = inputs.public_values;
    let n = pv.len();
    assert!(n >= PUBLIC_LEN, "public values too short: {n} < {PUBLIC_LEN}");

    // First row: stack[i] == stack_inputs[i]
    {
        let builder = &mut builder.when(frame.first_row());
        for (i, value) in pv[..STACK_DEPTH].iter().enumerate() {
            builder.assert_eq(local.stack.get(i), value.dup());
        }
    }

    // Last row: stack[i] == stack_outputs[i]
    {
        let builder = &mut builder.when(frame.last_row());
        for (i, value) in pv[STACK_DEPTH..PUBLIC_LEN].iter().enumerate() {
            builder.assert_eq(local.stack.get(i), value.dup());
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use core::borrow::Borrow;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_stark::air::native::{
        AirSpec, Assertion, UniformInputs, capture_from_spec,
        symbolic::{BaseInput, BaseLeaf, RowOffset, SymbolicExpr},
    };

    use super::{PUBLIC_LEN, STACK_DEPTH, enforce_main};
    use crate::vm::{
        CoreCols,
        constraints::{
            columns::{NUM_CORE_COLS, NUM_DECODER_COLS, NUM_SYSTEM_COLS},
            decoder,
            op_flags::OpFlags,
            system,
            test_utils::{ConstraintEvalContext, NativeConstraintEvalBuilder},
        },
    };

    #[test]
    fn public_boundaries_emit_all_inputs_before_outputs() {
        let mut local = CoreCols::<Felt>::default();
        local.stack.top = core::array::from_fn(|i| Felt::from_usize(3 * i));
        let public: [Felt; PUBLIC_LEN] = core::array::from_fn(|i| Felt::from_usize(100 + i));
        let context = ConstraintEvalContext::new().with_row_flags(true, true, false);
        let mut sink = NativeConstraintEvalBuilder::default();
        enforce_main(
            &context.frame(&local, &local),
            UniformInputs {
                public_values: &public,
                challenges: &[],
                exports: &[],
            },
            &mut sink,
            &local,
        );
        let expected: alloc::vec::Vec<QuadFelt> = (0..PUBLIC_LEN)
            .map(|i| (local.stack.top[i % STACK_DEPTH] - public[i]).into())
            .collect();
        assert_eq!(sink.evaluations, expected);
    }

    /// This is a helper subset, deliberately excluding the still-legacy stack and lookup bodies.
    /// Its non-Copy symbolic rows instantiate the same OpFlags polynomial used by mixed Core.
    #[test]
    fn native_helpers_accept_non_copy_rows_and_preserve_public_positions() {
        let spec = AirSpec {
            main_width: NUM_CORE_COLS,
            aux_width: 0,
            num_public_values: PUBLIC_LEN,
            num_challenges: 0,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        };
        let captured = capture_from_spec::<Felt, QuadFelt>(spec, |frame, inputs, sink| {
            let local: &CoreCols<_> = frame.main.current.borrow();
            let next: &CoreCols<_> = frame.main.next.borrow();
            let flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
            system::enforce_main(frame, sink, local, next, &flags);
            decoder::enforce_main(frame, sink, local, next, &flags);
            enforce_main(frame, inputs, sink, local);
        })
        .unwrap();
        assert_eq!(captured.descriptor.analysis().counts().ext, 0);
        let public_start = captured.assertions.len() - PUBLIC_LEN;
        assert!(public_start >= 19, "the 19 system assertions precede decoder and public inputs");
        for i in 0..PUBLIC_LEN {
            let Assertion::Base(SymbolicExpr::Mul { x: selector, y: difference, .. }) =
                &captured.assertions[public_start + i]
            else {
                panic!("public boundary must retain its selector times difference");
            };
            if i < STACK_DEPTH {
                assert!(matches!(selector.as_ref(), SymbolicExpr::Leaf(BaseLeaf::IsFirstRow)));
            } else {
                assert!(matches!(selector.as_ref(), SymbolicExpr::Leaf(BaseLeaf::IsLastRow)));
            }
            let SymbolicExpr::Sub { x: stack, y: public, .. } = difference.as_ref() else {
                panic!("public boundary must subtract the indexed public value");
            };
            assert!(matches!(stack.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Input(
                BaseInput::Main { offset: RowOffset::Current, index }
            )) if *index == NUM_SYSTEM_COLS + NUM_DECODER_COLS + i % STACK_DEPTH));
            assert!(matches!(public.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Input(
                BaseInput::Public(index)
            )) if *index == i));
        }
    }
}
