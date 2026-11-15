//! Chiplets trace constraints.
//!
//! This module enforces:
//! - chiplet selector constraints
//! - controller sub-chiplet main-trace constraints
//! - AEAD stream main-trace constraints
//! - bitwise chiplet main-trace constraints
//! - memory chiplet main-trace constraints
//! - ACE chiplet main-trace constraints
//!
//! Eidos compression constraints are enforced by the separate
//! [`crate::vm::EidosCompressionAir`], with byte-table relations supplied by
//! [`crate::vm::And8LookupAir`].
//!
//! Chiplet LogUp lookup-argument constraints are emitted by
//! [`crate::vm::constraints::lookup::chiplet_air::emit_chiplet_lookup_columns`] and wired
//! through [`crate::vm::ChipletsAir`]'s `LookupAir` impl from `ChipletsAir::eval`.

pub mod ace;
pub mod aead_stream;
pub mod bitwise;
pub mod columns;
pub mod hasher_control;
pub mod memory;
pub mod selectors;

#[cfg(test)]
mod transition_tests;

use miden_stark::air::native::Frame;
use selectors::ChipletSelectors;

use crate::vm::{ChipletCols, NativeMidenAirBuilder};

// ENTRY POINTS
// ================================================================================================

/// Enforces chiplets main-trace constraints.
pub fn enforce_main<AB>(
    frame: &Frame<'_, AB>,
    builder: &mut AB,
    local: &ChipletCols<AB::Expr>,
    next: &ChipletCols<AB::Expr>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: NativeMidenAirBuilder,
{
    // Each evaluator sees its own payload and the gates derived from the shared selectors.
    let controller = local.controller_cols();
    let controller_next = next.controller_cols();
    hasher_control::enforce_controller_constraints(
        frame,
        builder,
        controller,
        controller_next,
        selectors,
    );

    aead_stream::enforce_aead_stream_constraints(
        frame,
        builder,
        local.aead_stream_cols(),
        next.aead_stream_cols(),
        selectors,
    );
    bitwise::enforce_bitwise_constraints(builder, local.bitwise_cols(), selectors);
    memory::enforce_memory_constraints(builder, local.memory_cols(), next.memory_cols(), selectors);
    ace::enforce_ace_constraints_all_rows(builder, local.ace_cols(), next.ace_cols(), selectors);
    hasher_control::enforce_merkle_level_constraints(builder, controller, controller_next);
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use core::borrow::Borrow;

    use miden_core::{Felt, field::QuadFelt};
    use miden_stark::air::native::{
        AirSpec, Assertion, capture_from_spec,
        symbolic::{BaseInput, BaseLeaf, RowOffset, SymbolicExpr, SymbolicExpression},
    };

    use super::{columns::PeriodicCols, enforce_main, selectors::build_chiplet_selectors};
    use crate::vm::{ChipletCols, constraints::columns::NUM_CHIPLETS_COLS};

    fn assert_main(expression: &SymbolicExpression<Felt>, offset: RowOffset, index: usize) {
        assert!(matches!(expression, SymbolicExpr::Leaf(BaseLeaf::Input(
            BaseInput::Main { offset: actual_offset, index: actual_index }
        )) if *actual_offset == offset && *actual_index == index));
    }

    /// Native helper capture covers every ordinary chiplet with non-Copy expression/periodic
    /// inputs. Lookup declarations remain separate until the complete Chiplets source is sealed.
    #[test]
    fn native_chiplet_helpers_preserve_ace_components_and_final_merkle_scope() {
        let spec = AirSpec {
            main_width: NUM_CHIPLETS_COLS,
            aux_width: 0,
            num_public_values: 0,
            num_challenges: 0,
            num_exports: 0,
            preprocessed: None,
            periodic_columns: Cow::Owned(PeriodicCols::periodic_columns()),
        };
        let captured = capture_from_spec::<Felt, QuadFelt>(spec, |frame, _, sink| {
            let local: &ChipletCols<_> = frame.main.current.borrow();
            let next: &ChipletCols<_> = frame.main.next.borrow();
            let selectors = build_chiplet_selectors(frame, sink, local, next);
            enforce_main(frame, sink, local, next, &selectors);
        })
        .unwrap();
        // Selector15, controller63, AEAD50, bitwise1, memory22, ACE20, final Merkle-level1.
        assert_eq!(captured.descriptor.analysis().counts().base, 172);
        assert_eq!(captured.descriptor.analysis().counts().ext, 0);

        // ACE's arithmetic equality follows its ternary-op assertion. It remains two BASE-class
        // constraints, c0 then c1, pointing at the two result-value cells in the current row.
        for (ordinal, index) in [(165, 11), (166, 12)] {
            let Assertion::Base(SymbolicExpr::Mul { y: difference, .. }) =
                &captured.assertions[ordinal]
            else {
                panic!("ACE equality must remain a gated base assertion");
            };
            let SymbolicExpr::Sub { x: lhs, .. } = difference.as_ref() else {
                panic!("ACE equality must preserve lhs-minus-rhs construction");
            };
            assert_main(lhs, RowOffset::Current, index);
        }

        // The final Merkle-level constraint owns its raw marker/s0/op_final scope; it must stay
        // after ACE without acquiring current activity or a transition selector from a wrapper.
        let Assertion::Base(SymbolicExpr::Mul { x: gate, y: relation, .. }) =
            captured.assertions.last().unwrap()
        else {
            panic!("the final assertion must remain the Merkle-level relation");
        };
        let SymbolicExpr::Mul { x: merkle, y: not_final, .. } = gate.as_ref() else {
            panic!("the Merkle-level gate must retain its two-factor construction");
        };
        let SymbolicExpr::Mul { x: marker, y: selector, .. } = merkle.as_ref() else {
            panic!("the controller Merkle marker must remain quadratic");
        };
        assert_main(marker, RowOffset::Current, 22);
        assert_main(selector, RowOffset::Current, 1);
        let SymbolicExpr::Sub { x: one, y: op_final, .. } = not_final.as_ref() else {
            panic!("the final-row marker must remain complemented");
        };
        assert!(
            matches!(one.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Constant(value)) if *value == Felt::ONE)
        );
        assert_main(op_final, RowOffset::Current, 20);
        let SymbolicExpr::Sub { x: next_level, y: expected_level, .. } = relation.as_ref() else {
            panic!("the level constraint must remain an equality difference");
        };
        assert_main(next_level, RowOffset::Next, 19);
        let SymbolicExpr::Add { x: level, y: one, .. } = expected_level.as_ref() else {
            panic!("the expected level must advance by one");
        };
        assert_main(level, RowOffset::Current, 19);
        assert!(
            matches!(one.as_ref(), SymbolicExpr::Leaf(BaseLeaf::Constant(value)) if *value == Felt::ONE)
        );
    }
}
