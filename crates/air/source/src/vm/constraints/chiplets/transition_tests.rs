//! Boundary rules for chiplet sections, including boundaries with empty intervening sections.
//!
//! The section-order overview is:
//!
//! ```text
//! Controller -> (AEAD <-> Bitwise) -> Memory -> ACE -> Kernel ROM -> Padding
//! ```
//!
//! Forward jumps may skip empty optional sections. Within the AEAD/bitwise tier, AEAD enters at
//! phase 0, advances through phases 0..7, and may exit only after phase 7. Phases are determined
//! by the global chiplets row index, including on non-AEAD rows. The matrix below specifies every
//! edge, including bypasses and self-transitions omitted from the overview.
//!
//! These tests evaluate the production selector and destination constraints on two-row windows.
//! Acceptance here describes those boundary constraints, not a complete trace or lookup proof.

use alloc::vec::Vec;
use core::borrow::BorrowMut;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};

use super::{
    ace::enforce_ace_constraints_all_rows,
    aead_stream::enforce_aead_stream_constraints,
    columns::{AceCols, AeadStreamCols, MemoryCols, PeriodicCols},
    memory::enforce_memory_constraints,
    selectors::build_chiplet_selectors,
};
use crate::vm::{
    ChipletCols, constraints::test_utils::ConstraintEvalBuilder, trace::CHIPLETS_WIDTH,
};

#[derive(Clone, Copy, Debug)]
enum Section {
    Controller,
    Aead,
    Bitwise,
    Memory,
    Ace,
    Kernel,
    Padding,
}

use Section::{Ace, Aead, Bitwise, Controller, Kernel, Memory, Padding};

const SECTIONS: [Section; 7] = [Controller, Aead, Bitwise, Memory, Ace, Kernel, Padding];

impl Section {
    fn prefix(self) -> &'static [u8] {
        match self {
            Controller => &[0],
            Aead => &[1, 0, 0],
            Bitwise => &[1, 0, 1],
            Memory => &[1, 1, 0],
            Ace => &[1, 1, 1, 0],
            Kernel => &[1, 1, 1, 1, 0],
            Padding => &[1, 1, 1, 1, 1],
        }
    }

    fn row(self) -> ChipletCols<Felt> {
        let mut row = ChipletCols { chiplets: [Felt::ZERO; CHIPLETS_WIDTH] };
        for (cell, &bit) in row.chiplets.iter_mut().zip(self.prefix()) {
            *cell = Felt::from_u8(bit);
        }
        row
    }
}

fn accepted(evaluations: &[QuadFelt]) -> bool {
    assert!(!evaluations.is_empty(), "the evaluator must emit constraints");
    evaluations.iter().all(|&value| value == QuadFelt::ZERO)
}

fn assert_acceptance(evaluations: &[QuadFelt], expected: bool, context: &str) {
    let violations: Vec<_> = evaluations
        .iter()
        .enumerate()
        .filter(|(_, value)| **value != QuadFelt::ZERO)
        .collect();
    assert_eq!(accepted(evaluations), expected, "{context}; nonzero residuals: {violations:?}");
}

fn builder_at(row_index: usize) -> ConstraintEvalBuilder {
    let periodic_values = PeriodicCols::periodic_columns()
        .iter()
        .map(|column| column[row_index % column.len()])
        .collect();
    ConstraintEvalBuilder::new().with_periodic_values(periodic_values)
}

#[test]
fn section_transitions_and_empty_sections_follow_the_phase_aware_matrix() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Rule {
        Forbidden,
        AnyPhase,
        // Current row is phase 7, so the next row index is divisible by eight.
        CycleEnd,
    }
    use Rule::{AnyPhase as Any, CycleEnd as End, Forbidden as No};

    // Every forward bypass is explicit, including Controller -> Padding (all optional sections
    // empty). AEAD and bitwise may interleave despite the producer grouping AEAD before bitwise.
    // Next:       Controller AEAD Bitwise Memory ACE Kernel Padding
    #[rustfmt::skip]
    let transitions = [
        (Controller, [Any, End, Any, Any, Any, Any, Any]),
        (Aead,       [No,  Any, End, End, End, End, End]),
        (Bitwise,    [No,  End, Any, Any, Any, Any, Any]),
        (Memory,     [No,  No,  No,  Any, Any, Any, Any]),
        (Ace,        [No,  No,  No,  No,  Any, Any, Any]),
        (Kernel,     [No,  No,  No,  No,  No,  Any, Any]),
        (Padding,    [No,  No,  No,  No,  No,  No,  Any]),
    ];

    for (from, rules) in transitions {
        for (to, rule) in SECTIONS.into_iter().zip(rules) {
            for phase in 0..8 {
                let mut local = from.row();
                let next = to.row();
                // Kernel/padding prefixes overlap the next AEAD view's ctx/clk. Match these fields
                // so every carry equation remains satisfied even on a forbidden early exit:
                // rejection must come from the phase rule rather than an unrelated
                // payload mismatch.
                if matches!(from, Aead) {
                    let stream: &mut AeadStreamCols<Felt> = local.chiplets[3..23].borrow_mut();
                    stream.read_mut().ctx = next.aead_stream_cols().read().ctx;
                    stream.read_mut().clk = next.aead_stream_cols().read().clk;
                }
                let row_index = 8 + phase;
                let context = format!("{from:?} -> {to:?} at row {row_index} ({rule:?})");
                let mut builder = builder_at(row_index);
                let selectors = build_chiplet_selectors(&mut builder, &local, &next);
                assert_acceptance(
                    &builder.evaluations,
                    rule != No,
                    &format!("{context}: section order"),
                );
                if rule == No {
                    // Optimized gates assume ordered prefixes. A phase failure must never mask a
                    // missing section-order check, even for an aligned Memory -> AEAD transition.
                    continue;
                }

                // Entry checks belong to the preceding row, regardless of which intervening
                // sections are empty. Self-transitions and jumps past a target must
                // leave its entry gate off.
                assert_eq!(
                    selectors.memory_entry_next,
                    Felt::from_bool(matches!((from, to), (Controller | Aead | Bitwise, Memory))),
                    "{context}: memory entry",
                );
                assert_eq!(
                    selectors.ace_entry_next,
                    Felt::from_bool(matches!(
                        (from, to),
                        (Controller | Aead | Bitwise | Memory, Ace)
                    )),
                    "{context}: ACE entry",
                );

                builder.evaluations.clear();
                enforce_aead_stream_constraints(
                    &mut builder,
                    local.aead_stream_cols(),
                    next.aead_stream_cols(),
                    &selectors,
                );
                assert_acceptance(
                    &builder.evaluations,
                    rule == Any || phase == 7,
                    &format!("{context}: AEAD phase alignment"),
                );
            }
        }
    }
}

#[test]
fn only_padding_may_occupy_the_last_row() {
    for section in SECTIONS {
        let mut builder = builder_at(15).with_row_flags(false, true, false);
        build_chiplet_selectors(&mut builder, &section.row(), &Controller.row());
        assert_acceptance(
            &builder.evaluations,
            matches!(section, Padding),
            &format!("{section:?} at the last row: all chiplets must be inactive"),
        );
    }
}

#[test]
fn padding_can_wrap_to_controller_only_at_the_cyclic_opening() {
    for is_last_row in [false, true] {
        let mut builder = builder_at(15).with_row_flags(false, is_last_row, !is_last_row);
        let selectors = build_chiplet_selectors(&mut builder, &Padding.row(), &Controller.row());
        assert_acceptance(
            &builder.evaluations,
            is_last_row,
            &format!("Padding -> Controller: last row = {is_last_row}"),
        );
        if is_last_row {
            // The cyclic opening still sees raw next-row membership, while current activity and
            // controller continuation must vanish on the terminal padding row.
            assert_eq!(selectors.controller_next_active, Felt::ONE);
            assert_eq!(selectors.controller_transition, Felt::ZERO);
            assert_eq!(selectors.controller_active, Felt::ZERO);
            assert_eq!(selectors.aead_stream_active, Felt::ZERO);
            assert_eq!(selectors.bitwise_active, Felt::ZERO);
            assert_eq!(selectors.memory_active, Felt::ZERO);
            assert_eq!(selectors.ace_active, Felt::ZERO);
            assert_eq!(selectors.memory_entry_next, Felt::ZERO);
            assert_eq!(selectors.ace_entry_next, Felt::ZERO);
        }
    }
}

#[test]
fn only_active_prefix_cells_are_required_to_be_boolean() {
    for section in SECTIONS {
        let next = section.row();
        // Every prefix cell is checked on the current row, including the AEAD/bitwise split at
        // column 2. Disable transition checks to isolate Booleanity from prefix monotonicity.
        for column in 0..section.prefix().len() {
            for value in [0, 1, 2] {
                let mut local = section.row();
                local.chiplets[column] = Felt::from_u8(value);
                let mut builder = ConstraintEvalBuilder::new().with_row_flags(false, false, false);
                build_chiplet_selectors(&mut builder, &local, &next);
                assert_eq!(
                    accepted(&builder.evaluations),
                    value != 2,
                    "{section:?}: prefix column {column} = {value} must be Boolean",
                );
            }
        }
        // Cells beyond the prefix are payload; a value of 2 there must not acquire a selector
        // Booleanity requirement. Padding has no further selector columns to test.
        for column in section.prefix().len()..5 {
            let mut local = section.row();
            local.chiplets[column] = Felt::from_u8(2);
            let mut builder = ConstraintEvalBuilder::new().with_row_flags(false, false, false);
            build_chiplet_selectors(&mut builder, &local, &next);
            assert!(
                accepted(&builder.evaluations),
                "{section:?}: column {column} is payload, not a selector",
            );
        }
    }
}

fn memory_entry_evaluations(from: Section, next: &ChipletCols<Felt>) -> Vec<QuadFelt> {
    let local = from.row();
    let mut builder = ConstraintEvalBuilder::new();
    let selectors = build_chiplet_selectors(&mut builder, &local, next);
    assert!(accepted(&builder.evaluations), "{from:?} -> Memory: valid section order");
    assert_eq!(selectors.memory_entry_next, Felt::ONE, "{from:?} -> Memory: initializes memory");
    builder.evaluations.clear();
    enforce_memory_constraints(&mut builder, local.memory_cols(), next.memory_cols(), &selectors);
    builder.evaluations
}

#[test]
fn empty_sections_do_not_skip_memory_initialization() {
    for from in [Controller, Aead, Bitwise] {
        let mut next = Memory.row();
        let memory: &mut MemoryCols<Felt> = next.chiplets[3..20].borrow_mut();
        memory.is_read = Felt::ONE;
        memory.is_word = Felt::ONE;
        assert!(
            accepted(&memory_entry_evaluations(from, &next)),
            "{from:?} -> Memory: a first read of zero-initialized memory satisfies entry constraints",
        );
        for lane in 0..4 {
            let mut forged = next.clone();
            let memory: &mut MemoryCols<Felt> = forged.chiplets[3..20].borrow_mut();
            memory.values[lane] = Felt::from_u8(42);
            assert!(
                !accepted(&memory_entry_evaluations(from, &forged)),
                "{from:?} -> Memory: a fresh read cannot invent a nonzero value in lane {lane}",
            );
        }

        // A first write may initialize its written lanes, while every unwritten lane stays zero.
        for written_lane in 0..4 {
            let mut next = Memory.row();
            let memory: &mut MemoryCols<Felt> = next.chiplets[3..20].borrow_mut();
            memory.idx0 = Felt::from_bool(written_lane & 1 != 0);
            memory.idx1 = Felt::from_bool(written_lane & 2 != 0);
            memory.values[written_lane] = Felt::from_u8(42);
            assert!(
                accepted(&memory_entry_evaluations(from, &next)),
                "{from:?} -> Memory: first element write can initialize lane {written_lane}",
            );
            for unwritten_lane in (0..4).filter(|&lane| lane != written_lane) {
                let mut forged = next.clone();
                let memory: &mut MemoryCols<Felt> = forged.chiplets[3..20].borrow_mut();
                memory.values[unwritten_lane] = Felt::ONE;
                assert!(
                    !accepted(&memory_entry_evaluations(from, &forged)),
                    "{from:?} -> Memory: writing lane {written_lane} leaves lane {unwritten_lane} zero",
                );
            }
        }

        let mut next = Memory.row();
        let memory: &mut MemoryCols<Felt> = next.chiplets[3..20].borrow_mut();
        memory.is_word = Felt::ONE;
        memory.values = [Felt::from_u8(42); 4];
        assert!(
            accepted(&memory_entry_evaluations(from, &next)),
            "{from:?} -> Memory: first word write can initialize every lane",
        );
    }
}

#[test]
fn empty_sections_do_not_skip_ace_initialization() {
    for from in [Controller, Aead, Bitwise, Memory] {
        for s_start in [0, 1] {
            let local = from.row();
            let mut next = Ace.row();
            let ace: &mut AceCols<Felt> = next.chiplets[4..20].borrow_mut();
            ace.s_start = Felt::from_u8(s_start);
            let mut builder = ConstraintEvalBuilder::new();
            let selectors = build_chiplet_selectors(&mut builder, &local, &next);
            assert!(accepted(&builder.evaluations), "{from:?} -> ACE: valid section order");
            assert_eq!(selectors.ace_entry_next, Felt::ONE, "{from:?} -> ACE: initializes ACE");
            builder.evaluations.clear();
            enforce_ace_constraints_all_rows(
                &mut builder,
                local.ace_cols(),
                next.ace_cols(),
                &selectors,
            );
            assert_eq!(
                accepted(&builder.evaluations),
                s_start == 1,
                "{from:?} -> ACE: the first ACE row requires s_start = 1, got {s_start}",
            );
        }
    }
}
