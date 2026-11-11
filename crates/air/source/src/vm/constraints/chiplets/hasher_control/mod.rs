//! Controller sub-chiplet constraints.
//!
//! The controller records one Eidos compression request per row. Hash rows carry
//! `block[8] || cv_in[4]` in `state` and `cv_out[4]` in `row_data`. Merkle rows carry
//! `block[8] || cv_out[4]` in `state` and `[node_index, node_index_next, is_start, level]`
//! in `row_data`.

pub mod flags;

use flags::ControllerFlags;
use miden_core::field::PrimeCharacteristicRing;
use miden_stark::air::AirBuilder;

use crate::vm::{
    MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletSelectors},
        utils::BoolNot,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforces controller row validity, operation sequencing, and hash/Merkle routing.
///
/// Merkle level increments are enforced by [`enforce_merkle_level_constraints`].
pub fn enforce_controller_constraints<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cols_next: &ControllerCols<AB::Var>,
    selectors: &ChipletSelectors<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let is_active = selectors.controller_active.clone();
    let is_transition = selectors.controller_transition.clone();
    let rows = ControllerFlags::<AB::Expr>::new(cols);

    let merkle_start: AB::Expr = cols.merkle_is_start().into();
    let merkle_start_next: AB::Expr = cols_next.merkle_is_start().into();
    let op_final: AB::Expr = cols.op_final.into();
    let is_active_next = selectors.controller_next_active.clone();
    let merkle_or_padding: AB::Expr = cols.merkle_or_padding.into();
    let controller_s0: AB::Expr = cols.s0.into();

    // Column 1 is zero on AEAD and bitwise rows. The constraint below zeros column 22
    // in later sections, so the Merkle gate stays quadratic without an activity factor.
    let controller_padding = is_active.clone() * merkle_or_padding.clone() * controller_s0.not();
    let controller_merkle = merkle_or_padding.clone() * controller_s0.clone();

    // Trace skeleton.
    builder.when_first_row().assert_one(is_active.clone());
    builder.when_first_row().assert_one(cols.s0);

    // Controller row addresses start at one and advance through controller padding. The
    // address relation ends with the controller section.
    builder.when_first_row().assert_one(cols.addr);
    builder
        .when(is_transition)
        .assert_eq(cols_next.addr.into(), cols.addr.into() + AB::Expr::ONE);

    let first_merkle_row: AB::Expr = cols.s1 + cols.s2 - cols.s1 * cols.s2;
    builder.when_first_row().assert_zero(first_merkle_row * merkle_start.not());

    let first_mv_row = Into::<AB::Expr>::into(cols.s1) * Into::<AB::Expr>::into(cols.s2).not();
    builder.when_first_row().assert_eq(cols.mrupdate_id, first_mv_row);

    builder.when(is_active.clone()).assert_bools([cols.s0, cols.s1, cols.s2]);
    builder.when(is_active.clone()).assert_bool(op_final.clone());
    builder.when(is_active.clone()).assert_zero(rows.is_invalid.clone());
    builder
        .when(is_active.clone())
        .assert_eq(merkle_or_padding.clone(), rows.is_padding.clone() + rows.is_merkle.clone());
    builder.when(is_active.not() * controller_s0).assert_zero(merkle_or_padding);

    // Padding rows stay padding until the controller section ends.
    {
        let gate = controller_padding.clone() * is_active_next.clone();
        let builder = &mut builder.when(gate);
        builder.assert_zero(cols_next.s0);
        builder.assert_one(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }

    // Padding rows carry the address and MRUPDATE id, with no operation payload.
    {
        let builder = &mut builder.when(controller_padding);
        builder.assert_zeros(cols.state);
        builder.assert_zeros(cols.row_data);
        builder.assert_zero(cols.op_final);
    }

    // The controller-local MRUPDATE id increments exactly when the next row starts an MV leg.
    {
        let mrupdate_id: AB::Expr = cols.mrupdate_id.into();
        let s1_next: AB::Expr = cols_next.s1.into();
        let s2_next: AB::Expr = cols_next.s2.into();
        let mv_start_next = s1_next * s2_next.not() * merkle_start_next.clone();
        let ctrl_pair = is_active.clone() * is_active_next.clone();
        builder
            .when(ctrl_pair)
            .assert_eq(cols_next.mrupdate_id, mrupdate_id + mv_start_next);
    }

    // Operation sequencing.
    {
        let gate = is_active.clone() * rows.is_hash.clone() * op_final.not();
        let builder = &mut builder.when(gate);
        builder.assert_one(is_active_next.clone());
        builder.assert_zero(cols_next.s0);
        builder.assert_zero(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }
    {
        let gate = controller_merkle.clone() * op_final.not();
        let builder = &mut builder.when(gate);
        builder.assert_one(is_active_next.clone());
        builder.assert_one(cols_next.s0);
        builder.assert_eq(cols_next.s1, cols.s1);
        builder.assert_eq(cols_next.s2, cols.s2);
        builder.assert_zero(merkle_start_next.clone());
    }

    // Conversely, any continuation row must follow a non-final matching row.
    {
        let hash_absorb_next = Into::<AB::Expr>::into(cols_next.s0).not()
            * Into::<AB::Expr>::into(cols_next.s1).not()
            * Into::<AB::Expr>::into(cols_next.s2).not();
        let gate = is_active_next.clone() * hash_absorb_next;
        let builder = &mut builder.when(gate);
        builder.assert_zero(op_final.clone());
        builder.assert_zero(cols.s1);
        builder.assert_zero(cols.s2);
    }
    {
        let merkle_or_padding_next: AB::Expr = cols_next.merkle_or_padding.into();
        let merkle_cont_next = is_active_next
            * merkle_or_padding_next
            * Into::<AB::Expr>::into(cols_next.s0)
            * merkle_start_next.not();
        let builder = &mut builder.when(merkle_cont_next);
        builder.assert_zero(op_final.clone());
        builder.assert_one(cols.s0);
        builder.assert_eq(cols.s1, cols_next.s1);
        builder.assert_eq(cols.s2, cols_next.s2);
    }

    // Hash continuation: the next hash row's input CV equals this row's output CV.
    {
        let gate = is_active * rows.is_hash * op_final.not();
        let cv_next = cols_next.state_tail();
        let cv_out = cols.hash_cv();
        let builder = &mut builder.when(gate);
        for i in 0..4 {
            builder.assert_eq(cv_next[i], cv_out[i]);
        }
    }

    // Merkle rows.
    {
        let builder = &mut builder.when(controller_merkle.clone());

        builder.assert_bool(merkle_start.clone());
        builder.when(merkle_start).assert_zero(cols.merkle_level());

        let node_index: AB::Expr = cols.merkle_node_index().into();
        let node_index_next: AB::Expr = cols.merkle_node_index_next().into();
        let bit = node_index - node_index_next.double();
        builder.assert_bool(bit);
    }

    // Merkle continuation: carry the shifted index and route the digest into the selected block
    // word of the next row, using that row's virtual direction bit.
    {
        let merkle_cont = controller_merkle.clone() * op_final.not();
        let builder = &mut builder.when(merkle_cont);
        builder.assert_eq(cols_next.merkle_node_index(), cols.merkle_node_index_next());

        let node_index_next: AB::Expr = cols_next.merkle_node_index().into();
        let node_index_after_next: AB::Expr = cols_next.merkle_node_index_next().into();
        let bit_next = node_index_next - node_index_after_next.double();
        let digest = cols.merkle_digest();
        let block_lo_next = cols_next.block_lo();
        let block_hi_next = cols_next.block_hi();
        for j in 0..4 {
            builder.assert_eq(
                digest[j],
                block_lo_next[j] + bit_next.clone() * (block_hi_next[j] - block_lo_next[j]),
            );
        }
    }

    // Final Merkle row reaches the root, so its shifted index is zero.
    builder
        .when(controller_merkle)
        .when(op_final)
        .assert_zero(cols.merkle_node_index_next());
}

/// Enforces the Merkle path level increment between consecutive rows of a path.
///
/// [`enforce_controller_constraints`] requires level zero on the start row.
pub fn enforce_merkle_level_constraints<AB>(
    builder: &mut AB,
    cols: &ControllerCols<AB::Var>,
    cols_next: &ControllerCols<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    let op_final: AB::Expr = cols.op_final.into();
    let merkle_or_padding: AB::Expr = cols.merkle_or_padding.into();
    let controller_merkle = merkle_or_padding * Into::<AB::Expr>::into(cols.s0);
    let level: AB::Expr = cols.merkle_level().into();

    builder
        .when(controller_merkle * op_final.not())
        .assert_eq(cols_next.merkle_level(), level + AB::Expr::ONE);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::borrow::BorrowMut;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };

    use crate::vm::{
        ChipletCols, ControllerCols,
        constraints::{
            chiplets::selectors::build_chiplet_selectors, test_utils::ConstraintEvalBuilder,
        },
        trace::CHIPLETS_WIDTH,
    };

    const EMPTY_CHIPLET_ROW: ChipletCols<Felt> =
        ChipletCols { chiplets: [Felt::ZERO; CHIPLETS_WIDTH] };
    const MP_VERIFY_SELECTORS: [u64; 3] = [1, 0, 1];

    fn merkle_controller_row(
        selectors: [u64; 3],
        node_index: u64,
        is_start: bool,
        is_final: bool,
    ) -> ChipletCols<Felt> {
        let mut row = EMPTY_CHIPLET_ROW;
        let cols: &mut ControllerCols<Felt> = row.chiplets[1..].borrow_mut();
        let [s0, s1, s2] = selectors.map(Felt::new_unchecked);
        *cols = ControllerCols {
            s0,
            s1,
            s2,
            state: [Felt::ZERO; 12],
            row_data: [
                Felt::new_unchecked(node_index),
                Felt::new_unchecked(node_index >> 1),
                Felt::from_bool(is_start),
                Felt::ZERO,
            ],
            op_final: Felt::from_bool(is_final),
            mrupdate_id: Felt::ZERO,
            merkle_or_padding: Felt::ONE,
            addr: Felt::ONE,
        };
        for (i, value) in cols.state[8..].iter_mut().enumerate() {
            *value = Felt::new_unchecked(10 + i as u64);
        }
        row
    }

    fn eval_controller_pair(
        local: &ChipletCols<Felt>,
        next: &ChipletCols<Felt>,
        first_row: bool,
    ) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new().with_row_flags(first_row, false, true);
        let selectors = build_chiplet_selectors(&mut builder, local, next);
        super::enforce_controller_constraints(
            &mut builder,
            local.controller_cols(),
            next.controller_cols(),
            &selectors,
        );
        super::enforce_merkle_level_constraints(
            &mut builder,
            local.controller_cols(),
            next.controller_cols(),
        );
        builder.evaluations
    }

    fn assert_accepts(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next, false);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO), "{message}");
    }

    fn assert_rejects(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next, false);
        assert!(evaluations.iter().any(|value| *value != QuadFelt::ZERO), "{message}");
    }

    fn valid_merkle_continuation_pair() -> (ChipletCols<Felt>, ChipletCols<Felt>) {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 5, true, false);
        let mut next = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        let cols: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols.addr = Felt::new_unchecked(2);
        cols.row_data[3] = Felt::ONE;
        cols.state[..4].copy_from_slice(&local.controller_cols().merkle_digest());
        (local, next)
    }

    #[test]
    fn merkle_controller_accepts_valid_index_route() {
        let (local, next) = valid_merkle_continuation_pair();
        assert_accepts(&local, &next, "valid Merkle continuation should satisfy constraints");
    }

    #[test]
    fn controller_section_must_start_on_the_first_trace_row() {
        let mut row = EMPTY_CHIPLET_ROW;
        row.chiplets[..3].copy_from_slice(&[Felt::ONE, Felt::ONE, Felt::ZERO]);
        // Satisfy the other controller first-row values so the section check must reject this
        // memory row even when its shared cells resemble a controller start.
        let cols: &mut ControllerCols<Felt> = row.chiplets[1..].borrow_mut();
        cols.addr = Felt::ONE;

        let evaluations = eval_controller_pair(&row, &row, true);
        assert!(evaluations.iter().any(|value| *value != QuadFelt::ZERO));
    }

    #[test]
    fn controller_addr_starts_at_one() {
        for addr in [0, 1, 7] {
            let (mut local, mut next) = valid_merkle_continuation_pair();
            let cols: &mut ControllerCols<Felt> = local.chiplets[1..].borrow_mut();
            cols.addr = Felt::new_unchecked(addr);
            let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
            cols_next.addr = Felt::new_unchecked(addr + 1);
            let evaluations = eval_controller_pair(&local, &next, true);
            assert_eq!(
                evaluations.iter().all(|value| *value == QuadFelt::ZERO),
                addr == 1,
                "first controller address = {addr}",
            );
        }
    }

    #[test]
    fn controller_addr_rejects_repeats_and_skips() {
        for addr in [1, 3] {
            let (local, mut next) = valid_merkle_continuation_pair();
            let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
            cols_next.addr = Felt::new_unchecked(addr);
            assert_rejects(&local, &next, "controller addresses must advance by exactly one");
        }
    }

    #[test]
    fn controller_addr_advances_through_padding_and_stops_at_section_end() {
        let mut padding = EMPTY_CHIPLET_ROW;
        let cols: &mut ControllerCols<Felt> = padding.chiplets[1..].borrow_mut();
        cols.s1 = Felt::ONE;
        cols.merkle_or_padding = Felt::ONE;
        cols.addr = Felt::new_unchecked(8);

        let mut next = padding.clone();
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.addr = Felt::new_unchecked(9);
        assert_accepts(&padding, &next, "padding must advance the controller address");
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.addr = Felt::new_unchecked(8);
        assert_rejects(&padding, &next, "padding must not repeat a controller address");

        let mut non_controller = EMPTY_CHIPLET_ROW;
        non_controller.chiplets[0] = Felt::ONE;
        let cols: &mut ControllerCols<Felt> = non_controller.chiplets[1..].borrow_mut();
        cols.addr = Felt::new_unchecked(100);
        assert_accepts(&padding, &non_controller, "the address relation stops at section end");
        assert_accepts(
            &non_controller,
            &non_controller,
            "non-controller rows have no controller address relation",
        );
    }

    #[test]
    fn controller_merkle_marker_allows_aead_payload_only_before_memory() {
        let mut row = EMPTY_CHIPLET_ROW;
        row.chiplets[0] = Felt::ONE;
        let cols: &mut ControllerCols<Felt> = row.chiplets[1..].borrow_mut();
        cols.merkle_or_padding = Felt::new_unchecked(42);
        assert_accepts(&row, &row, "AEAD can store payload in the controller marker cell");

        row.chiplets[1] = Felt::ONE;
        assert_rejects(&row, &row, "memory cannot activate the controller Merkle gate");
    }

    #[test]
    fn merkle_controller_rejects_nonzero_level_on_start_row() {
        let (mut local, mut next) = valid_merkle_continuation_pair();
        // Keep the increment valid so only the start-level constraint can reject these rows.
        let cols: &mut ControllerCols<Felt> = local.chiplets[1..].borrow_mut();
        cols.row_data[3] = Felt::ONE;
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.row_data[3] = Felt::new_unchecked(2);

        assert_rejects(&local, &next, "a Merkle start row must carry level zero");
    }

    #[test]
    fn merkle_controller_rejects_unincremented_level_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.row_data[3] = Felt::ZERO;

        assert_rejects(
            &local,
            &next,
            "a Merkle continuation must carry the previous level plus one",
        );
    }

    #[test]
    fn merkle_controller_rejects_skipped_level_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.row_data[3] = Felt::new_unchecked(2);

        assert_rejects(&local, &next, "a Merkle continuation must not skip a level");
    }

    #[test]
    fn merkle_controller_rejects_wrong_shifted_index_on_current_row() {
        let (mut local, next) = valid_merkle_continuation_pair();
        let cols: &mut ControllerCols<Felt> = local.chiplets[1..].borrow_mut();
        cols.row_data[1] += Felt::ONE;

        assert_rejects(&local, &next, "Merkle row must carry node_index_next = node_index >> 1");
    }

    #[test]
    fn merkle_controller_rejects_wrong_node_index_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.row_data[0] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must carry current node_index into the next row",
        );
    }

    #[test]
    fn merkle_controller_rejects_wrong_digest_route_to_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        let cols_next: &mut ControllerCols<Felt> = next.chiplets[1..].borrow_mut();
        cols_next.state[0] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must route digest into the next selected block half",
        );
    }

    #[test]
    fn merkle_controller_rejects_nonzero_final_shifted_index() {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        let next = EMPTY_CHIPLET_ROW;

        assert_rejects(&local, &next, "final Merkle row must have shifted index zero");
    }
}
