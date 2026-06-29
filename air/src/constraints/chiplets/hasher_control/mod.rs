//! Controller sub-chiplet constraints.
//!
//! The controller records one BlakeG compression request per row. Hash rows carry
//! `block[8] || cv_in[4]` in `state` and `cv_out[4]` in `row_data`. Merkle rows carry
//! `block[8] || cv_out[4]` in `state` and `[node_index, node_index_next, is_start, 0]`
//! in `row_data`.

pub mod flags;

use flags::ControllerFlags;
use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::AirBuilder;

use crate::{
    ChipletCols, MidenAirBuilder,
    constraints::{
        chiplets::{columns::ControllerCols, selectors::ChipletFlags},
        utils::BoolNot,
    },
};

// ENTRY POINT
// ================================================================================================

/// Enforce all controller sub-chiplet constraints.
pub fn enforce_controller_constraints<AB>(
    builder: &mut AB,
    local: &ChipletCols<AB::Var>,
    next: &ChipletCols<AB::Var>,
    chiplet: &ChipletFlags<AB::Expr>,
) where
    AB: MidenAirBuilder,
{
    let cols: &ControllerCols<AB::Var> = local.controller();
    let cols_next: &ControllerCols<AB::Var> = next.controller();
    let rows = ControllerFlags::<AB::Expr>::new(cols);

    let merkle_start: AB::Expr = cols.merkle_is_start().into();
    let merkle_start_next: AB::Expr = cols_next.merkle_is_start().into();
    let op_final: AB::Expr = local.controller_op_final().into();
    let s_ctrl_next: AB::Expr = next.chiplets[0].into();
    let merkle_or_padding: AB::Expr = local.controller_merkle_or_padding().into();
    let controller_s0: AB::Expr = cols.s0.into();

    // Do not multiply this gate by `s_ctrl`: controller selector constraints make it zero
    // off controller rows, and the narrower form keeps continuation-routing degree unchanged.
    let controller_padding =
        chiplet.is_active.clone() * merkle_or_padding.clone() * controller_s0.clone().not();
    let controller_merkle = merkle_or_padding.clone() * controller_s0.clone();

    // Trace skeleton.
    builder.when_first_row().assert_one(chiplet.is_active.clone());
    builder.when_first_row().assert_one(cols.s0);

    let first_merkle_row: AB::Expr = Into::<AB::Expr>::into(cols.s1)
        + Into::<AB::Expr>::into(cols.s2)
        - Into::<AB::Expr>::into(cols.s1) * Into::<AB::Expr>::into(cols.s2);
    builder
        .when_first_row()
        .assert_zero(first_merkle_row * merkle_start.clone().not());

    let first_mv_row = Into::<AB::Expr>::into(cols.s1) * Into::<AB::Expr>::into(cols.s2).not();
    builder.when_first_row().assert_eq(local.controller_mrupdate_id(), first_mv_row);

    builder
        .when(chiplet.is_active.clone())
        .assert_bools([cols.s0, cols.s1, cols.s2]);
    builder.when(chiplet.is_active.clone()).assert_bool(op_final.clone());
    builder.when(chiplet.is_active.clone()).assert_zero(rows.is_invalid.clone());
    builder
        .when(chiplet.is_active.clone())
        .assert_eq(merkle_or_padding.clone(), rows.is_padding.clone() + rows.is_merkle.clone());
    builder
        .when(chiplet.is_active.clone().not() * controller_s0)
        .assert_zero(merkle_or_padding);

    // Padding rows stay padding until the controller section ends.
    {
        let gate = controller_padding.clone() * s_ctrl_next.clone();
        let builder = &mut builder.when(gate);
        builder.assert_zero(cols_next.s0);
        builder.assert_one(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }

    // Padding rows carry only the MRUPDATE id.
    {
        let builder = &mut builder.when(controller_padding.clone());
        builder.assert_zeros(cols.state);
        builder.assert_zeros(cols.row_data);
        builder.assert_zero(local.controller_op_final());
    }

    // The controller-local MRUPDATE id increments exactly when the next row starts an MV leg.
    {
        let mrupdate_id: AB::Expr = local.controller_mrupdate_id().into();
        let s1_next: AB::Expr = cols_next.s1.into();
        let s2_next: AB::Expr = cols_next.s2.into();
        let mv_start_next = s1_next * s2_next.not() * merkle_start_next.clone();
        let ctrl_pair = chiplet.is_active.clone() * s_ctrl_next.clone();
        builder
            .when(ctrl_pair)
            .assert_eq(next.controller_mrupdate_id(), mrupdate_id + mv_start_next);
    }

    // Operation sequencing.
    {
        let gate = chiplet.is_active.clone() * rows.is_hash.clone() * op_final.clone().not();
        let builder = &mut builder.when(gate);
        builder.assert_one(s_ctrl_next.clone());
        builder.assert_zero(cols_next.s0);
        builder.assert_zero(cols_next.s1);
        builder.assert_zero(cols_next.s2);
    }
    {
        let gate = controller_merkle.clone() * op_final.clone().not();
        let builder = &mut builder.when(gate);
        builder.assert_one(s_ctrl_next.clone());
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
        let gate = s_ctrl_next.clone() * hash_absorb_next;
        let builder = &mut builder.when(gate);
        builder.assert_zero(op_final.clone());
        builder.assert_zero(cols.s1);
        builder.assert_zero(cols.s2);
    }
    {
        let merkle_or_padding_next: AB::Expr = next.controller_merkle_or_padding().into();
        let merkle_cont_next = s_ctrl_next
            * merkle_or_padding_next
            * Into::<AB::Expr>::into(cols_next.s0)
            * merkle_start_next.not();
        let builder = &mut builder.when(merkle_cont_next);
        builder.assert_zero(op_final.clone());
        builder.assert_one(cols.s0);
        builder.assert_eq(cols.s1, cols_next.s1);
        builder.assert_eq(cols.s2, cols_next.s2);
    }

    // Hash continuation: the next hash row's input CV equals this row's output digest.
    {
        let gate = chiplet.is_active.clone() * rows.is_hash.clone() * op_final.clone().not();
        let cv_next = cols_next.state_tail();
        let digest = cols.hash_digest();
        let builder = &mut builder.when(gate);
        for i in 0..4 {
            builder.assert_eq(cv_next[i], digest[i]);
        }
    }

    // Merkle rows.
    {
        let builder = &mut builder.when(controller_merkle.clone());

        builder.assert_bool(merkle_start.clone());
        builder.assert_zero(cols.row_data[3]);

        let node_index: AB::Expr = cols.merkle_node_index().into();
        let node_index_next: AB::Expr = cols.merkle_node_index_next().into();
        let bit = node_index - node_index_next.double();
        builder.assert_bool(bit);
    }

    // Merkle continuation: carry the shifted index and route the digest into the next row's
    // selected rate half, using the next row's virtual direction bit.
    {
        let merkle_cont = controller_merkle.clone() * op_final.clone().not();
        let builder = &mut builder.when(merkle_cont);
        builder.assert_eq(cols_next.merkle_node_index(), cols.merkle_node_index_next());

        let node_index_next: AB::Expr = cols_next.merkle_node_index().into();
        let node_index_after_next: AB::Expr = cols_next.merkle_node_index_next().into();
        let bit_next = node_index_next - node_index_after_next.double();
        let digest = cols.merkle_digest();
        let rate0_next = cols_next.rate0();
        let rate1_next = cols_next.rate1();
        for j in 0..4 {
            builder.assert_eq(
                digest[j],
                rate0_next[j] + bit_next.clone() * (rate1_next[j] - rate0_next[j]),
            );
        }
    }

    // Final Merkle row reaches the root, so its shifted index is zero.
    builder
        .when(controller_merkle)
        .when(op_final)
        .assert_zero(cols.merkle_node_index_next());
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_crypto::stark::{
        air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
        matrix::RowMajorMatrix,
    };

    use crate::{
        ChipletCols,
        constraints::chiplets::selectors::build_chiplet_selectors,
        trace::{
            AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, CHIPLETS_DATA_WIDTH, CHIPLETS_MODE_COL,
            CHIPLETS_WIDTH,
        },
    };

    const S_CTRL_COL: usize = 0;
    const CTRL_BASE: usize = 1;
    const CTRL_SELECTOR_COUNT: usize = 3;
    const CTRL_STATE_WIDTH: usize = 12;
    const CTRL_STATE_BASE: usize = CTRL_BASE + CTRL_SELECTOR_COUNT;
    const CTRL_ROW_DATA_BASE: usize = CTRL_STATE_BASE + CTRL_STATE_WIDTH;
    const CTRL_OVERLAY_WIDTH: usize = core::mem::size_of::<crate::ControllerCols<u8>>();
    const OP_FINAL_COL: usize = CTRL_BASE + CTRL_OVERLAY_WIDTH;
    const MERKLE_OR_PADDING_COL: usize = CHIPLETS_MODE_COL;

    const MP_VERIFY_SELECTORS: [u64; 3] = [1, 0, 1];

    struct ConstraintEvalBuilder {
        main: RowMajorMatrix<Felt>,
        aux: RowMajorMatrix<QuadFelt>,
        randomness: Vec<QuadFelt>,
        permutation_values: Vec<QuadFelt>,
        periodic_values: Vec<Felt>,
        preprocessed: RowWindow<'static, Felt>,
        evaluations: Vec<QuadFelt>,
    }

    impl ConstraintEvalBuilder {
        fn new() -> Self {
            Self {
                main: RowMajorMatrix::new(vec![Felt::ZERO; CHIPLETS_WIDTH * 2], CHIPLETS_WIDTH),
                aux: RowMajorMatrix::new(
                    vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2],
                    AUX_TRACE_WIDTH,
                ),
                randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
                permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
                periodic_values: Vec::new(),
                preprocessed: RowWindow::from_two_rows(&[], &[]),
                evaluations: Vec::new(),
            }
        }
    }

    impl AirBuilder for ConstraintEvalBuilder {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type PreprocessedWindow = RowWindow<'static, Felt>;
        type MainWindow = RowMajorMatrix<Felt>;
        type PublicVar = Felt;
        type PeriodicVar = Felt;

        fn main(&self) -> Self::MainWindow {
            self.main.clone()
        }

        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            &self.preprocessed
        }

        fn is_first_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_last_row(&self) -> Self::Expr {
            Felt::ZERO
        }

        fn is_transition(&self) -> Self::Expr {
            Felt::ONE
        }

        fn is_transition_window(&self, size: usize) -> Self::Expr {
            assert_eq!(size, 2, "controller tests use two-row transition windows");
            self.is_transition()
        }

        fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
            self.evaluations.push(QuadFelt::from(x.into()));
        }

        fn public_values(&self) -> &[Self::PublicVar] {
            &[]
        }

        fn periodic_values(&self) -> &[Self::PeriodicVar] {
            &self.periodic_values
        }
    }

    impl ExtensionBuilder for ConstraintEvalBuilder {
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;

        fn assert_zero_ext<I>(&mut self, x: I)
        where
            I: Into<Self::ExprEF>,
        {
            self.evaluations.push(x.into());
        }
    }

    impl PermutationAirBuilder for ConstraintEvalBuilder {
        type MP = RowMajorMatrix<QuadFelt>;
        type RandomVar = QuadFelt;
        type PermutationVar = QuadFelt;

        fn permutation(&self) -> Self::MP {
            self.aux.clone()
        }

        fn permutation_randomness(&self) -> &[Self::RandomVar] {
            &self.randomness
        }

        fn permutation_values(&self) -> &[Self::PermutationVar] {
            &self.permutation_values
        }
    }

    fn merkle_controller_row(
        selectors: [u64; 3],
        node_index: u64,
        is_start: bool,
        is_final: bool,
    ) -> ChipletCols<Felt> {
        let mut row = ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        };
        row.chiplets[S_CTRL_COL] = Felt::ONE;
        row.chiplets[MERKLE_OR_PADDING_COL] = Felt::ONE;
        row.chiplets[CTRL_BASE] = Felt::new_unchecked(selectors[0]);
        row.chiplets[CTRL_BASE + 1] = Felt::new_unchecked(selectors[1]);
        row.chiplets[CTRL_BASE + 2] = Felt::new_unchecked(selectors[2]);
        for i in 0..4 {
            row.chiplets[CTRL_STATE_BASE + 8 + i] = Felt::new_unchecked(10 + i as u64);
        }
        row.chiplets[CTRL_ROW_DATA_BASE] = Felt::new_unchecked(node_index);
        row.chiplets[CTRL_ROW_DATA_BASE + 1] = Felt::new_unchecked(node_index >> 1);
        row.chiplets[CTRL_ROW_DATA_BASE + 2] = if is_start { Felt::ONE } else { Felt::ZERO };
        row.chiplets[OP_FINAL_COL] = if is_final { Felt::ONE } else { Felt::ZERO };
        row
    }

    fn non_controller_row() -> ChipletCols<Felt> {
        ChipletCols {
            chiplets: [Felt::ZERO; CHIPLETS_DATA_WIDTH],
            chip_clk: Felt::ONE,
        }
    }

    fn set_rate0(row: &mut ChipletCols<Felt>, digest: [Felt; 4]) {
        for (i, value) in digest.into_iter().enumerate() {
            row.chiplets[CTRL_STATE_BASE + i] = value;
        }
    }

    fn merkle_digest(row: &ChipletCols<Felt>) -> [Felt; 4] {
        [
            row.chiplets[CTRL_STATE_BASE + 8],
            row.chiplets[CTRL_STATE_BASE + 9],
            row.chiplets[CTRL_STATE_BASE + 10],
            row.chiplets[CTRL_STATE_BASE + 11],
        ]
    }

    fn eval_controller_pair(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        let selectors = build_chiplet_selectors(&mut builder, local, next);
        super::enforce_controller_constraints(&mut builder, local, next, &selectors.controller);
        builder.evaluations
    }

    fn assert_accepts(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next);
        assert!(evaluations.iter().all(|value| *value == QuadFelt::ZERO), "{message}");
    }

    fn assert_rejects(local: &ChipletCols<Felt>, next: &ChipletCols<Felt>, message: &str) {
        let evaluations = eval_controller_pair(local, next);
        assert!(evaluations.iter().any(|value| *value != QuadFelt::ZERO), "{message}");
    }

    fn valid_merkle_continuation_pair() -> (ChipletCols<Felt>, ChipletCols<Felt>) {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 5, true, false);
        let mut next = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        set_rate0(&mut next, merkle_digest(&local));
        (local, next)
    }

    #[test]
    fn merkle_controller_accepts_valid_index_route() {
        let (local, next) = valid_merkle_continuation_pair();
        assert_accepts(&local, &next, "valid Merkle continuation should satisfy constraints");
    }

    #[test]
    fn merkle_controller_rejects_wrong_shifted_index_on_current_row() {
        let (mut local, next) = valid_merkle_continuation_pair();
        local.chiplets[CTRL_ROW_DATA_BASE + 1] += Felt::ONE;

        assert_rejects(&local, &next, "Merkle row must carry node_index_next = node_index >> 1");
    }

    #[test]
    fn merkle_controller_rejects_wrong_node_index_on_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_ROW_DATA_BASE] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must carry current node_index into the next row",
        );
    }

    #[test]
    fn merkle_controller_rejects_wrong_digest_route_to_next_row() {
        let (local, mut next) = valid_merkle_continuation_pair();
        next.chiplets[CTRL_STATE_BASE] += Felt::ONE;

        assert_rejects(
            &local,
            &next,
            "Merkle continuation must route digest into the next selected rate half",
        );
    }

    #[test]
    fn merkle_controller_rejects_nonzero_final_shifted_index() {
        let local = merkle_controller_row(MP_VERIFY_SELECTORS, 2, false, true);
        let next = non_controller_row();

        assert_rejects(&local, &next, "final Merkle row must have shifted index zero");
    }
}
