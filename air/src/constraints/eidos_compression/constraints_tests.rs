use alloc::vec::Vec;

use miden_core::field::{Field, PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::{
    air::{AirBuilder, ConstraintDegrees, ExtensionBuilder, PermutationAirBuilder, RowWindow},
    matrix::RowMajorMatrix,
};

use super::{
    constraints::{
        enforce_footer_rows, enforce_fused_rows, enforce_inactive_footer_input_aux,
        enforce_inactive_footer_output_aux,
    },
    layout::*,
    lookup::{FOOTER_INPUT_COLUMN, FOOTER_OUTPUT_COLUMN},
    model::initial_working_state,
    periodic::get_periodic_column_values,
    schedule::{EIDOS_COMPRESSION_IV, G_IDX_DIAG, fused_step_at},
    selectors::EidosCompressionSelectors,
    trace::{
        EidosCompressionFeltRow, TraceMode, generate_felt_trace_block,
        generate_felt_trace_block_with_cycle_id,
        generate_felt_trace_block_with_initial_state_for_test, rewrite_felt_footer_for_test,
    },
};
use crate::{
    Felt, HandwrittenMidenAir, MidenAir,
    constraints::and8_lookup::eidos::normalize,
    lookup::{ConstraintLookupBuilder, LookupAir},
};

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,
    extension_evaluations: Vec<QuadFelt>,
    preprocessed_window: RowWindow<'static, Felt>,
    is_first_row: Felt,
    is_last_row: Felt,
}

#[test]
fn handwritten_constraint_degree_remains_three() {
    let air = HandwrittenMidenAir(MidenAir::EidosCompression);
    let degree = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
    assert_eq!(degree, ConstraintDegrees { base: 3, ext: 3 });
}

#[test]
fn footer_input_aux_is_pinned_outside_full_cv_rows() {
    let row = [Felt::ZERO; NUM_COLS];

    for row_idx in 0..BLOCK_PERIOD {
        let mut builder =
            ConstraintEvalBuilder::new(&row, &row, periodic_row(row_idx), row_idx, BLOCK_PERIOD);
        builder.aux.values[FOOTER_INPUT_COLUMN] = QuadFelt::ONE;
        let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);

        enforce_inactive_footer_input_aux(&mut builder, &selectors);

        assert_eq!(builder.extension_evaluations.len(), 1);
        let expected = if row_idx == 0 || row_idx == BLOCK_PERIOD - 1 {
            QuadFelt::ZERO
        } else {
            QuadFelt::ONE
        };
        assert_eq!(builder.extension_evaluations[0], expected, "row {row_idx}");
    }
}

#[test]
fn footer_output_aux_is_pinned_outside_aead_footers() {
    for mode in [Felt::ZERO, Felt::ONE] {
        for row_idx in 0..BLOCK_PERIOD {
            let mut row = [Felt::ZERO; NUM_COLS];
            row[F_MODE_COL] = mode;
            let mut builder = ConstraintEvalBuilder::new(
                &row,
                &row,
                periodic_row(row_idx),
                row_idx,
                BLOCK_PERIOD,
            );
            builder.aux.values[FOOTER_OUTPUT_COLUMN] = QuadFelt::ONE;
            let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);

            enforce_inactive_footer_output_aux(&mut builder, &row, &selectors);

            assert_eq!(builder.extension_evaluations.len(), 1);
            let is_active = mode == Felt::ONE && row_idx >= FOOTER_START;
            let expected = QuadFelt::from_bool(!is_active);
            assert_eq!(builder.extension_evaluations[0], expected, "mode {mode}, row {row_idx}");
        }
    }
}

#[test]
fn inactive_footer_aux_pins_close_zero_denominator_rows() {
    // With alpha = beta = 0 and an all-zero fused row, both footer-column denominators are zero.
    // Their zero multiplicities therefore make the generic cross-multiplied constraints vacuous.
    // The handwritten inactive-row pins must still reject nonzero auxiliary cells.
    let row = [Felt::ZERO; NUM_COLS];
    let mut builder = ConstraintEvalBuilder::new(&row, &row, periodic_row(1), 1, BLOCK_PERIOD);
    builder.aux.values[FOOTER_INPUT_COLUMN] = QuadFelt::ONE;
    builder.aux.values[FOOTER_OUTPUT_COLUMN] = QuadFelt::ONE;

    let air = MidenAir::EidosCompression;
    let mut lookup_builder = ConstraintLookupBuilder::new(&mut builder, &air);
    LookupAir::eval(&air, &mut lookup_builder);
    lookup_builder.finish();

    // Column zero emits its anchor and recurrence; every later column emits one constraint.
    assert_eq!(builder.extension_evaluations.len(), AUX_COLS + 1);
    assert_eq!(builder.extension_evaluations[FOOTER_INPUT_COLUMN + 1], QuadFelt::ZERO);
    assert_eq!(builder.extension_evaluations[FOOTER_OUTPUT_COLUMN + 1], QuadFelt::ZERO);

    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_inactive_footer_input_aux(&mut builder, &selectors);
    enforce_inactive_footer_output_aux(&mut builder, &row, &selectors);

    assert_eq!(&builder.extension_evaluations[AUX_COLS + 1..], &[QuadFelt::ONE, QuadFelt::ONE]);
}

impl ConstraintEvalBuilder {
    fn new(
        local: &[Felt; NUM_COLS],
        next: &[Felt; NUM_COLS],
        periodic_values: Vec<Felt>,
        row_idx: usize,
        trace_len: usize,
    ) -> Self {
        let mut main = Felt::zero_vec(2 * NUM_COLS);
        main[..NUM_COLS].copy_from_slice(local);
        main[NUM_COLS..].copy_from_slice(next);

        Self {
            main: RowMajorMatrix::new(main, NUM_COLS),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * AUX_COLS], AUX_COLS),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values,
            evaluations: Vec::new(),
            extension_evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            is_first_row: Felt::from_bool(row_idx == 0),
            is_last_row: Felt::from_bool(row_idx + 1 == trace_len),
        }
    }

    fn into_base_evaluations(self) -> Vec<Felt> {
        assert!(
            self.extension_evaluations.is_empty(),
            "EidosCompression base-constraint tests must not emit extension-field constraints",
        );
        self.evaluations
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
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition(&self) -> Self::Expr {
        Felt::ONE - self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "EidosCompression 32-row tests use two-row transition windows");
        self.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(x.into());
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
        self.extension_evaluations.push(x.into());
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

fn test_block() -> [u32; 16] {
    [
        0x0000_0001,
        0x0000_0002,
        0x0000_0003,
        0x0000_0004,
        0x8000_0005,
        0x0000_0006,
        0x0000_0007,
        0x0000_0008,
        0x0000_0009,
        0x8000_000a,
        0x8000_000b,
        0x0000_000c,
        0x0000_000d,
        0x0000_000e,
        0x0000_000f,
        0x0000_0010,
    ]
}

fn test_h() -> [u32; 8] {
    [
        0x0000_0021,
        0x8000_0001,
        0x8000_0022,
        0x0000_0043,
        0x0000_0023,
        0x0000_0065,
        0x0000_0024,
        0x0000_0087,
    ]
}

fn alternate_test_block() -> [u32; 16] {
    test_block().map(|word| word.wrapping_add(0x0101_0101))
}

fn alternate_test_h() -> [u32; 8] {
    test_h().map(|word| word.wrapping_add(0x0010_0010))
}

fn periodic_row(row_idx: usize) -> Vec<Felt> {
    get_periodic_column_values()
        .iter()
        .map(|column| column[row_idx % column.len()])
        .collect()
}

fn eval_fused_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, BLOCK_PERIOD);
    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    builder.into_base_evaluations()
}

fn eval_footer_row(local: &[Felt; NUM_COLS], next: &[Felt; NUM_COLS], row_idx: usize) -> Vec<Felt> {
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, BLOCK_PERIOD);
    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.into_base_evaluations()
}

pub(super) fn eval_main_row(trace: &[EidosCompressionFeltRow], row_idx: usize) -> Vec<Felt> {
    let next_idx = (row_idx + 1).min(trace.len() - 1);
    let local = &trace[row_idx];
    let next = &trace[next_idx];
    let mut builder =
        ConstraintEvalBuilder::new(local, next, periodic_row(row_idx), row_idx, trace.len());
    let selectors = EidosCompressionSelectors::<Felt>::new(builder.periodic_values(), 0);
    enforce_fused_rows(&mut builder, local, next, &selectors);
    enforce_footer_rows(&mut builder, local, next, &selectors);
    builder.into_base_evaluations()
}

fn two_cycle_trace(second_cycle_id: u64) -> Vec<EidosCompressionFeltRow> {
    let first =
        generate_felt_trace_block_with_cycle_id(test_block(), test_h(), 0, TraceMode::Compression);
    let second = generate_felt_trace_block_with_cycle_id(
        alternate_test_block(),
        alternate_test_h(),
        second_cycle_id,
        TraceMode::Compression,
    );
    first.rows.into_iter().chain(second.rows).collect()
}

fn assert_all_zero(values: &[Felt]) {
    assert!(
        values.iter().all(|value| *value == Felt::ZERO),
        "expected all constraints to vanish"
    );
}

fn assert_any_nonzero(values: &[Felt]) {
    assert!(values.iter().any(|value| *value != Felt::ZERO), "expected a failing constraint");
}

fn footer_xor_word_value(row: &EidosCompressionFeltRow, slot_base: usize) -> u32 {
    let bytes = core::array::from_fn(|byte| {
        let base = footer_xor_slot_col(slot_base + byte, 0);
        let lhs = row[base].as_canonical_u64() as u8;
        let rhs = row[base + 1].as_canonical_u64() as u8;
        lhs ^ rhs
    });
    u32::from_le_bytes(bytes)
}

fn rewrite_footer_d_prefix(trace: &mut [EidosCompressionFeltRow], footer: usize) {
    let origin = FOOTER_START + footer;
    let row = &trace[origin];
    let out_even = footer_xor_word_value(row, F_OUTPUT_EVEN_SLOT_BASE);
    let out_odd = footer_xor_word_value(row, F_OUTPUT_ODD_SLOT_BASE);
    let top_bit = footer_top_bit_value(row);
    let masked_odd = out_odd - (top_bit << 24);
    let packed = Felt::from_u32(out_even) + Felt::from_u64(1 << 32) * Felt::from_u32(masked_odd);

    for later_footer in footer..FOOTER_ROWS {
        trace[FOOTER_START + later_footer][footer_interface_tail_col(footer)] = packed;
    }
}

fn footer_top_bit_value(row: &EidosCompressionFeltRow) -> u32 {
    let a = row[F_TOP_BIT_SLOT_BASE_COL];
    let b = row[F_TOP_BIT_SLOT_BASE_COL + 1];
    let x = normalize(F_TOP_BIT_LOOKUP_BYTE_POSITION, row[F_TOP_BIT_SLOT_BASE_COL + 2]);
    (a + b - x).halve().as_canonical_u64() as u32
}

#[test]
fn air_constraint_mutation_matrix_rejects_each_witness_family() {
    let cases = [
        ("message cycle id", 0, G_COMPRESSION_CYCLE_ID_COL, 0),
        ("k2", 0, G_K2_BASE_COL, 0),
        ("AC lhs", 0, g_ac_byte_slot_col(0, 0, 0), 0),
        ("AC rhs", 0, g_ac_byte_slot_col(0, 0, 1), 0),
        ("AC and", 0, g_ac_byte_slot_col(0, 0, 2), 0),
        ("BD rhs", 0, g_bd_rot_slot_col(0, 0, 1), 0),
        ("BD contribution", 0, g_bd_rot_slot_col(0, 0, 2), 0),
        ("fused transition", 1, g_ac_byte_slot_col(0, 0, 1), 0),
        ("footer bridge", FOOTER_START, footer_future_w_col(0, 0), FUSED_G_ROWS - 1),
        ("footer B-sum bridge", FOOTER_START, F_B_SUM_CORRECTION_COL, FUSED_G_ROWS - 1),
        ("footer xor duplicate", FOOTER_START, footer_xor_slot_col(8, 1), FOOTER_START),
        ("footer top byte", FOOTER_START, F_TOP_BIT_SLOT_BASE_COL, FOOTER_START),
        ("footer CV correction", FOOTER_START, F_CV_STORAGE_COLS[0], FOOTER_START),
        ("footer message word", FOOTER_START, footer_msg_word_col(0), FOOTER_START),
        ("footer range limb", FOOTER_START, footer_range_slot_col(0, 0), FOOTER_START),
        ("footer range padding", FOOTER_START, footer_range_slot_col(0, 1), FOOTER_START),
        (
            "footer interface tail",
            FOOTER_START,
            footer_interface_tail_col(0),
            FOOTER_START,
        ),
        ("footer future-W tail", FOOTER_START, footer_future_w_col(0, 11), FOOTER_START),
        ("footer R canonical inverse", FOOTER_START, F_R_CANON_INV_BASE_COL, FOOTER_START),
        ("footer R canonical zero", FOOTER_START, F_R_CANON_Z_BASE_COL, FOOTER_START),
        ("footer C canonical inverse", FOOTER_START, F_C_CANON_INV_COL, FOOTER_START),
        ("footer C canonical zero", FOOTER_START, F_C_CANON_Z_COL, FOOTER_START),
        (
            "footer multiplicity transition",
            FOOTER_START + 1,
            F_COMPRESSION_MULTIPLICITY_COL,
            FOOTER_START,
        ),
        ("footer mode", FOOTER_START, F_MODE_COL, FOOTER_START),
        ("footer clk", FOOTER_START, F_CLK_COL, FOOTER_START),
        (
            "footer cycle id transition",
            FOOTER_START + 1,
            F_COMPRESSION_CYCLE_ID_COL,
            FOOTER_START,
        ),
    ];

    for (name, mutated_row, mutated_col, evaluated_row) in cases {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        trace.rows[mutated_row][mutated_col] += Felt::ONE;
        assert!(
            eval_main_row(&trace.rows, evaluated_row)
                .iter()
                .any(|&value| value != Felt::ZERO),
            "mutation {name:?} was not rejected",
        );
    }
}

#[test]
fn air_constraints_accept_two_consecutive_compression_cycles() {
    let trace = two_cycle_trace(1);

    for row in 0..trace.len() {
        assert_all_zero(&eval_main_row(&trace, row));
    }
}

#[test]
fn air_constraints_pin_first_compression_cycle_id_to_zero() {
    let mut trace = two_cycle_trace(2);
    for row in trace.iter_mut().take(BLOCK_PERIOD) {
        row[F_COMPRESSION_CYCLE_ID_COL] = Felt::ONE;
    }

    assert_any_nonzero(&eval_main_row(&trace, 0));
}

#[test]
fn air_constraints_reject_inconsistent_fused_cycle_id() {
    let mut trace = two_cycle_trace(1);
    trace[5][G_COMPRESSION_CYCLE_ID_COL] += Felt::ONE;

    assert_any_nonzero(&eval_main_row(&trace, 5));
}

#[test]
fn air_constraints_pin_inner_fused_cycle_id_constancy() {
    let mut trace = two_cycle_trace(1);

    // This is the original two-cycle forgery with every per-row ID equality left intact: most of
    // cycle 0 borrows cycle 1's ID, while row 0, row 27, and the footer retain cycle 0's ID. Only
    // the cross-row cycle-ID constraint can reject the two discontinuities.
    for row in trace.iter_mut().take(FUSED_G_ROWS - 1).skip(1) {
        row[G_COMPRESSION_CYCLE_ID_COL] = Felt::ONE;
    }

    for row_idx in 0..trace.len() {
        let rejected = eval_main_row(&trace, row_idx).iter().any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            matches!(row_idx, 0 | 26),
            "unexpected constraint result on forged row {row_idx}",
        );
    }
}

#[test]
fn air_constraints_reject_inconsistent_footer_cycle_id() {
    let mut trace = two_cycle_trace(1);
    trace[FOOTER_START][F_COMPRESSION_CYCLE_ID_COL] += Felt::ONE;

    assert_any_nonzero(&eval_main_row(&trace, FOOTER_START));
}

#[test]
fn air_constraints_bind_fused_and_footer_cycle_ids() {
    let mut trace = two_cycle_trace(1);
    trace[FOOTER_START][F_COMPRESSION_CYCLE_ID_COL] += Felt::ONE;

    assert_any_nonzero(&eval_main_row(&trace, FUSED_G_ROWS - 1));
}

#[test]
fn air_constraints_require_consecutive_cycle_ids() {
    let trace = two_cycle_trace(2);

    assert_any_nonzero(&eval_main_row(&trace, BLOCK_PERIOD - 1));
}

#[test]
fn air_fused_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for row in 0..FUSED_G_ROWS {
        assert_all_zero(&eval_fused_row(&trace.rows[row], &trace.rows[row + 1], row));
    }
}

#[test]
fn air_fused_constraints_reject_bad_carry() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][G_K2_BASE_COL] = Felt::new_unchecked(2);

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_accept_all_ternary_k3_roots() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let row_idx = FUSED_G_ROWS - 1;
    let g = 0;
    let next = trace.rows[row_idx + 1];

    for root in [Felt::ZERO, Felt::ONE, Felt::TWO] {
        trace.rows[row_idx][g_k3_col(g)] = root;
        assert_all_zero(&eval_fused_row(&trace.rows[row_idx], &next, row_idx));
    }
}

#[test]
fn air_fused_constraints_reject_nonternary_k3_values() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let row_idx = FUSED_G_ROWS - 1;
    let next = trace.rows[row_idx + 1];

    for invalid in [Felt::from_u32(3), Felt::from_u32(17), -Felt::ONE] {
        trace.rows[row_idx][g_k3_col(0)] = invalid;
        assert_any_nonzero(&eval_fused_row(&trace.rows[row_idx], &next, row_idx));
    }
}

#[test]
fn air_fused_constraints_pin_k2_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let row_idx = FUSED_G_ROWS - 1;
    let g = 0;
    let next = trace.rows[row_idx + 1];
    let row = &mut trace.rows[row_idx];
    let original_k2 = row[G_K2_BASE_COL + g];
    let delta = (original_k2 - Felt::TWO) * Felt::from_u64(1 << 32);

    // Preserve the second addition equation while making k2 non-boolean. The last fused row has
    // no fused-row transition, so no other main-trace constraint sees the adjusted c_new witness.
    row[G_K2_BASE_COL + g] = Felt::TWO;
    row[g_bd_rot_slot_col(g, 0, 1)] += delta;

    assert_any_nonzero(&eval_fused_row(row, &next, row_idx));
}

#[test]
fn air_fused_constraints_reject_bad_rotation_payload() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_bd_rot_slot_col(0, 0, 2)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_reject_bad_initial_iv() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[0][g_bd_rot_slot_col(0, 0, 1)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_fused_constraints_pin_both_initial_iv_halves() {
    for iv_idx in [0, 4] {
        let mut initial_v = initial_working_state(test_h());
        initial_v[8 + iv_idx] = EIDOS_COMPRESSION_IV[iv_idx] ^ 1;
        let trace = generate_felt_trace_block_with_initial_state_for_test(
            test_block(),
            test_h(),
            initial_v,
            TraceMode::Compression,
        );

        for row_idx in 0..BLOCK_PERIOD {
            let rejected =
                eval_main_row(&trace.rows, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == 0,
                "IV word {iv_idx} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_fused_constraints_reject_bad_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[1][g_ac_byte_slot_col(0, 0, 1)] += Felt::ONE;

    assert_any_nonzero(&eval_fused_row(&trace.rows[0], &trace.rows[1], 0));
}

#[test]
fn air_missing_b_transition_is_replaced_by_the_total_b_relation() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for row in 0..FUSED_G_ROWS - 1 {
        let local = &trace.rows[row];
        let mut next = trace.rows[row + 1];
        let step = fused_step_at(row).expect("row is fused");
        let next_step = fused_step_at(row + 1).expect("next row is fused");
        let affected_word = step.lane_map[MISSING_ROTATION_G][1];
        let affected_next_g = next_step
            .lane_map
            .iter()
            .position(|lane| lane[1] == affected_word)
            .expect("the affected word remains in a B lane");

        // Compensating the B input in reconstructed A isolates the intentionally omitted direct
        // B transition. The total-B lookup remains responsible for rejecting this mutation.
        next[g_bd_rot_slot_col(affected_next_g, 0, 0)] += Felt::ONE;
        next[g_msg_word_col(affected_next_g)] -= Felt::ONE;
        assert_all_zero(&eval_fused_row(local, &next, row));

        // Preserving the total with another B lane cannot float both values: that lane's direct
        // transition remains and rejects the compensated mutation.
        let anchored_next_g = (affected_next_g + 1) % NUM_G;
        next[g_bd_rot_slot_col(anchored_next_g, 0, 0)] -= Felt::ONE;
        next[g_msg_word_col(anchored_next_g)] += Felt::ONE;
        assert_any_nonzero(&eval_fused_row(local, &next, row));
    }
}

#[test]
fn air_last_fused_total_b_bridge_accepts_only_equal_two_sided_changes() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let local = &trace.rows[FUSED_G_ROWS - 1];
    let mut footer0 = trace.rows[FOOTER_START];
    let affected_idx = F_FUTURE_W_WORD_INDICES
        .iter()
        .position(|&word_idx| word_idx == G_IDX_DIAG[MISSING_ROTATION_G][1])
        .expect("footer 0 carries the affected final B word");

    footer0[footer_future_w_col(0, affected_idx)] += Felt::ONE;
    assert_any_nonzero(&eval_footer_row(local, &footer0, FUSED_G_ROWS - 1));

    let coefficient = super::algebra::cv_storage_coefficient::<Felt>(7);
    footer0[F_B_SUM_CORRECTION_COL] += coefficient.inverse();
    assert_all_zero(&eval_footer_row(local, &footer0, FUSED_G_ROWS - 1));
}

#[test]
fn air_reconstructed_inputs_are_anchored_on_every_fused_row() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    // Row zero's reconstructed `a` is anchored by the atomic cycle-tagged CV relation. Every
    // later row's reconstructed `a` and `c` must be anchored by the immediately preceding
    // transition. Change only a locally valid carry encoding so no booleanity constraint can mask
    // a missing transition anchor.
    for row_idx in 1..FUSED_G_ROWS {
        for g in 0..NUM_G {
            let mut forged = trace.rows[row_idx];
            let k3 = forged[g_k3_col(g)].as_canonical_u64();
            let alternate_k3 = (k3 + 1) % 3;
            forged[g_k3_col(g)] = Felt::new_unchecked(alternate_k3);

            let evaluations = eval_fused_row(&trace.rows[row_idx - 1], &forged, row_idx - 1);
            assert!(
                evaluations.iter().any(|&value| value != Felt::ZERO),
                "reconstructed a[{g}] floated on fused row {row_idx}",
            );

            let mut forged = trace.rows[row_idx];
            forged[G_K2_BASE_COL + g] = Felt::ONE - forged[G_K2_BASE_COL + g];

            let evaluations = eval_fused_row(&trace.rows[row_idx - 1], &forged, row_idx - 1);
            assert!(
                evaluations.iter().any(|&value| value != Felt::ZERO),
                "reconstructed c[{g}] floated on fused row {row_idx}",
            );
        }
    }
}

#[test]
fn air_reconstructed_c_is_anchored_by_iv_on_first_row() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for g in 0..NUM_G {
        let mut forged = trace.rows[0];
        forged[G_K2_BASE_COL + g] = Felt::ONE - forged[G_K2_BASE_COL + g];

        let evaluations = eval_fused_row(&forged, &trace.rows[1], 0);
        assert!(
            evaluations.iter().any(|&value| value != Felt::ZERO),
            "initial IV did not anchor reconstructed c[{g}]",
        );
    }
}

#[test]
fn air_constraints_pin_all_four_fused_transition_families() {
    let original = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let alternate = generate_felt_trace_block(
        alternate_test_block(),
        alternate_test_h(),
        TraceMode::Compression,
    );

    for boundary in 0..FUSED_G_ROWS_PER_ROUND {
        let mut forged = original.rows;

        // Splice four locally valid rows from another compression. The only broken equations are
        // the two boundary transitions, which belong to the same row family four rows apart. A
        // source mutation deleting that transition family therefore makes this case fully valid.
        forged[boundary + 1..boundary + 5]
            .copy_from_slice(&alternate.rows[boundary + 1..boundary + 5]);

        for row_idx in 0..BLOCK_PERIOD {
            let rejected = eval_main_row(&forged, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == boundary || row_idx == boundary + FUSED_G_ROWS_PER_ROUND,
                "transition-family {boundary} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_accept_generated_trace() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });

    for row in FUSED_G_ROWS - 1..BLOCK_PERIOD {
        let next = row.saturating_add(1).min(BLOCK_PERIOD - 1);
        assert_all_zero(&eval_footer_row(&trace.rows[row], &trace.rows[next], row));
    }
}

#[test]
fn air_footer_constraints_reject_bad_bridge() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_future_w_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FUSED_G_ROWS - 1],
        &trace.rows[FOOTER_START],
        FUSED_G_ROWS - 1,
    ));
}

#[test]
fn air_footer_constraints_pin_all_four_direct_output_bridges() {
    for word_idx in [0, 1, 8, 9] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        let mut forged_final_v = trace.final_v;
        forged_final_v[word_idx] ^= 1;
        rewrite_felt_footer_for_test(
            &mut trace.rows,
            test_block(),
            test_h(),
            forged_final_v,
            TraceMode::Compression,
        );

        for row_idx in 0..BLOCK_PERIOD {
            let rejected =
                eval_main_row(&trace.rows, row_idx).iter().any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == FUSED_G_ROWS - 1,
                "final word {word_idx} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_reject_bad_message_limb() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_range_slot_col(0, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_reject_bad_current_cv_binding() {
    for footer in 0..FOOTER_ROWS {
        for &col in &F_CV_STORAGE_COLS[2 * footer..2 * footer + 2] {
            let mut trace =
                generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
            trace.rows[FOOTER_START + footer][col] += Felt::ONE;
            let next = (FOOTER_START + footer + 1).min(BLOCK_PERIOD - 1);

            assert_any_nonzero(&eval_footer_row(
                &trace.rows[FOOTER_START + footer],
                &trace.rows[next],
                FOOTER_START + footer,
            ));
        }
    }
}

#[test]
fn air_footer_constraints_pin_current_message_cv_and_tail_values() {
    for footer in 0..FOOTER_ROWS {
        let origin = FOOTER_START + footer;
        let columns = [
            footer_msg_word_col(0),
            footer_msg_word_col(1),
            F_CV_STORAGE_COLS[2 * footer],
            F_CV_STORAGE_COLS[2 * footer + 1],
            footer_interface_tail_col(footer),
        ];

        for col in columns {
            let mut trace =
                generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

            trace.rows[origin][col] += Felt::ONE;
            let next = (origin + 1).min(BLOCK_PERIOD - 1);
            assert_any_nonzero(&eval_footer_row(&trace.rows[origin], &trace.rows[next], origin));
        }
    }
}

#[test]
fn air_footer_constraints_pin_output_high_word_bindings() {
    for slot_base in [F_OUTPUT_EVEN_SLOT_BASE, F_OUTPUT_ODD_SLOT_BASE] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        let origin = FOOTER_START;
        let byte_base = footer_xor_slot_col(slot_base, 0);
        let lhs = trace.rows[origin][byte_base].as_canonical_u64() as u8;
        let rhs = (trace.rows[origin][byte_base + 1].as_canonical_u64() as u8) ^ 1;
        trace.rows[origin][byte_base + 1] = Felt::from_u8(rhs);
        trace.rows[origin][byte_base + 2] = Felt::from_u8(lhs & rhs);
        rewrite_footer_d_prefix(&mut trace.rows, 0);

        for row_idx in FOOTER_START..BLOCK_PERIOD {
            let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
            let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
                .iter()
                .any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == origin,
                "output slot {slot_base} had an unexpected result on row {row_idx}",
            );
        }
    }
}

#[test]
fn air_footer_constraints_pin_top_bit_mask() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    let footer = (0..FOOTER_ROWS)
        .find(|&footer| footer_top_bit_value(&trace.rows[FOOTER_START + footer]) == 128)
        .expect("test vector must exercise an odd output word with its top bit set");
    let origin = FOOTER_START + footer;

    trace.rows[origin][F_TOP_BIT_SLOT_BASE_COL + 1] = Felt::ZERO;
    trace.rows[origin][F_TOP_BIT_SLOT_BASE_COL + 2] = Felt::ZERO;
    rewrite_footer_d_prefix(&mut trace.rows, footer);

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx == origin,
            "top-bit-mask forgery had an unexpected result on row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_future_w_shift() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][footer_future_w_col(0, 0)] += Felt::ONE;

    // Evaluate F0 directly, without the last-fused-to-F0 bridge, to isolate the footer queue shift.
    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_reject_bad_canonicality() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START][F_C_CANON_Z_COL] = Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_constraints_pin_noncanonical_pair_rejection() {
    let mut block = test_block();
    block[0] = 7;
    block[1] = u32::MAX;
    // Bypass the production writer's canonical-input precondition so this fixture can isolate the
    // AIR's corresponding constraint. The writer rejection is covered separately in trace tests.
    let h = test_h();
    let trace = generate_felt_trace_block_with_initial_state_for_test(
        block,
        h,
        initial_working_state(h),
        TraceMode::Compression,
    );
    let evaluations =
        eval_footer_row(&trace.rows[FOOTER_START], &trace.rows[FOOTER_START + 1], FOOTER_START);

    // `(7, u32::MAX)` packs to 6 modulo the Goldilocks prime, colliding with `(6, 0)`. All other
    // footer constraints accept this honest Eidos compression witness; only `z * lo = 0` rejects
    // the non-canonical representation.
    assert_eq!(evaluations.iter().filter(|&&value| value != Felt::ZERO).count(), 1);
}

#[test]
fn air_footer_constraints_pin_mode_booleanity() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    for row in trace.rows.iter_mut().skip(FOOTER_START) {
        row[F_MODE_COL] = Felt::from_u8(2);
        row[F_COMPRESSION_MULTIPLICITY_COL] = Felt::ZERO;
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let evaluations = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx);
        assert_any_nonzero(&evaluations);
    }
}

#[test]
fn air_footer_constraints_pin_mode_persistence() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    let footer3 = &mut trace.rows[BLOCK_PERIOD - 1];
    footer3[F_MODE_COL] = Felt::ZERO;
    let out_even = footer_xor_word_value(footer3, F_OUTPUT_EVEN_SLOT_BASE);
    let out_odd = footer_xor_word_value(footer3, F_OUTPUT_ODD_SLOT_BASE);
    let top_bit = footer_top_bit_value(footer3);
    let masked_odd = out_odd - (top_bit << 24);
    footer3[footer_interface_tail_col(FOOTER_ROWS - 1)] =
        Felt::from_u32(out_even) + Felt::from_u64(1 << 32) * Felt::from_u32(masked_odd);

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx == BLOCK_PERIOD - 2,
            "mode-persistence forgery had an unexpected result on row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_footer_transition() {
    let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
    trace.rows[FOOTER_START + 1][footer_r_col(1, 0)] += Felt::ONE;

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}

#[test]
fn air_footer_state_band_pins_every_cross_row_value() {
    let trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);

    for footer in 0..FOOTER_ROWS - 1 {
        let row_idx = FOOTER_START + footer;
        let local = &trace.rows[row_idx];
        let next = &trace.rows[row_idx + 1];

        for idx in 0..2 * footer + 2 {
            let mut forged_next = *next;
            forged_next[footer_r_col(footer + 1, idx)] += Felt::ONE;
            assert!(
                eval_footer_row(local, &forged_next, row_idx)
                    .iter()
                    .any(|&value| value != Felt::ZERO),
                "footer {footer} did not carry R[{idx}]",
            );
        }

        for idx in 0..=2 * footer + 1 {
            let mut forged_next = *next;
            forged_next[F_CV_STORAGE_COLS[idx]] += Felt::ONE;
            assert!(
                eval_footer_row(local, &forged_next, row_idx)
                    .iter()
                    .any(|&value| value != Felt::ZERO),
                "footer {footer} did not carry CV[{idx}]",
            );
        }

        for idx in 0..=footer {
            let mut forged_next = *next;
            forged_next[footer_interface_tail_col(idx)] += Felt::ONE;
            assert!(
                eval_footer_row(local, &forged_next, row_idx)
                    .iter()
                    .any(|&value| value != Felt::ZERO),
                "footer {footer} did not carry interface tail[{idx}]",
            );
        }

        for idx in 0..4 {
            let mut forged_local = *local;
            forged_local[footer_future_w_col(footer, idx)] += Felt::ONE;
            assert!(
                eval_footer_row(&forged_local, next, row_idx)
                    .iter()
                    .any(|&value| value != Felt::ZERO),
                "footer {footer} did not bind consumed future-W[{idx}]",
            );
        }

        for idx in 0..footer_future_w_indices(footer + 1).len() {
            let mut forged_next = *next;
            forged_next[footer_future_w_col(footer + 1, idx)] += Felt::ONE;
            assert!(
                eval_footer_row(local, &forged_next, row_idx)
                    .iter()
                    .any(|&value| value != Felt::ZERO),
                "footer {footer} did not shift future-W[{idx}]",
            );
        }
    }
}

#[test]
fn air_footer_constraints_pin_cv_and_interface_tail_persistence() {
    for is_cv in [true, false] {
        let mut trace = generate_felt_trace_block(test_block(), test_h(), TraceMode::Compression);
        for footer in 1..FOOTER_ROWS {
            let col = if is_cv {
                F_CV_STORAGE_COLS[0]
            } else {
                footer_interface_tail_col(0)
            };
            trace.rows[FOOTER_START + footer][col] += Felt::ONE;
        }

        for row_idx in FOOTER_START..BLOCK_PERIOD {
            let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
            let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
                .iter()
                .any(|&value| value != Felt::ZERO);
            assert_eq!(
                rejected,
                row_idx == FOOTER_START,
                "{} persistence had an unexpected result on row {row_idx}",
                if is_cv { "CV" } else { "interface tail" },
            );
        }
    }
}

#[test]
fn air_footer_constraints_reject_aead_compression_multiplicity() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    for row in trace.rows.iter_mut().skip(FOOTER_START) {
        row[F_COMPRESSION_MULTIPLICITY_COL] = Felt::ONE;
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let evaluations = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx);
        assert_any_nonzero(&evaluations);
    }
}

#[test]
fn air_footer_constraints_pin_aead_clk_persistence() {
    let mut trace =
        generate_felt_trace_block(test_block(), test_h(), TraceMode::AeadXof { clk: 19 });
    for (footer, row) in trace.rows.iter_mut().skip(FOOTER_START).enumerate() {
        row[F_CLK_COL] = Felt::from_usize(19 + footer);
    }

    for row_idx in FOOTER_START..BLOCK_PERIOD {
        let next_idx = (row_idx + 1).min(BLOCK_PERIOD - 1);
        let rejected = eval_footer_row(&trace.rows[row_idx], &trace.rows[next_idx], row_idx)
            .iter()
            .any(|&value| value != Felt::ZERO);
        assert_eq!(
            rejected,
            row_idx < BLOCK_PERIOD - 1,
            "AEAD clk persistence had an unexpected result on footer row {row_idx}",
        );
    }
}

#[test]
fn air_footer_constraints_reject_bad_multiplicity_transition() {
    let mut trace = generate_felt_trace_block(
        test_block(),
        test_h(),
        TraceMode::CompressionWithMultiplicity { multiplicity: 2 },
    );
    trace.rows[FOOTER_START + 1][F_COMPRESSION_MULTIPLICITY_COL] = Felt::new_unchecked(3);

    assert_any_nonzero(&eval_footer_row(
        &trace.rows[FOOTER_START],
        &trace.rows[FOOTER_START + 1],
        FOOTER_START,
    ));
}
