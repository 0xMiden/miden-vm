use std::vec::Vec;

use miden_core::field::{PrimeCharacteristicRing, QuadFelt};
use miden_crypto::stark::air::{
    AirBuilder, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder, RowWindow,
    WindowAccess,
    symbolic::{AirLayout, SymbolicAirBuilder, SymbolicExpression},
};
use miden_crypto::stark::matrix::RowMajorMatrix;

use super::layout::{FIRST_B_HIN_PAIR2_BASE_COL, FIRST_B_HIN_PAIR3_BASE_COL};
use super::local_checks;
use super::views::{ACRow, BDRow};
use super::{NUM_BLAKEG_COMPRESSION_COLS, periodic, selectors::Selectors};
use crate::Felt;

type Sym = SymbolicAirBuilder<Felt, QuadFelt>;
type Expr = SymbolicExpression<Felt>;

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<Felt>,
    preprocessed_window: RowWindow<'static, Felt>,
}

impl ConstraintEvalBuilder {
    fn new(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS], periodic_values: Vec<Felt>) -> Self {
        let mut main = Felt::zero_vec(NUM_BLAKEG_COMPRESSION_COLS * 2);
        main[..NUM_BLAKEG_COMPRESSION_COLS].copy_from_slice(local);
        Self {
            main: RowMajorMatrix::new(main, NUM_BLAKEG_COMPRESSION_COLS),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2], 1),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            periodic_values,
            evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
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

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "BlakeG tests use two-row transition windows");
        Felt::ONE
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &[]
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
        let _value: QuadFelt = x.into();
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

impl PeriodicAirBuilder for ConstraintEvalBuilder {
    type PeriodicVar = Felt;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

fn blakeg_symbolic_layout() -> AirLayout {
    AirLayout {
        preprocessed_width: 0,
        main_width: NUM_BLAKEG_COMPRESSION_COLS,
        num_public_values: 0,
        permutation_width: 1,
        num_permutation_challenges: 2,
        num_permutation_values: 0,
        num_periodic_columns: periodic::NUM_BLAKEG_PERIODIC_COLUMNS,
    }
}

fn ac_periodic_values() -> Vec<Felt> {
    let mut values = vec![Felt::ZERO; periodic::NUM_BLAKEG_PERIODIC_COLUMNS];
    values[periodic::P_IS_A] = Felt::ONE;
    values
}

fn first_b_periodic_values() -> Vec<Felt> {
    let mut values = vec![Felt::ZERO; periodic::NUM_BLAKEG_PERIODIC_COLUMNS];
    values[periodic::P_IS_B] = Felt::ONE;
    values[periodic::P_IS_FIRST_B] = Felt::ONE;
    values
}

fn eval_ac_a_new_byte_binding(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS]) -> Vec<Felt> {
    let mut builder = ConstraintEvalBuilder::new(local, ac_periodic_values());
    let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
    let ac = ACRow::<ConstraintEvalBuilder>::new(local);
    local_checks::enforce_ac_a_new_bytes_match_word(&mut builder, &ac, &sel);
    builder.evaluations
}

fn eval_first_b_hin_binding(local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS]) -> Vec<Felt> {
    let mut builder = ConstraintEvalBuilder::new(local, first_b_periodic_values());
    let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
    let bd = BDRow::<ConstraintEvalBuilder>::new(local);
    local_checks::enforce_first_b_hin_matches_b_words(&mut builder, &bd, &sel);
    builder.evaluations
}

fn eval_ac_message_schedule(
    local: &[Felt; NUM_BLAKEG_COMPRESSION_COLS],
    expected_idx: u64,
) -> Vec<Felt> {
    let mut periodic_values = ac_periodic_values();
    periodic_values[periodic::P_SIGMA_MSG_0] = Felt::new_unchecked(expected_idx);
    let mut builder = ConstraintEvalBuilder::new(local, periodic_values);
    let sel = Selectors::<ConstraintEvalBuilder>::new(builder.periodic_values(), 0);
    let ac = ACRow::<ConstraintEvalBuilder>::new(local);
    local_checks::enforce_ac_message_schedule(&mut builder, &ac, &sel);
    builder.evaluations
}

#[test]
fn a_new_bytes_are_bound_to_add3_word() {
    let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];

    assert!(
        eval_ac_a_new_byte_binding(&local).iter().all(|value| *value == Felt::ZERO),
        "zero row must satisfy the a_new byte binding",
    );

    // Slot 0 field 1 is `a_new_byte[0]`; with zero a/b/msg/k3, the arithmetic word is zero.
    local[1] = Felt::ONE;
    assert!(
        eval_ac_a_new_byte_binding(&local).iter().any(|value| *value != Felt::ZERO),
        "changing an a_new byte without changing the add3 word must be rejected",
    );
}

#[test]
fn ac_message_indices_are_bound_to_sigma_schedule() {
    let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];
    local[48] = Felt::new_unchecked(7);

    assert!(
        eval_ac_message_schedule(&local, 7).iter().all(|value| *value == Felt::ZERO),
        "matching SIGMA index must satisfy the schedule binding",
    );

    local[48] = Felt::new_unchecked(8);
    assert!(
        eval_ac_message_schedule(&local, 7).iter().any(|value| *value != Felt::ZERO),
        "wrong message index for the A/C row must be rejected",
    );
}

#[test]
fn first_b_hin_pairs_are_bound_to_b_words() {
    let mut local = [Felt::ZERO; NUM_BLAKEG_COMPRESSION_COLS];
    local[FIRST_B_HIN_PAIR2_BASE_COL] = Felt::new_unchecked(2);
    local[FIRST_B_HIN_PAIR3_BASE_COL] = Felt::new_unchecked(3);

    assert!(
        eval_first_b_hin_binding(&local).iter().all(|value| *value == Felt::ZERO),
        "zero first-B row with matching HIN fields must satisfy the binding",
    );

    local[FIRST_B_HIN_PAIR2_BASE_COL + 1] = Felt::ONE;
    assert!(
        eval_first_b_hin_binding(&local).iter().any(|value| *value != Felt::ZERO),
        "changing routed HIN pair 2 without changing B.b must be rejected",
    );

    local[FIRST_B_HIN_PAIR2_BASE_COL + 1] = Felt::ZERO;
    local[FIRST_B_HIN_PAIR3_BASE_COL] = Felt::new_unchecked(4);
    assert!(
        eval_first_b_hin_binding(&local).iter().any(|value| *value != Felt::ZERO),
        "wrong routed HIN pair index must be rejected",
    );
}

#[test]
fn carry_free_k2_quadratic_stays_degree_three_under_periodic_gate() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let diff: Expr = local[0] + local[1] - next[0];
    let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
    let constraint = sel.is_b() * diff.clone() * (diff - two32);

    assert_eq!(constraint.degree_multiple(), 3);
}

#[test]
fn carry_free_k3_bits_stay_degree_three_under_periodic_gate() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let k3: Expr = local[0].into();
    let bit0: Expr = local[1].into();
    let bit1: Expr = local[2].into();
    let one = Expr::ONE;
    let two = Expr::from(Felt::new_unchecked(2));
    let bool0 = sel.is_a() * bit0.clone() * (one.clone() - bit0.clone());
    let bool1 = sel.is_a() * bit1.clone() * (one - bit1.clone());
    let exclusive = sel.is_a() * bit0.clone() * bit1.clone();
    let reconstruct = sel.is_a() * (k3 - bit0 - two * bit1);

    assert_eq!(bool0.degree_multiple(), 3);
    assert_eq!(bool1.degree_multiple(), 3);
    assert_eq!(exclusive.degree_multiple(), 3);
    assert_eq!(reconstruct.degree_multiple(), 2);
}

#[test]
fn add3_with_k3_bits_and_no_full_k3_column_stays_degree_three() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let bit0: Expr = local[0].into();
    let bit1: Expr = local[1].into();
    let a: Expr = local[2].into();
    let b: Expr = local[3].into();
    let msg: Expr = local[4].into();
    let a_new: Expr = local[5].into();
    let one = Expr::ONE;
    let two = Expr::from(Felt::new_unchecked(2));
    let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
    let k3 = bit0.clone() + two * bit1.clone();

    let bool0 = sel.is_ac() * bit0.clone() * (one.clone() - bit0.clone());
    let bool1 = sel.is_ac() * bit1.clone() * (one - bit1.clone());
    let exclusive = sel.is_ac() * bit0 * bit1;
    let add3 = sel.is_ac() * (a_new - a - b - msg + two32 * k3);

    assert_eq!(bool0.degree_multiple(), 3);
    assert_eq!(bool1.degree_multiple(), 3);
    assert_eq!(exclusive.degree_multiple(), 3);
    assert_eq!(add3.degree_multiple(), 2);
}

#[test]
fn bd_rotation_contribution_sum_stays_degree_two_under_periodic_gate() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let expected: Expr = local[0].into();
    let contributions: [Expr; 4] = core::array::from_fn(|idx| local[idx + 1].into());
    let actual = contributions.into_iter().fold(Expr::ZERO, |acc, term| acc + term);

    let rot12 = sel.is_b() * (actual.clone() - expected.clone());
    let rot7 = sel.is_d() * (actual - expected);

    assert_eq!(rot12.degree_multiple(), 2);
    assert_eq!(rot7.degree_multiple(), 2);
}

#[test]
fn inverse_canonicality_gadget_stays_degree_three_under_msg_gate() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let lo: Expr = local[0].into();
    let hi: Expr = local[1].into();
    let inv: Expr = local[2].into();
    let z: Expr = local[3].into();
    let h = hi - Expr::from(Felt::new_unchecked((1u64 << 32) - 1));

    let inverse_or_zero = sel.is_msg_row() * (h.clone() * inv + z.clone() - Expr::ONE);
    let zero_flag = sel.is_msg_row() * z.clone() * h;
    let canonical = sel.is_msg_row() * z * lo;

    assert_eq!(inverse_or_zero.degree_multiple(), 3);
    assert_eq!(zero_flag.degree_multiple(), 3);
    assert_eq!(canonical.degree_multiple(), 3);
}

#[test]
fn direct_rate_packing_transition_stays_degree_two_under_msg_gate() {
    let builder = Sym::new(blakeg_symbolic_layout());
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let sel = Selectors::<Sym>::new(builder.periodic_values(), 0);

    let lo: Expr = local[0].into();
    let hi: Expr = local[1].into();
    let next_rate: Expr = next[0].into();
    let two32 = Expr::from(Felt::new_unchecked(1u64 << 32));
    let transition = sel.is_msg_row() * (next_rate - lo - two32 * hi);

    assert_eq!(transition.degree_multiple(), 2);
}

#[test]
fn blakeg_main_constraints_stay_degree_three() {
    let mut builder = Sym::new(blakeg_symbolic_layout());
    super::enforce_main(&mut builder);
    let max_degree = builder
        .base_constraints()
        .iter()
        .map(SymbolicExpression::degree_multiple)
        .max()
        .unwrap_or(0);
    let high_degree_indices = builder
        .base_constraints()
        .iter()
        .enumerate()
        .filter_map(|(idx, constraint)| {
            (constraint.degree_multiple() > 3).then_some((idx, constraint.degree_multiple()))
        })
        .collect::<Vec<_>>();

    assert_eq!(max_degree, 3, "high-degree constraints: {high_degree_indices:?}");
}
