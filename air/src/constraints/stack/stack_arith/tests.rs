use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{Field, PrimeCharacteristicRing, PrimeField64, QuadFelt},
    operations::opcodes,
};
use miden_crypto::stark::{
    air::{AirBuilder, EmptyWindow, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder},
    matrix::RowMajorMatrix,
};

use super::enforce_main;
use crate::{
    MainCols,
    constraints::op_flags::{OpFlags, generate_test_row},
    trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
};

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    evaluations: Vec<QuadFelt>,
}

impl ConstraintEvalBuilder {
    fn new() -> Self {
        Self {
            main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2], AUX_TRACE_WIDTH),
            randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
            permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
            periodic_values: Vec::new(),
            evaluations: Vec::new(),
        }
    }
}

impl AirBuilder for ConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type PreprocessedWindow = EmptyWindow<Felt>;
    type MainWindow = RowMajorMatrix<Felt>;
    type PublicVar = Felt;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "stack_arith only uses 2-row transition constraints");
        Felt::ONE
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(QuadFelt::from(x.into()));
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

impl PeriodicAirBuilder for ConstraintEvalBuilder {
    type PeriodicVar = Felt;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

/// Sets the u32 helper registers (hasher_state[2..7]) in the decoder.
fn set_u32_helpers(row: &mut MainCols<Felt>, lo: u32, hi: u32) {
    row.decoder.hasher_state[2] = Felt::new_unchecked(lo as u64 & 0xffff);
    row.decoder.hasher_state[3] = Felt::new_unchecked((lo as u64) >> 16);
    row.decoder.hasher_state[4] = Felt::new_unchecked(hi as u64 & 0xffff);
    row.decoder.hasher_state[5] = Felt::new_unchecked((hi as u64) >> 16);
    row.decoder.hasher_state[6] = Felt::ZERO;
}

fn eval_stack_arith(local: &MainCols<Felt>, next: &MainCols<Felt>) -> Vec<QuadFelt> {
    let mut builder = ConstraintEvalBuilder::new();
    let op_flags = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
    enforce_main(&mut builder, local, next, &op_flags);
    builder.evaluations
}

#[test]
fn stack_arith_u32add_constraints_allow_non_u32_operands() {
    let non_u32 = Felt::new_unchecked(Felt::ORDER_U64 - 1);
    assert!(non_u32.as_canonical_u64() > u32::MAX as u64);

    let mut local = generate_test_row(opcodes::U32ADD as usize);
    local.stack.top[0] = non_u32;
    local.stack.top[1] = Felt::ONE;
    set_u32_helpers(&mut local, 0, 0);

    let next = generate_test_row(0);

    let op_flags: OpFlags<Felt> = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
    assert_eq!(op_flags.u32add(), Felt::ONE);
    assert_eq!(op_flags.u32sub(), Felt::ZERO);

    let evaluations = eval_stack_arith(&local, &next);
    assert!(
        evaluations.iter().all(|value| *value == QuadFelt::ZERO),
        "expected U32ADD constraints to accept a non-u32 operand with forged u32 outputs"
    );
}

#[test]
fn stack_arith_u32sub_constraints_allow_non_u32_operands() {
    let non_u32 = Felt::new_unchecked(Felt::ORDER_U64 - 1);
    let diff = ((1u64 << 32) - 12_290) as u32;
    assert!(non_u32.as_canonical_u64() > u32::MAX as u64);

    let mut local = generate_test_row(opcodes::U32SUB as usize);
    local.stack.top[0] = Felt::new_unchecked(12_289);
    local.stack.top[1] = non_u32;
    set_u32_helpers(&mut local, diff, 0);

    let mut next = generate_test_row(0);
    next.stack.top[0] = Felt::ONE;
    next.stack.top[1] = Felt::new_unchecked(diff as u64);

    let op_flags: OpFlags<Felt> = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
    assert_eq!(op_flags.u32sub(), Felt::ONE);
    assert_eq!(op_flags.u32add(), Felt::ZERO);

    let evaluations = eval_stack_arith(&local, &next);
    assert!(
        evaluations.iter().all(|value| *value == QuadFelt::ZERO),
        "expected U32SUB constraints to accept a non-u32 operand with forged u32 outputs"
    );
}

#[test]
fn stack_arith_u32mul_constraints_allow_non_u32_sha256_rotr_operand() {
    let non_u32 = Felt::new((u32::MAX as u64) + 2);
    let rotr_7_multiplier = Felt::new(1 << 25);
    let product = non_u32.as_canonical_u64() * rotr_7_multiplier.as_canonical_u64();
    let lo = product as u32;
    let hi = (product >> 32) as u32;

    assert!(non_u32.as_canonical_u64() > u32::MAX as u64);

    let mut local = generate_test_row(opcodes::U32MUL as usize);
    local.stack.top[0] = rotr_7_multiplier;
    local.stack.top[1] = non_u32;
    set_u32_helpers(&mut local, lo, hi);
    local.decoder.hasher_state[6] = Felt::new(u32::MAX as u64 - hi as u64).inverse();

    let mut next = generate_test_row(0);
    next.stack.top[0] = Felt::new(lo as u64);
    next.stack.top[1] = Felt::new(hi as u64);

    let op_flags: OpFlags<Felt> = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
    assert_eq!(op_flags.u32mul(), Felt::ONE);

    let evaluations = eval_stack_arith(&local, &next);
    assert!(
        evaluations.iter().all(|value| *value == QuadFelt::ZERO),
        "expected U32MUL constraints to accept a non-u32 operand with forged rotr outputs"
    );
}

#[test]
fn stack_arith_u32div_constraints_allow_non_u32_sha256_shr_operand() {
    let non_u32 = Felt::new((u32::MAX as u64) + 2);
    let divisor = Felt::new(8);
    let quotient = Felt::new(non_u32.as_canonical_u64() / divisor.as_canonical_u64());
    let remainder = Felt::new(non_u32.as_canonical_u64() % divisor.as_canonical_u64());
    let lo = (non_u32.as_canonical_u64() - quotient.as_canonical_u64()) as u32;
    let hi = (divisor.as_canonical_u64() - remainder.as_canonical_u64() - 1) as u32;

    assert!(non_u32.as_canonical_u64() > u32::MAX as u64);

    let mut local = generate_test_row(opcodes::U32DIV as usize);
    local.stack.top[0] = divisor;
    local.stack.top[1] = non_u32;
    set_u32_helpers(&mut local, lo, hi);

    let mut next = generate_test_row(0);
    next.stack.top[0] = remainder;
    next.stack.top[1] = quotient;

    let op_flags: OpFlags<Felt> = OpFlags::new(&local.decoder, &local.stack, &next.decoder);
    assert_eq!(op_flags.u32div(), Felt::ONE);

    let evaluations = eval_stack_arith(&local, &next);
    assert!(
        evaluations.iter().all(|value| *value == QuadFelt::ZERO),
        "expected U32DIV constraints to accept a non-u32 operand with forged shr outputs"
    );
}
