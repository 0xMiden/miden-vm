use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
/// Numerical immutable input context for helpers with a separate native assertion sink.
pub(in crate::vm::constraints) struct ConstraintEvalContext {
    selectors: miden_stark::air::native::Selectors<Felt>,
    periodic_values: Vec<Felt>,
}

impl ConstraintEvalContext {
    pub(in crate::vm::constraints) fn new() -> Self {
        Self {
            selectors: miden_stark::air::native::Selectors {
                first: Felt::ZERO,
                last: Felt::ZERO,
                transition: Felt::ONE,
            },
            periodic_values: Vec::new(),
        }
    }

    pub(in crate::vm::constraints) fn with_row_flags(
        mut self,
        first: bool,
        last: bool,
        transition: bool,
    ) -> Self {
        self.selectors = miden_stark::air::native::Selectors {
            first: Felt::from_bool(first),
            last: Felt::from_bool(last),
            transition: Felt::from_bool(transition),
        };
        self
    }

    pub(in crate::vm::constraints) fn with_periodic_values(mut self, values: Vec<Felt>) -> Self {
        self.periodic_values = values;
        self
    }

    pub(in crate::vm::constraints) fn frame<'a>(
        &'a self,
        local: &'a super::columns::CoreCols<Felt>,
        next: &'a super::columns::CoreCols<Felt>,
    ) -> miden_stark::air::native::AirFrame<'a, Felt, QuadFelt> {
        self.frame_rows(local.as_slice(), next.as_slice())
    }

    pub(in crate::vm::constraints) fn frame_rows<'a>(
        &'a self,
        local: &'a [Felt],
        next: &'a [Felt],
    ) -> miden_stark::air::native::AirFrame<'a, Felt, QuadFelt> {
        use miden_stark::air::native::{AirFrame, Rows};
        AirFrame {
            main: Rows { current: local, next },
            preprocessed: Rows { current: &[], next: &[] },
            aux: Rows { current: &[], next: &[] },
            periodic: &self.periodic_values,
            selectors: self.selectors,
        }
    }
}

/// Numerical sink with no row, selector, or uniform input access.
#[derive(Default)]
pub(in crate::vm::constraints) struct NativeConstraintEvalBuilder {
    pub(in crate::vm::constraints) evaluations: Vec<QuadFelt>,
}

impl miden_stark::air::native::LiftedAirBuilder for NativeConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type ExtExpr = QuadFelt;

    fn emit_base(&mut self, value: Felt, _: miden_stark::air::native::ConstraintMeta<'_>) {
        self.evaluations.push(value.into());
    }

    fn emit_ext(&mut self, value: QuadFelt, _: miden_stark::air::native::ConstraintMeta<'_>) {
        self.evaluations.push(value);
    }
}
