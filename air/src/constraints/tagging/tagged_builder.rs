use alloc::vec::Vec;

use miden_crypto::stark::air::MidenAirBuilder;

use super::{CURRENT_MAX_ID, TagRecord, state};

/// Wraps an AIR builder and records tag IDs in the order assertions are emitted.
///
/// This is intended for structural validation: IDs must be strictly increasing, unique, and
/// cover the full range `0..=CURRENT_MAX_ID`.
pub struct TaggedAirBuilder<AB> {
    inner: AB,
    records: Vec<TagRecord>,
    used: Vec<Option<&'static str>>,
    prev_enabled: bool,
}

impl<AB> TaggedAirBuilder<AB> {
    /// Enable tagging for the current thread and wrap the provided builder.
    pub fn new(inner: AB) -> Self {
        let prev_enabled = state::is_enabled();
        state::set_enabled(true);
        Self {
            inner,
            records: Vec::new(),
            used: vec![None; CURRENT_MAX_ID + 1],
            prev_enabled,
        }
    }

    pub fn records(&self) -> &[TagRecord] {
        &self.records
    }

    /// Panics if any ID in `0..=CURRENT_MAX_ID` was not recorded.
    pub fn assert_complete(&self) {
        let missing: Vec<usize> = self
            .used
            .iter()
            .enumerate()
            .filter_map(|(id, entry)| entry.is_none().then_some(id))
            .collect();

        if !missing.is_empty() {
            panic!("missing constraint ids: {missing:?}");
        }
    }

    fn record(&mut self, tag: TagRecord) {
        tag.validate(&mut self.used, self.records.len());
        self.records.push(tag);
    }
}

impl<AB> Drop for TaggedAirBuilder<AB> {
    fn drop(&mut self) {
        state::set_enabled(self.prev_enabled);
    }
}

impl<AB> MidenAirBuilder for TaggedAirBuilder<AB>
where
    AB: MidenAirBuilder,
{
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type M = AB::M;
    type PublicVar = AB::PublicVar;
    type PeriodicVal = AB::PeriodicVal;
    type EF = AB::EF;
    type ExprEF = AB::ExprEF;
    type VarEF = AB::VarEF;
    type MP = AB::MP;
    type RandomVar = AB::RandomVar;

    fn main(&self) -> Self::M {
        self.inner.main()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let tag = state::consume_tag();
        self.record(tag);
        self.inner.assert_zero(x);
    }

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        let tag = state::consume_tag();
        self.record(tag);
        self.inner.assert_zero_ext(x);
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }

    fn periodic_evals(&self) -> &[Self::PeriodicVal] {
        self.inner.periodic_evals()
    }

    fn preprocessed(&self) -> Self::M {
        self.inner.preprocessed()
    }

    fn permutation(&self) -> Self::MP {
        self.inner.permutation()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        self.inner.permutation_randomness()
    }

    fn aux_bus_boundary_values(&self) -> &[Self::VarEF] {
        self.inner.aux_bus_boundary_values()
    }
}
