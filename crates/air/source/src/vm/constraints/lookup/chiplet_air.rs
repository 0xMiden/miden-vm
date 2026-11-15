//! Chiplet-trace LogUp lookup AIR.
//!
//! Owns the chiplet-trace side of the Miden VM's LogUp argument: four lookup columns, one
//! per `emit_*` function in [`super::buses`]. This module wires them together
//! via a single [`ChipletBusContext`] that carries the two-row window plus a shared
//! [`ChipletActiveFlags`] snapshot.
//!
//! Columns (in emission order):
//! - chiplet responses (memory / bitwise / hasher replies).
//! - hash-kernel virtual table.
//! - shared wiring column: ACE wiring + hasher compression link.
//! - four-Felt hasher result and chaining-value returns.
//!
//! [`ChipletLookupBuilder`] builds the shared active flags from the chiplet selector columns.
//! Adapters may override the default construction while preserving those flag semantics.

use core::borrow::Borrow;

use miden_stark::lookup::{LookupBuilder, native};

use super::buses::{
    chiplet_responses::{self, emit_chiplet_responses},
    hash_kernel::{self, emit_hash_kernel_table},
    hasher_returns::{self, emit_hasher_returns},
    wiring::{self, emit_v_wiring},
};
use crate::vm::{
    ChipletCols, Felt,
    constraints::chiplets::{columns::PeriodicCols, selectors::ChipletActiveFlags},
};

// CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Extension trait the chiplet-trace [`LookupAir`] requires from its [`LookupBuilder`].
///
/// Carries a single hook, [`build_chiplet_active`](Self::build_chiplet_active), for
/// constructing the shared [`ChipletActiveFlags`] snapshot consumed by the four
/// chiplet-trace bus emitters. Symmetric to [`super::main_air::MainLookupBuilder`]; see its
/// docs for the rationale behind the explicit-impl-no-blanket pattern.
pub(crate) trait ChipletLookupBuilder: LookupBuilder<F = Felt> {
    /// Build the shared [`ChipletActiveFlags`] snapshot for one `eval` call.
    ///
    /// Default body calls [`ChipletActiveFlags::from_chiplet_cols`] against the multi-AIR
    /// `ChipletCols` view. Adapters can override this when a cheaper construction path is
    /// worthwhile.
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Var>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// NATIVE CHIPLET LOOKUP BUILDER
// ================================================================================================

/// Activity construction over immutable expression rows. Explicit adapter implementations preserve
/// the source-specific override seam; the concrete prover uses the same polynomial default.
pub(crate) trait NativeChipletLookupBuilder: native::LookupBuilder<F = Felt> {
    fn build_chiplet_active(
        &self,
        local: &ChipletCols<Self::Expr>,
    ) -> ChipletActiveFlags<Self::Expr> {
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

// CHIPLET BUS CONTEXT
// ================================================================================================

/// Borrowed expression inputs and one owned activity snapshot for the four chiplet columns.
pub(crate) struct ChipletBusContext<'a, E> {
    pub local: &'a ChipletCols<E>,
    pub next: &'a ChipletCols<E>,
    pub periodic: &'a PeriodicCols<E>,
    pub chiplet_active: ChipletActiveFlags<E>,
}

impl<'a, E> ChipletBusContext<'a, E> {
    fn new<LB>(
        builder: &LB,
        local: &'a ChipletCols<E>,
        next: &'a ChipletCols<E>,
        periodic: &'a PeriodicCols<E>,
    ) -> Self
    where
        LB: NativeChipletLookupBuilder<Expr = E>,
    {
        let chiplet_active = builder.build_chiplet_active(local);
        Self { local, next, periodic, chiplet_active }
    }
}

// CHIPLET LOOKUP COLUMNS
// ================================================================================================

/// Per-column fraction stride, in emission order (see [`emit_chiplet_lookup_columns`]).
pub(crate) const CHIPLET_COLUMN_SHAPE: [usize; 4] = [
    chiplet_responses::MAX_INTERACTIONS_PER_ROW,
    hash_kernel::MAX_INTERACTIONS_PER_ROW,
    wiring::MAX_INTERACTIONS_PER_ROW,
    hasher_returns::MAX_INTERACTIONS_PER_ROW,
];

/// Emit the chiplet-trace LogUp columns.
///
/// Driven by `ChipletsAir`'s [`LookupAir`] impl.
pub(crate) fn emit_chiplet_lookup_columns<LB: NativeChipletLookupBuilder>(
    frame: &native::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
) {
    let local: &ChipletCols<_> = frame.main.current.borrow();
    let next: &ChipletCols<_> = frame.main.next.borrow();
    let periodic: &PeriodicCols<_> = frame.periodic.borrow();
    let ctx = ChipletBusContext::new(&*builder, local, next, periodic);
    emit_chiplet_responses::<LB>(builder, &ctx);
    emit_hash_kernel_table::<LB>(builder, &ctx);
    emit_v_wiring::<LB>(builder, &ctx);
    emit_hasher_returns::<LB>(builder, &ctx);
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_stark::{
        air::{RowWindow, WindowAccess},
        lookup::{Challenges, Deg, LookupBuilder, LookupFractions, ProverLookupBuilder},
    };

    use super::{CHIPLET_COLUMN_SHAPE, ChipletLookupBuilder};
    use crate::vm::{
        ChipletCols, ChipletsAir, MidenAir,
        constraints::chiplets::{columns::PeriodicCols, selectors::ChipletActiveFlags},
        logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
        trace::CHIPLETS_WIDTH,
    };

    /// A concrete old adapter override, retaining the real scalar column callbacks.
    struct HookProbe<'a> {
        inner: ProverLookupBuilder<'a, Felt, QuadFelt>,
        calls: Cell<usize>,
    }

    impl<'a> LookupBuilder for HookProbe<'a> {
        type F = Felt;
        type Expr = Felt;
        type Var = Felt;
        type EF = QuadFelt;
        type ExprEF = QuadFelt;
        type VarEF = QuadFelt;
        type PeriodicVar = Felt;
        type MainWindow = RowWindow<'a, Felt>;
        type PreprocessedWindow = RowWindow<'a, Felt>;
        type Column<'b>
            = <ProverLookupBuilder<'a, Felt, QuadFelt> as LookupBuilder>::Column<'b>
        where
            Self: 'b;

        fn main(&self) -> Self::MainWindow {
            LookupBuilder::main(&self.inner)
        }
        fn preprocessed(&self) -> &Self::PreprocessedWindow {
            LookupBuilder::preprocessed(&self.inner)
        }
        fn periodic_values(&self) -> &[Felt] {
            LookupBuilder::periodic_values(&self.inner)
        }
        fn next_column<'b, R>(
            &'b mut self,
            f: impl FnOnce(&mut Self::Column<'b>) -> R,
            deg: Deg,
        ) -> R {
            LookupBuilder::next_column(&mut self.inner, f, deg)
        }
    }

    impl ChipletLookupBuilder for HookProbe<'_> {
        fn build_chiplet_active(&self, local: &ChipletCols<Felt>) -> ChipletActiveFlags<Felt> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(local.controller_cols().addr, Felt::from_u32(19));
            let window = LookupBuilder::main(&self.inner);
            assert_eq!(window.next_slice()[23], Felt::from_u32(41));
            ChipletActiveFlags::from_chiplet_cols(local)
        }
    }

    #[test]
    fn legacy_chiplet_override_receives_the_stable_current_next_pair_once() {
        let mut current = [Felt::ZERO; CHIPLETS_WIDTH];
        let mut next = current;
        current[23] = Felt::from_u32(19);
        next[23] = Felt::from_u32(41);
        let periodic: alloc::vec::Vec<_> =
            PeriodicCols::periodic_columns().iter().map(|column| column[0]).collect();
        let challenges = Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );
        let mut fractions = LookupFractions::from_shape(CHIPLET_COLUMN_SHAPE.to_vec(), 1);
        {
            let inner = ProverLookupBuilder::new(
                RowWindow::from_two_rows(&current, &next),
                RowWindow::from_two_rows(&[], &[]),
                &periodic,
                &challenges,
                &MidenAir::Chiplets,
                &mut fractions,
            );
            let mut builder = HookProbe { inner, calls: Cell::new(0) };
            miden_stark::air::native::migration::eval_lookup(&ChipletsAir, &mut builder, 0);
            assert_eq!(builder.calls.get(), 1);
        }
        assert_eq!(fractions.counts().len(), CHIPLET_COLUMN_SHAPE.len());
    }
}
