//! Main-trace LogUp lookup AIR.
//!
//! Owns the main-trace side of the Miden VM's LogUp argument: four lookup columns, one
//! per `emit_*` function in [`super::buses`]. This module wires them together via a single
//! [`MainBusContext`] that carries the two-row window plus a shared [`LookupOpFlags`] instance.
//!
//! Columns (in emission order):
//! - block-stack table + u32 and Merkle-depth range checks + log-deferred capacity + range-table
//!   response (merged — see [`super::buses::block_stack_and_range_logcap`]).
//! - block-hash queue + op-group table.
//! - chiplet requests from the decoder + U32DIV remainder-bound range checks.
//! - stack overflow table.
//!
//! The [`NativeMainLookupBuilder`] hook lets flag construction diverge
//! between the constraint path (polynomial, the default body) and the prover path (boolean fast
//! path). The constraint and debug adapters use the default body; the prover adapter overrides the
//! hook in [`super::extension_impls`].

use core::borrow::Borrow;

use miden_stark::lookup;

use super::{
    BusId,
    buses::{
        LookupOpFlags,
        block_hash_and_op_group::{self, emit_block_hash_and_op_group},
        block_stack_and_range_logcap::{self, emit_block_stack_and_range_logcap},
        chiplet_requests::{self, emit_chiplet_requests},
        stack_overflow::{self, emit_stack_overflow},
    },
};
use crate::vm::{CoreCols, Felt, constraints::columns::NUM_CORE_COLS};

// NATIVE MAIN LOOKUP BUILDER
// ================================================================================================

/// Source-specific flag construction over independently borrowed expression rows.
///
/// Implement adapters explicitly: a blanket implementation would prevent the concrete prover
/// adapter from selecting its boolean opcode fast path.
pub(crate) trait NativeMainLookupBuilder: lookup::LookupBuilder<F = Felt> {
    fn build_op_flags(
        &self,
        local: &CoreCols<Self::Expr>,
        next: &CoreCols<Self::Expr>,
    ) -> LookupOpFlags<Self::Expr> {
        LookupOpFlags::from_main_cols(&local.decoder, &local.stack, &next.decoder)
    }
}

// MAIN BUS CONTEXT
// ================================================================================================

/// Immutable expression rows and one owned flag polynomial for the four main-trace emitters.
pub(crate) struct MainBusContext<'a, E> {
    pub local: &'a CoreCols<E>,
    pub next: &'a CoreCols<E>,
    pub op_flags: LookupOpFlags<E>,
}

impl<'a, E> MainBusContext<'a, E> {
    fn new<LB>(builder: &LB, local: &'a CoreCols<E>, next: &'a CoreCols<E>) -> Self
    where
        LB: NativeMainLookupBuilder<Expr = E>,
    {
        let op_flags = builder.build_op_flags(local, next);
        Self { local, next, op_flags }
    }
}

// MAIN LOOKUP AIR
// ================================================================================================

/// LogUp lookup argument over the main trace.
///
/// Zero-sized. Emits four permutation columns: the first packs block-stack + u32 and Merkle-depth
/// range checks + log-deferred capacity + range-table response; the second unions block-hash queue
/// and op-group table; the third hosts the decoder's chiplet requests and U32DIV remainder-bound
/// range checks; the fourth hosts the stack overflow table. The chiplet-trace half of the argument
/// lives in [`super::chiplet_air::ChipletLookupAir`].
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct MainLookupAir;

/// Per-column fraction stride, in emission order (see [`MainLookupAir`] docs).
pub(crate) const MAIN_COLUMN_SHAPE: [usize; 4] = [
    block_stack_and_range_logcap::MAX_INTERACTIONS_PER_ROW,
    block_hash_and_op_group::MAX_INTERACTIONS_PER_ROW,
    chiplet_requests::MAX_INTERACTIONS_PER_ROW,
    stack_overflow::MAX_INTERACTIONS_PER_ROW,
];

impl<LB> lookup::LookupAir<LB> for MainLookupAir
where
    LB: NativeMainLookupBuilder,
{
    fn column_shape(&self) -> &[usize] {
        &MAIN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // All VM LookupAir implementations share this width so they use the same bus prefixes.
        super::messages::MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        // Main-trace emitters touch `BusId::{BlockStackTable, BlockHashTable, OpGroupTable,
        // RangeCheck, LogDeferredRoot}` plus the buses used by the shared chiplet-requests column.
        // The adapter's bus-prefix table is shared across every LookupAir it runs, so
        // returning `BusId::COUNT` (the total bus-type count) is the safe upper bound.
        BusId::COUNT
    }

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        // Combined-trace readers may supply wider rows; Core owns its leading columns.
        let local: &CoreCols<_> = frame.main.current[..NUM_CORE_COLS].borrow();
        let next: &CoreCols<_> = frame.main.next[..NUM_CORE_COLS].borrow();

        let ctx = MainBusContext::new(&*builder, local, next);

        emit_block_stack_and_range_logcap::<LB>(builder, &ctx);
        emit_block_hash_and_op_group::<LB>(builder, &ctx);
        emit_chiplet_requests::<LB>(builder, &ctx);
        emit_stack_overflow::<LB>(builder, &ctx);
    }
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
        operations::opcodes,
    };
    use miden_stark::{
        air::Rows,
        lookup::{self, Challenges, Deg, LookupFractions, ProverLookupBuilder},
    };

    use super::{MAIN_COLUMN_SHAPE, MainLookupAir, NativeMainLookupBuilder};
    use crate::vm::{
        CoreCols,
        constraints::{
            lookup::{BusId, buses::LookupOpFlags, messages::MIDEN_MAX_MESSAGE_WIDTH},
            op_flags::generate_test_row,
        },
    };

    /// Test-only custom native hook over the real scalar collector. Its row checks distinguish
    /// current from next and its counter detects accidental default-polynomial dispatch.
    struct HookProbe<'a> {
        inner: ProverLookupBuilder<'a, Felt, QuadFelt>,
        calls: Cell<usize>,
    }

    impl<'a> lookup::LookupBuilder for HookProbe<'a> {
        type F = Felt;
        type Expr = Felt;
        type ExprEF = QuadFelt;
        type Column<'b>
            = <ProverLookupBuilder<'a, Felt, QuadFelt> as lookup::LookupBuilder>::Column<'b>
        where
            Self: 'b;

        fn next_column<'b, R>(
            &'b mut self,
            f: impl FnOnce(&mut Self::Column<'b>) -> R,
            deg: Deg,
        ) -> R {
            lookup::LookupBuilder::next_column(&mut self.inner, f, deg)
        }
    }

    impl NativeMainLookupBuilder for HookProbe<'_> {
        fn build_op_flags(
            &self,
            local: &CoreCols<Felt>,
            next: &CoreCols<Felt>,
        ) -> LookupOpFlags<Felt> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(local.system.clk, Felt::from_u32(19));
            assert_eq!(next.system.clk, Felt::from_u32(41));
            let flags =
                LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder);
            assert_eq!(flags.push(), Felt::ONE);
            assert_eq!(flags.end_next(), Felt::ONE);
            flags
        }
    }

    #[test]
    fn native_hook_runs_once_on_the_original_row_pair() {
        let mut local = generate_test_row(opcodes::PUSH.into());
        let mut next = generate_test_row(opcodes::END.into());
        local.system.clk = Felt::from_u32(19);
        next.system.clk = Felt::from_u32(41);
        // MainLookupAir also accepts combined-trace readers. Its Core prefix and hook
        // must keep working even when the row contains additional unrelated columns.
        let mut current = local.as_slice().to_vec();
        let mut following = next.as_slice().to_vec();
        current.extend([Felt::from_u32(101), Felt::from_u32(103)]);
        following.extend([Felt::from_u32(107), Felt::from_u32(109)]);
        let challenges = Challenges::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );
        let mut fractions = LookupFractions::from_shape(MAIN_COLUMN_SHAPE.to_vec(), 1);
        {
            let frame = lookup::LookupFrame {
                main: Rows { current: &current, next: &following },
                preprocessed: Rows { current: &[], next: &[] },
                periodic: &[],
            };
            let inner = ProverLookupBuilder::new(&challenges, &MAIN_COLUMN_SHAPE, &mut fractions);
            let mut builder = HookProbe { inner, calls: Cell::new(0) };
            lookup::LookupAir::eval(&MainLookupAir, &frame, &mut builder);
            assert_eq!(builder.calls.get(), 1);
        }
        assert_eq!(fractions.counts().len(), MAIN_COLUMN_SHAPE.len());
    }
}
