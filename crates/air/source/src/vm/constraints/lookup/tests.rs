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

use super::{
    BusId, MIDEN_MAX_MESSAGE_WIDTH,
    buses::LookupOpFlags,
    chiplet_air::{CHIPLET_COLUMN_SHAPE, NativeChipletLookupBuilder},
    main_air::{MAIN_COLUMN_SHAPE, MainLookupAir, NativeMainLookupBuilder},
};
use crate::vm::{
    ChipletCols, ChipletsAir, CoreCols,
    constraints::{
        chiplets::{columns::PeriodicCols, selectors::ChipletActiveFlags},
        op_flags::generate_test_row,
    },
    trace::CHIPLETS_WIDTH,
};

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

    fn next_column<'b, R>(&'b mut self, f: impl FnOnce(&mut Self::Column<'b>) -> R, deg: Deg) -> R {
        lookup::LookupBuilder::next_column(&mut self.inner, f, deg)
    }
}

impl NativeMainLookupBuilder for HookProbe<'_> {
    fn build_op_flags(&self, local: &CoreCols<Felt>, next: &CoreCols<Felt>) -> LookupOpFlags<Felt> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(local.system.clk, Felt::from_u32(19));
        assert_eq!(next.system.clk, Felt::from_u32(41));
        let flags = LookupOpFlags::from_boolean_row(&local.decoder, &local.stack, &next.decoder);
        assert_eq!(flags.push(), Felt::ONE);
        assert_eq!(flags.end_next(), Felt::ONE);
        flags
    }
}

impl NativeChipletLookupBuilder for HookProbe<'_> {
    fn build_chiplet_active(&self, local: &ChipletCols<Felt>) -> ChipletActiveFlags<Felt> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(local.controller_cols().addr, Felt::from_u32(19));
        ChipletActiveFlags::from_chiplet_cols(local)
    }
}

fn assert_hook_called_once<A>(
    air: A,
    shape: &[usize],
    current: &[Felt],
    next: &[Felt],
    periodic: &[Felt],
) where
    for<'a> A: lookup::LookupAir<HookProbe<'a>>,
{
    let frame = lookup::LookupFrame {
        main: Rows { current, next },
        preprocessed: Rows { current: &[], next: &[] },
        periodic,
    };
    let challenges = Challenges::new(
        QuadFelt::from_u32(7),
        QuadFelt::from_u32(11),
        MIDEN_MAX_MESSAGE_WIDTH,
        BusId::COUNT,
    );
    let mut fractions = LookupFractions::from_shape(shape.to_vec(), 1);
    let inner = ProverLookupBuilder::new(&challenges, shape, &mut fractions);
    let mut builder = HookProbe { inner, calls: Cell::new(0) };
    lookup::LookupAir::eval(&air, &frame, &mut builder);
    assert_eq!(builder.calls.get(), 1);
}

#[test]
fn vm_lookup_hooks_receive_the_authored_rows_once() {
    let mut local = generate_test_row(opcodes::PUSH.into());
    let mut next = generate_test_row(opcodes::END.into());
    local.system.clk = Felt::from_u32(19);
    next.system.clk = Felt::from_u32(41);
    // Exercise the Core prefix and hook with additional columns from a combined row.
    let current = [local.as_slice(), &[Felt::from_u32(101), Felt::from_u32(103)]].concat();
    let following = [next.as_slice(), &[Felt::from_u32(107), Felt::from_u32(109)]].concat();
    assert_hook_called_once(MainLookupAir, &MAIN_COLUMN_SHAPE, &current, &following, &[]);

    let mut current = [Felt::ZERO; CHIPLETS_WIDTH];
    let mut next = current;
    current[23] = Felt::from_u32(19);
    next[23] = Felt::from_u32(41);
    let periodic: alloc::vec::Vec<_> =
        PeriodicCols::periodic_columns().iter().map(|column| column[0]).collect();
    assert_hook_called_once(ChipletsAir, &CHIPLET_COLUMN_SHAPE, &current, &next, &periodic);
}
