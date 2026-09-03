use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::{Matrix, RowMajorMatrix},
};

use super::{AUX_WIDTH, MUL_COL_OFFSET, NUM_MAIN_COLS, UintStoreMulAir};
use crate::{
    logup::build_logup_aux_trace,
    uint::{StoreRegisters, mul::MulRegisters},
};

pub(crate) fn build_aux(
    main: &RowMajorMatrix<Felt>,
    challenges: &[QuadFelt],
) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
    let (logup, sigma) = build_logup_aux_trace(&UintStoreMulAir, main, challenges);
    let logup_width = logup.width();
    let n = main.height();
    let beta = challenges[1];

    let store = StoreRegisters::new(beta, NUM_MAIN_COLS, 0);
    let mut mul = MulRegisters::new(beta, NUM_MAIN_COLS, MUL_COL_OFFSET);

    let mut data = Vec::with_capacity(AUX_WIDTH * n);
    let mut store_id = QuadFelt::ZERO;
    let mut mul_id = QuadFelt::ZERO;
    for r in 0..n {
        data.extend((0..logup_width).map(|c| logup.values[r * logup_width + c]));
        data.push(store_id);
        data.push(mul_id);
        data.push(mul.s());

        store_id += store.contrib(main, r);
        mul_id += mul.step(main, r);
    }

    (RowMajorMatrix::new(data, AUX_WIDTH), sigma)
}
