use alloc::vec::Vec;

use miden_air::trace::{AUX_TRACE_RAND_ELEMENTS, STACK_AUX_TRACE_OFFSET};
use miden_core::field::Field;

use super::{Felt, ONE, Operation, ZERO, build_trace_from_ops, rand_array};
use crate::stack::OverflowTableRow;

// CONSTANTS
// ================================================================================================

const P1_COL_IDX: usize = STACK_AUX_TRACE_OFFSET;
const TWO: Felt = Felt::new(2);

// OVERFLOW TABLE TESTS
// ================================================================================================

#[test]
#[expect(clippy::needless_range_loop)]
fn p1_trace() {
    let ops = vec![
        Operation::U32add, // no shift, clk 1
        Operation::Pad,    // right shift, clk 2
        Operation::Pad,    // right shift, clk 3
        Operation::U32add, // no shift, clk 4
        Operation::Drop,   // left shift, clk 5
        Operation::Pad,    // right shift, clk 6
        Operation::Drop,   // left shift, clk 7
        Operation::Drop,   // left shift, clk 8
        Operation::Drop,   // left shift, clk 9
        Operation::Pad,    // right shift, clk 10
        Operation::Drop,   // left shift, clk 11
    ];
    let init_stack = (1..17).collect::<Vec<_>>();
    let trace = build_trace_from_ops(ops, &init_stack);
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let row_values = [
        OverflowTableRow::new(Felt::new(2), ONE, ZERO).to_value(&alphas),
        OverflowTableRow::new(Felt::new(3), TWO, TWO).to_value(&alphas),
        OverflowTableRow::new(Felt::new(6), TWO, TWO).to_value(&alphas),
        OverflowTableRow::new(Felt::new(10), ZERO, ZERO).to_value(&alphas),
    ];

    // make sure the first entry is ONE
    let mut expected_value = ONE;
    assert_eq!(expected_value, p1[0]);

    // SPAN and U32ADD do not affect the overflow table
    assert_eq!(expected_value, p1[1]);
    assert_eq!(expected_value, p1[2]);

    // two PADs push values 1 and 2 onto the overflow table
    expected_value *= row_values[0];
    assert_eq!(expected_value, p1[3]);
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[4]);

    // U32ADD does not affect the overflow table
    assert_eq!(expected_value, p1[5]);

    // DROP removes a row from the overflow table
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[6]);

    // PAD pushes the value onto the overflow table again
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[7]);

    // two DROPs remove both values from the overflow table
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p1[8]);
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[9]);

    // at this point the table should be empty
    assert_eq!(expected_value, ONE);

    // the 3rd DROP should not affect the overflow table as it is already empty
    assert_eq!(expected_value, p1[10]);

    // PAD pushes the value (ZERO) onto the overflow table again
    expected_value *= row_values[3];
    assert_eq!(expected_value, p1[11]);

    // and then the last DROP removes it from the overflow table
    expected_value *= row_values[3].inverse();
    assert_eq!(expected_value, p1[12]);

    // at this point the table should be empty again, and it should stay empty until the end
    assert_eq!(expected_value, ONE);
    for i in 13..(p1.len()) {
        assert_eq!(ONE, p1[i]);
    }
}
