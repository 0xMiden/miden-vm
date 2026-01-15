use alloc::{collections::BTreeMap, vec::Vec};

use miden_core::utils::ToElements;
use miden_utils_testing::rand::rand_array;

use super::{Felt, RangeChecker, ZERO};
use crate::{PrimeField64, RangeCheckTrace};

#[test]
fn range_checks() {
    let mut checker = RangeChecker::new();

    let values = [0, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 100, 355, 620].to_elements();

    for &value in values.iter() {
        // add the value to the range checker's trace
        checker.add_value(value.as_canonical_u64() as u16);
    }

    let RangeCheckTrace { trace, aux_builder: _ } = checker.into_trace(64);
    validate_trace(&trace, &values);

    // skip the padded rows
    let mut i = 0;
    while trace[0][i] == ZERO && trace[1][i] == ZERO {
        i += 1;
    }

    // make sure the values are arranged as expected
    validate_row(&trace, &mut i, 0, 1);
    validate_row(&trace, &mut i, 1, 1);
    validate_row(&trace, &mut i, 2, 4);
    validate_row(&trace, &mut i, 3, 3);
    validate_row(&trace, &mut i, 4, 2);

    validate_bridge_rows(&trace, &mut i, 4, 100);

    validate_row(&trace, &mut i, 100, 1);

    validate_bridge_rows(&trace, &mut i, 100, 355);

    validate_row(&trace, &mut i, 355, 1);

    validate_bridge_rows(&trace, &mut i, 355, 620);

    validate_row(&trace, &mut i, 620, 1);
}

#[test]
fn range_checks_rand() {
    let mut checker = RangeChecker::new();
    let values = rand_array::<u64, 300>();
    let values = values.into_iter().map(|v| Felt::new(v as u16 as u64)).collect::<Vec<_>>();
    for &value in values.iter() {
        checker.add_value(value.as_canonical_u64() as u16);
    }

    let trace_len = checker.trace_len().next_power_of_two();
    let RangeCheckTrace { trace, aux_builder: _ } = checker.into_trace(trace_len);
    validate_trace(&trace, &values);
}

// HELPER FUNCTIONS
// ================================================================================================

fn validate_row(trace: &[Vec<Felt>], row_idx: &mut usize, value: u64, num_lookups: u64) {
    assert_eq!(trace[0][*row_idx], Felt::new(num_lookups));
    assert_eq!(trace[1][*row_idx], Felt::new(value));
    *row_idx += 1;
}

fn validate_trace(trace: &[Vec<Felt>], lookups: &[Felt]) {
    assert_eq!(2, trace.len());

    // trace length must be a power of two
    let trace_len = trace[0].len();
    assert!(trace_len.is_power_of_two());

    // --- validate the trace ---------------------------
    let mut i = 0;
    let mut lookups_16bit = BTreeMap::new();

    // process the first row
    assert_eq!(trace[1][i], ZERO);
    let count = trace[0][i].as_canonical_u64();
    lookups_16bit.insert(0u16, count);
    i += 1;

    // process all other rows
    let mut prev_value = 0u16;
    while i < trace_len {
        // make sure the value is a 16-bit value
        let value = trace[1][i].as_canonical_u64();
        assert!(value <= 65535, "not a 16-bit value");
        let value = value as u16;

        // make sure the delta between this and the previous value is 0 or a power of 3 and at most
        // 3^7
        let delta = value - prev_value;
        assert!(valid_delta(delta));

        // keep track of lookup count for each value
        let multiplicity = trace[0][i].as_canonical_u64();
        lookups_16bit
            .entry(value)
            .and_modify(|count| *count += multiplicity)
            .or_insert(multiplicity);

        i += 1;
        prev_value = value;
    }

    // validate the last row (must be 65535)
    let last_value = trace[1][i - 1].as_canonical_u64();
    assert_eq!(65535, last_value);

    // remove all the looked up values from the lookup table
    for value in lookups {
        let value = value.as_canonical_u64();
        assert!(value <= 65535, "not a 16-bit value");
        let value = value as u16;

        assert!(lookups_16bit.contains_key(&value));
        lookups_16bit.entry(value).and_modify(|count| {
            assert!(*count > 0);
            *count -= 1;
        });
    }

    // make sure 16-bit table is empty
    for &value in lookups_16bit.values() {
        assert_eq!(0, value);
    }
}

fn validate_bridge_rows(
    trace: &[Vec<Felt>],
    row_idx: &mut usize,
    curr_value: u64,
    next_value: u64,
) {
    let mut gap = next_value - curr_value;
    let mut bridge_val = curr_value;
    let mut stride = 3_u64.pow(7);
    while gap != stride {
        if gap > stride {
            gap -= stride;
            bridge_val += stride;
            validate_row(trace, row_idx, bridge_val, 0);
        } else {
            stride /= 3;
        }
    }
}

/// Checks if the delta between two values is 0 or a power of 3 and at most 3^7
fn valid_delta(delta: u16) -> bool {
    delta == 0 || (59049_u16.is_multiple_of(delta) && delta <= 2187)
}
