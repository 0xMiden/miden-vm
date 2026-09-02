use alloc::vec;

use miden_air::trace::and8_lookup::{BYTE_LOOKUP_COUNT_LEN, RANGE_CHECK_COUNT_OFFSET};

use super::RangeChecker;

// TESTS
// ================================================================================================

#[test]
fn range_checks_are_counted_by_value() {
    let mut checker = RangeChecker::new();

    for value in [0, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 100, 355, 620] {
        checker.add_value(value);
    }

    assert_eq!(checker.count(0), 1);
    assert_eq!(checker.count(1), 1);
    assert_eq!(checker.count(2), 4);
    assert_eq!(checker.count(3), 3);
    assert_eq!(checker.count(4), 2);
    assert_eq!(checker.count(100), 1);
    assert_eq!(checker.count(355), 1);
    assert_eq!(checker.count(620), 1);
    assert_eq!(checker.count(u16::MAX), 0);
}

#[test]
fn range_checks_write_to_byte_pair_count_region() {
    let mut checker = RangeChecker::new();
    for value in [0, 1, 255, 256, 256, u16::MAX] {
        checker.add_value(value);
    }

    let mut counts = vec![0u64; BYTE_LOOKUP_COUNT_LEN];
    checker.write_range_counts(&mut counts);

    assert_eq!(counts[RANGE_CHECK_COUNT_OFFSET], 1);
    assert_eq!(counts[RANGE_CHECK_COUNT_OFFSET + 1], 1);
    assert_eq!(counts[RANGE_CHECK_COUNT_OFFSET + 255], 1);
    assert_eq!(counts[RANGE_CHECK_COUNT_OFFSET + 256], 2);
    assert_eq!(counts[RANGE_CHECK_COUNT_OFFSET + usize::from(u16::MAX)], 1);
}

#[test]
fn add_range_checks_counts_stack_or_memory_batches() {
    let mut checker = RangeChecker::new();
    checker.add_range_checks(&[7, 8]);
    checker.add_range_checks(&[7, 9, 10, 10]);

    assert_eq!(checker.count(7), 2);
    assert_eq!(checker.count(8), 1);
    assert_eq!(checker.count(9), 1);
    assert_eq!(checker.count(10), 2);
}
