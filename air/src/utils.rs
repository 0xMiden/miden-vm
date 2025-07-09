use alloc::vec::Vec;
use core::ops::Range;

use miden_core::utils::range as create_range;

use super::FieldElement;

// BASIC CONSTRAINT OPERATORS
// ================================================================================================

/// Returns zero only when a == b.
pub fn are_equal<E: FieldElement>(a: E, b: E) -> E {
    a - b
}

#[inline(always)]
pub fn is_binary<E: FieldElement>(v: E) -> E {
    v.square() - v
}

#[inline(always)]
pub fn binary_not<E: FieldElement>(v: E) -> E {
    E::ONE - v
}

#[inline(always)]
pub fn is_zero<E: FieldElement>(v: E) -> E {
    v
}

// TRAIT TO SIMPLIFY CONSTRAINT AGGREGATION
// ================================================================================================

pub trait EvaluationResult<E: FieldElement> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E);
}

impl<E: FieldElement> EvaluationResult<E> for [E] {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

impl<E: FieldElement> EvaluationResult<E> for Vec<E> {
    fn agg_constraint(&mut self, index: usize, flag: E, value: E) {
        self[index] += flag * value;
    }
}

// TRANSITION CONSTRAINT RANGE
// ================================================================================================

/// Manages the starting index and length of transition constraints for individual processors so
/// indices can be handled easily during transition evaluation.
#[derive(Debug)]
pub struct TransitionConstraintRange {
    pub(super) stack: Range<usize>,
    pub(super) range_checker: Range<usize>,
    pub(super) chiplets: Range<usize>,
}

impl TransitionConstraintRange {
    pub fn new(
        sys: usize,
        stack_len: usize,
        range_checker_len: usize,
        chiplets_len: usize,
    ) -> Self {
        let stack = create_range(sys, stack_len);
        let range_checker = create_range(stack.end, range_checker_len);
        let chiplets = create_range(range_checker.end, chiplets_len);

        Self { stack, range_checker, chiplets }
    }
}

// MACRO TO SIMPLIFY RANGE HANDLING
// ================================================================================================
/// Select an array range from a mutable result array and a specified range.
#[macro_export]
macro_rules! select_result_range {
    ($result:expr, $range:expr) => {
        &mut $result[$range.start..$range.end]
    };
}

// TESTS
// ================================================================================================
#[cfg(test)]
mod tests {
    use miden_core::utils::range as create_range;

    use super::TransitionConstraintRange;

    #[test]
    fn transition_constraint_ranges() {
        let sys_constraints_len = 1;
        let stack_constraints_len = 2;
        let range_constraints_len = 3;
        let aux_constraints_len = 4;

        let constraint_ranges = TransitionConstraintRange::new(
            sys_constraints_len,
            stack_constraints_len,
            range_constraints_len,
            aux_constraints_len,
        );

        assert_eq!(constraint_ranges.stack.start, sys_constraints_len);
        assert_eq!(constraint_ranges.stack.end, sys_constraints_len + stack_constraints_len);
        assert_eq!(
            constraint_ranges.range_checker.start,
            sys_constraints_len + stack_constraints_len
        );
        assert_eq!(
            constraint_ranges.range_checker.end,
            sys_constraints_len + stack_constraints_len + range_constraints_len
        );
        assert_eq!(
            constraint_ranges.chiplets.start,
            sys_constraints_len + stack_constraints_len + range_constraints_len
        );
        assert_eq!(
            constraint_ranges.chiplets.end,
            sys_constraints_len
                + stack_constraints_len
                + range_constraints_len
                + aux_constraints_len
        );
    }

    #[test]
    fn result_range() {
        let mut result: [u64; 6] = [1, 2, 3, 4, 5, 6];

        // Select the beginning.
        let range = create_range(0, 3);
        let selected_range = select_result_range!(&mut result, range);
        assert_eq!(selected_range, [1, 2, 3]);

        // Select the middle.
        let range = create_range(1, 2);
        let selected_range = select_result_range!(&mut result, range);
        assert_eq!(selected_range, [2, 3]);

        // Select the end.
        let range = create_range(5, 1);
        let selected_range = select_result_range!(&mut result, range);
        assert_eq!(selected_range, [6]);
    }
}
