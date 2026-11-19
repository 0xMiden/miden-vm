use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
};
use miden_stark::air::AirBuilder;

use crate::vm::{MidenAirBuilder, constraints::utils::BoolNot};

/// Polynomial selectors derived from the two-column operation-batch encoding.
pub(crate) struct OpBatchSelectors<E> {
    pub groups_8: E,
    pub groups_4: E,
    pub groups_2: E,
    code_sq: E,
}

impl<E> OpBatchSelectors<E>
where
    E: Algebra<Felt>,
{
    pub fn new(full_batch: E, batch_size_code: E) -> Self {
        let code_sq = batch_size_code.square();
        let half = Felt::ONE.halve();
        let groups_4 = (code_sq.clone() + batch_size_code.clone()) * half;
        let groups_2 = (code_sq.clone() - batch_size_code) * half;
        Self {
            groups_8: full_batch,
            groups_4,
            groups_2,
            code_sq,
        }
    }

    /// Returns the 1-group selector. Active 1-group and inactive rows both encode as `(0, 0)`,
    /// so the constrained SPAN/RESPAN selector supplies the missing context.
    pub fn groups_1(&self, span_or_respan: E) -> E {
        span_or_respan - self.groups_8.clone() - self.code_sq.clone()
    }
}

/// Enforces the operation-batch encoding, zeroes hasher lanes unused by short batches, and requires
/// a short batch to be the last batch of its basic block.
pub(super) fn enforce<AB>(
    builder: &mut AB,
    span_or_respan: AB::Expr,
    full_batch: AB::Var,
    batch_size_code: AB::Var,
    group_count: AB::Var,
    hasher_state: &[AB::Var; 8],
) where
    AB: MidenAirBuilder,
{
    builder.assert_bool(full_batch);
    builder.assert_zero(
        batch_size_code * (batch_size_code - AB::Expr::ONE) * (batch_size_code + AB::Expr::ONE),
    );
    builder.assert_zero(full_batch * batch_size_code);

    // Pin each committed value directly on rows where the encoding is inactive.
    {
        let builder = &mut builder.when(span_or_respan.not());
        builder.assert_zero(full_batch);
        builder.assert_zero(batch_size_code);
    }

    let selectors = OpBatchSelectors::new(full_batch.into(), batch_size_code.into());
    let groups_1 = selectors.groups_1(span_or_respan.clone());
    let groups_1_or_2 = groups_1.clone() + selectors.groups_2.clone();
    let groups_1_or_2_or_4 = span_or_respan - selectors.groups_8;

    // Fewer than 8 groups: h4..h7 are unused and must be zero.
    {
        let builder = &mut builder.when(groups_1_or_2_or_4.clone());
        for lane in &hasher_state[4..8] {
            builder.assert_zero(*lane);
        }
    }

    // Fewer than 4 groups: h2..h3 are also unused.
    {
        let builder = &mut builder.when(groups_1_or_2);
        for lane in &hasher_state[2..4] {
            builder.assert_zero(*lane);
        }
    }

    // Only 1 group: h1 is also unused.
    builder.when(groups_1).assert_zero(hasher_state[1]);

    // group_count is the block's remaining group count, including this batch. A short batch must
    // exhaust it, so no later batch remains: the count equals the width 1, 2 or 4, which makes
    // count - 1 equal to groups_2 + 3 * groups_4.
    let count_minus_one: AB::Expr = group_count.into() - AB::Expr::ONE;
    let width_minus_one = selectors.groups_2 + selectors.groups_4 * Felt::from_u8(3);
    builder.assert_zero(groups_1_or_2_or_4 * count_minus_one - width_minus_one);
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, ONE, ZERO,
        field::{PrimeCharacteristicRing, QuadFelt},
    };

    use super::{OpBatchSelectors, enforce};
    use crate::vm::{
        constraints::test_utils::ConstraintEvalBuilder,
        trace::decoder::{
            OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
        },
    };

    const NUM_BATCH_CONSTRAINTS: usize = 13;

    /// Index of the remaining-count constraint, which `enforce` emits last.
    const SHORT_BATCH_COUNT: usize = 12;

    fn evaluate(
        span_or_respan: Felt,
        [full_batch, batch_size_code]: [Felt; 2],
        group_count: Felt,
        hasher_state: [Felt; 8],
    ) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        enforce(
            &mut builder,
            span_or_respan,
            full_batch,
            batch_size_code,
            group_count,
            &hasher_state,
        );
        assert_eq!(builder.evaluations.len(), NUM_BATCH_CONSTRAINTS);
        builder.evaluations
    }

    fn assert_accepts(
        span_or_respan: Felt,
        encoding: [Felt; 2],
        group_count: Felt,
        hasher_state: [Felt; 8],
    ) {
        assert_rejects(&[], span_or_respan, encoding, group_count, hasher_state);
    }

    fn assert_rejects(
        expected: &[usize],
        span_or_respan: Felt,
        encoding: [Felt; 2],
        group_count: Felt,
        hasher_state: [Felt; 8],
    ) {
        let rejected: Vec<_> = evaluate(span_or_respan, encoding, group_count, hasher_state)
            .into_iter()
            .enumerate()
            .filter_map(|(idx, value)| (value != QuadFelt::ZERO).then_some(idx))
            .collect();
        assert_eq!(
            rejected, expected,
            "SPAN/RESPAN {span_or_respan}, encoding {encoding:?}, group count {group_count}"
        );
    }

    #[test]
    fn selectors_match_the_canonical_encoding() {
        let cases = [
            (OP_BATCH_1_GROUPS, (ZERO, ZERO, ZERO, ONE)),
            (OP_BATCH_8_GROUPS, (ONE, ZERO, ZERO, ZERO)),
            (OP_BATCH_4_GROUPS, (ZERO, ONE, ZERO, ZERO)),
            (OP_BATCH_2_GROUPS, (ZERO, ZERO, ONE, ZERO)),
        ];

        for ([full, code], expected) in cases {
            let selectors = OpBatchSelectors::new(full, code);
            assert_eq!(
                (
                    selectors.groups_8,
                    selectors.groups_4,
                    selectors.groups_2,
                    selectors.groups_1(ONE),
                ),
                expected,
            );
        }

        let inactive = OpBatchSelectors::new(ZERO, ZERO);
        assert_eq!(inactive.groups_1(ZERO), ZERO);
    }

    #[test]
    fn canonical_batches_accept_payloads_and_enforce_short_counts() {
        let cases = [(OP_BATCH_1_GROUPS, 1), (OP_BATCH_2_GROUPS, 2), (OP_BATCH_4_GROUPS, 4)];
        let payload = Felt::from_u8(7);
        for (encoding, width) in cases {
            let mut lanes = [ZERO; 8];
            lanes[..usize::from(width)].fill(payload);
            assert_accepts(ONE, encoding, Felt::from_u8(width), lanes);
            for count in [width - 1, width + 1] {
                assert_rejects(&[SHORT_BATCH_COUNT], ONE, encoding, Felt::from_u8(count), lanes);
            }
        }

        // A full batch may have successors. An inactive row may use the count for another purpose.
        assert_accepts(ONE, OP_BATCH_8_GROUPS, Felt::from_u8(9), [payload; 8]);
        assert_accepts(ZERO, OP_BATCH_1_GROUPS, Felt::from_u8(5), [payload; 8]);
    }

    #[test]
    fn invalid_encodings_trigger_expected_constraints() {
        // Each group count satisfies the remaining-count constraint where any count can.
        assert_rejects(&[0], ONE, [Felt::from_u8(2), ZERO], ONE, [ZERO; 8]);
        assert_rejects(&[1], ONE, [ZERO, Felt::from_u8(2)], Felt::from_u8(11), [ZERO; 8]);
        assert_rejects(&[3], ZERO, [ONE, ZERO], ONE, [ZERO; 8]);

        // A nonzero size code with a full flag or on an inactive row also has no valid count.
        assert_rejects(&[2, SHORT_BATCH_COUNT], ONE, [ONE, ONE], ONE, [ZERO; 8]);
        assert_rejects(&[4, SHORT_BATCH_COUNT], ZERO, [ZERO, ONE], ONE, [ZERO; 8]);
    }

    #[test]
    fn each_unused_hasher_lane_is_pinned_independently() {
        let cases = [
            (OP_BATCH_4_GROUPS, 4, 4..8, 5),
            (OP_BATCH_2_GROUPS, 2, 2..8, 9),
            (OP_BATCH_1_GROUPS, 1, 1..8, 11),
        ];

        for (encoding, width, unused_lanes, first_constraint) in cases {
            for lane in unused_lanes {
                let mut hasher_state = [ZERO; 8];
                hasher_state[lane] = ONE;
                let constraint = match lane {
                    4..=7 => 5 + lane - 4,
                    2..=3 => 9 + lane - 2,
                    1 => first_constraint,
                    _ => unreachable!(),
                };
                assert_rejects(&[constraint], ONE, encoding, Felt::from_u8(width), hasher_state);
            }
        }
    }
}
