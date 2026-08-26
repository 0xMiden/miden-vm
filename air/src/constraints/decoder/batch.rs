use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing},
};
use miden_crypto::stark::air::AirBuilder;

use crate::{MidenAirBuilder, constraints::utils::BoolNot};

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

/// Enforces the operation-batch encoding and zeroes hasher lanes unused by short batches.
pub(super) fn enforce<AB>(
    builder: &mut AB,
    span_or_respan: AB::Expr,
    full_batch: AB::Var,
    batch_size_code: AB::Var,
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
        let builder = &mut builder.when(span_or_respan.clone().not());
        builder.assert_zero(full_batch);
        builder.assert_zero(batch_size_code);
    }

    let selectors = OpBatchSelectors::new(full_batch.into(), batch_size_code.into());
    let groups_1 = selectors.groups_1(span_or_respan.clone());
    let groups_1_or_2 = groups_1.clone() + selectors.groups_2;
    let groups_1_or_2_or_4 = span_or_respan - selectors.groups_8;

    // Fewer than 8 groups: h4..h7 are unused and must be zero.
    {
        let builder = &mut builder.when(groups_1_or_2_or_4);
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
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        Felt, ONE, ZERO,
        field::{PrimeCharacteristicRing, QuadFelt},
    };

    use super::{OpBatchSelectors, enforce};
    use crate::{
        constraints::stack::test_utils::ConstraintEvalBuilder,
        trace::decoder::{
            OP_BATCH_1_GROUPS, OP_BATCH_2_GROUPS, OP_BATCH_4_GROUPS, OP_BATCH_8_GROUPS,
        },
    };

    const NUM_BATCH_CONSTRAINTS: usize = 12;

    fn evaluate(
        span_or_respan: Felt,
        [full_batch, batch_size_code]: [Felt; 2],
        hasher_state: [Felt; 8],
    ) -> Vec<QuadFelt> {
        let mut builder = ConstraintEvalBuilder::new();
        enforce(&mut builder, span_or_respan, full_batch, batch_size_code, &hasher_state);
        assert_eq!(builder.evaluations.len(), NUM_BATCH_CONSTRAINTS);
        builder.evaluations
    }

    fn assert_accepts(span_or_respan: Felt, encoding: [Felt; 2], hasher_state: [Felt; 8]) {
        assert!(
            evaluate(span_or_respan, encoding, hasher_state)
                .into_iter()
                .all(|value| value == QuadFelt::ZERO),
        );
    }

    fn assert_only_constraint_rejects(
        expected_constraint: usize,
        span_or_respan: Felt,
        encoding: [Felt; 2],
        hasher_state: [Felt; 8],
    ) {
        let rejected: Vec<_> = evaluate(span_or_respan, encoding, hasher_state)
            .into_iter()
            .enumerate()
            .filter_map(|(idx, value)| (value != QuadFelt::ZERO).then_some(idx))
            .collect();
        assert_eq!(rejected, [expected_constraint]);
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
    fn constraints_accept_exactly_the_canonical_encodings() {
        let nonzero = Felt::new_unchecked(7);
        assert_accepts(ONE, OP_BATCH_8_GROUPS, [nonzero; 8]);
        assert_accepts(
            ONE,
            OP_BATCH_4_GROUPS,
            [nonzero, nonzero, nonzero, nonzero, ZERO, ZERO, ZERO, ZERO],
        );
        assert_accepts(
            ONE,
            OP_BATCH_2_GROUPS,
            [nonzero, nonzero, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO],
        );
        assert_accepts(ONE, OP_BATCH_1_GROUPS, [nonzero, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO]);
        assert_accepts(ZERO, OP_BATCH_1_GROUPS, [nonzero; 8]);
    }

    #[test]
    fn each_encoding_constraint_rejects_independently() {
        assert_only_constraint_rejects(0, ONE, [Felt::from_u8(2), ZERO], [ZERO; 8]);
        assert_only_constraint_rejects(1, ONE, [ZERO, Felt::from_u8(2)], [ZERO; 8]);
        assert_only_constraint_rejects(2, ONE, [ONE, ONE], [ZERO; 8]);
        assert_only_constraint_rejects(3, ZERO, [ONE, ZERO], [ZERO; 8]);
        assert_only_constraint_rejects(4, ZERO, [ZERO, ONE], [ZERO; 8]);
    }

    #[test]
    fn each_unused_hasher_lane_is_pinned_independently() {
        let cases = [
            (OP_BATCH_4_GROUPS, 4..8, 5),
            (OP_BATCH_2_GROUPS, 2..8, 9),
            (OP_BATCH_1_GROUPS, 1..8, 11),
        ];

        for (encoding, unused_lanes, first_constraint) in cases {
            for lane in unused_lanes {
                let mut hasher_state = [ZERO; 8];
                hasher_state[lane] = ONE;
                let constraint = match lane {
                    4..=7 => 5 + lane - 4,
                    2..=3 => 9 + lane - 2,
                    1 => first_constraint,
                    _ => unreachable!(),
                };
                assert_only_constraint_rejects(constraint, ONE, encoding, hasher_state);
            }
        }
    }
}
