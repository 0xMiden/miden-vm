//! Proof-order ranking for a multi-AIR relation.
//!
//! A lifted STARK commits its AIR traces in ascending `(log height, instance index)` order, which
//! varies per workload. That permutation is named by its Lehmer rank relative to the canonical
//! instance order, so a relation, its MASM verifier, and their tests can all refer to one
//! ordering by the same number.

/// Largest AIR count whose complete permutation set fits in the `u32` tag space.
///
/// `12!` fits; `13!` does not. Ranking must reject larger compositions before any rank is
/// narrowed to `u32`.
pub const MAX_ORDER_AIRS: usize = 12;

/// Compute `n!`.
pub const fn factorial(n: usize) -> usize {
    let mut result: usize = 1;
    let mut factor: usize = 2;
    while factor <= n {
        result = match result.checked_mul(factor) {
            Some(value) => value,
            None => panic!("factorial overflows usize"),
        };
        factor += 1;
    }
    result
}

/// Tag of a proof ordering: its Lehmer rank relative to the canonical (identity) instance order.
///
/// Digit `i` counts the smaller instance indices to the right of position `i`, weighted
/// by `(n - 1 - i)!`. Panics unless `proof_order` is a nonempty permutation of
/// `0..proof_order.len()` within [`MAX_ORDER_AIRS`].
pub fn order_tag(proof_order: &[usize]) -> u32 {
    let num_airs = proof_order.len();
    assert!(
        (1..=MAX_ORDER_AIRS).contains(&num_airs),
        "proof order must contain 1..={MAX_ORDER_AIRS} AIRs"
    );
    assert!(is_permutation(proof_order), "proof order must be a permutation");
    let mut rank: u64 = 0;
    for i in 0..num_airs {
        let smaller_after =
            proof_order[i + 1..].iter().filter(|&&index| index < proof_order[i]).count();
        rank += smaller_after as u64 * factorial(num_airs - 1 - i) as u64;
    }
    u32::try_from(rank).expect("tags of a supported AIR count fit in u32")
}

/// Decode a tag into its proof ordering over `num_airs` AIRs.
///
/// Returns `None` for tags at or above `num_airs!`, which name no ordering.
pub fn order_from_tag(tag: u32, num_airs: usize) -> Option<Vec<usize>> {
    if !(1..=MAX_ORDER_AIRS).contains(&num_airs) {
        return None;
    }
    if tag as usize >= factorial(num_airs) {
        return None;
    }
    let mut rank = tag as usize;
    let mut remaining: Vec<usize> = (0..num_airs).collect();
    let mut order = Vec::with_capacity(num_airs);
    for i in 0..num_airs {
        let factor = factorial(num_airs - 1 - i);
        // The next Lehmer digit selects an instance index from the remaining ordered list.
        order.push(remaining.remove(rank / factor));
        rank %= factor;
    }
    Some(order)
}

fn is_permutation(proof_order: &[usize]) -> bool {
    let mut seen = vec![false; proof_order.len()];
    proof_order
        .iter()
        .all(|&index| index < seen.len() && !core::mem::replace(&mut seen[index], true))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn order_tags_round_trip_over_the_whole_range() {
        for num_airs in 1..=6 {
            for tag in 0..factorial(num_airs) as u32 {
                let order = order_from_tag(tag, num_airs).expect("tag in range");
                assert_eq!(order_tag(&order), tag, "round trip fails at {num_airs} AIRs, {tag}");
            }
            assert_eq!(order_from_tag(factorial(num_airs) as u32, num_airs), None);
            let identity: Vec<usize> = (0..num_airs).collect();
            assert_eq!(order_tag(&identity), 0, "the identity ordering must be tag 0");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn larger_order_tags_round_trip(raw_tags in any::<[u32; 6]>()) {
            for (num_airs, raw_tag) in (7..=MAX_ORDER_AIRS).zip(raw_tags) {
                let tag = raw_tag % factorial(num_airs) as u32;
                let order = order_from_tag(tag, num_airs).expect("tag in range");
                prop_assert_eq!(order_tag(&order), tag);
            }
        }
    }

    /// The permutation check is a correctness precondition, not a debug aid: a repeated index
    /// would silently produce a tag another ordering already owns.
    #[test]
    #[should_panic(expected = "proof order must be a permutation")]
    fn order_tag_rejects_invalid_permutations_in_all_builds() {
        let _ = order_tag(&[0, 0, 2]);
    }

    /// `13!` overflows the `u32` tag space, so ranking must refuse it rather than wrap.
    #[test]
    fn air_counts_past_the_tag_space_are_refused() {
        assert_eq!(order_from_tag(0, MAX_ORDER_AIRS + 1), None);
        assert!(order_from_tag(0, MAX_ORDER_AIRS).is_some());
        assert!(u32::try_from(factorial(MAX_ORDER_AIRS)).is_ok());
        assert!(u32::try_from(factorial(MAX_ORDER_AIRS + 1)).is_err());
    }
}
