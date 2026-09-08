//! Proof order of a multi-AIR relation: Lehmer ranking and the sorting network that derives it.
//!
//! A lifted STARK commits its AIR traces in ascending `(log height, instance index)` order, which
//! varies per workload. This module names that permutation by its Lehmer rank relative to the
//! canonical instance order for exhaustive and reference tests. Production MASM verifiers do not
//! rank: they sort packed `(height, index)` keys with the fixed comparator network generated here,
//! which the order-maps renderer turns into a branch-free procedure.

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

/// Packed proof-order key stride: `key = PROOF_ORDER_KEY_STRIDE * log_height + instance_index`.
///
/// Sorting these keys ascending is exactly the stable sort by `(log_height, instance_index)` the
/// proof order is defined as, provided every instance index is below the stride. Keys are compared
/// as `u32`s, so the log height must also stay below `2^32 / PROOF_ORDER_KEY_STRIDE`; production
/// verifiers bound it below 30 before any key is formed.
pub(crate) const PROOF_ORDER_KEY_STRIDE: usize = 16;
const _: () = assert!(MAX_ORDER_AIRS <= PROOF_ORDER_KEY_STRIDE, "keys must separate every AIR");
// The generated pass unpacks the instance index with `u32and.(PROOF_ORDER_KEY_STRIDE - 1)`.
const _: () = assert!(
    PROOF_ORDER_KEY_STRIDE.is_power_of_two(),
    "the key stride must be a power of two"
);

/// One compare-exchange of a sorting network, as the pair of key positions `(lo, hi)` it touches
/// (`lo < hi`). After the exchange the smaller key sits at position `lo` and the larger at `hi`.
pub(crate) type Comparator = (usize, usize);

/// A size-optimal 29-comparator sorting network for the PVM's ten AIRs.
///
/// The exact schedule is SorterHunter's MIT-licensed `N10L29D8` network, pinned at
/// <https://github.com/bertdobbelaere/SorterHunter/blob/392762f916688756242d90febced98ad157bc6d2/sorting_networks_extended.html#L185-L195>.
/// Codish et al. prove that 29 comparators are minimal for ten inputs
/// (<https://doi.org/10.1016/j.jcss.2015.11.014>). The zero-one test below independently verifies
/// this particular schedule over all 1,024 Boolean inputs.
const TEN_INPUT_SORTING_NETWORK: [Comparator; 29] = [
    (0, 8),
    (1, 9),
    (2, 7),
    (3, 5),
    (4, 6),
    (0, 2),
    (1, 4),
    (5, 8),
    (7, 9),
    (0, 3),
    (2, 4),
    (5, 7),
    (6, 9),
    (0, 1),
    (3, 6),
    (8, 9),
    (1, 5),
    (2, 3),
    (4, 8),
    (6, 7),
    (1, 2),
    (3, 5),
    (4, 6),
    (7, 8),
    (2, 3),
    (4, 5),
    (6, 7),
    (3, 4),
    (5, 6),
];

/// A sorting network over `num_inputs` keys.
///
/// Ten inputs use the smaller network above. Every other supported input count uses Batcher's
/// merge exchange (Knuth, TAOCP vol. 3, §5.2.2, Algorithm M), which is defined for arbitrary input
/// counts, not only powers of two.
///
/// Comparators are listed in application order; each is `(lo, hi)` with `lo < hi`, and the network
/// is data-oblivious, so a verifier can apply it to untrusted keys with a fixed instruction
/// sequence. Four inputs take five comparators; ten take 29.
///
/// Panics unless `1 <= num_inputs <= MAX_ORDER_AIRS`; the exhaustive zero-one test below is what
/// makes the construction trustworthy for every supported size.
pub(crate) fn sorting_network(num_inputs: usize) -> Vec<Comparator> {
    assert!(
        (1..=MAX_ORDER_AIRS).contains(&num_inputs),
        "sorting networks are generated for 1..={MAX_ORDER_AIRS} inputs"
    );
    if num_inputs == 10 {
        return TEN_INPUT_SORTING_NETWORK.to_vec();
    }
    let mut comparators = Vec::new();
    let n = num_inputs;
    let t = usize::BITS - (n - 1).leading_zeros(); // ceil(log2 n); 0 for n == 1
    let mut p = if t == 0 { 0 } else { 1usize << (t - 1) };
    while p > 0 {
        let mut q = 1usize << (t - 1);
        let mut r = 0usize;
        let mut d = p;
        loop {
            for i in 0..n - d {
                if i & p == r {
                    comparators.push((i, i + d));
                }
            }
            if q == p {
                break;
            }
            d = q - p;
            q /= 2;
            r = p;
        }
        p /= 2;
    }
    comparators
}

/// Applies `network` to `keys` in place, exactly as the verifier does.
#[cfg(test)]
pub(crate) fn apply_sorting_network(network: &[Comparator], keys: &mut [u64]) {
    for &(lo, hi) in network {
        if keys[lo] > keys[hi] {
            keys.swap(lo, hi);
        }
    }
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

    /// Zero-one principle: a comparator network sorts every input iff it sorts every 0/1 input.
    /// Every supported size is swept exhaustively, so the generator is trusted by evidence, not
    /// by its derivation.
    #[test]
    fn sorting_networks_sort_every_boolean_input() {
        for num_inputs in 1..=MAX_ORDER_AIRS {
            let network = sorting_network(num_inputs);
            assert!(network.iter().all(|&(lo, hi)| lo < hi && hi < num_inputs));
            for bits in 0u32..(1 << num_inputs) {
                let mut keys: Vec<u64> =
                    (0..num_inputs).map(|i| u64::from(bits >> i & 1)).collect();
                apply_sorting_network(&network, &mut keys);
                assert!(
                    keys.windows(2).all(|pair| pair[0] <= pair[1]),
                    "{num_inputs}-input network fails on boolean input {bits:#b}"
                );
            }
        }
    }

    /// Packed keys sorted by the network reproduce the stable `(height, index)` sort the proof
    /// order is defined as, ties included.
    #[test]
    fn packed_keys_sort_to_the_stable_proof_order() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state >> 33
        };
        for num_inputs in 1..=MAX_ORDER_AIRS {
            let network = sorting_network(num_inputs);
            for _ in 0..200 {
                // Heights come from a small range so ties are common.
                let heights: Vec<u64> = (0..num_inputs).map(|_| 6 + next() % 6).collect();
                let mut expected: Vec<usize> = (0..num_inputs).collect();
                expected.sort_by_key(|&i| (heights[i], i));
                let mut keys: Vec<u64> = (0..num_inputs)
                    .map(|i| heights[i] * PROOF_ORDER_KEY_STRIDE as u64 + i as u64)
                    .collect();
                apply_sorting_network(&network, &mut keys);
                let order: Vec<usize> =
                    keys.iter().map(|key| (key % PROOF_ORDER_KEY_STRIDE as u64) as usize).collect();
                assert_eq!(order, expected, "heights {heights:?}");
            }
        }
    }

    /// The comparator counts are part of the verifier's cycle budget; a generator change must
    /// surface here rather than only as a MASM diff.
    #[test]
    fn network_sizes_are_pinned() {
        assert_eq!(sorting_network(1).len(), 0);
        assert_eq!(sorting_network(2).len(), 1);
        assert_eq!(sorting_network(4).len(), 5);
        assert_eq!(sorting_network(10).len(), 29);
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
