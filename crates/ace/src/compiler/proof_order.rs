//! Fixed sorting networks for the MASM proof-order renderer.

use crate::MAX_ORDER_AIRS;

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
/// (<https://doi.org/10.1016/j.jcss.2015.11.014>). By the zero-one principle, correctness over all
/// 1,024 Boolean inputs establishes correctness for arbitrary inputs from a totally ordered domain.
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
/// # Panics
///
/// Panics unless `1 <= num_inputs <= MAX_ORDER_AIRS`.
///
/// The returned comparator sequence sorts arbitrary inputs over a totally ordered domain.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// By the zero-one principle, this exhaustive sweep validates each supported comparator network
    /// for arbitrary inputs over a totally ordered domain.
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

    /// The comparator counts are part of the verifier's cycle budget and pin the generated MASM
    /// schedule.
    #[test]
    fn network_sizes_are_pinned() {
        assert_eq!(sorting_network(1).len(), 0);
        assert_eq!(sorting_network(2).len(), 1);
        assert_eq!(sorting_network(4).len(), 5);
        assert_eq!(sorting_network(10).len(), 29);
    }
}
