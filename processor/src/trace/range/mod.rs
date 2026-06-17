use alloc::collections::BTreeMap;

use miden_air::trace::and8_lookup::{
    BYTE_LOOKUP_COUNT_LEN, BYTE_PAIR_ROWS, RANGE_CHECK_COUNT_OFFSET,
};

#[cfg(test)]
mod tests;

// RANGE CHECKER
// ================================================================================================

/// Range checker for the VM.
///
/// This component collects multiplicities for all 16-bit range checks performed by the VM. It does
/// not check values directly; the table side of the `RangeCheck` bus is emitted by the byte-pair
/// lookup AIR, whose fixed rows enumerate every value `value = 256 * a + b`.
pub struct RangeChecker {
    /// Tracks lookup count for each checked value.
    lookups: BTreeMap<u16, usize>,
}

impl RangeChecker {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    /// Returns a new [RangeChecker] with no pending range-check requests.
    pub fn new() -> Self {
        Self { lookups: BTreeMap::new() }
    }

    // TRACE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Records one range-check request for `value`.
    pub fn add_value(&mut self, value: u16) {
        self.add_value_repeated(value, 1);
    }

    /// Adds `count` lookups for the specified value.
    pub fn add_value_repeated(&mut self, value: u16, count: usize) {
        if count == 0 {
            return;
        }
        self.lookups.entry(value).and_modify(|v| *v += count).or_insert(count);
    }

    /// Adds a batch of range-check requests.
    pub fn add_range_checks(&mut self, values: &[u16]) {
        // Stack u32 operations request four helper limbs. Memory uses this helper for the two
        // sorted-access delta limbs and records address-decomposition checks separately.
        debug_assert!(values.len() == 2 || values.len() == 4);

        for value in values.iter() {
            self.add_value(*value);
        }
    }

    // LOOKUP COUNT GENERATION
    // --------------------------------------------------------------------------------------------

    /// Adds the collected range-check multiplicities to the byte-pair lookup count vector.
    ///
    /// The byte-pair table row order is `(a << 8) + b`, which is exactly the 16-bit value
    /// `256 * a + b`, so the range-check count for `value` is written to
    /// `RANGE_CHECK_COUNT_OFFSET + value`.
    pub fn write_range_counts(self, counts: &mut [u64]) {
        debug_assert_eq!(counts.len(), BYTE_LOOKUP_COUNT_LEN);
        debug_assert_eq!(BYTE_PAIR_ROWS, usize::from(u16::MAX) + 1);
        for (value, count) in self.lookups {
            counts[RANGE_CHECK_COUNT_OFFSET + usize::from(value)] +=
                u64::try_from(count).expect("range-check multiplicity exceeds u64");
        }
    }

    // TEST HELPERS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub fn count(&self, value: u16) -> usize {
        self.lookups.get(&value).copied().unwrap_or(0)
    }
}

impl Default for RangeChecker {
    fn default() -> Self {
        Self::new()
    }
}
