//! Column-agnostic, subset-based LogUp interaction harness.
//!
//! The prover path pushes one `(multiplicity, encoded_denominator)` pair per interaction into a
//! flat buffer. [`InteractionLog`] slices that buffer into per-row bags (across all columns) and
//! exposes one assertion, [`InteractionLog::assert_contains`]: for each row, the bag of expected
//! `(mult, msg)` pairs the test describes must be a multiset-subset of the bag of actual pushes.
//!
//! Tests describe expected interactions via [`Expectations`], which accepts raw
//! [`LookupMessage`] instances and encodes them against the log's challenges. `Expectations` is
//! column-blind by construction — two messages routed onto different aux columns still compare
//! equal if they share both multiplicity and encoded denominator.
//!
//! No scalar sums, no per-column deltas, no terminals: those views invite missing + spurious
//! interactions to cancel silently. Subset semantics over raw `(mult, denom)` tuples keeps every
//! expected interaction independently observable.

use alloc::{format, string::String, vec::Vec};
use std::collections::HashMap;

use miden_air::{
    LiftedAir, ProcessorAir,
    lookup::{
        BusId, Challenges, LookupFractions, LookupMessage, MIDEN_MAX_MESSAGE_WIDTH, MidenLookupAir,
        build_lookup_fractions,
    },
};
use miden_core::field::QuadFelt;
use miden_utils_testing::rand::rand_array;

use super::{ExecutionTrace, Felt};

// INTERACTION LOG
// ================================================================================================

/// Per-row record of every `(multiplicity, denominator)` pair the prover path emitted for a
/// given execution trace, aggregated across all aux columns.
///
/// Column identity is intentionally discarded: a row's contribution to the LogUp closure
/// identity is the union of its per-column pushes, and processor-side tests should stay
/// invariant under any AIR-side column repack.
pub(super) struct InteractionLog {
    /// Random challenges used to encode messages. Exposed so `Expectations` can encode
    /// hand-built [`LookupMessage`] instances against the same challenges used by the prover
    /// path above.
    pub challenges: Challenges<QuadFelt>,
    /// `rows[r]` = multiset of `(mult, denom)` pushes the prover produced at main-trace row
    /// `r`, across all columns, in builder order.
    rows: Vec<Vec<(Felt, QuadFelt)>>,
}

impl InteractionLog {
    /// Drive the prover-path pipeline on `trace` with fresh random challenges and slice the
    /// resulting [`LookupFractions`] buffer into per-row bags.
    pub fn new(trace: &ExecutionTrace) -> Self {
        let main_trace = trace.main_trace().to_row_major();
        let public_vals = trace.to_public_values();
        let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

        // `QuadFelt` itself isn't `Randomizable`, so draw 4 base-field elements and pair them.
        let raw = rand_array::<Felt, 4>();
        let alpha = QuadFelt::new([raw[0], raw[1]]);
        let beta = QuadFelt::new([raw[2], raw[3]]);
        let challenges =
            Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

        let fractions = build_lookup_fractions(
            &MidenLookupAir,
            &main_trace,
            &periodic,
            &public_vals,
            &challenges,
        );

        Self { challenges, rows: split_rows(&fractions) }
    }

    /// Verify that each row's expected bag is a multiset-subset of that row's actual bag of
    /// prover pushes.
    ///
    /// For every `(row, mult, denom)` in `expected`, there must be a matching unclaimed push at
    /// that row with identical `(mult, denom)`. Two expected entries with the same triple
    /// require two matching pushes. Actual pushes that no expected entry claims are ignored —
    /// this is the whole point of subset semantics, so partial tests can focus on one bus or
    /// one instruction without enumerating every other interaction that happens to fire.
    ///
    /// Panics on the first mismatch with a message listing the unmatched expected entry and
    /// the full actual row bag.
    pub fn assert_contains(&self, expected: &Expectations) {
        // Group expected entries by row: rows_expected[r] = count of each (mult, denom) key.
        let mut rows_expected: HashMap<usize, HashMap<FracKey, usize>> = HashMap::new();
        for &(row, mult, denom) in &expected.entries {
            *rows_expected.entry(row).or_default().entry(frac_key(mult, denom)).or_default() += 1;
        }

        for (row, want) in rows_expected {
            assert!(
                row < self.rows.len(),
                "expected row {row} but trace has only {} rows",
                self.rows.len(),
            );
            let mut have: HashMap<FracKey, usize> = HashMap::new();
            for &(m, d) in &self.rows[row] {
                *have.entry(frac_key(m, d)).or_default() += 1;
            }

            for (&(mult, denom), want_count) in &want {
                let have_count = have.get(&(mult, denom)).copied().unwrap_or(0);
                if have_count < *want_count {
                    panic!(
                        "row {row}: expected {want_count} push(es) of (mult={}, denom={:?}) but \
                         only {have_count} such push(es) fired.\n  actual row bag: {}",
                        display_mult(mult),
                        denom,
                        format_row(&self.rows[row]),
                    );
                }
            }
        }
    }
}

// EXPECTATIONS
// ================================================================================================

/// Hand-assembled list of `(row, multiplicity, encoded_denominator)` triples representing the
/// interactions a test expects to see somewhere on that row.
///
/// [`Expectations`] is column-blind by construction: `add` / `remove` / `signed` encode a
/// [`LookupMessage`] against the owning [`InteractionLog`]'s challenges and store only the
/// resulting denominator plus the signed multiplicity, so the subsequent subset check never
/// consults column identity.
pub(super) struct Expectations<'a> {
    challenges: &'a Challenges<QuadFelt>,
    entries: Vec<(usize, Felt, QuadFelt)>,
}

impl<'a> Expectations<'a> {
    /// Start an empty expectation set tied to `log`'s challenges.
    pub fn new(log: &'a InteractionLog) -> Self {
        Self {
            challenges: &log.challenges,
            entries: Vec::new(),
        }
    }

    /// Add an expected `+1 · 1 / encode(msg)` interaction at `row`.
    pub fn add<M>(&mut self, row: usize, msg: &M) -> &mut Self
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.push(row, Felt::ONE, msg)
    }

    /// Add an expected `-1 · 1 / encode(msg)` interaction at `row`.
    pub fn remove<M>(&mut self, row: usize, msg: &M) -> &mut Self
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        self.push(row, -Felt::ONE, msg)
    }

    /// Add an expected `mult · 1 / encode(msg)` interaction at `row` with arbitrary
    /// multiplicity. Use for range-check table lookups and kernel-ROM table multiplicities.
    fn push<M>(&mut self, row: usize, mult: Felt, msg: &M) -> &mut Self
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let denom = msg.encode(self.challenges);
        self.entries.push((row, mult, denom));
        self
    }
}

// HELPERS
// ================================================================================================

/// `(mult, denom)` — a direct `HashMap` key using the `Hash + Eq` impls both `Felt` and
/// `QuadFelt` already provide (`BinomialExtensionField` derives `Hash` in p3-field).
type FracKey = (Felt, QuadFelt);

fn frac_key(mult: Felt, denom: QuadFelt) -> FracKey {
    (mult, denom)
}

/// Render a `Felt` multiplicity as its signed integer form when it's close to `0` (i.e.
/// `p - k` for small `k`), otherwise as the raw canonical value. Makes failure messages
/// readable when the multiplicity is `±1` or another small signed integer.
fn display_mult(m: Felt) -> String {
    const P: u64 = 0xffff_ffff_0000_0001; // Goldilocks modulus
    let v = m.as_canonical_u64();
    if v <= 16 {
        format!("{v}")
    } else if v >= P - 16 {
        format!("-{}", P - v)
    } else {
        format!("{v}")
    }
}

fn format_row(bag: &[(Felt, QuadFelt)]) -> String {
    let mut s = String::from("[");
    for (i, &(m, d)) in bag.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("(mult={}, denom={:?})", display_mult(m), d));
    }
    s.push(']');
    s
}

/// Slice the flat `LookupFractions` buffer into per-row bags using the row-major `counts`
/// layout (see `air/src/lookup/fractions.rs` for the ordering spec).
fn split_rows(fractions: &LookupFractions<Felt, QuadFelt>) -> Vec<Vec<(Felt, QuadFelt)>> {
    let num_cols = fractions.num_columns();
    let counts = fractions.counts();
    let flat = fractions.fractions();

    let num_rows = counts.len() / num_cols;
    let mut rows = Vec::with_capacity(num_rows);
    let mut cursor = 0usize;
    for per_row in counts.chunks(num_cols) {
        let total: usize = per_row.iter().sum();
        rows.push(flat[cursor..cursor + total].to_vec());
        cursor += total;
    }
    rows
}
