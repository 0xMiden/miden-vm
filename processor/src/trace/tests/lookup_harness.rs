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

use alloc::vec::Vec;

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
    /// For every `(row, mult, denom)` in `expected`, there must be at least as many matching
    /// pushes at that row. Unclaimed actual pushes are ignored — this is the whole point of
    /// subset semantics, so partial tests can focus on one bus or one instruction without
    /// enumerating every other interaction that happens to fire.
    pub fn assert_contains(&self, expected: &Expectations) {
        for &entry in &expected.entries {
            let (row, mult, denom) = entry;
            let want = expected.entries.iter().filter(|&&e| e == entry).count();
            let have = self.rows[row].iter().filter(|&&(m, d)| m == mult && d == denom).count();
            assert!(
                have >= want,
                "row {row}: expected at least {want}× (mult={mult:?}, denom={denom:?}), saw {have}.\n\
                 actual row bag: {:?}",
                self.rows[row],
            );
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
