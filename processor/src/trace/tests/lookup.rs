//! End-to-end collection-phase smoke test for the prover-side LogUp pipeline.
//!
//! Runs a tiny MASM basic block through `build_trace_from_ops`, materialises the
//! resulting main trace as a [`RowMajorMatrix<Felt>`], and pipes it through
//! [`build_lookup_fractions`] + [`accumulate_slow`]. The test validates:
//!
//! 1. **Shape-const drift**: every bus emitter's declared `MAX_INTERACTIONS_PER_ROW` is large
//!    enough to accommodate real trace data (the `debug_assert!` inside
//!    `ProverLookupBuilder::column` panics on overflow).
//! 2. **Zero-denominator bugs**: every encoded `LookupMessage` evaluates to a non-zero
//!    extension-field element, so `accumulate_slow`'s per-fraction `try_inverse` does not panic.
//! 3. **Pipeline plumbing**: row slicing with wraparound, per-row periodic composition, `RowWindow`
//!    construction over a real matrix, and the dense `LookupFractions` buffer all line up.
//!
//! The test does **not** assert algebraic correctness of individual aux-column values
//! or terminal closure — those checks need the follow-up constraint-path round-trip
//! oracle. Column terminals are printed to stderr for manual inspection.

use miden_air::{
    LiftedAir, ProcessorAir,
    lookup::{LookupChallenges, MidenLookupAir, accumulate_slow, build_lookup_fractions},
};
use miden_core::field::{PrimeCharacteristicRing, QuadFelt};

use super::{Felt, build_trace_from_ops, rand_array};
use crate::operation::Operation;

/// Smallest end-to-end check: run a tiny real trace through the LogUp collection
/// driver and verify the debug-mode shape check never trips, no zero denominators
/// are produced, and the accumulator runs to completion.
#[test]
fn build_lookup_fractions_on_tiny_span() {
    // A handful of ops inside a span. Pad/Add/Mul/Drop exercise decoder + stack +
    // range checks with minimal setup — same flavour of ops as the existing
    // `decoder.rs` / `stack.rs` tests use.
    let ops = vec![
        Operation::Pad,
        Operation::Pad,
        Operation::Add,
        Operation::Pad,
        Operation::Mul,
        Operation::Drop,
    ];
    let trace = build_trace_from_ops(ops, &[]);

    let main_trace = trace.main_trace().to_row_major();
    let public_vals = trace.to_public_values();
    let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

    // QuadFelt challenges for LogUp, built from 4 random Felts (QuadFelt itself doesn't
    // implement Randomizable, so we draw base-field elements and pair them). Distinct
    // from the legacy multiset path in decoder.rs which uses Felt challenges directly.
    let raw = rand_array::<Felt, 4>();
    let alpha = QuadFelt::new([raw[0], raw[1]]);
    let beta = QuadFelt::new([raw[2], raw[3]]);
    let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

    let air = MidenLookupAir;
    let fractions = build_lookup_fractions(&air, &main_trace, &periodic, &public_vals, &challenges);

    // --- Shape bookkeeping ---
    let num_rows = trace.main_trace().num_rows();
    assert_eq!(fractions.num_rows(), num_rows);
    assert_eq!(fractions.num_columns(), 7);
    assert_eq!(fractions.counts().len(), num_rows * 7);

    // --- Trace is not degenerate: at least one fraction was collected somewhere.
    //     If every column was empty the emitters, shape consts, or trace are broken. ---
    assert!(
        !fractions.fractions().is_empty(),
        "no fractions collected — trace is degenerate or emitters are broken",
    );

    // --- Slow accumulator runs without panicking. This is the real regression check:
    //     a bad emitter or a zero bus_prefix would produce a zero-denominator fraction
    //     and `try_inverse` inside `accumulate_slow` would panic. ---
    let aux = accumulate_slow(&fractions);
    assert_eq!(aux.len(), 7);
    for col_aux in &aux {
        assert_eq!(col_aux.len(), num_rows + 1);
        assert_eq!(col_aux[0], QuadFelt::ZERO);
    }

    // --- Informational: per-column terminals. A follow-up commit hardens these into
    //     concrete assertions once we know the expected boundary value for each column
    //     (some close to zero, log_precompile transcript has a non-zero boundary). ---
    for (col, col_aux) in aux.iter().enumerate() {
        std::eprintln!("lookup column {col} terminal = {:?}", col_aux[num_rows]);
    }
}
