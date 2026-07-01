# BytePairLut: preprocessed-column migration

> **Status — implemented (commit `8fbd826`).** The four data columns are
> now a fixed, verifier-known preprocessed table; only the three
> multiplicities remain witness. This file records the design that
> shipped. Audit reference: [`airs/byte-pair-lut.md`](airs/byte-pair-lut.md);
> design rationale: [`chiplets/byte_pair_lut.md`](chiplets/byte_pair_lut.md).

## Problem (the gap that was closed)

The chiplet's main trace used to carry seven columns: `a`, `b`,
`c_andnot`, `c_xor`, plus three multiplicities (`COL_MULT_ANDNOT`,
`COL_MULT_XOR`, `COL_MULT_RANGE16`).

The first four were committed but **unconstrained** by the AIR. A
correct prover (`generate_trace`) filled them with the right values, but
nothing in `eval` forced `a, b ∈ [0, 256)` or bound `c_andnot`, `c_xor`
to the bytewise ops. That was unsound: a malicious prover could emit
arbitrary tuples on the `BytePairLut` / `Range16` buses.

An even earlier version asserted bit-binarity on per-bit `A_BITS` /
`B_BITS` columns and bound `c_andnot`, `c_xor` from those bits. Those
constraints were stripped because they only existed to keep the
all-witness layout sound; they are subsumed (and would be pointless
overhead) once the data columns are preprocessed.

## What shipped

The 0.26 framework supports preprocessed (verifier-known,
prover-non-witness) columns. The implemented layout:

- Trace height fixed at `2^16`, indexed by `r = (a << 8) | b`.
- `a`, `b`, `c_andnot`, `c_xor` moved to a **preprocessed** matrix
  (`preprocessed_table()`, returned by `BaseAir::preprocessed_trace()`;
  `preprocessed_width() = 4`), enumerating all `(a, b) ∈ [0, 256)²` in
  lex order with the correct `c_*` values. Column indices `PRE_A`,
  `PRE_B`, `PRE_C_ANDNOT`, `PRE_C_XOR`.
- The three multiplicity columns (`COL_MULT_*`, `NUM_MAIN_COLS = 3`)
  remain witness.
- `BytePairLutMsg` / `Range16Msg` construction is unchanged.

Soundness follows from the preprocessed commitment being pinned to the
fixed correct values — the verifier rebuilds it deterministically from
the AIR list and observes it into Fiat-Shamir, so a prover cannot forge
it.

## The combined-window detail (not anticipated by the original plan)

The original plan assumed `eval` would read the four data columns via
`builder.preprocessed()`. Our LogUp runs through the miden-vm lookup
framework, whose `LookupBuilder` exposes only `main()` — there is **no
preprocessed accessor**, and `WindowAccess::current_slice()` must return
one contiguous slice while the preprocessed and main rows live in
separate committed traces.

So the eval reads the data through a **combined `[preprocessed ++ main]`
window** instead:

- **Constraint side** (`logup::CombinedWindow` / `LookupMainWindow`,
  `src/logup/constraint.rs`): for an AIR that declares preprocessed
  columns, `CyclicConstraintLookupBuilder::main()` returns an owned
  `[preprocessed ++ main]` concatenation; AIRs without preprocessed
  columns pass `main` through unchanged (no copy). Gated on a
  `has_preprocessed` flag passed to `new()` — probing `preprocessed()`
  is unsafe for no-preprocessed AIRs (the `SymbolicAirBuilder` panics on
  its 0-row window). All call sites pass `self.preprocessed_width() > 0`.
- **Prover side** (`build_aux`, `byte_pair_lut.rs`): reconstructs the
  table and prepends it to the witness multiplicities, feeding the same
  combined matrix to the unmodified `build_logup_aux_trace` /
  `build_lookup_fractions`.

Both paths therefore read identical column indices: `PRE_*` for the data,
`NUM_PREPROCESSED_COLS + COL_MULT_*` for the multiplicities (window width
`NUM_LOOKUP_COLS = 7`).

## Driver threading

`Preprocessed::build(statement, config)` builds the per-AIR preprocessed
bundle (auto from each AIR's `preprocessed_trace()`, observed into
Fiat-Shamir). `ChipletAir` delegates `preprocessed_trace` /
`preprocessed_width`; `SessionTraces::prove` / `SessionProof::verify`
(and the EcStack subset tests) build it and pass `Some(&preprocessed)` /
`Some(commitment)` — both deterministic from the AIR list, so the
verifier rebuilds the commitment it trusts. The per-chiplet test harness
is unchanged: `check_constraints` re-materializes the table itself, and
balance-check helpers combine via `tests::combined_lookup_main`.
