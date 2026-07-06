# BytePairLut — 8×8 byte-pair lookup table

> **AIR reference:** [`airs/byte-pair-lut.md`](../airs/byte-pair-lut.md) — complete column / constraint / bus reference for this chiplet.

Provides byte-level bitwise ops and 16-bit range checks. The
leaf chiplet of the Keccak stack: depends on nothing, gets
required by [Bitwise64](bitwise64.md) (byte-wise on LOGIC rows)
and Range16-by-anyone-who-needs-it.

Implementation: [`src/primitives/byte_pair_lut.rs`](../../src/primitives/byte_pair_lut.rs).

## Relations

- **`BytePairLut(op, a, b, c)`** with `op ∈ {0=AndNot, 1=Xor}`,
  `a, b ∈ [0, 256)`, `c = op(a, b)`.
- **`Range16(w)`** with `w ∈ [0, 2^16)`, splitting
  `w = a + 256·b` LSB-first onto the matching `(a, b)` row.

Provides only; no requires.

`AndNot` rather than `And` because Keccak χ uses `(¬a) ∧ b`
directly; the 64-bit chiplet decomposes χ into byte-level
AndNot requires without an extra negation layer.

## Layout

- **Width**: 3 witness main columns (the multiplicity columns) +
  4 preprocessed (verifier-known) data columns (`a`, `b`, `c_andnot`,
  `c_xor`) + 1 aux column.
- **Height**: fixed at `2^16` — one row per `(a, b) ∈ [0, 256)²`
  in lex order, with multiplicities zero on untouched rows. The
  preprocessed table and the witness multiplicity trace share this
  height and line up by row index.
- **`log_quotient_degree = 2`** — column 0 batches 3 self-provide
  fractions, so its gated last-row σ-close lands at degree `3 + 2 = 5`
  → lqd 2 (`ceil(log2(5 − 1)) = 2`).

## Soundness

The four data columns (`a`, `b`, `c_andnot`, `c_xor`) are a fixed,
verifier-known **preprocessed** table — `2^16` rows enumerating every
`(a, b) ∈ [0, 256)²` in lex order with the correct
`c_andnot = (¬a) & b`, `c_xor = a ^ b`. A prover cannot forge them, so
the `(op, a, b, c)` / `(w,)` tuples the chiplet provides are pinned to
correct values and the chiplet is **sound**: callers inherit sound byte
range checks and bitwise-op results. Only the three multiplicity columns
are witness (range-unchecked; pinned to actual demand by the global
`Σ σ = 0` balance, per the fixed-consume invariant).

Because `LookupBuilder` has no preprocessed accessor, the LogUp eval
reads the data and multiplicities together through a combined
`[preprocessed ++ main]` window (`logup::CombinedWindow`); the
prover-side `build_aux` reconstructs the table and prepends it
identically. The preprocessed flip shipped in commit `8fbd826`; see
`docs/byte-pair-lut-preprocessed.md` for the implemented design.
