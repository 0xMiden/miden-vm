# Forward-looking

Open work, in rough order.

## Heterogeneous constraint degrees

Historically every constraint — bit binarity, the LogUp closing, etc. —
was evaluated on the same blowup-8 LDE. Splitting low-degree constraints
(binarity, range checks) onto a smaller subgroup needs both sub-AIR
composition (lifting) and quotient LDE-up; neither alone suffices.

**Adopted (2026-06, branch `feat-framework-0.26`):** `miden-lifted-stark`
0.26 evaluates each AIR's quotient on its **native coset** (per-AIR
`log_quotient_degree`), delivering the quotient-LDE-up half — a non-P2
chiplet at degree 3 pays quotient blowup ×2 instead of riding Poseidon2's
×8. Blowup is still a single global PCS factor (not separate main/aux),
so this is partial, but it's the part that moves cost. One subtlety from
the same migration: dropping the σ/n-cyclic adapter for the natural
last-row σ-closing adds +1 to the σ-hosting column's degree, nudging
`chunk` and `keccak_node` from lqd 2 to 3 (both sat exactly at the deg-5
boundary) — a small, localized give-back against the broad per-AIR win.
The upgrade also makes preprocessed columns expressible; the **BytePairLut
soundness fix** (its data columns → preprocessed) **shipped** in commit
`8fbd826` — the four data columns are now a fixed verifier-known table, so
the chiplet is sound. See [framework-migration.md](framework-migration.md).

The architectural [mixed-degree blowup assumption](architecture.md#mixed-degree-blowup-assumption)
makes its degree decisions under this regime.

## Prefer narrow traces over trace area, within a degree budget

A recursive verifier opens every committed column at each FRI query, so
the cost of the layer we recurse over tracks **opening width** (total
columns across all AIRs) × **query count**, not trace height — rows are
comparatively cheap (padding is paid once; per-row prover work
amortizes). Two orthogonal levers shrink that product:

- **Fewer queries** — raise the FRI blowup *rate* `ρ⁻¹`: a larger code
  distance means each query catches a cheating prover with higher
  probability, so fewer suffice. A protocol knob, independent of the AIR.
- **Fewer columns** — *this principle*: prefer the narrower trace even at
  some row cost. One dispatched AIR over N that re-commit a shared
  skeleton; packing that trades rows for columns; referencing values by
  pointer/id instead of committing the full intermediate.

**The caveat is constraint degree.** Narrowing (selector products, wider
LogUp batches) tends to raise the max degree `d`, and the quotient
`C / Z_H` (degree ≈ `(d−1)·n`) is committed as `2^⌈log₂(d−1)⌉` extra
columns — opened every query like any other. So a narrowing that crosses
a `log_quotient_degree` tier can hand back the opening width it saved
(this is *not* the FRI rate above — degree moves the column count, never
the query count). The rule: **narrow within a fixed degree budget** —
shave columns only while `log_quotient_degree` holds at its tier.

The per-column win is roughly constant (the opening plus the recursive
multiplier), so it compounds across many columns or proofs and is
negligible for a one-off handful. Applied here: the eval chip's central
hasher ([`transcript-eval.md`](transcript-eval.md)), bitwise64 carrier
chaining ([`chiplets/bitwise64-chaining.md`](chiplets/bitwise64-chaining.md)),
ptr-keyed domain relations.
