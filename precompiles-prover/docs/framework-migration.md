# Framework migration: `miden-lifted-stark` 0.24 → 0.26

Assessment of adopting the newer upstream framework to (1) **close the
BytePairLut soundness gap** via preprocessed columns and (2) gain
**per-AIR quotient degree** (heterogeneous constraint degrees). Backed by
a throwaway-branch dependency spike (2026-06).

> **Status — executed (2026-06, branch `feat-framework-0.26`).** Steps 1–6
> below are done: library + **287 tests** (273 lib + 14 ignored prove/verify
> round-trips) + all 4 examples green on 0.26. Step 3 went further than
> planned — the σ/n-cyclic adapter was **dropped** for a natural last-row
> σ-closing (no `inv_n`), so `eval_external` just sums the per-AIR σ. One
> measured cost: that closing's `when_transition` gate adds +1 degree to the
> σ-hosting column, taking `chunk` and `keccak_node` from lqd 2 → 3. Step 6
> (the BPL preprocessed flip — the soundness goal) **shipped** in commit
> `8fbd826`; it took a combined `[preprocessed ++ main]` window rather than a
> `builder.preprocessed()` read (see step 6 below). Step 7 is optional.

## Verdict

**Adoptable now, and worth it — no dependency-substrate blocker.** Both
features shipped in the *stable, published* `0.26.0` (crates.io,
2026-06-02), and that release drops onto our **existing** p3 / miden
substrate. Adoption is a bounded, single-branch **API migration** (the
two `[BREAKING]` changes below), not the multi-repo version-cascade an
earlier read of the `next` branch suggested.

> Earlier worry, now retracted: the `0xMiden/crypto` **`next`** branch is
> on p3 0.6 / miden-crypto 0.27, which *would* force a substrate cascade.
> But `next` is **0.27-dev**; the **published 0.26** predates that jump and
> is still p3 0.5.x / miden-crypto 0.24. Adopting 0.26 ≠ adopting `next`.

## What we're on vs. what we'd adopt

| | Current | Target (0.26) | `next` (0.27-dev) |
|---|---|---|---|
| `miden-lifted-air` / `-stark` | 0.24 (crates.io) | **0.26** | 0.27-dev (git) |
| p3-* | 0.5.2 | **0.5.2** (unchanged) | 0.6 |
| miden-crypto | 0.24 | **0.24** (unchanged) | 0.27 |
| miden-core / -air | miden-vm rev (0.23) | **unchanged** | — |

The framework also relocated repos (miden-vm → `0xMiden/crypto`, under
`stark/`), but the published crates are consumed from crates.io exactly as
today.

## Spike evidence (throwaway branch, `cargo check`)

Bumping only `miden-lifted-{air,stark}` to `0.26` in `Cargo.toml`:

- **Resolver added only the 4 miden crates** (air/stark/transcript/hasher
  0.26); the lockfile kept **`p3-field 0.5.2`** and **`miden-crypto
  0.24.0`** — no p3 0.6, no crypto 0.27 pulled. So 0.26 is API-compatible
  with our substrate.
- `cargo check` produced **34 errors, all `E0432` unresolved imports** of
  *removed* symbols — **zero `Felt: Field` / p3 / miden-crypto type
  errors**. Breakdown:
  - `AuxBuilder` — ~15 files
  - `ReducedAuxValues`, `VarLenPublicInputs` — ~17 files
  - `prove_multi` / `verify_multi` / `AirInstance` / `AirWitness` — `prove.rs`
  - `PcsParams` / `StarkDigest` / `StarkProof` — `stark_config.rs`
- The eval-side **`builder.preprocessed()`** accessor (p3 `AirBuilder`,
  re-exported by lifted-air; used in lifted-air 0.26's own `debug.rs`)
  compiled against our **p3 0.5.2** — so reading preprocessed columns in
  `eval` works on our substrate.

Same p3/crypto versions ⇒ the same trait our `Felt` already satisfies
under 0.24; the resolver short-circuits at imports, so the full
trait-instantiation pass runs only after the import/driver layer is
migrated, but there is no version-level reason for it to fail.

## The 0.26 API (relevant deltas)

- `BaseAir` (now re-exported from `p3_air`): `width()`,
  `preprocessed_trace() -> Option<RowMajorMatrix<F>>` (default `None`),
  read in `eval` via `AirBuilder::preprocessed()`.
- `LiftedAir`: gains `preprocessed_width()` (default 0) and
  `constraint_degree() -> ConstraintDegrees { base, ext }` (split
  base-/extension-field degree maxima). **`build_aux_trace` moves onto
  `LiftedAir`** with a new signature `(main, air_inputs, aux_inputs,
  challenges)` — the separate `AuxBuilder` trait is gone. `periodic_columns()`
  stays. `reduced_aux_values` / `num_var_len_public_inputs` are **removed**.
- New `MultiAir<F, EF>` trait (`type Air`, `airs()`, `eval_external(...)`,
  `observe(...)`): owns its AIRs and carries the cross-AIR σ reduction that
  `reduced_aux_values` used to do.
- Driver: `Statement` / `ProverStatement`, `ProverInstance::new(config,
  stmt, preprocessed)`, and `Preprocessed::build(statement, config)` (auto
  per-AIR `preprocessed_trace()` → committed bundle, observed into
  Fiat-Shamir). Replaces `prove_multi` / `verify_multi` / `AirInstance` /
  `AirWitness`.

Changelog refs: preprocessed `#1021`; per-AIR native quotient cosets
`#991`; MultiAir + aux-fold + Statement `#992`; reduced_aux_values →
eval_external `#992` — all `0.26.0`.

## Per-AIR quotient degree — prover-perf, not just verifier width

`#991` evaluates each AIR's quotient on its **native coset** (`n_j · D_j`)
instead of the global maximum. So a chiplet whose max constraint degree is
3 (`log_quotient_degree = 1`, quotient blowup ×2) stops riding
Poseidon2's degree-9 (`lqd = 3`, blowup ×8) quotient — **~4× less
quotient LDE work** for that chiplet, on top of the recursive-verifier
opening-width win in [architecture.md](architecture.md#width-vs-area-design-for-the-recursive-verifier).
For the non-P2 chiplets (the bulk of trace area) this is the dominant
prover-throughput lever.

**Nuance (the catch).** Per-AIR `lqd` is derived from
`max(base, ext)` degree — `ConstraintDegrees` reports them separately, but
the quotient is one domain per AIR sized to the higher. So a non-P2
chiplet reaches `lqd = 1` only if **both** its main (`base`) **and** its
LogUp aux (`ext`) constraints are ≤ degree 3. Today the LogUp columns
are allowed up to degree 9 (the "degree-9 / lqd-3 budget" in the chiplet
docs), so chiplets sitting there stay at `lqd = 3`. Dropping them needs
the aux degree brought down too — e.g. splitting σ batches into more,
lower-degree columns (trading aux *columns* for lower *degree*). That is
the **opposite** of today's "narrow within a fixed degree budget"
pressure, and per-AIR `lqd` is exactly what makes the trade pay (the
blowup saving is now local to the chiplet). Free for chiplets already
≤ 3; a deliberate redesign for those at higher aux degree.

This is *not* the separate main-vs-aux blowup that
[architecture.md](architecture.md#mixed-degree-blowup-assumption)
designs toward (blowup is still one global PCS `log_blowup`, with `lqd ≤
log_blowup`). But the `base`/`ext` split in `ConstraintDegrees` is the
building block, and per-AIR quotient sizing already delivers the part that
moves cost.

## Migration plan

A single focused branch; substrate untouched.

1. **Bump** `Cargo.toml`: `miden-lifted-{air,stark}` 0.24 → 0.26 (hasher
   follows transitively). Nothing else.
2. **Fold `AuxBuilder` into `LiftedAir::build_aux_trace`** for the 15 AIRs:
   move each `*Prover`'s body onto its AIR under the new signature
   (`air_inputs` / `aux_inputs` unused → empty for now); delete the
   `ChipletProver` enum. The `logup::build_logup_aux_trace` helper is
   unchanged, just called from the AIR. *Mechanical.*
3. **Replace `reduced_aux_values` with `MultiAir::eval_external`**: a
   `ChipletMultiAir` owns the 15 AIRs; the σ closure
   (`single_sigma_reduced_aux` / `NUM_SIGMA_VALUES`) moves into
   `eval_external`. Drop `ReducedAuxValues` / `VarLenPublicInputs`.
   *Highest-risk step — the σ/n reduction is load-bearing.*
4. **Rewrite the driver** (`session/prove.rs`): build `Statement` /
   `ProverStatement`, `Preprocessed::build`, `ProverInstance`; swap
   `prove_multi` / `verify_multi` / `check_constraints` for the 0.26
   equivalents. Fix the `stark_config.rs` renames.
5. **Verify**: full suite green (287, after dropping the now-obsolete
   `reduced_aux_values` / `air_validates` tests), behaviour unchanged — BPL
   still on the witness layout at this point.
6. **Close the BPL gap** (`#1021`, the goal — small, isolated).
   **Done — commit `8fbd826`.** In `BytePairLutAir`, override
   `preprocessed_width() = 4` + `BaseAir::preprocessed_trace()` returning
   the enumerated `2¹⁶ × 4` `(a, b, c_andnot, c_xor)` table; drop those
   columns from the main trace (only the 3 multiplicities remain witness).
   **Deviation from this plan:** the eval could *not* simply switch its
   data reads to `builder.preprocessed()` — our LogUp runs through the
   miden-vm lookup framework, whose `LookupBuilder` exposes only `main()`
   (no preprocessed accessor, and `current_slice()` must be one contiguous
   slice). So the eval reads a combined `[preprocessed ++ main]` window:
   `logup::CombinedWindow` / `LookupMainWindow` (constraint side, gated on
   a `has_preprocessed` flag — probing `preprocessed()` panics for
   no-preprocessed AIRs) and a matching `build_aux` that prepends the
   reconstructed table (prover side). The interim-unsoundness notes in
   [chiplets/byte_pair_lut.md](chiplets/byte_pair_lut.md) /
   [byte-pair-lut-preprocessed.md](byte-pair-lut-preprocessed.md) have
   been removed.
7. **(Optional) Harvest per-AIR `lqd`**: it's automatic on 0.26; to push
   non-P2 chiplets to `lqd = 1`, audit their aux degree and split σ
   batches where it pays.

## Caveats

- The 34 import errors are the **first layer**; fixing them exposes
  signature-level follow-ons (e.g. `BaseAir::num_public_values` may have
  relocated, the `build_aux_trace` arity). Bounded and mechanical, but
  more than 34 edits.
- Keep **0.26 (adopt now)** distinct from **`next` / 0.27 (p3 0.6 +
  crypto 0.27)** — the latter is a separate, larger future bump and is
  *not* required for either feature here.
- Risk is concentrated in step 3 (the σ/n `eval_external` re-fit); do a
  one-chiplet vertical slice through steps 2–4 before the full roll-out.
