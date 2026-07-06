# Poseidon2 AIR (`transcript::poseidon2::Poseidon2Air`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/poseidon2.md](../chiplets/poseidon2.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/transcript/poseidon2/mod.rs`, `src/transcript/poseidon2/trace.rs`.

## Purpose

A **source** chiplet for the Poseidon2-f[12] permutation. It mints two
relations and consumes none from peers: it **provides** the input state
on [`Poseidon2In`](relation-registry.md#6--poseidon2in) (three 4-felt
chunks `rate0`/`rate1`/`capacity`, tag-discriminated) and the
post-permutation digest on
[`Poseidon2Out`](relation-registry.md#7--poseidon2out), both keyed by a
per-cycle `perm_seq_id`. The chiplet's `state[0..12]` rows *are* the
permutation: row 0 holds the prover-committed input, the 16-row schedule
evolves it, and row 15 holds the output — `state[0..4]` of which is the
exposed digest.

One permutation = one 16-row cycle. **Absorption chains** are in-trace:
a cycle flagged `is_absorb = 1` inherits its input capacity from the
previous cycle's row-15 capacity through a transition constraint, so the
intermediate capacity never crosses the bus — only the chain head's
`InCap` and the chain tail's `OutRate0` are published.

⚠ The earlier `Range16` consume on the two multiplicity cells has been
**removed** in this revision (it is *not* gated off conditionally — there
is no `Range16` insert in `LookupAir::eval` at all). Multiplicities are
plain `ProvideMult` (`u32`) counts pinned to their In/Out consumer counts
by bus balance, under the VM-wide fixed-consume invariant; the chiplet
consumes nothing from any bus. See
[../lookup-argument.md](../lookup-argument.md).

## Core structure (packed 16-row schedule)

Same packed schedule as Miden's hasher chiplet: 8 external + 22 internal
rounds folded into 16 rows. Each row applies at most one S-box layer
(keeping the per-row constraint at degree 7 before gating), so the round
boundaries are merged:

| Row(s) | Step | Selector | Witnesses |
|--------|------|----------|-----------|
| 0 | init linear + ext1: `h' = M_E(S(M_E(h) + ark))` | `is_init_ext` | none |
| 1–3 | single ext: `h' = M_E(S(h + ark))` | `is_ext` | none |
| 4–10 | 3× packed internal | `is_packed_int` | `w[0..3]` (lane-0 S-box outs) |
| 11 | int22 + ext5 (`ARK_INT[21]` hardcoded) | `is_int_ext` | `w[0]` |
| 12–14 | single ext | `is_ext` | none |
| 15 | boundary (final state, no transition) | (none) | none |

The four step selectors are mutex and partition rows 0–14; all four are
0 on row 15. Their complement
`p_last_in_cycle = 1 − is_init_ext − is_ext − is_packed_int − is_int_ext`
fires exactly on row 15 and gates the cycle-boundary constraints with no
extra periodic column.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 19` |
| Period | `PERIOD = 16` rows = one permutation cycle |
| Height | `(total_cycles · 16)` rounded up to a power of two (min `16`); trailing cycles are padding (`in_mult = out_mult = 0`, only `perm_seq_id` non-zero) |
| Periodic columns | `16` (`NUM_PERIODIC_COLS = 4 + 12`): 4 step selectors + 12 `ark` lanes (verifier-computed, uncommitted) |
| Aux width | `1` = a single LogUp running-sum column (`NUM_AUX_COLS = 1`, `COLUMN_SHAPE = [4]`); no Schwartz–Zippel register |

The 19 main columns split into three groups (per the `mod.rs` layout
comment): 4 **cycle-constant** scalars, the 12-lane sponge state, and 3
S-box witnesses.

## Main columns

Columns 0–3 are **cycle-constant** (held equal across the 16-row block by
transition constraints). Columns 4–15 are the 12 state lanes
(`COL_STATE_BEGIN = 4`, capacity at `COL_CAPACITY_BEGIN = 12`); their
*meaning* depends on the row (row 0 = input, row 15 = output, interiors =
intermediate round states). Columns 16–18 are S-box witnesses, live only
on the packed-internal and int+ext rows.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `COL_PERM_SEQ_ID` | all | `[0, height/16)` (canonical Goldilocks) | cycle-constant permutation id; cycle K holds value K. Bus key; increments by 1 per cycle |
| 1 | `COL_IN_MULTIPLICITY` | all | `[0, 2³²)` (`ProvideMult`) | cycle-constant; caller-side consume count of the In-side tuples (`InCap`/`InRate0`/`InRate1`). Pinned by bus balance, **not** range-checked |
| 2 | `COL_OUT_MULTIPLICITY` | all | `[0, 2³²)` (`ProvideMult`) | cycle-constant; caller-side consume count of the `OutRate0` digest. May exceed `in_mult` (one creator, many readers). Pinned by balance, not range-checked |
| 3 | `COL_IS_ABSORB` | all | `{0, 1}` | cycle-constant chain selector; `1` ⇒ this cycle inherits input capacity from the previous cycle's row-15 capacity (no caller `InCap`) |
| 4–15 | `state[0..12]` | all | each `∈ Goldilocks` | the 12 sponge lanes `[rate0[4], rate1[4], capacity[4]]`. Row 0 = input state, row 15 = output; `state[0..4]` at row 15 = digest. Interior rows hold the per-step intermediate state |
| 16 | `w[0]` (`COL_WITNESS_BEGIN`) | 4–10, 11 | each `∈ Goldilocks` | lane-0 S-box output witness; round 0 of a packed triple (rows 4–10) and the int leg of row 11. Forced `0` on all other rows |
| 17 | `w[1]` | 4–10 | each `∈ Goldilocks` | lane-0 S-box output witness, round 1 of a packed triple. Forced `0` off packed-internal rows |
| 18 | `w[2]` | 4–10 | each `∈ Goldilocks` | lane-0 S-box output witness, round 2 of a packed triple. Forced `0` off packed-internal rows |

### Periodic columns (verifier-computed, uncommitted)

16 columns over the 16-row period (`poseidon2_program`); they add no
opening width.

| Col | Name | Fires on | Content |
|-----|------|----------|---------|
| 0 | `PCOL_IS_INIT_EXT` | row 0 | init-linear + ext1 selector |
| 1 | `PCOL_IS_EXT` | rows 1–3, 12–14 | single-external selector |
| 2 | `PCOL_IS_PACKED_INT` | rows 4–10 | packed-3×-internal selector |
| 3 | `PCOL_IS_INT_EXT` | row 11 | int22 + ext5 selector |
| 4–15 | `ark[0..12]` (`PCOL_ARK_BEGIN`) | per schedule | per-lane round constants: `ARK_EXT_INITIAL[0..4]` (rows 0–3); `ARK_INT[3·triple + k]` in lanes 0–2, zeros elsewhere (rows 4–10); `ARK_EXT_TERMINAL[0]` (row 11, int leg uses hardcoded `ARK_INT[21]`); `ARK_EXT_TERMINAL[1..4]` (rows 12–14); all-zero (row 15) |

`p_last_in_cycle` (row 15) is *derived* from the four selectors, not a
column.

## Constraints

Step-transition (Phase 1 poly) constraints reach **degree 9**
(`activity` × selector × S-box = `1 + 1 + 7`), the chiplet-wide ceiling
fixing `log_quotient_degree = 3`. All structural constraints are degree
≤ 3. Degrees count periodic columns at degree 1.

Throughout, `activity = in_multiplicity + out_multiplicity` (degree 1; a
sum of two cycle-constant columns). Step transitions are gated by
`activity`, so a padding cycle (`activity = 0`) vacuates the Poseidon2
algebra — the prover zero-fills rather than evaluating a dummy
permutation. The gate also blocks the `in_mult = 0, out_mult > 0`
fake-digest attack: any live cycle runs the real permutation of the
committed row-0 state.

### Boundary (`when_first_row`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `perm_seq_id = 0` | 1 | the cycle counter starts at 0; bus addresses are interpretable from there |
| 2 | `is_absorb = 0` | 1 | cycle 0 is a fresh perm / chain head, never a continuation — eliminates the wrap-chain mode across the `perm_seq_id` discontinuity |

### `perm_seq_id` chain

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `(1 − p_last_in_cycle) · (perm_seq_id' − perm_seq_id) = 0` | 2 | cycle-constant within a cycle (rows 0–14) |
| 4 | `when_transition: p_last_in_cycle · (perm_seq_id' − perm_seq_id − 1) = 0` | 2 | increments by 1 across each cycle boundary; the row-15→row-0 wrap is left to the boundary + per-cycle step to pin `0, 1, 2, …` |

### Multiplicity constancy

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `(1 − p_last_in_cycle) · (in_multiplicity' − in_multiplicity) = 0` | 2 | `in_mult` cycle-constant; visible at the row-0 In provides and row-15 (unused but balanced) |
| 6 | `(1 − p_last_in_cycle) · (out_multiplicity' − out_multiplicity) = 0` | 2 | `out_mult` cycle-constant; visible at the row-15 Out provide |

Neither carries a range or binarity constraint — each is pinned to its
bus's `+1`-weighted consumer count by balance.

### `is_absorb` structure

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 7 | `is_absorb · (1 − is_absorb) = 0` | 2 | chain selector is boolean (`assert_bool`) |
| 8 | `(1 − p_last_in_cycle) · (is_absorb' − is_absorb) = 0` | 2 | cycle-constant; the prover toggles freely *between* cycles, chain coherence enforced by capacity-carry + bus |

### Capacity carry (cycle boundary)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 9 | `p_last_in_cycle · is_absorb' · (state'[i] − state[i]) = 0`, `i ∈ [8, 12)` | 3 | if the next cycle is an absorb continuation, its row-0 input capacity equals this cycle's row-15 output capacity — threads capacity without publishing it. Off-boundary rows have `p_last_in_cycle = 0` |

### Poseidon2 step transitions

Each is gated `activity · selector`; expansions follow the `math.rs`
helpers (`apply_init_plus_ext`, `apply_single_ext`,
`apply_packed_internals`, `apply_internal_plus_ext`) exactly. `MAT_DIAG`,
`ARK_*` come from `Hasher`.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 10 | `activity · is_init_ext · (state'[i] − apply_init_plus_ext(state, ark)[i]) = 0`, `i ∈ 0..12` | 9 | row-0 merged init-linear + ext1; one S-box layer over affine `(M_E(h) + ark)` |
| 11 | `activity · is_ext · (state'[i] − apply_single_ext(state, ark)[i]) = 0`, `i ∈ 0..12` | 9 | single external round `M_E(S(h + ark))` (rows 1–3, 12–14) |
| 12 | `activity · is_packed_int · check_k = 0`, `k ∈ 0..3`, where `check_k = w[k] − (state₀^{(k)} + ark_int[k])⁷` | 9 | three lane-0 S-box witness checks per packed triple (rows 4–10) |
| 13 | `activity · is_packed_int · (state'[i] − apply_packed_internals(…)[i]) = 0`, `i ∈ 0..12` | 5 | next-state after 3 internal rounds, affine in the witnesses (deg 1) under the deg-1 gate + deg-1 selector → low |
| 14 | `activity · is_int_ext · int_ext_check = 0`, `int_ext_check = w[0] − (state[0] + ARK_INT[21])⁷` | 9 | row-11 int-leg lane-0 S-box witness check (`ARK_INT[21]` hardcoded, not a periodic column) |
| 15 | `activity · is_int_ext · (state'[i] − apply_internal_plus_ext(state, w[0], ARK_INT[21], ark, MAT_DIAG)[i]) = 0`, `i ∈ 0..12` | 9 | row-11 merged int22 + ext5 next-state; one external S-box layer over the affine internal substitution |

### Witness zeroing (ungated)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 16 | `(1 − is_packed_int − is_int_ext) · w[0] = 0` | 2 | `w[0]` is meaningful only on packed-internal + int+ext rows; zero elsewhere so it can't leak into other rows' algebra |
| 17 | `(1 − is_packed_int) · w[k] = 0`, `k ∈ {1, 2}` | 2 | `w[1]`, `w[2]` live only on packed-internal rows |

These are left ungated by `activity`: on padding rows the witnesses are
already zero by construction, so no constraint is imposed there beyond
the trivial.

## Buses & lookups

`COLUMN_SHAPE = [4]` — one LogUp column batching 4 fractions total
(3 in batch A + 1 in batch B), in a single group `poseidon2-bus`.

This chiplet **provides** both Poseidon2 buses and **consumes none**
(the prior `Range16` requires were removed; multiplicities are pinned by
balance, not range-checked).

### Provides

The per-row fired multiplicity folds the batch outer flag into the
fraction's inner multiplicity. Sign convention: provide = `−m`.

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, 0, state[0..4])` (`InRate0`) | `−in_multiplicity · is_init_ext` | row 0 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, 1, state[4..8])` (`InRate1`) | `−in_multiplicity · is_init_ext` | row 0 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id, 2, state[8..12])` (`InCap`) | `−in_multiplicity · (1 − is_absorb) · is_init_ext` | row 0 |
| [`Poseidon2Out`](relation-registry.md#7--poseidon2out) (7) | `(perm_seq_id, state[0..4])` (digest) | `−out_multiplicity · (1 − is_absorb') · p_last_in_cycle` | row 15 |

`InCap`'s `(1 − is_absorb)` factor suppresses the capacity provide on
chain-interior/tail cycles (capacity is inherited, not published).
`OutRate0`'s `(1 − is_absorb')` reads the *next* row's `is_absorb` (a
first-class next-row LogUp window access) so the digest is published only
by a chain tail (`is_absorb' = 0`). Both multiplicities are plain counts
pinned to their consumer counts by bus balance — no range check.

### Consumes

None. ⚠ Earlier revisions consumed two
[`Range16`](relation-registry.md#1--range16) (1) tuples here (one per
multiplicity) as defense-in-depth; this revision removes them entirely
— there is no `Range16` insert in `LookupAir::eval`, and `generate_trace`
documents that "the chiplet consumes no `Range16`."

### Mutex batching

The four fractions split into two **periodic-disjoint** batches within
the single group (`is_init_ext · p_last_in_cycle = 0`, so at most one
batch is live on any row, capping the per-row fraction count at the
larger batch):

- **Batch A** (`row0`, outer flag `is_init_ext`, 3 fractions): the three
  `Poseidon2In` provides at row 0.
- **Batch B** (`row15`, outer flag `p_last_in_cycle`, 1 fraction): the
  lone `Poseidon2Out` provide at row 15.

Because the two flags are mutually exclusive across the period, the group
soundly shares one running sum. The resulting column constraint degree is
**5** (`v_g = max(n_A·f_A, n_B·f_B)` with `n_A = 4`), comfortably below
the deg-9 step-transition ceiling, so the bus is not the binding
constraint and `log_quotient_degree` stays at 3.
