# KeccakSponge AIR (`hash::keccak::sponge::KeccakSpongeAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/keccak-sponge.md](../chiplets/keccak-sponge.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/hash/keccak/sponge/mod.rs`, `src/hash/keccak/sponge/program.rs`,
> `src/hash/keccak/sponge/trace.rs`.

## Purpose

The **sponge** chiplet performs the FIPS 202 sponge construction
(absorb + multi-rate `pad10*1` padding + squeeze) on top of the Keccak
[round chiplet's](keccak-round.md) 25-round / 3200-IP permutation cycle.
It does not own a permutation: one period (32 rows) drives **one** Keccak
permutation by handing that permutation its round-0 input lanes and its
round constants over [`Memory64`](relation-registry.md#4--memory64), and
reading the permutation's output back.

Per-invocation it **consumes** one request on the
[`KeccakSponge`](relation-registry.md#5--keccaksponge) bus
(`(sponge_seq_id, chunk_ptr, len_bytes)`), provided **externally** by the
transcript chiplet / orchestrator. It then walks the input as a chunk
tape — **consuming** lane values from [`Memory64`](relation-registry.md#4--memory64)
at a disjoint `CHUNK_ADDR_BASE` (= `2^48`, `src/hash/memory64.rs:38`)
sub-namespace produced by the chunk chiplet — XORs each rate lane into
the running state, applies the pad bytes by verifying its own
byte-decomposed columns (see "Byte-shadow columns" below) directly
against [`BytePairLut`](relation-registry.md#0--bytepairlut), and **provides**
the resulting state lanes back on
[`Memory64`](relation-registry.md#4--memory64) as the next permutation's
round-0 inputs. On the last block it consumes the final permutation output
(squeeze) for the 21 non-digest lanes, leaving the 4 digest lanes in
Memory64 for the transcript to read.

`sponge_seq_id` (the global row counter) anchors every per-row Memory64
address as a degree-1 expression in `sponge_seq_id` and the periodic
`p_idx`; the address algebra (`100·sponge_seq_id − 99·p_idx − 128`,
`… − 99·p_idx`, etc.) places each tuple in the round chiplet's IP space
so producer and consumer meet. See
[../chiplets/keccak-sponge.md](../chiplets/keccak-sponge.md) for the full
derivation.

## Core structure

One period = 32 rows = one absorption block = one Keccak permutation.
Within a period the periodic program classifies each row by `p_idx`:
rate XORin (`[0, 17)`), capacity passthrough (`[17, 25)`), the dedicated
lane-16 trailing-`0x80` row (`25`), the extra chunk-consume rows that mop
up last-block overshoot lanes (`[26, 29)`), and NOP slack (`[29, 32)`).
A row's *mutex* scenario (which absorb/padding class it runs) is selected
by witness gating flags; two *parallel* bus actions — the RC provide and
the last-block squeeze consume — ride along on state-lane rows
independently of the mutex scenario (`mod.rs` `LookupAir::eval`). A
trailing `act = 0` region pads the trace to a power of two and is inert on
every bus.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 67` (27 structural/padding/lane-value columns + 40 byte-shadow columns for `chunk`, `state_prev`, `state_new`, `cleared`, `padded`) |
| Period | `SPONGE_PERIOD = 32` rows = one absorption block / one Keccak permutation (`program.rs:37`) |
| Height | `(Σ num_blocks · 32)` rounded up to a power of two (min one period); trailing rows are `act = 0` padding (`trace.rs:390`) |
| Periodic columns | `NUM_PERIODIC_COLS = 11` verifier-computed (`program.rs:40`) |
| Aux width | `NUM_AUX_COLS = 24` LogUp columns |
| Exposed σ | `num_aux_values = NUM_SIGMA_VALUES` — a single σ residue aggregating all three buses, summed into the cross-AIR `Σ σ = 0` by `MultiAir::eval_external` (`logup::sigma_sum`) |

The chiplet exposes one σ residue; it nets the sponge's contribution
across all three buses (Memory64, BytePairLut, KeccakSponge) into one
running sum, kept per-bus-balanced by the bus-prefix-distinguished
encodings and Schwartz–Zippel on random α.

## Main columns

Indices follow the `COL_*` constants in `mod.rs`. Several `state_*` cells
are **role-polymorphic** — their meaning depends on the row class
(state-lane vs. the lane-16 `0x80` row), noted inline. "On rows" names the
row class where a cell is *constrained / used*; padding rows (`act = 0`)
and unrelated row classes leave a cell free (it then touches no bus and no
live constraint).

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `COL_SPONGE_SEQ_ID` | all | `[0, height)` | global sponge row counter, `+1` per row; base of every degree-1 address; carried in the `KeccakSponge` request so the transcript can derive the digest address |
| 1 | `COL_ACT` | all | `{0, 1}` | sticky-downward activity flag; multiplies every bus multiplicity, so trace-tail rows are bus-inert |
| 2 | `COL_BYTES_LEFT` | all (chain gated by `act`) | felt | bytes remaining to absorb; pinned to `len_bytes` at each invocation's first row by the `KeccakSponge` consume, `−8` per rate row, holds elsewhere (may underflow past the pad row — nothing reads it after) |
| 3 | `COL_IS_FIRST_BLOCK_OF_INVOCATION` | all | `{0, 1}` | `1` throughout an invocation's first absorption period; gates the prev-perm consume *off*, the capacity-init "provide 0" *on*, and the `state_prev = 0` pin |
| 4 | `COL_CHUNK_PTR` | all | chunk-tape offset | sponge-side cursor into the chunk chiplet's flat Memory64 tape; pinned to the invocation base by the `KeccakSponge` consume, `+1` per fired chunk consume within the invocation, jumps freely at invocation seams |
| 5 | `COL_IS_ZERO` | rate XORin rows (carried across period) | `{0, 1}` | past-pad indicator; monotone non-decreasing within the period; equals `is_last_block_period` past slot 17 |
| 6 | `COL_IS_CHUNK_AVAIL` | rate / extra rows (carried) | `{0, 1}` | chunks-available indicator; monotone non-increasing within the period; `1` iff the chunk chiplet provides at this row's chunk address |
| 7–14 | `COL_B_BEGIN`..`+8` (`b_0..b_7`) | last-block period (broadcast) | each `{0, 1}` | unary selector bits for `byte_offset ∈ [0, 7]`; exactly one fires on the last block, none elsewhere. `Σ_j b_j` is the inline `is_last_block_period`; `Σ_j j·b_j` is `byte_offset` |
| 15 | `COL_CHUNK_LO` | rate / extra rows | `[0, 2³²)` | chunk lane value, low half; Memory64-pinned when `is_chunk_avail = 1`, else pinned `0` by zero-fill |
| 16 | `COL_CHUNK_HI` | rate / extra rows | `[0, 2³²)` | chunk lane value, high half (same as 15) |
| 17 | `COL_STATE_PREV_LO` | state-lane rows / lane-16 `0x80` row | `[0, 2³²)` | **role-polymorphic**: prev-perm output lane (consumed) on state-lane rows; lane-16 *intermediate* (pre-`0x80`) on the `0x80` row. Low half |
| 18 | `COL_STATE_PREV_HI` | as 17 | `[0, 2³²)` | high half of `state_prev` |
| 19 | `COL_STATE_NEW_LO` | state-lane rows / lane-16 `0x80` row | `[0, 2³²)` | **role-polymorphic**: new lane value (provided, = perm-`n` round-0 input) on state-lane rows; lane-16 *final* (post-`0x80`) on the `0x80` row. Low half |
| 20 | `COL_STATE_NEW_HI` | as 19 | `[0, 2³²)` | high half of `state_new` |
| 21 | `COL_STATE_OUT_LO` | last-block state-lane rows where `p_squeeze_active` | `[0, 2³²)` | perm-`n` last-perm output for lane `p_idx`, consumed by the squeeze; Memory64-pinned by the round chiplet's output provide; free when squeeze gate off. Low half |
| 22 | `COL_STATE_OUT_HI` | as 21 | `[0, 2³²)` | high half of `state_out` |
| 23 | `COL_CLEARED_LO` | pad row (committed on all rate rows) | `[0, 2³²)` | pad-row intermediate `cleared = AndNot(andnot_mask, chunk)`; meaningful only on the pad row. Low half |
| 24 | `COL_CLEARED_HI` | as 23 | `[0, 2³²)` | high half of `cleared` |
| 25 | `COL_PADDED_LO` | pad row (committed on all rate rows) | `[0, 2³²)` | pad-row intermediate `padded = cleared XOR padding_mask`. Low half |
| 26 | `COL_PADDED_HI` | as 25 | `[0, 2³²)` | high half of `padded` |

### Byte-shadow columns

Five of the lane values above also carry an 8-byte little-endian
decomposition, each linked to its `_lo`/`_hi` halves by an ungated local
constraint (§Constraints) and consumed directly by the `BytePairLut`
byte requires (§Buses & lookups) — no intermediate chiplet.

| Range | Name | Linked to |
|-------|------|-----------|
| 27–34 | `CHUNK_BYTES_RANGE` (`chunk_bytes`) | `COL_CHUNK_LO/HI` |
| 35–42 | `STATE_PREV_BYTES_RANGE` (`state_prev_bytes`) | `COL_STATE_PREV_LO/HI` |
| 43–50 | `STATE_NEW_BYTES_RANGE` (`state_new_bytes`) | `COL_STATE_NEW_LO/HI` |
| 51–58 | `CLEARED_BYTES_RANGE` (`cleared_bytes`) | `COL_CLEARED_LO/HI` |
| 59–66 | `PADDED_BYTES_RANGE` (`padded_bytes`) | `COL_PADDED_LO/HI` |

Indices 0..66 inclusive = 67 columns = `NUM_MAIN_COLS`.

The following are **not** committed columns — they are degree-1 inline
expressions in `eval` (`mod.rs`):

- `is_last_block_period := Σ_j b_j`
- `byte_offset := Σ_j j·b_j`
- `is_state_lane := p_rate_block + p_capacity`
- `is_intra := 1 − is_first_block_of_invocation`
- `is_first_row_of_invocation := p_first · is_first_block_of_invocation`
- `is_pad := is_zero' − is_zero`
- `is_verbatim := 1 − is_zero'`
- `enters_new_invocation := p_last · is_first_block'`
- `andnot_mask`, `padding_mask` halves := `Σ_j MASK[j] · b_j`
  (mask tables `ANDNOT_MASK_{LO,HI}`, `PADDING_MASK_{LO,HI}`, `mod.rs:228`)

## Periodic columns (verifier-computed, uncommitted)

`NUM_PERIODIC_COLS = 11`, one value per `p_idx ∈ [0, 32)`, built by
`sponge_program()` (`program.rs:145`). Indices follow `program::COL_*`
(re-exported as `PCOL_*` in `mod.rs:178`).

| Idx | Name | Value at `p_idx` | Used for |
|-----|------|------------------|----------|
| 0 | `COL_IDX` | `p_idx` itself, `[0, 32)` | base of every degree-1 address expression |
| 1 | `COL_FIRST` | `1` iff `p_idx == 0` | row-0-of-period boundary |
| 2 | `COL_LAST` | `1` iff `p_idx == 31` | stands in for `p_first` of the next row in transition constraints (next-row periodics aren't readable) |
| 3 | `COL_RATE_BLOCK` | `1` iff `p_idx ∈ [0, 17)` | rate XORin rows; `bytes_left` decrement; chains; pad-lane tie-down |
| 4 | `COL_CAPACITY` | `1` iff `p_idx ∈ [17, 25)` | capacity rows |
| 5 | `COL_RC_ACTIVE` | `1` iff `p_idx ∈ [0, 24)` | gates the RC provide (Keccak has only 24 RCs; slot 24 carries none) |
| 6 | `COL_SQUEEZE_ACTIVE` | `1` iff `p_idx ∈ [4, 25)` | gates the last-block squeeze consume (skips digest lanes `[0, 4)`) |
| 7 | `COL_PAD_0X80` | `1` iff `p_idx == 25` | gates the lane-16 trailing-`0x80` row's Memory64 + BytePairLut emissions |
| 8 | `COL_RC_LO` | `RC[p_idx]` low u32 on `p_rc_active` rows, else `0` | RC value provided to Memory64 |
| 9 | `COL_RC_HI` | `RC[p_idx]` high u32 on `p_rc_active` rows, else `0` | RC value provided to Memory64 |
| 10 | `COL_EXTRA` | `1` iff `p_idx ∈ [26, 29)` | gates the extra chunk-consume rows (last-block overshoot lanes, paired with `b_sum`) |

The "state-lane" predicate `p_idx ∈ [0, 25)` is computed inline as
`p_state_lane = p_rate_block + p_capacity` (`mod.rs:332`) — no dedicated
column.

## Constraints

Local (Phase 1) row constraints from `LiftedAir::eval` (`mod.rs:317`),
grouped by purpose. Degrees count `Periodic`, `Main`, and `Aux`
symbolic variables at degree 1 each (Plonky3 convention; see
[README.md](README.md#degree-notes) and the chiplet doc's degree
discussion). Unless noted, a constraint is `when_transition`-gated
(cyclic wrap `N−1 → 0` excluded) or ungated; the one boundary constraint
is `when_first_row`.

### Boundary (`when_first_row`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `sponge_seq_id = 0` | 1 | row counter starts at 0 (convention; makes addresses interpretable). `chunk_ptr`, `act`, `is_first_block` are deliberately **not** pinned here so the zero-invocation (all-`act = 0`) trace stays valid |

### Activity and row counter

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 2 | `act · (1 − act) = 0` | 2 | activity flag is boolean |
| 3 | `when_transition: (1 − act) · act' = 0` | 2 | sticky-downward: forbids `0 → 1` within `[0, N−2]`; the wrap is left free so a 1's-prefix/0's-suffix trace cycles back to `act₀ = 1` |
| 4 | `when_transition: (act − act') · (1 − p_last · Σ_j b_j) = 0` | 2 | drop placement: the unique `1 → 0` transition must land at slot 31 (`p_last = 1`) of a last-block period (`Σ b_j = 1`) |
| 5 | `when_transition: sponge_seq_id' − sponge_seq_id − 1 = 0` | 1 | row counter increments by 1 (wrap left free) |

### `is_first_block_of_invocation` structure

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `is_first_block · (1 − is_first_block) = 0` | 2 | boolean |
| 7 | `(1 − p_last) · (is_first_block' − is_first_block) = 0` | 2 | constant within a period; `(1 − p_last)` lets it toggle freely at period boundaries (where the `KeccakSponge` consume + transcript `sponge_seq_id` pin which period starts an invocation) |

### `bytes_left` decrement chain (both branches gated by `act`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 8 | `act · p_rate_block · (bytes_left' − bytes_left + 8) = 0` | 3 | absorb row: decrement by 8 |
| 9 | `act · (1 − enters_new_invocation) · (1 − p_rate_block) · (bytes_left' − bytes_left) = 0` | 4 | non-absorb row, no invocation seam at next row: hold steady. The `enters_new_invocation = p_last · is_first_block'` factor releases the hold at the seam so `bytes_left` can reset to the next `len_bytes`. The `act` gate makes the all-dead trace vacuous (and is load-bearing: it admits the empty transcript while still forbidding the `act = 1 ∧ is_first_block = 0` cyclic-fixed-point forgery via `M·136 ≢ 0 mod p`) |

### `chunk_ptr` chain

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 10 | `when_transition: (1 − enters_new_invocation) · (chunk_ptr' − chunk_ptr − (p_rate_block + p_extra · Σ_j b_j) · is_chunk_avail) = 0` | 5 | advance `chunk_ptr` by 1 per fired chunk consume (rate rows every block + last-block extra rows for overshoot lanes), gated off at invocation seams where the `KeccakSponge` consume re-pins the base. No global enumeration-from-0; overlap/gap freedom comes from Memory64 balance vs. the chunk chiplet. **Highest-degree local constraint** (deg-2 seam gate × deg-3 advance term) |

### Chunk zero-fill (ungated)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 11 | `(1 − is_chunk_avail) · chunk_lo = 0` | 2 | pin chunk low half to 0 when no lane is provided, so a prover-chosen unpinned chunk can't steer a verbatim XOR; under-emission yields a deterministic zero-extended digest caught downstream |
| 12 | `(1 − is_chunk_avail) · chunk_hi = 0` | 2 | same for the high half |

### Padding state machine

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 13 | `is_zero · (1 − is_zero) = 0` | 2 | past-pad indicator is boolean |
| 14 | `is_chunk_avail · (1 − is_chunk_avail) = 0` | 2 | chunks-available indicator is boolean |
| 15 | `b_j · (1 − b_j) = 0`, `j ∈ [0, 8)` | 2 | each unary selector bit is boolean (8 constraints) |
| 16 | `(1 − p_last) · is_zero · (1 − is_zero') = 0` | 3 | `is_zero` non-decreasing within a period |
| 17 | `(1 − p_last) · (1 − is_chunk_avail) · is_chunk_avail' = 0` | 3 | `is_chunk_avail` non-increasing within a period (contiguous prefix) |
| 18 | `p_first · is_zero = 0` | 1 | pad hasn't fired at slot 0 of any period (every period starts fresh) |
| 19 | `(1 − p_last) · (b_j' − b_j) = 0`, `j ∈ [0, 8)` | 2 | selector bits constant within a period (8 constraints) |
| 20 | `(1 − p_rate_block) · (Σ_j b_j − is_zero) = 0` | 2 | on non-absorb rows the selector sum ties to `is_zero` (= `is_last_block_period` there) |

### Pad placement (gated by `act`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 21 | `act · p_last · is_first_block' · (1 − is_zero) = 0` | 4 | pad-must-fire: at slot 31 of an active period followed by a new invocation, force `is_zero = 1` — a new invocation may only begin right after a padded last block, so no invocation is truncated. The `act` gate makes the dead-region → row-0 wrap vacuous so any block count is admissible |
| 22 | `p_rate_block · (is_zero' − is_zero) · (Σ_j j·b_j − bytes_left) = 0` | 2 | pad-lane tie-down: on the unique pad transition row, pin `byte_offset = bytes_left ∈ [0, 7]`. The `p_rate_block` factor also absorbs the period-wrap `is_pad = −1` case (lands on slot 31 where `p_rate_block = 0`) |

### State witness pins

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 23 | `p_state_lane · is_first_block · state_prev_lo = 0` | 2 | no prev-perm on a first block: pin `state_prev = 0` so `state_new = state_prev ⊕ chunk` yields `state_new = chunk` (rate) / `0` (capacity). Low half |
| 24 | `p_state_lane · is_first_block · state_prev_hi = 0` | 2 | high half of #23 |
| 25 | `p_rate_block · is_zero · (state_new_lo − state_prev_lo) = 0` | 3 | past-pad rate row (garbage/zero-tail): state propagates `state_new = state_prev` (no `BytePairLut` request fires). Low half |
| 26 | `p_rate_block · is_zero · (state_new_hi − state_prev_hi) = 0` | 3 | high half of #25 |
| 27 | `p_capacity · (state_new_lo − state_prev_lo) = 0` | 2 | capacity identity passthrough `state_new = state_prev`. Low half |
| 28 | `p_capacity · (state_new_hi − state_prev_hi) = 0` | 2 | high half of #27 |

Rate XORin rows with `is_zero = 0` (verbatim and pad-row classes) and the
lane-16 `0x80` row have `state_new` pinned by their `BytePairLut` byte
requires (§Buses & lookups), so they need no local state constraint.

### Byte-shadow linking (ungated)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 29–38 | `pack_le(x_bytes[0..4], 256) − x_lo = 0`, `pack_le(x_bytes[4..8], 256) − x_hi = 0`, for `x ∈ {chunk, state_prev, state_new, cleared, padded}` | 2 | pins each byte-shadow range (§Byte-shadow columns) to its `_lo`/`_hi` halves, so a `BytePairLut`-verified byte result is also the value every other bus message (Memory64 prev-perm consume, new-state provide, chunk consume) reads. Ungated: both sides are otherwise free witness on rows where the value is unused, so an honest prover always satisfies this by construction (10 constraints) |

**Local degree summary.** Max local witness-degree is **5** (constraint
#10, the `chunk_ptr` chain), then deg 4 (#9 `bytes_left` non-absorb, #21
pad-must-fire). All other local constraints are deg ≤ 3. The lookup
constraints set the chiplet's `log_quotient_degree = 3` (col 0 reaches
constraint deg 7), so the local constraints sit below the LogUp ceiling
(see the chiplet doc's constraint-degree summary).

## Buses & lookups

`NUM_AUX_COLS = 24`. Sign convention: **provide = `−k`**, **consume =
`+k`**; every multiplicity is also multiplied by `act` so trace-tail
rows touch no bus.

The sponge touches three buses, all defined in `src/relations.rs`:

- [`Memory64`](relation-registry.md#4--memory64) (id 4) — provided
  **externally** (multiset bus; the round chiplet, this sponge, and the
  chunk chiplet are all producers/consumers at disjoint IP/address
  ranges).
- [`BytePairLut`](relation-registry.md#0--bytepairlut) (id 0) — provided
  by the leaf `BytePairLut` table; the sponge issues 8 byte-wise
  requires per pad/absorb XOR/ANDNOT op directly on its byte-shadow
  columns.
- [`KeccakSponge`](relation-registry.md#5--keccaksponge) (id 5) —
  provided **externally** by the transcript chiplet / orchestrator; the
  sponge only consumes the per-invocation request.

So the sponge **provides** only Memory64 tuples (new-state, RC,
lane-16 final) and **consumes** Memory64, BytePairLut, and KeccakSponge
tuples. Address expressions are degree-1 in `sponge_seq_id`, `p_idx`,
`chunk_ptr`; on gated-off rows some go integer-negative and wrap, but
`mult = 0` zeroes their LogUp contribution.

### Provides

All on [`Memory64`](relation-registry.md#4--memory64) `(addr, lo, hi)`:

| Insert | Address | Multiplicity | Fires on |
|--------|---------|--------------|----------|
| new-state | `100·sponge_seq_id − 99·p_idx` | `−2 · act` | state-lane rows (`p_state_lane`) |
| RC[p_idx] | `100·sponge_seq_id + 28·p_idx + 25` | `−3 · act · p_rc_active` | state-lane rows where `p_rc_active` (`p_idx ∈ [0, 24)`); value = `(rc_lo, rc_hi)` |
| lane-16 final | `100·sponge_seq_id − 2484` | `−2 · act · Σ_j b_j` | lane-16 `0x80` row (`p_pad_0x80`), last block; value = `(state_new_lo, state_new_hi)` |

### Consumes

| Bus | Insert | Address / tuple | Multiplicity | Fires on |
|-----|--------|-----------------|--------------|----------|
| [`Memory64`](relation-registry.md#4--memory64) | prev-perm | `(100·sponge_seq_id − 99·p_idx − 128, state_prev_lo, state_prev_hi)` | `+2 · act · is_intra` | state-lane rows, non-first-block (`is_intra = 1 − is_first_block`) |
| [`Memory64`](relation-registry.md#4--memory64) | squeeze | `(100·sponge_seq_id − 99·p_idx + 3072, state_out_lo, state_out_hi)` | `+2 · act · p_squeeze_active · Σ_j b_j` | state-lane rows where `p_squeeze_active` (`p_idx ∈ [4, 25)`), last block |
| [`Memory64`](relation-registry.md#4--memory64) | lane-16 intermediate | `(100·sponge_seq_id − 2484, state_prev_lo, state_prev_hi)` | `+2 · act · Σ_j b_j` | lane-16 `0x80` row, last block |
| [`Memory64`](relation-registry.md#4--memory64) | chunk-consume | `(CHUNK_ADDR_BASE + chunk_ptr, chunk_lo, chunk_hi)` | `act · (p_rate_block + p_extra · Σ_j b_j) · is_chunk_avail` | rate rows + last-block extra rows where chunks available |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | pad-row andnot, ×8 bytes | `(AndNot, andnot_mask_bytes[i], chunk_bytes[i], cleared_bytes[i])` | `act · p_rate_block · is_pad` | the pad row |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | pad-row xor-padding, ×8 bytes | `(Xor, cleared_bytes[i], padding_mask_bytes[i], padded_bytes[i])` | `act · p_rate_block · is_pad` | the pad row |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | pad-row xor-state, ×8 bytes | `(Xor, state_prev_bytes[i], padded_bytes[i], state_new_bytes[i])` | `act · p_rate_block · is_pad` | the pad row |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | verbatim xor-state, ×8 bytes | `(Xor, state_prev_bytes[i], chunk_bytes[i], state_new_bytes[i])` | `act · p_rate_block · is_verbatim` | verbatim rate rows |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | lane-16 xor, ×8 bytes | `(Xor, state_prev_bytes[i], PAD_CONST_BYTES[i], state_new_bytes[i])` | `act · p_pad_0x80 · Σ_j b_j` | lane-16 `0x80` row, last block (`PAD_CONST_BYTES[7] = 0x80`, all others `0`) |
| [`KeccakSponge`](relation-registry.md#5--keccaksponge) | request | `(sponge_seq_id, chunk_ptr, len_bytes=bytes_left)` | `act · is_first_row_of_invocation` | first row of each invocation (`p_first · is_first_block`) |

`andnot_mask_bytes[i]` / `padding_mask_bytes[i]` are periodic-derived
degree-1 expressions (`Σ_j b_j · mask_byte(...)`), extracted byte-by-byte
from the `ANDNOT_MASK_{LO,HI}` / `PADDING_MASK_{LO,HI}` constants — not
witness columns.

### Column packing

`NUM_AUX_COLS = 24`, 48 fractions total:

- **Col 0** (2 fractions): `new-state` provide + `prev-perm` consume —
  the two lowest-degree fractions, so the gated last-row close stays at
  the chiplet's constraint-degree ceiling.
- **Col 1** (3 fractions): `RC` provide + `lane-16 intermediate` consume
  + `lane-16 final` provide.
- **Col 2** (1 fraction): `squeeze` consume, alone (its degree-4
  multiplicity is the floor).
- **Cols 3–22** (20 columns, 2 fractions each = 40 fractions): the five
  `BytePairLut` byte-request groups above, 8 bytes each, two bytes per
  column.
- **Col 23** (2 fractions): the `KeccakSponge` request + the Memory64
  chunk-consume — two independent inserts on different buses, never
  colliding (distinct buses, and the request fires only on the
  invocation's first row); the bus-prefix-distinguished encodings keep
  their denominators distinct, so they share one column.

Within each column the multiplicities are one-hot by row (a selector /
periodic flag fires on at most the relevant row class) or on genuinely
independent buses, so the shared running sum is sound.
