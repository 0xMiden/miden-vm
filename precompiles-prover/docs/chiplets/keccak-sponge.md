# Keccak sponge chiplet

> **AIR reference:** [`airs/keccak-sponge.md`](../airs/keccak-sponge.md) — complete column / constraint / bus reference for this chiplet.

Sponge AIR over the [round chiplet's](keccak.md) 25-round /
3200-IP permutation cycle. One row per state lane, period 32 →
α = 100. Implemented; see
[`src/hash/keccak/sponge/`](../../src/hash/keccak/sponge/).

## Assumptions

1. **Period 32.** One absorption period drives one Keccak permutation.
   Address scaling α = 3200 / 32 = 100.
2. **One lane per row.** Each row in `[0, 25)` handles one state
   lane and bundles all the lane's bus actions on that row: rate
   XORin (lanes 0–16) or capacity passthrough (lanes 17–24), plus
   the RC provide that rides along (lanes 0–23 cover RC[0..24)),
   plus the last-block squeeze consume on non-digest lanes (4–24).
   Scenarios (first-block / intra-invocation / pad-row / chunks-
   absent / last-block) are selected by gating flags — no row
   duplication. One dedicated row handles the lane-16 trailing
   `0x80` XOR; the remainder is NOP slack.
3. **Sponge requires `(sponge_seq_id, chunk_ptr, len_bytes)` on `KeccakSponge`.** The
   transcript chiplet (or whatever calls Keccak) provides; sponge
   consumes the request. The require lands at row 0 of each
   invocation, gated by `is_first_row_of_invocation`. `len_bytes`
   flows directly into `bytes_left_0`; `chunk_ptr` pins the
   invocation's chunk-tape base (the `chunk_ptr` chain is relaxed at
   invocation seams — see [§ `chunk_ptr` chain](#chunk_ptr-chain));
   `sponge_seq_id` is the sponge row counter, carried so the
   transcript can derive the digest address in the round chiplet's
   IP space.
4. **Sponge always emits a padding block.** Per FIPS 202, every
   invocation gets a trailing pad block, so `is_pad` fires once per
   invocation in the last absorption period.
5. **Digest = 4 lanes left at `n_last·3200 + 3072 + i` for the
   transcript** to consume from Memory64. Sponge consumes the other
   21 non-digest lanes itself.
6. **Padding sub-circuit** — 8-bit selectors + `verbatim / padded /
   garbage / zeros` row classification + gated chunk consumption.

## Period structure

| `p_idx` | Count | Role |
|---|---|---|
| `[0, 17)` | 17 | Rate XORin (lane `i = p_idx`) + `RC[p_idx]` provide + squeeze (last-block, lanes 4–16) |
| `[17, 25)` | 8 | Capacity (lane `i = p_idx`) + `RC[p_idx]` provide (only `p_idx ∈ [17, 24)`) + squeeze (last-block) |
| `25` | 1 | Lane-16 trailing-`0x80` XOR (fires once per invocation) |
| `[26, 29)` | 3 | Extra chunk-consume — last-block overshoot lanes (see [§ Extra chunk-consume rows](#extra-chunk-consume-rows)) |
| `[29, 32)` | 3 | NOP slack |

Row 0 doubles as the invocation-bus require row (packed into
rate-lane-0 XORin, gated by `is_first_row_of_invocation`). Trace
tail (post-invocations) is gated to 0 multiplicity by `act = 0`
universally; no per-role logic.

Worst-case row inserts: 8 (rate XORin lane 16, non-first-block, last-
block, pad-row, chunks-available — `state_prev + chunk + andnot +
xor(padding) + xor(state) + state_new + RC + squeeze`). The lane-16
`0x80` row stays well under at 3 inserts and the dedicated row keeps
the lane-16 XORin row off the `0x80` Bitwise64. With mutex
grouping of the per-bus aux columns (see [§ Lookups](#lookups)),
the binding `log_quotient_degree = 3` under Plonky3's deg-1 periodic
convention.

## Per-row tracks

Each row carries one **mutex track** (which absorb/passthrough
scenario it's doing, or which non-state-lane role it plays — exactly
one option applies) plus, if it's a state-lane row, up to two
**parallel tracks** that ride along (RC provide and last-block
squeeze, each gated independently). The LogUp worst-case batch size
sums across the mutex track *and* the parallel tracks, so all three
contribute to `log_quotient_degree`.

### Mutex track

- **Rate XORin row** (`i = p_idx ∈ [0, 17)`): scenarios
  `{first-block, intra}` × row class `{verbatim, pad, garbage-tail,
  zero-tail}` × `{not-last-block, last-block}`.
  - First-block: skip `state_prev` consume; `state_new = chunk_i`.
  - Intra: `state_new = state_prev ⊕ chunk_i`.
  - Pad: clear garbage past `byte_offset` with andnot, XOR in
    `padding_mask`, XOR result into state.
  - Garbage-tail: consume chunk to balance the bus; state propagates
    by direct equality.
  - Zero-tail: no chunk consume; state propagates.

- **Capacity row** (`i = p_idx ∈ [17, 25)`): scenarios
  `{first-block, intra}` × `{not-last-block, last-block}`.
  - First-block: skip `state_prev` consume; provide `0`.
  - Intra: consume `state_prev_i`, provide identity.

- **Lane-16 trailing-`0x80` row** (`p_idx = 25`): on last-block,
  consume lane 16's intermediate value from Memory64 at
  `X = n·3200 + 16`, XOR with `0x80000000_00000000` via Bitwise64,
  provide the post-XOR value at the same address. Three inserts:
  1 Memory64 consume + 1 Bitwise64 + 1 Memory64 provide. Idle on
  non-last-block periods. Fires exactly once per invocation. The
  lane-16 rate XORin row at `p_idx = 16` always writes the pre-
  `0x80` value at `X`; the round chiplet's perm-`n` round-0 lane-16
  read consumes the post-`0x80` value at `X`. On last-block periods
  the address `X` therefore carries two distinct tuples — that's a
  multiset re-introduction at exactly one address per invocation.
  Cross-pairing (= a malicious prover wiring round chiplet's consume
  to the lane-16 row's provide while the dedicated row's
  consume/provide pair on each other) is foreclosed by the
  Bitwise64 message: it locally pins `final = intermediate ⊕ 0x80`.
  Any swap that tries to use `intermediate = final` forces
  `0x80 = 0` (contradiction); any other reshuffle leaves a tuple
  unbalanced. When `pad_lane = 16, byte_offset = 7`, leading `0x01`
  and trailing `0x80` collide at byte 7 of lane 16 → `0x81`
  naturally from the two separate XORs.

- **NOP slack** (`p_idx ∈ [26, 32)`): no bus action.

### Parallel tracks on state-lane rows

Both fire on every state-lane row (`p_idx ∈ [0, 25)`) where their
own gate holds, regardless of which mutex scenario the row is
running. They are not alternatives to the absorb / passthrough
scenarios — they ride along.

- **RC provide** — gated by `p_rc_active` (periodic, `p_idx ∈ [0, 24)`).
  Provides `RC[p_idx]` at perm `n`'s RC slot IP, read by the round
  chiplet at its ι and ZERO slots. Last capacity lane (`p_idx = 24`)
  carries no RC since Keccak has only 24 rounds.
- **Last-block squeeze** — gated by `p_squeeze_active` (periodic,
  `p_idx ∈ [4, 25)`) ∧ `is_last_block_period` (= `Σ_j b_j`, inline).
  Consumes perm `n`'s own lane-`p_idx` last-perm output (witnessed
  in `state_out_{lo,hi}`, bus-pinned by the round chiplet's perm-`n`
  output provide). Coverage: rate XORin rows at `p_idx ∈ [4, 17)`
  handle the 13 non-digest rate lanes; capacity rows at
  `p_idx ∈ [17, 25)` handle the 8 capacity lanes. Total 21 — the
  non-digest range. Digest lanes `[0, 4)` stay on Memory64 for the
  transcript to consume.

## Bus tuples

| Role | Dir | Mult | Address | Active |
|---|---|---|---|---|
| `KeccakSponge(sponge_seq_id, chunk_ptr, len_bytes)` | req | 1 | own bus | row 0 of invocation, gated `is_first_row_of_invocation` |
| Chunk lane | req | 1 | `CHUNK_ADDR_BASE + chunk_ptr` (Memory64) | rate XORin, chunks-available |
| Prev-perm lane | req | 2 | `100·sponge_seq_id − 99·p_idx − 128` | state-lane rows (`p_idx ∈ [0, 25)`), gated `1 − is_first_block_of_invocation` |
| New state lane | prov | 2 | `100·sponge_seq_id − 99·p_idx` | state-lane rows |
| `RC[p_idx]` | prov | 3 | `100·sponge_seq_id + 28·p_idx + 25` | state-lane rows where `p_rc_active` (`p_idx ∈ [0, 24)`) |
| Squeeze (non-digest) | req | 2 | `100·sponge_seq_id − 99·p_idx + 3072` | state-lane rows where `p_squeeze_active` (`p_idx ∈ [4, 25)`), gated `is_last_block_period` |
| Lane-16 0x80 consume | req | 2 | `100·sponge_seq_id − 2484` | `p_idx = 25`, gated `is_last_block_period` |
| Lane-16 0x80 provide | prov | 2 | `100·sponge_seq_id − 2484` | `p_idx = 25`, gated `is_last_block_period` |

Address algebra (`sponge_seq_id = 32·n + p_idx`):
- Prev-perm consume: `(n−1)·3200 + 3072 + p_idx` = lane-`p_idx`
  output of perm n−1. Substituting `n·3200 = 100·(sponge_seq_id − p_idx)`:
  `100·(sponge_seq_id − p_idx) − 3200 + 3072 + p_idx = 100·sponge_seq_id − 99·p_idx − 128`.
- New state provide: `n·3200 + p_idx` = perm n's round-0 lane-`p_idx`
  input, sitting at the tail of cycle n−1's dead round.
  `100·(sponge_seq_id − p_idx) + p_idx = 100·sponge_seq_id − 99·p_idx`.
- Two values 128 IPs apart — perm n−1's dead round — so each tuple
  has exactly one provider + one consumer (no value-collision attack
  surface).
- `RC[p_idx]` at `25 + n·3200 + p_idx·128`, parallel on state-lane
  rows: `25 + 100·(sponge_seq_id − p_idx) + 128·p_idx = 25 + 100·sponge_seq_id + 28·p_idx`.
- Squeeze at `n·3200 + 3072 + p_idx` (lane `i = p_idx`):
  `100·(sponge_seq_id − p_idx) + 3072 + p_idx = 100·sponge_seq_id − 99·p_idx + 3072`.
  Same formula for rate non-digest (`p_idx ∈ [4, 17)`) and capacity
  (`p_idx ∈ [17, 25)`); both gated by `p_squeeze_active`.
- Lane-16 0x80 row reads/writes at `n·3200 + 16`. With `p_idx = 25`:
  `100·(sponge_seq_id − p_idx) + 16 = 100·sponge_seq_id − 100·p_idx + 16 = 100·sponge_seq_id − 2484`.
  Consume picks up the pre-`0x80` value written by the lane-16
  rate XORin row at `p_idx = 16` of the same period (same address,
  same multiplicity); provide hands the post-`0x80` value to the
  round chiplet's perm-`n` round-0 lane-16 read (same address,
  different value).

### Field-negative address expressions on gated-off rows

Address expressions are degree-1 polynomials in `sponge_seq_id` and
`p_idx`; on rows where the message's gate is off (mult = 0) some
of them evaluate to integer-negative values, which wrap to large
Goldilocks elements. The LogUp aux term is
`mult · 1/(α − hash(addr, val…))`, so mult = 0 zeroes the
contribution regardless of `addr`. Concretely:

- `Prev-perm consume = 100·sponge_seq_id − 99·p_idx − 128`. Minimum
  −2504 at `sponge_seq_id = 0, p_idx = 24`. Gated by
  `1 − is_first_block_of_invocation`, so fires only for `n ≥ 1`,
  where the integer address `3200n + p_idx − 128 ≥ 3072`.
- `Lane-16 0x80 consume/provide = 100·sponge_seq_id − 2484`. Minimum
  −2484 at `sponge_seq_id = 0`. Gated by `p_idx = 25 ∧ is_last_block_period`,
  so fires only at `sponge_seq_id = 32n + 25`, where the integer address
  `3200n + 16 ≥ 16`.

The remaining four expressions (`KeccakSponge` require on its own
bus, chunk-lane require with positive base, new-state provide
`= 3200n + p_idx ≥ 0`, RC provide `= 3200n + 128·p_idx + 25 ≥ 25`,
squeeze consume `= 3200n + p_idx + 3072 ≥ 3076` on its fire-range
`p_idx ∈ [4, 25)`) are integer-non-negative on every row, gated or
not. So every bus tuple that actually enters the LogUp running sum
carries a non-negative integer address.

## Columns

Periodic columns are verifier-known (no witness/FRI cost). Witness
columns are prover-committed at every row of the trace; row classes
that don't use a column leave its value unconstrained on those rows.

### Periodic (32-row period)

One entry per `p_idx ∈ [0, 32)`.

| Name | Value at `p_idx` | Used for |
|---|---|---|
| `p_idx` | `p_idx` itself, integer `[0, 32)` | base of every degree-1 address expression |
| `p_first` | 1 iff `p_idx == 0` | row-0-of-period boundary |
| `p_last` | 1 iff `p_idx == 31` | stands in for `p_first` of the next period (`p_first_{r+1}`) in transition constraints, which can't read next-row periodics |
| `p_rate_block` | 1 iff `p_idx ∈ [0, 17)` | gates rate-XORin-row work, the `bytes_left` decrement, monotone chains, the pad-lane tie-down |
| `p_capacity` | 1 iff `p_idx ∈ [17, 25)` | gates capacity-row work |
| `p_rc_active` | 1 iff `p_idx ∈ [0, 24)` | gates the RC provide bundled into state-lane rows (skips `p_idx = 24` since Keccak has only 24 rounds) |
| `p_squeeze_active` | 1 iff `p_idx ∈ [4, 25)` | gates the squeeze consume bundled into state-lane rows on last-block (skips digest lanes `[0, 4)`) |
| `p_pad_0x80` | 1 iff `p_idx == 25` | gates the lane-16 trailing-`0x80` row's bus + Bitwise64 emissions on last-block |
| `p_extra` | 1 iff `p_idx ∈ [26, 29)` | gates the extra chunk-consume rows that mop up last-block overshoot lanes (paired with `b_sum`) |
| `rc_val_lo`, `rc_val_hi` | `RC[p_idx]` u32 halves on `p_rc_active` rows, `0` elsewhere | RC value provided to Memory64 from state-lane rows |

The "state-lane" predicate `p_idx ∈ [0, 25)` (= rate or capacity) is
`p_rate_block + p_capacity`, evaluated inline in the prev-perm and
new-state-lane bus message multiplicities — no dedicated column.

### Witness — structural (5)

- `sponge_seq_id` — global sponge row counter; +1 per row. Plays the same
  role as the round chiplet's `ip`; every per-row address is a
  degree-1 expression in `sponge_seq_id` and `p_idx`.
- `act` — sticky-downward activity flag. Multiplies every bus
  multiplicity, so trace-tail rows (post-invocations) contribute
  nothing to the bus regardless of what their other witness columns
  say.
- `bytes_left_r` — bytes remaining to absorb as of row `r`.
  Decrements by 8 on rate XORin rows during an invocation, holds
  steady on non-absorb rows, gets pinned to `len_bytes` at row 0 of
  each invocation by the `KeccakSponge` bus require. Tolerated to
  underflow past 0 after the pad row — nothing reads `bytes_left`
  past that point.
- `is_first_block_of_invocation` — 1 throughout the first
  absorption period of an invocation (32 rows), 0 elsewhere within
  the invocation, and 1 again on the next invocation's first
  absorption period. Gates the prev-perm consume *off* on
  state-lane rows of the first block, the capacity-init "provide 0"
  *on*, and the `state_prev = 0` pin on first-block state-lane
  rows.
- `chunk_ptr` — sponge-side cursor into the chunk chiplet's flat
  Memory64 tape. Pinned to the invocation's chunk-tape base by the
  `KeccakSponge` request at the first row of each invocation;
  increments by `(p_rate_block + p_extra · b_sum) · is_chunk_avail`
  per row within the invocation (i.e., +1 on every row that fires a
  chunk consume — rate rows on every block, plus the last block's
  extra rows for overshoot lanes — +0 elsewhere); jumps freely at
  invocation seams (the increment chain is gated off there). Used as the address offset for chunk consume:
  `chunk-consume-addr = CHUNK_ADDR_BASE + chunk_ptr`. There is no
  global enumeration-from-0 constraint: within an invocation the
  increment chain + `is_chunk_avail`'s non-increasing rule keep
  consumes consecutive in `p_idx` (no intra-invocation gaps);
  across invocations the per-invocation base comes from the
  `KeccakSponge` request, and Memory64 bus balance against the
  chunk chiplet's contiguous emissions forecloses overlaps
  (double-consume → tuple consumed more often than provided) and
  gaps (emitted-but-unconsumed → tuple provided but not consumed).
  Each segment spans exactly `4·k` lanes (`k = ceil(len_bytes / 32)`),
  so bases are `4`-aligned; the design doesn't depend on alignment
  either way (the chain is relaxed at seams regardless).

`is_first_row_of_invocation` is **not** a committed column — it's
the degree-1 inline expression
`p_first · is_first_block_of_invocation` (periodic `p_first` is
degree 0, witness `is_first_block_of_invocation` is degree 1), which
fires exactly when both `p_first` (row 0 of period) and
`is_first_block_of_invocation` (first absorption period of an
invocation) hold. That coincides with the first row of each
invocation by construction; the bus require's count-match against
the transcript's provides is then enforced by the per-tuple bus
balance, and binary-ness follows from the inputs being binary —
neither needs a dedicated placement constraint.

### Witness — padding state machine (10)

- `is_zero_p` — past-pad indicator on rate XORin rows; monotone
  non-decreasing across the 32 rows of the period. On rows past
  slot 17 it equals `is_last_block_period` (selector-sum-ties
  constraint pins it to `Σ_j b_j` there, and the monotone chain
  holds it across the rest of the period). On rate XORin rows
  before the pad row it is 0 even on a last-block period, so it
  cannot stand in for `is_last_block_period` on the early rate
  rows — see the `Σ_j b_j` shorthand below.
- `is_chunk_avail` — chunks-available indicator; monotone
  non-increasing across the period (once chunks run out, they stay
  out — a single contiguous prefix). `is_chunk_avail = 1` iff the
  chunk chiplet provides at this row's chunk address, `0` otherwise.
  Tied at the bus by Memory64 balance on the `[CHUNK_ADDR_BASE, +∞)`
  range: the chunk chiplet's per-invocation segment supplies exactly
  `4·k` lanes (`k = ceil(len_bytes / 32)`). The sponge consumes them
  in `chunk_ptr` order across the invocation's blocks — `17·num_blocks`
  on rate rows plus the last block's `overshoot` lanes on the extra
  rows `[26, 29)`. On an overshoot last block the prefix carries
  through the inert capacity / `0x80` rows so rate and extra stay one
  prefix (see [§ Extra chunk-consume rows](#extra-chunk-consume-rows)).
- `b_0`, `b_1`, …, `b_7` — unary selector bits for
  `byte_offset ∈ [0, 7]`, the pad row's byte-offset within its lane.
  Per-invocation broadcast: exactly one fires (on the last block),
  none fire on non-last blocks. Used as degree-1 inline operands in
  the `padding_mask` and `andnot_mask` expressions, keeping the
  Bitwise64 messages degree-1.

`is_last_block_period := Σ_j b_j` is not a committed column — it's
the degree-1 inline sum of the eight selector bits. By the
selector-bits-constant-within-period constraint, it is constant
across the period; by the selector-sum-ties constraint, it equals
`is_zero_p` on rows past slot 17 (= the period's terminal
`is_zero_p`, which is exactly what "is this the last absorption
period" means). So `Σ_j b_j` is the canonical `is_last_block_period`
signal everywhere in the period — including on the early rate
XORin rows where `is_zero_p` has not yet settled.

### Witness — per-row lane values (12)

- `chunk_lo`, `chunk_hi` — chunk lane value at this row. Bus-pinned
  by the chunk-bus require when `is_chunk_avail = 1`;
  unconstrained otherwise.
- `state_prev_lo`, `state_prev_hi` — dual-purpose:
  - On state-lane rows (rate XORin + capacity, `p_idx ∈ [0, 25)`):
    the prev-perm output lane value consumed from Memory64.
  - On the lane-16 `0x80` row (`p_idx == 25`): the *intermediate*
    (pre-`0x80`) lane-16 value consumed from Memory64.
- `state_new_lo`, `state_new_hi` — dual-purpose:
  - On state-lane rows: the new lane value written back to Memory64
    (perm-`n` round-0 input for that lane).
  - On the lane-16 `0x80` row: the *final* (post-`0x80`) lane-16
    value written back to Memory64.
- `state_out_lo`, `state_out_hi` — perm-`n` last-perm output for
  lane `p_idx`, consumed from Memory64 by the squeeze on last-block
  state-lane rows. Bus-pinned by the round chiplet's perm-`n`
  output provide (at IP `n·3200 + 3072 + p_idx`, mult 2). Used only
  when the squeeze gate fires (`p_squeeze_active ∧ is_last_block_period`);
  unconstrained on every other row. The value is distinct from
  `state_prev` (which is perm `n−1`'s output, a different perm)
  and from `state_new` (which is perm `n`'s round-0 input).
- `cleared_lo`, `cleared_hi` — pad-row intermediate
  `AndNot(andnot_mask, chunk_lane)`. Logically pad-row-only, but
  committed on all rate XORin rows for layout uniformity.
- `padded_lo`, `padded_hi` — pad-row intermediate
  `cleared XOR padding_mask`. Same uniform-commit pattern.

### Witness — LogUp aux

A single σ residue is exposed publicly (matches the convention of
the existing chiplets: `bitwise64`, `keccak/round`, `byte_pair_lut`
all expose `num_aux_values = 1`). It aggregates the sponge's net
contribution across all three buses (Memory64, Logic64,
KeccakSponge) — different buses produce distinct `(α − hash)`
denominators thanks to bus-prefix-distinguished encodings, and
Schwartz-Zippel on random α enforces per-bus balance even when
one σ accumulates residues from all of them.

The number of physical aux columns is an implementation detail:
declared inserts are spread across columns AND combined into
mutex groups so that per-column `log_quotient_degree ≤ 2`. Col 0
is the running-sum σ and (following the `bitwise64` pattern)
hosts its own batch in addition to chaining the per-row fraction
columns. Order of magnitude: 3 aux columns total (running-sum-
plus-Memory64 + Logic64-fractions + KS-and-chunk-fractions).

### Total

**~27 main witness columns** (5 structural + 10 padding + 12 lane
values), plus **3 aux columns** (single σ residue exposed; col 0
hosts the running σ and Memory64 batch, cols 1–2 are fraction
columns chained into col 0).

## Constraints

Local polynomial constraints on the witness, organized by purpose.
Lookups (bus interactions, Bitwise64 messages) live in their own
section below. Every constraint listed here is in
`when_transition` (cyclic skip of the last → first wrap) or
`when_first_row` (just row 0) unless explicitly noted as ungated.

`enters_new_invocation := p_first_{r+1} · is_first_block_{r+1}`
shorthand for the degree-1 derived signal that fires at the row
*before* a new invocation starts. When the trace's first invocation
starts at row 0 (the normal case, pinned by the `KeccakSponge` bus
require), the cyclic wrap from row `N − 1 → 0` also fires it. On
an all-zeros trace (no invocations, `is_first_block = 0`
throughout), it never fires.

### Boundary (`when_first_row`)

- `sponge_seq_id − 0 = 0`. Row counter starts at 0 — convention; nothing
  algebraically depends on it but it makes addresses interpretable.

`chunk_ptr` is **not** pinned at row 0: its base is supplied per
invocation by the `KeccakSponge` request (the first invocation's
request carries base `0` by convention, matching the chunk
chiplet's tape origin). See [§ `chunk_ptr` chain](#chunk_ptr-chain).

`act` and `is_first_block_of_invocation` are deliberately *not*
pinned at row 0. A PVM proof that contains zero Keccak invocations
(e.g. ECC-only transcripts) is a valid scenario: trace is all
`act = 0`, no bus message has non-zero multiplicity, the round
chiplet is also all-zeros, every σ residue is 0, balance is
trivial. When invocations *do* exist, the `KeccakSponge` bus
require's count match against the transcript-side provides forces
`is_first_row_of_invocation = 1` at exactly the right rows, which
in turn forces `act = 1` and `is_first_block_of_invocation = 1`
there — bus pinning alone is sufficient.

### Activity and row counter

- Binary: `act · (1 − act) = 0`. Deg 2.
- Sticky-downward (gated): `when_transition · (1 − act) · act' = 0`.
  Deg 2. Forbids 0→1 transitions within `[0, N−2]`. The cyclic wrap
  (row `N−1 → 0`) is *not* constrained, which is what lets the
  natural pattern (`act = 1` for a prefix, then `act = 0`) cycle
  back to `act_0 = 1` on the next loop.
- Drop placement: the unique 1→0 transition (if any) must occur at
  the last row of an invocation's last absorption period.
  `when_transition · (act − act') · (1 − p_first' · is_last_block_period) = 0`.
  Deg 2 (linear witness diff `act − act'` × deg-1 factor
  `(1 − periodic · witness)`). Stays within the blowup-2 group;
  doesn't escalate beyond the existing local-constraint max of 2.
  Equivalent to the more natural `act · (1 − act')` drop indicator
  under the sticky-downward constraint above (which already
  forbids `act − act' = −1`, the 0→1 case), so on valid traces
  `act − act' ∈ {0, 1}` and the two formulations coincide; the
  linear form is preferred because it costs one fewer witness
  multiplication.
  - All-zeros trace: `act − act' = 0` everywhere → constraint
    vacuously holds.
  - All-1's trace: same — never changes.
  - Normal 1's-then-0's pattern: drops at row `r` with
    `act_r = 1, act_{r+1} = 0`. Constraint forces
    `p_first_{r+1} · is_last_block_period_r = 1`, i.e., row `r` is
    slot 31 of the last-block period of the trace's last invocation.
- Row-counter +1: `sponge_seq_id' − sponge_seq_id − 1 = 0`. Deg 1.

### `is_first_block_of_invocation` structure

- Binary: `is_first_block · (1 − is_first_block) = 0`. Deg 2.
- Constant within period:
  `(1 − p_first_{r+1}) · (is_first_block' − is_first_block) = 0`.
  Deg 1.

At period boundaries (`p_first_{r+1} = 1`) the prover may toggle
freely; the `KeccakSponge` bus require count + the transcript-side
`sponge_seq_id` commitment pin which period starts an invocation.

### `bytes_left` decrement chain

`bytes_left` decrements by 8 on rate XORin rows of an invocation,
holds steady elsewhere, and is pinned by the `KeccakSponge` bus
require at the first row of each invocation (the row where
`enters_new_invocation_{r-1} = 1`).

Both branches are gated by `act`, so `bytes_left` is unconstrained on
dead rows:

- Absorb row:
  `act · p_rate_block · (bytes_left' − bytes_left + 8) = 0`. Deg 2.
- Non-absorb row, no invocation boundary at the next row:
  `act · (1 − enters_new_invocation) · (1 − p_rate_block) · (bytes_left' − bytes_left) = 0`.
  Deg 3.

The two branches have asymmetric gating because the
invocation-boundary row (`p_idx = 31`, where
`enters_new_invocation = 1`) is structurally a non-absorb row.
On the absorb branch, `p_rate_block = 1` fires only on
`p_idx ∈ [0, 17)`, which is per-row mutex with `p_idx = 31` — so
`enters_new_invocation` is identically 0 wherever the constraint
would otherwise fire, and the `(1 − enters_new_invocation)` factor
is redundant. On the non-absorb branch the seam at `p_idx = 31`
*is* covered by `(1 − p_rate_block) = 1`, so the
`(1 − enters_new_invocation)` factor is essential there to gate
the hold-steady constraint off at the seam — `bytes_left` jumps
to the next invocation's `len_bytes` on the row that the
`KeccakSponge` bus require pins (the first row of the new
invocation, `p_idx = 0` of the next period).

**Cyclic side-effect: rules out degenerate *active* traces; admits
the empty transcript.** On an *active* trace with no invocation
seams (`act = 1 ∧ is_first_block = 0` everywhere),
`enters_new_invocation = 0` *everywhere*, so the chain has no escape
valve at any seam — every period-boundary transition forces
`bytes_left' = bytes_left`. Net traversal over `M = N/32` periods is
then `X_0 − M · 136 ≡ X_0 (mod p)`, which requires
`M · 136 ≡ 0 (mod p)`. For Goldilocks (`p = 2^64 − 2^32 + 1`,
`gcd(p, 17) = 1`) and any practical trace height (`k ≤ 27` in
`M = 2^k`), `M · 136 = 17 · 2^{k+3}` is never a multiple of `p`. So
the chain is **unsatisfiable** under `act = 1 ∧ is_first_block = 0`
everywhere, forbidding any cyclic-fixed-point sponge trace (one that
would otherwise require finding `S` with `f^M(S) = S` for
Keccak-f[1600]) purely algebraically — Keccak preimage resistance
doesn't even need to weigh in.

The empty transcript escapes this only because it carries `act = 0`
everywhere: the `act` gate makes the chain vacuous on dead rows, so
`bytes_left` is unconstrained there and the cyclic-fixed-point
argument — which is about a *real*, fully-active trace — doesn't
apply. The all-zeros trace (`act = 0` everywhere) is therefore the
one valid empty-transcript trace. (Were the chain *ungated*, it would
also reject this legitimate all-dead trace, since the period-boundary
hold would fire on dead rows too — which is why the `act` gate is
load-bearing, not cosmetic.)

### `chunk_ptr` chain

`chunk_ptr` advances by 1 on each row that fires a chunk consume,
0 elsewhere — but only *within* an invocation. The increment chain
is gated off at invocation seams (`enters_new_invocation`), where
the `KeccakSponge` request re-pins `chunk_ptr` to the next
invocation's chunk-tape base:

```
(1 − enters_new_invocation) · (chunk_ptr' − chunk_ptr − (p_rate_block + p_extra · b_sum) · is_chunk_avail) = 0
```

The advance term fires on rate rows of every block, plus the extra
rows `[26, 29)` of the *last* block (gated by `b_sum`) that mop up
overshoot lanes (see [§ Extra chunk-consume rows](#extra-chunk-consume-rows)).
So `chunk_ptr` walks **all** `4·num_chunks` tape lanes of an
invocation contiguously — there is no seam gap. Deg 3 (the
`enters_new_invocation` factor times the deg-2 advance term).
`when_transition`-gated, so the cyclic wrap (row `N − 1 → 0`) is
unconstrained.

There is **no** `chunk_ptr_0 = 0` boundary and **no** global
enumeration constraint. Correctness comes from three pieces:

1. **Per-invocation base** — pinned by the `KeccakSponge` request
   (message #12 carries `chunk_ptr`), exactly as `bytes_left_0` is
   pinned by the same request.
2. **Intra-invocation contiguity** — within an invocation, the
   increment chain + `is_chunk_avail`'s non-increasing rule keep
   consumes a prefix (rate rows, then the last block's extra rows),
   carried across intra-invocation block boundaries (the seam gate
   only fires at *invocation* boundaries, not block boundaries).
3. **No overlap / no global gap** — Memory64 bus balance against
   the chunk chiplet's contiguous emissions. An overlapping base
   double-consumes some tape address (consumed more often than
   provided → imbalance); a base that skips emitted lanes leaves a
   provided-but-unconsumed tuple (imbalance). Either way the proof
   fails. So the transcript must set contiguous bases
   (`base_{i+1} = base_i + 4·num_chunks_i`), and the chunk chiplet
   emits each segment contiguously.

Because the sponge now consumes every lane the chiplet emits
(`4·num_chunks`, overshoot included), the per-invocation base is
`base_{i+1} = base_i + 4·num_chunks_i` = `4·chunk_seq_id_head` — back
to 4-aligned. The sponge still doesn't care about the absolute tape
layout, only that its consumes balance the chunk chiplet's provides.

### Padding state machine

- Binarity (all deg 2):
  - `is_zero · (1 − is_zero) = 0`.
  - `is_chunk_avail · (1 − is_chunk_avail) = 0`.
  - `b_j · (1 − b_j) = 0` for `j ∈ [0, 8)`.

- Within-period sticky transitions (deg 2):
  - `is_zero` is non-decreasing:
    `(1 − p_first_{r+1}) · is_zero · (1 − is_zero') = 0`.
  - `is_chunk_avail` is non-increasing (once chunks run out, they
    stay out within the period):
    `(1 − p_first_{r+1}) · (1 − is_chunk_avail) · is_chunk_avail' = 0`.

- Period boundary (deg 1):
  - `p_first · is_zero = 0`. (Pad hasn't fired yet at slot 0 of any
    period; correct even when the pad row is at `p_idx = 0`, since
    `is_zero` reflects the *pre*-row state.)

  `is_chunk_avail` is *not* pinned at the period boundary. The
  trailing padding block of `len_bytes ≡ 0 mod 136` invocations
  (including `len_bytes = 0`) can either have
  `is_chunk_avail_0 = 0` (the natural case when the chunk
  chiplet's per-invocation segment ended at the previous block
  boundary) or `is_chunk_avail_0 = 1` for the first few rows
  (when the chunk chiplet's per-invocation chunk-alignment
  zero-pad spills into this block — see [§ Open / out of scope](#open--out-of-scope)
  for the per-invocation lane-count contract). The `Memory64` bus
  balance pins `is_chunk_avail` to whatever the chunk chiplet
  provides on the row, and that pinning is consistent with both
  "chunks available" (chiplet provides → sponge consumes →
  `is_chunk_avail = 1`) and "no chunks available" (chiplet
  provides nothing → sponge doesn't consume →
  `is_chunk_avail = 0`). The non-increasing chain keeps it
  consistent within the period; the garbage-tail handling
  ([§ State propagation](#state-propagation-no-bitwise64-fires))
  keeps any chunk-aligned tail lanes from affecting state.

- Selector bits constant within period (deg 1):
  - `(1 − p_first_{r+1}) · (b_j' − b_j) = 0` for each `j`.

- Selector sum ties to `is_last_block_period` (deg 1):
  `(1 − p_rate_block) · (b_0 + b_1 + … + b_7 − is_zero) = 0`.

  Fires on non-absorb rows (`p_idx ≥ 17`), where `is_zero` has been
  carried up to `is_last_block_period` by extended monotonicity.
  On the last-block period one `b_j` fires (`Σ = 1`); on every
  other period all `b_j` are 0 (`Σ = 0`).

### Pad-must-fire (gated by `act`)

`act · p_first_{r+1} · is_first_block_{r+1} · (1 − is_zero) = 0`. Deg 4.

Fires at an *active* row `r` whose successor starts a *new*
invocation (slot 31 of any invocation's last absorb period that is
followed by another invocation), forcing `is_zero_r = 1` there.
Combined with the selector-sum-ties constraint (`Σ b_j = is_zero` on
rows with `p_idx ≥ 17`) and monotone within-period, this propagates
to `is_last_block_period = Σ b_j = 1` for the firing period, which in
turn forces the pad row to fire somewhere in `[0, 17)` of that
period. Net effect: a new invocation may only begin right after a
padded last block, so no invocation is truncated.

**Why `act`-gated.** The cyclic wrap (last row, slot 31, `p_last = 1`
→ row 0, which always has `is_first_block = 1`) would otherwise
trigger the constraint and demand `is_zero = 1` on the final row.
That holds when the trace ends exactly on the last invocation's
padded last block, but **not** when the total block count isn't a
power of two: the trace pads out with `act = 0` dead rows carrying
`is_zero = 0`, and the wrap would reject them. Gating by `act` makes
the dead-region → row-0 wrap vacuous, so any block count is
admissible. (Without the gate the sponge silently rejected every
3-, 5-, 6-, 7-… block trace.)

**Scope.** Pad-must-fire covers *intermediate* active→active seams.
It is silent on the **last invocation's last absorb period** —
either it's followed by `act = 0` dead rows (`is_first_block = 0`, no
trigger) or, with no dead rows, by the wrap (now `act`-gated but
`act = 1` there, so still enforced). Pad-fire on the last invocation
is anyway guaranteed by the **act drop placement** constraint
([§ Activity and row counter](#activity-and-row-counter)): the unique
1→0 transition can only happen at slot 31 of a period with
`is_last_block_period = 1`, which via the selector chain above forces
a pad row in that period — *and* that period is, by the drop
placement, the last invocation's last absorb period.

### Pad-lane tie-down

`p_rate_block · is_pad · (Σ_j j · b_j − bytes_left) = 0`. Deg 2.

Uses the `is_pad := is_zero' − is_zero` derived signal (see
[§ Derived multiplicity signals](#derived-multiplicity-signals)).
It's 1 at exactly the unique transition row of the last-block
period and 0 everywhere else. Where it's 1, the constraint forces
`bytes_left = byte_offset = Σ j · b_j ∈ [0, 7]`. The `p_rate_block`
gate restricts the constraint to rate slots; the same factor
absorbs the period-wrap `is_pad = −1` case, which always lands on
`p_idx = 31` where `p_rate_block = 0`.

### Why intra-invocation padding is impossible

Padding must fire in the *last* block of an invocation —
never mid-invocation. If a prover could pad early and continue
absorbing in the next block of the same invocation, they could
compute a shortened Keccak while claiming the full `len_bytes`.
No single constraint blocks this; the soundness argument runs
across the padding state machine collectively.

For `is_zero` to reach 1 at slot 31 of any period, the `0 → 1`
transition must land at some slot inside that period (slot 0 is
pinned to 0 by `p_first · is_zero = 0`). The transition is
algebraically restricted to rate slots:

1. **Transition at rate slot `k ∈ [0, 17)`.** Pad-lane tie-down
   fires with `p_rate_block_k = 1` and `is_pad_k = 1`, pinning
   `byte_offset = bytes_left_k`. Since `byte_offset = Σ j·b_j ∈
   [0, 7]` (sum over `b_j ∈ {0, 1}` weighted by `j ∈ [0, 8)`),
   this requires `bytes_left_k ∈ [0, 7]`.

2. **Transition at non-rate slot `k ∈ [17, 30]`.** Pad-lane
   tie-down has `p_rate_block_k = 0` and is vacuous, but
   *selector-sum-ties* + *selector-bits-constant-within-period*
   block the transition anyway:
   ties forces `Σ b_j_k = is_zero_k = 0` and
   `Σ b_j_{k+1} = is_zero_{k+1} = 1`; constancy forces
   `Σ b_j_k = Σ b_j_{k+1}`. Contradiction.

3. **No transition at slot 31 → slot 0 of the next period.** The
   sticky chain `(1 − p_first_{r+1}) · is_zero · (1 − is_zero') = 0`
   has the `(1 − p_first_{r+1})` factor vanish at the wrap, so
   `is_zero` *could* drop there — but `p_first · is_zero = 0` at
   slot 0 of the next period forces it back to 0 regardless. No
   period inherits `is_zero = 1` from its predecessor; every
   period starts fresh.

Cases 1+2+3 collapse to: padding can only fire when
`bytes_left ∈ [0, 7]` at the transition row. The `bytes_left`
chain enters that window exactly once per invocation — in the
last partial block — because the chain decrements by 8 on every
absorb row and holds on every non-absorb row, with the
period-boundary hold preserved by the non-absorb branch's
`(1 − p_last · is_first_block')` gate (only the seam to a new
invocation lets `bytes_left` reset to a fresh `len_bytes`).

**Concrete sketch.** For `len_bytes = 200` (block 0: 136 bytes,
block 1: 64 bytes):
- Block 0's rate slots hold `bytes_left ∈ [72, 200]`, all > 7 →
  no `is_zero` transition possible.
- Block 1's rate slots hold `bytes_left ∈ {64, 56, …, 8, 0,
  −8 mod p, …}` — only slot 8 has `bytes_left = 0 ∈ [0, 7]`.
  Pad fires there with `byte_offset = 0`, the FIPS 202 location.

**Closing the side-channel.** A prover *could* attempt to set
some `b_j = 1` without flipping `is_zero` in the same period —
this would mark the block as "last" without firing the pad row.
Selector-sum-ties at any non-rate slot then forces
`is_zero_k = Σ b_j_k = 1`, which routes back into Case 1's
transition requirement → pad-lane tie-down blocks it.

### `state_prev = 0` on first-block state-lane rows

- `(p_rate_block + p_capacity) · is_first_block · state_prev_lo = 0`.
- `(p_rate_block + p_capacity) · is_first_block · state_prev_hi = 0`.

Both deg 2. There's no prev-perm to consume on the first absorption
period of an invocation; pinning `state_prev = 0` lets the
`state_new = state_prev ⊕ chunk` formula naturally yield
`state_new = chunk` (= block value) for rate, and the capacity
identity passthrough naturally yield `state_new = 0` (= zero
capacity init).

### State propagation (no Bitwise64 fires)

- Rate XORin row past-pad (`is_zero = 1`, garbage-tail or zero-tail):
  - `p_rate_block · is_zero · (state_new_lo − state_prev_lo) = 0`.
  - `p_rate_block · is_zero · (state_new_hi − state_prev_hi) = 0`.

  Both deg 2.

- Capacity row identity passthrough (always):
  - `p_capacity · (state_new_lo − state_prev_lo) = 0`.
  - `p_capacity · (state_new_hi − state_prev_hi) = 0`.

  Both deg 1. On first-block capacity rows, the
  `state_prev = 0` constraint above then forces `state_new = 0`.

Rate XORin rows with `is_zero = 0` (real-input and pad-row classes)
have `state_new` pinned by the Bitwise64 messages they emit; the
lane-16 `0x80` row is similarly Bitwise64-pinned. No local
constraint needed for those.

### Chunk zero-fill on `is_chunk_avail = 0`

- `(1 − is_chunk_avail) · chunk_lo = 0`. Deg 2.
- `(1 − is_chunk_avail) · chunk_hi = 0`. Deg 2.

Both ungated. Pin `chunk_lo = chunk_hi = 0` on every row where the
chunk chiplet doesn't provide a lane — including pre-pad verbatim
rate XORin rows that would otherwise fire `Logic64(XOR, state_prev,
chunk, state_new)` with a prover-chosen, Memory64-unpinned chunk
witness and steer the state arbitrarily.

With the zero-fill in place, an under-emission by the chunk chiplet
yields a deterministic zero-extended digest (the sponge effectively
absorbs zeros for the missing lanes, and pad-row real bytes past
`byte_offset = 0` become zero), which the downstream digest check
at the transcript chiplet rejects. **No prover-chosen state
contamination**.

Same soundness posture the chiplet already takes for past-pad
garbage-tail rows: structural shape pinned locally; content
correctness completes at the transcript level. The zero-fill
extends that posture into the pre-pad slots, removing the
prover-choosable-bytes gap.

Ungating is safe because the chunk columns have no other role on
non-rate / NOP / dead rows; pinning them to 0 when
`is_chunk_avail = 0` there is benign.

### Constraint degree summary

Max local constraint witness-degree under Plonky3's deg-1 periodic
convention: **5**, the relaxed `chunk_ptr` chain
`(1 − enters_new_invocation) · (chunk_ptr' − chunk_ptr − (p_rate_block + p_extra · b_sum) · is_chunk_avail)`
— the deg-2 `enters_new_invocation` seam gate times the now-deg-3
advance term (`p_extra · b_sum · is_chunk_avail`). Next is the
`bytes_left` non-absorb branch
`(1 − p_last · is_first_block') · (1 − p_rate_block) · (bytes_left' − bytes_left)`
at deg 4, then the `act`-gated pad-must-fire at deg 4. Other local
constraints land at deg ≤ 3 (drop placement, monotone chains,
pad-lane tie-down, `state_prev = 0` on first-block, state
propagation on past-pad rate, chunk zero-fill). The lookup
constraints set the chiplet's `log_quotient_degree = 3` (constraint
deg 7 on col 0, deg 6 on col 1; see [§ Lookups](#lookups)), so the
local constraints sit comfortably below the LogUp ceiling.

## Lookups

The sponge interacts with three LogUp buses:

| Bus | Status | Tuple shape |
|---|---|---|
| `Memory64` | existing | `(addr, lo, hi)` |
| `Logic64` (from `Bitwise64`) | existing | `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` |
| `KeccakSponge` | new (this chiplet defines it; needs a `BusId::KeccakSponge` entry in `src/relations.rs`) | `(sponge_seq_id, chunk_ptr, len_bytes)` |

Chunk lane consumes ride on `Memory64` at a disjoint address range
starting at `CHUNK_ADDR_BASE`; the chunk chiplet (designed
separately) is the producer there. See [§ Open / out of scope](#open--out-of-scope)
for the full chunk-chiplet contract.

Sign convention: **provide = `−k`**, **consume = `+k`** (matches the
round chiplet). Every multiplicity is also multiplied by `act` so
trace-tail rows contribute zero to every bus regardless of other
witness state.

Plonky3's `SymbolicVariable::degree_multiple` treats `Periodic`,
`Main`, and `Aux` all as degree **1** (with a TODO in
`p3-air` to support the Winterfell-style periodic-deg-0 model
eventually — `p3-air-0.5.1/src/symbolic/variable.rs`). The deg
analysis below counts periodic factors at 1; the per-column
constraint degrees in §[Aux columns and σ exposure](#aux-columns-and-σ-exposure)
are computed under this convention.

### Derived multiplicity signals

All degree-1 in the witness unless noted; `pₓ` factors contribute
deg 1 each under Plonky3's symbolic convention.

- `is_state_lane := p_rate_block + p_capacity` — periodic, deg 1.
  Fires on rate XORin + capacity rows.
- `is_intra := 1 − is_first_block_of_invocation` — witness, deg 1.
- `is_first_row_of_invocation := p_first · is_first_block_of_invocation`
  — periodic · witness, deg 1.
- `is_pad := is_zero_p' − is_zero_p` — witness combinator, deg 1.
  On rate XORin rows it's binary (`{0, 1}`); at the period boundary
  (slot 31 → 0) it can be `−1`, but every mult that uses it is
  also multiplied by `p_rate_block`, which is `0` there.
- `is_verbatim := 1 − is_zero_p'` — witness, deg 1. Binary on rate
  XORin rows: `1` on verbatim (next row still absorbing), `0` on
  the pad row and on past-pad rows (next row past pad).
  Algebraically equivalent to `1 − is_zero_p − is_pad`, picked in
  this form because it touches only one witness column.
- `is_chunk_avail` — witness, deg 1 (committed directly; see
  [§ Witness — padding state machine](#witness--padding-state-machine-10)).
- `is_last_block_period := Σ_j b_j` — witness, deg 1. Constant
  across the period (selector-bits-constant constraint) and equal
  to `is_zero_p` past slot 17 (selector-sum-ties constraint), so
  it's the canonical "this period is the last absorb period"
  signal on every row.

### Memory64 messages

The six Memory64 messages partition by `p_idx` into two **mutex
batches** inside one group: messages #1–#4 fire only on state-lane
rows (`p_state_lane = p_rate_block + p_capacity`), messages #5–#6
fire only on the lane-16 0x80 row (`p_pad_0x80`). The batch outer
flags are pure periodics, so the denominator product never crosses
the row-type boundary.

**Batch A — state-lane rows** (outer flag `p_state_lane`, periodic, deg 0)

| # | Message | Mult inside batch | Tuple |
|---|---|---|---|
| 1 | Prev-perm consume | `+2 · act · is_intra` | `(100·sponge_seq_id − 99·p_idx − 128, state_prev_lo, state_prev_hi)` |
| 2 | New state provide | `−2 · act` | `(100·sponge_seq_id − 99·p_idx, state_new_lo, state_new_hi)` |
| 3 | `RC[p_idx]` provide | `−3 · act · p_rc_active` | `(100·sponge_seq_id + 28·p_idx + 25, rc_val_lo, rc_val_hi)` |
| 4 | Last-block squeeze | `+2 · act · p_squeeze_active · is_last_block_period` | `(100·sponge_seq_id − 99·p_idx + 3072, state_out_lo, state_out_hi)` |

**Batch B — lane-16 `0x80` row** (outer flag `p_pad_0x80`, periodic, deg 0)

| # | Message | Mult inside batch | Tuple |
|---|---|---|---|
| 5 | Lane-16 0x80 consume (intermediate) | `+2 · act · is_last_block_period` | `(100·sponge_seq_id − 2484, state_prev_lo, state_prev_hi)` |
| 6 | Lane-16 0x80 provide (final) | `−2 · act · is_last_block_period` | `(100·sponge_seq_id − 2484, state_new_lo, state_new_hi)` |

Mutex argument: `p_state_lane · p_pad_0x80 = 0` since they're
indicators of disjoint `p_idx` ranges (`[0, 25)` vs `{25}`). Group
algebra (one group containing two mutex batches with periodic
outer flags, each contributing deg 1):

- `u_g = 1 + (d_A − 1) · p_state_lane + (d_B − 1) · p_pad_0x80`
- `deg(d_A) = 4` (product of 4 encodings), `deg(d_B) = 2`.
- `deg(u_g) = max(4 + 1, 2 + 1) = 5`.
- `deg(v_g) ≤ 7` (worst-case batch-A numerator: outer flag deg 1,
  multiplicity `m_4 = 2 · act · p_squeeze_active · is_last_block_period`
  deg 3, multiplied through the 3 other deg-1 encodings:
  `1 + 3 + 3 = 7`).

Symbolic constraint deg ≤ `max(1 + deg(u_g), deg(v_g)) = max(6, 7)
= 7`, giving `log_quotient_degree = log2_ceil(6) = 3`.

Compare with a single batch of all 6 messages and outer flag 1:
`d` deg 6, constraint deg 8, `log_quotient_degree = log2_ceil(7)
= 3`. The mutex split holds the column at the same log-blowup tier
but trims constraint deg by 1 (7 vs 8). Under Winterfell-style
periodic-deg-0 (`p3-air` TODO), the split would drop a full tier;
that is the asymptotic motivation the design preserves.

### Logic64 (Bitwise64) messages

Operand abbreviations (all degree-1 linear inlines in the witness):
- `andnot_mask` — `0xFFFF_FFFF_FFFF_FFFF` shifted left by
  `8·byte_offset` bits, computed as `Σ_j b_j · ANDNOT_MASK[j]`
  where `ANDNOT_MASK[j] = 0xFFFF_FFFF_FFFF_FFFF << (8·j)` is the
  constant for `byte_offset = j`. Periodic-flavour but the `b_j`
  are witness, so the inline is witness deg 1. The intent is
  `(NOT andnot_mask) = keep_mask` covers bytes `[0, byte_offset)`
  with `0xFF` and bytes `[byte_offset, 8)` with `0x00`, so
  `cleared = (NOT andnot_mask) AND chunk` keeps the input bytes
  in positions `< byte_offset` and zeroes the rest. In particular
  for `byte_offset = 0` (pad row has no input bytes — happens
  whenever `bytes_in_block ≡ 0 mod 8`), `andnot_mask = 0xFF…FF`
  and `cleared = 0` regardless of `chunk`, so the pad-row algebra
  is independent of the chunk lane value on those rows.
- `padding_mask` — `0x01 << (8·byte_offset)` on non-lane-16 pad rows,
  bumped with the trailing `0x80` only on the lane-16 0x80 row (a
  different row from the pad row in our layout, so `padding_mask`
  here is just the leading `0x01`-byte mask).
- `pad_const := (0, 0x80000000)` — the lane-16 `0x80` constant
  split into u32 halves. Verifier-known constant.

The five Logic64 messages partition by row class into three
**mutex batches** inside one group: pad-row L64 (`is_pad`),
verbatim-row L64 (`is_verbatim`), and lane-16 0x80 L64
(`p_pad_0x80 · is_last_block_period`). The three are pairwise
mutex on any single row.

**Batch C — pad row** (outer flag `p_rate_block · is_pad`, deg 2)

| # | Message | Mult inside batch | Tuple `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` |
|---|---|---|---|
| 7 | Pad-row ANDNOT (clear past byte_offset) | `+act` | `(ANDNOT, andnot_mask_lo, andnot_mask_hi, chunk_lo, chunk_hi, cleared_lo, cleared_hi)` |
| 8 | Pad-row XOR(padding) (add `0x01` byte) | `+act` | `(XOR, cleared_lo, cleared_hi, padding_mask_lo, padding_mask_hi, padded_lo, padded_hi)` |
| 10 | Pad-row XOR(state) | `+act` | `(XOR, state_prev_lo, state_prev_hi, padded_lo, padded_hi, state_new_lo, state_new_hi)` |

**Batch D — verbatim row** (outer flag `p_rate_block · is_verbatim`, deg 2)

| # | Message | Mult inside batch | Tuple |
|---|---|---|---|
| 9 | Verbatim XOR(state) | `+act` | `(XOR, state_prev_lo, state_prev_hi, chunk_lo, chunk_hi, state_new_lo, state_new_hi)` |

**Batch E — lane-16 `0x80` row** (outer flag `p_pad_0x80 · is_last_block_period`, deg 2)

| # | Message | Mult inside batch | Tuple |
|---|---|---|---|
| 11 | Lane-16 `0x80` XOR | `+act` | `(XOR, state_prev_lo, state_prev_hi, pad_const_lo, pad_const_hi, state_new_lo, state_new_hi)` |

(`op` slot uses the `Logic64Op` tags — `ANDNOT = 0`, `XOR = 1` —
matching the bus encoding in [`Logic64Msg`](../../src/primitives/bitwise64.rs).)

Mutex argument:
- **C vs D**: both gated by `p_rate_block`; `is_pad = (is_zero_p' − is_zero_p)` requires `is_zero_p' = 1` to fire, `is_verbatim = (1 − is_zero_p')` requires `is_zero_p' = 0`. Cannot co-fire.
- **C, D vs E**: `p_rate_block · p_pad_0x80 = 0` (disjoint `p_idx` ranges).

Group algebra:
- `u_g = 1 + (d_C − 1) · f_C + (d_D − 1) · f_D + (d_E − 1) · f_E`
- `deg(d_C) = 3, deg(d_D) = deg(d_E) = 1`.
- Outer flag degrees: all three are deg 2
  (witness × periodic, each contributing deg 1).
- `deg(u_g) = max(3 + 2, 1 + 2, 1 + 2) = 5`.
- `deg(v_g) ≤ 5` (worst-case batch-C numerator: outer flag deg 2,
  3 deg-1 multiplicities `act`, multiplied through 2 other deg-1
  encodings: `2 + 1 + 2 = 5`).

Symbolic constraint deg ≤ `max(1 + 5, 5) = 6`, giving
`log_quotient_degree = log2_ceil(5) = 3`.

Compare with a single batch of all 5 messages and outer flag 1:
`d` deg 5, constraint deg 6, `log_quotient_degree = log2_ceil(5) = 3`.
The split lands at the same log-blowup tier under Plonky3 but
restores per-row-class accounting (verbatim and lane-16 rows
contribute their own — much lower-degree — batches independent of
the pad-row chain). Under Winterfell-style periodic-deg-0, the
split would drop a full tier.

State pinning on rows where no Logic64 fires (past-pad rate rows,
capacity rows, NOP slack) is handled by the local
`state_new = state_prev` constraints in
[§ State propagation](#state-propagation-no-bitwise64-fires).

### KeccakSponge + chunk consume (auxiliary column)

The remaining two messages live on the same aux column but on
different buses — KeccakSponge for the invocation request,
Memory64 for the chunk lane (at the `CHUNK_ADDR_BASE + chunk_ptr`
address). They are not mutex (the KS consume on the first row of
an invocation co-fires with the chunk consume whenever that
first row has chunks available), so they go into **one batch**
with outer flag `1`; per-message multiplicities carry all the
gating, and the bus-prefix-distinguished encodings keep
the KS and Memory64 contributions algebraically distinct.

| # | Message | Mult inside batch | Bus | Tuple |
|---|---|---|---|---|
| 12 | Invocation request consume | `+act · is_first_row_of_invocation` | `KeccakSponge` | `(sponge_seq_id, chunk_ptr, len_bytes)` |
| 13 | Chunk lane consume | `+act · (p_rate_block + p_extra · b_sum) · is_chunk_avail` | `Memory64` | `(CHUNK_ADDR_BASE + chunk_ptr, chunk_lo, chunk_hi)` |

The chunk-lane consume fires on rate rows of every block and, on the
last block only (`b_sum = 1`), the extra rows `[26, 29)` — see
[§ Extra chunk-consume rows](#extra-chunk-consume-rows).

Mult degree: 4 (`act · (p_rate_block + p_extra · b_sum) ·
is_chunk_avail` — `p_extra · b_sum` is deg 2, the rest deg 1 each).
With 2 declared inserts, `d` deg 2 and `n` deg ≤ `4 + 1 = 5`, so
symbolic constraint deg ≤ `max(1 + 2, 5) = 5`,
`log_quotient_degree = log2_ceil(4) = 2`. Still a tier below the
Memory64 / Logic64 columns that set the chiplet-wide `log_quot = 3`.

The chunk address `CHUNK_ADDR_BASE + chunk_ptr` is degree-1 in the
witness (`chunk_ptr`) and a constant offset (`CHUNK_ADDR_BASE`,
a verifier-known constant). This keeps the bus encoding at
degree 1 and avoids contaminating the Memory64 σ residue with any
higher-degree address term.

Message #12 also serves to pin `bytes_left_0 = len_bytes` at row 0
of each invocation (see [§ `bytes_left` decrement chain](#bytes_left-decrement-chain)).

### Extra chunk-consume rows

The chunk chiplet emits a fixed 4 lanes (32 bytes) per chunk and is
blind to the Keccak rate. Since `gcd(4, 17) = 1`, an invocation's
chunk tape (`4·num_chunks` lanes) overshoots the total block rate
capacity (`17·num_blocks` lanes) by

```
overshoot = 4·num_chunks − 17·num_blocks  ∈ {0, 1, 2, 3}
```

(the residue cycles `3, 2, 1, 0` with `num_blocks mod 4`). The rate
rows of the blocks absorb `17·num_blocks` lanes; the leftover
`overshoot` lanes must still be **consumed** off Memory64 so the bus
balances against the chiplet's provides — but they sit past the
padded message, so they must **not** be absorbed.

Three rows `[26, 29)` of every period carry the periodic flag
`p_extra`. On the **last block** of an invocation (gated by
`b_sum = is_last_block_period`) they fire the chunk-lane consume for
the overshoot lanes, advancing `chunk_ptr` but feeding nothing into
the Keccak state (they are not state-lane / pad / squeeze rows). On
non-last blocks `b_sum = 0` makes them inert NOPs.

**`is_chunk_avail` carry-through.** `is_chunk_avail` must stay a
single non-increasing prefix (the monotone rule). On an overshoot
last block the consuming rows are the 17 rate slots `[0, 17)` *and*
the extra slots `[26, 26 + overshoot)`, with the inert capacity /
`0x80` rows `[17, 26)` between them. The trace therefore sets
`is_chunk_avail = 1` across `[0, 26 + overshoot)` — carrying it
through the inert middle so the whole thing is one prefix. The
consume gate `(p_rate_block + p_extra · b_sum) · is_chunk_avail`
keeps the carry rows from actually consuming (both periodics are 0
there).

**No range check, and why that's sound.** The overshoot lanes are
consumed but never absorbed nor routed through Bitwise64, so they
are not range-checked. That's safe: they cancel against the chunk
chiplet's provides on Memory64 (the prover must set
`chunk_lo/hi` to whatever the chiplet emitted — honest traces emit 0
there, past `len_bytes`), and they touch nothing downstream.

**No mid-stream puncture.** Two facts confine the discarded lanes to
the post-message tail, so the absorbed sequence is exactly the
chunk tape prefix `tape[0, 17·num_blocks)`:

1. **`b_sum` gate ⟹ discards only on the last block.** Extra
   consumes can't fire on a non-last block, so they can't drop a
   lane that a later block's rate would have absorbed.
2. **Single-prefix ⟹ extra implies full rate.** To reach the extra
   slots the `is_chunk_avail` prefix must cover all of `[0, 26)`,
   i.e. all 17 rate slots are available. So a prover can't shrink the
   last block's rate (zero-filling a real message lane) *and* use
   extra rows — shrinking ends the prefix before slot 26, which
   leaves the displaced lane unconsumed → Memory64 imbalance.

Together with `chunk_ptr` walking all `4·num_chunks` lanes
contiguously, the only lanes that end up discarded are exactly the
`overshoot` lanes past `17·num_blocks` — which are past the padded
message. (This matters because Keccak-eval ties the chunks-object
commitment to the digest *by pointer*, trusting that the sponge
absorbed the committed tape; a mid-stream puncture would forge that
binding.)

### Worst-case per-row active inserts

Columns below labelled by *aux column*: M64 = state-lane + lane-16
0x80 batches (col 0); L64 = Logic64 batches (col 1);
aux = KeccakSponge + Memory64-chunk-consume (col 2). The chunk
consume is on `Memory64` but lives in the auxiliary aux column.

| Scenario | M64 col | L64 col | aux col | Total |
|---|---|---|---|---|
| Rate XORin pad row at `p_idx ∈ [4, 17)`, intra, last-block, chunks-avail | 4 (batch A: #1 + #2 + #3 + #4) | 3 (batch C: #7 + #8 + #10) | 1 (#13) | **8** |
| Lane-16 `0x80` row (`p_idx = 25`), last-block | 2 (batch B: #5 + #6) | 1 (batch E: #11) | 0 | 3 |
| Rate XORin verbatim, intra, non-last, chunks-avail | 3 (batch A) | 1 (batch D: #9) | 1 (#13) | 5 |
| First-row-of-invocation rate XORin verbatim, non-last block | 2 (batch A) | 1 (batch D) | 2 (#12 + #13) | 5 |
| Trace tail (`act = 0`) | 0 | 0 | 0 | 0 |

The pad row falling in `p_idx ∈ [4, 17)` is what stacks all four
state-lane-row Memory64 inserts (prev, new, RC, squeeze) against
the three pad-row Logic64 inserts and the chunk. Pad rows in
digest-lane positions `p_idx ∈ [0, 4)` lose the squeeze insert
(p_squeeze_active = 0) and cap at 7. Per-row active count is what
determines bandwidth; per-aux-column constraint degree
(after mutex grouping) is what determines `log_quotient_degree`.

### Aux columns and σ exposure

A single σ is exposed publicly (`num_aux_values = 1`, matching
`bitwise64` / `keccak/round` / `byte_pair_lut`). It aggregates the
sponge's net contribution across all three buses: each bus's
encoding includes a bus prefix, so messages from different buses
produce distinct `(α − hash)` denominators, and Schwartz-Zippel on
random α enforces per-bus balance from a single combined residue.

#### Why ≥ 3 aux columns

A single batch of all 13 inserts in one column would have
constraint degree `1 + 13 = 14`, giving `log_quotient_degree = 4`.
Even with mutex grouping, mixing buses in one column multiplies
the groups' `u_g` together (groups within a column are
product-closed, not mutex), pushing column constraint deg well
past the `log_quot = 3` tier. Splitting M64 and L64 across two
columns trims the per-column degree to fit one tier below that,
plus a third column for the unrelated KeccakSponge +
chunk-consume pair (the chunk consume rides on Memory64 at the
disjoint `CHUNK_ADDR_BASE`-anchored range, but its mutual gating
with the state-lane M64 messages is incompatible with the M64
column's mutex grouping, so it lives in the auxiliary column).

#### Recommended 3-aux-column layout

Following `bitwise64`'s pattern (col 0 hosts its own batch *and*
chains the per-row fraction columns), Memory64 lives directly on
the running-sum column. The other two batches stay as fraction
columns chained into col 0:

| Aux col | Role | Group / batch structure | `deg(u_g)` | Constraint deg | `log_quot_deg` |
|---|---|---|---|---|---|
| 0 | running σ + Memory64 fractions (state-lane + lane-16 0x80) | 1 group, 2 mutex batches (A: 4 inserts, B: 2 inserts), periodic outer flags (deg 1) | 5 | 7 | **3** |
| 1 | Logic64 fractions | 1 group, 3 mutex batches (C: 3 inserts, D: 1 insert, E: 1 insert), witness × periodic outer flags (deg 2) | 5 | 6 | **3** |
| 2 | KeccakSponge + Memory64 chunk-consume fractions | 1 batch of 2 independent inserts, outer flag = 1 | 2 | 5 | 2 |

Col 0's running-sum recurrence absorbs cols 1, 2's per-row values
as scalar additions; the absorbed deg-1 EF values don't multiply
into col 0's denominator, so col 0's constraint deg stays
`max(1 + deg(u_g_M64), deg(v_g_M64)) = max(6, 7) = 7`. Max
`log_quotient_degree` across all columns = **3** under Plonky3's
periodic-deg-1 convention, the same tier `bitwise64` lands at
in this codebase. Under the Winterfell-style periodic-deg-0
analysis the layout drops to `log_quot = 2`; both the M64 and L64
columns would lose one tier (see prior-section notes), so the
mutex-grouping design retains its asymptotic motivation even if
the current Plonky3 implementation absorbs that gain into its
conservative deg estimates.

#### What the mutex savings buy

Under Plonky3's deg-1 periodic convention (current state):

| | Memory64 column | Logic64 column |
|---|---|---|
| Naive single batch | `d` deg 6, constraint deg 8, `log_quot_deg = 3` | `d` deg 5, constraint deg 6, `log_quot_deg = 3` |
| Mutex split | `deg(u_g) = 5`, constraint deg 7, `log_quot_deg = 3` | `deg(u_g) = 5`, constraint deg 6, `log_quot_deg = 3` |

Under the Winterfell-style deg-0 periodic model (the `p3-air` TODO
target):

| | Memory64 column | Logic64 column |
|---|---|---|
| Naive single batch | `d` deg 6, constraint deg 7, `log_quot_deg = 3` | `d` deg 5, constraint deg 6, `log_quot_deg = 3` |
| Mutex split | `deg(u_g) = 4`, constraint deg 5, `log_quot_deg = 2` | `deg(u_g) = 4`, constraint deg 5, `log_quot_deg = 2` |

The key trick (per
[`miden-vm` LookupBuilder docstrings](https://github.com/0xMiden/miden-vm/blob/3176d1f/air/src/lookup/builder.rs)):
groups carry the denominator as `(1 − Σ f_i) + Σ f_i · d_i` instead
of `∏ d_i`. When the `f_i` flags are mutex, only the active branch
contributes; denominators of inactive branches never enter `u_g`.

## Open / out of scope

- **Chunk chiplet contract**. The chunk chiplet is a *separate AIR*
  that emits input-byte chunks on the `Memory64` bus at a disjoint
  address range starting at `CHUNK_ADDR_BASE` (pick a constant
  well above any sponge or round-chiplet IP, e.g. `1 << 48` — the
  exact value is convention; both producer and consumer just need
  to agree). The contract:

  - **Tape layout.** The chunk chiplet provides Memory64 lanes
    consecutively at `[CHUNK_ADDR_BASE, CHUNK_ADDR_BASE + N)`,
    where `N` is the total number of lanes across *all* sponge
    invocations in the trace. The tape is a concatenation of
    per-invocation segments; each segment is a contiguous run of
    8-byte lanes. Chunks (256-bit Poseidon-transcript atoms of 4
    lanes each) are how the chunk chiplet internally commits to
    the data; at the bus interface, each chunk row emits **either
    4 or 1** Memory64 messages — see *Thin last-chunk emission*
    below — and successive lanes within an invocation's segment
    land at consecutive addresses.
  - **Chunks belong to exactly one invocation.** The Poseidon
    transcript content-hashes each chunk to commit the Keccak
    input bytes; a chunk that straddled two invocations would
    blur which invocation the hash binds to. Cross-invocation
    chunks are therefore forbidden — every invocation gets its
    own self-contained chunk segment.
  - **Within an invocation, chunks may span block boundaries.**
    The 17-lane rate vs 4-lane chunk granularity mismatch
    resolves entirely inside an invocation: full 136-byte blocks
    consume 17 lanes (= 4.25 chunks), so the next block within
    the same invocation picks up mid-chunk. The sponge AIR
    doesn't see chunk boundaries — it just walks lanes via
    `chunk_ptr`.
  - **Full-chunk emission.** The chunk chiplet always emits all 4
    lanes of every chunk row — it has no `is_thin` column and no
    awareness of the Keccak rate. The sponge absorbs the resulting
    overshoot on the extra rows (next bullet).
  - **Per-invocation lane count.** Let `k = ceil(len_bytes / 32)`
    be the number of chunk rows. The chunk chiplet emits exactly
    `4 · k` lanes; the sponge consumes all of them — `17 · num_blocks`
    on rate rows (absorbed) and `overshoot = 4·k − 17·num_blocks ∈
    {0,1,2,3}` on the last block's extra rows (discarded, past the
    padded message). See
    [§ Extra chunk-consume rows](#extra-chunk-consume-rows).
  - **Sponge ↔ chiplet binding.** The sponge consumes Memory64
    at `CHUNK_ADDR_BASE + chunk_ptr` on every row where
    `(p_rate_block + p_extra · b_sum) · is_chunk_avail = 1`;
    `chunk_ptr` increments by 1 there and holds elsewhere
    ([§ `chunk_ptr` chain](#chunk_ptr-chain)).
    Bus balance on Memory64 over `[CHUNK_ADDR_BASE, +∞)` forces
    the sponge's `is_chunk_avail` pattern to align exactly with
    the chunk chiplet's emission pattern: any prefix-mismatch
    leaves a tuple unbalanced and the proof fails.
  - **Padding-only blocks.** A block with `bytes_in_block_n = 0`
    (e.g., the trailing padding block of a `len_bytes ≡ 0 mod 136`
    invocation, or `len_bytes = 0`) consumes 0 lanes from the
    chunk tape unless chunk-granularity spill from the previous
    block reaches into it. In either case `is_chunk_avail` is 0
    by the row the pad fires (slot 0) and the byte_offset = 0
    pad-row's `andnot_mask = 0xFFFF…FFFF` zeroes the chunk lane
    algebraically, so the bus-pin (or absence of one) at that row
    doesn't affect the digest.
  - **Garbage-tail / unpinned-pad-row tolerance.** When the
    chunk chiplet's emission stops before the sponge's pad row
    (i.e. `is_chunk_avail = 0` at slot `pad_lane_idx`), the
    sponge's witness `chunk_lo, chunk_hi` at that row is not
    bus-pinned. Two protections still hold:
    - For `byte_offset = 0`, `andnot_mask = 0xFFFF…FFFF` zeroes
      the chunk lane in `cleared = (NOT andnot_mask) AND chunk`,
      so the digest is independent of the witness value.
    - For `byte_offset > 0`, the witness chunk bytes
      `[0, byte_offset)` flow into `cleared → padded → state_new`
      and ultimately into the perm-LAST output that the
      transcript reads as the digest. The transcript chiplet's
      digest check then forces those bytes to be the actual
      input bytes (any other choice produces a digest the
      verifier doesn't expect). Soundness completes at the
      transcript level rather than at the sponge-side bus.

    Past-pad rate-XORin rows have `state_new = state_prev`
    regardless of `chunk_lo, chunk_hi`, so trailing zero-pad
    (or garbage) lanes the chunk chiplet may have emitted
    beyond `len_bytes` are algebraically discarded — the digest
    depends only on the first `len_bytes` bytes of the segment.
- **Transcript chiplet contract + div-by-136 gadget**. Transcript
  provides `(sponge_seq_id, chunk_ptr, len_bytes)` on `KeccakSponge`, derives the
  digest address `n_last·3200 + 3072 + i` from the tuple, consumes
  4 digest lanes from Memory64. Designed separately.

- **Per-invocation chunk-lane count is not sponge-enforced
  exactly.** The chunk-zero-fill constraints
  ([§ Chunk zero-fill](#chunk-zero-fill-on-is_chunk_avail--0))
  close the soundness gap on the *lower* bound: any chunk-chiplet
  under-emission causes the sponge to absorb zeros for the
  missing lanes, yielding a deterministic wrong digest the
  transcript chiplet rejects. The *upper* bound — that the chunk
  chiplet emits exactly `4 · ceil(len_bytes / 32)` lanes, rather
  than e.g. `17 · num_blocks` lanes of garbage-tail — is still
  caller-enforced. The future Keccak-eval chiplet (or
  whichever AIR provides `KeccakSponge(sponge_seq_id, chunk_ptr, len_bytes)`) pins
  the chunk chiplet's per-invocation lane count to the exact
  expected value by consuming a chunks-binding tuple from the
  chunk chiplet containing `(sponge_seq_id, n_chunks_or_n_lanes)` and
  locally enforcing the relationship against `len_bytes`. This is
  the analogue of the pvm-design's shared-`ptr`
  mechanism between `Binding(Chunks{n_chunks, ptr})` and
  `KeccakEval(ptr, len_bytes)`.
