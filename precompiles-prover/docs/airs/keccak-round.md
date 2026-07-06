# KeccakRound AIR (`hash::keccak::round::KeccakRoundAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/keccak.md](../chiplets/keccak.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/hash/keccak/round/mod.rs` (+ `program.rs`).

## Purpose

A TAM-style miniVM chiplet that computes one Keccak-f[1600] **round**
per period-128 program and stacks 24 rounds to cover a permutation. Each
row executes a single fused three-address operation `c = ROL(a OP b, s)`
(`OP ∈ {XOR, ANDNOT}`, both halves optional), reading its operands from
and writing its result to the
[`Memory64`](relation-registry.md#4--memory64) bus and delegating the
bit-level work to the Bitwise64 chiplet's
[`Logic64`](relation-registry.md#2--logic64) and
[`Rol64`](relation-registry.md#3--rol64) relations.

It **provides** no chiplet-owned relation. It is a pure *consumer/relayer*
on three external buses: it provides destination cells and consumes source
cells on the shared Memory64 multiset bus, and consumes Logic64 / Rol64 to
certify each row's arithmetic. The surrounding sponge AIR balances the
Memory64 σ for it — providing round-0 lane inputs and per-round constants
(RC), consuming last-round outputs — so the chiplet's residue is *not*
self-balancing in isolation (see `../chiplets/keccak.md`).

## Core structure

A single global instruction pointer `ip` (col 0) increments by 1 every
row; `ip` doubles as the Memory64 address each row writes to. Source
addresses are `ip − back_a` / `ip − back_b`, with the back-offsets stored
in preprocessed (periodic) columns, so a row's read addresses are fixed by
its slot. Operand and result words are committed as 32-bit `(lo, hi)`
halves in cols 1–8; the periodic selector flags pick which of the six op
shapes (NOP, pure ROL, pure XOR, pure ANDNOT, XORROL, ANDNOTROL) the row
runs. A `act` flag (col 9) gates every bus emission: it is `0` on each
perm cycle's trailing **dead round** and on trace-tail padding, so those
rows touch no bus.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 10` |
| Period | `ROUND_PERIOD = 128` rows = one Keccak round |
| Perm cycle | `PERM_CYCLE = (NUM_ROUNDS + 1) · 128 = 25 · 128 = 3200` rows (24 active rounds + 1 dead round) |
| Height | `next_power_of_two(n_perms · 3200)`; trailing rows walk the program with `act = 0` padding |
| Periodic columns | `NUM_PERIODIC_COLS = 9` preprocessed program columns (verifier-computed, uncommitted) |
| Aux width | `NUM_AUX_COLS = 2` LogUp columns (`COLUMN_SHAPE = [3, 2]`) |

The first row's `ip` boundary is `IP_BOUNDARY = 25`: sponge addresses
`[0, 25)` hold the round-0 lane inputs, `25` is RC[0] (= slot-0 IP), so
trace IPs begin at 25.

## Main columns

All ten columns are committed base-field columns. Cols 1–8 are
**role-polymorphic**: a word's *meaning* depends on the slot the row
runs (selected by the periodic flags). On a NOP / padding row none of the
word columns are bus-relevant; the local r-/c-pinning constraints still
hold but read vacuously.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `COL_IP` | all | canonical Goldilocks; `= 25` at row 0, `+1` per row | instruction pointer = the Memory64 address this row writes (`dst`) |
| 1 | `COL_A_LO` | all | `∈ [0, 2³²)` | source A low 32 bits (matched against Memory64 at `ip − back_a`) |
| 2 | `COL_A_HI` | all | `∈ [0, 2³²)` | source A high 32 bits |
| 3 | `COL_B_LO` | all | `∈ [0, 2³²)` | source B low 32 bits (unused / `0` on pure-ROL and NOP rows) |
| 4 | `COL_B_HI` | all | `∈ [0, 2³²)` | source B high 32 bits |
| 5 | `COL_R_LO` | all | `∈ [0, 2³²)` | logic intermediate low: `r = a OP b` on logic rows, pinned `r = a` otherwise |
| 6 | `COL_R_HI` | all | `∈ [0, 2³²)` | logic intermediate high |
| 7 | `COL_C_LO` | all | `∈ [0, 2³²)` | destination low: `c = ROL(r, s)` on ROL rows, pinned `c = r` otherwise |
| 8 | `COL_C_HI` | all | `∈ [0, 2³²)` | destination high |
| 9 | `COL_ACT` | all | `{0, 1}` | active flag: `1` on active rounds, `0` on each cycle's dead round and on trace-tail padding; constant within a round; gates every bus multiplicity |

> ⚠ unverified: the 32-bit range of the word columns (1–8) is not
> asserted by a local constraint in this AIR. The values are pinned
> through the Memory64 / Logic64 / Rol64 bus messages they feed (the
> Bitwise64 chiplet range-checks its operands); only `ip` (boundary +
> transition) and `act` (booleanity) carry local domain constraints
> here, alongside the r-/c-pinning equalities.

### Periodic columns (verifier-computed, uncommitted)

9 preprocessed program columns of length `ROUND_PERIOD = 128`, built by
`program::round_program()` (canonical column order below). The three
`is_*` op selectors plus `is_xorrol` are 0/1; `back_a`/`back_b`/`k` carry
addresses and the rotation multiplier; `dst_mult` and `p_last` are
structural.

| Idx | Name | Values | Role |
|-----|------|--------|------|
| 0 | `COL_IS_XOR` (`PCOL_IS_XOR`) | `{0, 1}` | row has an XOR (pure XOR or fused XORROL) |
| 1 | `COL_IS_ANDNOT` (`PCOL_IS_ANDNOT`) | `{0, 1}` | row has an ANDNOT (`is_xor + is_andnot ≤ 1`) |
| 2 | `COL_IS_ROL` (`PCOL_IS_ROL`) | `{0, 1}` | row has a rotation (= preprocessed `k ≠ 0` indicator) |
| 3 | `COL_BACK_A` (`PCOL_BACK_A`) | back-offset | `src_a_addr = ip − back_a` |
| 4 | `COL_BACK_B` (`PCOL_BACK_B`) | back-offset | `src_b_addr = ip − back_b` (`0` on pure-ROL / NOP) |
| 5 | `COL_K` (`PCOL_K`) | `2^s`, `s ∈ [0, 30]` | ROL shift multiplier (`0` when `is_rol = 0`) |
| 6 | `COL_DST_MULT` (`PCOL_DST_MULT`) | `∈ {0,1,2,3,5,12}` | destination provide multiplicity (`0` on NOP rows) |
| 7 | `COL_P_LAST` (`PCOL_P_LAST`) | `{0, 1}` | `1` at slot 127 (round's last slot); gates the `act` round-boundary toggle |
| 8 | `COL_IS_XORROL` (`PCOL_IS_XORROL`) | `{0, 1}` | `1` exactly on fused XORROL rows (`= is_xor · is_rol`); subtracted from the selector sum so a fused row's `src_a` read counts once |

> Note the index/position split: `p_last` is column **7** and `is_xorrol`
> is column **8** (the canonical `round_program()` tuple order is
> `is_xor, is_andnot, is_rol, back_a, back_b, k, dst_mult, p_last,
> is_xorrol`).

## Constraints

All main-trace (Phase 1) constraints are degree ≤ 2 (the cross-product of
a degree-1 periodic selector with a degree-1 main expression). Listed in
`LiftedAir::eval` order.

### Instruction pointer

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: ip = 25` | 1 | boundary: sponge addresses `[0, 25)` precede the trace IP range, so the first trace IP is `IP_BOUNDARY = 25` |
| 2 | `when_transition: ip' − ip − 1 = 0` | 1 | `ip` increments by 1; `when_transition` skips the `ip` increment's own cyclic wrap at row N−1 → 0. (The LogUp running-sum closes on the last row and no longer wraps.) |

### Active flag

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `act · (1 − act) = 0` | 2 | `act` is boolean (via `assert_bool`) |
| 4 | `(1 − p_last) · (act' − act) = 0` | 2 | `act` is constant within a round. `p_last = 1` only at slot 127, the transition that crosses a round boundary, so `act` may change only into slot 0 of the next round. Applied **ungated**: at the cyclic wrap (row N−1 → 0) row N−1 lands on slot 127 for any pow2 height ≥ 128, so `p_last = 1` makes the wrap vacuous — no `when_transition` needed. No `when_first_row` either: the sponge forces `act = 1` at row 0 by providing RC[0], which slot 1 must consume |

### Operand / result pinning

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `(1 − is_xor − is_andnot) · (r_lo − a_lo) = 0` | 2 | `r = a` on no-logic rows; pins `r` (the Rol64 input) on pure-ROL rows. Vacuous on NOP rows |
| 6 | `(1 − is_xor − is_andnot) · (r_hi − a_hi) = 0` | 2 | high half of the same |
| 7 | `(1 − is_rol) · (c_lo − r_lo) = 0` | 2 | `c = r` on no-ROL rows; pins the destination `c` (the Memory64 provide value) on pure-logic rows, where Rol64 is gated off |
| 8 | `(1 − is_rol) · (c_hi − r_hi) = 0` | 2 | high half of the same |

There is no separate booleanity constraint on the periodic `is_*`
selectors or on `dst_mult`/`k`: those are preprocessed (verifier-computed)
columns, fixed by `round_program()`, not committed witness.

## Buses & lookups

`COLUMN_SHAPE = [3, 2]` — two LogUp columns batching 3 and 2
mutually-exclusive fractions respectively. Every multiplicity below is
**also multiplied by `act`**, so dead-round and padding rows (`act = 0`)
contribute nothing on any bus. The chiplet emits up to 5 bus interactions
on an active fused-op row, 0 on a NOP / padding row.

Periodic-flag shorthands used below:

- `is_active = is_xor + is_andnot + is_rol − is_xorrol` — exactly 1 on
  every non-NOP row (the `− is_xorrol` term un-double-counts a fused row,
  which sets both `is_xor` and `is_rol`).
- `is_logic = is_xor + is_andnot` — 1 iff the row has a logic op.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(ip, c_lo, c_hi)` | `−act · dst_mult` | every destination-writing row (`dst_mult > 0`) |

The provide is emitted via signed `insert` (negative multiplicity)
rather than `remove`, because `remove` hard-codes mult `−1` and would
mis-account for the multi-value writes — `dst_mult ∈ {1, 2, 3, 5, 12}` in
this program (e.g. the ZERO slot's `dst_mult = 12`).

### Consumes

| Bus | Tuple | Multiplicity | Notes |
|-----|-------|--------------|-------|
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(ip − back_a, a_lo, a_hi)` (`src_a`) | `act · is_active` | source A; read once per non-NOP row |
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(ip − back_b, b_lo, b_hi)` (`src_b`) | `act · is_logic` | source B; only logic rows read it |
| [`Logic64`](relation-registry.md#2--logic64) (2) | `(is_xor, a_lo, a_hi, b_lo, b_hi, r_lo, r_hi)` | `act · is_logic` | certifies `r = (a XOR b)` or `r = andnot(a, b)`. `op = is_xor` because `Logic64Op::AndNot` has tag 0 and `Xor` tag 1 |
| [`Rol64`](relation-registry.md#3--rol64) (3) | `(r_lo, r_hi, c_lo, c_hi, k)` | `act · is_rol` | certifies `c = ROL(r, log₂ k)` |

### Mutex batching

The five fractions split across the two σ columns to bound constraint
degree:

- **Col 0** (`memory64`, 3 fractions): the `dst` provide (`−act·dst_mult`)
  plus the `src_a` (`+act·is_active`) and `src_b` (`+act·is_logic`)
  consumes — a **mixed-sign** batch in one running sum. Per the source,
  this column's constraint degree is 4 (D, N each deg 3 after the 3-batch
  recurrence).
- **Col 1** (`bitwise64`, 2 fractions): the Logic64 (`+act·is_logic`) and
  Rol64 (`+act·is_rol`) consumes. Constraint degree 3.

Within each column the multiplicities are one-hot by row-shape: on any
given row a Logic64 read excludes a pure-ROL Rol64 read (logic vs. ROL
selectors are mutually exclusive except on a fused XORROL row, where
both fire but on *distinct* tuples), and the memory `dst`/`src_a`/`src_b`
fractions carry distinct addresses, so the fractions legitimately share
one running sum. The aux blowup factor is 4 (col 0's degree-4 ceiling).

> The chiplet's Memory64 residue is balanced only by the surrounding
> sponge AIR (which provides round-0 inputs + RCs and consumes last-round
> outputs) and by the Bitwise64 chiplet on the Logic64 / Rol64 buses; in
> isolation the chiplet's σ does not sum to zero (see
> `../chiplets/keccak.md`, "Trace size" and "Sponge contract").
