# KeccakRound AIR (`hash::keccak::round::KeccakRoundAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/keccak.md](../chiplets/keccak.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/hash/keccak/round/mod.rs` (+ `program.rs`).

## Purpose

A TAM-style miniVM chiplet that computes one Keccak-f[1600] **round** per
period-128 program and stacks 24 rounds to cover a permutation, packed
into `NUM_LANES = 2` parallel column bands so the row count is ~1/2 of a
single stream. Each row executes a single fused three-address operation
`c = ROL(a OP b, s)` (`OP ∈ {XOR, ANDNOT}`, both halves optional), reading
its operands from and writing its result to the
[`Memory64`](relation-registry.md#4--memory64) bus, and verifying its own
byte-level correctness directly against
[`BytePairLut`](relation-registry.md#0--bytepairlut) — no intermediate
chiplet: every row commits its operands, logic result, and (if rotating)
rotate limbs as bytes, and issues the byte-pair / range-check requires
itself.

It **provides** no chiplet-owned relation. It is a pure *consumer/relayer*
on two external buses: it provides destination cells and consumes source
cells on the shared Memory64 multiset bus, and consumes `BytePairLut` to
certify each row's arithmetic. The surrounding sponge AIR balances the
Memory64 σ for it — providing round-0 lane inputs and per-round constants
(RC), consuming last-round outputs — so the chiplet's residue is *not*
self-balancing in isolation (see `../chiplets/keccak.md`).

## Core structure

A single global instruction pointer `ip` increments by 1 every row per
lane; `ip` doubles as the Memory64 address the lane writes to. Source
addresses are `ip − back_a` / `ip − back_b`, with the back-offsets stored
in preprocessed (periodic) columns shared across lanes, so a row's read
addresses are fixed by its slot. Operands (`a`, `b`), the logic result
`r = a OP b` (or `r = a` on no-logic rows), and — on rotating rows — the
rotate limbs are all committed as 8-byte little-endian decompositions.
The periodic selector flags pick which op shape a row runs. An `act` flag
gates every bus emission: it is `0` on each perm cycle's trailing **dead
round** and on trace-tail padding, so those rows touch no bus.

## Trace shape

| Property | Value |
|----------|-------|
| Lanes | `NUM_LANES = 2` |
| Lane width | `LANE_WIDTH = 34` |
| Main width | `NUM_MAIN_COLS = LANE_WIDTH · NUM_LANES = 68` |
| Period | `ROUND_PERIOD = 128` rows = one Keccak round |
| Perm cycle | `PERM_CYCLE = (NUM_ROUNDS + 1) · 128 = 25 · 128 = 3200` rows (24 active rounds + 1 dead round) per lane |
| Height | `next_power_of_two(perms_per_lane · 3200)`; trailing rows walk the program with `act = 0` padding |
| Periodic columns | `NUM_PERIODIC_COLS = 10` preprocessed program columns (verifier-computed, uncommitted), shared across lanes |
| Aux width | `NUM_AUX_COLS = 10 · NUM_LANES = 20` LogUp columns (`COLUMN_SHAPE`: `[1, 2, 2, 2, 2, 2, 2, 2, 2, 2]` per lane) |

The first row's `ip` boundary is `IP_BOUNDARY = 25` (lane 0 only): sponge
addresses `[0, 25)` hold the round-0 lane inputs, `25` is RC[0] (= slot-0
IP), so trace IPs begin at 25. A later lane's absolute `ip` frame is
pinned by the Memory64 bus instead (its round-0 reads of the
sponge-provided initial state), not by a boundary constraint.

## Main columns (per lane; absolute index = `lane · LANE_WIDTH + local`)

| Local col | Range | Name | Meaning |
|-----------|-------|------|---------|
| 0 | — | `COL_IP` | instruction pointer = the Memory64 address this row writes (`dst`) |
| 1–8 | `A_BYTES_RANGE` | `a_bytes[0..8]` | source A, byte-decomposed LSB-first (matched against Memory64 at `ip − back_a`) |
| 9–16 | `B_BYTES_RANGE` | `b_bytes[0..8]` | source B, byte-decomposed (real operand only when `is_xor \| is_andnot`; gated to 0 at the message level otherwise, so the raw column may hold anything on non-logic rows) |
| 17–24 | `R_BYTES_RANGE` | `r_bytes[0..8]` | logic result `r = a OP b`, or the passthrough `r = a` when no logic op is active |
| 25–32 | `ROT_LIMBS_RANGE` | `rot_limbs[0..8]` | populated iff `is_rol = 1`: 16-bit limbs of `(r_half + 2^32)·k` for `r`'s low/high halves — same construction as a rotate chiplet's ROL row, but rotating this row's own `r` |
| 33 | — | `COL_ACT` | active flag: `1` on active rounds, `0` on each cycle's dead round and on trace-tail padding; constant within a round; gates every bus multiplicity |

The Memory64 provide value at `ip` is the muxed expression `is_rol ·
rotated(rot_limbs) + (1 − is_rol) · packed(r_bytes)`, where `rotated`
reconstructs the true 64-bit rotation from `rot_limbs` — including the
half-swap for `ρ ≥ 32` (see `swap` below) — and `packed` re-assembles
`r_bytes` into 32-bit halves (see `hash::keccak::round::mod::rotated_halves`
/ `memory_provide_c`).

### Periodic columns (verifier-computed, uncommitted, shared across lanes)

10 preprocessed program columns of length `ROUND_PERIOD = 128`, built by
`program::round_program()` (canonical column order below). The three
`is_*` op selectors plus `is_xorrol` are 0/1; `back_a`/`back_b`/`k` carry
addresses and the rotation multiplier; `dst_mult`, `p_last`, and `swap`
are structural.

| Idx | Name | Values | Role |
|-----|------|--------|------|
| 0 | `COL_IS_XOR` (`PCOL_IS_XOR`) | `{0, 1}` | row has an XOR (pure XOR or fused XORROL) |
| 1 | `COL_IS_ANDNOT` (`PCOL_IS_ANDNOT`) | `{0, 1}` | row has an ANDNOT (`is_xor + is_andnot ≤ 1`) |
| 2 | `COL_IS_ROL` (`PCOL_IS_ROL`) | `{0, 1}` | row has a rotation (= preprocessed `k ≠ 0` indicator) |
| 3 | `COL_BACK_A` (`PCOL_BACK_A`) | back-offset | `src_a_addr = ip − back_a` |
| 4 | `COL_BACK_B` (`PCOL_BACK_B`) | back-offset | `src_b_addr = ip − back_b` (`0` on pure-ROL / NOP) |
| 5 | `COL_K` (`PCOL_K`) | `2^s`, `s ∈ [0, 30]` | the *reduced* ROL shift multiplier (`0` when `is_rol = 0`) |
| 6 | `COL_DST_MULT` (`PCOL_DST_MULT`) | `∈ {0,1,2,3,5,12}` | destination provide multiplicity (`0` on NOP rows) |
| 7 | `COL_P_LAST` (`PCOL_P_LAST`) | `{0, 1}` | `1` at slot 127 (round's last slot); gates the `act` round-boundary toggle |
| 8 | `COL_IS_XORROL` (`PCOL_IS_XORROL`) | `{0, 1}` | `1` exactly on fused XORROL rows (`= is_xor · is_rol`); subtracted from the selector sum so a fused row's `src_a` read counts once |
| 9 | `COL_SWAP` (`PCOL_SWAP`) | `{0, 1}` | `1` on fused slots whose *true* rotation `ρ ≥ 32`, where the chiplet shift is `ρ − 32 ≤ 30` and the true output's 32-bit halves are the reduced output's halves swapped |

## Constraints

All main-trace (Phase 1) constraints are degree ≤ 2 (the cross-product of
a degree-1 periodic selector with a degree-1 main expression), replicated
per lane over its disjoint column band. Listed in `LiftedAir::eval` order.

### Instruction pointer (per lane)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: ip = 25` (lane 0 only) | 1 | boundary: sponge addresses `[0, 25)` precede the trace IP range, so lane 0's first trace IP is `IP_BOUNDARY = 25` |
| 2 | `when_transition: ip' − ip − 1 = 0` | 1 | `ip` increments by 1; `when_transition` skips the cyclic wrap at row N−1 → 0 |

### Active flag (per lane)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `act · (1 − act) = 0` | 2 | `act` is boolean |
| 4 | `(1 − p_last) · (act' − act) = 0` | 2 | `act` is constant within a round; ungated, vacuous at the cyclic wrap since `p_last = 1` there for any pow2 height ≥ 128 |

### Byte passthrough pin (per lane, per byte `i ∈ [0, 8)`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `(1 − is_xor − is_andnot) · (r_bytes[i] − a_bytes[i]) = 0` | 2 | `r = a` on rows with no logic op active (pure-ROL and NOP rows) |

There is no separate booleanity constraint on the periodic `is_*`
selectors, `dst_mult`, or `k`: those are preprocessed (verifier-computed)
columns, fixed by `round_program()`, not committed witness.

## Buses & lookups (per lane)

Every multiplicity below is **also multiplied by `act`**, so dead-round
and padding rows (`act = 0`) contribute nothing on any bus.

Periodic-flag shorthands used below:

- `is_active = act · (is_xor + is_andnot + is_rol − is_xorrol)` — the
  row's `src_a`-read gate; reduces to `act && reads_a` (every non-NOP op
  reads `src_a` once). Also drives the `BytePairLut` byte requires
  directly — every row that reads `a` at all range-checks it.
- `reads_b = act · (is_xor + is_andnot)` — XOR / ANDNOT / fused XORROL
  read `src_b`.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Memory64`](relation-registry.md#4--memory64) | `(ip, c_lo, c_hi)` | `−act · dst_mult` | every destination-writing row (`dst_mult > 0`) |

The provide is emitted via signed `insert` (negative multiplicity)
rather than `remove`, because `remove` hard-codes mult `−1` and would
mis-account for the multi-value writes — `dst_mult ∈ {1, 2, 3, 5, 12}` in
this program.

### Consumes

| Bus | Tuple | Multiplicity | Notes |
|-----|-------|--------------|-------|
| [`Memory64`](relation-registry.md#4--memory64) | `(ip − back_a, a_lo, a_hi)` (`src_a`) | `is_active` | source A, packed from `a_bytes` |
| [`Memory64`](relation-registry.md#4--memory64) | `(ip − back_b, b_lo, b_hi)` (`src_b`) | `reads_b` | source B, packed from `b_bytes` |
| [`BytePairLut`](relation-registry.md#0--bytepairlut) | `(bpl_op, a_bytes[i], gated_b_bytes[i], r_bytes[i])`, `i ∈ [0, 8)` | `is_active` | 8 byte-wise requires verifying `r = op(a, b)` byte-by-byte; `bpl_op = 1 − is_andnot` (defaults to Xor on pure-ROL rows, combined with `gated_b_bytes[i] = (is_xor+is_andnot)·b_bytes[i]` this issues `BPL(Xor, a, 0, r)`, range-checking `a_bytes` and forcing `r = a` — the replacement for a chain-trick range check) |
| [`Range16`](relation-registry.md#1--range16) | `(rot_limbs[i])`, `i ∈ [0, 8)` | `act · is_rol` | 8 requires range-checking the rotate-limb decomposition |

### Column packing

Each lane's 19 fractions (1 `dst` provide, 2 memory64 requires, 8
`BytePairLut` byte requires, 8 `Range16` limb requires) pack into 10 aux
columns: the running-sum column holds `dst` alone, every other column
holds 2 fractions, keeping every closing constraint at degree ≤ 3
(`log_quotient_degree = 1`).

> The chiplet's Memory64 residue is balanced only by the surrounding
> sponge AIR (which provides round-0 inputs + RCs and consumes last-round
> outputs); in isolation the chiplet's σ does not sum to zero (see
> `../chiplets/keccak.md`, "Trace size" and "Sponge contract").
