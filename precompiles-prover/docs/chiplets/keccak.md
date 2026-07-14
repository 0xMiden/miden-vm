# Keccak-round miniVM chiplet

> **AIR reference:** [`airs/keccak-round.md`](../airs/keccak-round.md) — complete column / constraint / bus reference for this chiplet.

Orchestrates a single Keccak-f[1600] round via a three-address machine
(TAM) over the 64-bit memory bus. Repeats 24 times in a row-major
periodic program to cover one permutation; multiple permutations
stack cleanly in one trace, with the sponge AIR overwriting state at
absorb boundaries.

Implementation: [`src/hash/keccak/round/`](../../src/hash/keccak/round/).
Tests: [`src/tests/keccak.rs`](../../src/tests/keccak.rs).

## Architecture

- **Memory64 bus is a multiset of `(addr, lo, hi)` tuples.** Each cell
  is identified by a felt address and carries a 64-bit word as
  `(lo, hi)` u32 halves. The bus balances per-tuple: at a given
  address, two distinct values are two independent bus entries, each
  with its own provide/require accounting. Within one permutation we
  use it as a single-assignment store (the chiplet writes each cell
  once and consumers read it `m` times). Across permutations, the
  chiplet inserts a **dead round** at the end of each perm cycle so
  that perm N's last-perm outputs and perm N+1's round-0 inputs live
  at disjoint addresses — no per-address actor sharing, no multiset
  reliance for the seam. See "Multi-permutation traces" below.
- **25 rounds per cycle, 24 active + 1 dead.** The dead round runs
  the same period-128 program but with `act = 0`, so its bus mults
  vanish. Its 128 IPs sit between perm N's outputs and perm N+1's
  round-0 inputs, creating the address gap that the sponge writes
  fresh state into.
- **Fused TAM operation per row**: `c = ROL(a OP b, s)` where OP is
  XOR or ANDNOT and `s` is the row's *true* rotation (any amount FIPS 202
  needs — the chiplet's own byte-level rotate machinery handles `s ≥ 32`
  via a half-swap, see below). Both the logic and the ROL parts are
  optional — `is_rol = 0` means no rotation, `is_xor = is_andnot = 0`
  means no logic. One row format covers six op shapes:

  | is_xor | is_andnot | is_rol | meaning |
  | --- | --- | --- | --- |
  | 0 | 0 | 0 | NOP |
  | 0 | 0 | 1 | pure ROL: `c = ROL(a, s)` |
  | 1 | 0 | 0 | pure XOR: `c = a ⊕ b` |
  | 0 | 1 | 0 | pure ANDNOT: `c = andnot(a, b)` |
  | 1 | 0 | 1 | XORROL: `c = ROL(a ⊕ b, s)` |
  | 0 | 1 | 1 | ANDNOTROL: `c = ROL(andnot(a, b), s)` |

- **`NUM_LANES = 2` parallel column bands**, each running a contiguous
  block of permutations in its own disjoint band while sharing the
  (preprocessed, free) periodic program — the row count is ~1/2 of a
  single stream. Lane 0 keeps the explicit `ip = 25` anchor; a later
  lane's absolute `ip` frame is pinned by the Memory64 bus instead (its
  round-0 reads of the sponge-provided initial state).
- **Global IP** column per lane, increments by 1 every row.
- **Source addresses are IP-relative back-offsets** stored in
  preprocessed period-128 columns (`back_a`, `back_b`), shared across
  lanes. Destinations always write to `ip`. NOP slots set selectors and
  `dst_mult` to 0, leaving their IP unclaimed for an external producer
  (the sponge chiplet) to fill.
- **No intermediate chiplet.** Every row commits its own operands
  (`a_bytes`, `b_bytes`), logic result (`r_bytes`), and — on rotating
  rows — rotate limbs (`rot_limbs`) as byte/limb decompositions, and
  verifies them directly against [`BytePairLut`](byte_pair_lut.md) (byte
  requires + `Range16` requires), reusing the exact `+2^32` offset limb
  construction a rotate chiplet used to do in its own separate table.
  For `ρ ≥ 32`, the chiplet certifies the *reduced* rotation `ρ − 32 ≤
  30` (the byte/limb mechanism's soundness bound) and reconstructs the
  true rotated value by half-swapping the reduced output's 32-bit
  halves — `ROL(x, ρ) = halfswap(ROL(x, ρ − 32))` — for both the
  Memory64 provide and the true output every downstream row reads.
- **Sponge chiplet** provides round-0 lane inputs (all 25 lanes, into
  the dead-round IP gap) and per-round RCs, consumes round-23
  outputs (all 25 lanes — rate and capacity uniformly). Same memory
  bus, contract below.

## Per-row format

**Main columns, per lane (34), `NUM_MAIN_COLS = 68` total:**

| col | role |
| --- | --- |
| `ip` | row counter, transition `ip' − ip − 1 = 0` |
| `a_bytes[0..8]` | source A, byte-decomposed (matched against memory bus) |
| `b_bytes[0..8]` | source B, byte-decomposed (real operand only when `is_xor \| is_andnot`; gated to 0 at the message level otherwise) |
| `r_bytes[0..8]` | logic result `r = a OP b`, or the passthrough `r = a` when no logic op is active |
| `rot_limbs[0..8]` | populated iff `is_rol = 1`: 16-bit limbs of `(r_half + 2^32)·k` for `r`'s halves |
| `act` | 1 on active rounds, 0 on the dead round of each cycle and on trace-tail padding; constant within each round (changes only at round boundaries). Every bus multiplicity is multiplied by `act`. |

**Preprocessed columns (10), period 128, shared across lanes:**

| col | role |
| --- | --- |
| `is_xor` | binary, 1 if XOR present |
| `is_andnot` | binary, 1 if ANDNOT present (`is_xor + is_andnot ≤ 1`) |
| `is_rol` | binary, 1 if ROL present |
| `is_xorrol` | binary, 1 exactly on fused XORROL rows (= `is_xor · is_rol`); subtracted from the selector sum so a fused row's `src_a` read counts once, not twice |
| `back_a` | source A back-offset (`src_a_addr = ip − back_a`) |
| `back_b` | source B back-offset (unused for pure ROL, set 0) |
| `k` | the *reduced* ROL shift multiplier `2^shift`, `shift ≤ 30` (0 if `is_rol = 0`) |
| `dst_mult` | destination provide multiplicity |
| `p_last` | 1 at slot 127 of each round, 0 elsewhere (gates `act` round-boundary toggles) |
| `swap` | 1 on fused slots whose *true* rotation `ρ ≥ 32` |

Destinations always write to `ip` — no `dst_back_off` column. NOP slots
(including the RC slot at position 0) have `dst_mult = 0`.

## Local constraints (per row, per lane)

Active gating:

```
act · (1 − act) = 0                              (binary)
(1 − p_last) · (act' − act) = 0                  (constant within round)
```

`p_last` fires at slot 127 (the round's last slot). At that row the
multiplier vanishes and `act` is free to change across the transition
into slot 0 of the next round; at the other 127 rows of each round
`(1 − p_last) = 1` pins `act` constant. Applied ungated: at the
cyclic wrap row `N−1` (slot 127 for any pow2 height ≥ 128) the
multiplier is also zero, so the wrap to row 0 imposes no constraint.
`when_first_row` is absent from `act`: the sponge bus forces
`act = 1` at row 0 through its RC[0] provide, which the chiplet's
slot 1 must consume.

Beyond the bus interactions, the row pins `r` on rows with no logic op,
byte-wise for each `i ∈ [0, 8)`:

```
(1 − is_xor − is_andnot) · (r_bytes[i] − a_bytes[i]) = 0     (r = a when no logic)
```

Deg 2. Plus the IP transition `ip' − ip − 1 = 0` (deg 2,
`when_transition`) and the boundary `ip = 25` at row 0
(`when_first_row`, lane 0 only).

## Bus interactions per row (per lane)

All multiplicities below are *also* multiplied by `act`, so trace-tail
padding rows (with `act = 0`) contribute nothing on either bus.

| bus | direction | mult | message |
| --- | --- | --- | --- |
| memory64 | require | `is_active = act · (is_xor + is_andnot + is_rol − is_xorrol)` | `(ip − back_a, a_lo, a_hi)` |
| memory64 | require | `act · (is_xor + is_andnot)` | `(ip − back_b, b_lo, b_hi)` |
| memory64 | provide | `act · dst_mult` | `(ip, c_lo, c_hi)` — muxed: `is_rol` selects `rotated(rot_limbs)` (half-swapped if `swap`), else `packed(r_bytes)` |
| BytePairLut | require, ×8 | `is_active` | `(bpl_op, a_bytes[i], gated_b_bytes[i], r_bytes[i])` — `bpl_op = 1 − is_andnot` |
| Range16 | require, ×8 | `act · is_rol` | `(rot_limbs[i])` |

Up to 19 bus interactions on an active fused-op row (2 memory64 + 8 BPL +
8 Range16 + provide), 0 on NOP rows or padding rows — all packed into 10
aux columns per lane (2 fractions/column, the provide alone in the
running-sum column).

The `BytePairLut` `op` field uses `1 − is_andnot` (not `is_xor` directly)
because on pure-ROL rows (`is_xor = is_andnot = 0`) it must default to
Xor (tag 1) so the request resolves to `BPL(Xor, a, 0, r)` — range-checking
`a_bytes` and forcing `r = a`, the replacement for a chain-trick range
check now that every row commits its own bytes.

The memory provide uses `g.insert(flag=ONE, multiplicity=-dst_mult)`
rather than `g.remove(flag=dst_mult)`: the convenience `g.remove`
treats its flag as binary and pushes mult = -1 on the prover side,
which mis-accounts for the multi-value writes (`dst_mult ∈ {1, 2, 3, 5, 12}`
in this program). The explicit `insert` makes prover and constraint
paths agree.

## Operation count for one round

| step | ops | notes |
| --- | --- | --- |
| θ C-comp | 20 | 5 × balanced 4-XOR tree |
| θ D-ROL | 5 | one ROL(1) per x |
| θ D-XOR | 5 | `D[x] = C[(x−1) mod 5] ⊕ ROL(C[(x+1) mod 5], 1)` |
| θ-apply + ρπ | 25 | one fused XORROL per non-(0,0) lane (24, full-range via half-swap) + 1 plain XOR (lane (0,0), ρ=0); occupies 25 of the 37 reserved slot positions `[32, 69)`, the other 12 are NOP |
| χ ANDNOTs | 25 | one per output lane |
| χ XORs | 25 | 24 final outputs + 1 intermediate for (0,0) |
| ι | 1 | `A_final[0][0] = chi_00 ⊕ RC[r]` |
| RC slot | 1 | NOP; sponge writes `RC[r]` at this IP |
| NOP | 21 | 12 unused apply+ρπ slot positions + 1 ZERO slot + 8 trailing slackers |
| **total** | **128** | |

### ρ decomposition

Each lane's rotation resolves to one row, whatever the true amount
`ρ ∈ [0, 63]`. The chiplet's own byte/limb rotate mechanism
(`rot_limbs`, verified against `Range16`) certifies rotations up to
`shift ≤ 30` directly; for `ρ ≥ 32` the row certifies the *reduced*
rotation `ρ − 32 ≤ 30` and reconstructs the true output by
half-swapping the reduced result's 32-bit halves —
`ROL(x, ρ) = halfswap(ROL(x, ρ − 32))` — both for the value written
to Memory64 and for what any downstream row reads. `swap` (the
periodic column, 1 iff `ρ ≥ 32`) and `k` (the reduced multiplier
`2^shift`) are materialized once by `program::rol_decompose`. Keccak's
ρ table never lands in `[31, 35]`, so `ρ − 32 ≤ 30` always holds for
`ρ ≥ 32`.

ρ table (FIPS 202, x rows × y cols, indexed by *input* lane):

```
        y=0  y=1  y=2  y=3  y=4
x=0:    0   36    3   41   18
x=1:    1   44   10   45    2
x=2:   62    6   43   15   61
x=3:   28   55   25   21   56
x=4:   27   20   39    8   14
```

| ρ range | lanes | op | rows per lane |
| --- | --- | --- | --- |
| 0 | (0,0) | plain XOR, no rotation | 1 |
| [1, 30] | 14 | XORROL, `k = 2^ρ`, `swap = 0` | 1 |
| [32, 63] | 10 | XORROL, `k = 2^(ρ−32)`, `swap = 1` | 1 |
| **sum** | 25 | | **25** |

## Slot layout (period 128)

```
[  0,   1)  RC slot                (NOP; sponge writes RC[r] at this IP)
[  1,   2)  ZERO slot              (Andnot(RC, RC) = 0; mult 12)
[  2,  22)  θ C-computation        (20 XORs, 5 balanced trees)
[ 22,  27)  θ D-ROL                (5 ROL(1) ops)
[ 27,  32)  θ D-XOR                (5 XOR ops, produce D[0..5])
[ 32,  69)  θ-apply + ρπ           (37 ops, post-π row-major order)
[ 69,  94)  χ ANDNOTs              (25 ops)
[ 94, 102)  8 NO-OP slackers       (room for future tweaks)
[102, 103)  χ XOR for lane (0,0)   (intermediate, read by ι)
[103, 104)  ι: chi_00 ⊕ RC[r]      (final output for lane (0,0))
[104, 128)  χ XORs for 24 other lanes (final outputs feeding next round)
```

### Why this exact layout

- **RC slot at 0** of every round. The sponge writes RC[r] at IP
  `25 + r·128`, giving a contiguous external address space:
  `[0, 25)` for round-0 lane inputs (natural row-major:
  `state[i]` at addr `i`), `25` for RC[0], `26` for zero[0]
  (= chiplet-produced zero at slot 1's IP), then trace IPs.
- **ZERO slot at 1.** `Andnot(RC[r], RC[r]) = 0` for any `RC[r]`.
  This synthesizes a memory-bus zero cell so trailing ρπ rows can
  read `src_b = 0` via a constant intra-round back-offset
  (`back_b = trailing_slot − 1`). RC[r] mult bumps from 1 to 3 per
  round (ι reads it once; ZERO's src_a and src_b each read it).
- **ι at slot 103** (before the other χ XORs) so the 25 next-round
  inputs land in natural row-major order:
  `state[0] = lane (0,0)` at sponge addr 0,
  `state[24] = lane (4,4)` at sponge addr 24.
- **χ XORs for non-(0,0) lanes at slots 104..128** in row-major order
  by lane index. With `ip = 25` at row 0, round 0's cross-round reads
  land at sponge addresses `[0, 25)` exactly,
  `state[idx]` at addr `idx`.
- **Lane (0,0) special-cased.** χ XOR for (0,0) at slot 102 is the
  intermediate `chi_00 = B[0][0] ⊕ t[0][0]` (mult 1, read only by ι);
  ι output at slot 103 is the round's exported (0,0) value (mult 2,
  read by next round's θ).
- **8 NOP slackers** at slots 94..101 give headroom for future program
  tweaks (e.g., switching χ formulation) without breaking the
  period-128 constraint.

## ZERO slot (slot 1)

```
slot 1:  ANDNOT(RC[r], RC[r])  →  zero[r] = 0   dst_mult 12
```

Sources: both `src_a` and `src_b` point at slot 0 (the RC slot) with
`back_a = back_b = 1`. RC[r] mult bumps to 3 per round
(2 from ZERO slot + 1 from ι).

Read by the 12 trailing apply+ρπ rows for their `src_b` (constant
intra-round back-offset `trailing_slot − 1`).

## θ C-computation (slots 2..22)

For each `x ∈ [0, 5)`, compute
`C[x] = A[x][0] ⊕ A[x][1] ⊕ A[x][2] ⊕ A[x][3] ⊕ A[x][4]` as a
balanced 4-XOR tree at slots `[4x + 2, 4x + 6)`:

```
slot 4x+2:  XOR(A[x][0], A[x][1])   →  t_x0    dst_mult 1
slot 4x+3:  XOR(A[x][2], A[x][3])   →  t_x1    dst_mult 1
slot 4x+4:  XOR(t_x0, t_x1)         →  t_x2    dst_mult 1
slot 4x+5:  XOR(t_x2, A[x][4])      →  C[x]    dst_mult 2 (D[x±1] read it)
```

Source back-offsets pull `A[x][y]` from the previous round's χ output.
Previous-round slot positions:

- `s_χ_prev[0][0] = 103` (ι output of previous round).
- `s_χ_prev[x][y] = 103 + (x + 5y)` for `(x, y) ≠ (0, 0)` — i.e.
  `state[idx]` at slot `103 + idx` for idx ∈ [1, 24].

`back_a[s] = 128 + s − s_χ_prev[lane]` for cross-round reads;
`back_a[s] = s − source_slot` for intra-round reads.

## θ D (slots 22..32)

D-ROL slots (pure ROL with k=2, dst_mult = 1):

```
slot 22:  ROL(C[1], 1)   →  rc1
slot 23:  ROL(C[2], 1)   →  rc2
slot 24:  ROL(C[3], 1)   →  rc3
slot 25:  ROL(C[4], 1)   →  rc4
slot 26:  ROL(C[0], 1)   →  rc0
```

D-XOR slots (pure XOR, dst_mult = 5 — read once per `y` in apply+ρπ):

```
slot 27:  XOR(C[4], rc1)   →  D[0]
slot 28:  XOR(C[0], rc2)   →  D[1]
slot 29:  XOR(C[1], rc3)   →  D[2]
slot 30:  XOR(C[2], rc4)   →  D[3]
slot 31:  XOR(C[3], rc0)   →  D[4]
```

Each `C[x]` is read exactly twice: by `D[(x+1) mod 5]`'s ROL and by
`D[(x−1) mod 5]`'s XOR. C-comp `dst_mult = 2` matches.

## θ-apply + ρπ (slots 32..69)

After θ, each lane `A'[x][y] = A[x][y] ⊕ D[x]` is rotated by `ρ[x][y]`
and placed at position `π(x, y) = (y, (2x + 3y) mod 5)`. The chiplet
emits **exactly one row per output lane**, in post-π row-major order
(`out_y` outer, `out_x` inner), full-range in one fused op — `Xor`
for lane (0,0) (`ρ = 0`), `XorRol(ρ)` otherwise, using the true `ρ`;
the row's own byte/limb rotate mechanism handles the full range
(§ρ decomposition). Operand order chains a fan-out-5 `D[x]` on
`src_a` only for the column's first lane (`in_y == 0`, where `A`
can't chain further since its carrier is already spent at the θ
C-tree); every other lane keeps `A` in `src_a` (swapping costs +234
rows/keccak, measured).

`B[out_x][out_y]` is the row's own output, `dst_mult = 3` (each B
value is read 3× in χ). The 25 real ops occupy 25 of the 37 reserved
slot positions `[32, 69)`; the remaining 12 are NOP. Exact slot
indices, per-lane sources, and `ρ` values are in
[`program::slot_b`](../../src/hash/keccak/round/program.rs) and
[`program::emit_apply_rpi`](../../src/hash/keccak/round/program.rs)
— the canonical source, not reproduced here to avoid a second,
driftable copy.

## χ (slots 69..128, with NOP gap at 94..101 and ι at slot 103)

ANDNOTs at slots `[69, 94)`, row-major over output (x, y):

```
slot 69 + (x + 5y):  ANDNOT(B[(x+1) mod 5][y], B[(x+2) mod 5][y]) → t[x][y]
                     dst_mult 1 (read by matching χ XOR)
```

χ XOR for lane (0, 0) at slot 102 — intermediate (read only by ι):

```
slot 102:  XOR(B[0][0], t[0][0])  →  chi_00   dst_mult 1
```

ι at slot 103 — `state[0]` after the round:

```
slot 103:  XOR(chi_00, RC[r])  →  A_final[0][0]   dst_mult 2
```

Sources for ι:
- `src_a` = chi_00 from slot 102, `back_a = 103 − 102 = 1`.
- `src_b` = RC[r] from slot 0 of same round, `back_b = 103 − 0 = 103`.

χ XORs for the other 24 lanes at slots `[104, 128)` in row-major order
over `(x, y) ≠ (0, 0)` with index `idx = x + 5y`:

```
slot 104 + (idx − 1):  XOR(B[x][y], t[x][y])  →  A_χ[x][y]
                       dst_mult 2 (next round's C-comp and apply)
```

Net effect: `state[i]` (post-permutation lane at row-major index `i`)
lives at slot `103 + i` for all `i ∈ [0, 25)` — natural row-major
addressing for the sponge.

## Address-space layout

Each Keccak takes a 25-round cycle: 24 active rounds + 1 dead round
at the end. Cycle stride = 25 · 128 = 3200 rows / IPs.

```
[0, 25)             sponge perm-0 round-0 inputs for the first Keccak
                    (state[i] at addr i; sponge writes)
25 + n·3200         trace IP at row 0 of cycle n; = RC[0] addr for perm n
26 + n·3200         ZERO slot IP (chiplet-produced zero, mult 12)
[25 + n·3200,
 25 + n·3200+3072)  trace IPs for perm n's 24 active rounds
[25 + n·3200+3072,
 25 + (n+1)·3200)   trace IPs for cycle n's dead round (act = 0,
                    no chiplet bus emission). The last 25 of these IPs
                    coincide with perm n+1's round-0 input addresses.
25 + n·3200 + r·128 RC[r] address (sponge writes; coincides with
                    round-r RC slot IP), for r ∈ [0, 24)
26 + n·3200 + r·128 zero[r] address (chiplet provides; coincides with
                    round-r ZERO slot IP), for r ∈ [0, 24)
n·3200 + 3072 + i   perm n's last-perm output addresses (slots 103..127
                    of round 23 of cycle n), for i ∈ [0, 25). Mult 2 each.
(n+1)·3200 + i      perm n+1's round-0 input addresses for i ∈ [0, 25).
                    Disjoint from perm n's last outputs (separated by
                    103 unclaimed dead-round IPs). Sponge writes.
```

For a single Keccak (n = 0):
- IP at row 0 = 25. Trace rows 0..3199, IPs `[25, 3225)`.
- Sponge addresses (perm 0 inputs):
  - `state[i] = lane at (x, y) = (i mod 5, i / 5)` at addr `i` for
    `i ∈ [0, 25)`, mult 2 each.
  - RC[r] at addr `25 + r·128` for `r ∈ [0, 24)`, mult 3 (ι + ZERO ×2).
- Chiplet-produced cells (active rounds only):
  - zero[r] = 0 at addr `26 + r·128` for `r ∈ [0, 24)`, mult 12 each.
- Last-round outputs (consumed by sponge):
  - `state[i]` after the permutation lives at IP
    `25 + 23·128 + 103 + i = 3072 + i` for `i ∈ [0, 25)`. Lane (0, 0)
    at offset 103 (ι output), others at 104..127. Mult 2 each.
- Dead round IPs `[3097, 3225)`: no chiplet bus emission; the last 25
  (`[3200, 3225)`) are perm-1's round-0 input addresses if a perm 1
  follows.

For N stacked Keccaks: Keccak n's cycle starts at IP `25 + n·3200`,
ends at `25 + (n+1)·3200`. Perm n's last-perm outputs at
`[n·3200 + 3072, n·3200 + 3097)` are disjoint from perm n+1's round-0
inputs at `[(n+1)·3200, (n+1)·3200 + 25)` — the dead round's 103-IP
gap sits between them. **No two-tuple-at-same-address multiset trick
needed; each address has exactly one producer + one consumer.**

## Multi-permutation traces

Perm N's last-perm output IPs and perm N+1's round-0 input IPs are
**disjoint**, separated by the 103-IP unclaimed range of cycle N's
dead round. With cycle stride 3200:

- Perm N's last-perm outputs at IPs `[n·3200 + 3072, n·3200 + 3097)`
  (slots 103..127 of round 23 of cycle N), `dst_mult = 2` each.
- Cycle N's dead round at IPs `[n·3200 + 3097, n·3200 + 3225)`:
  128 IPs claimed by no row's bus emission (act = 0 zeroes all mults).
- Perm N+1's round-0 input IPs at `[(n+1)·3200, (n+1)·3200 + 25)`
  via the constant cross-round back-offset (`back_a` at slot s of
  round 0 = `128 + s − s_χ_prev[lane]`, giving read IP
  `current_ip − back_a = (n+1)·3200 + i` for the i-th lane).
  These IPs sit at the tail end of cycle N's dead round, which has
  `act = 0`; the chiplet emits nothing there, so the sponge alone
  produces the values the round-0 reads consume.

The sponge inserts itself at both ends of the seam:

| step | tuple | actor | mult |
| --- | --- | --- | --- |
| perm N writes lane `i` output | `(n·3200 + 3072 + i, v_N)` | chiplet provide | +2 |
| sponge consumes perm N's output | `(n·3200 + 3072 + i, v_N)` | sponge require | −2 |
| sponge writes perm N+1 input | `((n+1)·3200 + i, v_N+1_in)` | sponge provide | +2 |
| perm N+1 reads lane `i` input | `((n+1)·3200 + i, v_N+1_in)` | chiplet require | −2 |

Two **distinct addresses**, each with exactly one provider + one
consumer. Per-tuple balance is therefore per-address unambiguous: a
malicious prover has no second tuple at the same address with which
to cross-pair (round N provider ↔ round N+1 consumer at the same
address, leaving sponge's consume/provide to pair with each other on
a different value).

`v_N+1_in` is the sponge's choice — `v_N ⊕ block_i` for rate lanes in
intra-invocation absorbs, `v_N` for capacity lanes in the same
(capacity carries through identically across absorbs), and
`block_i || 0_capacity` for the first perm of a fresh invocation.
The sponge AIR's local constraints pin those values; the round
chiplet just reads whatever the bus delivers.

**Capacity lanes follow the same shape as rate lanes.** Both pass
through the sponge's consume → provide pair. Intra-invocation
capacity has sponge provide value = sponge consume value (identity);
fresh-invocation capacity has provide value = 0. The chiplet bus
contract treats all 25 lanes uniformly: produce-and-consume one tuple
per address.

**Fresh invocation start** is the same shape — sponge consumes the
prior invocation's last-perm outputs (squeezing 4 digest lanes via
the transcript chiplet, 21 non-digest via itself) and provides the
new perm 0's round-0 inputs at the new addresses (rate = `block_0`,
capacity = 0). All 25 cells, all at fresh addresses.

**Soundness**: per-tuple bus balance is enforced by the LogUp running
sum (cross-AIR identity `prod = 1, sum = 0`). Each seam tuple has
exactly 2 actors (one provider + one consumer), so per-tuple balance
uniquely pins provider value = consumer value. No alternate pairing
assignment is algebraically available to a malicious prover.

## Trace size

Per Keccak cycle: 25 · 128 = **3,200 rows** (24 active + 1 dead).

Stacked N permutations: `3200·N` rows, padded to the next power of two.

| N | rows used | trace size | rows wasted |
| --- | --- | --- | --- |
| 1 | 3,200 | 4,096 | 896 |
| 10 | 32,000 | 32,768 | 768 |
| 20 | 64,000 | 65,536 | 1,536 |
| 81 | 259,200 | 262,144 | 2,944 |
| 100 | 320,000 | 524,288 | 204,288 |
| 163 | 521,600 | 524,288 | 2,688 |
| 327 | 1,046,400 | 1,048,576 | 2,176 |

For batched proving, 81 Keccaks at 262,144 rows, 163 at 524,288, or
327 at 1,048,576 are the natural sweet spots — each pads ≤ 1.2% of
the trace.

The dead round at the end of each cycle contributes nothing to the
bus (act = 0 zeroes every multiplicity). It exists solely to space
perm N's outputs apart from perm N+1's round-0 inputs in IP space —
a "structural padding" round whose 128 rows enable the address
separation that prevents cross-perm bus malleability.

Padding rows beyond the last Keccak continue to execute the period-128
program (IPs incrementing) with `act = 0`, indistinguishable from the
dead round. The chiplet's residue σ in isolation isn't balanced (no
sponge counterpart); the sponge / surrounding system balances the σ
in a full proof.

## Sponge contract

Per Keccak permutation `n` (= cycle `n` of the round chiplet) with
cycle start at IP `S_n = 25 + n·3200`, the sponge AIR's bus
interactions are:

1. **Round-r RC** — provide at mult 3 each, for `r ∈ [0, 24)`:
   - RC[r] at address `S_n + r·128`. Mult 3 = ι (1) + ZERO slot src_a
     and src_b (2). The dead round (r = 24) has no RC.
2. **Perm N's round-0 inputs** — provide at mult 2 each, all 25 lanes:
   - `state_in[i]` at address `n·3200 + i` for `i ∈ [0, 25)`.
   - Intra-invocation absorbs: `state_in[i] = perm_(N−1)_out[i] ⊕
     block_i` for rate (`i ∈ [0, 17)`), `state_in[i] =
     perm_(N−1)_out[i]` for capacity (`i ∈ [17, 25)`; identity).
   - First perm of an invocation: `state_in[i] = block_i` for rate,
     `state_in[i] = 0` for capacity.
3. **Perm N's last-perm outputs** — require at mult 2 each, all 25
   lanes:
   - `perm_N_out[i]` at address `n·3200 + 3072 + i` for `i ∈ [0, 25)`
     (lane (0, 0) at offset 3072 from ι at slot 103; others at
     3073..3096 from χ XORs at slots 104..127).
   - Intra-invocation: sponge consumes all 25 to feed perm N+1's
     input (rate via XOR with the next block, capacity unchanged).
   - Last perm of an invocation: sponge consumes the 21 non-digest
     lanes (`i ∈ [4, 25)`); the transcript chiplet consumes the 4
     digest lanes (`i ∈ [0, 4)`).

The 24 RC values are the standard Keccak-f[1600] round-constant
schedule — a fixed pattern per `r`.

The chiplet produces zero internally (slot 1, `Andnot(RC[r], RC[r])`),
so the sponge does *not* provide a zero cell. RC[r] is read 3× per
round; sponge multiplicity matches.

The sponge AIR's own state (cumulative absorb buffer, invocation
boundaries, squeeze routing) is internal to that chiplet and not
visible on the Memory64 bus — only the boundary `(addr, lo, hi)`
tuples are.

## Bus accounting (per Keccak)

The chiplet's bus contributions are independent of the surrounding
sponge configuration:

| flow | count | per-cell mult | total mult |
| --- | --- | --- | --- |
| miniVM → memory64 (provides, all dst rows) | varies | varies | matches all reads internal to this perm + 2 reads per output lane (next perm's C-comp + apply) |
| miniVM → BytePairLut (byte requires, 8/row) | per round: 106 non-NOP rows (52 XOR + 25 ANDNOT + 5 ROL + 24 XORROL) × 8 = 848 | 1 | 24 · 848 = 20,352 |
| miniVM → Range16 (limb requires, 8/row) | per round: 29 rotating rows (5 pure ROL + 24 XORROL) × 8 = 232 | 1 | 24 · 232 = 5,568 |

Every request above is verified directly on the chiplet's own rows —
there is no separate chiplet whose trace is "sized independently"; the
BytePairLut/Range16 demand lands on the shared leaf table
([`byte_pair_lut.md`](byte_pair_lut.md)), sized from every caller's
combined requests.

The sponge AIR's bus contributions depend on its role at each
permutation boundary. With the dead-round address separation, every
perm boundary has sponge action on **all 25 lanes** (rate and
capacity uniformly), and each tuple is a clean two-actor pair
(sponge provider/consumer + chiplet consumer/provider at distinct
addresses).

| sponge role | per-perm memory64 interactions |
| --- | --- |
| First perm of invocation, round-0 inputs | 25 provides at mult 2 (17 rate = `block_i`, 8 capacity = 0) |
| Intra-invocation perm boundary | 25 requires + 25 provides at mult 2 each (rate XOR'd with next block, capacity carried through identically) |
| Each permutation's RCs | 24 provides at mult 3 |
| Last perm of invocation, squeeze | 21 non-digest requires at mult 2 (sponge) + 4 digest requires at mult 2 (transcript chiplet, on a separate bus) |

The chiplet's IPs in the dead round are unclaimed by both the chiplet
(act = 0) and (for IPs `[n·3200 + 3097, (n+1)·3200)`) by nobody; the
sponge's perm N+1 input provides land in the **last 25** of cycle N's
dead-round IPs, which the chiplet's perm N+1 round-0 reads consume.

## Implementation status

Live in [`src/hash/keccak/round/`](../../src/hash/keccak/round/):

- [`program.rs`](../../src/hash/keccak/round/program.rs) — slot table,
  periodic-column materialization, `Op` enum, `Slot` accessor.
- [`mod.rs`](../../src/hash/keccak/round/mod.rs) — `KeccakRoundAir`,
  `generate_trace`, `extract_output`. Constraints and lookup
  interactions, including the direct `BytePairLut`/`Range16` byte-level
  verification (no intermediate chiplet).

Tests in [`src/tests/keccak.rs`](../../src/tests/keccak.rs):

- Per-round oracle agreement against a FIPS 202 reference.
- Full 24-round permutation oracle agreement (zero, patterned, random
  inputs).
- `check_constraints` on the generated trace for canonical and random
  single-perm inputs, plus a 3-perm stacked trace.

The sponge ([`src/hash/keccak/sponge/`](../../src/hash/keccak/sponge/))
and Keccak node ([`src/hash/keccak/node/`](../../src/hash/keccak/node/))
are also landed; the full stack proves and verifies end-to-end, so the
Memory64 bus closes against the sponge's round-0-input / RC provides and
last-round output consumes.

## Future work

The round chiplet's own bus contract is complete — the sponge AIR
supplies the RC schedule, the all-25-lane round-0 input provides, and
the last-round output consumes, balancing the Memory64 σ across the
stack (verified by `bench_keccak_n`). The remaining round-relevant item
is the project-wide
[heterogeneous constraint degrees](../forward-looking.md).
