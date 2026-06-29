# Bitwise64 — 64-bit lane bitwise chiplet

> **AIR reference:** [`airs/bitwise64.md`](../airs/bitwise64.md) — complete column / constraint / bus reference for this chiplet.

Provides Keccak-shaped 64-bit logic ops and bit-rotates. Required
by the [Keccak round chiplet](keccak.md); requires
[`BytePairLut`](byte_pair_lut.md) byte-wise on LOGIC rows and
`Range16` limb-wise on ROL rows.

Implementation: [`src/primitives/bitwise64.rs`](../../src/primitives/bitwise64.rs).

## Row modes

Two row modes, gated by booleans `is_logic` and `is_rol`
(mutex enforced; both 0 = carrier/padding):

- **LOGIC**: provides `Logic64(op, a_lo, a_hi, b_lo, b_hi,
  c_lo, c_hi)` with `op ∈ {0=AndNot, 1=Xor}` and 32-bit halves
  (Goldilocks `p ≈ 2^64 − 2^32 + 1` cannot represent every
  `u64` canonically). Requires 8 byte-wise
  `BytePairLut(op, a_byte, b_byte, c_byte)` lookups, verifying
  `c = op(a, b)` byte-by-byte and implicitly range-checking
  each byte to `[0, 256)`. `c` is *not* committed — see the
  chain trick below.
- **ROL**: provides `Rol64(a_lo, a_hi, b_lo, b_hi, k)` with
  `b = rol_64(a, log2(k))` and `k = 2^s` a power of two `< 2^31`.
  Requires 8 `Range16` lookups for the 16-bit limbs of
  `((lo+2^32)·k, (hi+2^32)·k)`. The +2^32 offset eliminates the
  *low-end* limb-decomposition alias (`v + p` fits in `u64` for
  `v ∈ [0, 2^32 − 2]`); the `s ≤ 30` bound eliminates the
  *high-end* alias by forcing every `(half + 2^32)·k < p`. ROLs
  by `s ∈ [31, 63]` decompose into a swap-halves + ROL by
  `s − 32` on the caller side. The AIR does not enforce `k`'s
  power-of-two-ness; callers (the Keccak round) supply `k` from
  a periodic column of valid values.

Named for the umbrella ("bitwise") rather than any single
relation; future ops sharing the trace shape land alongside
without renaming.

## Layout

- **Width**: 19 main columns + 3 aux columns. Main: 8 `a_bytes`
  + 8 `b_limbs` (dual-purpose: 8-bit on LOGIC, 16-bit on ROL)
  + `op_or_k` (op tag on LOGIC, `k` on ROL) + 2 selectors.
  Aux: `aux_provide` (Logic64 + Rol64 self-provides combined,
  deg 3), `aux_logic_requires` (8 BPL byte summands, deg 9),
  `aux_rol_requires` (8 Range16 summands, deg 9).
- **`log_quotient_degree = 3`** — dominated by the deg-9
  requires columns.

## LOGIC chain trick

Each LOGIC row's `c` lives in the *next* row's `a_bytes`, locked
there by the byte-wise requires (which reference
`next_row.a_bytes[i]` as `c_byte`). So a LOGIC whose `a` is a prior
LOGIC's `c` can sit immediately after it, reusing the bytes the
producer's requires already constrained — no intermediate row.

`Bitwise64Requires` *records* requests rather than laying rows
eagerly; `build_chains` packs them at trace-gen. Chaining is on
operand `a` only, matched by **producer index**, not value — so
repeated values (the many θ chains producing `0`) never alias:

1. Map each value to the LOGIC requests producing it (by index).
2. ROLs claim first (each *must* cap a real producer — no
   fallback), then LOGICs; each takes the latest unclaimed producer
   of its `a` issued before it. One claimer per producer ⇒ the
   claim graph is a set of disjoint paths.
3. Walk each path from its head (a LOGIC that claimed nothing) into
   a `Chain { logics, cap: Option<RolCap> }` and emit: a LOGIC row
   per link, then the ROL cap, or one trailing dead carrier holding
   the uncapped tail's `c`.

Every chain is `L + 1` rows for `L` logics; a ROL-capped chain
spends the `+1` on a useful ROL row, an uncapped one on a dead
carrier. The packer recovers every recyclable carrier, so the only
carriers left are chain terminals that nothing consumes as an `a`.

ROL-priority is load-bearing: the contended value is `C[x]`, read
both by a D-ROL (rotate) and a D-XOR (chain on `a`); the ROL has no
fallback, so it must win. The driver must therefore emit a rotation
before any LOGIC that chains onto the same result — Keccak emits
every D-ROL before its D-XOR — else `build_chains` panics.

## ROL row construction

ROL's `b_limbs` carry 16-bit limbs of `(lo+2^32)·k` (first 4)
and `(hi+2^32)·k` (next 4). Two aliasing concerns shape the
soundness:

- **Low-end** (`v + p < 2^64`, i.e. `v ∈ [0, 2^32 − 2]`): a
  malicious decomposition of `v + p` represents the same Felt
  with different limbs. The `+2^32` offset moves `v` outside
  this range.
- **High-end** (`v ≥ p`): `v − p` is also a valid 4-limb
  decomposition for the same Felt. Avoided by capping `k ≤ 2^30`
  so that `(half + 2^32)·k_max = (2^33 − 1)·2^30 = 2^63 − 2^30 < p`.
  At `k = 2^31` the upper bound flips: max product becomes
  `(2^33 − 1)·2^31 = 2^64 − 2^31 > p`, leaving room for the
  attacker.

Together the two bounds eliminate the need for canonical-
decomposition witness columns. The chiplet enforces the bound
at IR-construction time (`Bitwise64Requires::require_rol`).
Constraints:

- Limb-decomp: `(a_lo + 2^32) · k = b_limbs[0] + b_limbs[1]·2^16
  + b_limbs[2]·2^32 + b_limbs[3]·2^48`, same shape for
  `(a_hi + 2^32) · k`.
- Range16 requires per limb (8 per row).
- **Rolled-output construction**: with `k = 2^s` the bit windows
  of `lo·k` and `2^32·hi·k` are disjoint, so the rolled lane's
  16-bit limbs are simple integer sums (pairing each low-half limb
  with the high-half limb that shares its bit window after the
  rotate): `c0 = b_limbs[0] + b_limbs[6]`,
  `c1 = b_limbs[1] + b_limbs[7]`, `c2 = b_limbs[2] + b_limbs[4]`,
  `c3 = b_limbs[3] + b_limbs[5]`.
  The +2^32 offsets contribute an extra +k to each 32-bit half,
  so the final packed halves are `b_lo = c0 + c1·2^16 - k`,
  `b_hi = c2 + c3·2^16 - k`.

## ROL soundness — predecessor must be LOGIC

ROL rows do not byte-range-check their own `a_bytes`. The
range check comes from the *previous* row's BPL byte requires
(which constrain `next_row.a_bytes ∈ [0, 256)`). Constraint
`is_rol_next · (1 − is_logic) = 0` (cyclic ungated) forbids
any non-LOGIC predecessor: subsumes ROL/ROL forbid AND
Carrier→ROL forbid AND padding→ROL at the cyclic wrap.

`build_chains` enforces this on the IR side: every ROL must claim a
prior LOGIC producing its `a`, which caps that producer's chain so
the ROL row directly follows a LOGIC. It panics if none exists. The
caller must emit that producing LOGIC before any LOGIC that would
chain onto the same `c`; for Keccak's `θ → ρ` ordering this happens
naturally.

## Disabled-row a_bytes are intentionally out-of-circuit

Carrier and trailing-padding rows' `a_bytes` aren't
byte-range-checked when the previous row is also disabled.
This is a non-issue: nothing reads those bytes in any
soundness-affecting constraint. With `is_logic = is_rol = 0`,
all per-row LogUp contributions zero out (the col-1/col-2
fraction constraints `D_i · acc[i] = N_i = 0` force
`acc[i] = 0` for any nonzero `D_i`, which holds whp under
fresh FS challenges), and col 0's mutex provides fold to
`(U, V) = (1, 0)`. The σ commitment and cross-AIR identity
are unaffected by whatever values sit in those slots.
