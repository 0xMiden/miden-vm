# Bitwise64 AIR (`primitives::bitwise64::Bitwise64Air`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/bitwise64.md](../chiplets/bitwise64.md),
> [../chiplets/bitwise64-chaining.md](../chiplets/bitwise64-chaining.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/primitives/bitwise64.rs`.

## Purpose

A **source** chiplet for 64-bit lane operations, named for the umbrella
("bitwise") rather than any single relation. It **provides** two
relations and mints both from its own committed witness:

- [`Logic64`](relation-registry.md#2--logic64) (2) —
  `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` with `op ∈ {0 = AndNot,
  1 = Xor}` and `c = op(a, b)`, each operand carried as 32-bit halves
  (Goldilocks `p ≈ 2⁶⁴ − 2³² + 1` cannot represent every `u64`
  canonically).
- [`Rol64`](relation-registry.md#3--rol64) (3) —
  `(a_lo, a_hi, b_lo, b_hi, k)` with `b = rol₆₄(a, log₂ k)` and
  `k = 2ˢ` a power of two with `s ≤ 30`.

Both are consumed by the Keccak round chiplet (χ / θ / ρ). To validate
its own results the chiplet **consumes** byte-wise
[`BytePairLut`](relation-registry.md#0--bytepairlut) (0) on LOGIC rows
(verifying `c = op(a, b)` byte-by-byte and implicitly range-checking
each byte to `[0, 256)`) and limb-wise
[`Range16`](relation-registry.md#1--range16) (1) on ROL rows
(range-checking the 16-bit limbs of the offset products). The AIR does
**not** enforce that `k` is a power of two or that `s ≤ 30`; callers
supply `k` from a periodic column of valid values and
`Bitwise64Requires::require_rol` asserts the bound at IR-construction
time (`src/primitives/bitwise64.rs:385`).

## Core structure

Three row modes, gated by the boolean pair `(is_logic, is_rol)`
(`src/primitives/bitwise64.rs:103`):

- **LOGIC** (`1, 0`): provides `Logic64`, consumes 8 byte-wise
  `BytePairLut`. `op_or_k` holds the op tag; `a_bytes` hold the 8 bytes
  of `a`; `b_limbs` hold the 8 bytes of `b`. The result `c` is **not
  committed** — it lives in the *next* row's `a_bytes`, locked there by
  this row's byte consumes referencing `next.a_bytes[i]` as `c_byte`
  (the **chain trick**).
- **ROL** (`0, 1`): provides `Rol64`, consumes 8 limb-wise `Range16`.
  `op_or_k` holds `k`; `b_limbs` hold the eight 16-bit limbs of
  `((a_lo + 2³²)·k, (a_hi + 2³²)·k)` — first four are `(a_lo + 2³²)·k`
  LSB-first, next four are `(a_hi + 2³²)·k`. The `+2³²` offset pushes
  each product out of the aliasable range `[0, 2³² − 2]`, removing the
  need for canonical-decomposition witness columns.
- **Carrier / padding** (`0, 0`): no provide, no consumes. Holds a
  chain value between LOGIC rows (so the previous LOGIC's byte consumes
  resolve), or zero-pads the trace.

**Chaining.** `Bitwise64Requires` *records* requests; `build_chains`
(`src/primitives/bitwise64.rs:440`) packs them into maximal `a`-chains
at trace-gen. Chaining is on operand `a` only, matched by **producer
index, not value** (so repeated values never alias). ROLs claim a
producer first (each must cap a real producer — no fallback), then
LOGICs; each claim graph is a set of disjoint paths. Each path emits one
LOGIC row per link, then either its ROL cap or one trailing dead carrier
holding the uncapped tail's `c`. Packing leaves the
`Logic64` / `Rol64` provide multiset unchanged, so it is invisible to
the bus and the digest — it only shrinks the row count.

**ROL soundness — predecessor must be LOGIC.** ROL rows do not
byte-range-check their own `a_bytes`; that check comes from the
*previous* row's BPL byte consumes (which constrain
`next.a_bytes ∈ [0, 256)`). The cyclic-ungated constraint
`next_is_rol · (1 − is_logic) = 0` forbids any non-LOGIC predecessor,
and `build_chains` lays every ROL directly after its producing LOGIC, so
the invariant holds structurally.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 19` |
| Period / chaining | none — flat row stream; a LOGIC row plus its result-bearing successor are linked by a **next-row** transition (the chain trick), not by a fixed period block |
| Height | `(Σ chains (logics.len() + 1))` rounded up to a power of two, minimum 1; trailing rows are all-zero (`is_logic = is_rol = 0`) padding (`src/primitives/bitwise64.rs:534`) |
| Periodic columns | `0` — none |
| Aux width | `3` (`NUM_AUX_COLS`) LogUp columns, `COLUMN_SHAPE = [1, 8, 8]`; one committed σ residue (col 0) |

## Main columns

Columns 0–7 (`a_bytes`) and 8–15 (`b_limbs`) are **role-polymorphic**:
their bit-width and meaning depend on the row mode. `b_limbs` in
particular is shared across LOGIC (8-bit bytes, range-checked by byte
consumes) and ROL (16-bit limbs, range-checked by `Range16`); the column
never carries more than 16 bits. Columns 16–18 are per-row scalars /
selectors.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0–7 | `A_BYTES_RANGE` (a-byte cells) | LOGIC, ROL, Carrier | each `∈ [0, 256)` on a row whose *predecessor* is LOGIC | the 8 LSB-first bytes of input `a`; reconstructed as halves `a_lo = Σⱼ₌₀³ aⱼ·256ʲ`, `a_hi = Σⱼ₌₄⁷ aⱼ·256ʲ`. On a LOGIC row these also receive the *previous* LOGIC's result `c` (chain trick) |
| 8–15 | `B_LIMBS_RANGE` (b-limb cells) — LOGIC role | LOGIC | each `∈ [0, 256)` (byte) | the 8 LSB-first bytes of operand `b`; `b_lo`/`b_hi` packed base-256. Range-checked via the row's `BytePairLut` consumes |
| 8–15 | `B_LIMBS_RANGE` (b-limb cells) — ROL role | ROL | each `∈ [0, 2¹⁶)` (16-bit) | the eight 16-bit limbs of `((a_lo + 2³²)·k, (a_hi + 2³²)·k)`: cells 8–11 = `(a_lo + 2³²)·k` LSB-first, cells 12–15 = `(a_hi + 2³²)·k`. Range-checked via the row's `Range16` consumes |
| 16 | `COL_OP_OR_K` — LOGIC role | LOGIC | `{0, 1}` | the op tag (`0 = AndNot`, `1 = Xor`); matches `BytePairOp::tag` |
| 16 | `COL_OP_OR_K` — ROL role | ROL | `k = 2ˢ`, `s ≤ 30` (caller-asserted) | the rotation multiplier `k`; AIR does **not** check power-of-two-ness or the bound |
| 16 | `COL_OP_OR_K` — Carrier role | Carrier / padding | `0` | unused |
| 17 | `COL_IS_LOGIC` | all | `{0, 1}` | LOGIC-mode selector; gates the `Logic64` provide and the 8 `BytePairLut` consumes |
| 18 | `COL_IS_ROL` | all | `{0, 1}` | ROL-mode selector; gates the `Rol64` provide and the 8 `Range16` consumes |

## Periodic columns

None. This chiplet uses no `Air::preprocessed_trace` / periodic columns;
its row-mode logic is driven entirely by the committed `is_logic` /
`is_rol` selectors and a single next-row window (`next_is_rol`,
`next.a_bytes`).

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 3
(`src/primitives/bitwise64.rs:661`). There are **6**. The LogUp argument
adds the Phase-2 aux columns (see *Buses & lookups*); no Phase-1
constraint asserts the rolled output `b` directly — its correctness is
carried by the `Rol64` provide tuple, which is reconstructed from the
`Range16`-validated limbs.

### Selector booleanity & mutex

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `is_logic · (1 − is_logic) = 0` | 2 | LOGIC-mode selector is boolean (`assert_bool`) |
| 2 | `is_rol · (1 − is_rol) = 0` | 2 | ROL-mode selector is boolean (`assert_bool`) |
| 3 | `is_logic · is_rol = 0` | 2 | at most one mode active per row; both 0 = carrier / padding |

### Row-ordering (ROL after LOGIC)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `next_is_rol · (1 − is_logic) = 0` (cyclic, ungated) | 2 | a ROL row's predecessor must be LOGIC, so the ROL's `a_bytes` inherit the predecessor's byte-range check. Cyclic-ungated, so it also forbids ROL→ROL, Carrier→ROL, and padding→ROL across the wrap |

### ROL limb decomposition

Gated by `is_rol`; `a_lo`/`a_hi` are the base-256 packs of `a_bytes`,
and `lo_offset_k_decomp` / `hi_offset_k_decomp` are the base-2¹⁶ packs
of `b_limbs[0..4]` / `b_limbs[4..8]`.

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `is_rol · ((a_lo + 2³²)·k − Σⱼ₌₀³ b_limbsⱼ·2¹⁶ʲ) = 0` | 3 | the low offset-product equals its 4-limb decomposition; the `+2³²` offset + `s ≤ 30` bound keep the product in `(2³², p)`, so the decomposition is unique without a witness column |
| 6 | `is_rol · ((a_hi + 2³²)·k − Σⱼ₌₀³ b_limbs₄₊ⱼ·2¹⁶ʲ) = 0` | 3 | same for the high offset-product |

## Buses & lookups

`COLUMN_SHAPE = [1, 8, 8]` (`src/primitives/bitwise64.rs:722`) — three
LogUp columns batching 1, 8 and 8 fractions respectively:

- **Col 0** (`AUX_PROVIDE`): a mutex group of the 2 self-provides
  (`Logic64` / `Rol64`), at most one active per row.
- **Col 1** (`AUX_LOGIC_REQUIRES`): an 8-way batch of the LOGIC byte
  consumes (`BytePairLut`).
- **Col 2** (`AUX_ROL_REQUIRES`): an 8-way batch of the ROL limb
  consumes (`Range16`).

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Logic64`](relation-registry.md#2--logic64) (2) | `(op, a_lo, a_hi, b_lo, b_hi, c_lo, c_hi)` | `−is_logic` | LOGIC rows |
| [`Rol64`](relation-registry.md#3--rol64) (3) | `(a_lo, a_hi, b_lo, b_hi, k)` | `−is_rol` | ROL rows |

Both provides share LogUp column 0. On a LOGIC row `op = op_or_k`,
`(a_lo, a_hi)` pack `a_bytes`, `(b_lo, b_hi)` pack `b_limbs`, and
`(c_lo, c_hi)` pack the **next** row's `a_bytes` (chain trick). On a ROL
row `k = op_or_k`, and the rolled output `b` is reconstructed from the
offset-product limbs — `c0 = b_limbs[0] + b_limbs[6]`,
`c1 = b_limbs[1] + b_limbs[7]`, `c2 = b_limbs[2] + b_limbs[4]`,
`c3 = b_limbs[3] + b_limbs[5]`, then `b_lo = c0 + c1·2¹⁶ − k`,
`b_hi = c2 + c3·2¹⁶ − k` (the `−k` cancels the two `+2³²` offsets per
half) — so the provided `b` is the validated limbs, not a free witness.

### Consumes

| Bus | Tuple / operand | Multiplicity | Notes |
|-----|-----------------|--------------|-------|
| [`BytePairLut`](relation-registry.md#0--bytepairlut) (0), byte `i ∈ 0..8` | `(op, a_bytes[i], b_limbs[i], next.a_bytes[i])` | `is_logic` (per byte) | LOGIC only; the 8 byte consumes verify `c = op(a, b)` byte-by-byte and range-check each `a`/`b`/`c` byte to `[0, 256)`. `c_byte` is the next row's `a_byte` (chain trick). All 8 share LogUp col 1 |
| [`Range16`](relation-registry.md#1--range16) (1), limb `i ∈ 0..8` | `(b_limbs[i],)` | `is_rol` (per limb) | ROL only; range-checks each offset-product limb to `[0, 2¹⁶)`. All 8 share LogUp col 2 |

### Mutex batching

The eight `BytePairLut` consumes (col 1) and the eight `Range16`
consumes (col 2) are each an 8-way **batch** that always pushes 8
fractions per row, with the row-mode gate baked into each insert's
inner multiplicity (`is_logic` for col 1, `is_rol` for col 2). On a row
of the wrong mode every fraction's multiplicity is 0, so the column's
per-row value collapses to 0 — the two batches never overlap because
`is_logic · is_rol = 0`. Col 0's two provides are mutually exclusive by
the same mutex (a LOGIC row fires only `Logic64`, a ROL row only
`Rol64`, a carrier / padding row neither), so the three columns are
legitimately disjoint and the split is purely a constraint-degree
choice (the 8-way batches sit at the degree-9 ceiling; `log_quotient_
degree = 3`).
