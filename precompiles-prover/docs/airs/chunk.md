# Chunk AIR (`hash::chunk::ChunkAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/chunk.md](../chiplets/chunk.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/hash/chunk/mod.rs`.

## Purpose

A **feeder** chiplet: it tiles each hash invocation's raw input bytes
into 32-byte chunks (one row per chunk) and routes every chunk three
ways. It **provides** each chunk's four 64-bit lanes on the
[`Memory64`](relation-registry.md#4--memory64) bus at
`CHUNK_ADDR_BASE + 4·chunk_seq_id + j` so a downstream hasher can read
them; it **consumes** the [`Poseidon2In`](relation-registry.md#6--poseidon2in)
rate (and, on chain heads, capacity) to drive a Poseidon2 absorption
chain that content-hashes each invocation; and it **provides** a
per-chain binding on the [`ChunkChain`](relation-registry.md#9--chunkchain)
bus pairing the chain's chunk-side index with its Poseidon2 cycle, so a
hasher-orchestration chiplet (Keccak node, …) can bind its invocation to
one absorption chain in a single tuple.

The chiplet does **not** read the Poseidon2 digest — `OutRate0` is the
downstream digest consumer's to consume. It mints no value of its own:
content/range soundness of `f[0..8]` completes downstream, transitively,
via the consuming hasher's byte-level routing and the P2 digest check.

## Core structure

Period **1** — there are no periodic columns; a row's class is decided
entirely by its witness selectors (`is_head`, `act`). Each row holds one
chunk's eight u32 felts `f[0..8]` (the chunk's 256 bits), which serve
double duty: four 64-bit Memory64 lanes `lane_j = (f[2j], f[2j+1])`, and
the two Poseidon2 rate halves `rate0 = f[0..4]` / `rate1 = f[4..8]` of a
single absorption cycle.

Two sequence counters thread the trace. `chunk_seq_id` increments by 1
globally (row 0 = 0) and is the chiplet's native chunk index; it is the
sole producer of the `CHUNK_ADDR_BASE` Memory64 namespace, so a global
sequence is sound. `perm_seq_id` is a **foreign key** into Poseidon2's
shared cycle namespace; it is constrained only by a **relaxed
within-chain `+1`** (the gate vanishes at chain heads), letting it jump
freely across invocations to interleave with P2's other callers while
forcing lockstep with `chunk_seq_id` inside an invocation. That lockstep
is load-bearing for soundness: it makes P2 absorb chunks in the same
order the downstream hasher reads them, closing a reorder hole that bus
balance alone would not detect.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 12` |
| Period | `1` row = one 32-byte chunk = one P2 absorption cycle |
| Height | `total_chunks` (`Σᵢ ⌈len_bytesᵢ / 32⌉`) rounded up to a power of two (min 1); trailing rows are inactive (`act = 0`) padding with `chunk_seq_id` / `perm_seq_id` continuing `+1` to satisfy the relaxed chains |
| Periodic columns | none (period 1) |
| Aux width | `3` LogUp columns (`COLUMN_SHAPE = [4, 3, 1]`); col 0 hosts the running σ |

Empty input still lays one canonical all-zero chunk (`num_chunks` is
`div_ceil(len, 32).max(1)`), so every invocation's chain has ≥ 1 row.

## Main columns

All 12 columns are committed base-field witnesses. Columns 0–3 are
structural / selector; columns 4–11 are the chunk content `f[0..8]`. No
column is role-polymorphic (period 1) and none is cycle-constant.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `COL_CHUNK_SEQ_ID` | all | `[0, height)`, `+1` per row, row 0 = 0 | sequential chunk index; `4·chunk_seq_id` is the chunk's Memory64 tape base |
| 1 | `COL_PERM_SEQ_ID` | all | P2 cycle id (foreign key) | the Poseidon2 cycle this row's absorption binds to; `+1` within a chain, free at heads |
| 2 | `COL_ACT` | all | `{0, 1}`, sticky-downward | activity flag; gates every bus multiplicity so dead trace-tail rows touch no bus |
| 3 | `COL_IS_HEAD` | all | `{0, 1}` | `1` on the chain-head (first chunk) row of each invocation; gates the `InCap` consume and the `ChunkChain` provide; `is_absorb = 1 − is_head` on the P2 side |
| 4 | `f[0]` (`COL_F_BEGIN`) | all | felt (AIR-unbinded here) | chunk word 0: Memory64 `lane0.lo`; P2 `rate0[0]` |
| 5 | `f[1]` | all | felt (AIR-unbinded here) | chunk word 1: Memory64 `lane0.hi`; P2 `rate0[1]` |
| 6 | `f[2]` | all | felt (AIR-unbinded here) | chunk word 2: Memory64 `lane1.lo`; P2 `rate0[2]` |
| 7 | `f[3]` | all | felt (AIR-unbinded here) | chunk word 3: Memory64 `lane1.hi`; P2 `rate0[3]` |
| 8 | `f[4]` | all | felt (AIR-unbinded here) | chunk word 4: Memory64 `lane2.lo`; P2 `rate1[0]` |
| 9 | `f[5]` | all | felt (AIR-unbinded here) | chunk word 5: Memory64 `lane2.hi`; P2 `rate1[1]` |
| 10 | `f[6]` | all | felt (AIR-unbinded here) | chunk word 6: Memory64 `lane3.lo`; P2 `rate1[2]` |
| 11 | `f[7]` (`COL_F_END − 1`) | all | felt (AIR-unbinded here) | chunk word 7: Memory64 `lane3.hi`; P2 `rate1[3]` |

`f` is range-unconstrained at this chiplet: only the `[0, len_bytes)`
bytes are guaranteed canonical, transitively, via the consuming hasher's
byte-level decomposition of its Memory64 reads; the P2 hash commits
whatever is in `f`, so any non-canonical / non-zero trailing felt yields
a digest the consumer's check rejects.

## Periodic columns

None — the chiplet runs at period 1, so it commits no periodic role
selectors. Row class is read from the `is_head` / `act` witness cells.

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 2. Source:
`ChunkAir::eval` in `src/hash/chunk/mod.rs`.

### Boundary (`when_first_row`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `when_first_row: chunk_seq_id = 0` | 1 | the native chunk index starts at 0; `perm_seq_id` / `act` / `is_head` are intentionally **un**pinned at row 0 (an all-padding trace is valid, and the first head's P2 cycle is pinned cross-chain by the `InCap` bus, not by a boundary constraint) |

### Sequence chains

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 2 | `when_transition: chunk_seq_idₙₑₓₜ − chunk_seq_id − 1 = 0` | 1 | global `+1` chunk index; runs unconditionally (including through dead rows so padding stays sequential), the cyclic wrap left unconstrained |
| 3 | `when_transition: (1 − is_headₙₑₓₜ) · (perm_seq_idₙₑₓₜ − perm_seq_id − 1) = 0` | 2 | relaxed within-chain `+1`: inside an absorption chain (successor not a new head) `perm_seq_id` advances in lockstep with `chunk_seq_id`; at chain heads the gate vanishes so it jumps freely to the new chain's P2 cycle. The lockstep forces P2's absorption order to equal the downstream hasher's Memory64 (address) order |

### Activity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 4 | `act · (1 − act) = 0` | 2 | activity flag is boolean |
| 5 | `when_transition: (1 − act) · actₙₑₓₜ = 0` | 2 | sticky-downward: once `act` drops it stays 0, so `act` is a 1-prefix then 0-suffix. A mid-invocation drop truncates that invocation's chunk count → the consuming hasher sees missing lanes → wrong digest → rejected downstream (no drop-placement constraint needed); cyclic wrap unconstrained |

### Selector

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `is_head · (1 − is_head) = 0` | 2 | chain-head flag is boolean |
| 7 | `is_head · (1 − act) = 0` | 2 | heads occur only on active rows (a head on a dead row would emit a spurious `InCap` / `ChunkChain` demand) |

Local constraints enforce only *shape*. `is_head` **placement** is pinned
by `InCap` bus balance (P2 provides `InCap` solely on `is_absorb = 0`
cycles, so the `is_head` pattern must match P2's chain heads exactly);
`f` **content** is pinned downstream. Max local witness-degree is **2**,
well below the LogUp ceiling.

## Buses & lookups

`COLUMN_SHAPE = [4, 3, 1]` — three LogUp columns batching 4, 3, and
1 mutually-co-firing fraction(s) respectively. Col 0 hosts the running σ;
cols 1 and 2 chain into col 0's running-sum recurrence as scalar additions
(they do not multiply col 0's denominator). A single σ is exposed
(`num_aux_values = NUM_SIGMA_VALUES`); the AIR declares the shared 4-felt
transcript root as a public input but does not read it (only the eval chip
does). Per-column witness-degrees are 6 / 4 / 2, giving
`log_quotient_degree = 3`.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Memory64`](relation-registry.md#4--memory64) (4) — lane 0 | `(CHUNK_ADDR_BASE + 4·chunk_seq_id, f[0], f[1])` | `−act` | every active row |
| [`Memory64`](relation-registry.md#4--memory64) (4) — lane 1 | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 1, f[2], f[3])` | `−act` | every active row |
| [`Memory64`](relation-registry.md#4--memory64) (4) — lane 2 | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 2, f[4], f[5])` | `−act` | every active row |
| [`Memory64`](relation-registry.md#4--memory64) (4) — lane 3 | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 3, f[6], f[7])` | `−act` | every active row |
| [`ChunkChain`](relation-registry.md#9--chunkchain) (9) | `(chunk_seq_id, perm_seq_id)` | `−act · is_head` | chain-head rows |

Memory64 provides stay at mult 1 per active row (`−act`): each chunk row
has exactly one downstream hasher consumer by the orchestrator's CR-dedup
invariant. The `ChunkChain` tuple carries the chunk-chiplet's **native**
index `chunk_seq_id_head` (not a hasher address), keeping the bus
hasher-agnostic — the consumer multiplies by its own lane width (e.g. the
Keccak node emits `chunk_ptr_head = 4·chunk_seq_id_head`) — and forbidding
inter-chunk addresses by construction.

### Consumes

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) — rate0 | `(perm_seq_id, 0, f[0], f[1], f[2], f[3])` | `act` | every active row |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) — rate1 | `(perm_seq_id, 1, f[4], f[5], f[6], f[7])` | `act` | every active row |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) — cap | `(perm_seq_id, 2, 2, 0, 0, 0)` | `act · is_head` | chain-head rows |

The `tag` field (`0` / `1` / `2`) is the rate0 / rate1 / capacity
selector minted by `Poseidon2InMsg::{rate0, rate1, cap}`. The capacity
payload is VM `Tag::CHUNKS.as_word() = [2, 0, 0, 0]`. These rate/cap
consumes are exactly the P2 chiplet's per-cycle `in_multiplicity`; the
chiplet never touches `out_multiplicity` (the digest side).

### Mutex batching

The eight fractions split across three σ columns to keep each column's
constraint degree inside the `log_quotient_degree = 3` tier (groups
within one column multiply their denominators):

- **Col 0** (`memory64`, 4 fractions): the four Memory64 lane provides,
  all mult `−act`. Hosts the running σ; denominator degree 4. The
  σ-hosting column is gated by `is_transition` / `is_last_row` for its
  last-row close, so its constraint degree is `4 + 2 = 6`.
- **Col 1** (`poseidon2-in`, 3 fractions): rate0, rate1 (mult `act`) and
  cap (mult `act · is_head`). Denominator degree 3, constraint degree
  `max(1 + 3, 4) = 4`.
- **Col 2** (`chunk-chain`, 1 fraction): the chain-head `ChunkChain`
  emit, mult `−act · is_head`. Denominator degree 1, constraint degree 2.

Within each column the inserts are **simultaneous** (a single batch with
flag `1`, gating folded into the per-insert multiplicities) — the
chiplet's messages all co-fire, so they fold into one `(N, D)` pair per
column rather than being mutually exclusive by row.
