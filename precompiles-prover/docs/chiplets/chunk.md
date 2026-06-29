# Chunk chiplet

> **AIR reference:** [`airs/chunk.md`](../airs/chunk.md) — complete column / constraint / bus reference for this chiplet.

Sits between any chunk-consuming hash chiplet and the
[Poseidon2 permutation chiplet](poseidon2.md). Three jobs:

1. **Populate Memory64** with each chunk's lanes at
   `CHUNK_ADDR_BASE + 4·chunk_seq_id + j` so a downstream hasher can
   read them (one 64-bit lane per Memory64 slot).
2. **Drive a Poseidon2 absorption chain** to content-hash each
   invocation's chunks, with capacity domain-separated by VM
   `Tag::CHUNKS = [2, 0, 0, 0]`.
3. **Expose a per-chain binding** on the `ChunkChain` bus (tuple
   `(chunk_seq_id_head, perm_seq_id_head)`) so a hasher-orchestration
   chiplet can bind its invocation to one absorption chain in a single
   LogUp tuple — closing the chunk-side foreign key on `perm_seq_id`.

One **row per chunk** = 32 bytes = 8 u32 felts = one Poseidon2
absorption block (`rate0[4] || rate1[4]`). The chiplet does **not**
read the digest — that's the consuming hash chiplet's job.
Implemented in [`src/hash/chunk/`](../../src/hash/chunk/).

## Assumptions

1. **One row per chunk; 8 felts per row.** A row holds 8 u32 felts
   `f[0..8]`, the chunk's 256 bits. They serve double duty:
   - **Memory64**: four 64-bit lanes `lane_j = (f[2j], f[2j+1])`
     for `j ∈ [0, 4)`.
   - **Poseidon2**: `rate0 = f[0..4]` (lanes 0–1, tag 0),
     `rate1 = f[4..8]` (lanes 2–3, tag 1). One row = one P2
     absorption cycle.
2. **`chunk_seq_id` is the fully-sequential chunk index**, +1 per
   row from 0. The chunk-tape offset is `4·chunk_seq_id` (each
   chunk owns 4 consecutive Memory64 addresses), so a per-invocation
   base is always `4·chunk_seq_id_head` — 4-aligned.
3. **One chunks-object (= absorption chain) per hash invocation.**
   Each invocation's chunks are a contiguous run of rows; the chain
   head (`is_head`) is the invocation's first chunk and consumes the
   capacity domain separator. Cross-invocation chunks are forbidden
   (the Poseidon hash binds each chunk to one invocation).
4. **No digest readout.** The chiplet feeds P2's rate inputs and the
   chain-head capacity, but never consumes `OutRate0`. The digest is
   read from P2 by the consuming hash chiplet. The chunk chiplet has
   no digest, `n_chunks`, or Binding columns.
5. **Consumer ↔ chunk binding via Memory64 only.** The consuming
   hasher reads Memory64 lanes at `(CHUNK_ADDR_BASE + chunk_ptr, …)`;
   bus balance on `[CHUNK_ADDR_BASE, +∞)` is the only consumer-facing
   contract. The consumer's per-invocation `chunk_ptr` base equals
   `4·chunk_seq_id_head`, carried in whatever request the consumer
   makes against the chunk tape.
6. **Full-chunk emission; hasher-agnostic.** Every chunk emits all
   four Memory64 lanes — the chiplet has no awareness of any hasher's
   block size or padding. Block-fit (e.g. a hasher whose rate doesn't
   divide the 4-lane chunk granularity) is the *consuming hasher's*
   problem: it mops up the 0–3 "overshoot" lanes that spill past its
   block capacity on whatever dedicated rows it uses for that.

## Period structure

**Period 1.** No periodic columns. Row class is decided by witness
selectors (`is_head`, `act`). Trace height is
`Σ_i ceil(len_bytes_i / 32)` padded to a power of two with `act = 0`.

## Bus tuples

Sign convention: provide = `−m`, consume = `+m`. All multiplicities
are gated by `act` so dead trace-tail rows contribute nothing.

| Role | Bus | Dir | Mult | Tuple | Active |
|---|---|---|---|---|---|
| Lane 0 provide | `Memory64` | prov | `−1` | `(CHUNK_ADDR_BASE + 4·chunk_seq_id, f0, f1)` | every active row |
| Lane 1 provide | `Memory64` | prov | `−1` | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 1, f2, f3)` | every active row |
| Lane 2 provide | `Memory64` | prov | `−1` | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 2, f4, f5)` | every active row |
| Lane 3 provide | `Memory64` | prov | `−1` | `(CHUNK_ADDR_BASE + 4·chunk_seq_id + 3, f6, f7)` | every active row |
| P2 `InRate0` consume | `Poseidon2In` | req | `+1` | `(perm_seq_id, 0, f0, f1, f2, f3)` | every active row |
| P2 `InRate1` consume | `Poseidon2In` | req | `+1` | `(perm_seq_id, 1, f4, f5, f6, f7)` | every active row |
| P2 `InCap` consume | `Poseidon2In` | req | `+1` | `(perm_seq_id, 2, 2, 0, 0, 0)` | chain-head rows (`is_head`) |
| `ChunkChain` provide | `ChunkChain` | prov | `−1` | `(chunk_seq_id, perm_seq_id)` | chain-head rows (`is_head`) |

`OutRate0` is deliberately absent (see assumption 4). On chain
heads the P2 chiplet provides `InCap` (gated `is_absorb = 0` on its
side); the chunk chiplet consuming it on `is_head` rows is what ties
the two chains together — `is_absorb(P2 cycle) = 1 − is_head(row)`,
enforced by bus balance.

The `ChunkChain` provide bundles the chain's chunk-side index
(`chunk_seq_id_head`) and P2 cycle (`perm_seq_id_head`) in one tuple
— the hasher-side foreign key. Multiplicity = `−act·is_head` (one
provide per active chain head). Consumers compute their own
hasher-specific addresses from `chunk_seq_id_head` (e.g. the Keccak
node chiplet emits `chunk_ptr_head = 4·chunk_seq_id_head` into its
`KeccakSponge` request); exposing the chunk-chiplet's native index
keeps the bus hasher-agnostic and forbids inter-chunk pointers by
construction.

### Buses

Two pre-existing buses + one provided here:

- `Poseidon2In` (width 6, `BusId::Poseidon2In = 6`) — provided by
  the [Poseidon2 chiplet](poseidon2.md)
  ([`src/transcript/poseidon2/`](../../src/transcript/poseidon2/)), consumed here. The
  message is [`Poseidon2InMsg`](../../src/transcript/poseidon2/messages.rs)
  with constructors `rate0` / `rate1` / `cap`. Fits the existing
  `MAX_MESSAGE_WIDTH = 8`.
- `Memory64` — existing.
- `ChunkChain` (width 2, `BusId::ChunkChain = 9`) — provided here.
  Self-defined by this chiplet, the message is
  [`ChunkChainMsg`](../../src/hash/chunk/message.rs). Consumed by
  hasher-orchestration chiplets (e.g. the Keccak node chiplet).

The Poseidon2 chiplet's caller surface counts In-side consumes via
its `in_multiplicity` (per cycle); the chunk chiplet's per-row
`InRate0` + `InRate1` (+ `InCap` on heads) are exactly those
consumes. The digest's `out_multiplicity` belongs to the
OutRate0 consumer (whichever hasher reads it), independent of this
chiplet — see [§ no digest readout](#open--out-of-scope).

## Columns

### Periodic

None.

### Witness — structural (3)

- `chunk_seq_id` — sequential chunk index; +1 per row, row 0 = 0.
  `4·chunk_seq_id` is the chunk's Memory64 tape base. Global-
  sequential is sound here because the chunk chiplet is the *sole*
  producer of its `CHUNK_ADDR_BASE` tape namespace.
- `perm_seq_id` — Poseidon2 cycle id this row's absorption binds
  to. A genuine **foreign key** into the P2 chiplet's *shared*
  cycle namespace — not derivable, since P2 has multiple callers
  (transcript tree hashing, downstream digest consumers, …)
  interleaving cycles, so the chunk chiplet's cycles are *not* a
  contiguous block. Constrained by a **relaxed within-chain `+1`**
  (gated off at chain heads — see
  [§ `perm_seq_id` chain](#perm_seq_id-chain)), not a global
  sequence: it's free to jump across invocations (interleaving with
  other P2 callers).

  The within-chain `+1` is **load-bearing for soundness**, not
  hygiene. It forces `perm_seq_id` and `chunk_seq_id` to advance in
  lockstep within an invocation, so P2 absorbs the chunks in the
  *same order* the downstream hasher reads them from Memory64
  (`chunk_seq_id`/address order). Without it the prover could
  permute the row→cycle assignment — the `Poseidon2In` bus would
  still balance (same cycle *set* `[C, C+k)`), but P2 would
  content-hash a permuted sequence `H` while the consuming hasher
  hashes the in-order sequence into digest `D`. The downstream
  digest-verification ties `H` and `D` by ptr without re-deriving
  their order, so it would accept a false "chunks-object `H` hashes
  to `D`" binding (`D ≠ hash(bytes-of-H)`). The lockstep closes
  that reorder hole. The chain head's `perm_seq_id` is pinned
  cross-chain by the `InCap` bus (P2 provides `InCap` only at
  `is_absorb = 0` cycles).
- `act` — sticky-downward activity flag. Gates every bus
  multiplicity.

### Witness — selector (1)

- `is_head` — 1 on the chain-head row of each invocation (its first
  chunk), 0 elsewhere. Gates the `InCap` consume; determines the
  P2 chain structure (`is_absorb = 1 − is_head`, tied by the
  `InCap` bus balance). P2 derives chain *tails* as the rows where
  `is_head_next = 1` (it publishes `OutRate0` there for the
  consuming hasher to read).

There is **no** explicit tail / `is_end` marker: tails emit 4 lanes
exactly like interior chunks, and the only consumer that needs the
tail (P2's `OutRate0`) derives it from `is_head_next`.

### Witness — chunk content (8)

- `f[0..8]` — eight u32 felts. `lane_j = (f[2j], f[2j+1])` on
  Memory64; `rate0 = f[0..4]`, `rate1 = f[4..8]` on Poseidon2. All
  four lanes are emitted every active row; `f` is otherwise
  unconstrained at this chiplet (range/content soundness completes
  downstream — see [§ Open](#open--out-of-scope)).

### Witness — LogUp aux (3)

Single σ exposed publicly (`num_aux_values = 1`). Col 0 = running σ +
Memory64 fractions; col 1 = Poseidon2 fractions; col 2 = ChunkChain
fractions. The AIR declares the shared 4-felt transcript root as a public
input but does not read it (only the eval chip does).

### Total

**12 main** (3 structural + 1 selector + 8 content) + **3 aux**.
No periodic columns.

## Constraints

### Boundary (`when_first_row`)

- `chunk_seq_id − 0 = 0`. Chunk index starts at 0.

`perm_seq_id` is **not** pinned at row 0 — its first head's cycle
is bus-pinned (see the [`perm_seq_id` chain](#perm_seq_id-chain)).
`act` and `is_head` are also not pinned at row 0: an all-padding
trace (no chunks) is valid, and when chunks exist the `InCap` bus
balance against P2 forces `is_head` at the right rows (and `act = 1`
there).

### `chunk_seq_id` chain

- `chunk_seq_id' − chunk_seq_id − 1 = 0`. Deg 1, `when_transition`
  (cyclic wrap unconstrained). Runs unconditionally through dead
  rows; the consumes it feeds are `act`-gated.

### `perm_seq_id` chain

- `(1 − is_head_next) · (perm_seq_id' − perm_seq_id − 1) = 0`.
  Deg 2, `when_transition`. Within an absorption chain (every
  transition whose successor is not a new chain head) `perm_seq_id`
  increments by 1, in lockstep with `chunk_seq_id`; at chain heads
  the gate vanishes and `perm_seq_id` jumps freely to the new
  chain's P2 cycle (pinned by the `InCap` bus). No row-0 boundary —
  the first head's cycle is bus-pinned. This lockstep is what makes
  P2's absorption order equal the downstream hasher's (closing the
  reorder hole — see the `perm_seq_id` column above); the
  cross-chain freedom is what lets P2's cycles interleave with
  other callers'.

### Activity

- Binary: `act · (1 − act) = 0`. Deg 2.
- Sticky-downward: `when_transition · (1 − act) · act' = 0`. Deg 2.
  Forces `act` to be a 1-prefix then 0-suffix. No drop-placement
  constraint is needed: a drop mid-invocation truncates that
  invocation's chunk count → the consuming hasher sees missing
  lanes → wrong digest → rejected at digest verification. The
  cyclic wrap is unconstrained.

### Selector binarity and dead-row gating

All deg 2:

- `is_head · (1 − is_head) = 0`.
- `is_head · (1 − act) = 0` — heads only on active rows.

### Why local constraints suffice

The chunk chiplet's local constraints only enforce *shape* (binarity,
dead-row gating, sequential chains). Content and structural
correctness complete across the buses:

- **`is_head` placement** is pinned by `InCap` bus balance: P2
  provides `InCap` only on `is_absorb = 0` cycles, so the chunk
  chiplet's `is_head` pattern must match P2's chain heads exactly,
  or the bus is unbalanced. A misplaced head splits/merges a P2
  chain → wrong digest → digest verification rejects.
- **`f` content** is pinned downstream (range-checked transitively
  by the consuming hasher's byte-level routing for the
  `[0, len_bytes)` bytes; the rest is discarded or digest-checked
  — see [§ Open](#open--out-of-scope)).

### Constraint degree summary

Max local constraint witness-degree: **2** (binarity, dead-row
gating, the `perm_seq_id` within-chain `+1`; the `chunk_seq_id`
chain is deg 1). Well below the LogUp ceiling.

## Lookups

Framework primitive recap (see `byte_pair_lut`): **inserts in a
batch are simultaneous** — their `(α − msg)` denominators fold into
one `(N, D)` pair; **batches in a group are mutex**; **groups in a
column multiply**. The chunk chiplet's messages all co-fire (no
mutual exclusion), so each column is one group with **one batch of
simultaneous inserts**, flag `1`, gating in the per-insert
multiplicities.

### Memory64 (col 0 — one batch, 4 simultaneous inserts)

- all four lanes: mult `−act` (every active row provides all four).

`d = ∏₄ (α − msgⱼ)` deg 4; `n` deg 4 (every insert mult `−act` is
deg 1, × 3 sibling denominators). Column hosts the running σ; the
natural last-row σ-closing gates its recurrence with the degree-1
`is_transition` / `is_last_row` selector, so constraint deg `4 + 2 = 6`
→ **`log_quotient_degree = 3`**.

### Poseidon2In (col 1 — one batch, 3 simultaneous inserts)

- rate0, rate1: mult `+act` (every active row).
- cap: mult `+act · is_head` (chain heads only). Tuple
  `(perm_seq_id, 2, 2, 0, 0, 0)` — the payload is VM
  `Tag::CHUNKS.as_word()`, sourced through `src/transcript/deferred_tags.rs`.

`d = ∏₃` deg 3; `n` deg 4 (cap mult deg 2 × 2 siblings). Fraction
column chained into col 0; constraint deg `max(1 + 3, 4) = 4` →
**`log_quotient_degree = 2`**.

The Memory64 and Poseidon2In groups live in **separate columns** —
groups within a column multiply, which would push past the
log_quot-3 tier.

### Aux columns

| Col | Role | Group | `deg(d)` | Constraint deg | log_quot |
|---|---|---|---|---|---|
| 0 | running σ + Memory64 | 1 batch, 4 inserts | 4 | 6 (= 2 + d, gated close) | **3** |
| 1 | Poseidon2In | 1 batch, 3 inserts | 3 | 4 | **2** |
| 2 | ChunkChain | 1 batch, 1 insert | 1 | 2 | **2** |

Cols 1 and 2 chain into col 0's running-sum recurrence as scalar additions
(don't multiply col 0's denominator). Single σ exposed. Max
`log_quotient_degree = 3` across the chiplet (set by col 0's gated
last-row close).

### Worst-case per-row active inserts

| Scenario | Memory64 | Poseidon2 | ChunkChain | Total |
|---|---|---|---|---|
| Chain-head (`act, is_head`) | 4 | 3 (rate0, rate1, cap) | 1 | 8 |
| Interior / tail | 4 | 2 | 0 | 6 |
| Dead (`act = 0`) | 0 | 0 | 0 | 0 |

## Chunk granularity vs hasher block size

The chunk chiplet emits a fixed 4 lanes (32 bytes) per chunk and is
deliberately blind to any hasher's block structure. If a hasher's
rate `r` (in lanes) doesn't divide 4, an invocation's chunk tape
(`4·num_chunks` lanes) overshoots the hasher's block capacity by
`4·num_chunks mod r ∈ {0, …, r−1}` lanes. Those overshoot lanes are
the *consuming hasher's* problem: it consumes and discards them on
whatever dedicated rows it uses for that. The chunk chiplet itself
does nothing special: full chunks, always.

## Open / out of scope

- **OutRate0 / digest readout**. The Poseidon2 chiplet provides
  `OutRate0` (the chunks-object digest) at chain tails, gated by its
  `out_multiplicity` (count of digest consumers); the consuming
  hash chiplet reads it, keyed by `perm_seq_id` of the tail. The
  chunk chiplet sets only the P2 `in_multiplicity` (its rate/cap
  consumes), never `out_multiplicity`. Until a digest consumer
  materialises, the digest side is simply unconsumed
  (`out_multiplicity = 0` on those cycles) — no standalone imbalance,
  since the Poseidon2 chiplet gates its `OutRate0` provide by
  `out_multiplicity`. The consuming hasher reads `OutRate0` at
  `perm_seq_id_head + n_chunks − 1`, where `perm_seq_id_head` is
  pulled from this chiplet's `ChunkChain` provide.
- **Range-check posture on `f`**. The chunk chiplet does not
  range-check `f[0..8]` to `[0, 2^32)`. Only the `[0, len_bytes)`
  bytes are guaranteed canonical, transitively, via whatever
  byte-level decomposition the consuming hasher applies to its
  Memory64 reads. Lanes past `len_bytes` (the zero-tail within the
  last used chunk and the overshoot lanes) are AIR-unbinded here;
  the P2 hash commits whatever is in `f`, so a non-canonical or
  non-zero trailing felt produces a digest the consumer's check
  rejects. Soundness completes at the transcript level.
- **Trace generation**. Given invocation byte slices, the prover
  lays out one row per chunk: `chunk_seq_id` running, `perm_seq_id`
  aligned to the P2 chiplet's allocated cycles, `is_head` on each
  invocation's first chunk, `f` packed LE (zero-padded past the
  input). Detailed algorithm + the P2 co-generation contract: designed
  with the implementation.
