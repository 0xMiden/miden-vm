# KeccakNode AIR (`hash::keccak::node::KeccakNodeAir`)

> **Scope.** Complete column / constraint / bus reference.
> Design rationale: [../chiplets/keccak-node.md](../chiplets/keccak-node.md).
> Bus tuple shapes: [relation-registry.md](relation-registry.md).
> Source: `src/hash/keccak/node/mod.rs`, `src/hash/keccak/node/trace.rs`.

## Purpose

An **orchestrator** chiplet: it binds one whole Keccak invocation into
the transcript DAG, one row per invocation. Per active row it ties
together a [chunk-absorption chain](chunk.md) and one
[sponge](keccak-sponge.md) run, reads the resulting 4-lane Keccak
digest `D` out of [`Memory64`](relation-registry.md#4--memory64), drives
**two** Poseidon2 perms over the
[`Poseidon2In`](relation-registry.md#6--poseidon2in) /
[`Poseidon2Out`](relation-registry.md#7--poseidon2out) buses (a
semantic one-chunk hash of `D`, then a `Keccak`-node hash of
`[H_input_chunks | H_digest_chunks]`), and **provides**
[`Binding`](relation-registry.md#8--binding)`(H_keccak, True)` — the
assertion consumed by the parent DAG node. It also **provides** the
per-invocation [`KeccakSponge`](relation-registry.md#5--keccaksponge)
request and **consumes** the chunk chiplet's
[`ChunkChain`](relation-registry.md#9--chunkchain) head.

It mints no stored value: every namespace identifier (`sponge_seq_id_head`,
`perm_seq_id_chunks`, …) and every hash (`D`, `H_input_chunks`,
`H_digest_chunks`, `H_keccak`) is **witnessed** and pinned by bus balance against the
sponge / chunk / Poseidon2 chiplets that actually produce it. Soundness
is the conjunction of those bus pinnings plus the content-addressing of
`H_keccak`: a wrong input yields a hash no DAG consumer matches, so the
`Binding` bus imbalances.

## Trace shape

| Property | Value |
|----------|-------|
| Main width | `NUM_MAIN_COLS = 30` |
| Period | `1` row = one Keccak invocation (no periodic columns) |
| Height | `n_invocations.next_power_of_two().max(1)`; trailing rows are inactive (`act = 0`) padding |
| Periodic columns | none |
| Aux width | `NUM_AUX_COLS = 4` LogUp columns (`COLUMN_SHAPE = [4, 4, 4, 4]`); single exposed σ |

One row per Keccak invocation. The accumulator dedupes by Keccak digest
(`(content, len_bytes)` identity): a duplicate input bumps the existing
row's `out_mult` and lays no new row, so a digest bound by N parents is
a single row at `out_mult = N` (true dedup, no per-`2¹⁶` row split).

## Main columns

All 30 columns are **per-row witnesses** (period 1; no role
polymorphism, no cycle-constancy). Multi-felt fields (`D`, the three
hashes) occupy contiguous index ranges.

| Col | Name | On rows | Range / values | Meaning |
|-----|------|---------|----------------|---------|
| 0 | `COL_ACT` | all | `{0, 1}` | sticky-downward block-active flag; gates every bus multiplicity (padding rows touch no bus) |
| 1 | `COL_SPONGE_SEQ_ID_HEAD` | all | sponge row counter | sponge invocation start; pinned by the `KeccakSponge` provide, advanced `+32·n_sponge_perms` across rows |
| 2 | `COL_N_SPONGE_PERMS` | all | block count | Keccak permutations (= sponge blocks) this invocation occupies; free witness, sponge-side pinned to `floor(len_bytes / 136) + 1` |
| 3 | `COL_CHUNK_SEQ_ID_HEAD` | all | chunk index | head chunk index of this invocation's chain; pinned by the `ChunkChain` consume, advanced `+n_chunks` across rows |
| 4 | `COL_N_CHUNKS` | all | chain length | chunks in this invocation's chain; free witness, bus-pinned to `ceil(17·n_sponge_perms / 4)` |
| 5 | `COL_PERM_SEQ_ID_CHUNKS` | all | P2 cycle | P2 cycle at the head of the chunks-absorption chain; pinned **per row** by `ChunkChain`, **not** constrained across rows (P2 is a shared namespace) |
| 6 | `COL_LEN_BYTES` | all | byte length | invocation byte length; pinned by `KeccakSponge`, folded into the keccak-node cap's `param_a` slot |
| 7 | `COL_PERM_SEQ_ID_DIGEST_CHUNKS` | all | P2 cycle | P2 cycle hashing `D` as a semantic one-chunk payload; free witness, P2-bus pinned |
| 8 | `COL_PERM_SEQ_ID_KECCAK` | all | P2 cycle | P2 cycle hashing `[H_input_chunks \| H_digest_chunks]` into the `Keccak` node; free witness, P2-bus pinned |
| 9–16 | `COL_D_BEGIN..COL_D_END` (`NUM_D = 8`) | all | each `∈ [0, 2³²)` | the 4-lane Keccak-256 digest as `[lo₀, hi₀, lo₁, hi₁, lo₂, hi₂, lo₃, hi₃]`; lane `j = (D[2j], D[2j+1])` on Memory64. `rate0 = D[0..4]` (lanes 0–1), `rate1 = D[4..8]` (lanes 2–3) on the digest-chunks perm |
| 17–20 | `COL_H_INPUT_CHUNKS_BEGIN..COL_H_INPUT_CHUNKS_END` (`NUM_HASH = 4`) | all | 4-felt hash | input chunks-chain digest, read from `Poseidon2Out` at `perm_seq_id_chunks + n_chunks − 1`; feeds the keccak-node perm as `rate0` |
| 21–24 | `COL_H_DIGEST_CHUNKS_BEGIN..COL_H_DIGEST_CHUNKS_END` (`NUM_HASH = 4`) | all | 4-felt hash | digest-chunks hash, read from `Poseidon2Out` at `perm_seq_id_digest_chunks`; feeds the keccak-node perm as `rate1` |
| 25–28 | `COL_H_KECCAK_BEGIN..COL_H_KECCAK_END` (`NUM_HASH = 4`) | all | 4-felt hash | `Keccak`-node hash, read from `Poseidon2Out` at `perm_seq_id_keccak`; provided as the `h` key of `Binding(H_keccak, True, 0, 0)` |
| 29 | `COL_OUT_MULT` | all | count (`0` off active rows) | downstream consumer count of the `Binding` provide (fires at mult `−out_mult`); plain count pinned by `Binding` bus balance (not range-checked), pinned to `0` on padding by constraint 4 |

`NUM_MAIN_COLS = COL_OUT_MULT + 1 = 30`, matching the 30 rows of this
table.

### Periodic columns

None. Row class is decided by `act` alone (period 1).

## Constraints

All main-trace (Phase 1) constraints below are degree ≤ 2 (well under
the LogUp ceiling). `n_sponge_perms` / `n_chunks` are **not** tied to
`len_bytes` by a local constraint — both are free witnesses pinned by
bus balance.

### Boundary (`when_first_row`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 1 | `sponge_seq_id_head = 0` | 1 | aligns the orchestrator's first invocation with the sponge's row-0 anchor; ungated by `act` (an all-inactive trace's witness is already 0) |
| 2 | `chunk_seq_id_head = 0` | 1 | same, for the chunk chiplet's row-0 anchor |

### Activity

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 3 | `act · (1 − act) = 0` | 2 | block-active flag is boolean |
| 4 | `when_transition: (1 − act) · act_next = 0` | 2 | sticky-downward — a 1-prefix then a 0-suffix; the drop placement is unconstrained, soundness completes across the buses |

### `out_mult` zeroing

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 5 | `(1 − act) · out_mult = 0` | 2 | pins `out_mult = 0` on dead rows so the `Binding` provide (mult `−out_mult`) contributes 0 on padding |

### Namespace continuity (`when_transition`, gated on `act_next`)

| # | Constraint | Deg | Rationale |
|---|-----------|-----|-----------|
| 6 | `act_next · (sponge_seq_id_head_next − sponge_seq_id_head − 32·n_sponge_perms) = 0` | 2 | 32 sponge rows per perm; sound because the sponge chiplet is the sole producer of its `sponge_seq_id` namespace. `act_next` gate keeps the activity drop from triggering spurious errors |
| 7 | `act_next · (chunk_seq_id_head_next − chunk_seq_id_head − n_chunks) = 0` | 2 | chunk namespace step; sound because the chunk chiplet is the sole producer of its tape namespace |

**No continuity on `perm_seq_id_chunks`, `perm_seq_id_digest_chunks`, or
`perm_seq_id_keccak`.** All three are pinned per row by P2-bus balance
(`ChunkChain` / `Poseidon2In` / `Poseidon2Out`), and P2 is a *shared*
namespace — chunk-content absorptions, transcript-node hashing, and this
chiplet's own one-shots interleave, so cross-row contiguity is not true.

## Buses & lookups

`COLUMN_SHAPE = [4, 4, 4, 4]` — four LogUp columns, each batching 4
mutually-exclusive fractions. Sign convention: provide = `−m`, consume =
`+m`. Every interaction is gated by `act` (or by `out_mult`, itself
pinned to 0 off active rows), so padding rows touch no bus. Derived
quantities used below:

- `chunk_ptr_head = 4·chunk_seq_id_head` (lane-width conversion lives
  here, keeping the chunk bus hasher-agnostic).
- `perm_seq_id_chunks_tail = perm_seq_id_chunks + n_chunks − 1` (the
  chunks-absorption chain tail).
- `digest_addr_base = 100·sponge_seq_id_head + 3200·n_sponge_perms − 128`
  (the sponge's `addr_squeeze` formula evaluated at the last block's
  digest rows); lane `j` reads at `digest_addr_base + j`.
- `cap_digest_chunks = Tag::CHUNKS.as_word() = [2, 0, 0, 0]`.
- `cap_keccak = Keccak256Precompile::assert_tag(len_bytes).as_word()`
  `= [Keccak256Precompile::id(), 0, len_bytes, 0]`.

### Provides

| Bus | Tuple | Multiplicity | Fires on |
|-----|-------|--------------|----------|
| [`KeccakSponge`](relation-registry.md#5--keccaksponge) (5) | `(sponge_seq_id_head, chunk_ptr_head, len_bytes)` | `−act` | every active row |
| [`Binding`](relation-registry.md#8--binding) (8) | `(h = H_keccak, kind = True, ptr = 0, domain_id = 0)` | `−out_mult` | every active row (count `out_mult`) |

The `KeccakSponge` provide pins the sponge invocation's start,
chunk-tape base, and message length. The `Binding(_, True, 0, 0)`
provide is the assertion; `out_mult` is the consumer count, pinned by
`Binding` bus balance.

### Consumes

| Bus | Tuple | Multiplicity | Notes |
|-----|-------|--------------|-------|
| [`ChunkChain`](relation-registry.md#9--chunkchain) (9) | `(chunk_seq_id_head, perm_seq_id_chunks)` | `+act` | bundles the chain's two foreign keys; closes the chunk-side FK per row |
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(digest_addr_base + 0, D[0], D[1])` | `+2·act` | digest lane 0 (matches the round chiplet's `dst_mult = 2`) |
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(digest_addr_base + 1, D[2], D[3])` | `+2·act` | digest lane 1 |
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(digest_addr_base + 2, D[4], D[5])` | `+2·act` | digest lane 2 |
| [`Memory64`](relation-registry.md#4--memory64) (4) | `(digest_addr_base + 3, D[6], D[7])` | `+2·act` | digest lane 3 |
| [`Poseidon2Out`](relation-registry.md#7--poseidon2out) (7) | `(perm_seq_id_chunks_tail, H_input_chunks)` | `+act` | the chunks-chain digest |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_digest_chunks, tag 0, D[0..4])` | `+act` | digest-chunks perm rate0 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_digest_chunks, tag 1, D[4..8])` | `+act` | digest-chunks perm rate1 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_digest_chunks, tag 2, cap_digest_chunks)` | `+act` | digest-chunks perm cap |
| [`Poseidon2Out`](relation-registry.md#7--poseidon2out) (7) | `(perm_seq_id_digest_chunks, H_digest_chunks)` | `+act` | digest-chunks perm digest |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_keccak, tag 0, H_input_chunks)` | `+act` | keccak-node perm rate0 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_keccak, tag 1, H_digest_chunks)` | `+act` | keccak-node perm rate1 |
| [`Poseidon2In`](relation-registry.md#6--poseidon2in) (6) | `(perm_seq_id_keccak, tag 2, cap_keccak)` | `+act` | keccak-node perm cap |
| [`Poseidon2Out`](relation-registry.md#7--poseidon2out) (7) | `(perm_seq_id_keccak, H_keccak)` | `+act` | keccak-node perm digest |

### Mutex batching

The 15 fractions split across the four σ columns to bound constraint
degree; each column holds one group of one 4-insert batch. All insert
multiplicities are degree ≤ 1 (`× act`, `× out_mult`, or `× 2·act`), so
each batch has `d = 4`, `n = 4`. Ungated fraction columns (cols 1–3)
land at `max(1 + 4, 4) = 5`; the σ-hosting col 0 carries the
`is_transition` / `is_last_row` selector for its natural last-row close,
adding +1 → degree `4 + 2 = 6`. So `log_quotient_degree =
ceil(log2(6 − 1)) = 3`.

- **Col 0** (`handshake-and-chunks-digest`, 4 fractions): the
  `KeccakSponge` provide, the `Binding(_, True, 0, 0)` provide, the
  `ChunkChain` consume, and the `Poseidon2Out(H_input_chunks)` consume.
- **Col 1** (`memory64-d-limbs`, 4 fractions): the four `Memory64`
  digest-lane consumes.
- **Col 2** (`digest-chunks-p2`, 4 fractions): the three `Poseidon2In`
  consumes (rate0/rate1/cap) + the `Poseidon2Out` digest consume of the
  digest-chunks perm.
- **Col 3** (`keccak-p2`, 4 fractions): the three `Poseidon2In` consumes
  + the `Poseidon2Out` digest consume of the keccak-node perm.

Unlike the period-blocked chiplets, these batches are **not** mutex
(period 1: all four inserts of a column fire simultaneously on every
active row). Each column is one batch combining its four inserts into a
single product-of-denominators fraction; cols 1–3 chain into col 0's
running-sum recurrence as scalar additions, and the single σ is exposed
publicly (`num_aux_values = 1`).
