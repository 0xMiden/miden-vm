# Keccak-node chiplet

> **AIR reference:** [`airs/keccak-node.md`](../airs/keccak-node.md) — complete column / constraint / bus reference for this chiplet.

The Keccak side of the transcript-eval chip. Ties one
[chunk-absorption chain](chunk.md) and one [sponge](keccak-sponge.md)
invocation into one Keccak transcript-DAG node and provides
`Binding(H_keccak, True, 0, 0)` per the eval model in
[`transcript-eval.md`](../transcript-eval.md). One row per Keccak
invocation; sticky-downward `act` flag, no periodic columns.
Implemented in [`src/hash/keccak/node/`](../../src/hash/keccak/node/).

Per active row, the chiplet does seven things at once over the LogUp
buses:

1. **Issues `KeccakSponge(sponge_seq_id_head, 4·chunk_seq_id_head, len_bytes)`** —
   pins the sponge's invocation start, chunk-tape base, and message
   length. The `·4` lives here (consumer-side conversion — the
   witness side's `ChunkSeqId::ptr()`); the chunk bus stays
   hasher-agnostic.
2. **Consumes a `ChunkChain(chunk_seq_id_head, perm_seq_id_chunks)`**
   provide from the chunk chiplet — bundles the chain's two foreign
   keys in one tuple.
3. **Reads `D[0..4]` from `Memory64`** at the round chiplet's perm-N
   digest-output addresses (4 lanes, mult 2 — matching the round
   chiplet's `dst_mult = 2` provide; the orchestrator is the sole
   consumer of those lanes).
4. **Drives one Poseidon2 perm** over `(rate0 = D[0..4], rate1 =
   D[4..8], cap = Tag::CHUNKS = [2, 0, 0, 0])` → reads
   `H_digest_chunks` from `Poseidon2Out` at `perm_seq_id_digest_chunks`.
   This treats the packed digest as a semantic one-chunk payload; it does
   not add a physical chunk-chiplet row.
5. **Reads `H_input_chunks`** from `Poseidon2Out` at `perm_seq_id_chunks +
   n_chunks − 1` (the chunks-absorption chain's tail).
6. **Drives a second Poseidon2 perm** over `(rate0 = H_input_chunks,
   rate1 = H_digest_chunks, cap = [Keccak256Precompile::id(), 0,
   len_bytes, 0])` → reads `H_keccak` from `Poseidon2Out` at
   `perm_seq_id_keccak`.
7. **Provides `Binding(H_keccak, True, 0, 0)`** — the assertion. The
   resulting `H_keccak` matches the protocol-correct Keccak node hash
   only if all the inputs (D, H_input_chunks, len_bytes) line up; otherwise
   no consumer in the DAG has a matching hash and the Binding bus
   imbalances.

## Assumptions

1. **One row per Keccak invocation.** No internal period. Trace height
   is `num_invocations.next_power_of_two().max(1)`; trailing rows are
   inactive (`act = 0`).
2. **`act` is sticky-downward.** A 1-prefix followed by a 0-suffix.
   The drop placement is unconstrained — soundness holds via bus
   balance (the sponge and chunk chiplets each consume / provide their
   share, mismatches imbalance some bus).
3. **All consumer-side namespace identifiers are witnessed.** The chip
   doesn't *compute* `sponge_seq_id_head`, `perm_seq_id_chunks`, … —
   it witnesses them and lets bus balance pin them.
4. **`D` and the three hashes (`H_input_chunks`, `H_digest_chunks`, `H_keccak`)
   are also witnessed** — Memory64 + Poseidon2 buses pin them to the
   sponge's actual output and the corresponding P2 cycles' digests.
5. **`chunk_ptr` lives in the consumer's namespace, not the chunk
   chiplet's.** The bus tuple uses `chunk_seq_id_head`; the
   `KeccakSponge` request multiplies by 4 here. Future hashers with
   different lane widths multiply by their own factor; inter-chunk
   addresses are unrepresentable by construction.

## Period structure

**Period 1.** No periodic columns. Row class is decided by `act`.

## Bus tuples

Sign convention: provide = `−m`, consume = `+m`. Every interaction
below is gated by `act` (or by `out_mult`, pinned to 0 off active rows),
so padding rows touch no bus.

| Role | Bus | Dir | Mult | Tuple |
|---|---|---|---|---|
| KS request | `KeccakSponge` | prov | `−act` | `(sponge_seq_id_head, 4·chunk_seq_id_head, len_bytes)` |
| Binding (True) | `Binding` | prov | `−out_mult` | `(h = H_keccak, kind = True, ptr = 0, domain_id = 0)` |
| ChunkChain | `ChunkChain` | req | `+act` | `(chunk_seq_id_head, perm_seq_id_chunks)` |
| D-lane 0 | `Memory64` | req | `+2·act` | `(addr_base + 0, D[0], D[1])` |
| D-lane 1 | `Memory64` | req | `+2·act` | `(addr_base + 1, D[2], D[3])` |
| D-lane 2 | `Memory64` | req | `+2·act` | `(addr_base + 2, D[4], D[5])` |
| D-lane 3 | `Memory64` | req | `+2·act` | `(addr_base + 3, D[6], D[7])` |
| Input chunks digest | `Poseidon2Out` | req | `+act` | `(perm_seq_id_chunks + n_chunks − 1, H_input_chunks)` |
| Digest chunks rate0 | `Poseidon2In` | req | `+act` | `(perm_seq_id_digest_chunks, 0, D[0..4])` |
| Digest chunks rate1 | `Poseidon2In` | req | `+act` | `(perm_seq_id_digest_chunks, 1, D[4..8])` |
| Digest chunks cap | `Poseidon2In` | req | `+act` | `(perm_seq_id_digest_chunks, 2, 1, 0, 0, V)` |
| Digest chunks digest | `Poseidon2Out` | req | `+act` | `(perm_seq_id_digest_chunks, H_digest_chunks)` |
| Keccak rate0 | `Poseidon2In` | req | `+act` | `(perm_seq_id_keccak, 0, H_input_chunks)` |
| Keccak rate1 | `Poseidon2In` | req | `+act` | `(perm_seq_id_keccak, 1, H_digest_chunks)` |
| Keccak cap | `Poseidon2In` | req | `+act` | `(perm_seq_id_keccak, 2, 7, len_bytes, 0, V)` |
| Keccak digest | `Poseidon2Out` | req | `+act` | `(perm_seq_id_keccak, H_keccak)` |

`addr_base = 100·sponge_seq_id_head + 3200·n_sponge_perms − 128` —
the sponge's `addr_squeeze` formula
`100·sponge_seq_id − 99·p_idx + 3072` evaluated at the last block's
digest rows (`p_idx ∈ [0, 4)` of the last period of the invocation).

### Buses

All six buses are pre-existing; the chiplet only consumes / provides
on them:

- `KeccakSponge` (`BusId::KeccakSponge = 5`) — the sponge's per-invocation
  request, provided here, consumed by the
  [sponge chiplet](keccak-sponge.md).
- `Binding` (`BusId::Binding = 8`) — the transcript eval bus; provided
  here, consumed by the parent DAG node.
- `ChunkChain` (`BusId::ChunkChain = 9`) — provided by the
  [chunk chiplet](chunk.md), consumed here.
- `Memory64` — existing.
- `Poseidon2In` / `Poseidon2Out` (`BusId::Poseidon2In = 6`,
  `BusId::Poseidon2Out = 7`) — provided by the
  [Poseidon2 chiplet](poseidon2.md), consumed here.

## Columns

### Periodic

None.

### Witness — structural (1)

- `act` — sticky-downward activity flag. Gates every bus
  multiplicity.

### Witness — heads / lengths (6)

- `sponge_seq_id_head`, `n_sponge_perms` — sponge invocation start +
  block count. Together they index the digest-lane Memory64 addresses
  (`100·sponge_seq_id_head + 3200·n_sponge_perms − 128 + j`) and the
  `+32·n_sponge_perms` continuity step.
- `chunk_seq_id_head`, `n_chunks` — chunk chain head + length. The
  `KeccakSponge.chunk_ptr` is `4·chunk_seq_id_head`
  (`ChunkSeqId::ptr()` witness-side); the `+n_chunks` continuity step.
- `perm_seq_id_chunks` — P2 cycle of the chunks-absorption chain's
  head. Pinned per row by the `ChunkChain` consume (the FK closes
  there); **not** constrained across rows, since other P2 callers
  (transcript-node hashing, this chiplet's own digest-chunks / keccak
  one-shots, …) interleave with chunk-content absorptions and leave
  gaps. Matches the chunk chiplet's shared-namespace stance — see
  `chunk.md`'s `perm_seq_id` column doc.
- `len_bytes` — message length. Folded into `KeccakSponge` and the
  Keccak-node hash's `param_a` cap slot.

### Witness — internal P2 cycles (2)

- `perm_seq_id_digest_chunks`, `perm_seq_id_keccak` — free witnesses,
  P2-bus balance pins each to a P2 chiplet cycle running a 1-block
  absorption.

### Witness — Keccak digest (8)

- `D[0..8]` — the Keccak-256 digest, laid out as
  `[lo_0, hi_0, lo_1, hi_1, lo_2, hi_2, lo_3, hi_3]`. Lane `j` =
  `(D[2j], D[2j+1])` on Memory64; `rate0 = D[0..4]` (lanes 0-1),
  `rate1 = D[4..8]` (lanes 2-3) on the digest-chunks P2 perm.

### Witness — computed hashes (12)

- `H_input_chunks[0..4]` — input chunks digest, read from `Poseidon2Out`
  at `perm_seq_id_chunks + n_chunks − 1`. Feeds the keccak-node P2 perm
  as `rate0`.
- `H_digest_chunks[0..4]` — digest-chunks hash, read from `Poseidon2Out`
  at `perm_seq_id_digest_chunks`. Feeds the keccak-node P2 perm as `rate1`.
- `H_keccak[0..4]` — Keccak-node hash, read from `Poseidon2Out` at
  `perm_seq_id_keccak`. Provided as the `h` key on `Binding`.

### Witness — consumer count (1)

- `out_mult` — number of transcript parents binding this node; the
  `Binding(H_keccak, True, 0, 0)` provide fires at mult `−out_mult`. A plain
  count, pinned to the consumer count by `Binding` bus balance — *not*
  range-checked (see [`../lookup-argument.md`](../lookup-argument.md)) —
  and pinned to 0 off active rows by `(1 − act) · out_mult = 0`. So a
  digest bound by N parents is one row at `out_mult = N` (true dedup, no
  per-`2^16` row split).

### Witness — LogUp aux (4)

Single σ exposed publicly (`num_aux_values = 1`). Col 0 = running σ +
handshake + chunks-digest fractions; cols 1–3 carry the M64 / digest-chunks
P2 / keccak-node P2 fractions and chain into col 0 as scalar additions
(`column_shape = [4, 4, 4, 4]`). The σ-closing is natural last-row (no
`inv_n`, no wrap — see [`../lookup-argument.md`](../lookup-argument.md)).
Public input: the shared 4-felt transcript root, declared by this AIR but
not read (only the eval AIR reads it).

### Total

**30 main** (1 structural + 6 heads/lengths + 2 internal P2 + 8 D +
12 hashes + 1 `out_mult`) + **5 aux**. No periodic columns.

## Constraints

### Boundary (`when_first_row`)

- `sponge_seq_id_head = 0` — aligns the orchestrator's first
  invocation with the sponge's `sponge_seq_id = 0` row-0 anchor.
- `chunk_seq_id_head = 0` — same for the chunk chiplet's
  `chunk_seq_id = 0` row-0 anchor.

Both ungated by `act` — an all-inactive trace's witness is already
zero so the constraints are vacuous, and the gating cost (a mult) is
not worth the saved noise.

### Activity

- Binary: `act · (1 − act) = 0`. Deg 2.
- Sticky-downward: `when_transition · (1 − act) · act' = 0`. Deg 2.
  No drop-placement constraint — soundness completes across the
  buses.

### Continuity (gated on `act_next`)

All deg 2, `when_transition`. Gated on `act_next` so the activity
drop doesn't trigger spurious continuity errors and dead rows
contribute nothing:

- Sponge namespace: `act' · (sponge_seq_id_head' − sponge_seq_id_head
  − 32·n_sponge_perms) = 0`. Sound because the sponge chiplet is the
  sole producer of its `sponge_seq_id` namespace.
- Chunk namespace: `act' · (chunk_seq_id_head' − chunk_seq_id_head −
  n_chunks) = 0`. Sound because the chunk chiplet is the sole
  producer of its `CHUNK_ADDR_BASE` tape namespace.

No continuity on `perm_seq_id_chunks`, `perm_seq_id_digest_chunks`, or
`perm_seq_id_keccak`. All three are pinned per row by P2-bus balance
(`ChunkChain` / `Poseidon2In` / `Poseidon2Out`), and P2 is a *shared*
namespace — chunk-content absorptions, transcript-node hashing, and
this chiplet's own one-shots interleave, so cross-row contiguity
isn't true and would have to be relaxed anyway as soon as a second
P2 caller materialises.

### Constraint degree summary

Max local constraint witness-degree: **2** (binarity, sticky-down,
continuity equations). Well below the LogUp ceiling.

## Lookups

All four cols share a shape: one group, one batch of four simultaneous
inserts, fired on every active row (multiplicities differ by sign and a
`2·` factor on the digest lanes). All insert mults are degree ≤ 1, so
each four-insert batch has `d = 4`, `n = 4`. Ungated fraction columns
(cols 1–3) land at `max(1 + d, n) = 5`; the σ-hosting col 0 carries the
`is_transition` / `is_last_row` selector for its natural last-row close,
adding +1 → degree `4 + 2 = 6`. So `log_quotient_degree =
ceil(log2(6 − 1)) = 3` overall (the σ-column's +1 gate is the cost of
dropping the old σ/n adapter and its `inv_n` public input; 0.26's
per-AIR quotient coset absorbs it — see
[`../lookup-argument.md`](../lookup-argument.md)).

### Col 0 — running σ + handshake + chunks digest

| Insert | Mult | Message |
|---|---|---|
| ks-request | `−act` | `KeccakSpongeMsg { sponge_seq_id_head, 4·chunk_seq_id_head, len_bytes }` |
| binding-truth | `−out_mult` | `BindingMsg::truth(H_keccak)` |
| chunk-chain | `+act` | `ChunkChainMsg { chunk_seq_id_head, perm_seq_id_chunks }` |
| p2out-h-chunks | `+act` | `Poseidon2OutMsg { perm_seq_id_chunks + n_chunks − 1, H_input_chunks }` |

### Col 1 — Memory64 D-limb consumes

| Insert | Mult | Message |
|---|---|---|
| d-lane-0 | `+2·act` | `Memory64Msg { addr_base + 0, D[0], D[1] }` |
| d-lane-1 | `+2·act` | `Memory64Msg { addr_base + 1, D[2], D[3] }` |
| d-lane-2 | `+2·act` | `Memory64Msg { addr_base + 2, D[4], D[5] }` |
| d-lane-3 | `+2·act` | `Memory64Msg { addr_base + 3, D[6], D[7] }` |

### Col 2 — digest-chunks P2 perm

| Insert | Mult | Message |
|---|---|---|
| p2in-rate0 | `+act` | `Poseidon2InMsg::rate0(perm_seq_id_digest_chunks, D[0..4])` |
| p2in-rate1 | `+act` | `Poseidon2InMsg::rate1(perm_seq_id_digest_chunks, D[4..8])` |
| p2in-cap | `+act` | `Poseidon2InMsg::cap(perm_seq_id_digest_chunks, [2, 0, 0, 0])` |
| p2out-h-digest-chunks | `+act` | `Poseidon2OutMsg { perm_seq_id_digest_chunks, H_digest_chunks }` |

### Col 3 — keccak-node P2 perm

| Insert | Mult | Message |
|---|---|---|
| p2in-rate0 | `+act` | `Poseidon2InMsg::rate0(perm_seq_id_keccak, H_input_chunks)` |
| p2in-rate1 | `+act` | `Poseidon2InMsg::rate1(perm_seq_id_keccak, H_digest_chunks)` |
| p2in-cap | `+act` | `Poseidon2InMsg::cap(perm_seq_id_keccak, [Keccak256Precompile::id(), 0, len_bytes, 0])` |
| p2out-h-keccak | `+act` | `Poseidon2OutMsg { perm_seq_id_keccak, H_keccak }` |

### Aux columns

| Col | Role | Group | `deg(d)` | Constraint deg | log_quot |
|---|---|---|---|---|---|
| 0 | running σ + handshake + chunks digest | 1 batch, 4 inserts | 4 | 6 (gated) | **3** |
| 1 | Memory64 D-limbs | 1 batch, 4 inserts | 4 | 5 | 2 |
| 2 | digest-chunks P2 | 1 batch, 4 inserts | 4 | 5 | 2 |
| 3 | keccak-node P2 | 1 batch, 4 inserts | 4 | 5 | 2 |

Col 0 hosts σ: its last-row close is gated by `is_transition` /
`is_last_row` (+1 degree → 6), setting the AIR's
`log_quotient_degree = 3`. Cols 1–3 chain into col 0's running-sum
recurrence as scalar additions.

## Soundness sketch

Five pinnings together close the orchestrator. Each constraint /
bus's role is local; soundness is the conjunction.

1. **Chain pairing.** `ChunkChain` bus balance forces every
   orchestrator invocation to consume some real
   `(chunk_seq_id_head, perm_seq_id_chunks)` pair the chunk chiplet
   emitted — phantom chains unrepresentable.
2. **n_chunks pinning.** Sponge's `chunk_ptr` chain consumes exactly
   `4·ceil(17·n_sponge_perms / 4)` lanes per invocation; our
   continuity `chunk_seq_id_head_next = chunk_seq_id_head + n_chunks`
   advances by `4·n_chunks`. Memory64 bus balance per-address forces
   the two to match per-invocation → `n_chunks =
   ceil(17·n_sponge_perms / 4)`. Combined with `n_sponge_perms`
   pinning below, `n_chunks` is pinned to `ceil(len_bytes / 32)`
   modulo small floor / ceil slack at block boundaries.
3. **n_sponge_perms pinning.** Sponge's `pad-must-fire` constraint
   demands `is_zero = 1` at the last row before each new invocation,
   which only happens in the unique natural-pad period
   `floor(len_bytes / 136)`. Field wraparound on `bytes_left` is
   infeasible (~2^61 rate rows needed). So `n_sponge_perms =
   floor(len_bytes / 136) + 1`. Independent of `ChunkChain` —
   sponge-side only.
4. **chunk_ptr 4-alignment.** `chunk_ptr` enters Keccak-side only via
   `4·chunk_seq_id_head` constructed in the message — inter-chunk
   pointers are unrepresentable by construction.
5. **Content-addressing closes the rest.** Even with the above, a
   prover *could* witness a wrong `H_input_chunks` (read at a different
   P2-Out cycle) or wrong `D` (point at zero lanes). Both routes
   produce a `H_keccak` that doesn't match any protocol-correct
   Keccak DAG node, so `Binding(H_keccak, True, 0, 0)` has no consumer
   in the DAG — Binding bus imbalance, proof rejected. The `InCap`
   bus-balance with the chunk chiplet's chain heads pins
   `perm_seq_id_chunks` to a real chain start, so `OutRate0` at
   `perm_seq_id_chunks + n_chunks − 1` is the genuine `n_chunks`-prefix
   digest of that chain.

The chain pinnings (`+n_chunks`, `+32·n_sponge_perms`) also rule out
*aliasing and gaps* in the per-namespace covers: the orchestrator's
sequence of `(sponge_seq_id_head_i, chunk_seq_id_head_i,
perm_seq_id_chunks_i)` is a strict arithmetic progression, so distinct
invocations can't claim overlapping ranges or skip ranges that the
chunk / sponge chiplets emit.

## Per-direction len_bytes / `n_chunks` slack

Two failure modes from a `len_bytes` vs `n_chunks` mismatch:

- **Zero-extension (`L < ceil(17·n_sponge_perms/4)`):** chunk chain
  shorter than what the sponge needs. Sponge's `is_chunk_avail = 0`
  past the chain end, `chunk_lo/hi` pinned to 0, sponge absorbs zero
  bytes for the tail. Memory64 balances (sponge consumes only what
  chunk provides), `D` is deterministically zero-padded, `H_keccak`
  represents a valid "len_bytes bytes, zero tail" node — accepted by
  the protocol or not depending on whether such a node exists in the
  consumer DAG.
- **Under-extension (`L > ceil(17·n_sponge_perms/4)`):** chunk chain
  longer than the sponge can drain in its pinned perms. Sponge stops
  consuming after `4·ceil(17·n_sponge_perms/4)` lanes; the remaining
  `4·(L − ceil(...))` lanes are provided by chunk but consumed by
  nobody (the next invocation's `chunk_ptr_head_{i+1}` jumps past
  them by orchestrator continuity). Memory64 imbalance → trace
  rejected.

So zero-extension is representable (and harmless if the protocol
allows it); under-extension is structurally ruled out. See
[`chunk.md`](chunk.md) and [`keccak-sponge.md`](keccak-sponge.md) for
the sponge-side details.

## Open / out of scope

- **A separate eval-chip Keccak arm.** The current design deliberately fuses
  the terminal Keccak node here and provides `Binding(H_keccak, True, 0, 0)`
  directly; splitting that back out would need a new design reason.
- **`n_sponge_perms` vs `n_chunks` formula in the AIR.** The chiplet
  witnesses both as free fields and lets bus balance pin them.
  Encoding `n_chunks = ceil(17·n_sponge_perms / 4)` directly as a
  local constraint would let the orchestrator drop `n_chunks` as a
  column — saves 1 column, costs a ceiling-divide gadget. Not worth
  it now; revisit if column count becomes pressure.
