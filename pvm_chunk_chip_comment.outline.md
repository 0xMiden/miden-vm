# Chunk chip comment — proposed outline

Awaiting approval before writing the full draft.

---

## Design choices I'm locking in (subject to your review)

These are the non-obvious decisions I'm baking in. Push back on any of
them and I'll rework before drafting.

1. **Reverse row order per section, single 12-felt state per row.**
   Row 0 of a chunks-object section (= "top" in trace order) holds
   chunk N−1 — the *last* chunk absorbed, whose rate output is the
   commitment hash. The bottom row of the section holds chunk 0, the
   first chunk absorbed, with `cap_prev = IV`. Both `ptr` and `n`
   (the forward-order chunk index) **decrement by 1** per row:
   `next.ptr = curr.ptr − 1`, `next.n = curr.n − 1`.

   Reverse order is what makes the single-state trick work. Each row
   stores exactly one 12-felt RPO state: `[val[8], cap[4]]`. The
   `cap[4]` slot holds the **output** of this row's absorb; the
   *input* to this row's absorb (= `cap_prev` in the Absorb/Hash bus
   tuple) is whatever the next trace row is doing — because in
   reverse order, the next trace row holds the previous chunk in
   forward order, so *its* cap output is *this* row's cap input. The
   AIR bus request reads `cap_prev = is_bot * IV + (1 − is_bot) *
   next.cap`, using the `next` frame transitions already give us for
   free. Forward order would need a separate `cap_prev[4]` column
   because you can't reference `prev` in AIR — that's the 4 columns
   reverse order saves.

   Pointer indexing is the annoying consequence: the top row's `ptr`
   column holds `base_ptr + N − 1` (the pointer of the *last* chunk),
   and the bottom row's holds `base_ptr` (the *first* chunk's
   pointer). The Binding tuple, provided from the top row, recovers
   `base_ptr` as `curr.ptr − curr.n` and `n_chunks` as `curr.n + 1`.

2. **Two bus interactions with the permutation chip, not one.** The
   spec §9 summary lists the chunk chip as an Absorb consumer only,
   but Absorb's tuple `(cap_out, val, cap_prev)` doesn't expose the
   rate output — and we need the rate output on the *last* chunk of
   each object because that's the chunks commitment hash (the `hash`
   field of the Binding tuple). My proposal: chunk chip consumes
   **Absorb on non-top rows** (ordinary chunks, cap output matters)
   and **Hash on top rows** (final chunk, rate output = commitment
   hash). Both framings of the same RPO permutation; one request per
   active row. This means §9's bus summary gains one entry (chunk
   chip becomes a second consumer of the Hash bus) — flagged as spec
   amendment in the draft.

   Alternatives I considered and rejected:
   - *Use Hash for every row* — can't, the Hash tuple doesn't carry
     cap output so the chain breaks.
   - *Add a 10th bus exposing both cap and rate output* — more
     invasive than consuming an existing bus twice.
   - *Double-request the top row (Absorb + Hash)* — wasteful, and
     costs no fewer columns than the `cap[4]` overload below.

3. **Column overload: `cap[4]` holds cap output OR rate output.**
   On non-top rows these 4 columns are the cap output of this row's
   absorb, and the *next* trace row reads them as its `cap_prev`
   through the Absorb-bus request. On the top row of a section the
   same 4 columns hold the **rate** output (= chunks commitment
   hash), fed to the Hash bus and to the Binding tuple. Safe because
   `is_top` selects which bus request fires, so the column is only
   ever read under one interpretation per row. Documenting the dual
   interpretation explicitly in the schema table.

4. **`ptr` and `n` both decrement by 1 per row.** `ptr` is the
   canonical chunk pointer for this row's chunk; on the top row it's
   `base_ptr + N − 1`, on the bottom row it's `base_ptr`. `n` is the
   forward-order chunk index; on the top row `n = N − 1`, on the
   bottom row `n = 0`. Uniform identity across the section:
   `base_ptr = ptr − n` and `N = n + 1` on the top row. No separate
   `base_ptr` or `n_chunks` column needed.

5. **Pointer allocation is host-side, enforced by bus balance.**
   The AIR doesn't run a pointer allocator — the host chooses `ptr`
   values during Phase A / Phase B witness generation (see host
   comment §3 / open question 2). The AIR just verifies that
   whatever `ptr` each chunk-chip row claims matches whatever `ptr`
   the Keccak chip claims for its matching ChunkVal consumer, via
   LogUp balance on the ChunkVal bus. For the digest↔chunks shared
   pointer of §6.7, the host must assign the same `ptr` to the
   KeccakDigestLeaf witness and the Chunks witness — host-side
   discipline, not an AIR constraint. Covered in §5 of the draft.

---

## Section topic list

Following the `pvm_opcode_comment.md` template: short visible intro
+ mermaid data-flow diagram + headline properties bullet list, with
a `## Details` divider and everything else in collapsed `<details>`
blocks.

**Visible (above the fold):**

- **Why a dedicated chip.** 3-ish paragraphs. Byte-level chunk data
  is variable-length and can't live inside the eval chip (which is
  tag-dispatched and fixed-shape per row) or the Keccak chip (which
  works over already-assembled chunks by pointer). The sponge
  construction needs AIR-level verification because its output — the
  chunks commitment hash — is what ties the tag-7 Keccak node's
  `rhs` child to a specific chunk sequence. The host's `chunk_store`
  is just a witness hint; the chunk chip is what makes the commitment
  soundly binding.

- **Architectural shape.** One mermaid diagram showing: permutation
  chip → (Absorb, Hash) → chunk chip → (Binding, ChunkVal) → eval
  chip / Keccak chip. Pastel fills with `color:#000` per the
  `pvm_opcode_comment.md` tree-DAG pattern. Three buses in, two
  buses out. Labels name each bus with its width.

- **Headline properties bullet list.** 5-6 bullets:
  - **17-column trace** — 12-felt sponge state (`val[8]` rate +
    `cap[4]` overloaded capacity/digest) plus 5 metadata columns
    (`is_active`, `is_top`, `is_bot`, `ptr`, `n`). One RPO
    permutation request per active row; no explicit cap-threading
    transition constraint — the chain is enforced entirely by
    LogUp balance on the Absorb/Hash buses.
  - **Reverse row order within each section.** Row 0 of a section
    (top) holds chunk N−1 (commitment-hash row); bottom row holds
    chunk 0 (cap_prev = IV). Letting each row read `next.cap` as
    its cap input is what saves the 4 columns a forward-ordered
    chip would need for `cap_prev[4]`.
  - **Sponge IV lives in the bus request, not as a column.** On bot
    rows the Absorb/Hash request's `cap_prev_expr` selects `[1, 0,
    0, CURRENT_VERSION]` directly via the `is_bot` selector. No
    trace-wide boundary constraint; multiple chunks objects stack
    as back-to-back sections without any trace-level alignment.
  - **The chunks commitment hash is the rate output of the top
    row's permutation** — one RPO call, no separate finalize row,
    no extra permutation beyond the N absorbs.
  - **Shared-`ptr` discipline is host-side.** The eval chip's
    Keccak arm (§6.7) requires `KeccakDigest.ptr == Chunks.ptr`;
    this is enforced by the host's Phase B driver allocating one
    pointer per Keccak node and reusing it across both bindings.
    The AIR only checks ChunkVal bus balance.
  - **§9 bus summary gains one entry:** chunk chip becomes a
    second consumer of the Hash bus (top rows only). Flagged as a
    spec amendment.

**Collapsed details blocks:**

1. **`<details><summary><strong>§1 Trace schema — column layout and
   meanings</strong></summary>`** — the full column table (below),
   with an ASCII-art schematic showing a 3-chunk section followed
   by a 2-chunk section followed by padding. Annotates which
   columns are live on first/middle/last/padding rows.

2. **`<details><summary><strong>§2 Per-row constraints — selectors,
   boundary, transition</strong></summary>`** — the constraint list.

   *Selector booleans:* `is_active² = is_active`, `is_top² = is_top`,
   `is_bot² = is_bot`, each gated by `is_active`. On single-chunk
   sections, `is_top = is_bot = 1` — so no exclusivity constraint
   between them.

   *Row-local "boundary" (really a selector implication):*
   `is_bot * n = 0` (bottom row has forward-index zero). There's no
   explicit `cap_prev = IV` constraint — that discipline lives in
   the bus request's `cap_prev_expr` (see §3), which multiplies IV
   by `is_bot`.

   *Section-continuation transition (non-bot active rows):*
   - `(1 − is_bot) * is_active * (next.n − (n − 1)) = 0` — `n`
     decrements
   - `(1 − is_bot) * is_active * (next.ptr − (ptr − 1)) = 0` — `ptr`
     decrements
   - `(1 − is_bot) * is_active * (1 − next.is_active) = 0` — the
     next row is also active (section stays contiguous)
   - `(1 − is_bot) * is_active * next.is_top = 0` — the next row is
     not a new top (we're still in this section)

   *Section-juxtaposition (bot rows):*
   - `is_bot * next.is_active * (1 − next.is_top) = 0` — if the
     row after a bot is active, it must be a new section's top
   - no further constraint — a bot can be followed by padding

   *Implicit "new section starts with is_top":* the transition rules
   above ensure that every active row is either (a) a continuation
   of its predecessor's section or (b) a new top following a bot or
   padding. No explicit "prev" constraint is needed because AIR
   reads it from the bot row's side.

   *Capacity chain:* **no explicit transition constraint.** The
   Absorb/Hash bus request on each non-bot row reads `cap_prev` from
   `next.cap`, and LogUp balance with the permutation chip enforces
   the chain end-to-end. This is the main simplification reverse
   order buys.

   *Padding:* fully gated — every transition carries an `is_active`
   factor, every bus request carries `is_active` in its multiplicity,
   so padding rows contribute zero to constraints and zero to bus
   balance.

3. **`<details><summary><strong>§3 Bus interactions — four relations
   with LogUp tuple specs</strong></summary>`** — first define the
   shared `cap_prev_expr` used by both Absorb and Hash requests:

   ```
   cap_prev_expr[i] = is_bot * IV[i] + (1 - is_bot) * next.cap[i]
                     for i in 0..4
   ```

   where `IV = [1, 0, 0, CURRENT_VERSION]`. On a bot row, it's the
   tag-1 capacity IV; otherwise it's the next trace row's cap (which
   in reverse order is the preceding chunk's cap output = this
   chunk's cap input).

   Then four relations:

   - **Absorb consumer** (width 16, non-top active rows). Tuple:
     `(curr.cap[4], curr.val[8], cap_prev_expr[4])`.
     Multiplicity: `is_active * (1 − is_top)`. Provided by the
     permutation chip — pins `curr.cap = RPO(curr.val ||
     cap_prev_expr)[CAPACITY_RANGE]`.
   - **Hash consumer** (width 16, top active rows). Tuple:
     `(curr.cap[4], curr.val[8], cap_prev_expr[4])`.
     Multiplicity: `is_active * is_top`. Provided by the permutation
     chip — pins `curr.cap = RPO(curr.val ||
     cap_prev_expr)[DIGEST_RANGE]` = the chunks commitment hash.
     Flag as §9 spec amendment: chunk chip becomes a second Hash
     consumer.
   - **ChunkVal provider** (width 9, every active row). Tuple:
     `(curr.ptr, curr.val[8])`. Multiplicity: `is_active`. Consumed
     by the Keccak chip (§8.5). On the top row of a section the
     tuple is `(base_ptr + N − 1, chunk_{N−1})`; on the bottom row,
     `(base_ptr, chunk_0)`.
   - **Binding provider** (width 7, top active rows only). Tuple:
     `(curr.cap[4], value_tag = 4, aux = curr.n + 1, ptr =
     curr.ptr − curr.n)`. Multiplicity: `is_active * is_top`.
     `curr.cap` on a top row is the rate output = chunks commitment
     hash; `curr.n + 1` = `n_chunks`; `curr.ptr − curr.n` = base
     pointer. Consumed by the eval chip when it resolves a Keccak
     tag-7 node's `rhs` (§6.7 shared-pointer mechanism).

4. **`<details><summary><strong>§4 Pointer allocator and the shared
   ptr with Keccak</strong></summary>`** — explain that the chunk
   chip and KeccakDigestLeaf arm don't allocate pointers themselves;
   the host's Phase B driver does. For each Keccak tag-7 node the
   host assigns one fresh pointer and uses it for BOTH the
   KeccakDigestLeaf binding AND the Chunks binding, so the eval
   chip's `require Binding(lhs, KeccakDigest(ptr))` and `require
   Binding(rhs, Chunks(ptr, n_chunks))` naturally resolve to the
   same `ptr` — which is the §6.7 mechanism. The chunk chip's
   `ptr` column on the last row equals whatever the host allocated;
   ChunkVal bus balance against the Keccak chip is what stops the
   host from lying. Reference the host comment's open question 2.

5. **`<details><summary><strong>§5 Trace-generation pseudocode —
   host-side population</strong></summary>`** — sketch showing
   iteration over `PrecompileState.chunk_store` in topological
   order (same order as `dag.nodes`). For each chunks object, the
   driver runs the sponge **forward** to compute all cap outputs
   and the final rate output, then emits rows in **reverse** order
   so that row 0 of the section is the top (chunk N−1) and the
   section's bottom row is chunk 0. Padding fills the rest.

   ```
   fn populate_chunk_chip(witness: &PvmWitness) -> Vec<ChunkChipRow> {
       let mut rows = Vec::new();
       for (commitment_hash, felts) in witness.chunk_store.iter_topo() {
           let base_ptr = witness.ptr_of_chunks(commitment_hash);
           let n_chunks = felts.len();   // felts: &[[Felt; 8]]

           // Forward pass: run the sponge, collect per-chunk outputs.
           let mut cap = [ONE, ZERO, ZERO, CURRENT_VERSION];
           let mut per_chunk_output = Vec::with_capacity(n_chunks);
           for (k, chunk) in felts.iter().enumerate() {
               let state = rpo_permute_rate_cap(chunk, &cap);
               let (rate_out, cap_out) = split_state(state);
               // Non-top rows store cap_out; the top row stores rate_out.
               let slot = if k == n_chunks - 1 { rate_out } else { cap_out };
               per_chunk_output.push(slot);
               cap = cap_out;
           }

           // Emit rows in reverse: row 0 = chunk N-1 (top), last = chunk 0 (bottom).
           for k in (0..n_chunks).rev() {
               rows.push(ChunkChipRow {
                   is_active: ONE,
                   is_top:    (k == n_chunks - 1).into(),
                   is_bot:    (k == 0).into(),
                   ptr:       base_ptr + Felt::from(k as u64),
                   n:         Felt::from(k as u64),
                   val:       felts[k],
                   cap:       per_chunk_output[k],
               });
           }
       }
       pad_to_power_of_two(&mut rows);
       rows
   }
   ```

   Note that emission order and sponge order are opposite: the
   driver absorbs `chunk_0, chunk_1, ..., chunk_{N−1}` forward, but
   writes `chunk_{N−1}` to the top row of the section and
   `chunk_0` to the bottom.

6. **`<details><summary><strong>§6 Padding and end-of-trace</strong>
   </summary>`** — padding rows set `is_active = 0` and zero every
   other column. Bus-request multiplicities all carry an `is_active`
   factor, so padding contributes no requests / no provides. Both
   boundary and transition constraints either multiply by
   `is_active` or by `(1 - is_last) * is_active`, so padding rows
   are free of constraint burden. Sections can start on any row;
   no alignment requirement. Empty chunk trace (no chunks objects)
   is handled trivially by all-padding rows.

7. **`<details><summary><strong>§7 Open questions</strong></summary>`**
   — the ones I've identified:
   1. **Hash bus second consumer.** The spec §9 lists only the eval
      chip as a Hash consumer. This proposal makes the chunk chip a
      second consumer (for last-chunk rows). Do you want to amend
      §9 accordingly, or prefer an alternative — e.g. a new
      `ChunkDigest` bus of width 16 with tuple `(digest[4], val[8],
      cap_prev[4])` provided by the permutation chip and consumed
      only by the chunk chip? Functionally identical; naming
      clarity is the tradeoff.
   2. **Zero-length chunks objects.** Are they legal? An empty
      chunks commitment would need the RPO permutation of just the
      IV `(rate=0, cap=IV)`, which is a meaningful hash but corresponds
      to a section with zero rows — impossible to represent in this
      layout without a dedicated "empty section" row. My proposal
      is to forbid them at host-side: the chunk chip only handles
      N ≥ 1, and the host rejects `InsertChunks { felts: [] }`.
      Alternative: allow them via a single "is_empty" selector row
      that does a one-shot IV hash with zero rate.
   3. **Interleaving vs contiguity of sections.** Chunks objects
      must occupy contiguous row ranges — interleaving two objects
      in one trace would break the capacity threading. This is
      enforced automatically by the section-continuation transition
      constraint. I'll state it explicitly but there's no actual
      design choice.
   4. **Max `n_chunks` per object.** No hard cap beyond what fits
      in the trace. Is there a Miden-side maximum on `len_bytes`
      for Keccak tag-7 nodes that would propagate here? The spec's
      `param_a = len_bytes` is a felt field, so the theoretical max
      is a felt value, but in practice the trace row budget caps
      it. No AIR change needed.
   5. **Shared-pointer allocator coordination.** Related to host
      open question 2: the Phase B driver must walk Keccak nodes in
      an order that allows it to allocate one shared `ptr` per
      (digest, chunks) pair. Simplest implementation: walk
      `dag.nodes` topologically, and at each Keccak node allocate
      a single fresh `ptr` which is then stamped into both the
      KeccakDigestLeaf binding row and the Chunks binding row. No
      central allocator chip needed.

---

## Trace schema column list

Total width: **17 columns** — 12-felt sponge state + 5 metadata.
All columns in the chip's main trace (no auxiliary columns beyond
the standard LogUp accumulator).

Row order: **reverse within a section.** Row 0 of a section ("top")
holds chunk N−1 (last chunk absorbed, produces commitment hash);
bottom row holds chunk 0 (first chunk absorbed, cap_prev = IV).

| # | Name | Width | Type | Live on | Meaning |
|---|------|-------|------|---------|---------|
| 1 | `is_active` | 1 | bool | all rows | 1 on live section rows, 0 on padding |
| 2 | `is_top` | 1 | bool | active | 1 iff this row is the top of its section (chunk N−1, last absorbed, commitment-hash row) |
| 3 | `is_bot` | 1 | bool | active | 1 iff this row is the bottom of its section (chunk 0, first absorbed) |
| 4 | `ptr` | 1 | felt | active | canonical chunk pointer for this row's chunk; top row `= base_ptr + N − 1`, bottom row `= base_ptr`, decrements per trace row |
| 5 | `n` | 1 | felt | active | forward-order chunk index; top row `= N − 1`, bottom row `= 0`, decrements per trace row |
| 6..13 | `val[8]` | 8 | felt | active | this row's 8-felt chunk payload (32 bytes u32-LE) — the rate half of the RPO state |
| 14..17 | `cap[4]` | 4 | felt | active | **dual-interpretation:** non-top rows → cap *output* of this row's absorb (next row reads it as cap_prev). Top row → rate output = chunks commitment hash, fed to Hash bus + Binding. The capacity half of the RPO state. |

Single-chunk section: `is_top = is_bot = 1` on the one row of the
section; `n = 0`, `ptr = base_ptr`, `cap = rate_output` (commitment
hash), Hash bus request uses `cap_prev_expr = IV` (because `is_bot
= 1`).

**Section lifecycle in a single-row view (reverse order):**

```text
row role         is_active is_top is_bot   cap_prev_expr    cap-slot holds         bus provides
──────────────  ───────── ────── ──────   ──────────────   ────────────────────   ──────────────
top of N>1         1        1      0       next.cap         rate_out = hash       Hash,   ChunkVal, Binding
middle             1        0      0       next.cap         cap_out                Absorb, ChunkVal
bottom of N>1      1        0      1       IV               cap_out                Absorb, ChunkVal
sole (N=1)         1        1      1       IV               rate_out = hash       Hash,   ChunkVal, Binding
padding            0        0      0       (gated off)      (zero)                 —
```

Capacity chain lives in the bus requests, not in explicit transition
constraints: each row's Absorb/Hash request pins `cap = RPO(val ||
cap_prev_expr)[...]`, and `cap_prev_expr` reads `next.cap` on non-bot
rows. LogUp balance across all three buses is what enforces the
chain end-to-end.

**Capacity IV:** `IV = [ONE, ZERO, ZERO, CURRENT_VERSION]` at
`state[8..12]`, matching spec §4's tag-1 domain separator.

---

## Remaining things I want your call on before I write the draft

1. **Hash bus second consumer vs new `ChunkDigest` bus.** Proposing
   to make the chunk chip a second consumer of the Hash bus and
   note this as a §9 amendment. Acceptable, or do you want a
   dedicated 10th bus (e.g. `ChunkDigest(digest[4], val[8],
   cap_prev[4])`, width 16, provided by the permutation chip and
   consumed only by the chunk chip)? Functionally identical;
   tradeoff is naming clarity vs. bus count.

2. **Zero-length chunks objects.** Forbid host-side (my proposal,
   matches the Phase B `InsertChunks` validation) or support them
   via a dedicated empty-section single-row pattern that hashes
   only the IV?

3. **Row-schema presentation in the draft.** The markdown column
   table above + the text lifecycle block — is that the right
   visual, or do you want an ASCII / mermaid strip showing a
   2-section trace (e.g. N=3 section above an N=2 section above
   padding) with `is_top`/`is_bot` / `n` / `ptr` column values
   filled in row by row?

4. **Depth of the constraint block.** Should §2 show every
   constraint as an explicit algebraic polynomial (close to
   implementation-ready), or stay semantic ("n decrements by 1 on
   non-bot rows") with only the non-obvious ones spelled out?
   Leaning toward semantic with spelled-out examples for the
   tricky `cap_prev_expr` and section-juxtaposition rules.

Green-light these four and I'll write the full comment into
`.claude/pvm_chunk_chip_comment.md`.
