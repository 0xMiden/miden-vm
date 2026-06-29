# AGENTS.md

Context for picking up this project mid-stream without access to
prior conversation history.

## What this is

A scratch repo for prototyping a chiplet-based zkVM dedicated to
cryptographic precompiles, targeting `Keccak-f[1600]`. Built on
[`miden-lifted-stark`](https://hackmd.io/@adr1anh/HyBchnFZlx) (a
Plonky3 fork of Miden VM's STARK) using the relation /
require / provide LogUp idiom from Miden VM.

Status: experimental. Read [`README.md`](README.md) and the
topic docs under [`docs/`](docs/) (indexed by
[`DESIGN.md`](DESIGN.md)) first — the architecture is stable
and the code reads as a spec.

## Documentation structure — keep in sync with code

The docs **are** the spec; treat them as part of every change, not an
afterthought. A code change to a chiplet's columns, constraints, or buses
is incomplete until its docs match.

- [`README.md`](README.md) — entry point (what the stack is, how to run it).
- [`DESIGN.md`](DESIGN.md) — a thin index into `docs/`.
- [`docs/`](docs/) top level — cross-cutting: [`architecture.md`](docs/architecture.md),
  [`lookup-argument.md`](docs/lookup-argument.md) (the LogUp mechanism),
  [`forward-looking.md`](docs/forward-looking.md), and migration/decision memos.
- **[`docs/chiplets/`](docs/chiplets/) — design rationale ("why").** One file
  per chiplet: the shape, the trade-offs, the soundness arguments.
- **[`docs/airs/`](docs/airs/) — the audit reference ("what").** One file per
  AIR, enumerating **every column** (index, range, meaning), **every
  constraint** (degree + rationale), and **every bus interaction**
  (provides/consumes, multiplicities, mutex batching) — written so an external
  auditor can check the implementation against one written spec. The
  cross-cutting bus list is
  [`docs/airs/relation-registry.md`](docs/airs/relation-registry.md).

**The sync rule** (this is why future sessions exist to honour it):

- Change a chiplet's columns / constraints / buses / `COLUMN_SHAPE` / `NUM_*`
  / lqd → update its `docs/airs/<chiplet>.md` (and `relation-registry.md` if a
  bus is added or changed). A PR that moves a column or a bus without touching
  `airs/` is **incomplete**.
- Change the *why* (a new soundness argument, a layout trade-off) → update its
  `docs/chiplets/<chiplet>.md`.
- Both families are cross-linked and both are canonical.
- After a framework or seam change, **grep the docs** for the old names
  (removed APIs, renamed buses, dropped constants, old version strings) — a
  stale audit doc is worse than none, because it reads authoritative.

## What's landed

The full stack proves and verifies end-to-end over **fifteen chiplets**:
[`examples/bench_keccak_n.rs`](examples/bench_keccak_n.rs) threads N Keccak
invocations into one public transcript root (built via `ProverInstance` /
`VerifierInstance`); the integration tests in
[`src/tests/integration.rs`](src/tests/integration.rs) guard the
cross-chiplet bus balance directly. Per-AIR specs (every column, constraint,
bus) live in [`docs/airs/`](docs/airs/); design rationale in
[`docs/chiplets/`](docs/chiplets/). The macro inventory (see
[`README.md`](README.md) for the full chiplet list, incl. the uint store /
add / mul and the EC group store / group-law add / `EcMsm`):

- **Shared primitives** — `BytePairLut` (8×8 byte-pair table + `Range16`)
  and `Bitwise64` (64-bit logic + rotate; requires `BytePairLut` /
  `Range16`).
- **Shared hasher infra** — the `Memory64` bus (a *multiset* of
  `(addr, lo, hi)` tuples: one provide per IP within a permutation, the
  multiset semantics exploited only for state overwrite at sponge seams —
  [`src/hash/memory64.rs`](src/hash/memory64.rs)) and `Chunk` (input
  chunking + Poseidon2 content commitment, shared across hashers).
- **Keccak** — `round` (TAM miniVM, one round / 128 rows), `sponge`
  (absorb/squeeze, padding, perm seams), `node` (interns by digest,
  provides `Binding(H_keccak, True)`).
- **Transcript** — `Poseidon2` (the transcript's hash; `Poseidon2In/Out`
  buses) and the **transcript eval chip** (`transcript/eval/`): the
  content-addressed DAG — the AND-tree fold plus uint-leaf / uint-op and EC
  create / binop / MSM nodes — hashed into one public root, with the
  `Binding` bus tying each node's value to the relations that prove it.
- **Non-native uint + EC** — a 256-bit uint store + `UintAdd` / `UintMul`
  (Schwartz–Zippel limb identities), and the EC group store + group-law
  `EcGroupAdd` + symbolic `EcMsm` (the `MsmClaimTerm` resolve seam binds a
  claim into the root, decoupled from the addition-chain strategy).
- **LogUp adapter** ([`src/logup/`](src/logup/)) — fork of miden-vm's
  `LookupAir` / `LookupBuilder` (pin `3176d1fd`) with the column-0 closing
  patched to the **natural last-row σ-closing** (no reserved dead last row,
  no `inv_n`); only `CyclicConstraintLookupBuilder` (legacy name) and
  `build_logup_aux_trace` are forked. A preprocessed chiplet (BytePairLut)
  reads its fixed table through `logup::CombinedWindow`. Bus-id registry in
  [`src/relations.rs`](src/relations.rs).

Open: **heterogeneous constraint-degree LDE** — 0.26 delivered per-AIR
quotient cosets, but the blowup is still one global PCS factor (see
[`docs/forward-looking.md`](docs/forward-looking.md)).

## Architectural decisions baked in

Fixed; don't re-litigate without strong reason:

- **Natural last-row σ-closing** for column 0 (`src/logup/constraint.rs`).
  `when_first: acc[0] = 0`; `when_transition: D₀·(acc_next − Σ_{i<L} acc[i])
  − N₀ = 0`; `when_last: D₀·(σ − Σ_{i<L} acc[i]) − N₀ = 0`. σ is committed as
  the single permutation value; **no `inv_n` public input** (public values
  are just the shared 4-felt transcript root). The col-0 transition/last gate
  costs +1 symbolic degree vs the older *ungated σ/n-cyclic* form it
  replaced (which used a `+σ·inv_n` correction + a wrap); 0.26's per-AIR
  quotient coset absorbs it. (chunk & keccak_node thereby sit at lqd 3, not
  2.) The `Cyclic*` type names in the adapter are legacy.
- **Multi-column fraction architecture**: col 0 is the only
  running sum; cols 1+ are per-row fraction columns. Each fraction
  column has its own ungated `D_i · acc[i] − N_i = 0` constraint;
  col 0 absorbs `Σᵢ acc[i]` per row in addition to its own group's
  `N_0/D_0`. Single σ per chiplet — col 0's running sum already
  aggregates all per-row contributions.
- **`LookupAir<LB>::eval`** describes the LogUp argument via the
  closure-based API (`builder.next_column(|col| col.group(name, |g|
  { g.add(...); g.batch(name, flag, |b| { b.insert(...) }) })))`.
  `LiftedAir::eval` runs Phase 1 non-LogUp constraints on `&mut AB`,
  then wraps in `CyclicConstraintLookupBuilder::new(builder, self,
  self.preprocessed_width() > 0)` and dispatches to `LookupAir::eval`. The
  prover side is `LiftedAir::build_aux_trace` (a free `build_aux` the AIR
  delegates to → `build_logup_aux_trace`); the 0.24 `AuxBuilder` trait is
  gone, and `MultiAir::eval_external` (not `reduced_aux_values`) closes the
  cross-AIR `Σ σ = 0`.
- **Single global `(α, β)`** drawn after main-trace commitment.
  Domain separation is via `bus_prefix[i] = α + (i+1)·β^W`,
  precomputed in `Challenges` (re-exported from
  `miden_air::lookup::Challenges`). Bus IDs registered in
  [`src/relations.rs`](src/relations.rs) as a `BusId` enum.
- **LookupMessage trait bounds**: every chiplet's `*Msg` impl uses
  the shape `where E: Algebra<E>, EF: Algebra<E>` — the blanket
  `impl<R: PrimeCharacteristicRing> Algebra<R> for R` plus the
  `Algebra<F>: PrimeCharacteristicRing` super-bound carries
  everything else.
- **Tests live under `src/tests/`** (not inline `#[cfg(test)] mod
  tests`) to keep production source files audit-friendly.
- **Trace heights are powers of two**, padded with all-zero rows.

## Per-chiplet gotchas

Column layouts, constraint degrees, and slot tables live in
[`docs/chiplets/`](docs/chiplets/) — consult those, not here. The
non-obvious traps worth carrying into a session:

- **ROL's predecessor must be a LOGIC row**
  (`is_rol_next · (1 − is_logic) = 0`, cyclic). So Keccak's trailing ρπ
  rows are **XORROL with `src_b = ZERO`** (a dummy XOR), not pure ROL —
  that's what lets Bitwise64's IR materialize the Real-LOGIC + Carrier
  pair the invariant needs.
- **Fused XORROL rows set both `is_xor` and `is_rol`** — any per-row
  count built from the selector sum double-counts them; subtract the
  one-hot `is_xorrol` (this was the bug behind the first end-to-end bus
  imbalance).
- **Bitwise64 ROL decomposition**: the `+2³²` offset on
  `((lo+2³²)·k, (hi+2³²)·k)` kills the low-end limb alias and the
  `k < 2³¹` bound the high-end one. `op_or_k` / `b_limbs` are
  dual-purpose (op-tag vs `k`; bytes vs limbs).
- **Keccak ρπ slot table is post-π indexed** (`slot_b(out_x, out_y)`,
  input resolved via `pi_inverse`, ρ of the *input* lane) — the classic
  off-by-π bug.
- **Multi-value memory provides use `g.insert(ONE, −dst_mult)`**, never
  `g.remove(dst_mult)` (which hard-codes mult −1 and mis-accounts the
  `dst_mult ∈ {1, 2, 3, 5, 12}` writes).
- **Permutation chaining is address-separated via a dead round** (25
  rounds = 24 active + 1 dead = 3200 rows); the sponge feeds each perm's
  round-0 inputs into the previous cycle's dead-round IP gap, and `act`
  gates every bus mult so the dead round / padding stay off the bus.
- **Logic64's `op` slot is `is_xor`** (`AndNot = 0`, `Xor = 1`).

## User preferences (sticky)

These came up across the session and should be honoured by default:

- **Never push without an explicit command**. Commit freely;
  pushing is the user's call. Force-push only when explicitly told.
- **Commit messages**: tight, "what" and "why", co-author trailer
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Rustdoc is for users, not project management. Rustdoc is not
  a changelog.** No forward-looking text ("upcoming X", "future
  deliverable", "deferred"), no historical context ("legacy was 3
  cols", "previously asserted X", "was removed when…"), no
  speculative future code. Keep rustdoc consistent with what the
  API does *now*. Memos, migration plans, and project planning
  live in `docs/` (or AGENTS.md), never inline in module docs.
- **`std::iter::zip(a, b)`** over `a.iter().zip(b.iter())` for
  peer iterators; **`itertools::izip!`** for ≥3-way zips. Prefer
  `IntoIterator` impls (`for x in &v`) where natural — but
  **`column.iter_mut()` is preferred over `for x in &mut *column`**
  reborrow pattern.
- **Don't add unnecessary Felt arithmetic** in hot paths. Direct
  byte/u32/u64 → Felt casts where possible.
- **`assert!`** (not `debug_assert!`) for caller-bug-detecting
  preconditions in IR construction APIs. Witness-construction time
  is not perf-sensitive; silent corruption is worse than panic.
- **Fixed-size key spaces want a `Vec`** (e.g. BPL's
  `BytePairLutRequires::counts`), not a `BTreeMap`/`HashMap`.
  Direct array indexing is simpler and faster on the hot path.
- **Tests in `src/tests/{chiplet}.rs`**, never inline.
- **Doc-link style**: prefer bare names that resolve via existing
  `use` imports; fall back to display-syntax (`[`Name`](full::Path)`)
  where the path is foreign. Avoid `[`crate::foo::Bar`]` rendered
  literally.
- **Trait-bound conciseness**: when an existing trait has all the
  super-bounds you need, prefer the single bound (e.g.
  `EF: Algebra<E>` over the four-term `PrimeCharacteristicRing +
  Clone + Algebra<E> + core::fmt::Debug`).
- **`use core::array;`** at the top, then `array::from_fn(...)`;
  no inline `core::array::from_fn` FQNs.
- **Sanity-check container choices.** If a `VecDeque`/`HashMap`
  is reached for, ask whether the access pattern actually justifies
  it — VecDeque-as-append-only-Vec was a real trap.
- **`vec.extend([..])` over chained `.push` calls.** A run of
  consecutive `.push(x)` writing a fixed group of values collapses
  to `vec.extend([x1, x2, ..., xn])`. Reads cleanly as a single
  conceptual unit and skips the per-call dispatch.
- **`cargo fmt` on every change.** Run `cargo fmt` (or
  `rustfmt --edition 2024 <files>` for surgical scope) before
  committing any Rust edit. The repo baseline is fmt-clean for all
  non-WIP files; preserve that property.
- **Cross-chiplet interned identifiers are newtyped handles** minted
  only by the owning accumulator (`UintPtr`, `EcGroupPtr` /
  `EcPointPtr`, `PermSeqId` / `PermSpan`, `ChunkSeqId`,
  `SpongeSeqId`): private field, the interning/allocating entry is
  the sole constructor, raw numbers surface only at trace-cell writes
  (`.addr()` / `.seq()`) and in bare-chiplet tests via the
  `cfg(test)` `forged()` escapes. Namespace conversions are named
  methods, never inline arithmetic (`ChunkSeqId::ptr()` is the
  chunk-row → Memory64-word-address seam, replacing scattered
  `*4`/`/4`). A raw `u32`/`u64` id crossing a requires boundary is a
  smell.
- **Provide/consume multiplicities are the `ProvideMult` alias**
  (`relations.rs`), never a bare `u32`: a demand ledger reads
  `Ptr → ProvideMult`, and every new `_mult` / consumer-count field or
  param takes the alias. It's a transparent `u32` (arithmetic is
  untouched) — it just names the LogUp-multiplicity role so the next
  rebase needn't retype freshly-added counters.

## Trace-gen construction (extend, not index)

Every chiplet's `generate_trace` builds its main trace the **same
way** — the bitwise64 shape in
[`src/primitives/bitwise64.rs`](src/primitives/bitwise64.rs) is the
reference: `Vec::with_capacity(height · W)`, append each row, then
`resize(height · W, ZERO)` (or extend explicit padding rows when the
tail isn't all-zero). The Vec's length *is* the running row counter;
there is no `trace[r·W + COL] = …` random access. This structurally
enforces single-pass, forward-only generation (a row can't be
addressed out of order) and keeps every trace-gen one shape.

The *row* is assembled one of two ways:

- **Default — column-order `extend`.** Append each field group in
  column order, so the source order of the extends *is* the layout:
  ```rust
  values.extend(a.to_le_bytes().map(Felt::from)); // COL_A_BEGIN..
  values.extend(b.to_le_bytes().map(Felt::from)); // COL_B_BEGIN..
  values.extend([Felt::from(op.tag()), Felt::ONE, Felt::ZERO]); // op, is_logic, is_rol
  ```
  Writing a row then reconciles trace-gen against the AIR's `COL_*`
  constants — a free standing cross-check (the AIR indexes `COL_*`;
  trace-gen never does). This is the point of the convention; use it
  wherever a row's set columns are written in a fixed order, even if
  many are zero (extend the zeros explicitly). Pull a `push_row`
  helper out when the row shape recurs (node, poseidon2).

- **Fallback — `[Felt; W]` scratch + named index, then `extend`.**
  Only for rows whose set columns **scatter by branch** (the sponge's
  per-lane `lo/hi` pairs at non-adjacent columns + the `COL_B_BEGIN + …`
  byte-offset selector): zero-init a stack `[Felt; W]`, write the
  scattered columns by `COL_*` index, then `values.extend(scratch)`.
  The outer extend (and its forward-only guarantee) is preserved; only
  the inner fill is index-based — honest, since there's no column
  order to reconcile when columns genuinely scatter per branch.

Per-row bus `require`s — Range16 on `out_mult` / multiplicities, and
cross-chiplet demand the rows consume (a relation block's store
lookups → the store's ledger, the round→bw64 pattern) — fire in the
same single pass, padding rows included; free-standing `route_*` /
`require_*_checks` companions that re-iterate the records are not
used (they double the witness derivation and can desync from the laid
rows). `generate_trace` therefore **consumes its accumulator** (by
value — trace-gen is terminal): laying twice, which would double-route
demand, is a compile error, the same move-only discipline as `Truthy`.
Read accumulator state (counts, recorded ops) before generating. Where the row index is
recovered from a record's allocated range (chunk `chunk_seq_id`, p2
cycle), `debug_assert!` the running counter against that range so the
forward-only assumption is checked, not just assumed.

## How a typical refactor proceeds

For non-trivial structural changes (e.g., σ/n adoption, the
`*Requires → *Prover` split, ROL, the LookupAir migration, the
`Bitwise64Requires` HashMap rework): the user wants a
**plan-confirm-implement** loop. State the proposed shape
(selector encoding, aux column layout, constraint degrees, IR
changes); wait for confirmation; then implement. Surface
secondary consequences (e.g., the dummy-LOGIC problem when ROL
came up; the ROL `s < 31` bound when the +2³² offset trick was
re-audited) before locking in.

After a feature lands, the user often asks for a **denoise pass**:
look for over-eager rustdoc, dead helpers, vestigial parameters,
historical commentary, redundant trait bounds. Worth proposing.
