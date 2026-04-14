# Transcript Authoring — Host-side Architecture

**Version:** 0 (initial)

> **This is a very tentative design.** Not a finalized spec — a much more
> exhaustive, file-by-file implementation plan will follow in a separate
> issue. Everything below is open for discussion.
>
> *Co-authored with Claude (Opus 4.6).*

---

## Why this exists

The PVM AIR in the comment above specifies how a transcript gets
*verified*: an eval chip walks a tree of typed commitments (field
elements, group elements, Keccak digests, assertions), dispatching to
auxiliary chips that enforce arithmetic and hashing rules. Every rule
the eval chip checks becomes a LogUp bus relation, and every bus
relation needs a **provider side**: concrete tuples of field values,
canonical pointers, arithmetic trace rows, chunk sequences, digest
preimages.

**None of that witness data exists on its own.** Something has to
produce it as MASM programs run and build commitment DAGs. On the
Miden side, that "something" is the host — the same abstraction layer
that currently holds the advice provider, dispatches emitted events,
and generally owns any non-trace state the VM needs during execution.

This comment proposes what that machinery should look like. It's a
host-side analogue to the PVM AIR spec: both specs describe the same
content but from opposite ends, with the **transcript root** — a
single 4-felt public input — as the only point where they touch.

## What's proposed

A new **`PrecompileState` island** on the host, living alongside the
advice provider. It holds:

- an **expression DAG** of every commitment MASM ever builds, keyed by
  4-felt hash, deduped structurally;
- **value tables** (field, group, chunk, Keccak) populated as values
  become known, with canonical pointers assigned eagerly for leaves
  and lazily for derived values;
- a plug-in **evaluator registry** so new fields or curves can be
  added without touching the core host;
- an **eval cache** memoizing execution-time evaluation results.

A new **`PrecompileEventHandler` trait**, parallel to `EventHandler`,
that takes a shared reference to the island and returns a bag of
mutations. **No interior mutability** — the processor validates the
mutations atomically and applies them.

A **two-phase lifecycle**:

- **Phase A — during execution.** Handlers build structural DAG nodes,
  opportunistically populate value tables as values become known, and
  cache any eval events MASM requested.
- **Phase B — after execution.** A single driver walks the DAG,
  finishes evaluating any derived values that weren't touched in
  Phase A, enforces equality assertions via pointer comparison, and
  emits the AIR provider trace tables into a serialized `PvmWitness`.

Three primitives MASM can call, exposed through a new
`stdlib::crypto::pvm` module:

1. **Register** — MASM computes a commitment hash via a Poseidon2
   preimage locally (~15 cycles, no host call), emits an event, and
   the host records the structural node in the DAG.
2. **Assert equality** — MASM builds a `FieldBinOp::Eq` or
   `GroupBinOp::Eq` node and appends its hash to a running transcript
   root via Miden's existing `log_precompile` opcode. The transcript
   root is a public input of the Miden execution proof.
3. **Evaluate** — MASM asks the host for the value of an expression,
   either as a new leaf hash (chainable into another expression) or
   as raw value bytes on the advice stack (branchable in plain MASM).

## Integration surface with the execution proof

Exactly one thing crosses the boundary between Miden's execution proof
and any downstream PVM proof: **the transcript root**. It's a public
input on both sides.

- On the **Miden side**, the root is threaded through
  `pc_transcript_state` by Miden's existing `log_precompile` opcode
  and `PrecompileTranscript` machinery. Each call appends one more
  assertion hash to the root.
- On the **PVM side**, the same root is the public input the AIR
  starts from, walking backwards through the DAG to check that every
  assertion evaluates to `True`.

Everything else — DAG shape, pointer assignment, value tables, trace
rows, evaluator choice — is host-side *hinting* that the PVM re-checks
independently. If the host produces incorrect data, the PVM simply
fails to verify; Miden's execution proof gives the PVM nothing to
trust except the transcript root.

The contract with `log_precompile` is minimal: **(a)** the transcript
root is a deterministic function of the ordered list of assertion
hashes, and **(b)** it's exposed as a public input of the Miden
execution proof. The host architecture is invariant under the specific
transcript shape — whether the running transcript is a sponge, a
tagged tree, or something else, conditions (a) and (b) are the only
thing this design depends on. A sibling proposal covers potential
changes to the `log_precompile` opcode contract and transcript
internals.

## Scope of change

A sizeable but contained host-side feature. Approximate breadth:

**New:**

- `PrecompileState` struct + storage on the host.
- `PrecompileEventHandler` trait and `HostEventRegistry` dispatch.
- `PrecompileMutation` enum with per-variant validation.
- `ExprDag` arena + hash-index DAG structure.
- `ExprEvaluator` trait and evaluator registry.
- Phase B witness-generation driver.
- `PvmWitness` serialization type (delivered alongside the STARK proof).
- `stdlib::crypto::pvm` MASM module (hash helpers + registration
  wrappers + eval wrappers).

**Removed:**

- `pc_requests: Vec<PrecompileRequest>` from `AdviceProvider` — the
  island supersedes it.
- `PrecompileVerifier` registry — the PVM replaces its "re-run the
  precompile in-process" model.

**Unchanged:**

- Miden's existing `log_precompile` opcode, `PrecompileTranscript`,
  and the `pc_transcript_state` public input (modulo a separate
  sibling proposal).
- `AdviceProvider` itself and every other existing host abstraction.
- The `EventHandler` trait (kept as-is for non-precompile events).

---

## Details

The rest of this comment is collapsed for discussion hygiene. Expand
any section relevant to a specific review thread.

<details>
<summary><strong>Terminology — "pointers" vs "hashes" vs "NodeIds"</strong></summary>

The AIR spec uses felt-valued `ptr`s to address values inside the
PVM's field, group, chunk, and Keccak tables. **These pointers are an
AIR-internal implementation detail** — they exist so the LogUp bus
relations can be finite-width tuples. They are never observed by MASM,
never appear on the stack, and never show up in any content-addressed
hash. The host's DAG, its dedup logic, and all its expression-level
event handlers work purely in terms of **4-felt commitment hashes** —
the only content-addressed identity the Miden side ever sees or
produces.

Canonical pointers are still needed eventually, because the AIR's
`FieldLookup`, `FieldEval`, `GroupLookup`, `GroupEval`, and
`KeccakEval` provider tuples are all pointer-keyed. The host allocates
them **opportunistically, as values become known**: leaf registrations
get a pointer immediately, aggregate registrations (GroupCreate,
Keccak) get one after resolving their children, derived values
(FieldBinOp / GroupBinOp results) get one when they're evaluated —
either during execution via an eval event or during Phase B as a
residue sweep. Pointers live inside `PrecompileState`'s value tables;
they never appear in the DAG node structure, in any registration
event, or on the MASM stack.

`NodeId` (introduced below as the `ExprDag`'s arena index for cheap
child edges) is a **distinct, unrelated concept** from these AIR
pointers. `NodeId` addresses *expressions* in the DAG — one per unique
commitment hash, 1:1 with structural position. `FieldPtr`/`GroupPtr`/
etc. address *canonical values* in the provider tables — two distinct
expressions can evaluate to the same canonical value and share a
pointer. `NodeId` is local to the DAG data structure and is never
seen outside the host.

</details>

<details>
<summary><strong>Requirements (R1–R8)</strong></summary>

- **R1 — DAG construction.** Build a content-addressed DAG of
  expression nodes (FieldLeaf, FieldBinOp, GroupCreate, GroupBinOp,
  KeccakDigestLeaf, Keccak) during execution, keyed by the PVM
  commitment hash that MASM computed. Structurally identical
  subexpressions dedup automatically.
- **R2 — Equality assertions.** Provide a mechanism for MASM to assert
  that two expressions are equal, appending the assertion hash to the
  running transcript root (the only AIR-enforced side effect).
- **R3 — Evaluation.** Offer two execution-time evaluation events so
  MASM can query the value of an expression: one returning a leaf
  hash (so the caller can feed it to another expression), one
  returning the raw value (so the caller can branch on it in plain
  MASM).
- **R4 — Witness generation.** At end of execution, produce the tables
  consumed by every PVM AIR bus — field table, group table, FieldEval
  trace, GroupEval trace, chunk store, KeccakEval trace.
- **R5 — Canonical pointer assignment.** Guarantee that equal values
  get the same `ptr` in the witness. This is the foundation of `Eq`
  soundness.
- **R6 — Plug-in evaluators.** Different field types and curves must
  be supportable without changes to the core host, analogous to
  today's `PrecompileVerifier` registry.
- **R7 — No interior mutability.** Preserve the existing
  mutation-return pattern used by `EventHandler`: handlers return a
  bag of mutations and the processor applies them.
- **R8 — Isolate from `AdviceProvider`.** Precompile state has
  distinct access patterns and should not pollute the advice
  abstraction.

</details>

<details>
<summary><strong>Precompile state island — struct layout and population</strong></summary>

A new `PrecompileState` struct lives on the host next to `AdviceProvider`:

```
Host
├── AdviceProvider  { stack, map, store }
└── PrecompileState {
      dag,          // structural expression DAG
      field_table,  // canonical (field_ty, canonical_value) -> FieldPtr
      group_table,  // canonical (group_ty, x_ptr, y_ptr)    -> GroupPtr
      chunk_store,  // chunk sequences, keyed by commitment hash
      keccak_table, // per-Keccak-node (digest, n_chunks, len_bytes),
                    // keyed by the Keccak node's commitment hash
      eval_cache,   // execution-time memoization of derived values
      evaluators,   // plug-in registry:
                    //   Arc<HashMap<EvalKey, Arc<dyn ExprEvaluator>>>
    }
```

The **value tables** (`field_table`, `group_table`, `chunk_store`,
`keccak_table`) are populated *opportunistically* during Phase A as
values become known: leaf registrations allocate pointers immediately,
aggregate registrations (GroupCreate, Keccak) resolve their children
and allocate, and eval events trigger recursive evaluation that
populates any derived nodes they touch. Phase B then sweeps the DAG
for derived nodes that were never touched during execution, evaluates
them, fills in the remaining entries, and emits the FieldEval /
GroupEval / KeccakEval **trace tables** — which are *only* produced
in Phase B and never held on `PrecompileState`.

The advice provider loses `pc_requests: Vec<PrecompileRequest>`; the
island replaces it entirely.

</details>

<details>
<summary><strong>DAG — arena + hash index</strong></summary>

```
ExprDag {
    nodes: Vec<ExprNode>,               // insertion-order, topological
    hash_index: HashMap<Word, NodeId>,  // dedup
    assertions: Vec<NodeId>,            // ordered transcript leaves
}
```

Children are referenced by `NodeId` (u32), not by hash, so edges are
cheap. Insertion order is always topological because a parent's
registration cannot run before its children already exist. Dedup
happens at insert time: same hash ⇒ same `NodeId`. Identical
subexpressions are never duplicated.

Node identity is the PVM commitment hash. On every registration the
host recomputes the Poseidon2 permutation from operand hashes + tag
metadata and rejects any mismatch — MASM is trusted only insofar as
"if MASM lies, insert fails".

</details>

<details>
<summary><strong>Extended event handler trait</strong></summary>

The existing `EventHandler` trait stays as-is for generic events. A
parallel trait handles events that need to see the precompile island:

```rust
trait PrecompileEventHandler: Send + Sync + 'static {
    fn on_event(
        &self,
        process:    &ProcessorState,
        precompile: &PrecompileState,
    ) -> Result<PrecompileEventResponse, EventError>;
}

struct PrecompileEventResponse {
    advice:     Vec<AdviceMutation>,      // stack / map / store
    precompile: Vec<PrecompileMutation>,  // DAG / assertions / cache
}
```

A `HostEventRegistry` dispatches to the precompile registry first,
then falls back to the generic registry. Precompile handlers have
read access to the island but can only mutate it by returning
mutations.

</details>

<details>
<summary><strong>Mutation enum and validation</strong></summary>

```
PrecompileMutation::
    InsertFieldLeaf        { hash, field_ty, value }
    InsertFieldBinOp       { hash, op, field_ty, lhs, rhs }
    InsertGroupCreate      { hash, group_ty, x, y }
    InsertGroupBinOp       { hash, op, group_ty, lhs, rhs }
    InsertKeccakDigestLeaf { hash, digest }
    InsertChunks           { hash, felts }
    InsertKeccak           { hash, len_bytes, digest_leaf, chunks }
    LogAssertion           { hash }
    StoreEvalResult        { expr, result }
```

Child references are `Word` (commitment hash), resolved to `NodeId`
at apply time. `apply_mutation` does three things per mutation:

1. Resolve child hashes via `hash_index`; reject if any are absent.
2. Recompute the Poseidon2 permutation with the tag-specific preimage
   and compare to the claimed `hash`; reject on mismatch.
3. Insert (or dedup) into the DAG, and — for nodes whose value is
   immediately known — allocate the corresponding canonical pointer
   in the value table (leaves get their pointer from the `value`
   field; aggregates look up their children's pointers first).

Validation is atomic per event: all mutations in a response are
validated first, then applied.

</details>

<details>
<summary><strong>Two-phase lifecycle — Phase A registration, Phase B witness generation</strong></summary>

The host splits precompile work into two phases, with the boundary
drawn at "end of Miden execution":

**Phase A — registration (during execution).** Event handlers build
the structural DAG *and* opportunistically populate the value tables
as values become known:

- **Leaf registrations** (FieldLeaf, KeccakDigestLeaf, Chunks) — the
  value is immediate (in the preimage or the event calldata). The
  handler canonicalizes it and allocates a pointer on the spot.
- **Aggregate registrations** (GroupCreate, Keccak) — the handler
  resolves the child nodes via the DAG, looks up their pointers in
  the relevant value tables, and allocates a pointer for the
  aggregate. GroupCreate also enforces on-curve here; a malformed
  point rejects the mutation.
- **Eval events** (`eval_to_hash`, `eval_to_advice`) — the handler
  recursively evaluates the target expression via the evaluator
  registry, allocating pointers for every derived value it touches
  on the way up, and caches results in `eval_cache`.

Phase A does *not* evaluate `FieldBinOp` / `GroupBinOp` nodes that
aren't touched by an eval event. They stay purely structural —
commitment hash + operand links — until Phase B.

**Phase B — witness generation (after execution).** A single driver
walks `dag.nodes` in topological order, finishes any derived values
that weren't evaluated in Phase A (cache misses trigger `ExprEvaluator`
invocations and populate the value tables), and emits the AIR
provider trace tables:

```
PvmWitness {
    version,
    transcript_root,
    nodes,          // serialized DAG in topological order
    field_table,    // FieldLookup provider tuples  (built A, finalized B)
    group_table,    // GroupLookup provider tuples  (built A, finalized B)
    chunk_store,    // ChunkVal provider tuples      (built A, finalized B)
    field_eval,     // FieldEval provider tuples    (Phase B only)
    group_eval,     // GroupEval provider tuples    (Phase B only)
    keccak_store,   // KeccakEval provider tuples   (Phase B only)
}
```

The **value tables** (`field_table`, `group_table`, `chunk_store`,
`keccak_table`) are built up during Phase A and serialized into
`PvmWitness` essentially unchanged at the end of Phase B. The **trace
tables** (`field_eval`, `group_eval`, `keccak_store`) are Phase-B-only:
they record the sequence of binary operations the evaluator performed,
which is only fully known after the residue sweep.

**Eq soundness check.** `FieldBinOp::Eq` and `GroupBinOp::Eq` nodes
are resolved to `lhs_ptr == rhs_ptr` — either when touched by a
Phase A eval event, or during the Phase B sweep if not. A mismatch
fails witness generation immediately; no `PvmWitness` is produced,
no PVM proof can be generated. **This is where a prover that claimed
an assertion that isn't actually true gets caught.** The check costs
exactly one pointer comparison per Eq node, because canonical pointer
assignment in the value tables already ensures "equal canonical
values share a pointer".

Phase B is a pure function of Phase A + the evaluator registry — so
it's deterministic, cacheable, and testable in isolation.

</details>

<details>
<summary><strong>Evaluator framework</strong></summary>

Parallel to the existing `PrecompileVerifier` registry, but for
execution-time *evaluation* rather than post-hoc verification:

```rust
trait ExprEvaluator: Send + Sync + 'static {
    fn evaluate(&self, node: &ExprNode, ctx: &EvalContext<'_>)
        -> Result<EvaluatedValue, EvalError>;
    fn canonicalize(&self, value: &EvaluatedValue) -> CanonicalBytes;
}
```

`EvalContext` is read-only (DAG + cache). Any new results bubble up
as `StoreEvalResult` mutations; no shared mutable state.

Evaluators are keyed by `(NodeKind, FieldTy | GroupTy)`. Adding a new
field or curve means registering a new evaluator — the core host is
untouched.

</details>

<details>
<summary><strong>MASM interface — <code>stdlib::crypto::pvm</code></strong></summary>

Three layers in a new `stdlib::crypto::pvm` module:

- **Hash helpers** (~15 cycles each, no host calls):
  `hash_field_leaf`, `hash_field_binop`, `hash_group_create`,
  `hash_group_binop`, `hash_keccak_digest_leaf`, `hash_keccak`. Pure
  Poseidon2 permutations with tag-specific preimages, built on top
  of Miden's existing `hperm` instruction.
- **Registration wrappers**: `register_field_leaf`,
  `register_field_binop`, etc. Each calls the matching hash helper
  and then emits an event so the host can record the node in its
  DAG.
- **Eval wrappers**: `eval_to_hash`, `eval_to_advice`. Each emits an
  event; the handler evaluates and returns either a new leaf hash
  (mode 1) or the raw value bytes on the advice stack (mode 2).

</details>

<details>
<summary><strong>Assertion mechanism — three conceptual steps</strong></summary>

Logging an equality assertion is, conceptually, three steps:

1. **Build an `Eq` node in the DAG** over the two operand hashes,
   using the registration pattern above. The result is a 4-felt
   commitment hash for the `Eq` expression.
2. **Append that hash to a running transcript root** that is a public
   input of the Miden execution proof. The transcript root commits to
   the ordered sequence of assertions the program claims are true.
3. **Tag the Eq node as an assertion in the host DAG** so Phase B
   witness generation knows which nodes the downstream PVM verifier
   must evaluate to `True`.

Steps 1 and 3 are pure host-side hints: a registration event followed
by a `LogAssertion { hash }` mutation.

**Step 2 is the only step that produces witness data visible in the
Miden execution proof itself, and it already exists in the VM today.**
Miden's `log_precompile` opcode and `PrecompileTranscript` machinery
already absorb commitment hashes into a running transcript state that
is exposed as a public input. This design reuses that machinery
unchanged and treats it as a black-box primitive: "append an assertion
hash to a public-input transcript root". Whatever internal shape that
transcript takes (sponge, tree, tagged, untagged) is orthogonal to
this design and belongs to its own discussion.

The only contract between the host architecture described here and
whichever transcript mechanism Miden VM ships is:

- **(a)** the final transcript root is a deterministic function of
  the ordered list of assertion hashes, and
- **(b)** it is exposed as a public input of the execution proof.

That root is the sole rendezvous point between the two proof
systems: the Miden side never sees DAG shape, the PVM side never
sees Miden execution internals, and the PVM verifier uses this root
as its entry point to walk backwards through the DAG and check every
assertion.

A **separate proposal** covers the specific shape of the transcript
and the `log_precompile` opcode contract (stack handling, hasher bus
interaction, MASM wrapper, version constant). The host-side
architecture in this comment is unchanged by whichever version of
that proposal lands — conditions (a) and (b) above are invariant
across every transcript reshape option currently under discussion,
and they're the only pieces this design relies on.

</details>

<details>
<summary><strong>AIR bus ↔ host table mapping</strong></summary>

Every bus in the AIR spec needs a provider. This table shows who
authors what, and in which phase the data is available:

| Bus          | Width | AIR provider      | Host source                     | Phase |
|--------------|-------|-------------------|---------------------------------|-------|
| Binding      | 7     | eval chip (self)  | —                               | —     |
| Hash         | 16    | permutation chip  | `dag.nodes` (preimage dispatch) | B     |
| Absorb       | 16    | permutation chip  | `chunk_store` absorb sequences  | B     |
| FieldLookup  | 10    | field chip        | `field_table`                   | A / B |
| FieldEval    | 5     | field chip        | `field_eval` trace rows         | B     |
| GroupLookup  | 4     | group chip        | `group_table`                   | A / B |
| GroupEval    | 5     | group chip        | `group_eval` trace rows         | B     |
| KeccakEval   | 2     | Keccak chip       | `keccak_store`                  | B     |
| ChunkVal     | 9     | chunk chip        | `chunk_store`                   | A / B |

**A / B** means the host source is a value table populated
*opportunistically* during Phase A (at leaf registration, aggregate
registration, or eval events) and finalized during Phase B's residue
sweep. **B** means the data is only produced once Phase B starts —
typically a trace table enumerating the operations the evaluator
performed, which can't exist until all values are known.

The host is the authority for every provider side that sits outside
the PVM chips themselves. Value tables (`field_table`, `group_table`,
`chunk_store`, `keccak_table`) live on `PrecompileState` throughout
execution and are serialized unchanged into `PvmWitness`. Trace tables
(`field_eval`, `group_eval`, `keccak_store`) are built by the Phase B
driver and only exist in the final `PvmWitness`.

</details>

---

## Open questions

1. **Field-element internal representation.** AIR spec §2.2 stores
   field elements as u16 limbs. The host's `FieldTable` rows need to
   match this so FieldEval consumes them directly. Exact felt/byte
   layout is tbd.
2. **Shared pointer for Keccak digest + chunks in the witness.** AIR
   §6.7 requires the `KeccakDigest` and `Chunks` bindings to share a
   `ptr` — a witness-side concern, since the host's DAG itself is
   hash-addressed. Phase B needs one allocator serving both kinds of
   table entries for a given Keccak node so they end up with a
   common pointer identifier.
3. **Cross-execution caching.** Default is per-execution. Caching
   small leaves across executions could cut DAG size substantially;
   defer until measured.
4. **Error surface.** Every rejection path (hash mismatch, missing
   child, evaluator failure, Eq mismatch in Phase B) needs a stable
   error identifier. Single enum on the precompile island.

A much more exhaustive issue with the concrete file-by-file
implementation plan will follow separately.
