# PVM Host: Precompile DAG, Evaluation, and Assertion Framework

Design notes for the processor-side mechanism that supports PVM-style precompile
requests. Companion to `PVM.md`, focused on the *host boundary*: the data
structures that live inside the processor, the interface MASM uses to drive
them, and the framework for plugging in new kinds of precompiles.

Section references of the form `PVM.md §N` point into the sibling document.

## 1. Goals & non-goals

**Goals**
- Build content-addressed DAGs of arithmetic expressions (field, group) during
  execution, keyed by the PVM commitment hash that MASM already computed.
- Let MASM log equality assertions between two such expressions into the
  transcript. Transcript appends are the *only* "real" precompile request with
  AIR teeth; everything else is host hinting.
- Provide a framework for plugging in evaluators (how to actually compute
  `a + b` over a target field, EC addition over a curve, etc.) without
  hardcoding them into the core DAG — parallel to the existing
  `PrecompileVerifier` registry in `core/src/precompile.rs:200-283`.
- Preserve the existing `EventHandler` mutation-returning pattern. **No interior
  mutability on handler state.** Handlers return mutation values; the processor
  applies them.
- Move precompile state out of `AdviceProvider` into its own dedicated island.

**Non-goals**
- Actually implementing field / group / curve arithmetic. Evaluator
  implementations are stubbed.
- Changing `LogPrecompile` opcode semantics or the tag-specific hash helpers.
  Those are owned by `PVM.md` §4.2–§4.3 and inherited unchanged.
- Touching Keccak, SHA-512, ECDSA paths beyond noting where they hook into the
  new state island.

## 2. Core abstraction

Every expression is a node in a Merkle-like DAG. **The node's identity is its
commitment hash** (4 felts), computed by MASM using the PVM tag-specific hash
helpers (PVM.md §4.3). Consequences:

- **Dedup is automatic.** Same structural expression ⇒ same hash ⇒ same DAG
  entry.
- **No handles cross the MASM boundary.** MASM only ever carries `[Felt; 4]`
  commitments. No arena IDs, pointers, or opaque handles.
- **Assertions are first-class nodes.** An equality assertion is just a
  `FieldBinOp::Eq` (tag 4) or `GroupBinOp::Eq` (tag 6) whose hash is then
  passed to the `LogPrecompile` opcode.
- **Hash verification at the host.** The host *recomputes* the Poseidon2
  permutation for every registered node and rejects mismatches, so the DAG is
  authoritative for the claim "MASM computed this hash correctly" even without
  AIR support for the registration events.

### Tags covered (subset of PVM.md §1)

| Tag | Kind           | Payload (val[8])                  | Purpose                              |
|-----|----------------|-----------------------------------|--------------------------------------|
| 2   | `FieldLeaf`    | u32-LE encoding of a field elt.   | Introduce concrete field values      |
| 4   | `FieldBinOp`   | `lhs_hash ‖ rhs_hash`             | Field add/sub/mul/eq                 |
| 5   | `GroupCreate`  | `x_hash ‖ y_hash`                 | Introduce an affine point            |
| 6   | `GroupBinOp`   | `lhs_hash ‖ rhs_hash`             | Group add/sub/eq                     |

Tag 0 (`Transcript`) is handled by the existing `LogPrecompile` opcode — *not*
by this DAG.

## 3. Architectural shift: precompile state island

Today: `AdviceProvider.pc_requests: Vec<PrecompileRequest>` — opaque blobs
bundled into the advice provider (`processor/src/host/advice/mod.rs:56`).

Tomorrow: a dedicated **precompile state island**, owned by the host next to
the `AdviceProvider`, containing the expression DAG, chunk store, and
per-execution evaluation caches. The advice provider loses `pc_requests`
entirely; the island takes over.

```
Host
├── AdviceProvider { stack, map, store }
└── PrecompileState {
      dag:        ExprDag,
      chunks:     ChunkStore,
      eval_cache: HashMap<NodeId, EvaluatedValue>,
      evaluators: Arc<PrecompileEvaluatorRegistry>,
    }
```

Rationale:
- Precompile state has fundamentally different access patterns from advice
  state: it is authored in structured bursts by a handful of specific handlers,
  not by arbitrary user code.
- Moving it out of `AdviceProvider` stops polluting that abstraction with
  concerns (DAGs, tagged nodes, evaluation) specific to the PVM path.
- Gives us a clean place to hang the evaluator registry, caches, and future
  instrumentation (tracing, diagnostics, per-expression timings).
- Natural boundary for serialization handoff to the PVM trace generator.

## 4. Data structures

### 4.1 `ExprDag` — arena + hash index

```rust
// core/src/precompile/dag.rs

pub struct ExprDag {
    nodes: Vec<ExprNode>,              // insertion-order arena
    hash_index: HashMap<Word, NodeId>, // Word -> position in `nodes`
    assertions: Vec<NodeId>,           // ordered transcript leaves
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct NodeId(u32);

pub struct ExprNode {
    hash: Word,       // self-commitment; also key in hash_index
    body: ExprBody,
}

pub enum ExprBody {
    FieldLeaf  { field_ty: FieldTy, encoded: [Felt; 8] },
    FieldBinOp { op: FieldOp,  field_ty: FieldTy, lhs: NodeId, rhs: NodeId },
    GroupCreate{ group_ty: GroupTy, x: NodeId, y: NodeId },
    GroupBinOp { op: GroupOp,  group_ty: GroupTy, lhs: NodeId, rhs: NodeId },
}
```

**Why arena + hash index instead of just `HashMap<Word, Node>`:**
1. **Compact internal links.** Child refs are `NodeId` (4 bytes), not `Word`
   (32 bytes). Edges dominate the DAG; pay the 4-felt key cost once per unique
   node, not once per edge.
2. **Deterministic iteration order.** `nodes: Vec<_>` gives insertion order for
   free — which is topological by construction (§4.2) and exactly what the
   downstream PVM trace generator wants.
3. **Cheap serialization.** Dump `nodes` verbatim; rebuild `hash_index` in
   O(n) on the verifier side.
4. **Cache locality.** Handlers frequently walk `lhs → rhs`; indirection
   through `&nodes[id.0 as usize]` is one load vs. a hash lookup.

### 4.2 Invariants enforced by `ExprDag::insert`

- `nodes[i].hash` is unique. Duplicates short-circuit and return the existing
  `NodeId`.
- Topological: a node's children have smaller `NodeId`. Handlers cannot
  construct cycles because insert rejects any mutation whose referenced child
  is absent.
- Node identity == PVM commitment hash. The hash is *recomputed* at insert
  time (§5.1) and mismatches are rejected.

### 4.3 `PrecompileState`

```rust
pub struct PrecompileState {
    dag: ExprDag,
    chunks: ChunkStore,                                         // §11
    eval_cache: HashMap<NodeId, EvaluatedValue>,
    evaluators: Arc<PrecompileEvaluatorRegistry>,               // §7
}
```

`eval_cache` memoizes evaluated subtrees so that repeated `eval(X)` calls from
MASM don't re-walk the whole DAG. It lives on the island rather than inside
`ExprDag` because its semantics are execution-time-only (never serialized to
the PVM).

### 4.4 `EvaluatedValue` (stub)

```rust
pub enum EvaluatedValue {
    Field { field_ty: FieldTy, bytes: Vec<u8> },
    Group { group_ty: GroupTy, bytes: Vec<u8> },
}
```

Intentionally opaque. Concrete evaluators own the serialization format for
their own field/group representations. Neither the DAG nor the mutation
pipeline inspects the contents.

## 5. Mutation pattern (replaces interior mutability)

`AdviceMutation` is applied post-handler by `AdviceProvider::apply_mutations`
(`processor/src/host/advice/mod.rs:67-90`). We extend the same pattern with a
**separate** mutation enum scoped to the precompile island:

```rust
pub enum PrecompileMutation {
    InsertFieldLeaf  { hash: Word, field_ty: FieldTy, encoded: [Felt; 8] },
    InsertFieldBinOp { hash: Word, op: FieldOp,  field_ty: FieldTy,
                       lhs: Word, rhs: Word },
    InsertGroupCreate{ hash: Word, group_ty: GroupTy, x: Word, y: Word },
    InsertGroupBinOp { hash: Word, op: GroupOp,  group_ty: GroupTy,
                       lhs: Word, rhs: Word },
    LogAssertion     { hash: Word },
    StoreEvalResult  { expr: Word, result: EvaluatedValue },
    // ... chunks, keccak digest leaves, etc. — future
}
```

**Children are referenced by `Word`, not `NodeId`**, because `NodeId`s only
make sense relative to a particular snapshot of the DAG. Resolution happens at
apply time.

### 5.1 `apply_mutation` semantics

On `InsertFieldBinOp { hash, op, field_ty, lhs, rhs }`:
1. Resolve `lhs`, `rhs` to `NodeId`s via `hash_index`. Reject if either is
   absent.
2. **Recompute the expected hash** from `(lhs, rhs, field_ty, op)` via the
   tag-4 Poseidon2 permutation (the same computation MASM's
   `hash_field_binop` does). Reject if it doesn't match the claimed `hash`.
3. `dag.insert(hash, ExprBody::FieldBinOp { ... })`. Dedup short-circuits if
   the node already exists.

Mutations are **idempotent**: a registration firing twice for the same
expression is safe. This matters because MASM wrappers can be composed freely
without the host coordinating.

On `LogAssertion { hash }`:
1. Resolve `hash` to a `NodeId`. Reject if absent.
2. Append to `dag.assertions`. *Not* deduped — the same assertion can be
   logged multiple times and the transcript will reflect that.

On `StoreEvalResult { expr, result }`:
1. Resolve `expr` to a `NodeId`.
2. Insert into `eval_cache` (overwrite is fine; result is deterministic).

### 5.2 Atomicity

All mutations in a single event's response are validated first, then applied.
Any validation error rolls back the whole event (no partial state change).
This matches the user's expectation that an event is the unit of effect.

## 6. Precompile event handler trait

The existing `EventHandler` trait (`processor/src/host/handlers.rs:24-26`)
stays as-is for generic events. We introduce a **parallel** trait for handlers
that need access to the precompile island:

```rust
// processor/src/host/precompile_handlers.rs

pub trait PrecompileEventHandler: Send + Sync + 'static {
    fn on_event(
        &self,
        process: &ProcessorState,
        precompile: &PrecompileState,
    ) -> Result<PrecompileEventResponse, EventError>;
}

pub struct PrecompileEventResponse {
    pub advice: Vec<AdviceMutation>,          // stack/map/store updates
    pub precompile: Vec<PrecompileMutation>,  // DAG / assertions / eval cache
}
```

Why a separate trait rather than a sub-trait or an extra variant:
- **Different capability set.** Precompile handlers read `&PrecompileState`;
  generic handlers don't — and we don't want generic handlers accidentally
  gaining that capability.
- **Clean separation in the registry** (§6.1).
- **No impact on the fast path** for generic handlers, which stay exactly as
  they are today.

### 6.1 Registry

```rust
pub struct HostEventRegistry {
    generic: EventHandlerRegistry,
    precompile: PrecompileEventHandlerRegistry,
}
```

Dispatch order on `op_emit`:
1. System events (reserved, fixed).
2. Precompile handlers (if registered).
3. Generic handlers.
4. Error: unhandled event.

A given event ID routes to at most one handler, so the handler's signature
determines which mutation bag it can fill. Registration uses the same
duplicate-detection rules `EventHandlerRegistry` already enforces.

### 6.2 Processor-side glue (pseudocode)

```rust
let response = host.dispatch_event(event_id, process, &precompile_state)?;
precompile_state.validate_mutations(&response.precompile)?; // all-or-nothing
advice_provider.apply_mutations(response.advice)?;
precompile_state.apply_mutations(response.precompile)?;
```

`validate_mutations` is the hash-recompute + child-resolution pass. If it
fails, neither advice nor precompile state is touched.

## 7. Evaluator framework

Parallel to `PrecompileVerifier` registry but for *execution-time
evaluation*:

```rust
// core/src/precompile/evaluator.rs

pub trait ExprEvaluator: Send + Sync + 'static {
    fn evaluate(
        &self,
        node: &ExprNode,
        ctx: &EvalContext<'_>,
    ) -> Result<EvaluatedValue, EvalError>;
}

pub struct EvalContext<'a> {
    dag: &'a ExprDag,
    cache: &'a HashMap<NodeId, EvaluatedValue>,
    // read-only. Any new evaluation results are returned up the stack and
    // ultimately emitted as StoreEvalResult mutations.
}

pub struct PrecompileEvaluatorRegistry {
    field: BTreeMap<FieldTy, Arc<dyn ExprEvaluator>>,
    group: BTreeMap<GroupTy, Arc<dyn ExprEvaluator>>,
}
```

Evaluators are keyed by `(NodeKind, FieldTy | GroupTy)`. A `BN254FieldEvaluator`
handles `FieldTy::BN254Scalar`, a `BLS12_381G1Evaluator` handles
`GroupTy::BLS12_381_G1`, etc. Plugging in a new curve = registering a new
evaluator; no changes to the DAG or handlers.

### 7.1 Read-only evaluation, write via mutations

The `EvalContext` is **read-only**: evaluators see the DAG and the cache, but
cannot mutate them. Intermediate results produced during a single top-level
`evaluate` call accumulate in an ephemeral local cache inside the handler's
stack frame, and at the end the handler returns `StoreEvalResult` mutations
for every new entry. This keeps the "mutations only" invariant intact and
avoids any shared mutable state.

### 7.2 Where the evaluator is invoked

Evaluation is driven from the precompile event handler for the `eval` events
(§9). The handler:
1. Reads the target expression hash from the stack.
2. Resolves it to an `ExprNode` via `precompile.dag`.
3. Invokes the registered evaluator.
4. Assembles a response: advice mutations for the stack/advice return, plus
   precompile mutations for any new cache entries and any new leaf nodes.

The apply step writes everything atomically.

## 8. Registration events (host hints)

Every expression-registration event is a **hint**. The host re-derives
everything it stores. The AIR does not depend on these events firing — they
only populate the DAG that is later handed to the PVM trace generator.

### 8.1 `pvm::field::register_leaf`
- **MASM in:**  `[VALUE_LE(8), field_ty, ...]`
- **MASM out:** `[LEAF_HASH(4), ...]` (computed by `hash_field_leaf`)
- **Mutations emitted:** `InsertFieldLeaf { hash, field_ty, encoded }`

### 8.2 `pvm::field::register_binop`
- **MASM in:**  `[LHS_HASH(4), RHS_HASH(4), field_ty, op, ...]`
- **MASM out:** `[RESULT_HASH(4), ...]`
- **Mutations emitted:** `InsertFieldBinOp { ... }`

### 8.3 `pvm::group::register_create`, `pvm::group::register_binop`
Analogous for tags 5 and 6.

In all cases the handler recomputes the hash from the operand hashes + op +
field/group type using the tag-specific Poseidon2 preimage. MASM is trusted
only insofar as "if MASM lies, insert fails" — there is no path by which a
mismatched hash reaches the DAG.

## 9. Evaluation events

Two modes, both prerequisites for assertions: MASM must have two operand
hashes *and* they must exist in the DAG before it can build an `Eq` node and
log it.

### 9.1 Mode 1 — eval to hash (`pvm::eval::to_hash`)

**Contract:**
- **MASM in:**  `[EXPR_HASH(4), ...]`
- **MASM out:** `[LEAF_HASH(4), ...]`
  A new leaf node hash representing the evaluated value.
- **Handler work:**
  1. Look up `EXPR_HASH` in `precompile.dag`. Reject if absent.
  2. Run the registered `ExprEvaluator` to produce `EvaluatedValue`.
  3. Compute `LEAF_HASH` — the same hash MASM would get from
     `hash_field_leaf(value, field_ty)` or `hash_group_create(...)`.
  4. Response:
     - `advice: [ExtendStack(LEAF_HASH)]`
     - `precompile: [InsertFieldLeaf { hash: LEAF_HASH, ... }, StoreEvalResult
       { expr: EXPR_HASH, result }]`
- **Use case:** "I want to assert `poly(x) == 0`. Give me a leaf hash
  representing the evaluation of `poly(x)` so I can `Eq` it against a ZERO
  leaf." MASM never sees the concrete value.

### 9.2 Mode 2 — eval to advice (`pvm::eval::to_advice`)

**Contract:**
- **MASM in:**  `[EXPR_HASH(4), ...]`
- **MASM out:** the raw value felts on the advice stack (e.g. 8 u32-LE felts
  for a field element, more for a group point).
- **Handler work:**
  1. Look up `EXPR_HASH`. Reject if absent.
  2. Evaluate.
  3. Response:
     - `advice: [ExtendStack(encoded_value_felts)]`
     - `precompile: [StoreEvalResult { expr: EXPR_HASH, result }]`
  4. Does **not** register a new FieldLeaf. If the caller wants the value in
     the DAG, it calls `pvm::field::register_leaf` itself.
- **Use case:** "I need to branch on the actual value" — e.g. to pick a
  witness, to select a code path, to feed another computation in plain MASM.

### 9.3 Relationship

Mode 1 is Mode 2 composed with an internal leaf registration. We expose both
separately so the common "just give me the hash so I can `Eq` it" case does
not round-trip values through the MASM stack, and so the "I really need the
concrete bytes" case doesn't bloat the DAG with unneeded leaves.

## 10. Assertion event

Assertions are the *only* thing that touches the transcript and therefore
the *only* thing with AIR teeth. Registration and evaluation events are pure
host hints.

### 10.1 `pvm::assert::field_eq` (MASM-level wrapper)

```masm
pub proc assert_field_eq
    # Input: [LHS_HASH(4), RHS_HASH(4), field_ty, ...]
    # 1. Build the Eq node in the DAG (hint)
    push.EQ_OP movdn.9
    exec.register_field_binop           # => [EQ_HASH, ...]
    # 2. Tag it as a transcript assertion (hint)
    dupw emit.pvm::assert::log
    # 3. Real transcript append (AIR-enforced)
    exec.sys::log_precompile_request    # => [NEW_ROOT, ...]
end
```

- `pvm::assert::log` handler emits a single
  `LogAssertion { hash: EQ_HASH }` mutation. No AIR interaction.
- `log_precompile` is the only instruction with AIR teeth: it reads the
  assertion hash off the stack, runs one tagged Poseidon2 permutation on
  `[prev_root, assertion, [0,0,0,CURRENT_VERSION]]`, and threads the new root
  through `pc_transcript_state`. The hasher chiplet enforces the computation;
  no knowledge of the DAG reaches the opcode or the AIR.

### 10.2 `pvm::assert::group_eq`
Analogous with tag 6.

### 10.3 Safety argument

Even if every registration / eval / assert-log hint event is *lies*, the
proof still verifies — it just produces a DAG that the PVM trace generator
can't make sense of, and the assertion chain produced by `log_precompile`
chains nodes the PVM can't evaluate. The STARK is sound; the downstream
PVM verification step becomes the gate.

## 11. `op_log_precompile`'s role

Unchanged from `PVM.md` §4.2. Single-purpose opcode:
- Reads assertion hash from `stack[8..12]`.
- Reads `prev_root` from helpers (virtual-table bus "remove").
- Runs one tagged Poseidon2 permutation with
  `[RATE0=prev_root, RATE1=assertion, CAP=[0,0,0,VERSION]]`.
- Writes the new root to `stack[8..12]_next` (virtual-table bus "add").
- Zero knowledge of the DAG. Zero interaction with the host event dispatch.

The DAG exists entirely as a host-side hint structure. If the DAG disappeared
between execution and proof serialization, the STARK would still verify — it
would just be unusable as a PVM input.

## 12. Chunks and external precompiles

`ChunkStore`, Keccak digest leaves, SHA-512, ECDSA: noted as future work. They
share the island but live in their own sub-structures
(`PrecompileState.chunks`, etc.) with their own mutation variants. The
pattern is the same: a handler is registered as a `PrecompileEventHandler`,
reads what it needs from `ProcessorState + PrecompileState`, and returns
mutations the apply step validates and commits.

## 13. Wiring summary

```
MASM                            Host                          Island
────                            ────                          ──────
emit.pvm::field::register_*     PrecompileEventHandler
                                   reads &ProcessorState
                                   reads &PrecompileState
                                   returns Response {
                                     advice:     [...],
                                     precompile: [
                                       InsertFieldBinOp { ... }
                                     ],
                                   }
                                ─────────────────────────────▶ validate:
                                                                - recompute hash
                                                                - resolve children
                                                               apply:
                                                                - dedup insert

emit.pvm::eval::to_hash         handler reads dag,
                                   invokes ExprEvaluator,
                                   returns Response {
                                     advice:     [ExtendStack(leaf_hash)],
                                     precompile: [
                                       InsertFieldLeaf(...),
                                       StoreEvalResult(...),
                                     ],
                                   }

emit.pvm::eval::to_advice       handler evaluates,
                                   returns Response {
                                     advice:     [ExtendStack(value_felts)],
                                     precompile: [StoreEvalResult(...)],
                                   }

emit.pvm::assert::log           handler returns Response {
                                     precompile: [LogAssertion { hash }],
                                   }

log_precompile  (opcode)        processor state
                                   pc_transcript_state
                                      ← RPO(prev_root, assertion, VERSION)
                                   (no host interaction; AIR-enforced)
```

## 14. Files affected

**New**
- `core/src/precompile/dag.rs` — `ExprDag`, `ExprNode`, `ExprBody`, `NodeId`
- `core/src/precompile/state.rs` — `PrecompileState`, `PrecompileMutation`,
  `validate_mutations`, `apply_mutations`
- `core/src/precompile/evaluator.rs` — `ExprEvaluator`, `EvalContext`,
  `PrecompileEvaluatorRegistry`, `EvalError`
- `processor/src/host/precompile_handlers.rs` — `PrecompileEventHandler`,
  `PrecompileEventHandlerRegistry`, `PrecompileEventResponse`,
  `HostEventRegistry`
- `crates/lib/core/src/handlers/pvm/` — per-event handler impls
- `crates/lib/core/asm/crypto/pvm.masm` — tag hash helpers + register/eval/
  assert wrappers (the hash helpers themselves come from `PVM.md` §4.3)
- `.claude/pvm_host.md` — this document

**Modified**
- `processor/src/host/advice/mod.rs:56` — drop `pc_requests`
- `processor/src/host/mod.rs:34-57` —
  `AdviceMutation::ExtendPrecompileRequests` removed; event dispatch plumbing
  extended to thread `&PrecompileState` into precompile handlers and to route
  `PrecompileMutation` out
- `processor/src/host/handlers.rs:24-26` — `EventHandler` trait unchanged; new
  trait added alongside
- `processor/src/fast/mod.rs` — `ExecutionOutput` gains `precompile_state:
  PrecompileState`
- `core/src/proof.rs` — `ExecutionProof` gains DAG field; `pc_requests`
  removed
- `core/src/precompile.rs` — `PrecompileRequest`, `PrecompileTranscript`,
  `PrecompileVerifier` slated for deprecation once existing precompiles
  migrate to the island

## 15. Open questions

1. **Atomic vs. incremental mutation apply.** Current design: validate all,
   then apply all (§5.2). Cleanest semantically. Incremental would allow
   partial side effects on error, which we probably don't want.
2. **Evaluator reentrancy.** A top-level `evaluate` may need to recursively
   evaluate siblings. Current design: evaluators use an ephemeral local cache
   during a single call; new results are returned as `StoreEvalResult`
   mutations only at the top level. This avoids any shared mutable state but
   means memoization doesn't cross event boundaries until the apply step
   commits the results.
3. **Error recovery.** If an evaluator fails (malformed DAG, missing
   evaluator entry), abort the program or treat as a failed precompile and
   continue? Proposed: abort. The DAG state is then uncertain.
4. **Cross-execution caching.** Per-execution island is simplest and matches
   the proof model. Caching frequently-used small-int leaves across
   executions could cut DAG size. Defer until measured.
5. **Typed node IDs.** `NodeId(u32)` is untyped; we could split into
   `FieldNodeId` / `GroupNodeId` to catch mismatches at compile time. Adds
   boilerplate; defer.
6. **Group-coordinate typing.** Should `InsertGroupCreate` check that `x` and
   `y` resolve to field nodes of the correct `field_ty` for the group's base
   field? Cheap, worth doing at apply time.
7. **Does the advice provider need to know about the island at all?** Today
   it holds `pc_requests`. After this change it doesn't. But some existing
   helpers (`fingerprint`, serialization for tests) assume advice state
   includes precompile requests. Migration task.

---

# Part II — Implementation plan

This part is scoped to someone picking up the work. It leans on the PVM AIR
spec published in [discussion #3005](https://github.com/0xMiden/miden-vm/discussions/3005)
(archived locally in `.claude/PVM.md` §1) and translates it into concrete
host-side deliverables.

## 16. Mapping PVM AIR buses to host tables

The AIR defines **9 LogUp buses**. Every bus has a provider and a consumer;
if the host is meant to generate the witness that downstream PVM proving
consumes, it must produce, for every one of these buses, the full list of
tuples on whichever side is authored *outside* the PVM chips themselves.
The table below is the contract.

| AIR bus       | Width | AIR provider       | AIR consumer       | What the host authors                                                            |
|---------------|-------|--------------------|--------------------|----------------------------------------------------------------------------------|
| Binding       | 7     | eval chip          | eval chip          | *nothing* — self-balanced by the PVM eval chip                                   |
| Hash          | 16    | permutation chip   | eval chip          | host provides the list of **nodes** (`cap[4] ‖ val[8] → digest[4]`) for tag dispatch |
| Absorb        | 16    | permutation chip   | chunk chip         | host provides the **chunk absorption sequence** per chunk object                 |
| FieldLookup   | 10    | field chip         | eval chip          | host provides the **field table**: every `(field_ty, val[8], out_ptr)` referenced by a FieldLeaf |
| FieldEval     | 5     | field chip         | eval chip          | host provides the **field-arith trace**: every `(op, field_ty, lhs_ptr, rhs_ptr, out_ptr)` for Add/Sub/Mul BinOps |
| GroupLookup   | 4     | group chip         | eval chip          | host provides the **group table**: every `(group_ty, x_ptr, y_ptr, group_ptr)` referenced by a GroupCreate |
| GroupEval     | 5     | group chip         | eval chip          | host provides the **group-arith trace**: every `(op, group_ty, lhs_ptr, rhs_ptr, out_ptr)` for Add/Sub BinOps |
| KeccakEval    | 2     | Keccak chip        | eval chip          | host provides the **keccak-eval trace**: every `(ptr, len_bytes)` for Keccak nodes |
| ChunkVal      | 9     | chunk chip         | Keccak chip        | host provides the **per-chunk data**: every `(chunk_ptr, val[8])`                |

The same tables seed the *other* provider sides (permutation chip, chunk
chip, etc.) at PVM trace-gen time — but those computations live inside the
PVM prover. The host's contract is to emit a witness that uniquely
determines every tuple downstream PVM chips must produce.

**Two consequences for our data structures:**

1. The `ExprDag` is *not* sufficient on its own. It captures structure but
   not pointer-assigned values. A `WitnessTables` struct holds the ptr
   tables that the above buses consume.
2. Registration events populate the DAG; a **witness-generation pass** at
   end-of-execution walks the DAG, invokes evaluators, allocates canonical
   pointers, and fills the tables.

## 17. Canonical pointer assignment

The AIR spec (§2.3, §8.2, §8.3 of the discussion) is explicit:

> Pointer equality implies value equality: the chips must enforce canonical
> pointer assignment.

This is what makes `FieldBinOp::Eq` sound. The Eq arm compares only `ptr`s
— it never touches values. If the host assigned different pointers to equal
values, the proof would reject *valid* equalities. If it assigned the same
pointer to different values, soundness would break (but this is caught by
the PVM field chip's canonicity check).

**Host responsibility:** implement a canonicalizing allocator per
`(field_ty)` and per `(group_ty)`:

```rust
pub struct FieldTable {
    // canonical value -> ptr (canonical form is evaluator-defined;
    // for Goldilocks-like fields this is the reduced u16-limb vector)
    ptr_by_value: HashMap<(FieldTy, CanonicalFieldBytes), FieldPtr>,
    // ptr -> (field_ty, limbs, val[8])
    rows: Vec<FieldTableRow>,
}

pub struct FieldTableRow {
    ptr: FieldPtr,
    field_ty: FieldTy,
    limbs: Vec<u16>,      // for FieldEval bus
    val_u32le: [Felt; 8], // for FieldLookup bus and FieldLeaf preimage
}

pub struct GroupTable {
    ptr_by_coords: HashMap<(GroupTy, FieldPtr, FieldPtr), GroupPtr>,
    rows: Vec<GroupTableRow>,
}

pub struct GroupTableRow {
    ptr: GroupPtr,
    group_ty: GroupTy,
    x_ptr: FieldPtr,
    y_ptr: FieldPtr,
}
```

Allocation is idempotent: `intern_field(field_ty, value)` returns the
existing ptr if one exists, else allocates a fresh one. The
`rows: Vec<_>` side stores the row in allocation order, which is also the
order the witness gets serialized.

**Canonical form** is evaluator-owned (§7 of Part I). Different field types
may have different canonicalization rules (e.g. BN254 scalar mod r vs.
BLS12-381 base mod p). The `ExprEvaluator` trait gains a method:

```rust
pub trait ExprEvaluator: Send + Sync + 'static {
    fn evaluate(&self, node: &ExprNode, ctx: &EvalContext<'_>)
        -> Result<EvaluatedValue, EvalError>;

    /// Canonicalize a raw value into a byte form that hashes to the same
    /// identity as any other representation of the same value. Used as
    /// the key in `FieldTable::ptr_by_value`.
    fn canonicalize(&self, value: &EvaluatedValue) -> CanonicalFieldBytes;
}
```

## 18. Witness tables

Extend `PrecompileState` with the tables that match the AIR's provider
sides:

```rust
pub struct PrecompileState {
    // Structural DAG, authored incrementally by registration events.
    dag: ExprDag,

    // Canonical pointer tables, filled by the witness-generation pass.
    field_table: FieldTable,
    group_table: GroupTable,
    chunk_store: ChunkStore,
    keccak_table: KeccakTable,

    // Per-node resolved pointers (NodeId -> ResolvedPtr).
    // Filled alongside the tables during witness-gen.
    resolved: HashMap<NodeId, ResolvedPtr>,

    // Execution-time eval cache for pvm::eval::* events.
    eval_cache: HashMap<NodeId, EvaluatedValue>,

    // Plug-in point for arithmetic + canonicalization.
    evaluators: Arc<PrecompileEvaluatorRegistry>,
}

pub enum ResolvedPtr {
    Field(FieldPtr),
    Group(GroupPtr),
    KeccakDigest(KeccakPtr),
    Chunks(ChunkPtr, u32 /* n_chunks */),
    True, // for Eq nodes, Transcript nodes, Keccak nodes
}
```

### 18.1 Two phases

**Phase A — registration (during execution):** handlers write `ExprNode`s
into `dag`. Only structural data lands here — no values, no pointers, no
arithmetic. Handlers recompute the Poseidon2 hash (§5.1) and the
child-existence invariant but do no semantic work.

**Phase B — witness generation (end of execution):** a single driver walks
`dag.nodes` in insertion order (which is topological) and, for each node:

1. Dispatches to the evaluator registry based on `node.body`.
2. The evaluator computes the value (or delegates to cached sub-results).
3. The driver canonicalizes, allocates a pointer in the matching table,
   and records `resolved[node_id] = …`.
4. For BinOp nodes, the driver also appends a row to the FieldEval /
   GroupEval trace table.
5. For Keccak nodes, it appends to KeccakEval and ensures ChunkVal rows
   are present.
6. For Eq nodes, it checks `lhs_ptr == rhs_ptr` and records `True` (or
   fails witness gen if the equality doesn't hold — meaning MASM claimed
   an assertion that isn't actually valid).

Phase B is a pure function of Phase A plus the evaluator registry. It is
idempotent and deterministic, which makes it testable in isolation.

### 18.2 Why Phase A is *only* structural

Because the PVM AIR is the final arbiter, the host has no incentive to
pre-compute pointers during execution:

- Pointer allocation is order-sensitive; two different execution orders
  that insert the same set of (value, ptr) pairs in different orders
  would produce different witnesses. Phase B fixes the order to DAG
  insertion order.
- Arithmetic during execution is wasted work if the MASM path that
  triggered the registration turns out to be unreachable (rare but
  possible under conditional branches).
- `pvm::eval::*` events are the only execution-time code paths that
  legitimately need concrete values, and they already have their own
  plumbing (§9).

## 19. Witness serialization

The final artifact handed to the PVM trace generator is a
`PvmWitness`:

```rust
pub struct PvmWitness {
    version: Felt,

    // Transcript root = public input at air/src/lib.rs:67 [36..40]
    transcript_root: Word,

    // All nodes, in DAG insertion order (topological).
    nodes: Vec<SerializedNode>,

    // Per-bus tuple lists. Each row here corresponds to exactly one
    // provider tuple on the named AIR bus.
    field_table:    Vec<FieldTableRow>,   // FieldLookup provider
    group_table:    Vec<GroupTableRow>,   // GroupLookup provider
    field_eval:     Vec<FieldEvalRow>,    // FieldEval provider
    group_eval:     Vec<GroupEvalRow>,    // GroupEval provider
    chunk_store:    Vec<ChunkStoreRow>,   // Absorb + ChunkVal providers
    keccak_store:   Vec<KeccakStoreRow>,  // KeccakEval provider
}

pub struct SerializedNode {
    hash: Word,
    tag: u8,
    param_a: Felt,
    param_b: Felt,
    // For tags 0,4,5,6,7: (lhs_hash, rhs_hash). For tag 2,3: the 8
    // rate felts.
    val: [Felt; 8],
}
```

`hash_index` is *not* serialized; the verifier rebuilds it on load.

Length scaling:
- `nodes.len()` ≈ number of unique expressions. Duplicates are already
  deduped by the DAG.
- `field_table.len()` ≈ number of distinct canonical field values across
  all `field_ty`s.
- `field_eval.len()` ≈ number of unique FieldBinOp nodes (one row per
  non-Eq BinOp).
- `chunk_store` ≈ number of distinct chunk sequences × chunks-per-sequence.

In the common case (ZK-friendly field + a few equality checks) these are
all small.

## 20. Ordered implementation plan

The idea is to land this in stages that each compile and each have tests.
Every stage is a standalone PR's worth of work.

### Stage 1: data structures and witness types

**Files created:**
- `core/src/precompile/dag.rs`
- `core/src/precompile/tables.rs` (FieldTable, GroupTable, ChunkStore, KeccakTable)
- `core/src/precompile/witness.rs` (PvmWitness, SerializedNode, row types)
- `core/src/precompile/state.rs` (PrecompileState, PrecompileMutation)

**Scope:** pure data-structure code, no integration. Tests cover:
- `ExprDag::insert` dedup + topological invariant
- `FieldTable::intern` idempotency and canonical ptr assignment
- `PrecompileMutation` round-trip serialization
- `PvmWitness` round-trip serialization

**No evaluator needed yet.** Everything that would need arithmetic is
stubbed with a trait object that panics.

### Stage 2: host event dispatch and registry

**Files created:**
- `processor/src/host/precompile_handlers.rs`

**Files modified:**
- `processor/src/host/handlers.rs` — unchanged, just referenced
- `processor/src/host/mod.rs` — add `HostEventRegistry` that wraps both
  registries; wire dispatch through it
- `processor/src/host/default.rs` — update `DefaultHost` to own a
  `PrecompileState`

**Scope:** generic plumbing for the new trait. Tests:
- Register a mock `PrecompileEventHandler` that returns a known
  mutation, verify the mutation is validated + applied
- Verify generic `EventHandler` still works through the new registry
- Verify event ID collisions between generic and precompile registries
  are rejected

**No real PVM handlers yet.**

### Stage 3: registration event handlers

**Files created:**
- `crates/lib/core/src/handlers/pvm/field.rs` (register_leaf, register_binop)
- `crates/lib/core/src/handlers/pvm/group.rs` (register_create, register_binop)
- `crates/lib/core/src/handlers/pvm/assert.rs` (log assertion)
- `crates/lib/core/asm/crypto/pvm.masm` (hash helpers from PVM.md §4.3 +
  register wrappers)

**Scope:** end-to-end for the hint path. Tests:
- MASM program that registers a leaf, verifies the host DAG contains the
  node with the correct hash
- MASM program that registers a BinOp over two leaves, verifies the
  structural link
- Negative test: hash mismatch at host rejects the mutation
- Negative test: dangling child reference rejects the mutation

**Evaluator is still a panic stub.** No assertion testing yet (Stage 5).

### Stage 4: evaluator framework

**Files created:**
- `core/src/precompile/evaluator.rs` (trait + registry + context)
- `core/src/precompile/eval_driver.rs` (Phase B witness-gen driver)
- A test-only `Goldilocks` evaluator for e2e tests (NOT the real BN254/
  BLS12-381 ones — those are separate work)

**Files modified:**
- `core/src/precompile/state.rs` — add `generate_witness(&self) -> PvmWitness`

**Scope:** wire up the witness-gen pass. Tests:
- Goldilocks evaluator computes `a + b`, assigns canonical ptrs
- FieldEval trace matches the expected (op, lhs_ptr, rhs_ptr, out_ptr)
- Eq node succeeds when operands canonicalize to the same ptr, fails when
  they don't
- `generate_witness` on an empty DAG returns a valid empty witness

**Real evaluators (BN254, BLS12-381) are out of scope; leave them as
registrations that an external crate provides.**

### Stage 5: eval events

**Files modified:**
- `crates/lib/core/src/handlers/pvm/eval.rs` — `eval::to_hash`,
  `eval::to_advice`
- `crates/lib/core/asm/crypto/pvm.masm` — eval wrappers

**Scope:** execution-time access to the evaluator. Tests:
- MASM program: register `a`, register `b`, register `a+b`, eval it to
  hash, compare to an expected leaf hash
- MASM program: eval to advice, pop the value, use it to branch
- Negative test: eval of a DAG node that has no evaluator registered for
  its field_ty returns a clean error

### Stage 6: assertion event + opcode wiring

This depends on `log_precompile` being updated per `PVM.md` §4.2. If that
is not yet done, Stage 6 blocks on it.

**Files modified:**
- `crates/lib/core/asm/sys/mod.masm` — new 5-cycle wrapper (PVM.md §4.2)
- `crates/lib/core/asm/crypto/pvm.masm` — `assert_field_eq`,
  `assert_group_eq`
- Whatever AIR constraint changes `log_precompile` needs (owned by
  `PVM.md` §4.2 — not this doc)

**Scope:** close the loop. End-to-end test: MASM program that registers
two expressions, asserts equality, transcript root in public inputs is
the expected value, witness generation succeeds, witness contains the
expected assertion row.

### Stage 7: Keccak migration

Adapt the existing Keccak handler (`crates/lib/core/src/handlers/keccak256.rs`)
to populate the DAG + chunk store instead of producing a
`PrecompileRequest`. Out of scope for the initial PVM path unless there's
an existing program that depends on it.

### Stage 8: deprecation

Remove `AdviceMutation::ExtendPrecompileRequests`,
`AdviceProvider.pc_requests`, `PrecompileRequest`, `PrecompileTranscript`,
`PrecompileVerifier`, and related types. Confirm no callers remain.

## 21. Testing strategy

Three layers:

**Unit tests** (one per data-structure module):
- `ExprDag`: insert dedup, topological check, invariant rejection on
  bad input
- `FieldTable`/`GroupTable`: canonical ptr assignment, idempotency
- `PrecompileMutation::apply`: every variant, plus hash-recompute
  rejection
- `PvmWitness`: round-trip serialization

**Integration tests** (one per handler, in `processor/tests/`):
- Each MASM wrapper driven from a minimal program, assertions on the
  resulting `PrecompileState` after execution

**End-to-end tests** (in `miden-vm/tests/` or equivalent):
- Full program with registration → eval → assertion → transcript root
  in public inputs; verify the emitted `PvmWitness` matches a
  hand-constructed reference

**Property tests** (using `proptest`, per CLAUDE.md's project conventions):
- Random expression DAGs with deterministic canonical pointer allocation
  produce the same witness regardless of the order of hint event
  invocation (modulo DAG insertion order)
- Any DAG that Phase B accepts round-trips through serialization
  byte-for-byte

## 22. What this doc doesn't answer yet

- **Exact `FieldOp` / `GroupOp` enum numbering.** Must match PVM AIR
  encoding (discussion §5). Belongs in `core/src/precompile/ops.rs`.
- **Real evaluator implementations** for BN254 / BLS12-381 base and
  scalar fields. Likely a follow-up crate that depends on
  `arkworks` or `halo2-fields`.
- **Chunk store details** for Keccak. PVM AIR §6.7 requires a shared
  `ptr` between `KeccakDigest` and `Chunks`; the host must allocate
  this from a single pointer pool and be careful with lifetime.
- **Error codes.** Every mutation rejection, every evaluator failure,
  every witness-gen inconsistency needs a named error with a stable
  identifier. Belongs in `core/src/precompile/error.rs`.
- **Serialization format** — the byte layout of `PvmWitness`. Should
  be chosen to be stable, versioned (`CURRENT_VERSION`), and
  self-describing enough to survive minor schema extensions.

## 23. Quick reference for the person picking this up

Start by reading, in order:
1. `PVM.md` §1–§4 (the AIR-facing design)
2. This doc §1–§15 (the host-side design rationale)
3. This doc §16–§20 (the implementation plan)
4. Discussion #3005 comment 1 (the AIR spec, authoritative)

Code you'll want to reference:
- `processor/src/host/handlers.rs:24-26` — existing `EventHandler` trait
- `processor/src/host/mod.rs:34-57` — existing `AdviceMutation`
- `processor/src/host/advice/mod.rs:52-90` — existing `apply_mutations`
  pattern (the model we're copying)
- `core/src/precompile.rs:72-283` — types we're replacing
- `processor/src/execution/operations/crypto_ops/mod.rs:462-508` —
  `op_log_precompile` (modified by `PVM.md` §4.2, not this doc)

Commands you'll use:
- `make test-fast` after each stage
- `make test-processor test=pvm` for handler-specific tests
- `make test-core test=precompile` for data-structure tests
- `make lint` before every commit

