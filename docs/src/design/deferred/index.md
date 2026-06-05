---
title: "Deferred computation"
sidebar_position: 1
---

# Deferred computation

*Deferred computation* is the mechanism by which a Miden program offloads an expensive or
non-native computation — a hash, a signature check, elliptic-curve or big-integer arithmetic — and
emits, in its place, an auditable record of *what was claimed*. That record is a content-addressed
DAG of nodes, committed by a single rolling digest (`DeferredState.root`, the **deferred root**).
The DAG is designed to be verified **externally**: either alongside the Miden
VM's STARK proof, or by a dedicated *Precompile VM* whose proof attests that every committed node
evaluates correctly.

The DAG can be read as a small **program**: each node is a term, and evaluating the deferred root
to `TRUE` proves every claim it transitively references. The framework (`miden_core::deferred`)
owns the data model, the deferred root, and the serialization format; individual *precompiles* plug
in the meaning of the nodes.

> **Status.** The VM now commits the final deferred root in its proof public inputs, and execution
> proofs carry `DeferredStateWire` so verifiers can rehydrate and evaluate the opened deferred state
> under the installed precompile registry. See [Status and scope](#status-and-scope) and
> [Deferred-state serialization](./serialization.md).
>
> For the precise `DeferredState`, precompile, and public API contract, see
> [Deferred state semantics and API contract](./semantics.md).

## Motivation

The deferred subsystem generalizes an earlier, linear request-list design. A linear list of
standalone assertions (hash checks, signatures, and similar claims) is simple, but becomes expensive
the moment the Precompile VM must prove computation at a finer grain — a *single* curve or field
operation. In the linear model every binary operation is its own assertion: hash its operands and
result into a statement. A calculation like `(a + b) · c` cannot reference or share its sub-results
— each step is an opaque, standalone request. For operation-heavy precompiles this at least doubles
the VM's hashing.

The fix is to stop treating deferred work as a *sequence of requests* and treat it as a **graph of
tagged payloads and joins**. Once the deferred statements are modelled as a DAG, much falls into
place: each node evaluates to a canonical node; an operation *references* its operands by their
content address instead of re-hashing them; shared sub-computations are shared in the graph. When
the framework needs ordered accumulation, it represents it as a chain of semantic AND nodes whose
root is a statement that must evaluate to `TRUE`.

Crucially, the DAG is the language the Precompile VM already speaks. The way a precompile's
operations and constraints are described in that VM is inherently a graph of canonical values,
payloads, and joins — so by modelling deferred computation the same way, **a precompile's native
(host) implementation comes to mirror its constraint implementation.** One structure drives both.
This direction is developed in the draft specification in GitHub discussion #3005.

## The model

A **node** is a `(tag, payload)` pair, addressed by its 4-felt Poseidon2 **digest**. Identical
content yields an identical digest, so equal subterms are shared automatically (hash-consing).

- A **tag** is a node's identity and constructor: externally, precompile tags are built with
  `Tag::precompile(id, args)`, while `Tag::from_word` is reserved for raw stack/wire decoding. The `id`
  selects the owning precompile; the three immediate felts (`args`) are entirely the precompile's
  to interpret (a discriminant, a data length, a small constant, …). The framework reserves ids `0`
  and `1` for itself: `Tag::TRUE = [0, 0, 0, 0]` tags the canonical `TRUE` node, and
  `Tag::AND = [1, 0, 0, 0]` tags semantic conjunction nodes. No precompile may claim either id.
  Deferred statement accumulation uses the same semantic `AND` constructor as a restricted
  right-spined chain.
- A **payload** is the node's body, in one of three shapes:
  - the framework `TRUE` sentinel, carrying no data; it is the only zero-payload node;
  - a data payload: one or more 8-felt rate-sized chunks, linearly hashed under the tag. An empty
    data payload is forbidden; precompiles decide whether a data payload represents a scalar,
    digest, message, hash preimage, coordinate, or some other local value;
  - a join payload: two child digests (`lhs`, `rhs`) for anything referential, such as an
    operation, predicate, or AND step.

The digest binds the tag in the Poseidon2 capacity, so a node's address commits to *both* its
identity and its body.

## Precompiles

A **precompile** is the framework's extension point: an implementation of the `Precompile` trait
that claims one tag id and, within that slice of tag space, defines a *family of node types*
plus the rules that give them meaning. Think of it as a small typed sub-language embedded in the
DAG. The `miden-precompiles` crate provides production hash and signature wrappers today, while
mock/test-support precompiles in `miden_core::testing::precompile` exercise framework-only cases
such as elliptic-curve groups and big-integer fields.

A precompile supplies three things:

- `decode(args) -> Option<NodeType>` — *type-checks* a tag: which constructor is this, and what
  structural shape does it carry (`NodeType::Data(n)` or `NodeType::Join`)? Tag inspection only.
  For data tags, this is also the precompile-owned size gate: returning `NodeType::Data(n)`
  authorizes the host to read exactly `n` 8-felt chunks, so oversized data tags should be rejected
  here. `NodeType::True` is reserved for the framework TRUE sentinel; a precompile must not return
  it.
- `evaluate(args, payload, …) -> Result<Node>` — computes a node's **canonical form**. The
  common roles are: validate a canonical value represented as data (its canonical is itself),
  evaluate an operation (evaluate the child canonicals, then combine), or check a predicate
  (evaluate operands, return the `TRUE` node on success or fail otherwise). These roles are
  conventions, not a fixed taxonomy — a precompile is free to define unary operations, multi-ary
  constructors, and so on over data and join payloads.
- `init() -> Vec<Node>` — contributes any canonical constant values (e.g. `ZERO`, `ONE`, a curve
  generator) at registry-initialization time.

Precompiles are collected in a **`PrecompileRegistry`**, the framework's dispatcher: it routes each
tag id to its owning precompile and is otherwise indifferent to how the precompile behaves. A
precompile's `id` is derived the same way event IDs are — the name hashed with Blake3 and folded
into a single field element — but in its own domain-separated namespace, so a precompile and an
event of the same name get different ids by construction. The registry rejects misconfigured or
duplicate ids at construction. The default registry is empty and rejects every precompile-owned
tag. A `DeferredState` carries the registry it evaluates under; top-level VM prove/verify paths
install the `miden-precompiles` registry, and lower-level APIs accept an explicit registry for
custom proof-bound precompile sets.

During evaluation the framework hands the precompile a `DeferredContext`, through which it can
`get_node` for a registered digest, `evaluate_digest` a child digest to its canonical digest, or
`register` a freshly-minted helper node into the DAG. Registered helper nodes are validated under
the same registry and must satisfy the ordinary child-closure rules. The precompile never touches
the deferred root directly — it supplies only per-node meaning, and the framework drives the
depth-first recursion.

The in-memory `DeferredState` may memoize evaluation results internally. That memoization is
transparent to precompile implementations and is not serialized as trusted state.

## Building the DAG from a program

A program grows the DAG through three system events. Each event mutates only the *host-side*
`DeferredState`; no register event hands a digest back through advice. Code that later uses or logs
that digest must derive it **in-circuit** from the same operand-stack or memory data in a
precompile-specific assembly procedure.

| Event (`adv.*`)            | Operand stack in                 | Effect |
| -------------------------- | -------------------------------- | ------ |
| `register_deferred`        | `[PAYLOAD_LO, PAYLOAD_HI, TAG, …]` | Decodes `TAG` and registers an operand-stack node, then evaluates it immediately. `TAG` is one 4-felt word. `PAYLOAD_LO || PAYLOAD_HI` is exactly 8 felts: either one data chunk or two 4-felt child digests for a join. Join payloads may reference only already-registered children, except for the implicit `TRUE_DIGEST`. No advice/stack output; code that needs `NODE_DIGEST` computes it in-circuit with one `hperm` over `[PAYLOAD_LO, PAYLOAD_HI, TAG]`. |
| `register_deferred_data`   | `[TAG, ptr, …]`                  | Decodes `TAG` and registers a memory-backed node, then evaluates it immediately. Data tags read the tag-declared number of 8-felt chunks from word-aligned memory at `ptr`; join tags read exactly 8 felts and interpret them as `lhs_digest || rhs_digest`; `TRUE` is rejected. No advice/stack output; code that needs `NODE_DIGEST` computes it in-circuit from the same `TAG` and memory range using the digest rule for the decoded payload shape. |
| `evaluate_deferred`        | `[NODE_DIGEST, …]`               | Looks the node up, evaluates it to canonical form, and pushes the canonical's `tag || payload` felts onto the **advice stack**. The first `adv_pushw` reads `TAG`; data payloads then return two words per 8-felt chunk; join payloads return `lhs_digest` then `rhs_digest`; `TRUE` returns only its tag word. |

`register_*` validate the tag's shape and, for join-shaped nodes, child closure. They store the
original node under its digest, evaluate it immediately, and fail immediately if semantic evaluation
fails.

### Why the digest is computed in-circuit

A system event is an unconstrained advice hook: the honest handler can compute a digest, but the
AIR has no constraint tying an advice-supplied digest to the operand-stack payload or to memory at
`ptr`. If a digest folded into the deferred root came from advice, a prover could attest
a node over data the circuit never held. Deriving it in-circuit (`hperm` / `mem_stream`) closes the
gap, and it composes with the verifier:

- the **in-circuit hash** binds the digest to the circuit's own operand stack / memory;
- the **deferred-root match** binds that digest to the wire the verifier rehydrates;
- `DeferredState::from_wire` then rehydrates the canonical deferred-state opening and evaluates the
  expected root from serialized data.

Together, these pieces bind the wire — and therefore every evaluation the verifier re-checks — to
the data the circuit actually committed to.

### Why `evaluate_deferred` is a bare event

`evaluate_deferred`'s output is a *deferred evaluation* the circuit cannot perform, so it must come
through advice — but that makes it an **unbound host hint**. Using it soundly requires re-hashing
the returned `tag || payload` in-circuit and logging a predicate that `from_wire` re-checks; an
in-circuit `eq`/`assert` over two raw evaluate results proves nothing. Because that obligation is
precompile-specific (which predicate to log is the precompile's business), `evaluate_deferred` is
intentionally *not* exposed as a generic safe `sys` procedure. A precompile-specific assembly
procedure must bind the raw event output to the circuit data it cares about. The same ownership
applies to registration: a precompile-specific procedure can make a raw register event safe by
computing the node digest in-circuit from the operand stack or memory, so the worst a misuse can do
is make the verifier reject.

Predicates are **not** special-cased on evaluation: their canonical is the `TRUE` node, pushed as
`Node::to_felts()` (tag first, then payload) like any other node — which for `TRUE` is just its
4-felt tag, since `TRUE` has no payload. A failed predicate has already surfaced as an error before
any felts are pushed.

## The deferred root

The deferred root is a rolling AND-chain. `DeferredState.root` starts at the zero word
(`TRUE_DIGEST`), which is also the digest of the always-present canonical `Node::TRUE`. To fold a
verified
**statement** — any registered digest that evaluates to `TRUE`, not necessarily a primitive
predicate node — the framework registers an AND node
`{ tag: Tag::AND, payload: prev_root || stmt_digest }` and advances the root to that node's digest.
The append path first evaluates the statement under the installed registry and rejects missing or
non-`TRUE` statements. Wire verification does not replay append history; it opens the wire's
implicit root and evaluates that root directly. The digest is structural: even `AND(TRUE, TRUE)` hashes
under the distinct capacity `[1, 0, 0, 0]` and is not equal to `TRUE_DIGEST`, though it evaluates
semantically to `TRUE`.

The verifier's obligation collapses to a single fixed point: **evaluate the root to `TRUE`, and
every logged statement holds.** There is no separate finalization step.

## Deferred-state serialization and verification

The proof serialization format is `DeferredStateWire`, not the in-memory `DeferredState`. `to_wire`
lowers the root-reachable opened state to a passive, canonical, topologically ordered entry
stream. Wire index `0`
is the implicit `TRUE_DIGEST`; `entries[i]` has wire index `i + 1`; join entries encode children by
index and may reference only `0` or earlier entries. Empty `entries` opens `TRUE_DIGEST`; a non-empty
wire opens the digest of the last entry. `to_wire` emits a deterministic child-first DFS of the
root-reachable closure, so unreferenced orphans are dropped.

`DeferredState::from_wire(registry, wire, max_elements)` is the only trusted path from wire bytes
back to a validated state. It runs as a structural decode, a canonicality check, and a root
evaluation. This validates the wire's own implicit root; verifier proof plumbing compares the
returned `state.root()` against the VM proof's committed deferred root.

1. **structural** — seed index `0` as the implicit `TRUE_DIGEST`, reconstruct each explicit
   entry (translating child indices back to digests), decode its tag, check that the entry variant
   and payload shape match the declared `NodeType`, reject explicit `TRUE`, reject duplicate
   digests, and require join children to reference only earlier entries;
2. **canonicality** — register decoded entries into a fresh state, set the implicit wire root as
   `state.root`, and require `state.to_wire() == wire`; this rejects dangling nodes,
   non-root-last encodings, and equivalent-but-reordered topological wire;
3. **semantic** — evaluate the implicit wire root under the installed precompiles and require it to
   equal the canonical `TRUE` node. Evaluation may insert canonical/helper nodes in addition to
   the wire nodes.

A wire that yields any integrity error is rejected; a faithful one reconstructs a state whose root is
the wire's implicit root and whose canonical wire output is byte-for-byte identical to the input
wire.

## Status and scope

This framework is proof-bound in the VM. In its current form:

- the VM accumulates the DAG host-side and exposes the `DeferredState` on the execution output;
- `ExecutionProof` carries `DeferredStateWire`;
- the verifier rehydrates that opened state under a `PrecompileRegistry`, evaluates the opened root,
  and compares it to the deferred root committed by the VM proof public input;
- legacy core-library crypto wrappers are advice-only compatibility helpers; proof-bound concrete
  precompile use lives in the `miden-precompiles` package.

The target PVM flow can consume `ExecutionOutput.deferred_state` directly during same-process native
proving. Serialization remains the boundary format for partial proofs, external proving handoff, and
standalone verifier rehydration.

The external STARK that verifies the committed DAG, the **Precompile VM**, is described in GitHub
discussion #3005.
