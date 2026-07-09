---
title: "Deferred computation"
sidebar_position: 1
---

# Deferred computation

*Deferred computation* is the mechanism by which a Miden program offloads an expensive or
non-native computation — a hash, a signature check, elliptic-curve or big-integer arithmetic — and
emits, in its place, an auditable record of *what was claimed*. That record is a content-addressed
DAG of nodes, committed by a single rolling digest (`DeferredState.root`, the **deferred
root commitment**). The DAG is designed to be verified **externally**: either alongside the Miden
VM's STARK proof, or by a dedicated *Precompile VM* whose proof attests that every committed node
evaluates correctly.

The DAG can be read as a small **program**: each node is a term, and evaluating the deferred root
to `TRUE` proves every claim it transitively references. The framework (`miden_core::deferred`)
owns the data model, the root commitment, and the wire format; individual *precompiles* plug in the
meaning of the nodes.

> **Status.** This page describes the current proof-bound precompile model: the VM accumulates
> the DAG during execution, `ExecutionProof` carries its canonical `DeferredStateWire`, and the
> verifier rehydrates that wire with the built-in precompile registry before checking the STARK
> proof. See [Status and scope](#status-and-scope).
>
> For the precise `DeferredState`, precompile, and public API contract, see
> [Deferred state semantics and API contract](./semantics.md).

## Motivation

The deferred subsystem models proof-bound work as a **graph of tagged payloads and structural
edges**. This lets the Precompile VM prove computation at a finer grain — for example, a single
curve or field operation — without re-hashing every intermediate as an opaque standalone assertion.
A calculation like `(a + b) · c` can reference and share sub-results by content address, so
operation-heavy precompiles avoid duplicating the same hashing work.

Each deferred node evaluates to a canonical node; an operation references its operands by their
content address; shared sub-computations are shared in the graph. When the framework needs ordered
accumulation, it represents it as a chain of semantic AND nodes whose root is a statement that must
evaluate to `TRUE`.

The DAG is also intended to match the draft Precompile VM model. In that design, a precompile's
operations and constraints are described as a graph of canonical values, payloads, and joins — so
modelling deferred computation the same way lets a precompile's native host implementation mirror
its eventual constraint implementation. This direction is developed in GitHub discussion #3005.

## The model

A **node** is a `(tag, payload)` pair, addressed by its 4-felt Poseidon2 **digest**. Identical
content yields an identical digest, so equal subterms are shared automatically (hash-consing).

- A **tag** is a node's identity and constructor: externally, precompile tags are built with
  `Tag::precompile(id, args)`, while `Tag::from_word` is reserved for raw stack/wire decoding. The `id`
  selects the owning precompile; the three immediate felts (`args`) are entirely the precompile's
  to interpret (a discriminant, a data length, a small constant, …). The framework reserves ids `0`,
  `1`, and `2` for itself: `Tag::TRUE = [0, 0, 0, 0]` tags the canonical `TRUE` node,
  `Tag::AND = [1, 0, 0, 0]` tags semantic conjunction nodes, and
  `Tag::CHUNKS = [2, 0, 0, 0]` tags framework-owned opaque byte chunks. No precompile may claim
  these ids. Deferred statement accumulation uses the same semantic `AND` constructor as a
  restricted right-spined chain.
- A **payload** is the node's body, in one of four shapes:
  - the framework `TRUE` sentinel, carrying no data; it is the only zero-payload node;
  - a data payload: one or more 8-felt rate-sized chunks, linearly hashed under the tag. An empty
    data payload is forbidden; precompiles decide whether a data payload represents a scalar,
    digest, message, hash preimage, coordinate, or some other local value;
  - a join payload: two child digests (`lhs`, `rhs`) for anything referential, such as a binary
    operation, predicate, or AND step;
  - a pair-list payload: one or more structural digest pairs for precompile-specific multi-pair
    structures. Pairs are encoded in payload order as 8-felt chunks `lhs || rhs`, and their child
    order is `lhs0`, `rhs0`, `lhs1`, `rhs1`, and so on. Canonical wire encodes the same ordered
    pairs as topological child indices. Empty pair lists are rejected; exact pair-count/arity
    constraints are semantic and enforced by the owning precompile. Budget accounting treats each
    pair as one ordinary 8-felt payload block, in addition to the tag word.

The digest binds the tag in the Poseidon2 capacity, so a node's address commits to *both* its
identity and its body. Every non-empty payload is absorbed as one or more 8-felt blocks under the
node tag.

## Precompiles

A **precompile** is the framework's extension point: an implementation of the `Precompile` trait
that claims one tag id and, within that slice of tag space, defines a *family of node types*
plus the rules that give them meaning. Think of it as a small typed sub-language embedded in the
DAG. Concrete proof-bound precompiles live in the `miden-precompiles` crate; MASM support code
for them is currently treated as internal implementation detail.

A precompile supplies three things:

- `decode(args) -> Option<NodeType>` — *type-checks* a tag: which constructor is this, and what
  structural shape does it carry? This inspects only `Tag::args()`; payload data is not available yet.
  The returned shape drives registration and wire handling, but exact data/pair-list arity is
  semantic and is checked during precompile evaluation:
  - `NodeType::Data` declares a non-empty opaque data payload.
  - `NodeType::Join` declares one payload block containing two child digests.
  - `NodeType::PairList` declares a non-empty list of structural `lhs || rhs` digest pairs.
  - `NodeType::True` is reserved for the framework TRUE sentinel; a precompile must not return it.
- `evaluate(args, payload, …) -> Result<Node>` — computes a node's **canonical form**. The
  common roles are: validate a canonical value represented as data (its canonical is itself),
  evaluate an operation (evaluate the child canonicals, then combine), or check a predicate
  (evaluate operands, return the `TRUE` node on success or fail otherwise). These roles are
  conventions, not a fixed taxonomy — a precompile is free to define multi-ary constructors and so
  on over data, join, and pair-list payloads.
- `init() -> Vec<Node>` — contributes any canonical constant values (e.g. `ZERO`, `ONE`, a curve
  generator) at registry-initialization time.

Precompiles are collected in a **`PrecompileRegistry`**, the framework's dispatcher: it routes each
tag id to its owning precompile and is otherwise indifferent to how the precompile behaves. A
precompile's `id` is derived the same way event IDs are — the name hashed with Blake3 and folded
into a single field element — but in its own domain-separated namespace, so a precompile and an
event of the same name get different ids by construction. The registry rejects misconfigured or
duplicate ids at construction. The default registry is empty and rejects every precompile-owned
tag. A `DeferredState` carries the registry it evaluates under. The default registry is empty;
the public VM/prover/verifier path installs the standard `miden-precompiles` registry for bundled
proof-bound precompiles.

During evaluation the framework hands the precompile a `DeferredContext`, through which it can
`get_node` for a registered digest, `evaluate_digest` a child digest to its canonical digest, or
`register` a freshly-minted helper node into the DAG. Registered helper nodes are validated under
the same registry and must satisfy the ordinary child-closure rules. The precompile never touches
the commitment directly — it supplies only per-node meaning, and the framework drives the
depth-first recursion.

The in-memory `DeferredState` may memoize evaluation results internally. That memoization is
transparent to precompile implementations and is not serialized as trusted state.

## Building the DAG from a program

A program grows and evaluates the DAG through deferred system events. Each event mutates only the
*host-side* `DeferredState`; no register event hands a digest back through advice. Code that later
uses or logs that digest must derive it **in-circuit** from the same operand-stack or memory data in
a precompile-specific assembly procedure.

| Event (`adv.*`)            | Operand stack in                 | Effect |
| -------------------------- | -------------------------------- | ------ |
| `register_deferred`        | `[PAYLOAD_LO, PAYLOAD_HI, TAG, …]` | Decodes `TAG` and registers an operand-stack node, then evaluates it immediately. `TAG` is one 4-felt word. `PAYLOAD_LO || PAYLOAD_HI` is exactly 8 felts: one data chunk, two 4-felt child digests for a join, or one `lhs_digest || rhs_digest` pair for a pair-list node. Structural child digests may reference only already-registered children, except for the implicit `TRUE_DIGEST`. No advice/stack output; code that needs `NODE_DIGEST` computes it in-circuit with one `hperm` over `[PAYLOAD_LO, PAYLOAD_HI, TAG]`. |
| `register_deferred_data`   | `[TAG, ptr, n_chunks, …]`        | Decodes `TAG` and registers a memory-backed node, then evaluates it immediately. Data tags read exactly `n_chunks` 8-felt chunks from word-aligned memory at `ptr`; pair-list tags interpret those chunks as `lhs_digest || rhs_digest` pairs; join tags require `n_chunks == 1` and interpret the single chunk as `lhs_digest || rhs_digest`; `TRUE` is rejected. No advice/stack output; code that needs `NODE_DIGEST` computes it in-circuit from the same `TAG` and memory range using the digest rule for the decoded payload shape. |
| `evaluate_deferred`        | `[NODE_DIGEST, …]`               | Looks the node up, evaluates it to canonical form, and pushes the canonical tag plus canonical payload felts onto the **advice stack**. The tag is first in advice-pop order; for a single 8-felt payload, `adv_pushw adv_pushw adv_pushw` leaves `[PAYLOAD_LO, PAYLOAD_HI, TAG, …]` on the operand stack. `TRUE` emits only `Tag::TRUE`. |
| `evaluate_deferred_tag`    | `[NODE_DIGEST, …]`               | Looks the node up, evaluates it to canonical form, and pushes only the canonical tag onto the **advice stack**. `TRUE` emits `Tag::TRUE`. |
| `evaluate_deferred_payload` | `[NODE_DIGEST, …]`              | Payload-only compatibility event. Looks the node up, evaluates it to canonical form, and pushes only the canonical payload felts onto the **advice stack**. For each 8-felt data chunk, advice is arranged as `HIGH` then `LOW` so `adv_pushw adv_pushw` leaves `LOW` on top and `HIGH` beneath it; chunks preserve canonical chunk order. Join payloads use the same two-word LIFO convention, leaving `lhs_digest` above `rhs_digest` after two `adv_pushw`s. `TRUE` emits no advice. |

`register_*` validate the tag's shape and child closure for structural payloads. They store the
original node under its digest, evaluate it immediately, and fail immediately if semantic evaluation
fails.

### Why the digest is computed in-circuit

A system event is an unconstrained advice hook: the honest handler can compute a digest, but the
AIR has no constraint tying an advice-supplied digest to the operand-stack payload or to memory at
`ptr`. If a digest folded into the deferred root commitment came from advice, a prover could attest
a node over data the circuit never held. Deriving it in-circuit (`hperm` / `mem_stream`) closes the
gap, and it composes with the verifier:

- the **in-circuit hash** binds the digest to the circuit's own operand stack / memory;
- once the deferred root is threaded into proof public inputs, the **deferred-root match** will
  bind that digest to the wire the verifier rehydrates;
- `DeferredState::from_wire` then rehydrates the canonical wire opening and evaluates the expected
  root from wire data.

Once the root is public, these pieces bind the wire — and therefore every evaluation the verifier
re-checks — to the data the circuit actually committed to.

### Why `evaluate_deferred` is a bare event

A deferred-evaluation event's output is a *deferred evaluation* the circuit cannot perform, so it
must come through advice — but that makes it an **unbound host hint**. Using it soundly requires
re-hashing the returned payload (and, for the full event, checking the returned tag) in-circuit and
logging a predicate that `from_wire` re-checks; an in-circuit `eq`/`assert` over two raw evaluate
results proves nothing. Because that obligation is precompile-specific (which predicate to log is
the precompile's business), deferred evaluation is intentionally *not* exposed as a generic safe
`sys` procedure. A precompile-specific assembly procedure must bind the raw event output to the
circuit data it cares about. The same ownership applies to registration: a precompile-specific
procedure can make a raw register event safe by computing the node digest in-circuit from the
operand stack or memory, so the worst a misuse can do is make the verifier reject.

Predicates are **not** special-cased on evaluation: their canonical is the `TRUE` node like any
other successful predicate. `evaluate_deferred_payload` emits no advice for `TRUE` because `TRUE`
has no payload, while `evaluate_deferred_tag` and full `evaluate_deferred` emit `Tag::TRUE`. A
failed predicate has already surfaced as an error before any felts are pushed.

## The deferred root commitment

The deferred root commitment is a rolling AND-chain. `DeferredState.root` starts at the zero word
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

The verifier's deferred obligation collapses to a single fixed point: **rehydrate the proof-carried
wire, compare its root to the public deferred root, evaluate that root to `TRUE`, and every logged
statement holds.** There is no separate finalization step.

## Wire format and verification

The proof/witness format is `DeferredStateWire`, not the in-memory `DeferredState`. `to_wire`
lowers state to a passive, canonical, topologically ordered entry stream:

- wire index `0` is the implicit `TRUE_DIGEST`;
- `entries[i]` has wire index `i + 1`;
- data entries carry literal data chunks;
- join entries encode both children by index;
- pair-list entries encode each pair's children by index;
- structural child indices may reference only `0` or earlier entries;
- empty `entries` opens `TRUE_DIGEST`; a non-empty wire opens the digest of the last entry.

`to_wire` emits a deterministic child-first DFS of the root-reachable closure, so unreferenced
orphans are dropped.

`DeferredState::from_wire(registry, wire, max_elements)` is the only trusted path from wire bytes
back to a validated state. It runs as a structural decode, a canonicality check, and a root
evaluation. This validates the wire's own implicit root; proof verification compares the returned
`state.root()` against the public deferred root committed by the VM trace.

1. **structural** — seed index `0` as the implicit `TRUE_DIGEST`, reconstruct each explicit
   entry (translating structural child indices back to digests), decode its tag, check that the entry
   variant and payload shape match the declared `NodeType`, reject explicit `TRUE`, reject duplicate
   digests, and require structural children to reference only earlier entries;
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

This framework is now the proof-bound precompile substrate. In its current form:

- the VM accumulates the DAG host-side and exposes the `DeferredState` on the execution output;
- `log_deferred` advances the deferred root by folding registered statements with `Tag::AND`;
- the final deferred root is threaded into the STARK public inputs;
- `ExecutionProof` carries a canonical `DeferredStateWire`, which the verifier rehydrates under the
  built-in precompile registry before checking the STARK proof;
- the `miden-precompiles` crate provides concrete hash, arithmetic, and curve precompile
  implementations used by core-library facades and built-in verification.

The proof format binds the final deferred root, not a registry name or version. For that reason,
execution, trace generation, proof generation, and verification all use the built-in
`miden_precompiles::registry()` policy. The public VM/prover/verifier APIs do not accept
caller-supplied precompile registries. Use `verify_with_max_deferred_elements(...)` when verifying
proofs produced with a non-default deferred-state budget.

More generic DAG resource accounting remains a follow-up; the external STARK that verifies a
committed DAG, the **Precompile VM**, is described in GitHub discussion #3005.
