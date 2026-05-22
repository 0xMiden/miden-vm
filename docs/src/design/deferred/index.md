---
title: "Deferred computation"
sidebar_position: 1
---

# Deferred computation

*Deferred computation* is the mechanism by which a Miden program offloads an expensive or
non-native computation — a hash, a signature check, elliptic-curve or big-integer arithmetic — and
emits, in its place, an auditable record of *what was claimed*. That record is a content-addressed
DAG of nodes, committed by a single rolling digest (`DeferredState.root`, the **deferred
commitment**). The DAG is verified **externally**: either alongside the Miden VM's STARK proof, or
by a dedicated *Precompile VM* whose proof attests that every committed node evaluates correctly.

The DAG can be read as a small **program**: each node is a term, and reducing the commitment to
`TRUE` proves every claim it transitively references. The framework (`miden_core::deferred`) owns
the data model, the commitment, and the wire format; individual *precompiles* plug in the meaning
of the nodes.

> **Status.** This page describes the framework as an additive substrate: the VM accumulates the
> DAG during execution and exposes it on the execution output, but it is not yet folded into the
> STARK proof. The proof-model cutover — and the migration of the existing precompiles onto this
> model — lands separately. See [Status and scope](#status-and-scope).

## Motivation

The deferred subsystem replaces an earlier, linear design. In that design a program deferred work to
a future Precompile VM by committing to a **list of precompile requests** — each request a
standalone assertion (a hash check, a signature) — folded one after another into a running sponge
transcript. The structure was a sequence: commit a request, absorb it, repeat.

That linearity becomes expensive the moment the Precompile VM must prove computation at a finer
grain — a *single* curve or field operation. In the linear model every binary operation is its own
assertion: hash its operands and result into a statement, then absorb that statement into the
transcript. That is two hashes per operation, and an expression like `(a + b) · c` cannot reference
or share its sub-results — each step is an opaque, standalone request. For operation-heavy
precompiles this at least doubles the VM's hashing.

The fix is to stop treating deferred work as a *sequence of requests* and treat it as a **graph of
expressions**. Once the deferred statements are modelled as a DAG, much falls into place: each node
is an expression that evaluates to something; an operation *references* its operands by their
content address instead of re-hashing them; shared sub-expressions are shared in the graph. The
linear transcript does not disappear — it becomes a special case. The transcript is itself an
assertion: a chain of AND nodes whose root is a statement that must evaluate to `TRUE`. "Commit to a
list" and "commit to an expression DAG" are the same mechanism.

Crucially, the DAG is the language the Precompile VM already speaks. The way a precompile's
operations and constraints are described in that VM is inherently a graph of expressions — so by
modelling deferred computation the same way, **a precompile's native (host) implementation comes to
mirror its constraint implementation.** One structure drives both. This direction is developed in
the draft specification in GitHub discussion #3005.

## The model

A **node** is a `(tag, payload)` pair, addressed by its 4-felt Poseidon2 **digest**. Identical
content yields an identical digest, so equal subterms are shared automatically (hash-consing).

- A **tag** is a node's identity and constructor: `Tag { id, args: [Felt; 3] }`. The `id` selects
  the owning precompile; the three immediate felts (`args`) are entirely the precompile's to
  interpret (a discriminant, a chunk length, a small constant, …). The framework reserves
  `id == ZERO` for itself — it tags the canonical `TRUE` node and the AND nodes of the commitment;
  no precompile may claim it.
- A **payload** is the node's body, in one of two shapes:
  - an **expression** — exactly 8 felts (one Poseidon2 rate block): raw value data for a leaf, or
    two packed child digests (`lhs || rhs`) for anything referential (an operation, a predicate,
    an AND step);
  - a **chunk** body — `n ≥ 1` 8-felt blocks of bulk data (a hash preimage, a message), whose
    digest is the linear hash of the `8n` felts under the tag. An empty chunk body is forbidden.

The digest binds the tag in the Poseidon2 capacity, so a node's address commits to *both* its
identity and its body.

## Precompiles

A **precompile** is the framework's extension point: an implementation of the `Precompile` trait
that claims one `Tag::id` and, within that slice of tag space, defines a *family of node types*
plus the rules that give them meaning. Think of it as a small typed sub-language embedded in the
DAG — the reference precompiles cover hashes, signatures, elliptic-curve groups, and big-integer
fields.

A precompile supplies three things:

- `decode(args) -> Option<NodeType>` — *type-checks* a tag: which constructor is this, and what
  structural shape does it carry (`Value`, `Binary`, or `Chunks(n)`)? Tag inspection only.
- `reduce(args, payload, …) -> Result<Node>` — *normalizes* a node to its **canonical form**. The
  common roles are: validate a value leaf (its canonical is itself), evaluate an operation (resolve
  the child canonicals, then combine), or check a predicate (resolve operands, return the `TRUE`
  node on success or fail otherwise). These roles are conventions, not a fixed taxonomy — a
  precompile is free to define unary operations, multi-ary constructors, and so on over the three
  structural shapes.
- `init() -> Vec<Node>` — contributes any canonical constant leaves (e.g. `ZERO`, `ONE`, a curve
  generator) at registry-initialization time.

Precompiles are collected in a **`PrecompileRegistry`**, the framework's dispatcher: it routes each
`Tag::id` to its owning precompile and is otherwise indifferent to how the precompile behaves. A
precompile's `id` is derived the same way event IDs are — the name hashed with Blake3 and folded
into a single field element — but in its own domain-separated namespace, so a precompile and an
event of the same name get different ids by construction. The registry rejects misconfigured or
duplicate ids at construction. The default registry is empty and rejects every tag; a host installs
precompiles via `FastProcessor::with_precompile`.

During reduction the framework hands the precompile a `WitnessBuilder`, through which it can
`resolve` a child digest to its canonical or `intern` a freshly-minted child into the DAG. The
precompile never touches the data model or the commitment directly — it supplies only per-node
meaning, and the framework drives the depth-first recursion.

## Building the DAG from a program

A program grows the DAG through three system events. Each event mutates only the *host-side*
`DeferredState`; the digest a program uses is **derived in-circuit**, never handed back through
advice. The `sys` core-library module wraps the two register events in a thin helper.

| Event (`adv.*`)            | `sys` helper     | Operand stack in                 | Effect |
| -------------------------- | ---------------- | -------------------------------- | ------ |
| `register_deferred`        | `register_expr`  | `[PAYLOAD_LO, PAYLOAD_HI, TAG, …]` | Decodes the tag and interns the expression node. No advice/stack output; the helper then computes `NODE_DIGEST` with one `hperm` over `[PAYLOAD, TAG]`. |
| `register_deferred_chunk`  | `register_chunk` | `[TAG, ptr, n_chunks, …]`        | Decodes `n` from the tag, reads `8n` felts from memory at `ptr`, interns the chunk node. No advice/stack output; the helper then computes `NODE_DIGEST` with a `mem_stream` linear hash over the same `8n` felts. |
| `evaluate_deferred`        | *(none)*         | `[NODE_DIGEST, …]`               | Looks the node up, reduces it, interns the canonical, and pushes the canonical's `tag || payload` felts onto the **advice stack** (`TAG` first, then payload words in hash order). |

`register_*` validate the tag's shape and intern the node, but do not reduce it — they are pure
host hints that populate the DAG.

### Why the digest is computed in-circuit

A system event is an unconstrained advice hook: the honest handler can compute a digest, but the
AIR has no constraint tying an advice-supplied digest to the operand-stack payload or to memory at
`ptr`. If the digest folded into the transcript came from advice, a prover could attest a node over
data the circuit never held. Deriving it in-circuit (`hperm` / `mem_stream`) closes the gap, and it
composes with the verifier:

- the **in-circuit hash** binds the digest to the circuit's own operand stack / memory;
- **transcript root-match** (a public input) binds that digest to the wire the verifier rehydrates;
- `DeferredState::rehydrate` then re-reduces every logged statement from wire data.

Together these bind the wire — and therefore every reduction the verifier re-checks — to the data
the circuit actually committed to.

### Why `evaluate_deferred` is a bare event

`evaluate_deferred`'s output is a *deferred reduction* the circuit cannot perform, so it must come
through advice — but that makes it an **unbound host hint**. Using it soundly requires re-hashing
the returned `tag || payload` in-circuit and logging a predicate that `rehydrate` re-checks; an
in-circuit `eq`/`assert` over two raw evaluate results proves nothing. Because that obligation is
precompile-specific (which predicate to log is the precompile's business), `evaluate_deferred` is
intentionally *not* wrapped as a safe `sys` proc: each precompile wraps the raw event itself. The
register helpers, by contrast, return an already-bound digest, so they are safe by default — the
worst a misuse can do is make the verifier reject.

Predicates are **not** special-cased on evaluation: their canonical is the `TRUE` node, which
serializes to its 12 felts like any other expression. A failed predicate has already surfaced as an
error before any felts are pushed.

## The deferred commitment

The commitment is a rolling AND-chain. `DeferredState.root` starts at the zero word (`TRUE_DIGEST`,
the empty-transcript terminal). To fold a verified **statement** — a predicate node that reduces to
`TRUE` — the framework interns an AND node `{ tag: TRUE, payload: prev_root || stmt_digest }` and
advances the root to that node's digest. Because the AND tag is the zero word, the AND node's digest
is exactly `Poseidon2::merge(prev_root, stmt_digest)`: the chain is a 2-to-1 hash fold, and its head
is a complete digest at every step.

> **The fold reuses the existing `log_precompile` opcode.** Folding a statement (`merge(root,
> stmt)`) is identical to one step of the VM's rolling precompile transcript, so the new
> `sys::log_node_digest` helper feeds a node digest straight into `log_precompile`. The opcode is
> doing *deferred-commitment* work, not anything precompile-specific; it will be renamed
> `log_deferred` once it is no longer shared with the model this work supersedes.

The verifier's obligation collapses to a single fixed point: **reduce the root to `TRUE`, and every
logged statement holds.** There is no separate finalization step.

## Wire format and verification

The in-memory `DeferredState` does not travel in the proof. `to_wire` lowers it to a passive
`DeferredStateWire`: a topologically-ordered list of entries in which referential nodes encode their
children by **index** into earlier entries (an 8-byte pair of `u32`s) rather than by 64-byte
digests. The walk is a DFS post-order from the root that emits exactly the root's reachable closure,
so unreferenced orphans are dropped and the commitment is recoverable as the digest of the last
entry.

`rehydrate` is the only trusted path from wire bytes back to a validated state. It runs in two
phases, with a reachability gate between them:

1. **structural** — reconstruct each node (translating child indices back to digests), decode its
   tag, check that the payload shape matches the declared `NodeType`, and intern it;
2. **reachability** — reject any entry outside the root's structural closure, so an adversarial wire
   cannot smuggle in hidden or bloat nodes;
3. **semantic** — walk the AND-chain from the root down to the terminal, asserting each step is a
   well-formed AND node and **re-evaluating each statement to the `TRUE` node** under the installed
   precompiles.

A wire that yields any integrity error is rejected; a faithful one reconstructs a state equivalent
to the prover's.

## Status and scope

This framework is an additive substrate. In its current form:

- the VM accumulates the DAG host-side and exposes the `DeferredState` on the execution output;
- the state is **not** yet threaded into the STARK proof, and the AIR is unchanged;
- the legacy precompile path (`core::precompile`, the `sys::log_precompile_request` wrapper) is
  untouched, and is still documented under [Precompiles](../stack/precompiles.md).

The proof-model cutover — threading the deferred commitment into the proof, migrating the existing
precompiles onto this model, and retiring the request-list transcript — lands in a follow-up. The
external STARK that verifies the committed DAG, the **Precompile VM**, is described in GitHub
discussion #3005.
