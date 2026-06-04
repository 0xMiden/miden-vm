---
title: "Deferred state semantics and API contract"
sidebar_position: 2
---

# Deferred state semantics and API contract

`DeferredState` is the host-side witness for deferred DAG verification and the deferred root
commitment. The in-memory state is not serialized directly; execution proofs carry
`DeferredStateWire`, and `DeferredState::from_wire` rebuilds a trusted state by decoding canonical
wire and evaluating the wire's implicit root under the installed `PrecompileRegistry`.

The simplified state model is:

```rust
pub struct DeferredState {
    registry: Arc<PrecompileRegistry>,
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    remaining_elements: usize,
    // evaluation results may be memoized internally, but this is not part of the public contract
}
```

## Vocabulary

- **Registered** means a digest has an entry in `DeferredState.nodes`. Registration can happen
  through `DeferredState::register`, evaluation storing canonical/helper nodes, `log_statement`
  storing framework `AND` nodes, or wire rehydration rebuilding entries.
- **Evaluated** means a registered input digest has been semantically reduced to a canonical node
  under the installed `PrecompileRegistry`. The canonical node is also stored in `nodes` so it can
  be referenced by downstream nodes.
- **Logged** or **root-reachable** means a registered digest contributes to `DeferredState.root`.
  Only the root-reachable closure is serialized by `to_wire`; registered/evaluated orphans are
  dropped.

## Registered nodes

`nodes` is the durable node store.

- `TRUE_DIGEST` is always present and maps to `Node::TRUE`.
- `Node::TRUE` costs no budget.
- Every non-TRUE node is keyed by `node.digest()`.
- Join-shaped nodes may reference only children already present in `nodes`, except for the implicit
  `TRUE_DIGEST`.
- Re-registering identical content is idempotent and free.
- Reusing an existing digest for different content is rejected as a conflicting node.

Registration stores and shape-checks a node in `nodes`, evaluates it immediately, and stores the
canonical result. False predicates and other semantic evaluation failures are reported by
registration.

## One remaining budget

`DeferredState::new(registry, max_elements)` initializes one total budget:

```text
remaining_elements = max_elements
```

Initialization also installs the registry's `init()` constants, charging them against that same
budget. `extend_precompiles(precompiles)` merges additional precompiles into an existing state
without discarding existing nodes, evaluation results, root, or budget accounting.

Every new unique durable node inserted into `nodes` decrements `remaining_elements` by the node's
field-element footprint using checked subtraction. Duplicate insertion is free, so registering the
same data node at the exact budget limit succeeds. Evaluation results do not have a separate budget
and do not double-count canonical payloads; only canonical/helper nodes newly inserted into `nodes`
are charged.

For data-payload nodes, the precompile's `decode` result is also the size gate: returning
`NodeType::Data(n)` authorizes the host to read and allocate exactly `n` 8-felt chunks for that
tag. Precompiles should reject oversized data tags in `decode` instead of relying on a separate
deferred data-size limit.

If insertion exhausts the remaining budget, execution aborts with a budget error. The insertion path
owns this accounting; processor deferred handlers do not perform post-mutation deferred budget
checks.

## Evaluation

Evaluation first requires the input digest to be present in `nodes`; evaluation state alone never
creates durable DAG membership. A call to `evaluate_digest(digest)` returns the digest of the
canonical node. This is a semantic operation: it may compute the result or use internal
memoization, but callers do not observe that distinction. Callers that need canonical node contents
can compose `evaluate_digest` with `get_node`.

Framework nodes evaluate as follows:

```text
Node::TRUE => Node::TRUE
Node::AND(lhs, rhs) =>
  require evaluate_digest(lhs) == TRUE_DIGEST
  require evaluate_digest(rhs) == TRUE_DIGEST
  Node::TRUE
```

Precompile-owned nodes are evaluated by `PrecompileRegistry::evaluate`, which dispatches to the
owning `Precompile` with a `DeferredContext`.

`DeferredContext` gives precompile implementations the same semantic split:

- `get_node(digest)` queries the registered/original node by digest without evaluating it.
- `evaluate_digest(digest)` evaluates a registered child digest to its canonical digest.
- `evaluate_digest_pair(lhs, rhs)` evaluates two registered child digests to canonical digests.
- `ensure_equal(lhs, rhs)` evaluates two children and requires their canonical digests to match.
- `register(node)` inserts a freshly minted helper node and returns its original digest.

## Root and wire

`root` starts at `TRUE_DIGEST`. `log_statement(stmt_digest)` evaluates the current root and
statement, requires both to evaluate to `Node::TRUE`, then appends one framework `AND` node:

```text
next_root = digest(Node::and(previous_root, stmt_digest))
```

`to_wire` serializes only the root-reachable closure in canonical child-first order. The wire root
is implicit: empty wire opens `TRUE_DIGEST`, otherwise the root is the digest of the final entry.
`from_wire(registry, wire, max_elements)` decodes untrusted wire, rejects non-canonical or dangling
wire by requiring `state.to_wire() == wire`, then evaluates the implicit wire root to `Node::TRUE`.
Evaluation may insert canonical/helper nodes in addition to the wire nodes. Verifier proof plumbing
compares the returned `state.root()` to the deferred root committed by the VM proof.

## Public API

The preferred public `DeferredState` surface is small:

- `DeferredState::new(registry, max_elements)` for a state booted with precompile constants
- `extend_precompiles(precompiles)` for additive setup
- `registry()`
- `root()`
- `remaining_elements()`
- `get_node(digest)` and `nodes() -> &BTreeMap<Digest, Node>` for registered-node inspection
- `decode(tag)` for structural tag decoding
- `register(node)` for inserting concrete node content
- `evaluate_digest(digest)` for the canonical digest
- `log_statement(stmt_digest)`
- `to_wire()`
- `from_wire(registry, wire, max_elements)`

Callers that have a concrete node should explicitly `register` it; they may call
`evaluate_digest` on the returned digest when they need the canonical result, and then `get_node` if
they need canonical node contents. Raw evaluation memoization and direct root mutation are not part
of the public contract.

## Scope note

The VM proof now binds the final deferred root to the execution proof's `DeferredStateWire`.
Top-level VM prove/verify paths install the `miden-precompiles` registry, while lower-level
registry-aware APIs allow callers to supply an explicit registry for custom proof-bound
precompiles.
