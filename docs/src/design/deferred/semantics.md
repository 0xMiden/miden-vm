---
title: "Deferred state semantics and API contract"
sidebar_position: 2
---

# Deferred state semantics and API contract

`DeferredState` is the host-side witness for deferred DAG verification. The in-memory state is not
serialized directly; proofs carry `DeferredStateWire`, and `DeferredState::from_wire` rebuilds a
trusted state by decoding canonical wire and evaluating the wire's implicit root under the installed
`PrecompileRegistry`.

The simplified state model is:

```rust
pub struct DeferredState {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
    evals: BTreeMap<Digest, Digest>, // input digest -> canonical digest
    remaining_elements: usize,
}
```

## Durable nodes

`nodes` is the only durable node store.

- `TRUE_DIGEST` is always present and maps to `Node::TRUE`.
- `Node::TRUE` costs no budget.
- Every non-TRUE node is keyed by `node.digest()`.
- Join-shaped nodes may reference only already-materialized children, except for the implicit
  `TRUE_DIGEST`.
- Re-registering identical content is idempotent and free.
- Reusing an existing digest for different content is rejected as a conflicting node.

Registration materializes and shape-checks a node. It does not reduce operations or prove
predicates; false predicates fail only when evaluated or logged as statements.

## One remaining budget

`DeferredState::new(max_elements)` initializes one total budget:

```text
remaining_elements = max_elements
```

`PrecompileRegistry::new_state(max_elements)` builds the same state and then installs the
registry's `init()` constants, charging them against that same budget.

Every new unique durable node inserted into `nodes` decrements `remaining_elements` by the node's
field-element footprint using checked subtraction. Duplicate insertion is free, so registering the
same chunk node at the exact budget limit succeeds. Evaluation memos do not have a separate budget
and do not double-count canonical payloads; only canonical/helper nodes newly materialized in
`nodes` are charged.

For chunk-bodied nodes, the precompile's `decode` result is also the size gate: returning
`NodeType::Chunks(n)` authorizes the host to read and allocate exactly `n` chunks for that tag.
Precompiles should reject oversized chunk tags in `decode` instead of relying on a separate deferred
chunk-size limit.

If insertion exhausts the remaining budget, execution aborts with a budget error. The insertion path
owns this accounting; processor deferred handlers do not perform post-mutation deferred budget
checks.

## Evaluation memos

`evals` maps an input digest to the digest of its canonical result:

```text
evals: input_digest -> canonical_digest
```

Canonical node contents live only in `nodes`.

Evaluation first requires the input digest to be present in `nodes`; a memo entry alone never
creates membership. On a memo hit, the canonical digest is looked up in `nodes` and the canonical
node is returned. On a miss, the framework reduces the node, inserts/materializes the canonical node
through the same insertion helper used by registration, then records the memo.

Framework nodes reduce as follows:

```text
Node::TRUE => Node::TRUE
Node::AND(lhs, rhs) =>
  require evaluate(lhs) == Node::TRUE
  require evaluate(rhs) == Node::TRUE
  Node::TRUE
```

Precompile-owned nodes are reduced by `PrecompileRegistry::reduce`, which dispatches to the owning
`Precompile` with a `WitnessBuilder` for resolving children and interning helper nodes.

## Transcript and wire

`root` starts at `TRUE_DIGEST`. `append_statement(registry, stmt_digest)` evaluates the statement
and requires it to reduce to `Node::TRUE`, then appends one framework `AND` node:

```text
next_root = digest(Node::and(previous_root, stmt_digest))
```

`to_wire` serializes only the root-reachable closure in canonical child-first order. The wire root
is implicit: empty wire opens `TRUE_DIGEST`, otherwise the root is the digest of the final entry.
`from_wire(wire, registry, max_elements)` decodes untrusted wire, rejects non-canonical or dangling
wire by requiring `state.to_wire(registry) == wire`, then evaluates the implicit wire root to
`Node::TRUE`. Evaluation repopulates `evals` and may materialize canonical/helper nodes in addition
to the wire nodes. Proof plumbing should compare the returned `state.root()` to the externally
committed root.

## Public API

The preferred public `DeferredState` surface is small:

- `DeferredState::new(max_elements)` for a bare state
- `PrecompileRegistry::new_state(max_elements)` for a state booted with precompile constants
- `root()`
- `register(registry, node)`
- `evaluate(registry, digest)`
- `append_statement(registry, stmt_digest)`
- `to_wire(registry)`
- `from_wire(wire, registry, max_elements)`

Raw node access and direct root mutation remain private or crate-private. Callers that have a
concrete node should explicitly `register` it and then `evaluate` the returned digest.

## Scope note

This pass simplifies deferred state and budgeting only. It does not change `log_precompile`
behavior or the legacy precompile transcript path.
