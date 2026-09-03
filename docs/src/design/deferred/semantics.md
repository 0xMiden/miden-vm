---
title: "Deferred state semantics and API contract"
sidebar_position: 2
---

# Deferred state semantics and API contract

`DeferredState` is the host-side state used to evaluate a deferred DAG and maintain its root
commitment. It is prover input, not cryptographic evidence. A deferred execution proof transports a
passive `DeferredStateWire`; hydration into a singleton `PrecompileWitness` is a separate façade
operation.

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
- Structural nodes may reference only children already present in `nodes`, except for the implicit
  `TRUE_DIGEST`:
  - `Join` has two child digests.
  - `PairList` has one or more pairs of child digests.
- Re-registering identical content is idempotent and free.
- Reusing an existing digest for different content is rejected as a conflicting node.

Registration stores and shape-checks a node in `nodes`, evaluates it immediately, and stores the
canonical result. False predicates and other semantic evaluation failures are reported by
registration.

## One fixed ceiling

`DeferredState::new(registry)` initializes one total budget from the library safety ceiling:

```text
remaining_elements = MAX_DEFERRED_ELEMENTS
```

Initialization also installs the registry's `init()` constants, charging them against that same
budget. `extend_precompiles(precompiles)` merges additional precompiles into an existing state
without discarding existing nodes, evaluation results, root, or budget accounting.

Every new unique durable node inserted into `nodes` decrements `remaining_elements` by the node's
field-element footprint using checked subtraction. Duplicate insertion is free, so registering the
same data node at the exact budget limit succeeds. Evaluation results do not have a separate budget
and do not double-count canonical payloads; only canonical/helper nodes newly inserted into `nodes`
are charged.

The precompile's `decode` result is the framework shape gate:

- `NodeType::Data` authorizes a non-empty data payload. For memory-backed registration, the host
  reads exactly the stack-supplied `n_chunks`; precompile evaluation checks any tag-derived semantic
  data length.
- `NodeType::Join` authorizes exactly one 8-felt payload block, interpreted as two child digests.
- `NodeType::PairList` authorizes a non-empty list of `lhs_digest || rhs_digest` chunks. Precompile
  evaluation checks any tag-derived semantic pair count.

Processor handlers perform a cheap deferred-budget pre-check before allocating or reading a
memory-backed payload, but exact data/pair-list arity remains precompile-specific semantics.

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

`to_wire` serializes only the root-reachable closure in canonical child-first order:

- data entries carry literal data chunks;
- join entries emit two child indices;
- pair-list entries emit pairs of child indices.

The wire root is implicit: empty wire opens `TRUE_DIGEST`, otherwise the root is the digest of the
final entry. `from_wire(registry, wire)` decodes untrusted wire under `MAX_DEFERRED_ELEMENTS`,
rejects non-canonical or dangling wire by requiring `state.to_wire() == wire`, then evaluates the
implicit wire root to `Node::TRUE`. Evaluation may insert canonical/helper nodes in addition to the
wire nodes.

## Proof obligations and composition

`Prover::prove` proves the VM first. A `TRUE_DIGEST` root yields
`PrecompileStatus::Empty`. Any other root yields `PrecompileStatus::Deferred` with a passive
`DeferredStateWire`. Canonical proof decoding does not need a registry and does not hydrate that
wire.
`Prover::prove_full` proves both stages directly from the in-memory execution witness.

For delegated proving, call `miden_vm::precompile_witness_from_wire` explicitly. It applies the
bundled registry, reconstructs the state, checks canonical wire structure, and evaluates the
implicit root to `TRUE`. The result is a singleton witness suitable for
`Prover::prove_precompile`.

`PrecompileWitness::merge` accepts a non-empty vector of singleton witnesses. It preserves exact
input order and duplicate root multiplicity: `[one, one, two]` remains `[one, one, two]`. A
one-input merge remains singleton; a multi-root result cannot be merged recursively. DAG nodes may
be deduplicated, but root occurrences are not. The root count and merged hydrated state are bounded
by
the fixed `MAX_PRECOMPILE_ROOTS` and `MAX_DEFERRED_ELEMENTS` hard ceilings.

The resulting `PrecompileProof` carries the ordered roots. Their left reduction, beginning with the
first root, is the statement verified by the aggregate precompile STARK. For one execution proof,
coverage is membership of its single VM-authenticated root in that sequence. Verification is
stateless and does not consume occurrences across calls, so one aggregate proof can complete each
compatible deferred proof independently; sequence order and duplicates still determine the STARK
statement.

`VmProof` and `PrecompileProof` are unvalidated transport records with public fields. `StarkProof`
retains private fields and its existing constructor and accessor interface. `ExecutionProof` is the
canonical binary transport. Its constructor, Serde representation, and `complete` method may
represent inconsistent artifacts. None of these operations establishes validity.

`Verifier::verify_precompile` validates the precompile proof shape, expected root membership,
ordered aggregate folding, and the precompile STARK. It can validate a precompile artifact against
an expected outstanding root and returns its authenticated security parameters. `Verifier::verify`
checks the proof's compatibility declaration and execution lifecycle before it verifies the VM
STARK. It reuses `verify_precompile` for complete proofs. A successful deferred verification returns
the authenticated VM security parameters and outstanding root. A successful complete verification
has no outstanding obligation and, when it includes a precompile proof, also returns the PVM
security parameters.


## Transport and limits

`ExecutionProof::to_bytes` is infallible. `ExecutionProof::read_from_bytes` checks canonical syntax,
rejects trailing bytes, and does not need a registry. The proof stores the transport format and the
compatible VM and PVM verifier root histories. Decoding selects the format-specific proof decoder.
Native verification requires a shared VM root and a shared PVM root with the verifier's private
support policy. Transport preserves the precompile state without validating consistency between
artifacts. `DeferredStateWire` is passive until the bundled façade hydration step.

Canonical binary decoders enforce fixed hard ceilings before allocating declared collections:
`MAX_STARK_PROOF_BYTES` per inner STARK, `MAX_PRECOMPILE_ROOTS` per ordered root list, and
`MAX_DEFERRED_ELEMENTS` for deferred wire. Hydration and witness merge also enforce the deferred
state and root ceilings. These are library safety bounds, not configurable protocol, whole-envelope,
file, network, or ingestion policy.

Proof and wire artifacts use derived Serde as a representation format. Generic Serde
deserialization is not guaranteed to apply the canonical decoder's early allocation bounds and must
not be treated as a hardened untrusted-input decoder.

The canonical representational minima are 2 bytes for `StarkProof`, 34 bytes for `VmProof`, and 3
bytes for `PrecompileProof`, because an empty-root record remains transportable until verification.
The shortest canonical singleton `PrecompileProof` is 35 bytes; a vector of two such records has a
71-byte shortest encoding.

Recursive VM verification packages the unchanged proof stream under
`proof_request_key(verifier_root, claim_commitment)`. The consumer derives the same key from the
claim commitment and `vm::verify_proof` procedure root, fetches the stream with
`adv.push_mapval`, and then invokes `vm::verify_proof`. Claim and kernel preimages remain
separately content-addressed; no proof values are copied into claim memory. Recursive verification
authenticates and returns the VM root but does not settle precompile work.
