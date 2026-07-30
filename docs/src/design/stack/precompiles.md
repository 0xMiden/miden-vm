# Precompiles

Precompiles let Miden programs make claims about expensive computations without executing them
directly in the VM trace, while still binding those claims into the VM proof. This page covers the
VM-side mechanics: wrappers register deferred nodes, bind their digests to circuit-visible data, and
log statement digests that evaluate to `TRUE`. `ExecutionProof` carries `DeferredProof` material for
the resulting root; for proof shapes, see [Deferred computation](../deferred/index.md).

Concrete proof-bound implementations live in the `miden-precompiles` crate. Their MASM support
modules are currently internal implementation detail used by core-library facades and tests.

## Current data model

| Concept | Description |
| ------- | ----------- |
| `Tag` | A 4-felt node constructor. Framework ids `0`, `1`, and `2` are reserved for `TRUE`, semantic `AND`, and opaque framework `CHUNKS`; precompile ids are derived from precompile names and interpret the remaining three `args` felts locally. |
| `Node` | A content-addressed `(tag, payload)` term in the deferred DAG. Payloads are data chunks, join child digests, pair lists of `lhs_digest || rhs_digest` chunks, or the framework `TRUE` sentinel. |
| `Precompile` | A host implementation that owns one precompile id, decodes the structural shape for its tags, evaluates nodes to canonical form, and optionally contributes canonical constants through `init()`. |
| `PrecompileRegistry` | The host/framework dispatcher for trusted precompile implementations. Public VM/prover/verifier APIs use the standard registry from `miden-precompiles`. |
| `DeferredState` | The host-side DAG witness accumulated during execution. It tracks registered nodes, evaluates them under the registry, and maintains the rolling deferred root. |
| `DeferredStateWire` | The canonical wire format for partial proofs. It is passive data until rehydrated and validated with `DeferredState::from_wire`. |
| Deferred root | A single digest public value. Each logged statement appends `Node::AND(previous_root, statement_digest)` and advances the root to that node digest. |

## Lifecycle overview

1. **Wrapper registers nodes** – Internal MASM support code stages node payloads on the operand
   stack or in memory and emits `adv.register_deferred` / `adv.register_deferred_data`.
   Registration stores the node in host-side `DeferredState`, checks structural child closure, and
   evaluates the node immediately under the installed registry.
2. **Wrapper binds digests inside the VM** – Registration arguments are visible in the VM execution
   trace, but the event does not constrain the host-side `DeferredState` update. Memory-backed
   registration additionally performs direct host reads without adding AIR memory accesses. The
   wrapper computes each proof-relevant digest with VM instructions from the exact same tag and
   stack payload or ordered memory chunk sequence.
3. **Wrapper evaluates only through explicit predicates** – When a wrapper uses
   `adv.evaluate_deferred*` to obtain host-computed canonical data, it must use VM instructions to
   relate that advice to values established independently of it, then log a statement digest that
   the verifier can re-evaluate.
4. **`log_deferred` folds a statement** – The opcode expects `STMNT` at stack offsets `4..8`.
   `STMNT` must already be registered in `DeferredState` and evaluate to `TRUE`. The constrained
   Poseidon2 permutation computes `ROOT_NEW = rate0(Poseidon2([ROOT_PREV, STMNT, Tag::AND]))`, and
   host-side deferred state records the corresponding `AND` node.
5. **Prover binds the deferred root** – The VM STARK uses the final deferred root as a public input.
   `ExecutionProof` carries the chosen `DeferredProof` form: default proving produces final material
   (`Empty` or `Stark`), while explicit partial proving preserves `Wire`.
6. **Verifier resolves and checks** – Final verification resolves a trusted root from `DeferredProof`
   before VM STARK verification and rejects `Wire`. `Verifier::verify_partial` accepts only `Wire`,
   rehydrates it under the built-in `miden_precompiles::registry()` with the configured deferred
   budget, then verifies the VM STARK against the hydrated root.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes deferred advice events and `log_deferred`, maintains the rolling deferred root, and exposes the final root as a public value. |
| Host / advice provider | Maintains `DeferredState`, runs trusted precompile implementations, and supplies evaluation advice when wrappers request it. |
| MASM wrapper | Registers concrete deferred nodes, computes node/statement digests with VM instructions from exact stack payloads or memory reads, logs only registered statements that should evaluate to `TRUE`, and hides helper outputs from callers when appropriate. |
| Prover | Uses the final deferred root as a VM STARK public input and includes the chosen `DeferredProof` form in `ExecutionProof`: final `Empty`/`Stark` by default, or `Wire` for explicit partial proving. |
| Verifier | Resolves a trusted deferred root from `DeferredProof` before VM STARK verification. Final verification rejects `Wire`; partial verification rehydrates `Wire` under the built-in `miden_precompiles::registry()`. |

## Conventions

- Tag layout: `TAG = [precompile_id, arg0, arg1, arg2]`.
  - `precompile_id` selects the framework or owning precompile.
  - `arg0..arg2` are interpreted by the selected precompile.
  - Framework id `0` is `Tag::TRUE`; framework id `1` is `Tag::AND`; framework id `2` is
    `Tag::CHUNKS`.
- Payload shapes are declared by the selected precompile's `decode(args)`, but semantic lengths are
  tag-specific and validated by the owning precompile:
  - `NodeType::Data` accepts one or more opaque 8-felt chunks. For memory-backed registration,
    the stack-supplied `n_chunks` determines how many chunks are read.
  - `NodeType::Join` reads `lhs_digest || rhs_digest`.
  - `NodeType::PairList` accepts one or more `lhs_digest || rhs_digest` chunks. Precompiles that
    encode a pair count in tag arguments must check the actual payload length during evaluation.
- `log_deferred` stack effect: `[_, STMNT, _, ...] -> [ROOT_NEW, OUT_RATE1, OUT_CAP, ...]` where
  `STMNT` occupies stack offsets `4..8`. Wrappers usually drop the three output words after the root
  transition has been constrained.
- Input and memory layouts are precompile-specific. Core-library wrappers define the native formats
  for hash facades and for arithmetic/curve support used by signature verification.

## Examples

- Hash support wrappers register the input/result nodes needed for the hash claim and log a
  statement digest that verifies the claimed digest.
- Signature support wrappers register the public key, precompile-specific message input, signature,
  and verification predicate nodes, then log the predicate statement.


## Related reading

- [Deferred computation](../deferred/index.md) – deferred DAG model and final/partial proof shapes.
- [`log_deferred` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour
  and opcode semantics.
- `DeferredStateWire` implementation (`core/src/deferred/wire.rs`) – partial-proof deferred witness
  details.
