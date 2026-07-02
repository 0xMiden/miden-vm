# Precompiles

Precompiles let Miden programs defer expensive computations to host-side implementations while
still binding the claimed result into the VM proof. The current proof-bound model is the
content-addressed deferred DAG described in [Deferred computation](../deferred/index.md): programs
register deferred nodes, log statement digests that evaluate to `TRUE`, proofs carry
`DeferredStateWire`, and verifiers rehydrate that wire under a supplied `PrecompileRegistry`.

Concrete proof-bound implementations live in the `miden-precompiles` crate. Their MASM support
modules are currently internal implementation detail used by core-library facades and tests.

## Current data model

| Concept | Description |
| ------- | ----------- |
| `Tag` | A 4-felt node constructor. Framework ids `0`, `1`, and `2` are reserved for `TRUE`, semantic `AND`, and opaque framework `CHUNKS`; precompile ids are derived from precompile names and interpret the remaining three `args` felts locally. |
| `Node` | A content-addressed `(tag, payload)` term in the deferred DAG. Payloads are data chunks, join child digests, pair lists of `lhs_digest || rhs_digest` chunks, or the framework `TRUE` sentinel. |
| `Precompile` | A host implementation that owns one precompile id, decodes the structural shape for its tags, evaluates nodes to canonical form, and optionally contributes canonical constants through `init()`. |
| `PrecompileRegistry` | The verifier/host dispatcher for trusted precompile implementations. Verification must use the registry that corresponds to the proof-bound precompile set being accepted. |
| `DeferredState` | The host-side DAG witness accumulated during execution. It tracks registered nodes, evaluates them under the registry, and maintains the rolling deferred root. |
| `DeferredStateWire` | The canonical proof-carried wire format for the root-reachable deferred DAG. It is passive data until rehydrated and validated with `DeferredState::from_wire`. |
| Deferred root | A single digest public value. Each logged statement appends `Node::AND(previous_root, statement_digest)` and advances the root to that node digest. |

## Lifecycle overview

1. **Wrapper registers nodes** – Internal MASM support code stages node payloads on the operand
   stack or in memory and emits `adv.register_deferred` / `adv.register_deferred_data`.
   Registration stores the node in host-side `DeferredState`, checks structural child closure, and
   evaluates the node immediately under the installed registry.
2. **Wrapper binds digests in-circuit** – The wrapper computes any proof-relevant node digest from the
   same stack or memory data visible to the circuit. A digest supplied only by advice is not a sound
   proof binding.
3. **Wrapper evaluates only through explicit predicates** – When a wrapper uses
   `adv.evaluate_deferred*` to obtain host-computed canonical data, it must re-bind that advice output
   to circuit-visible data and log a statement digest that the verifier can re-evaluate.
4. **`log_deferred` folds a statement** – The opcode expects `STMNT` at stack offsets `4..8`.
   `STMNT` must already be registered in `DeferredState` and evaluate to `TRUE`. The constrained
   Poseidon2 permutation computes `ROOT_NEW = rate0(Poseidon2([ROOT_PREV, STMNT, Tag::AND]))`, and
   host-side deferred state records the corresponding `AND` node.
5. **Prover serializes the wire** – The prover serializes `trace.deferred_state().to_wire()` into
   `ExecutionProof` and uses the final deferred root as the STARK public input.
6. **Verifier rehydrates and checks** – The verifier decodes `DeferredStateWire` with the caller's
   `PrecompileRegistry`, rejects non-canonical or semantically false wires, compares the rehydrated
   root to the public deferred root, and then verifies the STARK proof.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes deferred advice events and `log_deferred`, maintains the rolling deferred root, and exposes the final root as a public value. |
| Host / advice provider | Maintains `DeferredState`, runs trusted precompile implementations, and supplies evaluation advice when wrappers request it. |
| MASM wrapper | Registers concrete deferred nodes, computes node/statement digests from circuit-visible data, logs only registered statements that should evaluate to `TRUE`, and hides helper outputs from callers when appropriate. |
| Prover | Includes the canonical `DeferredStateWire` in `ExecutionProof`. |
| Verifier | Rehydrates `DeferredStateWire` under a supplied `PrecompileRegistry`, checks the final deferred root, and verifies the STARK proof. |

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
- Input and memory layouts are precompile-specific. The `miden-precompiles` wrappers define the
  native formats for hash, arithmetic, curve, and signature precompiles.

## Examples

- Hash support wrappers register the input/result nodes needed for the hash claim and log a
  statement digest that verifies the claimed digest.
- Signature support wrappers register the public key, message or prehash, signature, and
  verification predicate nodes, then log the predicate statement.


## Related reading

- [Deferred computation](../deferred/index.md) – deferred DAG model, `DeferredStateWire`, and verification.
- [`log_deferred` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour
  and opcode semantics.
- `DeferredStateWire` implementation (`core/src/deferred/wire.rs`) – proof-carried deferred witness
  details.
