# Precompile Flow

Precompiles let Miden programs defer expensive computations to the host while still producing
auditable evidence inside the STARK. This page describes how the VM, host, prover, and verifier
coordinate to maintain a sequential commitment to every precompile invocation.

## Core data

| Concept | Description |
| ------- | ----------- |
| `PrecompileRequest` | The raw calldata for a precompile invocation. Requests are stored by the host and included in the proof artifact. |
| `PrecompileCommitment` | A word pair `(TAG, COMM)` emitted by the host-side precompile handler. `COMM` is the RPO hash commitment to the request’s calldata (or other handler-specific witness). The tag encodes the precompile identifier and optional metadata. |
| `PrecompileSponge` | An RPO256 sponge that aggregates all commitments. The VM stores only the 4-element capacity word; the verifier reconstructs the same sponge from the recorded requests. |

## Lifecycle overview

1. **Handler emits advice** – When a MASM wrapper invokes a precompile, the host handler:
   - Computes the raw calldata, stores it as a `PrecompileRequest`, and exposes the request via advice.
   - Recomputes the matching `PrecompileCommitment` and provides `(TAG, COMM)` so the program can log the operation.
2. **`log_precompile` absorbs the commitment** – The wrapper (or any caller) invokes the `log_precompile` instruction with the tag and `COMM` (the calldata commitment). The instruction:
   - Reads the previous capacity `CAP_PREV` from helper registers (supplied non-deterministically).
   - Applies the RPO permutation to `[CAP_PREV, TAG, COMM]`, producing `[CAP_NEXT, R0, R1]`.
   - Writes `[R1, R0, CAP_NEXT]` back onto the stack; programs typically drop these words immediately.
3. **Virtual table initialization** – Capacity tracking is wired via the chiplets’ virtual table. The verifier initializes the auxiliary column with variable‑length public inputs (similar to the kernel ROM chiplet) so that the column includes the initial and final sponge capacities for the execution.
4. **Trace output** – Execution records each `PrecompileRequest` and carries the current capacity forward. The VM never finalizes the sponge; it only retains the capacity between absorptions.
5. **Prover packaging** – The prover includes the list of precompile requests in the proof. The final capacity is not a serialized public input today; it is used by the verifier to initialize/enforce the boundary constraint of the auxiliary column via variable‑length public inputs.
6. **Verifier reconstruction** – Given the requests:
   - The verifier replays each request through the appropriate `PrecompileVerifier` to recompute each commitment.
   - Starting from an empty sponge (`PrecompileSponge::new()`), the verifier absorbs each commitment in order, reconstructing the same capacity sequence as the VM.
   - The final capacity is enforced at the auxiliary column boundary via variable‑length public inputs.
7. **Sponge finalization convention** – By convention, external consumers who need a digest finalize the sponge by absorbing two empty words (zeros in the rate) and permuting once more. We follow this pattern because `log_precompile` discards the rate outputs (`R0`, `R1`), leaving only the capacity available to subsequent steps.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes `log_precompile`, maintains the capacity word internally, and participates in capacity initialization via the chiplets’ virtual table. |
| Host / MASM wrapper | Provides advice containing raw calldata, recomputes `(TAG, COMM)`, and invokes `log_precompile`. |
| Prover | Includes the precompile requests in the proof. |
| Verifier | Replays requests into registered verifiers, rebuilds the sponge, optionally finalizes it (absorbing two zero words), and enforces the initial/final capacity via variable‑length public inputs. |

## Related reading

- [`log_precompile` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour and semantics.
- `PrecompileSponge` implementation (`core/src/precompile.rs`) – sponge details in the codebase.
- Kernel ROM chiplet initialization pattern (`../chiplets/kernel_rom.md`) – example use of variable‑length public inputs to initialize a chiplet/aux column via the bus.

Note: Winterfell currently does not verify the precompile sponge capacity as a public input. The capacity is enforced indirectly via variable‑length public inputs that initialize the auxiliary column, and the external verification API returns the reconstructed commitment for consumers that need it.
