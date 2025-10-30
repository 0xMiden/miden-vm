# Precompiles

Precompiles let Miden programs defer expensive computations to the host while still producing
auditable evidence inside the STARK. This page describes how the VM, host, prover, and verifier
coordinate to maintain a sequential commitment to every precompile invocation.

## Core data

| Concept | Description |
| ------- | ----------- |
| `PrecompileRequest` | Minimal calldata for a precompile, recorded by the host when the event handler runs. It contains exactly the information needed to deterministically recompute the result and the commitment. Requests are included in the proof artifact. |
| `PrecompileCommitment` | A word pair `(TAG, COMM)` computed by the MASM wrapper, and deterministically recomputable from the corresponding `PrecompileRequest`. `COMM` typically commits to inputs, and may also include outputs for long results; the three free elements in `TAG` carry metadata and/or simple results. Together `(TAG, COMM)` represent the full request (inputs + outputs). |
| `PrecompileTranscript` | A sequential commitment to all precompile requests. Implemented with an RPO256 sponge; the VM stores only the capacity (4 elements). The verifier reconstructs the same transcript by re‑evaluating requests and their commitments. Finalizing yields a transcript digest. |

## Lifecycle overview

1. **Wrapper emits event** – The MASM wrapper stages inputs (e.g., on stack/memory) and emits the event for the target precompile.
2. **Host handler runs** – The host executes the event handler, reads required inputs from the current process state, stores a `PrecompileRequest` (raw calldata) for later verification, and pushes the precompile result to the VM via the advice stack.
3. **Wrapper constructs commitment** – The wrapper pops result(s) from advice, computes `(TAG, COMM)` per the precompile’s convention, and prepares to log the operation.
4. **`log_precompile` records the commitment** – The wrapper invokes `log_precompile` with `[COMM, TAG, PAD, ...]`. The instruction:
   - Reads the previous transcript capacity `CAP_PREV` (non‑deterministically via helper registers).
   - Applies the RPO permutation to `[CAP_PREV, TAG, COMM]`, producing `[CAP_NEXT, R0, R1]`.
   - Writes `[R1, R0, CAP_NEXT]` back onto the stack; programs typically drop these words immediately.
5. **Capacity tracking via vtable** – Capacity is tracked inside the VM via the chiplets’ virtual table; the host never tracks capacity. The table always stores the current capacity (the transcript state). On each `log_precompile`:
   - The previous capacity is removed from the table.
   - The permutation links `CAP_PREV --[TAG,COMM]--> CAP_NEXT`.
   - The next capacity is inserted back into the table.
   This enforces that updates can only occur by applying the permutation.
6. **Trace output and proof** – The capacity state is used to construct the vtable auxiliary column, while the prover stores only the ordered `PrecompileRequest`s in the proof.
7. **Verifier reconstruction** – The verifier replays each request via a `PrecompileVerifier` to recompute `(TAG, COMM)`, records them into a fresh transcript, and enforces the initial/final capacity via public inputs. To check correct linking, the verifier initializes the column with an initial insertion of the empty capacity and a removal of the final capacity; the final capacity is provided as a public input to the AIR.
8. **Finalization convention** – When a digest is needed, finalize the transcript by absorbing two empty words (zeros in the rate) and permuting once. The transcript digests the ordered sequence of `[TAG, COMM]` words for all requests; `log_precompile` discards rate outputs (`R0`, `R1`), so only the capacity persists.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes `log_precompile`, maintains the capacity word internally, and participates in capacity initialization via the chiplets’ virtual table. |
| Host | Executes the event handler, reads inputs from process state, stores `PrecompileRequest`, and returns the result via the advice provider (typically the advice stack; map/Merkle store as needed). |
| MASM wrapper | Collects inputs and emits the event; pops results from advice; computes `(TAG, COMM)`; invokes `log_precompile`. |
| Prover | Includes the precompile requests in the proof. |
| Verifier | Replays requests via registered verifiers, rebuilds the transcript, enforces the initial/final capacity via variable‑length public inputs, and finalizes to a digest if needed. |

## Conventions

- Tag layout: `TAG = [event_id, meta1, meta2, meta3]`.
  - First element is the precompile’s `event_id`.
  - The remaining three elements carry metadata or simple results:
    - Examples: byte length of inputs; boolean validity of a signature; flag bits.
- Commitment layout: `COMM`
  - Typically commits to inputs.
  - May also include outputs when results are long, so that `(TAG, COMM)` together represent the full request (inputs + outputs).
  - The exact composition is precompile‑specific and defined by its verifier specification.
- `log_precompile` stack effect: `[COMM, TAG, PAD, ...] -> [R1, R0, CAP_NEXT, ...]` where
  `RPO([CAP_PREV, TAG, COMM]) = [CAP_NEXT, R0, R1]`.

- Input encoding:
  - By convention, inputs are encoded as packed u32 values in field elements (4 bytes per element, little‑endian). If the input length is not a multiple of 4, the final u32 is zero‑padded. Because of this packing, wrappers commonly include the byte length in `TAG` to distinguish data bytes from padding.

## Examples

- Hash function
  - Inputs: byte sequence at a given memory location; Output: digest (long).
  - Wrapper emits the event; handler reads memory and returns digest via advice; wrapper computes:
    - `TAG = [event_id, len_bytes, 0, 0]`
    - `COMM = Rpo256( Rpo256(input_words) || Rpo256(digest_words) )` (bind input and digest)
  - Wrapper calls `log_precompile` with `[COMM, TAG, PAD, ...]` and drops the outputs.

- Signature scheme
  - Inputs: public key, message (or prehash), signature; may include flag bits indicating special operation options. Output: `is_valid` (boolean).
  - Wrapper emits the event; handler verifies and may push auxiliary results; wrapper computes:
    - `TAG = [event_id, is_valid, flags, 0]` (encode simple result and flags)
    - `COMM = Rpo256( prepared_inputs[..] )` (inputs‑only is typical when outputs are simple)
  - Wrapper calls `log_precompile` to record the request commitment and result tag.

## Related reading

- [`log_precompile` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour and semantics.
- `PrecompileTranscript` implementation (`core/src/precompile.rs`) – transcript details in the codebase.
- Kernel ROM chiplet initialization pattern (`../chiplets/kernel_rom.md`) – example use of variable‑length public inputs to initialize a chiplet/aux column via the bus.
