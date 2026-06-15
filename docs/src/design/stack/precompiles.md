# Precompiles

Precompiles let Miden programs defer expensive computations to the host while still producing
auditable evidence inside the STARK. This page describes how the VM, host, prover, and verifier
coordinate to maintain a sequential commitment to every precompile invocation.

## Core data

| Concept | Description |
| ------- | ----------- |
| `PrecompileRequest` | Minimal calldata for a precompile, recorded by the host when the event handler runs. It contains exactly the information needed to deterministically recompute the result and the commitment. Requests are included in the proof artifact. |
| `PrecompileCommitment` | A word pair `(TAG, COMM)` computed by the MASM wrapper, and deterministically recomputable from the corresponding `PrecompileRequest`. `COMM` typically commits to inputs, and may also include outputs for long results; the three free elements in `TAG` carry metadata and/or simple results. Together `(TAG, COMM)` represent the full request (inputs + outputs). |
| `PrecompileTranscript` | A linear hash tree over the native VM hash that produces a rolling digest of every precompile request: `state' = hash(state, STMNT)`. The state is itself a complete digest at every step, so no separate finalization step is required. The verifier reconstructs the same transcript by re-evaluating each request and recording its commitment. |

## Lifecycle overview

1. **Wrapper emits event** – The MASM wrapper stages inputs (e.g., on stack/memory) and emits the event for the target precompile.
2. **Host handler runs** – The host executes the event handler, reads required inputs from the current process state, stores a `PrecompileRequest` (raw calldata) for later verification, and pushes the precompile result to the VM via the advice stack.
3. **Wrapper constructs commitment** – The wrapper pops result(s) from advice, computes `(TAG, COMM)` per the precompile’s convention, and prepares to log the operation.
4. **`sys::log_precompile_request` folds the commitment into the transcript** – The wrapper calls the helper with `[COMM, TAG, ...]` on top of the stack. The helper:
   - Computes the per-call statement word `STMNT = hmerge(COMM, TAG)`.
   - Seats `STMNT` at stack[4..8] (the second BCOMPRESS block word) by pushing one zero word above it, then invokes the `log_precompile` opcode, which folds `STMNT` into the rolling transcript state. `STATE_PREV` is supplied non-deterministically via helper registers.
   - Drops the three output words `[STATE_NEW, OUT_RATE1, OUT_CAP]` so they are not visible to the caller.
5. **Transcript-state tracking via vtable** – The transcript state is tracked inside the VM via the chiplets’ virtual table; the host never tracks it. The table always stores the current state. On each `log_precompile`:
   - The previous state is removed from the table.
   - The compression step links `STATE_PREV --[STMNT]--> STATE_NEW`.
   - The next state is inserted back into the table.
   This enforces that updates can only occur through the native hash compression step.
6. **Trace output and proof** – The transcript state is used to construct the vtable auxiliary column, while the prover stores only the ordered `PrecompileRequest`s in the proof.
7. **Verifier reconstruction** – The verifier replays each request via a `PrecompileVerifier` to recompute `(TAG, COMM)`, records them into a fresh transcript, and enforces the initial/final state via public inputs. To check correct linking, the verifier initializes the column with an initial insertion of the empty state and a removal of the final state; the final state is provided as a public input to the AIR.
8. **No separate finalization step** – Because the fold is a 2‑to‑1 hash (`merge(state, STMNT)`), the state is itself a complete digest at every step. The transcript digest is just the final state.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes `log_precompile`, maintains the rolling transcript state internally, and participates in state initialization via the chiplets’ virtual table. |
| Host | Executes the event handler, reads inputs from process state, stores `PrecompileRequest`, and returns the result via the advice provider (typically the advice stack; map/Merkle store as needed). |
| MASM wrapper | Collects inputs and emits the event; pops results from advice; computes `(TAG, COMM)`; calls `sys::log_precompile_request`. |
| Prover | Includes the precompile requests in the proof. |
| Verifier | Replays requests via registered verifiers, rebuilds the transcript, and enforces the initial/final state via variable‑length public inputs. The final state is itself the transcript digest — no extra finalization step is needed. |

## Conventions

- Tag layout: `TAG = [event_id, meta1, meta2, meta3]`.
  - First element is the precompile’s `event_id`.
  - The remaining three elements carry metadata or simple results:
    - Examples: byte length of inputs; boolean validity of a signature; flag bits.
- Commitment layout: `COMM`
  - Typically commits to inputs.
  - May also include outputs when results are long, so that `(TAG, COMM)` together represent the full request (inputs + outputs).
  - The exact composition is precompile‑specific and defined by its verifier specification.
- `log_precompile` stack effect: `[_, STMNT, _, ...] -> [STATE_NEW, OUT_RATE1, OUT_CAP, ...]`
  where `BCOMPRESS` updates the transcript chaining word from `STATE_PREV` and `STMNT`.
  `STATE_PREV` is supplied non-deterministically via the user op helper registers. `STMNT`
  lives at stack[4..8] so its bus message lanes share with BCOMPRESS's second block word.
- `sys::log_precompile_request` stack effect: `[COMM, TAG, ...] -> [...]`. The helper computes
  `STMNT = hmerge(COMM, TAG)` and folds it into the transcript via `log_precompile`.

- Input encoding:
  - By convention, inputs are encoded as packed u32 values in field elements (4 bytes per element, little‑endian). If the input length is not a multiple of 4, the final u32 is zero‑padded. Because of this packing, wrappers commonly include the byte length in `TAG` to distinguish data bytes from padding.

## Examples

- Hash function
  - Inputs: byte sequence at a given memory location; Output: digest (long).
  - Wrapper emits the event; handler reads memory and returns digest via advice; wrapper computes:
    - `TAG = [event_id, len_bytes, 0, 0]`
    - `COMM = hash(hash(input_words), hash(digest_words))` (bind input and digest)
  - Wrapper calls `sys::log_precompile_request` with `[COMM, TAG, ...]` to fold the commitment into the transcript.

- Signature scheme
  - Inputs: public key, message (or prehash), signature; may include flag bits indicating special operation options. Output: `is_valid` (boolean).
  - Wrapper emits the event; handler verifies and may push auxiliary results; wrapper computes:
    - `TAG = [event_id, is_valid, flags, 0]` (encode simple result and flags)
    - `COMM = hash(prepared_inputs[..])` (inputs-only is typical when outputs are simple)
  - Wrapper calls `sys::log_precompile_request` to fold the request commitment and result tag into the transcript.

## Related reading

- [`log_precompile` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour and semantics.
- `PrecompileTranscript` implementation (`core/src/precompile.rs`) – transcript details in the codebase.
- Kernel ROM chiplet initialization pattern (`../chiplets/kernel_rom.md`) – example use of variable‑length public inputs to initialize a chiplet/aux column via the bus.
