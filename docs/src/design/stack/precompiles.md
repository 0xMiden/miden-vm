# Precompiles

Precompiles let Miden programs defer expensive computations to the host while still producing
auditable evidence inside the STARK. This page describes how the VM, host, prover, and verifier
coordinate to maintain a sequential commitment to every precompile invocation.

## Core data

| Concept | Description |
| ------- | ----------- |
| `PrecompileRequest` | Minimal calldata for a precompile, recorded by the host when the event handler runs. It contains exactly the information needed to deterministically recompute the result and the commitment. Requests are included in the proof artifact. |
| `PrecompileCommitment` | A triple `(TAG, COMM_0, COMM_1)` computed by the MASM wrapper, deterministically recomputable from the corresponding `PrecompileRequest`. `COMM_0` and `COMM_1` together commit to the calldata (and any output that needs binding); the three free elements in `TAG` carry metadata and/or simple results. |
| `STMNT` | The per-call statement word `STMNT = Permute(COMM_0, COMM_1, TAG).rate0`, where `TAG` enters the Poseidon2 sponge as initial capacity (acting as a domain separator). The transcript folds this single word into its rolling state. |
| `PrecompileTranscript` | A linear hash tree over Poseidon2: `state' = Permute(state, STMNT, ZERO).rate0`. The state is itself a complete digest at every step. The verifier reconstructs the same transcript by re‑evaluating requests, deriving each `STMNT`, and folding it into a fresh transcript. |

## Lifecycle overview

1. **Wrapper emits event** – The MASM wrapper stages inputs (e.g., on stack/memory) and emits the event for the target precompile.
2. **Host handler runs** – The host executes the event handler, reads required inputs from the current process state, stores a `PrecompileRequest` (raw calldata) for later verification, and pushes the precompile result to the VM via the advice stack.
3. **Wrapper constructs statement** – The wrapper pops result(s) from advice, computes the commitment halves `(COMM_0, COMM_1)` and the per-call `TAG`, then derives `STMNT = Permute(COMM_0, COMM_1, TAG).rate0` via a single `hperm`.
4. **`log_precompile` records the statement** – The wrapper invokes `log_precompile` with `[PAD, PAD, STMNT, ...]`. The instruction:
   - Reads the previous transcript state `STATE_PREV` (non‑deterministically, via helper registers).
   - Applies the Poseidon2 permutation to `[STATE_PREV, STMNT, ZERO]`, producing `[STATE_NEW, OUT_RATE1, OUT_CAP]`, with `STATE_NEW = output rate0`.
   - Writes the hasher output back via the identity lane→slot mapping: `STATE_NEW` lands at `stack[0..4]`, the unused rate1 and capacity halves at `stack[4..8]` and `stack[8..12]` respectively, so every column referenced by the chiplet bus message has a defined value.
5. **State tracking via vtable** – The transcript state is tracked inside the VM via the chiplets' virtual table; the host never tracks it. The table always stores the current rolling state. On each `log_precompile`:
   - The previous state is removed from the table.
   - The permutation links `STATE_PREV --[STMNT]--> STATE_NEW`.
   - The next state is inserted back into the table.
   This enforces that updates can only occur by applying the permutation.
6. **Trace output and proof** – The transcript state is used to construct the vtable auxiliary column, while the prover stores only the ordered `PrecompileRequest`s in the proof.
7. **Verifier reconstruction** – The verifier replays each request via a `PrecompileVerifier` to recompute `(TAG, COMM_0, COMM_1)`, derives `STMNT` and folds each into a fresh transcript, and enforces the initial (zero) and final state via public inputs. To check correct linking, the verifier initialises the column with an insertion of the empty state and a removal of the final state; the final state is provided as a public input to the AIR.
8. **No finalization** – Because each fold uses a 2-to-1 hash whose `rate0` output is itself the next state, the transcript state is a complete digest at every step. There is no separate finalization permutation.

## Responsibilities

| Participant | Responsibilities |
| ----------- | ---------------- |
| VM | Executes `log_precompile`, maintains the transcript-state word internally, and participates in transcript-state initialisation via the chiplets' virtual table. |
| Host | Executes the event handler, reads inputs from process state, stores `PrecompileRequest`, and returns the result via the advice provider (typically the advice stack; map/Merkle store as needed). |
| MASM wrapper | Collects inputs and emits the event; pops results from advice; computes `(TAG, COMM_0, COMM_1)`; derives `STMNT = Permute(COMM_0, COMM_1, TAG).rate0` via `hperm`; invokes `log_precompile`. |
| Prover | Includes the precompile requests in the proof. |
| Verifier | Replays requests via registered verifiers, rebuilds the transcript, and enforces the initial/final state via variable‑length public inputs. The state is its own digest. |

## Conventions

- Tag layout: `TAG = [event_id, meta1, meta2, meta3]`.
  - First element is the precompile's `event_id`.
  - The remaining three elements carry metadata or simple results:
    - Examples: byte length of inputs; boolean validity of a signature; flag bits.
- Commitment halves: `COMM_0`, `COMM_1` each a 4-element word.
  - Together they commit to the calldata; their composition is precompile-specific and defined by the verifier specification.
  - Typical pattern for hashes: `COMM_0 = Poseidon2(input_words)`, `COMM_1 = Poseidon2(digest_words)`.
  - Typical pattern for signatures: `COMM_0 = Poseidon2(Poseidon2(pk) || Poseidon2(msg_or_digest))`, `COMM_1 = Poseidon2(sig)`.
- Statement: `STMNT = Permute(COMM_0, COMM_1, TAG).rate0`.
- `log_precompile` stack effect: `[JUNK, JUNK, STMNT, ...] -> [STATE_NEW, RATE1_OUT, CAP_OUT, ...]`
  with `Permute(STATE_PREV, STMNT, ZERO) = [STATE_NEW, RATE1_OUT, CAP_OUT]` and the identity
  lane→slot mapping for the output (matching HPERM). The upper two stack words on input are
  unconstrained.

- Input encoding:
  - By convention, inputs are encoded as packed u32 values in field elements (4 bytes per element, little‑endian). If the input length is not a multiple of 4, the final u32 is zero‑padded. Because of this packing, wrappers commonly include the byte length in `TAG` to distinguish data bytes from padding.

## Examples

- Hash function
  - Inputs: byte sequence at a given memory location; Output: digest (long).
  - Wrapper emits the event; handler reads memory and returns digest via advice; wrapper computes:
    - `TAG    = [event_id, len_bytes, 0, 0]`
    - `COMM_0 = Poseidon2(input_words)`
    - `COMM_1 = Poseidon2(digest_words)`
  - Wrapper places `[COMM_0, COMM_1, TAG, ...]` on the stack, runs `hperm` to derive
    `STMNT = output_rate0`, drops the unused output halves, and calls
    `sys::log_precompile_request` (which pads two zero words below `STMNT` and invokes
    `log_precompile`).

- Signature scheme
  - Inputs: public key, message (or prehash), signature; may include flag bits indicating special operation options. Output: `is_valid` (boolean).
  - Wrapper emits the event; handler verifies and may push auxiliary results; wrapper computes:
    - `TAG    = [event_id, is_valid, flags, 0]`
    - `COMM_0 = Poseidon2(Poseidon2(pk) || Poseidon2(msg_or_digest))`
    - `COMM_1 = Poseidon2(sig)`
  - Wrapper derives `STMNT` via `hperm` and calls `sys::log_precompile_request`.

## Related reading

- [`log_precompile` instruction](../../user_docs/assembly/instruction_reference.md) – stack behaviour and semantics.
- `PrecompileTranscript` implementation (`core/src/precompile.rs`) – transcript details in the codebase.
- Kernel ROM chiplet initialization pattern (`../chiplets/kernel_rom.md`) – example use of variable‑length public inputs to initialize a chiplet/aux column via the bus.
