# Precompile VM: Miden-side Integration Notes

**Status:** exploratory first-draft spec (2026-04-14)
**Source discussion:** https://github.com/0xMiden/miden-vm/discussions/3005 (comment 1 = AIR spec)
**Branch context:** `adr1anh/bus` (on top of `next`)
**Goal:** produce a first-draft of a spec describing the Miden-VM-side changes required to support a Precompile VM ("PVM") whose input is a transcript — a binary tree of RPO commitments to field/group/Keccak computations. After stabilization, a condensed version will be posted as a new comment on the discussion; each major deliverable will be turned into a tracking issue.

This file is a running scratchpad; sections 1–3 are background, §4 is the proposed changes, §5–7 are loose ends and planning.

> **Scope note: Miden VM vs PVM are two separate STARK systems.** The PVM is a distinct VM with its own AIR, its own hash chip, its own bus relations. Miden's hasher chiplet is part of Miden's AIR and proves RPO permutations that occur during Miden execution; the PVM's hash chip is a separate piece of circuitry in a separate STARK proof. The two chips share the same *underlying permutation* (RPO), but their bus wiring, provider/consumer roles, and surrounding constraints are independent. In this document, "Miden's hasher chiplet" always means the one at `air/src/constraints/chiplets/hasher*`; "the PVM's hash chip" means comment 1 §8.1's permutation chip in the separate PVM AIR. No constraint code is directly shared between them — what we reuse is the permutation round structure (because it's the same math) and the state-layout *convention*.
>
> **Important amendment to the published PVM spec.** The AIR spec posted as comment 1 of the discussion describes the node preimage with `[tag, param_a, param_b, version]` at state positions **0..3** (labeled "capacity") and `val[8]` at positions **4..11** ("rate"), with the hash output extracted from positions **0..3** post-permutation. This ordering does not match Miden's native `hperm` layout, which is `[RATE0(4), RATE1(4), CAPACITY(4)]` (rate at state[0..8], capacity at state[8..12]) with digest at state[0..4] post-permutation (Miden's `DIGEST_RANGE`, i.e., `RATE0'`). **This file uses the Miden-native layout throughout.** The benefits are: (a) Miden's `log_precompile` opcode can call Miden's existing hasher chiplet with no state reshuffling; (b) MASM hash primitives can call `hperm` without juggling felts; (c) the PVM AIR's hash chip implementation can copy the Poseidon2 round-constraint structure from Miden's hasher chiplet because both use the same state-position convention, even though they remain separate chip instances. A companion amendment will be proposed to the PVM AIR spec. Since RPO is just a deterministic permutation, this is a pure relabeling of which state positions play which role — the cryptographic strength is unchanged, only the byte-for-byte digests differ.

---

## 1. What the PVM expects (recap from discussion #3005, comment 1 — with Miden-native layout amendment)

The PVM is specified as an AIR for an **eval chip** that recursively resolves commitment hashes into typed values, dispatching to auxiliary chips for arithmetic, group operations, Keccak hashing, and chunk management.

- **Hash function:** RPO / Poseidon2, permutation width **12**, rate **8**, capacity **4**. Miden's native sponge layout is `[RATE0(4), RATE1(4), CAPACITY(4)]`, and the standard digest is extracted from `state[0..4]` after permutation.

- **Node preimage layout (12 felts, Miden-native):**

  ```
  state index:  0 ............ 7        8        9        10       11
                val[8]                   tag_id   param_a  param_b  version
                ── rate ──               ──────── capacity ────────────────
  ```

  `val[8]` occupies `state[0..8]` (the two rate words), `[tag_id, param_a, param_b, version]` occupies `state[8..12]` (the capacity word). This is the **inverse** of the ordering in the published PVM comment; see the amendment note above.

- **`version` (state index 11)** is a fixed constant `CURRENT_VERSION` enforced by the eval chip. Any node with the wrong version is rejected. This is how we upgrade the spec safely.

- **Node hash:** `RPO(preimage)[0..4]` — extracted from `state[0..4]` after one permutation. This matches Miden's `DIGEST_RANGE` convention: the digest is the first rate word post-permutation (`RATE0'`).

- **Tag enumeration:**

  | `tag_id` | `param_a`  | `param_b` | Name | `val[8]` contents |
  |---|---|---|---|---|
  | 0 | 0          | 0         | Transcript        | `lhs_hash[4] ‖ rhs_hash[4]` (prev prefix, assertion) |
  | 1 | 0          | 0         | Chunk (IV only)   | — (never a node; used only as chunk-sponge IV) |
  | 2 | `field_ty` | 0         | FieldLeaf         | u32-LE encoding of the field element |
  | 3 | 0          | 0         | KeccakDigestLeaf  | u32-LE encoding of the 32-byte digest |
  | 4 | `field_ty` | `op`(0..3)| FieldBinOp        | `lhs_hash ‖ rhs_hash` |
  | 5 | `group_ty` | 0         | GroupCreate       | `x_hash ‖ y_hash` |
  | 6 | `group_ty` | `op`(0..2)| GroupBinOp        | `lhs_hash ‖ rhs_hash` |
  | 7 | `len_bytes`| 0         | Keccak            | `digest_hash ‖ chunks_hash` |

- **`ZERO_HASH = [0,0,0,0]`** is the trivial base case and evaluates to `True` (it's how a transcript chain terminates).

- The chunk sponge (tag 1) is the **only** PVM construct that still uses sponge-style absorption. Its capacity IV (stored at `state[8..12]` in Miden-native layout) is `[1, 0, 0, CURRENT_VERSION]` — tag 1 at capacity[0] acts as the domain separator, and `CURRENT_VERSION` sits at capacity[3] = state[11] to match the node-preimage convention.

### 1.1 What the Miden VM actually has to produce

The PVM takes as input:
1. **A single 4-felt transcript root** — committed as a Miden public output.
2. **A `PrecompileRequest`-shaped blob** containing the expression DAG (nodes keyed by commitment hash) and the chunk store, from which the PVM can reconstruct the entire transcript tree and its witness tables. This is passed out-of-band alongside the STARK proof (today it already is, just with a different shape).

So the Miden-VM-side work breaks into two orthogonal things:
- **Compute the transcript root as a public output.** That means: the `log_precompile`-equivalent opcode has to do a single RPO hash with Miden-native state layout `state[0..8] = val[8]`, `state[8..12] = [tag, pa, pb, version]`, and thread the root through a processor-state slot just like today.
- **Collect the DAG on the host side.** That means: event handlers that, over the course of execution, accumulate field/group/Keccak nodes into a DAG data structure that becomes the serialized PVM input.

Everything else (version bump, MASM primitives, keccak encoding) is plumbing.

---

## 2. Summary of current state (evidence-based, see §3 for full detail)

### 2.1 Existing precompile infrastructure

The Miden VM already has a fully working **sponge-based** precompile transcript system. The architecture is very close to what the PVM needs — the delta is mostly in the **shape of the hash** (sponge → one-shot tree node) and in **what the host accumulates** (opaque `Vec<u8>` calldata → typed DAG).

Key components that already exist, in order of flow:

| Layer | Type / symbol | File |
|---|---|---|
| Opcode | `Operation::LogPrecompile` (`0b0101_1110`) | `core/src/operations/mod.rs:122, 598-600` |
| Handler | `op_log_precompile` | `processor/src/execution/operations/crypto_ops/mod.rs:462-508` |
| Processor state | `System.pc_transcript_state: Word` | `processor/src/trace/parallel/processor.rs:434-439` |
| Host-side request | `PrecompileRequest { event_id, calldata: Vec<u8> }` | `core/src/precompile.rs:72-121` |
| Host-side sponge type | `PrecompileTranscript { state: Word }` | `core/src/precompile.rs:332-390` |
| Host commitment type | `PrecompileCommitment { tag, comm }` | `core/src/precompile.rs:152-195` |
| Verifier trait | `PrecompileVerifier` + registry | `core/src/precompile.rs:200-283` |
| Event-handler trait | `trait EventHandler` | `processor/src/host/handlers.rs:24-26` |
| Advice mutation variant | `AdviceMutation::ExtendPrecompileRequests` | `processor/src/host/mod.rs:34-55` |
| Advice provider storage | `AdviceProvider.pc_requests` | `processor/src/host/advice/mod.rs:52-57, 479-481` |
| Execution output | `ExecutionOutput.final_precompile_transcript` | `processor/src/fast/mod.rs:633-638` |
| Trace inputs | `TraceBuildOutput.precompile_requests_digest` | `processor/src/trace/mod.rs:54-91` |
| Execution trace | `ExecutionTrace.precompile_requests`, `final_precompile_transcript` | `processor/src/trace/mod.rs:179-217` |
| Public input | `PublicInputs.pc_transcript_state` at `[36..40]` | `air/src/lib.rs:67, 77, 104-140` |
| Virtual-table bus | transcript add/remove pair for `pc_transcript_state` | `processor/src/trace/chiplets/aux_trace/virtual_table.rs:170-256` |
| Proof packaging | `ExecutionProof { proof, hash_fn, pc_requests }` | `core/src/proof.rs:20-45` |
| MASM wrapper | `pub proc log_precompile_request` | `crates/lib/core/asm/sys/mod.masm:38-49` |

### 2.2 Current `log_precompile` opcode semantics

Today:

```
stack before : [COMM, TAG, PAD, ...]
stack after  : [R0, R1, CAP_NEXT, ...]

let CAP_PREV = processor_state.pc_transcript_state       // from helper register
let state    = [RATE0 = COMM, RATE1 = TAG, CAP = CAP_PREV]  // state[0..8] ‖ state[8..12]
let (R0, R1, CAP_NEXT) = Poseidon2.permute(state)
processor_state.pc_transcript_state = CAP_NEXT
```

This is a **sponge absorb step**, not a one-shot hash. The transcript state is the 4-felt sponge capacity; COMM + TAG are the two rate words of one absorption. Reasonable absorption pattern: each call appends 8 felts of "assertion" to the transcript.

### 2.3 Current `PrecompileTranscript` (host side)

`core/src/precompile.rs:332-390`: exact same thing as the opcode, but host-side:

```rust
pub struct PrecompileTranscript { state: Word }

fn record(&mut self, commitment: PrecompileCommitment) {
    let mut state = [ZERO; 12];
    state[RATE0_RANGE] = commitment.comm;
    state[RATE1_RANGE] = commitment.tag;
    state[CAPACITY_RANGE] = self.state;
    Poseidon2::apply_permutation(&mut state);
    self.state = state[CAPACITY_RANGE];
}
```

The transcript also has a `finalize()` that does one final absorption with empty rate and squeezes from `DIGEST_RANGE = state[0..4]`.

### 2.4 Current MASM wrapper

```masm
pub proc log_precompile_request
    padw movdnw.2
    # => [COMM, TAG, PAD, ...]
    log_precompile
    # => [R1, R0, CAP_NEXT, ...]
    dropw dropw dropw
end
```

This simply adds a PAD word, invokes the op, and drops the three output words. Callers arrive with `[COMM, TAG, ...]` and leave with `[...]`. The new opcode (§4.2) keeps a wrapper with the same structure — `padw padw log_precompile dropw dropw` — but the two `padw`s sink the assertion from the top word to the third word (where the new opcode reads it), and the hasher bus output is reordered so that `new_root` lands at the third next-row word and two `dropw`s leave it on top. The new wrapper is 5 cycles (1 cheaper than today) and leaves the new transcript root on the stack for free.

### 2.5 Current Keccak precompile (not a chiplet)

**Keccak is NOT a chiplet today.** It's a precompile event handler in `crates/lib/core/src/handlers/keccak256.rs`, and the keccak-f[1600] permutation happens off-chip via `miden_crypto::hash::keccak::Keccak256`. The handler's contract:

- **Input:** `[ptr, len_bytes]` on the stack; input bytes packed in memory as u32-LE felts (4 bytes per felt).
- **Output:** 8-felt digest pushed to the advice stack (each felt is a u32-LE chunk of the 32-byte digest).
- **Side effect:** `PrecompileRequest { event_id: KECCAK, calldata: raw_bytes }` appended to `AdviceProvider.pc_requests`.
- **Commitment shape:** `(tag = [KECCAK, len_bytes, 0, 0], comm = Poseidon2(Poseidon2(input) ‖ Poseidon2(digest)))`.

That commitment is then pushed onto the sponge transcript via `log_precompile_request`.

**Encoding note:** the current keccak handler already uses **u32-LE packing** for both inputs and outputs, matching the PVM spec's `val[8]` format. That's a big win — the encoding stays, only the commitment shape changes.

### 2.6 Current MASM hash primitives

| Op | Cycles | Stack |
|---|---|---|
| `hperm` | 1 | `[R0, R1, C, ...] → [R0', R1', C', ...]` (12 felts in place) |
| `hash` | 19 | 1-word → 1-word Poseidon2 hash (macro over hperm) |
| `hmerge` | 16 | 2-word → 1-word Poseidon2 merge (macro over hperm) |

**Miden's state layout is `[RATE0(4), RATE1(4), CAP(4)]`**, state indices 0..8 = rate, 8..12 = capacity. The digest is `state[0..4]` after permutation. Stack `hperm` maps `stack[0..12]` directly to `state[0..12]`.

**Domain separation convention:** in Miden, domain separators go into the capacity word at `state[8..12]`. The existing hasher chiplet reserves `CAPACITY_DOMAIN_IDX = 9` (= `state[9]` = capacity[1]) as a 1-felt domain slot for current uses. Example in `crates/lib/core/asm/crypto/aead.masm:64-79` which increments `capacity[0]`.

**Critical observation for Miden-side integration (with the Miden-native layout amendment from §1):** the amended PVM preimage places `val[0..8]` at `state[0..8]` (rate) and `[tag, pa, pb, version]` at `state[8..12]` (capacity), with digest extracted from `state[0..4]` post-permutation — i.e., exactly Miden's `[RATE0, RATE1, CAPACITY]` convention with `DIGEST_RANGE = state[0..4]`. A MASM caller who has `val[0..8]` on the top of stack and pushes the 4-felt capacity word below with `push.VERSION.PB.PA.TAG movdnw.2` gets the correct layout for `hperm` with no further juggling. This means every PVM node hash that the Miden VM computes (either inside `log_precompile` via the hasher chiplet, or inside MASM via `hperm`) executes as a single native Poseidon2 permutation with zero state reshuffling. **This is a Miden-side optimization**; the PVM's own hash chip is a separate AIR implementation and receives no direct benefit beyond being able to copy the same Poseidon2 round structure.

**There is no existing stdlib helper** for "hash a 12-felt preimage with a specified capacity initialization and return the 4-felt digest in one shot." The minimal native-layout procedure is ~15 cycles:

```masm
# stack before: [val[0..8], ...]   (top = val[0], val[7] at stack[7])
push.VERSION.PB.PA.TAG              # 4 cycles; top word becomes [TAG, PA, PB, VERSION]
movdnw.2                            # 1 cycle; moves that word behind val[8]
# stack: [val[0..8], TAG, PA, PB, VERSION, ...] (stack[8..12] is the capacity)
hperm                               # 1 cycle
# stack: [digest(4), _(4), _(4), ...]
swapw dropw swapw dropw             # 9 cycles; keep top word, drop next two
# stack: [digest, ...]
```

### 2.7 Event handler mechanism

**`Operation::Emit` (`0b0001_1111`)**: reads an event ID from stack position 0 and dispatches to the host's `on_event`. System events (19 built-in, e.g. `MerkleNodeMerge`, `HashToMap`) are handled internally; user events go to registered `EventHandler`s.

Trait:
```rust
pub trait EventHandler: Send + Sync + 'static {
    fn on_event(&self, process: &ProcessorState)
        -> Result<Vec<AdviceMutation>, EventError>;
}
```

Handlers get `&self` and read-only `ProcessorState`. They return:
```rust
pub enum AdviceMutation {
    ExtendStack { values: Vec<Felt> },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { infos: Vec<InnerNodeInfo> },
    ExtendPrecompileRequests { data: Vec<PrecompileRequest> },
}
```

**`&self` means handlers cannot directly mutate their own state.** Custom mutable state requires either (a) interior mutability (`Arc<Mutex<T>>` in the handler struct) or (b) a new `AdviceMutation` variant or (c) a new trait method with `&mut self`. Option (a) is the easiest and doesn't require touching core traits.

The `EventId` is derived deterministically from a BLAKE3 hash of the event name (`core/src/events/mod.rs`). That gives us a clean, decentralized way for each PVM operation to have its own event ID.

### 2.8 Existing PrecompileRequest flow

```
       MASM `emit.event(NAME)` + args
                │
                ▼
  EventHandler::on_event(&ProcessorState)
                │ returns Vec<AdviceMutation>
                ▼
  { advice stack push, advice map insert, precompile request push }
                │
                ▼
  AdviceProvider.pc_requests: Vec<PrecompileRequest>
                │ take_precompile_requests()
                ▼
  TraceBuildOutput.precompile_requests
                │
                ▼
  ExecutionTrace.precompile_requests
                │
                ▼
  ExecutionProof.pc_requests
```

And in parallel, the transcript state itself threads through:
```
log_precompile opcode
     │ writes pc_transcript_state
     ▼
System.pc_transcript_state
     │
     ▼
ExecutionOutput.final_precompile_transcript
     │
     ▼
PublicInputs.pc_transcript_state (at [36..40] of public values)
```

### 2.9 Active branches around precompiles

From `git branch`:
- `adr1anh/log-precompile` — initial log_precompile opcode
- `adr1anh/verify-precompiles` — verification integration
- `adr1anh/precompile-cleanup`
- `adr1anh/precompile-refactor`
- `adr1anh/optimize-precompiles`

This is an area with active in-flight work; spec changes should land against whichever branch is closest to stable.

---

## 3. Gap analysis: where we are vs where the PVM needs us

| Concern | Current | PVM spec wants | Gap |
|---|---|---|---|
| Transcript shape | Sponge-style absorb (state = 4-felt sponge capacity) | Binary tree of commitments, one 12-felt RPO hash per transcript node | **Change opcode semantics**: one-shot hash instead of absorb |
| Domain separation | Capacity bytes incremented ad-hoc per subsystem; no version | Fixed `[tag, pa, pb, version]` at `state[8..12]` of every preimage (Miden-native capacity slot) | **Introduce `CURRENT_VERSION`**; enforce tag=0 for transcript nodes |
| `log_precompile` opcode stack | reads `stack[0..8]` (COMM ‖ TAG), writes `stack[0..12]` as `[R0, R1, CAP_NEXT]` | reads `stack[8..12]` (ASSERTION, third word), writes `stack[0..12]` as `[junk, junk, new_root]` (reordered hasher output) | **Relabel bus-expression column refs**; MASM wrapper shrinks from 6 to 5 cycles |
| Transcript root public input | Sponge capacity at `[36..40]` | Transcript tree root at `[36..40]` | No wire change — same slot, different semantics |
| MASM helpers | `hperm`, `hash`, `hmerge`, sponge-style builders | Tagged-preimage one-shot hasher; typed helpers per tag | **Add stdlib helpers for tagged RPO nodes** |
| Keccak | Precompile (off-chip), u32-LE encoding, sponge commitment | Precompile (off-chip), u32-LE encoding, tree-node commitment `tag=7 val=digest_hash‖chunks_hash` | **Change commitment shape only**; encoding stays |
| Field / group arithmetic | No existing support | DAG of field/group nodes keyed by commitment hash; event-driven registration | **New host state + new event handlers** |
| `PrecompileRequest` contents | Opaque `Vec<u8>` per event | Must encode typed DAG of nodes (field table, group table, chunk store, transcript tree) | **New richer serialization** |
| Chunk store | No first-class concept | `Chunks` binding with sponge over tag=1 IV | **New mechanism** (host-side map; feeds PVM via `ChunkVal` rows) |

Summary: **3 in-place changes** (opcode semantics, keccak commitment shape, `PrecompileRequest` contents), **3 additions** (`CURRENT_VERSION`, MASM helpers, DAG event handlers + chunk store), **0 deletions** of existing concepts (the flow is still opcode → transcript-state public input + event handler → accumulated request).

---

## 4. Proposed changes — draft spec skeleton

Each subsection below is the first-draft write-up for one deliverable, intended to become a tracking issue.

### 4.1 Transcript shape change: sponge → tagged tree + version

**What changes:** the transcript state is no longer a sponge capacity accumulating arbitrary absorptions; it is the running root of a left-leaning binary tree of `Transcript` (tag 0) nodes, each of which commits to the previous root and an assertion hash.

**Specifically:**

- Define a crate-level constant `CURRENT_VERSION: Felt = Felt::new(0)` in `core/src/precompile.rs` (same file where the transcript types live today). Bumping this invalidates all prior proofs of the precompile VM. Initial value is 0; first post-merge bump will be to 1.

- The transcript root's initial value is `ZERO_HASH = [0, 0, 0, 0]`. This is both the algebraic identity of the transcript and the spec's `True` base case.

- Each "append to transcript" step is a single RPO hash of a 12-felt preimage arranged in Miden-native layout:
  ```
  state[0..4]  = prev_root[0..4]                  // RATE0 — first rate word
  state[4..8]  = assertion[0..4]                  // RATE1 — second rate word
  state[8..12] = [0, 0, 0, CURRENT_VERSION]       // CAPACITY — [tag=0, pa=0, pb=0, version]
  new_root     = RPO(state)[0..4]                 // first 4 positions post-permutation = RATE0'
  ```
  where `prev_root` is the 4-felt running root and `assertion` is the 4-felt root of the subtree being appended. This maps directly onto Miden's `hperm`: the assembler can put `[prev_root, assertion]` on the top 8 stack slots and the capacity word at stack[8..12], and the digest lands at stack[0..4].

- The final root after execution is committed as the Miden VM's `pc_transcript_state` public input, at the same `[36..40]` slot used today.

**Files affected:**

- `core/src/precompile.rs` — replace `PrecompileTranscript::record(PrecompileCommitment)` with a new `PrecompileTranscript::append(assertion: Word)` that does a one-shot RPO hash of the tagged preimage above. Delete `PrecompileTranscript::finalize()` (no longer meaningful — the state is already the root). `PrecompileCommitment` may still exist for host-side bookkeeping but no longer drives the sponge.

- `air/src/lib.rs:67, 77, 104-140` — rename `pc_transcript_state` to `pc_transcript_root` for clarity. No layout change.

- `processor/src/trace/chiplets/aux_trace/virtual_table.rs:170-256` — the virtual-table bus add/remove pair for the transcript state still applies (the root is still threaded through processor state); only the hash shape changes.

**Why not just do it all in MASM?** Because we want the AIR to enforce that the transcript root is *exactly* the tagged-tree hash, not "whatever the prover computed." Binding the version into the opcode's constraints means old-version proofs get rejected automatically. See §5.1.

### 4.2 `LogPrecompile` opcode: new contract

**Design goal:** consume the assertion, thread the new transcript root through processor state (via the existing virtual-table bus), and produce a MASM wrapper sequence that is at least as cheap as today's. The solution: **read the assertion from `stack[8..12]_cur`** (the third stack word) so that a caller's `padw padw` naturally puts the assertion exactly where the opcode expects it, and the hasher bus output positions are reordered as `[junk, junk, new_root]` so that two `dropw`s after the op leave `new_root` on top.

**Opcode stack contract:**

```
stack[0..8]_cur    : must be zero (provided by `padw padw` in the wrapper)
stack[8..12]_cur   : ASSERTION  (read by the opcode)
stack[12..16]_cur  : caller data (preserved)

stack[0..4]_next   : R1'        (junk, from permutation output state[4..8])
stack[4..8]_next   : CAP'       (junk, from permutation output state[8..12])
stack[8..12]_next  : R0' = new_root  (from permutation output state[0..4])
stack[12..16]_next : stack[12..16]_cur  (identity)

Stack shift: 0
```

**Internal (Miden-native `[RATE0, RATE1, CAPACITY]` layout):**

```rust
let prev_root = helper.prev_root                              // via virtual-table bus "remove"
let assertion = stack.get_word(8)                             // stack[8..12]_cur
let mut state = [ZERO; 12];
state[0..4]   = prev_root                                     // RATE0  (lhs = prev prefix)
state[4..8]   = assertion                                     // RATE1  (rhs = new assertion)
state[8..12]  = [ZERO, ZERO, ZERO, CURRENT_VERSION]           // CAPACITY: [tag=0, pa=0, pb=0, version]
let permuted  = Miden_Hasher_Chiplet::permute(state)          // standard HPERM
let new_root  = permuted[0..4]                                // DIGEST_RANGE
// Output is written to next-row stack with reordering (R1', CAP', R0'):
stack_next.set_word(0, permuted[4..8])                        // R1' → stack[0..4]_next (junk)
stack_next.set_word(4, permuted[8..12])                       // CAP' → stack[4..8]_next (junk)
stack_next.set_word(8, new_root)                              // R0' → stack[8..12]_next
// stack[12..16]_next = stack[12..16]_cur (identity)
processor.pc_transcript_state = new_root                      // via virtual-table bus "add"
```

**MASM wrapper** (5 cycles, preserves the full caller stack, consumes the assertion, leaves `new_root` on top):

```masm
pub proc log_precompile_request
    padw padw log_precompile dropw dropw
end
```

Trace through, starting from `[A0 A1 A2 A3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15]` (with assertion `A` on top):
1. `padw` → `[0 0 0 0 A X4..X11]`, overflow `[X12..X15]`
2. `padw` → `[0 0 0 0 0 0 0 0 A X4..X7]`, overflow `[X12..X15, X8..X11]`
3. `log_precompile` → `[j1 j2 new_root X4..X7]` (reads assertion at stack[8..12]_cur, writes reordered output to stack[0..12]_next, stack[12..16]_next = stack[12..16]_cur)
4. `dropw` → `[j2 new_root X4..X7 X8..X11]`, overflow `[X12..X15]`
5. `dropw` → `[new_root X4..X15]`, overflow empty

Final stack: `[new_root, X4..X15]`. Assertion consumed, new_root on top, all caller data below the assertion fully preserved.

A **drop-new_root variant** exists for callers who don't want the root on the stack:

```masm
pub proc log_precompile_request_drop
    padw padw log_precompile dropw dropw dropw
end
```

6 cycles (same as today's wrapper), consumes the assertion, leaves no residue.

**Why read the assertion from `stack[8..12]_cur` instead of `stack[0..4]_cur`?** Because then `padw padw` is the only "positioning" the caller needs — the two pads push the assertion exactly to the depth the opcode reads from. Compare:
- If the op read `stack[0..4]_cur`, the wrapper would be `padw padw movupw.2 log_precompile dropw dropw` = 6 cycles (the `movupw.2` is needed to move the assertion back to the top after padding).
- Reading from `stack[8..12]_cur` saves the `movupw.2` — 5 cycles total.

The cost is purely an AIR expression choice about which stack columns to reference for the bus tuple's input side; there's no runtime overhead.

**Why reorder the hasher bus output as `[R1', CAP', R0']`?** Because then `new_root = R0'` lands at `stack[8..12]_next` (= the third stack word), so after `dropw dropw` drops the two junk words above it, `new_root` is naturally on top. The alternative orderings either require extra `swapw`s or leave `new_root` in an inconvenient position.

**Cycle comparison vs today:**

| Variant | Sequence | Cycles | Net effect |
|---|---|---|---|
| Today's wrapper | `padw movdnw.2 log_precompile dropw dropw dropw` | 6 | consume 8 felts (COMM+TAG), output dropped |
| **New wrapper (keep new_root)** | `padw padw log_precompile dropw dropw` | **5** | consume 4 felts (assertion), new_root on top |
| New wrapper (drop new_root) | `padw padw log_precompile dropw dropw dropw` | 6 | consume 4 felts, output dropped |

The new "keep new_root" wrapper is **1 cycle cheaper than today** *and* provides the updated transcript root for free if the caller wants to chain further computation off of it.

**AIR-level changes.** The hasher chiplet's HPERM bus tuple format is reused unchanged — we do NOT add a new hasher operation selector, we just change how the `LogPrecompile` opcode maps its bus-tuple positions to trace columns.

The hasher bus tuple is still 24 felts wide (12 input state + 12 output state), with the chiplet as provider and the opcode as consumer. The consumer's expression (in `compute_log_precompile_request`) is rewritten:

- **Input side (12 felts):**
  - `state[0..4]` (RATE0) ← `helper.prev_root` (via virtual-table bus "remove", unchanged from today's cap_prev pattern)
  - `state[4..8]` (RATE1) ← `local.stack.get(8..12)` — the assertion at the third stack word (CHANGE: was COMM ‖ TAG at stack[0..8]_cur)
  - `state[8..12]` (CAPACITY) ← AIR constants `[0, 0, 0, CURRENT_VERSION]` — no trace columns at all (CHANGE: was cap_prev from helpers, which are now used for prev_root)

- **Output side (12 felts), reordered:**
  - `state[0..4]` (R0') ← `next.stack.get(8..12)` — the new_root lands at the third stack word (CHANGE: was stack[0..4]_next)
  - `state[4..8]` (R1') ← `next.stack.get(0..4)` — junk at the top (CHANGE: was stack[4..8]_next)
  - `state[8..12]` (CAP') ← `next.stack.get(4..8)` — junk at the second word (CHANGE: was stack[8..12]_next)

The reordering is purely an AIR expression choice — the chiplet provider still places R0', R1', CAP' in their natural state positions on its side of the bus. LogUp's constraint is that the 24-felt tuples match between provider and consumer; which trace column each tuple position reads from is free on each side.

**Helper register layout** (unchanged budget: 5 slots used, 5 free):
- `addr` (1 felt)
- `prev_root` (4 felts) — consumed by `pc_transcript_state` virtual-table bus "remove"

No helper columns are used for output — `new_root` lives on the next-row stack at `stack[8..12]_next`.

**Virtual-table bus for `pc_transcript_state`:**
- Remove side: reads `prev_root` from helper columns (conceptually the same as today's `cap_prev`; rename the range constant from `HELPER_CAP_PREV_RANGE` to `HELPER_PREV_ROOT_RANGE`).
- Add side: reads `new_root` from `next.stack[8..12]` (same column indices as today's `STACK_CAP_NEXT_RANGE`; rename to `STACK_NEW_ROOT_RANGE`).

**Files affected (Miden VM side only):**

- `core/src/operations/mod.rs:122, 598-600` — `LOGPRECOMPILE` opcode byte stays. `Operation::LogPrecompile` docs updated.
- `processor/src/execution/operations/crypto_ops/mod.rs:462-508` — rewrite `op_log_precompile`. Key diffs: read the assertion from `stack[8..12]_cur` (not stack[0..4]_cur and stack[4..8]_cur); build the hasher state as `[prev_root, assertion, 0, 0, 0, VERSION]`; write the permutation output to next-row stack as `[R1', CAP', R0']` so `new_root = R0'` ends up at stack[8..12]_next; the helper register variant still returns `{ addr, prev_root }` (same 5-felt layout, renamed from `cap_prev`).
- `air/src/constraints/chiplets/bus/chiplets.rs:1021-1090` — replace `compute_log_precompile_request` as described above. The tuple width stays at 24 felts; only the trace-column references change.
- `air/src/trace/log_precompile.rs` — rename `HELPER_CAP_PREV_RANGE` → `HELPER_PREV_ROOT_RANGE`, `STACK_CAP_NEXT_RANGE` → `STACK_NEW_ROOT_RANGE`. The input-side constants `STACK_COMM_RANGE` / `STACK_TAG_RANGE` are replaced by a single `STACK_ASSERTION_RANGE = 8..12`. The `STACK_R0_RANGE` / `STACK_R1_RANGE` output constants go away (replaced by `STACK_JUNK_R1_RANGE = 0..4` and `STACK_JUNK_CAP_RANGE = 4..8` if we want named junk slots, or just inlined in the bus expression).
- `air/src/constraints/lookup/buses/range_logcap.rs:42-68` — update the `pc_transcript_state` bus consumer to read `prev_root` from the renamed helper range and `new_root` from the renamed stack range. No structural change.
- `air/src/constraints/chiplets/bus/hash_kernel.rs` — minor: the chiplet provider side still emits a standard HPERM bus tuple; no change here beyond possibly adjusting label constants if needed.
- `processor/src/trace/chiplets/aux_trace/virtual_table.rs:170-256` — update column references to match the renamed constants.
- `crates/lib/core/asm/sys/mod.masm` — rewrite `log_precompile_request` as `padw padw log_precompile dropw dropw` (5 cycles, keeps new_root). Optionally add a `log_precompile_request_drop` variant.
- `core/src/precompile.rs:332-390` — `PrecompileTranscript::record` is replaced by a tagged one-shot hash with the same 12-felt state layout. Initial transcript state is `ZERO_HASH = [0, 0, 0, 0]`, same as today's default sponge state.

**Summary of the AIR delta vs. the current design:**

| Aspect | Today | Proposed |
|---|---|---|
| Hasher bus tuple width | 24 felts (12 in + 12 out) | 24 felts (same, HPERM reused) |
| New hasher chiplet operation | no | **no** — reuses HPERM |
| Bus input `RATE0` source | `COMM` at `stack[0..4]_cur` | `prev_root` at helpers |
| Bus input `RATE1` source | `TAG` at `stack[4..8]_cur` | `assertion` at **`stack[8..12]_cur`** |
| Bus input `CAPACITY` source | `cap_prev` at helpers | AIR constants `[0, 0, 0, VERSION]` |
| Bus output `R0'` lands at | `stack[0..4]_next` | `stack[8..12]_next` (reordered, = `new_root`) |
| Bus output `R1'` lands at | `stack[4..8]_next` | `stack[0..4]_next` (junk) |
| Bus output `CAP'` lands at | `stack[8..12]_next` | `stack[4..8]_next` (junk) |
| Helper register usage | 5 felts (`addr + cap_prev`) | 5 felts (`addr + prev_root`) — same |
| Stack columns touched next row | 12 (all output) | 12 (8 junk + 4 new_root) |
| MASM wrapper | 6 cycles (3 dropws) | **5 cycles** (2 dropws, keeps new_root) |
| `pc_transcript_state` virtual-table bus | yes | yes (unchanged, just renamed ranges) |

The opcode change is almost entirely a **relabeling** of which trace columns supply/receive each bus-tuple position, plus the capacity input changing from "helper felts" to "AIR constants." The hasher chiplet is untouched. The helper register budget is unchanged. The wrapper gets 1 cycle cheaper *and* becomes useful (leaves new_root on top).

**Action item — confirm LogUp expression flexibility.** The design assumes the consumer's bus expression can read the 12 output-state tuple positions from arbitrary (non-contiguous) trace columns: `output[0..4]` from `stack[8..12]_next`, `output[4..8]` from `stack[0..4]_next`, `output[8..12]` from `stack[4..8]_next`. This is standard in LogUp — each bus-tuple position is an AIR expression over trace columns, and there's no requirement that consecutive tuple positions come from consecutive columns. Worth sanity-checking when implementing that `compute_log_precompile_request` can be written this way without hitting any bus-framework assumptions.

### 4.3 MASM primitives

Add a small module `stdlib::crypto::pvm` (or put in `crates/lib/core/asm/crypto/pvm.masm`) with typed helpers for the PVM's tag enumeration. Each helper follows the same shape:
1. Caller arrives with `[val[0..8], ...]` on top of stack (`val[0]` at position 0, `val[7]` at position 7).
2. Helper pushes the 4-felt capacity word `[tag, pa, pb, version]` (via `push.VERSION.PB.PA.TAG`) and uses `movdnw.2` to move it behind `val[8]`, producing the native `hperm` layout `[RATE0, RATE1, CAPACITY]`.
3. Calls `hperm` — one cycle.
4. Extracts `state[0..4]` (the digest, conveniently at stack top) and drops the trailing 8 felts.

Draft helpers:

```masm
# pvm.masm
# All helpers leave the 4-felt node hash on top of the stack.
# CURRENT_VERSION must match core/src/precompile.rs; a unit test enforces this.

const.CURRENT_VERSION=0

#! Internal: extract the digest from a post-hperm stack and drop the rest.
#!
#! Stack input : [DIGEST(4), R1'(4), CAP'(4), ...]
#! Stack output: [DIGEST(4), ...]
#! Cycles      : 9
proc.squeeze_digest
    swapw dropw
    swapw dropw
end

#! Hash a PVM FieldLeaf node (tag=2).
#!
#! Stack input : [val[0..8], field_ty, ...]
#! Stack output: [digest(4), ...]
#! Cycles      : ~16 (1 consume_field_ty + 4 push + 1 movdnw + 1 hperm + 9 squeeze)
pub proc hash_field_leaf
    # Consume field_ty and push the capacity word [tag=2, pa=field_ty, pb=0, version=VERSION]
    # Stack order within the word: tag on top, version deepest.
    # Start:   [val[0..8], field_ty, ...]
    movup.8                              # [field_ty, val[0..8], ...]
    push.CURRENT_VERSION.0               # [0, VERSION, field_ty, val[0..8], ...]
    swap.2                               # [field_ty, VERSION, 0, val[0..8], ...]  (now pa, version-slot, pb-slot)
    # We want the capacity word to be [TAG=2, PA=field_ty, PB=0, VERSION] with TAG on top
    # after movdnw.2. Rearrange top 3 into [TAG, PA, PB, VERSION] order.
    # (Exact stack juggling TBD; use push.CURRENT_VERSION.0.field_ty.2 as the simpler form:)
    # SIMPLER FORM:
    # Start:   [val[0..8], field_ty, ...]
    # Aim:     [val[0..8], TAG=2, PA=field_ty, PB=0, VERSION=0, ...] (capacity word below val[8])
    # One-liner: construct the cap word on top, then movdnw.2 it behind val[8].
    movdnw.2                             # (placeholder; see squeeze_digest and the simpler pattern below)
    hperm
    exec.squeeze_digest
end

#! Cleaner pattern — emitted here as reference. Use this shape for all helpers.
#!
#! Start:   [val[0..8], ...]
#! After push.VERSION.PB.PA.TAG : [TAG, PA, PB, VERSION, val[0..8], ...]  (TAG on top)
#! After movdnw.2               : [val[0..8], TAG, PA, PB, VERSION, ...]  (cap word at stack[8..12])
#! After hperm                  : [DIGEST, R1', CAP', ...]
#! After squeeze_digest         : [DIGEST, ...]
#!
#! Cycles: 4 (push) + 1 (movdnw) + 1 (hperm) + 9 (squeeze) = 15.

#! Hash a PVM KeccakDigestLeaf node (tag=3). All params are fixed.
#!
#! Stack input : [digest_u32[0..8], ...]
#! Stack output: [digest_hash(4), ...]
#! Cycles      : 15
pub proc hash_keccak_digest_leaf
    push.CURRENT_VERSION.0.0.3           # cap = [TAG=3, PA=0, PB=0, VERSION]
    movdnw.2
    hperm
    exec.squeeze_digest
end

#! Hash a PVM FieldBinOp node (tag=4).
#!
#! Stack input : [LHS_HASH(4), RHS_HASH(4), field_ty, op, ...]
#! Stack output: [digest(4), ...]
#! Cycles      : ~20
pub proc hash_field_binop
    # The val[8] slot is LHS ‖ RHS; both are already on top of stack as val[0..8].
    # Consume op and field_ty to build the capacity word [TAG=4, PA=field_ty, PB=op, VERSION].
    push.CURRENT_VERSION                 # [VERSION, LHS, RHS, field_ty, op, ...]
    movup.10                             # [op, VERSION, LHS, RHS, field_ty, ...]
    movup.10                             # [field_ty, op, VERSION, LHS, RHS, ...]
    push.4                               # [TAG=4, field_ty, op, VERSION, LHS, RHS, ...]
    movdnw.2
    hperm
    exec.squeeze_digest
end

#! Hash a PVM GroupCreate node (tag=5).
#!
#! Stack input : [X_HASH(4), Y_HASH(4), group_ty, ...]
#! Stack output: [digest(4), ...]
pub proc hash_group_create
    push.CURRENT_VERSION.0               # [0, VERSION, X, Y, group_ty, ...]
    movup.10                             # [group_ty, 0, VERSION, X, Y, ...]
    push.5                               # [TAG=5, group_ty, 0, VERSION, X, Y, ...]
    movdnw.2
    hperm
    exec.squeeze_digest
end

#! Hash a PVM GroupBinOp node (tag=6). Identical shape to hash_field_binop with TAG=6.
pub proc hash_group_binop
    push.CURRENT_VERSION
    movup.10
    movup.10
    push.6
    movdnw.2
    hperm
    exec.squeeze_digest
end

#! Hash a PVM Keccak node (tag=7). len_bytes lives in param_a.
#!
#! Stack input : [DIGEST_LEAF_HASH(4), CHUNKS_HASH(4), len_bytes, ...]
#! Stack output: [digest(4), ...]
pub proc hash_keccak
    push.CURRENT_VERSION.0               # [0, VERSION, DL, CH, len_bytes, ...]
    movup.10                             # [len_bytes, 0, VERSION, DL, CH, ...]
    push.7                               # [TAG=7, len_bytes, 0, VERSION, DL, CH, ...]
    movdnw.2
    hperm
    exec.squeeze_digest
end

```

**MASM wrapper for `log_precompile`.** The opcode reads the assertion from `stack[8..12]_cur` (the third stack word) and writes the reordered hasher output `[junk, junk, new_root]` to `stack[0..12]_next`, so the wrapper is `padw padw log_precompile dropw dropw` (see §4.2). The two `padw`s push 8 zeros, sinking the caller's assertion from the top word to the third word; the opcode reads it there; the two `dropw`s peel off the 8 junk felts, leaving `new_root` on top with the caller's stack-below-the-assertion fully restored:

```masm
# crates/lib/core/asm/sys/mod.masm
pub proc log_precompile_request
    # Input:  [ASSERTION, caller_stack...]
    # Output: [new_root, caller_stack...]
    padw padw log_precompile dropw dropw
end
```

5 cycles total, 1 cheaper than today's wrapper. The new root is available on top of the stack for free — callers who don't want it can append a `dropw` (6 cycles total, same as today).

**Typical caller pattern:**
```masm
exec.crypto::pvm::hash_field_binop   # [ASSERTION, caller_stack...]
exec.sys::log_precompile_request      # [new_root, caller_stack...]
# new_root is now on top; drop it with `dropw` if unused
```

> ⚠️ The exact `movup.N` indices in the helper sketches above are approximate — the hash-field-binop helper needs to pop two scalar immediates (`op`, `field_ty`) from under an 8-felt val region, which requires a few `movup`s or a single `movupw` move. The canonical pattern to internalize is: **caller keeps `val[0..8]` on top; helper builds the capacity word immediately below via `push.VERSION.PB.PA.TAG` followed by `movdnw.2`, then calls `hperm` and squeezes.** This is ~15 cycles per hash when the scalar params are already immediates, or ~20 cycles when they come from the stack.

**Open question:** there's no single "generic tagged hasher" we can share across tags because MASM doesn't let us parameterize the capacity word at runtime without even more stack juggling. Each tag gets its own proc; that's fine — the PVM has 7 non-trivial tags (1 transcript handled directly by the `log_precompile` opcode, 6 others via `pvm.masm` helpers).

**Constant sharing:** `CURRENT_VERSION` must be the same in MASM and Rust. Options:
- Hardcode it in both places with a build-time test that asserts equality (simplest).
- Generate the MASM constant from Rust via `build.rs`.
- Have the assembler accept `const.CURRENT_VERSION=env!("MIDEN_PVM_VERSION")` or similar.

For a v0, just hardcode and add a `#[test]` that reads the MASM file and parses the constant.

**Files affected (new):**
- `crates/lib/core/asm/crypto/pvm.masm` (new) — helpers above.
- `docs/src/user_docs/assembly/pvm.md` (new) — user-facing docs.

### 4.4 Event handlers and DAG registration

**Goal:** give MASM programs the ability to request that the host record a new expression node in the DAG, returning the commitment hash (and possibly the computed value) to the stack.

**Pattern:** the MASM caller pushes operand commitments and operation metadata on the stack, emits a specific event, and the host handler:
1. Locks the shared DAG state.
2. Reads operand commitments from the stack.
3. Looks up the operand values in the DAG.
4. Computes the result (field add, group double, etc.) in host-side arithmetic.
5. Inserts the new node into the DAG under a new canonical pointer.
6. Computes the commitment hash (this can be done host-side for convenience, or deferred to MASM; see discussion below).
7. Returns `AdviceMutation::ExtendStack { values: commitment_hash_felts }` so MASM can pop it.

**Event names (draft):**
```
miden::pvm::field::register_leaf
miden::pvm::field::op::add
miden::pvm::field::op::sub
miden::pvm::field::op::mul
miden::pvm::field::op::eq
miden::pvm::group::create
miden::pvm::group::op::add
miden::pvm::group::op::sub
miden::pvm::group::op::eq
miden::pvm::keccak::hash       # replaces existing keccak256 event for PVM-bound hashing
```

**Host state layout (draft):**

```rust
pub struct PrecompileDag {
    field_nodes: HashMap<FieldKey, FieldNode>,       // key = (field_ty, ptr)
    group_nodes: HashMap<GroupKey, GroupNode>,       // key = (group_ty, ptr)
    keccak_digests: HashMap<u64, KeccakDigest>,      // key = ptr
    chunk_store: ChunkStore,                          // ptr -> Vec<[Felt; 8]>
    hash_to_node: HashMap<[Felt; 4], NodeRef>,       // commitment hash -> node ref
    transcript_nodes: Vec<TranscriptNode>,           // ordered log of tag-0 nodes
}

pub struct PvmEventHandler {
    dag: Arc<Mutex<PrecompileDag>>,
}

impl EventHandler for PvmEventHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        let mut dag = self.dag.lock().map_err(...)?;
        match event_id_to_op(event_id) {
            PvmOp::FieldAdd => self.handle_field_binop(FieldOp::Add, &mut dag, process),
            ...
        }
    }
}
```

All handlers are the same `PvmEventHandler` struct, dispatched by event ID. They all share the same `Arc<Mutex<PrecompileDag>>`. The host's lifecycle:
1. `let dag = Arc::new(Mutex::new(PrecompileDag::default()));`
2. For each PVM event name, `host.register_handler(name, Arc::new(PvmEventHandler { dag: Arc::clone(&dag) }))`.
3. Execute.
4. After execution, `Arc::try_unwrap(dag).unwrap().into_inner().unwrap()` to extract the final DAG.
5. The extracted DAG is serialized into the proof alongside (or replacing) `pc_requests`.

**Where does the DAG live after execution?** The natural place is to extend `ExecutionProof` with a new field `precompile_dag: PrecompileDag` alongside (or replacing) `pc_requests`. The PVM's trace generation consumes this as its input.

**Key design decision:** should the commitment hash be computed on the host side or in MASM?

- **Host-side:** simpler for MASM (no need to hash anything — just pop the hash from advice). But then the host is the source of truth for commitment hashes, and MASM has to trust it. That's actually fine because the host is always part of the trusted prover.
- **MASM-side:** MASM computes the hash via the `pvm::hash_*` helpers, guaranteeing that whatever ends up in the DAG matches whatever MASM is asserting about.

The cleaner option is **MASM-side hashing** — it closes the trust loop. The host's job is only to maintain the expression DAG and answer "given commitment X, what are its operand values?". MASM is responsible for computing the commitment hash of each new node it creates.

But this has a bootstrapping issue: for a `FieldBinOp::Add` node, MASM needs to know the commitment of the result in order to build subsequent nodes. MASM can compute that commitment without knowing the result's value — in Miden-native layout, the commitment is just `RPO(state)[0..4]` where `state[0..4] = lhs_hash`, `state[4..8] = rhs_hash`, and `state[8..12] = [4, field_ty, op=0, VERSION]`. This is purely a function of the operand commitments and the op parameters, not the values. So MASM can hash first, then call the host event to register the node under that hash.

**Revised flow:**

```
MASM side                              Host side
─────────                              ─────────
push operand commitments
push op metadata
compute c = hash_field_binop(...)      (local, no host interaction)
push c
emit pvm::field::op::add               ─────> PvmEventHandler:
                                                 lock dag
                                                 read c, lhs, rhs, op, field_ty from stack
                                                 verify c matches recomputed hash (defensive)
                                                 look up lhs_val, rhs_val
                                                 compute out_val = lhs_val + rhs_val
                                                 allocate out_ptr
                                                 insert (c -> FieldNode { out_val, out_ptr })
                                                 return ExtendStack([out_ptr])
                                        <────
pop out_ptr if needed (usually ignored)
```

This works and has a nice property: the commitment is computed by MASM (with the AIR enforcing the hash), and the host is just a persistent expression-DAG cache.

**Files affected (new):**
- `core/src/precompile/dag.rs` (new) — `PrecompileDag`, `FieldNode`, `GroupNode`, `ChunkStore`.
- `crates/lib/core/src/handlers/pvm.rs` (new) — `PvmEventHandler`, handler implementations.
- Event name constants added to `core/src/events/`.
- `crates/lib/core/asm/crypto/pvm.masm` (per §4.3) — the hashing helpers AND the emit wrappers that call `pvm::*::register_*` events.

**Open question:** if the DAG is going to be used across multiple MASM programs (e.g., a library of PVM-bound procedures), does it live per-execution or per-host? Per-execution is simpler; per-host enables caching. Default to per-execution.

### 4.5 Keccak precompile: adapt for PVM commitments

The existing `KeccakPrecompile` handler already does almost everything right:
- Input / output encoding is u32-LE (matches PVM spec).
- `len_bytes` is tracked.
- A `PrecompileRequest` is emitted carrying the raw bytes.

What changes is the **commitment shape**. Today:
```
tag  = [event_id, len_bytes, 0, 0]
comm = Poseidon2(Poseidon2(input_felts) ‖ Poseidon2(digest_felts))
(tag, comm) is pushed into the sponge transcript
```

The PVM spec says the transcript should commit to a Keccak node as:
```
Keccak tag = 7
param_a    = len_bytes
param_b    = 0
val[8]     = digest_leaf_hash[4] ‖ chunks_hash[4]
```

where `digest_leaf_hash` is a KeccakDigestLeaf node (tag 3) and `chunks_hash` is the root of a sponge chain over the input chunks (tag 1).

So the keccak event handler's job changes from "compute a single P2-based commitment" to:
1. Compute the digest (unchanged).
2. Compute the `KeccakDigestLeaf` hash = `RPO(state)[0..4]` where `state[0..8] = digest_u32_felts` (the 8-felt rate) and `state[8..12] = [3, 0, 0, VERSION]` (the capacity).
3. Compute the `Chunks` hash = chunk sponge with capacity IV `[1, 0, 0, VERSION]` absorbing 8 rate felts per chunk.
4. Compute the `Keccak` node hash = `RPO(state)[0..4]` where `state[0..4] = digest_leaf_hash`, `state[4..8] = chunks_hash`, `state[8..12] = [7, len_bytes, 0, VERSION]`.
5. Register the DAG entry for the digest (`KeccakDigestLeaf -> ptr`), the chunks (`Chunks(ptr, n_chunks)`), and the Keccak edge.
6. Return the `Keccak` node hash (step 4) to the MASM caller.
7. MASM appends that hash to the transcript via `log_precompile`.

Most of this is host-side work. The only MASM change is: the current MASM `keccak256::hash_bytes` flows through `log_precompile_request` which expects `[COMM, TAG, ...]`. It will change to just receive a single 4-felt commitment from the handler (= the Keccak node hash) and pass it to `log_precompile` as the assertion.

**Files affected:**
- `crates/lib/core/src/handlers/keccak256.rs` — handler computes the new commitment shape; stores extra DAG entries (digest leaf, chunks). Likely the handler grows a `PrecompileDag` reference and writes into it, per §4.4.
- `crates/lib/core/asm/crypto/hashes/keccak256.masm:102-140` — `hash_bytes_impl` returns a single 4-felt commitment instead of `[COMM, TAG, DIGEST_U32[8]]`.
- `core/src/precompile.rs` — `PrecompileCommitment` as currently defined (tag ‖ comm) may be replaced by a simpler `Word` since the commitment is now a standard 4-felt hash.

**Out of scope for this phase:** actually making keccak a chiplet (i.e., proving it inside the main Miden trace instead of deferring to verifier recomputation). That's a separate discussion and belongs to the PVM itself, which has its own keccak chip per comment 1 §8.5 of the discussion.

### 4.6 `PrecompileRequest` data structure evolution

Today: `PrecompileRequest { event_id, calldata: Vec<u8> }`, with verification done post-hoc by a `PrecompileVerifier` registry that re-runs each request.

For the PVM world, the entire `Vec<PrecompileRequest>` is replaced by a single `PrecompileDag` that contains:
- `field_table: HashMap<FieldPtr, FieldElement>`
- `group_table: HashMap<GroupPtr, GroupElement>`
- `chunk_store: HashMap<ChunkPtr, Vec<[Felt; 8]>>` (and the absorbed chunk roots)
- `digest_store: HashMap<DigestPtr, [Felt; 8]>` (raw Keccak digests)
- `nodes: HashMap<[Felt; 4], TranscriptNode>` (the whole DAG, keyed by commitment hash)
- `transcript_leaves: Vec<[Felt; 4]>` (the ordered list of hashes appended to the root-level transcript)
- `version: Felt`

This is what gets serialized as the PVM's input. The data volume is proportional to the number of distinct field/group/chunk values and the number of expression nodes, not to the total "compute" performed.

**Option:** bundle `PrecompileDag` as a single opaque `PrecompileRequest::new(DAG_EVENT_ID, dag.to_bytes())` to keep `ExecutionProof` untouched. This is a cop-out for v0 but avoids changing the proof packaging. Clean version: add a new field `ExecutionProof.precompile_dag` and phase out `pc_requests`.

**Files affected:**
- `core/src/precompile.rs` — add `PrecompileDag` + serialization.
- `core/src/proof.rs` — optionally add `precompile_dag` field to `ExecutionProof`.
- `processor/src/host/advice/mod.rs` — replace or augment `pc_requests` with the DAG.
- `processor/src/host/mod.rs` — new `AdviceMutation` variant for DAG mutations (or route everything through interior-mutable shared state as in §4.4).
- `processor/src/fast/mod.rs:633-638` — `ExecutionOutput` gains a `precompile_dag` field.
- `processor/src/trace/mod.rs:54-217` — `TraceBuildOutput`, `ExecutionTrace` threaded through.
- `prover/src/lib.rs` — proof construction passes the DAG through.

### 4.7 Chunk store and the chunk sponge (tag 1)

The PVM's chunk chip (spec §8.4) maintains a running sponge with Miden-native capacity IV `state[8..12] = [1, 0, 0, CURRENT_VERSION]` and absorbs 8 rate felts (`state[0..8]`) per chunk. The final sponge capacity after absorbing all chunks is the `Chunks` binding's root — matching how Miden's own sponge-construction hashers finalize. From the Miden side, we need to **compute the same sponge root** so that the transcript's `Keccak` node (tag 7) can reference the `Chunks` binding.

The chunk sponge is just a sponge whose capacity IV is `[1, 0, 0, VERSION]` at `state[8..12]` (tag 1 at capacity[0] is the domain separator) and whose rate absorbs 8 felts per chunk at `state[0..8]`. The absorb step is a single RPO permutation per chunk.

This can be done entirely on the host side for now — the MASM caller hands the handler a pointer to the input bytes, the handler chunks them into groups of 8 felts (u32-LE), runs the sponge, and stores:
- `chunks[ptr] = Vec<[Felt; 8]>` (the chunk data, indexed by `ptr`)
- `chunk_sponge_roots[ptr] = Word` (the final sponge root after absorbing all chunks)

The resulting `chunk_sponge_root` is what gets used as `chunks_hash` in the Keccak node (tag 7).

**There is no MASM-visible chunk sponge.** MASM interacts with chunks only indirectly: when computing a Keccak node, it tells the host "here are my bytes," and the host takes care of chunking, sponging, and producing both the digest leaf hash and the chunks hash.

This is a pragmatic shortcut — if we later want MASM code to construct chunks directly (e.g., for data availability proofs), we can add a separate MASM helper, but for the initial PVM integration the only consumer is Keccak.

### 4.8 Public output wiring

No change to the public output layout. The transcript root occupies the same `[36..40]` slot that `pc_transcript_state` occupies today. The only thing that changes is the **semantics** of those 4 felts — they now represent the root of a binary transcript tree, not a sponge capacity.

External systems that verify the Miden proof + the PVM proof will interpret these 4 felts as the PVM's public input.

**Naming cleanup (optional):** rename `pc_transcript_state` → `pc_transcript_root` throughout. Does not affect layout.

---

## 5. Decisions & open questions

### 5.1 Should the opcode enforce the tag, version, and shape, or just do `hperm`?

**Decision:** dedicated opcode, per §4.2. Rationale:
- Binding the version to the Miden AIR is the whole point of having a version. If we let MASM do the hash freely via `hperm`, bugs in `stdlib/asm/crypto/pvm.masm` become silent transcript corruption — the hasher chiplet is happy to hash whatever 12 felts the caller provides, and nothing would catch a wrong `VERSION` at the opcode level.
- The opcode also threads the transcript root through the `pc_transcript_state` processor-state slot and, via the virtual-table bus, into the public input. A `hperm`-only approach would require a separate mechanism to get the root into public inputs, and that mechanism would itself need a dedicated constraint.

Together, these two enforcement needs (version constant + root threading) justify a single dedicated opcode even though the hash math is the same as `hperm`.

**Alternative considered:** use plain `hperm` and rely on MASM for everything. Simpler core but weaker guarantees — no AIR-level version check, no automatic public-input threading. Rejected.

### 5.2 Where does `CURRENT_VERSION` live canonically?

**Decision (proposed):** `core::precompile::CURRENT_VERSION: Felt`, as a `pub const`. AIR imports it via `miden_core::precompile::CURRENT_VERSION`. MASM stdlib hardcodes a matching constant `const.CURRENT_VERSION=0` in `crypto/pvm.masm`, guarded by a unit test that parses the MASM file and checks consistency. When bumping the version, both must change together — the test fails if only one does. This is a compromise between tight coupling and tractable tooling.

**Alternatives considered:**
- `build.rs` codegen of the MASM file → adds complexity to the build and muddies the MASM module's provenance.
- Pass the version as an immediate operand to `log_precompile` → shifts the enforcement from the AIR to the caller, defeating the purpose.

### 5.3 What counts as an "assertion hash"?

Any 4-felt hash the MASM program computes using the PVM hash primitives, provided it is the root of a subtree that evaluates to `True` in the PVM. In practice, every transcript leaf is either a `FieldBinOp::Eq` or a `GroupBinOp::Eq` or a `Keccak` node — all of which evaluate to `True` per the PVM spec. The Miden VM neither knows nor cares what kind of node the assertion is; it just RPO-hashes it with the running root.

### 5.4 How does the host handler maintain mutable DAG state under `&self`?

Via `Arc<Mutex<PrecompileDag>>` as a field of the handler struct. All PVM handlers share the same `Arc`. The cost is one lock acquire per event, which is negligible compared to an RPO hash. See §4.4.

**Alternative considered:** add a new `AdviceMutation::ExtendPrecompileDag` variant + store DAG in `AdviceProvider`. Cleaner from the trait perspective (no interior mutability) but requires the handler to know enough to construct the mutation without reading the DAG, which is not possible for operations whose result depends on operand values that only the DAG knows. Rejected.

**Alternative considered:** give handlers `&mut self`. Requires a breaking change to the `EventHandler` trait and doesn't compose well with sharing handlers across event IDs. Rejected.

### 5.5 Chunk sponge in MASM or host-only?

**Decision:** host-only for v0, per §4.7. The only PVM consumer is Keccak, and Keccak is host-driven anyway.

Revisit if we get a use case for chunk-based commitments that MASM needs to construct on its own.

### 5.6 Field / group arithmetic in host or in MASM?

**Decision:** host. Field and group values never appear on the MASM stack — MASM only manipulates 4-felt commitment hashes. The host handler is responsible for all actual arithmetic (addition, EC doubling, etc.) in the target fields, because the Miden field is not the same as the target fields (the PVM has two curves A/B with a single prime Fp that is different from Miden's Goldilocks).

### 5.7 Single transcript vs multiple transcripts per program

For v0, single transcript. The PVM spec's `Transcript` tag (0) has a left-right structure that can already nest a sub-transcript as an "assertion" under the parent transcript, so multiple independent transcripts can be composed into one root. Revisit if there's demand for truly independent roots.

### 5.8 Backwards compatibility of the `ExecutionProof` format

The transition from `Vec<PrecompileRequest>` to `PrecompileDag` is breaking for external verifiers. Since this is pre-mainnet and the precompile feature is explicitly versioned (`CURRENT_VERSION = 0`), we can treat v0 as a clean break. The wire format for the proof envelope gets a new field; the sponge-transcript path is removed entirely, not maintained in parallel.

### 5.9 What about the existing `PrecompileVerifier` registry?

Goes away. The "verify by re-running the precompile in-process" model is replaced by "verify by running the PVM STARK proof over the DAG." The `PrecompileVerifier` trait and its registry can be deleted once the PVM is online; until then, they remain as the verification path for tests that don't yet have PVM integration. See migration plan in §7.

### 5.10 What about prep/preprocessing — does the DAG get hashed to a single commitment?

The spec says the transcript root is the PVM's public input. The DAG itself is trace-generation-only — it doesn't need its own commitment, because the DAG's consistency is enforced by the PVM's AIR (each node's commitment hash is derivable from its operands, and the transcript root binds to the whole thing). So from the Miden side, only the root is public.

### 5.11 Miden-native vs spec-native preimage layout

**Decision:** propose an amendment to the PVM AIR spec (comment 1) so that the node preimage uses Miden's `[RATE0(4), RATE1(4), CAPACITY(4)]` state ordering (rate at `state[0..8]`, capacity at `state[8..12]`, digest at `state[0..4]` post-permutation) instead of the spec's current "capacity-first" ordering (capacity at positions 0..3, rate at 4..11, output at 0..3).

**Rationale:**

1. **Zero-overhead MASM hashing inside Miden.** In the native layout, each PVM hash helper in `crypto/pvm.masm` is ~15 cycles (1 × `push.VERSION.PB.PA.TAG` word + 1 × `movdnw.2` + 1 × `hperm` + 9 cycles to squeeze). In the spec's layout, every helper would need a 12-felt reshuffle before calling `hperm` and another after, adding ~20 extra cycles per hash and making the helpers significantly more fragile. This optimization is entirely Miden-side — it affects the MASM programs that produce transcripts.

2. **Miden hasher chiplet reuse for `log_precompile`.** Miden's existing hasher chiplet accepts state in `[RATE0, RATE1, CAPACITY]` layout. Keeping the PVM's node hashes in the same layout means `op_log_precompile`'s bus interaction can submit its state directly to Miden's hasher chiplet with no reshuffling. The only net new change to the Miden hasher chiplet is the capacity-IV mechanism (4-felt fixed capacity), which is a small generalization of the existing 1-felt domain-separator slot. This optimization is Miden-side.

3. **PVM hash chip implementation sharing — structural, not literal.** The PVM is a separate AIR with a separate hash chip. Its bus relations (width 16 for `Hash`, width 16 for `Absorb`), its provider/consumer wiring to the PVM eval chip, and its handling of capacity IVs for transcript vs chunk sponges are all PVM-specific and *not* shared with Miden's hasher chiplet. What *is* shareable is the Poseidon2 permutation-round constraint structure (the packed 16-row representation of 31 rounds: 1 init + 8 external + 22 internal + 1 final), because both chips implement the same permutation. A PVM implementer can copy the round-constraint code from `air/src/constraints/chiplets/hasher*` with only bus-wiring changes, but this is source-level code reuse, not runtime constraint sharing between two chiplets in the same AIR.

4. **The spec's labeling is non-standard for RPO.** RPO as a permutation primitive has no canonical "capacity is at the start" or "capacity is at the end" convention — it's just a 12-element bijection. The Miden codebase has settled on `[RATE, CAPACITY]` (capacity at the end), and so does miden-crypto. Aligning the PVM spec with the existing Miden convention reduces the cognitive tax for implementers who read both specs.

**Cost:** the published PVM AIR spec (discussion #3005 comment 1) must be amended. This is cheap because (a) nothing depends on it yet, (b) the change is purely a relabeling of which state positions are called "capacity" vs "rate" — RPO's cryptographic output for any given 12-felt input is the same, only the mapping from semantic fields (tag, version, val) to state positions changes, and (c) we're pre-v0, so the first post-merge version bump will be from 0 to 1 regardless.

**Open action:** once this PVM.md note stabilizes, post an amendment to the AIR spec comment (or reply with a cross-referenced follow-up comment that notes the change) before any PVM implementation work begins.

### 5.12 Opcode stack contract: how to minimize trace-column pressure without adding a hasher chiplet op

**Constraint:** we can't add a new selector to Miden's hasher chiplet. The existing HPERM bus tuple is 24 felts wide (12 input state + 12 output state), and all 12 output felts must live in trace columns somewhere on the consumer side. The version `[0, 0, 0, VERSION]` capacity IV is a compile-time constant and doesn't need any trace columns.

**Available trace columns** for one opcode row:
- Helper columns (`hasher_state[2..12]`): 10 slots.
- Stack columns at row N and N+1: 16 each.

**What must be stored where:**
- `prev_root` (4 felts): helpers, consumed by `pc_transcript_state` virtual-table bus "remove". Same slot as today's `cap_prev`.
- `assertion` (4 felts): stack_cur, read by the opcode.
- `new_root` (4 felts): must be readable by the `pc_transcript_state` virtual-table bus "add". Can live on stack_next or helpers.
- 8 "don't-care" output felts (`R1'` and `CAP'` from the permutation): must exist in trace columns to match the hasher bus tuple, but aren't semantically meaningful. Can live on stack_next or helpers.

**Decision:** keep helpers at the same 5-slot usage as today (`addr + prev_root`), put all 12 output felts on the next-row stack, and use two tricks to minimize MASM cycle cost:

1. **Read the assertion from `stack[8..12]_cur`** (the third stack word), not the top. This means the MASM wrapper's `padw padw` naturally sinks the caller's assertion to exactly the depth the opcode expects, without a subsequent `movupw`.

2. **Reorder the hasher bus output as `[R1', CAP', R0']`**, so that `new_root = R0'` lands at `stack[8..12]_next` (the third stack word). After `dropw dropw` drops the two junk words at positions [0..8], `new_root` is naturally at the top of the stack.

The MASM wrapper becomes `padw padw log_precompile dropw dropw` = 5 cycles, 1 cheaper than today's 6-cycle wrapper, and leaves `new_root` on top for chained use.

**Rejected alternatives:**

- **Stack unchanged (identity transition).** Initially appealing — would be the cheapest possible stack-transition constraint. Infeasible because the 12 output felts need trace columns, and the helper budget (10 slots) plus input felts exceeds what we have. We'd need either a new hasher chiplet operation with a narrower bus tuple (rejected per user — can't add a new chiplet op) or to borrow from next-row stack columns (which conflicts with identity).

- **Read assertion from `stack[0..4]_cur` (top of stack).** Requires the wrapper to be `padw padw movupw.2 log_precompile dropw dropw` = 6 cycles, losing the 1-cycle savings. Reading from depth 8 avoids the `movupw` entirely.

- **Consume the assertion (shift -4), producing `[new_root]` on top.** Imposes a shift-left-by-4 constraint on the stack transition, plus constraints on where the 8 don't-cares live. Adds complexity without saving cycles vs the chosen design.

- **Move the transcript root onto the stack (stack-managed), eliminating `pc_transcript_state` as processor state.** Elegant, but breaks the existing virtual-table bus architecture and changes the public-input layout. The user's directive is to keep the transcript root in a virtual-table bus, so this option is rejected.

**Consequences of the chosen design:**
- Helper budget unchanged (5 slots used, same as today).
- Hasher chiplet untouched — no new operation selector.
- Trace-column layout: 12 next-row stack positions constrained (8 to junk, 4 to new_root), same as today.
- MASM wrapper is 1 cycle cheaper than today's (5 vs 6).
- Caller data at `stack[4..16]_cur` is fully preserved via the two `padw`s pushing to overflow.
- `new_root` is left on top of the stack after the wrapper as a free bonus.

---

## 6. Draft of the comment to post

Below is the draft of the comment content we'll post on discussion #3005 as a second comment (first one is the PVM AIR spec). It's a summary of §4 above, written for an audience that has already read comment 1.

---

### `### Miden-side changes to support the PVM`

Posting as a follow-up to the PVM AIR spec (comment 1). This comment describes the Miden VM-side changes needed so that Miden programs can produce transcripts that the PVM can decode.

This is the change surface from the PVM's consumer perspective. It's derived from the current shape of the precompile infrastructure on `next` (`core/src/precompile.rs`, `processor/src/execution/operations/crypto_ops/mod.rs`, `processor/src/host/handlers.rs`, `crates/lib/core/asm/sys/mod.masm`), which already has most of the scaffolding we need.

#### Current state

The Miden VM already has a precompile transcript, but it is a **sponge**, not a tree:

- `LogPrecompile` opcode: `[COMM, TAG, PAD] → [R0, R1, CAP_NEXT]` — one sponge absorb per call.
- `PrecompileTranscript { state: Word }` — 4-felt sponge capacity, updated by `record(PrecompileCommitment)`.
- Final state becomes public input at `[36..40]`.
- Event handlers (`trait EventHandler`) return `Vec<AdviceMutation>`, where `ExtendPrecompileRequests` queues `PrecompileRequest { event_id, calldata: Vec<u8> }` for post-hoc verification.
- Keccak is a handler (not a chiplet) using u32-LE packed input/output, with a commitment of shape `(tag=[event_id, len_bytes, 0, 0], comm=P2(P2(in) ‖ P2(out)))`.

> **Scope note.** The Miden VM and the Precompile VM are two separate STARK systems, each with its own AIR, trace, and hash/permutation chip. Everything below is about changes to the **Miden VM only**; the PVM's own AIR is specified in comment 1 and doesn't get constraint changes from this comment. When I say "the hasher chiplet," I mean Miden's, at `air/src/constraints/chiplets/hasher*`.
>
> **Amendment to the published PVM spec (preimage layout).** Comment 1 puts `[tag, param_a, param_b, version]` at state positions 0..3 and `val[8]` at positions 4..11, with hash output from positions 0..3 post-permutation. That layout is the **inverse** of Miden's native `hperm` convention (rate at `state[0..8]`, capacity at `state[8..12]`, digest at `state[0..4]` = `RATE0'`). Using the published layout on the Miden side would require shuffling felts around `hperm` on every hash call, wasting cycles, and would prevent Miden's `log_precompile` opcode from reusing Miden's existing hasher chiplet as-is. **This comment proposes amending the PVM AIR spec so the node preimage uses Miden-native layout**: `val[0..8]` at `state[0..8]`, `[tag, pa, pb, version]` at `state[8..12]`, digest from `state[0..4]`. Since RPO is a deterministic permutation, this is a pure relabeling — no cryptographic change, only the byte-for-byte digests differ. The PVM will still have its own hash chip with its own bus wiring; the benefit is that (a) Miden's hasher chiplet can handle PVM node hashes natively, (b) MASM hash primitives need no state reshuffling, and (c) the PVM's hash chip implementation can copy the Poseidon2 round-constraint structure from Miden's hasher chiplet (source-level, not a runtime sharing of the same chip instance).

#### Change 1: transcript shape, sponge → tagged tree with version

- Introduce `CURRENT_VERSION: Felt` as a `pub const` in `core/src/precompile.rs`, initial value `0`.
- Replace sponge absorb with a one-shot tagged hash. The transcript "append" operation uses Miden-native state layout:
  ```
  state[0..4]  = prev_root[0..4]                  // RATE0
  state[4..8]  = assertion[0..4]                  // RATE1
  state[8..12] = [0, 0, 0, CURRENT_VERSION]       // CAPACITY = [tag=0, pa=0, pb=0, version]
  new_root     = RPO(state)[0..4]                 // DIGEST_RANGE = RATE0' post-permutation
  ```
  This is a `Transcript` node (tag 0) in the amended PVM spec, with `val[8] = prev_root ‖ assertion` at the rate and `[tag, pa, pb, version]` at the capacity.
- Initial root is `ZERO_HASH = [0,0,0,0]`, matching the PVM's trivial-True base case.
- Public input slot (`[36..40]`) is unchanged — only the semantics of those 4 felts changes from "sponge capacity" to "transcript tree root."

#### Change 2: `LogPrecompile` opcode contract

The opcode reads the assertion from the **third stack word** (`stack[8..12]_cur`, not the top), reads `prev_root` from helper columns (via the existing `pc_transcript_state` virtual-table bus), hashes `[prev_root, assertion, 0, 0, 0, VERSION]` via the Miden hasher chiplet's existing HPERM bus, and writes the 12-felt permutation output to the next-row stack with the positions **reordered** as `[R1' (junk), CAP' (junk), R0' = new_root]`. The capacity IV `[0, 0, 0, CURRENT_VERSION]` is baked into the bus tuple as AIR compile-time constants — no trace columns, no helper slots.

Reading the assertion at depth 8 and putting `new_root` at depth 8 in the output makes the MASM wrapper symmetrical and minimal:

```masm
# crates/lib/core/asm/sys/mod.masm
pub proc log_precompile_request
    # Input:  [ASSERTION, caller_stack...]
    # Output: [new_root, caller_stack...]
    padw padw log_precompile dropw dropw
end
```

5 cycles total, 1 cheaper than today's wrapper. Step by step:
- `padw padw` pushes 8 zeros on top, sinking the assertion from `stack[0..4]` to `stack[8..12]` — exactly where the opcode reads it — and pushing the caller's stack down into overflow.
- `log_precompile` hashes the assertion with `prev_root` and the fixed capacity, writes `[R1', CAP', new_root]` to `stack[0..12]_next` (8 junk felts followed by `new_root` at positions [8..12]), and threads `new_root` through the `pc_transcript_state` virtual-table bus.
- `dropw dropw` peels off the 8 junk felts, bringing `new_root` to the top and popping the caller's original `stack[4..16]` back from overflow. Net: `new_root` on top, assertion consumed, caller data fully preserved.

The new root is kept on top of the stack as a free bonus — callers that don't want it can append a `dropw` (6 cycles total, same as today's wrapper).

**AIR changes are minimal — no new hasher chiplet operation.** We reuse the existing HPERM bus tuple (24 felts, 12 input + 12 output) and just rewrite `compute_log_precompile_request` in `air/src/constraints/chiplets/bus/chiplets.rs:1021` to map the tuple positions to different trace columns:

- **Bus input (12 felts):**
  - `state[0..4]` (RATE0) ← helper `prev_root` (same helper slot as today's `cap_prev`, just renamed)
  - `state[4..8]` (RATE1) ← `local.stack.get(8..12)` — **assertion at the third stack word** (was COMM+TAG at stack[0..8])
  - `state[8..12]` (CAPACITY) ← AIR constants `[0, 0, 0, CURRENT_VERSION]` — **no trace columns** (was `cap_prev` from helpers)

- **Bus output (12 felts), reordered:**
  - `state[0..4]` (R0' = `new_root`) ← `next.stack.get(8..12)` — **reordered to land at stack[8..12]_next** (was stack[0..4]_next)
  - `state[4..8]` (R1' = junk) ← `next.stack.get(0..4)`
  - `state[8..12]` (CAP' = junk) ← `next.stack.get(4..8)`

The hasher chiplet's provider side is **unchanged** — it still emits the 12-felt output state in its natural `[R0, R1, CAP]` order. The reordering happens purely in the consumer's AIR expression, which is a free choice of trace-column references in LogUp.

**Helper register layout** (unchanged budget: 5 slots used, 5 free):
- `addr` (1 felt)
- `prev_root` (4 felts) — consumed by `pc_transcript_state` virtual-table bus "remove", same slot as today's `cap_prev`

**Virtual-table bus for `pc_transcript_state`:**
- Remove side: reads `prev_root` from helper columns (same as today's `cap_prev`, column range renamed).
- Add side: reads `new_root` from `next.stack[8..12]` (same column range as today's `STACK_CAP_NEXT_RANGE`, renamed).

**Trace-column delta summary:**

| Aspect | Today | Proposed |
|---|---|---|
| Hasher bus tuple width | 24 felts | 24 felts (same HPERM format) |
| New hasher chiplet op | no | **no** (reuses HPERM) |
| Helper felts used | 5 (`addr + cap_prev`) | 5 (`addr + prev_root`) |
| Stack columns touched next row | 12 | 12 (8 junk + 4 new_root, reordered) |
| Assertion read from | `stack[0..8]_cur` (COMM+TAG) | `stack[8..12]_cur` (third word) |
| `new_root` lands at | — (CAP_NEXT at stack[8..12]_next) | `stack[8..12]_next` (reordered from R0') |
| Capacity IV | `cap_prev` from helpers | AIR constants |
| MASM wrapper | 6 cycles | **5 cycles**, keeps `new_root` on top |

The opcode change is almost entirely a relabeling of trace-column references in the bus expression, plus the capacity input migrating from helpers to AIR constants. The hasher chiplet is untouched.

**Why a dedicated Miden opcode rather than plain `hperm`?** (a) The AIR enforces the fixed capacity IV `[0, 0, 0, VERSION]` — an `hperm`-based transcript could silently absorb the wrong version if MASM had a bug, whereas the dedicated opcode's bus expression hard-wires the capacity constants; (b) the opcode threads `new_root` into the `pc_transcript_state` public input via the existing virtual-table bus, which an `hperm`-based approach would have to reinvent.

#### Change 3: MASM primitives for tagged-preimage hashing

Add a new stdlib module `crypto::pvm` with typed helpers, one per non-transcript PVM tag:
- `hash_field_leaf` (tag 2), `hash_field_binop` (tag 4)
- `hash_group_create` (tag 5), `hash_group_binop` (tag 6)
- `hash_keccak_digest_leaf` (tag 3), `hash_keccak` (tag 7)

Transcript nodes (tag 0) don't need a MASM helper — they're handled directly by the `log_precompile` opcode, which the caller invokes inline.

Thanks to the Miden-native layout amendment, each helper is a thin wrapper over `hperm`:
```masm
# Caller: [val[0..8], scalar params..., ...]
push.CURRENT_VERSION.PB.PA.TAG     # build capacity word [TAG, PA, PB, VERSION]
movdnw.2                            # move it behind val[8] → state[8..12]
hperm                               # state[0..12] permuted in place (Miden hasher chiplet)
swapw dropw swapw dropw             # keep state[0..4] as digest, drop the rest
# Result: [digest, ...]
```
Cycle cost per hash: ~15 cycles (1 × `hperm` + stack setup/extract). No runtime reordering of val[8]; it stays on top of stack where the caller produced it.

`CURRENT_VERSION` is hardcoded as a `const.CURRENT_VERSION=0` at the top of `pvm.masm`, kept in sync with the Rust constant by a unit test.

#### Change 4: event-driven DAG registration

MASM programs never handle field or group values directly — they only work with 4-felt commitment hashes. The actual arithmetic (in the target PVM fields, which are different from Miden's field) is done by host-side event handlers that maintain a shared `PrecompileDag`:

```
MASM                                      Host
─────                                     ────
1. compute c = hash_field_binop(...)      
   using `pvm.masm` helpers
2. emit.miden::pvm::field::op::add        →
                                          handler:
                                            lock dag
                                            verify c matches recomputed hash
                                            look up lhs, rhs values in dag
                                            compute out = lhs + rhs (in target field)
                                            register FieldNode(out) under c
                                          ←
3. continue
```

The `PrecompileDag` is held by the host as `Arc<Mutex<PrecompileDag>>` shared across all PVM handlers. After execution, the DAG is extracted from the host and serialized as the PVM's trace-generation input.

New events (draft names):
```
miden::pvm::field::register_leaf
miden::pvm::field::op::{add,sub,mul,eq}
miden::pvm::group::create
miden::pvm::group::op::{add,sub,eq}
miden::pvm::keccak::hash
```

#### Change 5: keccak precompile — commitment shape only

The Keccak handler keeps its current u32-LE encoding (which already matches the PVM spec), but its commitment shape changes from:
```
(tag=[event_id, len_bytes, 0, 0], comm=P2(P2(in) ‖ P2(out)))  # sponge absorb input
```
to the PVM-native tag-7 Keccak node:
```
keccak_hash = hash_keccak(len_bytes,
                          hash_keccak_digest_leaf(digest),
                          chunk_sponge_root(input_chunks))
```
computed host-side, with the handler inserting all the relevant DAG entries (the digest leaf, the chunks, the Keccak edge) before returning `keccak_hash` to MASM via advice push. MASM then appends `keccak_hash` to the transcript via `log_precompile`.

#### Change 6: `PrecompileRequest` → `PrecompileDag`

The current `Vec<PrecompileRequest>` (each a `{event_id, calldata: Vec<u8>}`) is replaced by a single `PrecompileDag` containing:
- `field_table: HashMap<FieldPtr, FieldElement>`
- `group_table: HashMap<GroupPtr, GroupElement>`
- `chunk_store: HashMap<ChunkPtr, Vec<[Felt; 8]>>`
- `digest_store: HashMap<DigestPtr, [u8; 32]>`
- `nodes: HashMap<[Felt; 4], TranscriptNode>`
- `transcript_leaves: Vec<[Felt; 4]>`
- `version: Felt`

The DAG is the PVM's trace-generation input. It is produced during Miden execution by the handlers described in change 4 and threaded through `ExecutionOutput → TraceBuildOutput → ExecutionTrace → ExecutionProof`.

The old `PrecompileVerifier` registry is removed (replaced by the PVM itself).

#### Scope of work (tentative issue breakdown)

1. **Transcript shape + version** — `core/src/precompile.rs` (`PrecompileTranscript::append`), `core/src/operations/mod.rs`, `processor/src/execution/operations/crypto_ops/mod.rs`.
2. **Opcode bus expression rewrite** — `air/src/constraints/chiplets/bus/chiplets.rs` (`compute_log_precompile_request`) and `air/src/trace/log_precompile.rs`. Input side: assertion at `stack[8..12]_cur`, capacity `[0, 0, 0, VERSION]` as AIR constants, `prev_root` from helpers. Output side: reordered so `R0' = new_root` lands at `stack[8..12]_next`. Rename column range constants (`HELPER_CAP_PREV_RANGE` → `HELPER_PREV_ROOT_RANGE`, `STACK_CAP_NEXT_RANGE` → `STACK_NEW_ROOT_RANGE`). **No hasher chiplet changes** — reuses existing HPERM.
3. **MASM wrapper update** — rewrite `sys::log_precompile_request` as `padw padw log_precompile dropw dropw` (5 cycles).
4. **MASM `crypto::pvm` helpers** — `crates/lib/core/asm/crypto/pvm.masm` (new), docs.
5. **`PrecompileDag` types and serialization** — `core/src/precompile/dag.rs` (new).
6. **PVM event handlers** — `crates/lib/core/src/handlers/pvm.rs` (new), event IDs in `core/src/events/`.
7. **Keccak handler rewrite** — `crates/lib/core/src/handlers/keccak256.rs`, `crates/lib/core/asm/crypto/hashes/keccak256.masm`.
8. **`ExecutionProof` DAG field** — `core/src/proof.rs`, prover wiring.
9. **Remove `PrecompileVerifier` registry** — cleanup after (1)–(8) are in.
10. **Migration test** — end-to-end test producing a transcript and feeding it to a stub PVM.

Items (1), (2), and (3) are coupled — the transcript `append` method, the bus expression rewrite, and the MASM wrapper must land together because the opcode's trace-column references and MASM stack contract change in lockstep. Items (4)–(10) are roughly linear.

---

## 7. Migration plan

Rough order, optimizing for minimal in-flight disruption to `next`:

1. **Land `CURRENT_VERSION` constant** in `core/src/precompile.rs` and reference it in `PrecompileTranscript::record()` as a no-op (e.g., add `debug_assert_eq!` that version is wired through). This is a safe prep step.
2. **Land the new `PrecompileTranscript::append(assertion)` method** alongside the existing `record()`, gated behind a feature flag or unused for now.
3. **Add the MASM `crypto::pvm` module** with all the tagged hashers. These are testable in isolation against a host-side reference implementation of the PVM hash.
4. **Rewrite `op_log_precompile`** to call `append` instead of sponge absorb, and update the MASM wrapper in `sys::log_precompile_request` accordingly. This is the first breaking change in the series; all callers of `log_precompile_request` need to be audited (currently: keccak256, sha512, eddsa, ecdsa per the transcript agent's findings).
5. **Introduce `PrecompileDag` type and host handler scaffolding** (per §4.4). Use it from the rewritten keccak handler as the pilot.
6. **Migrate sha512, eddsa, ecdsa** to the new flow, likely with similar per-precompile handlers.
7. **Add the DAG to `ExecutionOutput` / `TraceBuildOutput` / `ExecutionProof`**, phasing out `pc_requests` after all callers are migrated.
8. **Delete `PrecompileVerifier` registry** and the old `PrecompileCommitment` type once nothing references them.
9. **PVM spec hookup**: a stub PVM that consumes a `PrecompileDag` and validates its shape (no STARK proof yet — just a decoder that walks the DAG and checks consistency). This is the forcing function to confirm that the Miden-side changes actually produce what the PVM expects.

Steps 1–4 are the critical path; 5–8 can land incrementally. Step 9 can start early with a mock.

---

## 8. Work breakdown (draft issue titles)

1. `pvm/version`: Introduce `CURRENT_VERSION` constant in `core::precompile`.
2. `pvm/transcript-tree`: Replace `PrecompileTranscript::record` with tagged one-shot hash (`append`).
3. `pvm/opcode`: Rewrite `op_log_precompile` to read assertion from `stack[8..12]_cur` and emit the reordered hasher bus tuple (reuses existing HPERM). Rename `HELPER_CAP_PREV_RANGE` → `HELPER_PREV_ROOT_RANGE`, `STACK_CAP_NEXT_RANGE` → `STACK_NEW_ROOT_RANGE`. Delete `STACK_COMM_RANGE`/`STACK_TAG_RANGE`/`STACK_R0_RANGE`/`STACK_R1_RANGE` references and replace with `STACK_ASSERTION_RANGE = 8..12` on the input side and the reordered output-column mapping in `compute_log_precompile_request`.
4. `pvm/masm-wrapper`: Update `sys::log_precompile_request` to `padw padw log_precompile dropw dropw` (5 cycles, keeps new_root on top).
5. `pvm/masm-helpers`: Add `crates/lib/core/asm/crypto/pvm.masm` with per-tag hashers.
6. `pvm/dag-types`: Define `PrecompileDag`, `FieldNode`, `GroupNode`, `ChunkStore`.
7. `pvm/event-handlers`: Add `PvmEventHandler` with shared `Arc<Mutex<PrecompileDag>>`.
8. `pvm/keccak-commitment`: Migrate keccak256 handler to PVM node shape.
9. `pvm/proof-field`: Thread `PrecompileDag` through `ExecutionProof`.
10. `pvm/sha512-migrate`: Migrate sha512 handler to the new flow.
11. `pvm/eddsa-migrate`: Migrate eddsa handler to the new flow.
12. `pvm/ecdsa-migrate`: Migrate ecdsa handler to the new flow.
13. `pvm/cleanup`: Delete `PrecompileVerifier` registry and `PrecompileCommitment`.
14. `pvm/spec-test`: End-to-end test that a Miden program produces a PVM-decodable transcript.
