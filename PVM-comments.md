# Discussion #3005 — Draft Comments

These are draft replies to https://github.com/0xMiden/miden-vm/discussions/3005 (`Precompile VM architecture design`). Each section below is a self-contained comment that can be posted independently. **Not posted yet — for review.**

The comments are sized for two audiences in one read:
- **TL;DR + What/Why** at the top: skimmable for a CTO who wants to know what's going on.
- **Design + Files + Hints** below: enough detail for an engineer or agent to pick up the implementation.

There are six comments:

| # | Topic | Length |
|---|---|---|
| A | Spec amendment: preimage layout (Miden-native) | short |
| B | LogPrecompile opcode and transcript-shape changes | long, the main one |
| C | MASM primitives for hashing PVM-shaped nodes | medium |
| D | Event-driven DAG registration (host side) | medium |
| E | `PrecompileRequest` → `PrecompileDag` data structure evolution | medium |
| F | Keccak handler adaptation | short |

---
---

## Comment A — Proposed amendment to the published preimage layout

**TL;DR:** Comment 1 puts `[tag, param_a, param_b, version]` at state positions 0..3 (calling them "capacity") and `val[8]` at positions 4..11. That's the inverse of Miden's native sponge convention — Miden has rate at `state[0..8]` and capacity at `state[8..12]`, with the digest at `state[0..4]` post-permutation. **Proposing to amend the spec to use Miden-native ordering**: `val[0..8]` at `state[0..8]`, `[tag, pa, pb, version]` at `state[8..12]`, digest from `state[0..4]`. RPO is a deterministic permutation, so this is a pure relabeling of state positions — no cryptographic change, only the byte-for-byte digests differ.

**Why:**
1. Miden's `log_precompile` opcode can request the hash from Miden's existing hasher chiplet without any felt reordering — the input state is already in the format the chiplet consumes.
2. MASM hash helpers in the new `crypto::pvm` stdlib module call `hperm` directly with the natural stack layout — no `movdnw`/`movupw` reshuffling. ~15 cycles per node hash vs ~35+ if we had to reorder for every hash.
3. The PVM's own hash chip implementation can copy the Poseidon2 round-constraint structure verbatim from `air/src/constraints/chiplets/hasher*` — same state layout means same constraint expressions. (The two AIRs remain separate; this is source-level code reuse, not a runtime sharing of one chip instance across two VMs.)
4. Miden codebase and miden-crypto have already settled on the `[RATE, CAPACITY]` convention. Aligning the PVM spec removes a cognitive tax for implementers reading both specs.

**Cost:** the published spec must be edited. Cheap because nothing depends on it yet, the change is a pure relabeling, and we're pre-v0.

If this amendment is acceptable, the implementation comments in this thread (B–F below) all assume Miden-native layout. If you'd rather keep the spec's original layout, the Miden-side opcode and MASM helpers grow ~20 cycles per hash for state reshuffling — feasible but wasteful.

---
---

## Comment B — Miden-side changes to support the PVM: transcript shape and `LogPrecompile` opcode

**TL;DR:** The Miden VM already has a `log_precompile` opcode and a `pc_transcript_state` public input — but the transcript is currently a sponge, not the tagged binary tree the PVM needs. We can convert it with a **small AIR-level edit** (rewrite the consumer-side hasher bus expression in one file) plus a transcript-shape change in `core::precompile`. **No new hasher chiplet operation, no helper-budget change, no public-input layout change.** The existing MASM wrapper gets 1 cycle cheaper, leaves the new transcript root on top of the stack as a free bonus, and the assertion is consumed cleanly.

This comment describes the deliverable in detail. Sibling comments (C–F) cover MASM helpers, host-side DAG, data structures, and Keccak adaptation.

### Context (what exists today)

The Miden VM has a working precompile transcript subsystem:

| Layer | Type / symbol | File |
|---|---|---|
| Opcode | `Operation::LogPrecompile` (`0b0101_1110`) | `core/src/operations/mod.rs:122, 598-600` |
| Handler | `op_log_precompile` | `processor/src/execution/operations/crypto_ops/mod.rs:462-508` |
| Processor state | `System.pc_transcript_state: Word` | `processor/src/trace/parallel/processor.rs:434-439` |
| Sponge type | `PrecompileTranscript { state: Word }` | `core/src/precompile.rs:332-390` |
| Public input | `pc_transcript_state` at `[36..40]` of `PublicInputs::to_elements()` | `air/src/lib.rs:67, 77, 104-140` |
| Consumer-side bus expression | `chiplet_requests.rs:288-322` (`g.batch(op_flags.log_precompile(), …)`) | `air/src/constraints/lookup/buses/chiplet_requests.rs` |
| Virtual-table bus add/remove | `pc_transcript_state` thread | `air/src/constraints/lookup/buses/range_logcap.rs:42-68` |
| MASM wrapper | `pub proc log_precompile_request` (6 cycles) | `crates/lib/core/asm/sys/mod.masm:38-49` |

Today's opcode reads `COMM` from `stack[0..4]_cur` and `TAG` from `stack[4..8]_cur`, reads `CAP_PREV` from helpers, hashes via the hasher chiplet's `linear_hash_init` + `return_state` bus messages, and writes the 12-felt permutation output to `next.stack[0..12]` as `[R0, R1, CAP_NEXT]`. The current bus expression in `chiplet_requests.rs:288-322`:

```rust
g.batch(op_flags.log_precompile(), move |b| {
    let log_addr_e: LB::Expr = log_addr.into();
    let logpre_in: [LB::Expr; 12] = [
        // RATE0 = COMM (from current stack)
        stk.get(STACK_COMM_RANGE.start + 0..4),
        // RATE1 = TAG  (from current stack)
        stk.get(STACK_TAG_RANGE.start + 0..4),
        // CAP   = CAP_PREV (from helpers)
        user_helpers[HELPER_CAP_PREV_RANGE.start + 0..4],
    ];
    let logpre_out: [LB::Expr; 12] = [
        // RATE0' = R0       (next stack[0..4])
        stk_next.get(STACK_R0_RANGE.start + 0..4),
        // RATE1' = R1       (next stack[4..8])
        stk_next.get(STACK_R1_RANGE.start + 0..4),
        // CAP'   = CAP_NEXT (next stack[8..12])
        stk_next.get(STACK_CAP_NEXT_RANGE.start + 0..4),
    ];
    b.remove(HasherMsg::linear_hash_init(log_addr_e.clone(), logpre_in));
    let return_addr = log_addr_e + last_off;
    b.remove(HasherMsg::return_state(return_addr, logpre_out));
});
```

The `pc_transcript_state` virtual-table bus (`range_logcap.rs:42-68`) "removes" `cap_prev` from helper columns and "adds" `cap_next` from `next.stack[8..12]`. The result becomes the public input.

### What the PVM expects from the transcript

The PVM's transcript is a binary tree whose root is a single 4-felt RPO hash. Every "append assertion to transcript" step is one node of tag `0` (Transcript), with the preimage:

```
state[0..4]   = prev_root           // RATE0  (lhs = previous transcript prefix)
state[4..8]   = assertion           // RATE1  (rhs = the new assertion)
state[8..12]  = [0, 0, 0, VERSION]  // CAPACITY (tag=0, pa=0, pb=0, version constant)
new_root      = RPO(state)[0..4]    // DIGEST_RANGE = RATE0' post-permutation
```

(Layout assumes Miden-native — see Comment A.)

The version constant is fixed by the AIR. Bumping it invalidates all prior PVM proofs. Initial transcript root is `ZERO_HASH = [0, 0, 0, 0]`, matching the PVM's trivial-True base case — no special boundary handling needed.

### The proposed `LogPrecompile` opcode contract

**Stack contract:**

```
stack before: [..., assertion at stack[8..12]_cur, ...] (top 8 felts: caller's padding)
stack after:  [..., new_root  at stack[8..12]_next, ...] (with the rest reordered, see below)
```

The opcode reads the assertion from the **third stack word** (`stack[8..12]_cur`, not the top) and uses helper columns for `prev_root` (same helper slot as today's `cap_prev`, just renamed). The capacity IV `[0, 0, 0, VERSION]` is **not** in any trace columns — it's an AIR compile-time constant baked directly into the bus expression.

The 12-felt permutation output is written to `next.stack[0..12]` in **reordered** form so that `new_root = R0'` lands at `stack[8..12]_next`:

```
stack[0..4]_next   = R1'        (junk, from chiplet's natural state[4..8] post-permutation)
stack[4..8]_next   = CAP'       (junk, from chiplet's natural state[8..12] post-permutation)
stack[8..12]_next  = R0' = new_root
stack[12..16]_next = stack[12..16]_cur  (identity)
```

**MASM wrapper (5 cycles, 1 cheaper than today, keeps `new_root` on top):**

```masm
pub proc log_precompile_request
    # Input:  [ASSERTION, caller_stack...]
    # Output: [new_root,  caller_stack...]
    padw padw log_precompile dropw dropw
end
```

Stack trace, starting from `[A0..A3, X4..X15]` (assertion `A` on top, caller data `X` below):
1. `padw` → `[0..0, A, X4..X11]`, overflow `[X12..X15]`
2. `padw` → `[0..0, 0..0, A, X4..X7]`, overflow `[X12..X15, X8..X11]`
3. `log_precompile` → reads assertion at `stack[8..12]_cur`, writes reordered output to `stack[0..12]_next`. Result: `[j1, j2, new_root, X4..X7]`
4. `dropw` → `[j2, new_root, X4..X7, X8..X11]`, overflow `[X12..X15]`
5. `dropw` → `[new_root, X4..X15]`, overflow empty

Final: `[new_root, X4..X15]`. Assertion consumed, full caller stack preserved, `new_root` on top.

A drop-new_root variant (`padw padw log_precompile dropw dropw dropw` = 6 cycles) exists for callers that don't want the root.

**Why read the assertion from `stack[8..12]_cur` instead of the top?** Because then `padw padw` is the only positioning the wrapper needs. If the opcode read from `stack[0..4]_cur`, the wrapper would have to be `padw padw movupw.2 log_precompile dropw dropw` = 6 cycles, eliminating the 1-cycle savings. Reading at depth 8 matches where the pads naturally sink the assertion.

**Why reorder the output as `[R1', CAP', R0']`?** So that `new_root = R0'` lands at `stack[8..12]_next` — symmetric with where the assertion was read from. After two `dropw`s drop the junk above, `new_root` is naturally at the top.

### AIR-level changes

**No new hasher chiplet operation.** The existing HPERM-style bus interaction is reused unchanged on the chiplet's side. The only edit on the AIR side is rewriting the **consumer's** bus expression in `chiplet_requests.rs:288-322`. The hasher chiplet still emits its 12-felt input/output state in the natural `[RATE0, RATE1, CAP]` order; the consumer's expression maps each state position to a different trace column than today.

**The new bus expression** (replacing the snippet quoted earlier):

```rust
g.batch(op_flags.log_precompile(), move |b| {
    let log_addr_e: LB::Expr = log_addr.into();

    // Input state [RATE0, RATE1, CAPACITY]
    //   = [prev_root, assertion, (0, 0, 0, VERSION)]
    let logpre_in: [LB::Expr; 12] = [
        // RATE0 = prev_root, from helper columns
        user_helpers[HELPER_PREV_ROOT_RANGE.start + 0].into(),
        user_helpers[HELPER_PREV_ROOT_RANGE.start + 1].into(),
        user_helpers[HELPER_PREV_ROOT_RANGE.start + 2].into(),
        user_helpers[HELPER_PREV_ROOT_RANGE.start + 3].into(),
        // RATE1 = assertion, from third stack word at the current row
        stk.get(STACK_ASSERTION_RANGE.start + 0).into(),  // stack[8]_cur
        stk.get(STACK_ASSERTION_RANGE.start + 1).into(),
        stk.get(STACK_ASSERTION_RANGE.start + 2).into(),
        stk.get(STACK_ASSERTION_RANGE.start + 3).into(),
        // CAPACITY = [0, 0, 0, VERSION], all AIR compile-time constants
        LB::Expr::ZERO,
        LB::Expr::ZERO,
        LB::Expr::ZERO,
        LB::Expr::from(CURRENT_VERSION),
    ];

    // Output state [RATE0', RATE1', CAPACITY']
    //   = [new_root, junk_R1, junk_CAP]
    // Reordered so new_root lands at next.stack[8..12], junks at [0..8].
    let logpre_out: [LB::Expr; 12] = [
        // RATE0' = new_root, at next.stack[8..12]
        stk_next.get(STACK_NEW_ROOT_RANGE.start + 0).into(),
        stk_next.get(STACK_NEW_ROOT_RANGE.start + 1).into(),
        stk_next.get(STACK_NEW_ROOT_RANGE.start + 2).into(),
        stk_next.get(STACK_NEW_ROOT_RANGE.start + 3).into(),
        // RATE1' = junk, at next.stack[0..4]
        stk_next.get(STACK_JUNK_R1_RANGE.start + 0).into(),
        stk_next.get(STACK_JUNK_R1_RANGE.start + 1).into(),
        stk_next.get(STACK_JUNK_R1_RANGE.start + 2).into(),
        stk_next.get(STACK_JUNK_R1_RANGE.start + 3).into(),
        // CAPACITY' = junk, at next.stack[4..8]
        stk_next.get(STACK_JUNK_CAP_RANGE.start + 0).into(),
        stk_next.get(STACK_JUNK_CAP_RANGE.start + 1).into(),
        stk_next.get(STACK_JUNK_CAP_RANGE.start + 2).into(),
        stk_next.get(STACK_JUNK_CAP_RANGE.start + 3).into(),
    ];

    b.remove(HasherMsg::linear_hash_init(log_addr_e.clone(), logpre_in));
    let return_addr = log_addr_e + last_off;
    b.remove(HasherMsg::return_state(return_addr, logpre_out));
});
```

With the new range constants in `air/src/trace/log_precompile.rs`:

```rust
pub const HELPER_ADDR_IDX: usize = 0;
pub const HELPER_PREV_ROOT_RANGE: Range<usize> = 1..5;  // renamed from HELPER_CAP_PREV_RANGE

pub const STACK_ASSERTION_RANGE: Range<usize>  =  8..12;  // assertion read at depth 8
pub const STACK_NEW_ROOT_RANGE:  Range<usize>  =  8..12;  // new_root lands at next-row depth 8
pub const STACK_JUNK_R1_RANGE:   Range<usize>  =  0..4;
pub const STACK_JUNK_CAP_RANGE:  Range<usize>  =  4..8;

// DELETE: STACK_COMM_RANGE, STACK_TAG_RANGE, STACK_R0_RANGE, STACK_R1_RANGE,
// STACK_CAP_NEXT_RANGE, HELPER_CAP_PREV_RANGE
```

**Helper register layout** (unchanged budget — 5 felts used, 5 free):
- `addr` (1 felt)
- `prev_root` (4 felts) — consumed by `pc_transcript_state` virtual-table bus "remove"

**`pc_transcript_state` virtual-table bus** (`range_logcap.rs:42-68`):
- Remove side: reads `prev_root` from helper columns. Same as today's `cap_prev`, only the range constant rename.
- Add side: reads `new_root` from `next.stack[8..12]`. Same column indices as today's `STACK_CAP_NEXT_RANGE`, only the range constant rename.

### Trace-column delta vs today

| Aspect | Today | Proposed |
|---|---|---|
| Hasher bus tuple width | 24 felts (12 in + 12 out) | **24 felts** (same HPERM format) |
| New hasher chiplet operation | no | **no** |
| Helper felts used | 5 (`addr + cap_prev`) | 5 (`addr + prev_root`) |
| Stack columns touched next row | 12 | 12 (8 junk + 4 new_root, reordered) |
| Assertion read from | `stack[0..8]_cur` (COMM ‖ TAG) | `stack[8..12]_cur` (third word) |
| `new_root` lands at | — (CAP_NEXT at `next.stack[8..12]`) | `next.stack[8..12]` (reordered from R0') |
| Capacity IV | `cap_prev` from helpers | AIR constants `[0, 0, 0, VERSION]` |
| MASM wrapper | 6 cycles | **5 cycles**, keeps `new_root` on top |
| `pc_transcript_state` public input | sponge capacity at `[36..40]` | tree root at `[36..40]` (same slot, new semantics) |

### Files to touch

1. **`core/src/precompile.rs:332-390`** — replace `PrecompileTranscript::record(PrecompileCommitment)` with `PrecompileTranscript::append(assertion: Word)`. Add `pub const CURRENT_VERSION: Felt = Felt::new(0)`. Initial state stays `[0, 0, 0, 0]` (matches PVM's trivial-True). Delete `finalize()` — no longer meaningful. The `PrecompileCommitment` struct can be deleted (or kept as a host-side bookkeeping helper, but it no longer drives the transcript).

2. **`processor/src/execution/operations/crypto_ops/mod.rs:462-508`** — rewrite `op_log_precompile`. New body:

   ```rust
   pub(super) fn op_log_precompile<P: Processor, T: Tracer>(
       processor: &mut P,
       tracer: &mut T,
   ) -> Result<OperationHelperRegisters, OperationError> {
       // Read assertion from stack[8..12]_cur (third stack word, not the top)
       let assertion: Word = processor.stack().get_word(8);

       // Read prev_root from processor state
       let prev_root = processor.precompile_transcript_state();

       // Build the 12-element hasher state in Miden-native layout:
       //   [RATE0 = prev_root, RATE1 = assertion, CAPACITY = [0, 0, 0, VERSION]]
       let mut hasher_state: [Felt; STATE_WIDTH] = [ZERO; 12];
       hasher_state[STATE_RATE_0_RANGE].copy_from_slice(prev_root.as_slice());
       hasher_state[STATE_RATE_1_RANGE].copy_from_slice(assertion.as_slice());
       hasher_state[STATE_CAP_RANGE.start + 3] = CURRENT_VERSION;
       // (state[8..11] left as ZERO from initialization)

       let (addr, output_state) = processor.hasher().permute(hasher_state)?;

       // Extract the new transcript root (DIGEST_RANGE = first 4 output felts)
       let new_root: Word = output_state[DIGEST_RANGE].try_into().unwrap();

       // Update the processor's transcript state
       processor.set_precompile_transcript_state(new_root);

       // Write the reordered output to next-row stack:
       //   stack[0..4]_next  = R1' (junk)
       //   stack[4..8]_next  = CAP' (junk)
       //   stack[8..12]_next = R0' = new_root
       let r1: Word  = output_state[STATE_RATE_1_RANGE].try_into().unwrap();
       let cap: Word = output_state[STATE_CAP_RANGE].try_into().unwrap();
       processor.stack_mut().set_word(0, &r1);          // junk
       processor.stack_mut().set_word(4, &cap);         // junk
       processor.stack_mut().set_word(8, &new_root);    // meaningful

       tracer.record_hasher_permute(hasher_state, output_state);

       // Helper register: hasher addr + prev_root (for AIR bus interaction)
       Ok(OperationHelperRegisters::LogPrecompile { addr, prev_root })
   }
   ```

3. **`air/src/constraints/lookup/buses/chiplet_requests.rs:288-322`** — rewrite the `log_precompile` batch (full snippet above). This is the central edit.

4. **`air/src/trace/log_precompile.rs`** — rename column-range constants:
   - `HELPER_CAP_PREV_RANGE` → `HELPER_PREV_ROOT_RANGE`
   - `STACK_CAP_NEXT_RANGE` → `STACK_NEW_ROOT_RANGE`
   - Delete `STACK_COMM_RANGE`, `STACK_TAG_RANGE`, `STACK_R0_RANGE`, `STACK_R1_RANGE`
   - Add `STACK_ASSERTION_RANGE = 8..12`, `STACK_JUNK_R1_RANGE = 0..4`, `STACK_JUNK_CAP_RANGE = 4..8`

5. **`air/src/constraints/lookup/buses/range_logcap.rs:42-68`** — the `pc_transcript_state` virtual-table bus add/remove. Update column references to use the renamed range constants. No structural change.

6. **`air/src/constraints/lookup/buses/hash_kernel.rs`** and **`air/src/constraints/chiplets/bus/hash_kernel.rs`** — verify the provider side still emits the standard HPERM tuples. No changes expected; the chiplet doesn't know about log_precompile semantics.

7. **`crates/lib/core/asm/sys/mod.masm:38-49`** — rewrite the wrapper:

   ```masm
   #! Logs a precompile assertion onto the transcript root.
   #!
   #! Input  : [ASSERTION, caller_stack...]
   #! Output : [new_root,  caller_stack...]
   #! Cycles : 5
   pub proc log_precompile_request
       padw padw log_precompile dropw dropw
   end
   ```

   Optionally add a `log_precompile_request_drop` variant (6 cycles, no `new_root` on top).

8. **`processor/src/trace/chiplets/aux_trace/virtual_table.rs:170-256`** — update column references for the `pc_transcript_state` add/remove pair to use the renamed ranges. No structural change.

9. **`core/src/operations/mod.rs:122, 598-600`** — update the doc comment on `Operation::LogPrecompile`.

### Open questions / implementation hints

- **Confirm LogUp allows non-contiguous column references.** The new bus expression reads `output[0..4]` from `stack[8..12]_next`, `output[4..8]` from `stack[0..4]_next`, `output[8..12]` from `stack[4..8]_next`. Each tuple position is a free AIR expression in LogUp, so this should be fine, but worth a sanity check during implementation.
- **`CURRENT_VERSION` sync between Rust and MASM.** The Rust constant in `core::precompile` and the MASM `const.CURRENT_VERSION=0` in `sys/mod.masm` (or `crypto/pvm.masm`, see Comment C) must agree. Add a unit test that parses the MASM file and checks the constant against `miden_core::precompile::CURRENT_VERSION`. Bumping the version requires bumping both in lockstep.
- **Audit existing callers of `log_precompile_request`.** The wrapper signature changes from "consume `[COMM, TAG]`" to "consume `[ASSERTION]`, produce `[new_root]`". Existing callers (keccak256, sha512, eddsa, ecdsa per a recent code search) need to be updated to compute a single 4-felt assertion and pass it to the new wrapper. This is covered by the keccak comment (F) and equivalent migration steps for sha512/eddsa/ecdsa.
- **`PrecompileCommitment` and `PrecompileVerifier`.** Both can be deleted once the migration is complete. They're vestiges of the sponge-based "verify by re-running" model that the PVM replaces. See Comment E.

### Risk / blast radius

- **Public-input layout is unchanged.** The 4 felts at `[36..40]` still hold a transcript value; only the semantic changes from "sponge capacity" to "tree root." External verifiers that consume the public inputs need to be told about the new semantic but don't need a layout change.
- **No new hasher chiplet operation.** The hasher chiplet code is untouched. The blast radius of this change is one bus expression in `chiplet_requests.rs`, one struct in `core/src/precompile.rs`, the opcode handler, and column-range renames in `air/src/trace/log_precompile.rs`.
- **MASM compatibility.** Existing `log_precompile_request` callers will break — but they're all in stdlib, so the migration is a single-PR change.

---
---

## Comment C — MASM primitives for hashing PVM-shaped nodes

**TL;DR:** Add a `crypto::pvm` stdlib module with one helper per PVM node tag (FieldLeaf, FieldBinOp, GroupCreate, GroupBinOp, KeccakDigestLeaf, Keccak). Each helper is ~15 cycles and consists of `push.VERSION.PB.PA.TAG movdnw.2 hperm <squeeze>`. Transcript nodes (tag 0) are handled by the `log_precompile` opcode directly — see Comment B — so no helper for tag 0.

### Background

PVM nodes have the preimage shape (Miden-native, see Comment A):

```
state[0..8]   = val[8]                  // RATE
state[8..12]  = [tag, pa, pb, version]  // CAPACITY
hash          = RPO(state)[0..4]        // first 4 output positions
```

The MASM caller produces `val[8]` on top of the stack — this is the natural output of any 8-felt computation, e.g., concatenation of two 4-felt commitment hashes. The helper then pushes the 4-felt capacity word `[TAG, PA, PB, VERSION]` and uses `movdnw.2` to slot it in below `val[8]`, putting the 12 felts in the exact `hperm` layout. After `hperm`, the digest is at `state[0..4]` (top of stack). Two `swapw dropw` pairs peel off the 8 felts of `R1'` and `CAP'` to leave just the digest.

### Pattern

```masm
# Caller arrives with: [val[0..8], <scalar params>, ...]
# Helper builds the capacity word from the scalar params and the constant TAG/VERSION.

push.VERSION.PB.PA.TAG     # top word becomes [TAG, PA, PB, VERSION]
movdnw.2                    # move that word down by 2 word positions → stack[8..12]
hperm                       # state[0..12] permuted in place
swapw dropw swapw dropw     # keep state[0..4] as the digest, drop the rest
# Result: [digest, ...]
```

Cycle cost per node hash:
- `push.4` for the capacity word: 4 cycles (or 1 if combined as `push.VAL`)
- `movdnw.2`: 1 cycle
- `hperm`: 1 cycle
- `swapw dropw swapw dropw`: 4 cycles
- **Total: ~10–15 cycles** depending on whether scalar params come from the stack or are immediates.

### Draft helpers

```masm
# crates/lib/core/asm/crypto/pvm.masm

const.CURRENT_VERSION=0   # MUST match miden_core::precompile::CURRENT_VERSION; unit test enforces

#! Internal: drop the trailing 8 felts after hperm, keeping the digest on top.
proc.squeeze_digest
    swapw dropw swapw dropw
end

#! Hash a PVM KeccakDigestLeaf node (tag = 3, no params).
#! Stack input : [digest_u32[0..8], ...]
#! Stack output: [digest_hash(4), ...]
pub proc hash_keccak_digest_leaf
    push.CURRENT_VERSION.0.0.3   # cap = [TAG=3, PA=0, PB=0, VERSION]
    movdnw.2
    hperm
    exec.squeeze_digest
end

#! Hash a PVM FieldLeaf node (tag = 2, pa = field_ty).
#! Stack input : [val_u32[0..8], field_ty, ...]
#! Stack output: [field_hash(4), ...]
pub proc hash_field_leaf
    # Build cap = [TAG=2, PA=field_ty, PB=0, VERSION] from the field_ty under val[8]
    movup.8                        # bring field_ty to the top
    push.CURRENT_VERSION.0         # [VERSION, 0, field_ty, val[0..8], ...]
    movup.2                        # [field_ty, VERSION, 0, val[0..8], ...]
    push.2                         # [TAG=2, field_ty, VERSION, 0, val[0..8], ...]  (cap word forms top word)
    swap.2                         # adjust order to [TAG, PA=field_ty, PB=0, VERSION]
    movdnw.2
    hperm
    exec.squeeze_digest
end
# (exact movup/swap sequence to be confirmed when implementing — pattern is "build cap word, movdnw.2, hperm")

#! Hash a PVM FieldBinOp node (tag = 4, pa = field_ty, pb = op).
#! Stack input : [LHS_HASH(4), RHS_HASH(4), field_ty, op, ...]
#! Stack output: [out_hash(4), ...]
pub proc hash_field_binop
    # val[0..8] = LHS ‖ RHS already on top; build cap = [TAG=4, PA=field_ty, PB=op, VERSION]
    push.CURRENT_VERSION
    movup.10
    movup.10
    push.4
    movdnw.2
    hperm
    exec.squeeze_digest
end

# Similar: hash_group_create (tag 5), hash_group_binop (tag 6), hash_keccak (tag 7)
```

### Files

- **`crates/lib/core/asm/crypto/pvm.masm`** (new) — the helpers above.
- **`docs/src/user_docs/assembly/pvm.md`** (new, optional) — user-facing doc.
- A unit test in the assembler test suite that parses `pvm.masm`, extracts the `const.CURRENT_VERSION` value, and asserts equality with `miden_core::precompile::CURRENT_VERSION`. This is the version-sync guarantee.

### Open questions

- The exact `movup`/`swap` sequence in `hash_field_leaf`/`hash_field_binop` is approximate — minor adjustments depending on Miden's stack juggling primitives. The canonical pattern to internalize: **caller keeps `val[0..8]` on top; helper builds the cap word and `movdnw.2`s it behind val[8]; then `hperm` + `squeeze_digest`**. The exact instructions are mechanical.
- We probably want a dedicated stdlib unit test per helper that hashes a known input and compares against a Rust-side reference computation of the same node.

---
---

## Comment D — Event-driven DAG registration (host side)

**TL;DR:** Field and group arithmetic happens in the PVM's target fields, which are different from Miden's Goldilocks. The Miden VM cannot compute the result *values*, but MASM **can** compute the result *commitment hashes* (RPO is the same regardless of the underlying field). So the design is: MASM computes the commitment hash for each new node via the `crypto::pvm` helpers; the host maintains a typed expression DAG keyed by commitment hash; MASM emits an event for each new node, and the host's event handler looks up the operand values, computes the new value, and inserts it into the DAG.

### Background

The PVM's field/group chips own canonical pointers for every value (see comment 1, §8.2 / §8.3). The Miden VM never sees these values directly. What the Miden VM does see — via the MASM stack — is a stream of 4-felt commitment hashes. Each hash is a function of operand commitments and the operation's tag/params (tag 4 for FieldBinOp, tag 6 for GroupBinOp, etc.) — all data that MASM has on hand.

The host needs to maintain enough state across the execution to reconstruct the DAG when serializing the PVM input. That state is:

```rust
pub struct PrecompileDag {
    field_table:   HashMap<FieldPtr, FieldElement>,
    group_table:   HashMap<GroupPtr, GroupElement>,
    chunk_store:   HashMap<ChunkPtr, Vec<[Felt; 8]>>,
    digest_store:  HashMap<DigestPtr, [u8; 32]>,
    // Commitment hash → typed node reference
    nodes:         HashMap<[Felt; 4], TranscriptNode>,
    // Ordered list of root-level transcript leaves, as appended via log_precompile
    transcript_leaves: Vec<[Felt; 4]>,
    version: Felt,
}
```

This struct ends up serialized as the PVM's trace-generation input. See Comment E.

### Flow

For a `FieldBinOp::Add`:

```
MASM                                     Host
─────                                    ────
1. lhs_hash, rhs_hash already on stack   (DAG already has both)

2. compute c = hash_field_binop(...)
   via crypto::pvm helper

3. push c

4. emit miden::pvm::field::op::add  ───>  PvmEventHandler:
                                            lock dag
                                            read c, lhs_hash, rhs_hash, field_ty, op from stack
                                            (defensive) verify c == recompute(field_ty, lhs, rhs)
                                            v_lhs = dag.field_table[dag.nodes[lhs_hash].ptr]
                                            v_rhs = dag.field_table[dag.nodes[rhs_hash].ptr]
                                            v_out = v_lhs + v_rhs    (in target field)
                                            ptr_out = allocate canonical FieldPtr for v_out
                                            dag.nodes.insert(c, FieldNode { ptr_out })
                                            return ExtendStack([])  (or push diagnostics)
                                        <────
5. continue
```

The "compute commitment in MASM, register in host" split has a nice property: the AIR enforces (via the `crypto::pvm` helpers' `hperm` calls and the LogUp bus) that the commitment hash is a correct RPO of the operand commitments and the tag — so the host can trust the commitment value it sees. The host's only job is to maintain the value table; the cryptographic binding is done by Miden.

### Mutability under the `EventHandler` trait

The `EventHandler` trait at `processor/src/host/handlers.rs:24-26`:

```rust
pub trait EventHandler: Send + Sync + 'static {
    fn on_event(&self, process: &ProcessorState)
        -> Result<Vec<AdviceMutation>, EventError>;
}
```

Note `&self`, not `&mut self`. The handler can't directly mutate its own state. Two ways to handle this:

1. **Interior mutability (recommended).** Each PVM handler holds an `Arc<Mutex<PrecompileDag>>`. All handlers share the same `Arc`. Locking cost is one mutex acquire per event, negligible vs the underlying RPO hash. No trait changes.
2. **New `AdviceMutation::ExtendPrecompileDag` variant.** Cleaner from the trait perspective but requires the handler to know what to insert without reading the DAG, which doesn't work for ops whose result depends on existing entries (like `FieldBinOp::Add`). Rejected.

```rust
pub struct PvmEventHandler {
    dag: Arc<Mutex<PrecompileDag>>,
}

impl EventHandler for PvmEventHandler {
    fn on_event(&self, process: &ProcessorState)
        -> Result<Vec<AdviceMutation>, EventError>
    {
        let event_id = EventId::from_felt(process.get_stack_item(0));
        let mut dag = self.dag.lock().map_err(|_| EventError::PoisonedDag)?;
        match dispatch(event_id) {
            PvmOp::FieldOpAdd => self.handle_field_binop(FieldOp::Add, &mut dag, process),
            PvmOp::FieldOpSub => self.handle_field_binop(FieldOp::Sub, &mut dag, process),
            // ...
        }
    }
}
```

Lifecycle from the user's prover code:

```rust
let dag = Arc::new(Mutex::new(PrecompileDag::default()));
let handler = Arc::new(PvmEventHandler { dag: Arc::clone(&dag) });
host.register_handler("miden::pvm::field::op::add",   Arc::clone(&handler))?;
host.register_handler("miden::pvm::field::op::sub",   Arc::clone(&handler))?;
// ... register the rest
prover.execute(...)?;
let dag = Arc::try_unwrap(dag).unwrap().into_inner().unwrap();
// dag is now ready to feed to the PVM
```

### Event names (draft)

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
miden::pvm::keccak::hash       # subsumes the existing keccak256 event for PVM-bound use
```

EventIds are derived deterministically from the names via BLAKE3 (see `core/src/events/mod.rs:42-58`), so they're stable across runs.

### Files

- **`core/src/precompile/dag.rs`** (new) — `PrecompileDag`, `FieldNode`, `GroupNode`, `ChunkStore`, serialization.
- **`crates/lib/core/src/handlers/pvm.rs`** (new) — `PvmEventHandler` with `Arc<Mutex<PrecompileDag>>` and per-op handler functions.
- **`core/src/events/`** — event-name constants for the new events.
- **MASM emit sites** — each `crypto::pvm::hash_*` proc that needs a host registration step adds an `emit.miden::pvm::*` after it. (Or the helper itself emits — design choice.)

### Open questions

- **Per-execution vs per-host DAG lifetime.** Per-execution is simpler and matches the current `pc_requests` semantics (cleared on each `prove` call). Per-host enables caching across multiple executions but is more complex. Default to per-execution.
- **Defensive recomputation of commitments.** The host could recompute each commitment from operand commitments and tag/params, asserting equality with the value MASM passed. This would catch certain prover bugs early but adds host-side hashing work. Probably worth it as a debug-mode check at minimum.
- **What does the handler push back to MASM?** The handler returns `AdviceMutation::ExtendStack { values }`. For most operations, MASM doesn't need anything back (the commitment is already on the stack). For some — e.g., `FieldLeaf::register` from a value that the host generates — the handler might push the commitment hash. Per-operation design.

---
---

## Comment E — `PrecompileRequest` → `PrecompileDag` data structure evolution

**TL;DR:** The current `Vec<PrecompileRequest>` (each entry is `{event_id, calldata: Vec<u8>}`) is replaced by a single typed `PrecompileDag` that flows through `ExecutionOutput → TraceBuildOutput → ExecutionTrace → ExecutionProof`. The DAG is the PVM's trace-generation input. The old `PrecompileVerifier` registry — which re-ran each precompile in-process for verification — is deleted, replaced by "produce a STARK proof from the PVM."

### Current state

```rust
// core/src/precompile.rs:72-121
pub struct PrecompileRequest {
    event_id: EventId,
    calldata: Vec<u8>,
}

// processor/src/host/advice/mod.rs:52-57
pub struct AdviceProvider {
    stack: VecDeque<Felt>,
    map:   AdviceMap,
    store: MerkleStore,
    pc_requests: Vec<PrecompileRequest>,
}

// processor/src/host/mod.rs:34-55
pub enum AdviceMutation {
    ExtendStack { values: Vec<Felt> },
    ExtendMap { other: AdviceMap },
    ExtendMerkleStore { infos: Vec<InnerNodeInfo> },
    ExtendPrecompileRequests { data: Vec<PrecompileRequest> },
}

// core/src/proof.rs:20-45
pub struct ExecutionProof {
    proof: Vec<u8>,
    hash_fn: HashFunction,
    pc_requests: Vec<PrecompileRequest>,
}
```

Verification today: a `PrecompileVerifier` registry in `core/src/precompile.rs:200-283` knows how to re-run each precompile from the raw `calldata` bytes and reproduce its commitment.

### Proposed `PrecompileDag`

```rust
pub struct PrecompileDag {
    // Value tables, keyed by canonical pointer
    field_table:    HashMap<FieldPtr,  FieldNode>,
    group_table:    HashMap<GroupPtr,  GroupNode>,
    chunk_store:    HashMap<ChunkPtr,  Vec<[Felt; 8]>>,
    digest_store:   HashMap<DigestPtr, [u8; 32]>,

    // Commitment hash → typed node reference
    nodes:          HashMap<[Felt; 4], TranscriptNode>,

    // Ordered list of root-level transcript leaves (one per log_precompile call)
    transcript_leaves: Vec<[Felt; 4]>,

    // Version stamp matching CURRENT_VERSION at the time of generation
    version: Felt,
}

pub enum TranscriptNode {
    True,                                              // ZERO_HASH base case
    Field    { field_ty: u8, ptr: FieldPtr },
    Group    { group_ty: u8, ptr: GroupPtr },
    Keccak   { digest_ptr: DigestPtr, chunks_ptr: ChunkPtr, len_bytes: u64 },
    KeccakDigestLeaf { ptr: DigestPtr },
    Chunks   { ptr: ChunkPtr, n_chunks: u64 },
    FieldOp  { op: FieldOp, field_ty: u8, lhs: FieldPtr, rhs: FieldPtr, out: FieldPtr },
    GroupOp  { op: GroupOp, group_ty: u8, lhs: GroupPtr, rhs: GroupPtr, out: GroupPtr },
}
```

The DAG flows through:

```
PvmEventHandler
   │ inserts into Arc<Mutex<PrecompileDag>>
   ▼
After execution, Arc::try_unwrap → PrecompileDag
   │
   ▼
ExecutionOutput { ..., precompile_dag: PrecompileDag }
   │
   ▼
TraceBuildOutput { ..., precompile_dag: PrecompileDag }
   │
   ▼
ExecutionTrace { ..., precompile_dag: PrecompileDag }
   │
   ▼
ExecutionProof { proof, hash_fn, precompile_dag: PrecompileDag }
                                  │
                                  ▼
                           Serialized → PVM trace generation input
```

Note: the **transcript root** is still a Miden public input at `[36..40]` (see Comment B) — it's the only PVM-facing output that's part of the Miden STARK proof. The `PrecompileDag` is auxiliary witness data that travels alongside the proof.

### Files affected

- **`core/src/precompile.rs`** — add `PrecompileDag`, `TranscriptNode`, `FieldNode`, `GroupNode`. Add `Serializable`/`Deserializable` impls.
- **`core/src/proof.rs:20-45`** — add `precompile_dag: PrecompileDag` field. Optionally keep `pc_requests` during a transition window.
- **`processor/src/host/advice/mod.rs:52-57, 479-481`** — replace or augment `pc_requests` with the DAG (or keep DAG separate and remove `pc_requests` after migration).
- **`processor/src/host/mod.rs:34-55`** — keep `AdviceMutation` as-is; the DAG is mutated through the shared `Arc<Mutex>`, not via mutations.
- **`processor/src/fast/mod.rs:633-638`** — add `precompile_dag` field to `ExecutionOutput`.
- **`processor/src/trace/mod.rs:54-217`** — thread the DAG through `TraceBuildOutput` and `ExecutionTrace`.
- **`prover/src/lib.rs`** — proof construction passes the DAG through to `ExecutionProof::new`.

### What gets deleted

- `PrecompileRequest` struct (eventually).
- `PrecompileCommitment` struct.
- `PrecompileVerifier` trait and its registry.
- `AdviceMutation::ExtendPrecompileRequests` variant.
- The `take_precompile_requests()` method on `AdviceProvider`.
- The `pc_requests` field on `AdviceProvider` and `ExecutionProof`.

This cleanup happens after all current callers (keccak256, sha512, eddsa, ecdsa) are migrated to the new event-handler pattern (Comment D).

### Open questions

- **Bundle vs separate field on `ExecutionProof`.** Easiest first cut: add `precompile_dag` as a new field alongside `pc_requests` and migrate callers one at a time. Final cut: delete `pc_requests`.
- **Serialization format.** Standard `Serializable`/`Deserializable` impls following the rest of `core/src/precompile.rs`. Worth ensuring the format is forward-compatible (length prefix on each table) so DAG fields can be added without breaking existing PVM proofs.

---
---

## Comment F — Keccak handler adaptation for PVM commitments

**TL;DR:** The existing `KeccakPrecompile` handler at `crates/lib/core/src/handlers/keccak256.rs` already does almost everything right — u32-LE encoding for both input and output, `len_bytes` tracked, raw bytes captured. Only the **commitment shape** changes: from `(tag = [event_id, len_bytes, 0, 0], comm = P2(P2(input) ‖ P2(digest)))` to the PVM tag-7 Keccak node hash. The keccak handler also takes on responsibility for inserting the digest leaf, the chunks, and the keccak edge into the shared `PrecompileDag` (Comment D).

### What stays

- u32-LE packing for inputs (4 bytes per felt) — already matches the PVM spec's `val[8]` format.
- u32-LE digest output (8 felts of 4 bytes each).
- `len_bytes` from the stack.
- Raw bytes captured and hashed off-chip via `miden_crypto::hash::keccak::Keccak256`.

### What changes

The handler computes a **PVM Keccak node hash** instead of the current sponge commitment. The Keccak node (tag 7) commits to two children: a `KeccakDigestLeaf` (tag 3) and a `Chunks` binding (sponge over the input chunks). All three are PVM nodes that need to exist in the DAG.

```rust
fn on_event(&self, process: &ProcessorState)
    -> Result<Vec<AdviceMutation>, EventError>
{
    let mut dag = self.dag.lock()?;

    // 1. Read input from memory (unchanged)
    let ptr = process.get_stack_item(1).as_canonical_u64();
    let len_bytes = process.get_stack_item(2).as_canonical_u64();
    let input_bytes = read_memory_packed_u32(process, ptr, len_bytes)?;

    // 2. Compute the digest (unchanged)
    let digest = Keccak256::hash(&input_bytes);
    let digest_u32_felts = digest_to_u32_felts(&digest);  // 8 felts

    // 3. Compute the Chunks sponge root
    //    capacity IV = [1, 0, 0, VERSION] in Miden-native layout
    //    rate = 8 felts per chunk (u32-LE encoding)
    let chunks: Vec<[Felt; 8]> = chunk_input_to_8_felt_words(&input_bytes);
    let chunks_hash = compute_chunk_sponge_root(&chunks);
    let chunks_ptr = dag.allocate_chunk_ptr(chunks);

    // 4. Compute the KeccakDigestLeaf hash
    //    state[0..8] = digest_u32_felts, state[8..12] = [3, 0, 0, VERSION]
    let digest_leaf_hash = compute_pvm_node_hash(
        digest_u32_felts,
        /* tag */ 3, /* pa */ 0, /* pb */ 0,
    );
    let digest_ptr = dag.allocate_digest_ptr(digest);

    // 5. Compute the Keccak node hash
    //    state[0..4] = digest_leaf_hash, state[4..8] = chunks_hash
    //    state[8..12] = [7, len_bytes, 0, VERSION]
    let mut val = [Felt::ZERO; 8];
    val[0..4].copy_from_slice(&digest_leaf_hash);
    val[4..8].copy_from_slice(&chunks_hash);
    let keccak_hash = compute_pvm_node_hash(
        val,
        /* tag */ 7, /* pa */ Felt::from(len_bytes), /* pb */ 0,
    );

    // 6. Register all three nodes in the DAG
    dag.nodes.insert(digest_leaf_hash,
        TranscriptNode::KeccakDigestLeaf { ptr: digest_ptr });
    dag.nodes.insert(chunks_hash,
        TranscriptNode::Chunks { ptr: chunks_ptr, n_chunks: chunks.len() });
    dag.nodes.insert(keccak_hash,
        TranscriptNode::Keccak { digest_ptr, chunks_ptr, len_bytes });

    // 7. Push 4-felt keccak_hash + 8-felt digest_u32_felts to advice stack
    Ok(vec![
        AdviceMutation::extend_stack(digest_u32_felts),  // for backward compat
        AdviceMutation::extend_stack(keccak_hash),       // the new commitment
    ])
}
```

The MASM side of `keccak256::hash_bytes` (`crates/lib/core/asm/crypto/hashes/keccak256.masm:102-140`) shrinks because it no longer has to compute the COMM/TAG itself. It just emits the event, pulls `keccak_hash` from the advice stack, and passes it to `log_precompile_request` (Comment B).

### Files affected

- **`crates/lib/core/src/handlers/keccak256.rs`** — handler computes the new commitment shape, inserts DAG entries via `Arc<Mutex<PrecompileDag>>`, returns `keccak_hash` via advice push.
- **`crates/lib/core/asm/crypto/hashes/keccak256.masm:102-140`** — `hash_bytes_impl` returns a single 4-felt commitment (the keccak node hash) instead of `[COMM, TAG, DIGEST_U32[8]]`. The wrapper `hash_bytes` then calls `log_precompile_request` with that single hash.

### What's NOT in scope

- **Making keccak a chiplet** (i.e., proving keccak-f[1600] inside Miden's main trace). That's a separate discussion. The PVM has its own keccak chip (comment 1, §8.5) that takes responsibility for keccak constraint enforcement. From the Miden side, keccak stays as an off-chip precompile that produces commitments, exactly as today.

### Equivalent migration steps for sha512 / eddsa / ecdsa

These handlers follow the same pattern: compute the operation off-chip, register the result in the DAG, return a single 4-felt commitment to MASM, MASM appends via `log_precompile`. Each gets its own `TranscriptNode::*` variant if the PVM AIR has a chip that knows how to verify it; otherwise they can be treated as opaque "proof of computation" nodes (TBD per spec).
