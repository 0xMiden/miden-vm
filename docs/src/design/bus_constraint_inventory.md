# Bus Constraint Inventory

This document inventories every bus (auxiliary-trace) constraint in the Miden VM AIR: the protocol type, individual entry degrees, and — importantly — the semantic meaning of each message field.

All degrees were verified programmatically using a degree-logging symbolic builder (`air/tests/bus_degree_inventory.rs`).

## Overview

The Miden VM uses 8 auxiliary (bus) columns to enforce multiset and LogUp relations between components.

| Aux Index | Name | Protocol | Source File | Constraint Degree | Slack |
|:---------:|------|----------|-------------|:-----------------:|:-----:|
| 0 | P1_BLOCK_STACK | Running Product | `constraints/decoder/bus.rs` | **7** | 2 |
| 1 | P2_BLOCK_HASH | Running Product | `constraints/decoder/bus.rs` | **9** | 0 |
| 2 | P3_OP_GROUP | Running Product | `constraints/decoder/bus.rs` | **9** | 0 |
| 3 | P1_STACK | Running Product | `constraints/stack/bus.rs` | **9** | 0 |
| 4 | B_RANGE | LogUp | `constraints/range/bus.rs` | **9** | 0 |
| 5 | B_HASH_KERNEL | Running Product | `constraints/chiplets/bus/hash_kernel.rs` | **8** | 1 |
| 6 | B_CHIPLETS | Running Product | `constraints/chiplets/bus/chiplets.rs` | **9** | 0 |
| 7 | V_WIRING | LogUp | `constraints/chiplets/bus/wiring.rs` | **8** | 1 |

The maximum allowed constraint degree is **9** (see `docs/src/design/index.md`). If a constraint's degree were to grow beyond 9, helper columns would need to be introduced. Currently 5 of the 8 buses are saturated at degree 9, while 3 have remaining capacity.

## Message Encoding Protocol

All bus messages are encoded as random linear combinations:

```
message = alpha + beta^0 * elem[0] + beta^1 * elem[1] + ... + beta^(k-1) * elem[k-1]
```

where `alpha` and `beta` are verifier challenges drawn after trace commitment. The `Challenges` struct precomputes `beta_powers[0..16]` and provides `encode(elems)` and `encode_sparse(layout, values)`. Maximum message width is 16 elements (`MAX_MESSAGE_WIDTH`).

**Collision resistance**: two distinct messages collide only if `sum(beta^i * (a_i - b_i)) = 0`, which is a degree-k polynomial in `beta`. Over the 64-bit Goldilocks field, the probability is ≤ k/p ≈ k/2^64 — negligible.

### Chiplets Bus Standard Layout

The chiplets bus (B_CHIPLETS) uses a standardized coefficient layout defined in `air/src/trace/mod.rs::bus_message`:

| Beta Power | Index Name | Purpose |
|:----------:|------------|---------|
| β⁰ | `LABEL_IDX` | Transition label — identifies the operation type |
| β¹ | `ADDR_IDX` | Hasher chiplet row address |
| β² | `NODE_INDEX_IDX` | Merkle node index (0 for non-Merkle ops) |
| β³–β¹⁰ | `STATE_START_IDX`..+8 | Hasher state: RATE0[0..4] ‖ RATE1[0..4] |
| β¹¹–β¹⁴ | `CAPACITY_START_IDX`..+4 | Hasher capacity[0..3] (domain separation) |
| β¹² | `CAPACITY_DOMAIN_IDX` | Second capacity element (used for opcode in control blocks) |

This layout is **only used by the chiplets bus**. The decoder buses and stack overflow bus use their own simpler schemas (consecutive `beta^0..beta^k` without the standardized positions). This means the decoder and chiplet messages are not structurally compatible — they live on separate buses and there is no need for them to share a layout.

**Design thought**: the three decoder buses (p1, p2, p3) each use their own ad-hoc `encode([...])` calls with consecutive beta powers. A possible improvement would be to define named schemas (similar to `bus_message`) for these too, making the field positions self-documenting. However, since each decoder bus has only one message schema, the current approach is simple and correct.

## Degree Computation Rules

The symbolic degree model tracks `degree_multiple` — how many times the trace length `n` appears in the degree. Rules:

| Expression | degree_multiple |
|-----------|:-:|
| Trace column (current or next row) | 1 |
| Auxiliary (permutation) column | 1 |
| Periodic column | 1 |
| Challenge (α, β) | 0 |
| Constant | 0 |
| `IsTransition` | 0 |
| `IsFirstRow` / `IsLastRow` | 1 |
| `a + b` | `max(a, b)` |
| `a * b` | `a + b` |

For **running-product** buses: the constraint `p' * request - p * response = 0` has degree `1 + max(request_deg, response_deg)` since `p'` and `p` are degree 1 aux columns.

For **LogUp** buses: the constraint clears a common denominator, so the degree depends on the specific polynomial form.

## Operation Flag Degrees

Operation flags are computed from 7 opcode bits plus 2 degree-reduction helper columns (`op_bit_extra[0]`, `op_bit_extra[1]`). The degree-reduction columns allow high-opcode operations to have lower flag degrees: the prover fills them with specific products of opcode bits, and the verifier checks their consistency, effectively "pre-computing" part of the flag multiplication.

| Flag Degree | Opcode Range | Operations on Buses |
|:-----------:|:------------:|---------------------|
| 7 | 0–63 | MLOAD, MSTORE, MLOADW, MSTOREW, U32AND, U32XOR |
| 6 | 64–79 | (u32 arithmetic — not directly on bus constraints) |
| 5 | 80–95 | HPERM, MPVERIFY, SPLIT, LOOP, SPAN, JOIN, DYN, DYNCALL, EVALCIRCUIT, LOGPRECOMPILE, HORNERBASE, HORNEREXT, MSTREAM, PIPE |
| 4 | 96–127 | MRUPDATE, CALL, SYSCALL, END, REPEAT, RESPAN, HALT, CRYPTOSTREAM |

Composite flags: `right_shift` = 6, `left_shift` = 5, `u32_rc_op` = 3, `chiplets_memory_flag` = 3, `overflow` = 2.

**Observation on degree-7 flags**: the operations with the highest flag degree (7) are exactly the simple memory and bitwise ops (MLOAD, MSTORE, MLOADW, MSTOREW, U32AND, U32XOR). These consume 7 of the 8 available degrees on the chiplets bus (since the constraint adds 1 for the aux column multiplication). They can only afford a degree-1 message (a single `encode([...])` of trace columns). If any of these operations needed to send *two* messages as a product (like HPERM does), the constraint degree would reach 10, exceeding the budget. This is why multi-message products are only used by degree-4 and degree-5 operations.

---

## Bus 0: P1_BLOCK_STACK — Decoder Block Stack Table

**Protocol**: Running Product
**Constraint degree**: **7** (2 degrees of slack)

**Purpose**: Tracks the block nesting stack. Each time the decoder enters a new control-flow block (JOIN, SPLIT, SPAN, LOOP, CALL, etc.), a row is pushed describing the parent context. When the block ends (END) or transitions (RESPAN), the row is popped.

**Message schema** (from `processor/src/trace/tests/decoder.rs::BlockStackTableRow`):

| β power | Field | Description |
|:-------:|-------|-------------|
| β⁰ | `block_id` | Hasher address of the new block (row index in hasher chiplet) — uniquely identifies this block |
| β¹ | `parent_id` | Hasher address of the parent block (or `h1'` for RESPAN) |
| β² | `is_loop` | 1 if this block is a LOOP body, 0 otherwise |
| β³ | `parent_ctx` | Execution context ID of the parent (only for CALL/SYSCALL/DYNCALL; 0 otherwise) |
| β⁴ | `parent_fmp` | Frame pointer (`b0`, stack depth) of the parent context |
| β⁵ | `parent_stack_depth` | Stack depth register (`b1`, overflow address) of parent |
| β⁶ | `parent_overflow_addr` | Next overflow table address in parent context |
| β⁷–β¹⁰ | `parent_fn_hash[0..3]` | 4-element function hash digest of the calling function |

For non-CALL/SYSCALL operations, fields β³–β¹⁰ are all zero (the simple `encode([block_id, parent_id, is_loop])` only touches β⁰–β²). For CALL/SYSCALL/DYNCALL, the full 11-element message saves the caller's execution context so it can be restored on END.

**Boundary**: `p1[0] = 1`, `p1[last] = 1` (table must be empty at start and end)

### Response Entries (push onto block stack)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| JOIN | `is_join` | 5 | Simple: `[new_block_addr, parent_addr, 0]` — entering a JOIN; is_loop=0 | 1 | **6** |
| SPLIT | `is_split` | 5 | Simple: `[new_block_addr, parent_addr, 0]` | 1 | **6** |
| SPAN | `is_span` | 5 | Simple: `[new_block_addr, parent_addr, 0]` — entering a basic block | 1 | **6** |
| DYN | `is_dyn` | 5 | Simple: `[new_block_addr, parent_addr, 0]` | 1 | **6** |
| LOOP | `is_loop` | 5 | Simple: `[new_block_addr, parent_addr, s0]` — is_loop = stack top (1 if entering loop body) | 1 | **6** |
| RESPAN | `is_respan` | 4 | Simple: `[new_block_addr, h1', 0]` — h1' is the parent block's address from the next row's hasher state | 1 | **5** |
| CALL | `is_call` | 4 | Full: `[new_addr, parent_addr, 0, ctx, b0, b1, overflow_addr, fn_hash[0..3]]` — saves caller context | 1 | **5** |
| SYSCALL | `is_syscall` | 4 | Full: same as CALL | 1 | **5** |
| DYNCALL | `is_dyncall` | 5 | Full: `[new_addr, parent_addr, 0, ctx, h4, h5, fn_hash[0..3]]` — h4/h5 from hasher state hold shifted depth/overflow | 1 | **6** |

### Request Entries (pop from block stack)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| RESPAN | `is_respan` | 4 | Simple: `[current_addr, h1', 0]` — removes current block before pushing new RESPAN | 1 | **5** |
| END (simple blocks) | `is_end * (1 - is_call_flag - is_syscall_flag)` | 5 | Simple: `[current_addr, parent_addr', is_loop_flag]` — is_loop_flag from h5 column | 1 | **6** |
| END (after CALL/SYSCALL) | `is_end * (is_call_flag + is_syscall_flag)` | 5 | Full: `[current_addr, parent_addr', is_loop_flag, ctx', b0', b1', overflow_addr', fn_hash'[0..3]]` — restores caller context from next row | 1 | **6** |

**Note on the zero fields**: when a simple block (JOIN/SPLIT/SPAN/DYN) pushes `[block_id, parent_id, 0]` with zeros for fields 3–10, these zeros are multiplied by `beta^3..beta^10` in the encoding. The corresponding END pops `[block_id, parent_id, is_loop_flag, 0, 0, 0, 0, 0, 0, 0]` — the zeros must match exactly. Since `is_loop_flag` is also 0 for non-loop blocks, the simple 3-element and full 11-element messages are compatible: the longer message is just the shorter one with explicit zeros appended (the encode function only includes the provided elements, and omitted betas have no contribution — effectively zero).

**Degree slack**: this bus is only degree 7, leaving room for 2 more degrees. This means we could:
- Add one more message multiplication (product of two messages, degree 2) to an existing degree-5 flag entry and still reach only degree 8.
- Or add a new entry with a degree-7 flag and a degree-1 message (reaching 8).
- Or even add a degree-7 flag with a 2-message product (reaching 10) — this would NOT fit.

The slack exists because the flags for control-flow operations (JOIN, SPLIT, etc.) are degree 5 (not 7), and their messages are single encodings (degree 1).

---

## Bus 1: P2_BLOCK_HASH — Decoder Block Hash Table

**Protocol**: Running Product
**Constraint degree**: **9** (saturated)

**Purpose**: Tracks child block hashes that have been scheduled for execution but haven't completed yet. The program hash is seeded via `reduced_aux_values` at initialization. Each control-flow operation enqueues child hashes; END dequeues them when the child finishes.

**Message schema** (from `processor/src/trace/decoder/aux_trace/block_hash_table.rs::BlockHashTableRow`):

| β power | Field | Description |
|:-------:|-------|-------------|
| β⁰ | `parent_block_id` | Hasher address of the parent block |
| β¹–β⁴ | `child_block_hash[0..3]` | 4-element hash digest of the child block being scheduled |
| β⁵ | `is_first_child` | 1 if this is the first (left) child of a JOIN, 0 otherwise |
| β⁶ | `is_loop_body` | 1 if this is a loop body block (from LOOP or REPEAT), 0 otherwise |

`is_first_child` distinguishes the two children of a JOIN — the first child is executed, then the second. For SPLIT, LOOP, DYN, CALL, SYSCALL, only one child is enqueued, and `is_first_child=0`. For the END removal, `is_first_child` is computed from the *next* row's opcode: a block is a first child if the next operation is NOT END, REPEAT, or HALT (because a second child or continuation follows).

**Boundary**: `p2[0] = 1`, `p2[last]` = program hash commitment (from `reduced_aux_values`)

### Response Entries (enqueue child hashes)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| JOIN | `is_join` | 5 | **Product of two messages**: left_child(is_first=1) × right_child(is_first=0). The hasher state holds both hashes: h[0..3] = left, h[4..7] = right. | 2 | **7** |
| SPLIT | `is_split` | 5 | Conditional select: `s0*h[0..3] + (1-s0)*h[4..7]`. If s0=1 (condition true), executes the "then" branch (first half); else the "else" branch (second half). is_first_child=0, is_loop_body=0. | 2 | **7** |
| LOOP (s0=1) | `is_loop` | 5 | `is_loop * (s0 * msg + (1-s0))`: if s0=1, enqueue body hash h[0..3] with is_loop_body=1; if s0=0, skip (multiply by 1). The s0 gate adds 1 degree. | 1 (msg) | **7** |
| REPEAT | `is_repeat` | 4 | Enqueue body hash h[0..3] with is_loop_body=1 — re-entering a loop iteration | 1 | **5** |
| DYN | `is_dyn` | 5 | Enqueue h[0..3] (callee hash read from memory) with is_first_child=0 | 1 | **6** |
| DYNCALL | `is_dyncall` | 5 | Same as DYN | 1 | **6** |
| CALL | `is_call` | 4 | Enqueue h[0..3] (callee procedure hash) with is_first_child=0 | 1 | **5** |
| SYSCALL | `is_syscall` | 4 | Same as CALL (kernel procedure hash) | 1 | **5** |

### Request Entries (dequeue on block completion)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| END | `is_end` | 4 | `encode([parent_id', h0..3, is_first_child, is_loop_body_flag])` — **message degree 4** because `is_first_child` is computed from next-row op flags, each of which is degree 4 | 4 | **8** |

**Why END is the degree-limiting entry**: `is_first_child = 1 - (end_next + repeat_next + halt_next)` requires computing op flags from the next row's decoder bits. Each next-row flag is degree 4 (from `OpFlags::new` on next row columns — these are independent degree-4 flag computations, not the current row's cached flags). This degree-4 expression appears inside the `encode(...)` call, making the message degree 4. Combined with the `is_end` flag (degree 4): entry degree = 4 + 4 = 8, and constraint degree = 1 + 8 = 9.

**Design thought**: if `is_first_child` were stored in a helper column instead of being computed from next-row op flags, the message degree would drop to 1 and the entry degree to 5. This would bring the constraint down to degree 6, freeing 3 degrees. The cost would be one additional trace column.

---

## Bus 2: P3_OP_GROUP — Decoder Op Group Table

**Protocol**: Running Product
**Constraint degree**: **9** (saturated)

**Purpose**: Tracks operation groups within span blocks. A span block contains up to 8 operation groups (batches of opcodes). These are enqueued on SPAN/RESPAN and dequeued one-by-one as the decoder processes each group.

**Message schema** (from `processor/src/trace/tests/decoder.rs::OpGroupTableRow`):

| β power | Field | Description |
|:-------:|-------|-------------|
| β⁰ | `batch_id` | Hasher address of the span block (identifies which SPAN/RESPAN) |
| β¹ | `group_pos` | Position within the batch (counts down: group_count decrements as groups execute) |
| β² | `group_value` | The actual operation group data — a field element encoding up to 9 opcodes (each 7 bits), or a single PUSH immediate value |

**Boundary**: `p3[0] = 1`, `p3[last] = 1`

### Response Entries (insert groups on SPAN/RESPAN)

The number of groups inserted depends on the batch size flags (c0, c1, c2):

| Batch Size | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|------------|------|:--------:|---------------------|:-------:|:---------:|
| g8 (7 groups) | `c0` | 1 | Product of 7 individual group messages `v_1 * v_2 * ... * v_7`, where each `v_i = encode([batch_id', gc-i, h_i])` and `h_i` is the i-th hasher state element | 7 | **8** |
| g4 (3 groups) | `(1-c0)*c1*(1-c2)` | 3 | Product of 3 group messages: `v_1 * v_2 * v_3` | 3 | **6** |
| g2 (1 group) | `(1-c0)*(1-c1)*c2` | 3 | Single message: `v_1` | 1 | **4** |
| g1 (0 extra groups) | implicit | — | Identity (1) — the first group h0 is decoded immediately, no table entry needed | — | — |

**Why g8 reaches degree 8**: the batch flag `c0` is just a single trace column (degree 1), but it gates a product of 7 messages, each degree 1, giving a message-product degree of 7. Entry degree: 1 + 7 = 8.

### Request Entries (remove group on decode)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| Group decode | `f_dg = sp * (gc - gc')` | 2 | `encode([block_id, gc, group_value])` where `group_value` involves conditional: `is_push * s0' + (1-is_push) * (h0'*128 + opcode')` | 6 | **8** |

**Why message degree is 6**: `is_push` is a degree-5 flag. The conditional `is_push * s0'` multiplies a degree-5 expression by a degree-1 trace column, giving degree 6. `opcode'` is a weighted sum of next-row opcode bits (degree 1), and `h0'*128 + opcode'` is also degree 1. But the outer `(1-is_push) * (...)` is degree 5 * 1 = 6. The max of both branches is 6.

---

## Bus 3: P1_STACK — Stack Overflow Table

**Protocol**: Running Product
**Constraint degree**: **9** (saturated)

**Purpose**: The operand stack has 16 directly-accessible positions. When an operation pushes a new element (right-shift), the bottom element (`s15`) overflows into this table. When an operation pops (left-shift), an element is restored from the table.

The overflow table is a linked list: each entry records a value, the clock cycle when it was stored, and a pointer to the previous entry.

**Message schema** (from `processor/src/trace/stack/aux_trace.rs::OverflowTableRow`):

| β power | Field | Description |
|:-------:|-------|-------------|
| β⁰ | `clk` | VM clock cycle when the value was pushed to overflow — serves as the entry's unique address |
| β¹ | `val` | The field element that overflowed from stack position 15 |
| β² | `prev` | Clock cycle of the previous overflow entry (linked list pointer; 0 if this is the first entry) |

**Boundary**: `p1[0] = 1`, `p1[last] = 1`

### Response Entries (push to overflow)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| Right shift | `right_shift` | 6 | `encode([clk, s15, b1])`: clock cycle, value falling off the bottom of the stack, current overflow pointer (b1 column) | 1 | **7** |

### Request Entries (pop from overflow)

| Operation | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|------|:--------:|---------------------|:-------:|:---------:|
| Left shift | `left_shift * overflow` | 7 | `encode([b1, s15', b1'])`: current overflow pointer, value being restored to s15, new overflow pointer | 1 | **8** |
| DYNCALL | `dyncall * overflow` | 7 | `encode([b1, s15', hasher_state[5]])`: same but uses hasher state[5] for the new overflow pointer (DYNCALL modifies the overflow chain specially) | 1 | **8** |

**Why the flag is degree 7**: `overflow = (b0 - 16) * h0` (degree 2) tests whether the overflow table is non-empty. `left_shift` (degree 5) or `dyncall` (degree 5) combined with `overflow` gives degree 7.

**Why removal on response side uses different fields**: for insertion (right-shift), the message is `[clk, s15, b1]` — the current clock, value, and current overflow pointer. For removal (left-shift), the message is `[b1, s15', b1']` — the *previous* clock (which is b1, since b1 stores the address of the last overflow entry), the value being restored (next row's s15), and the *new* overflow pointer (next row's b1). This works because b1 always points to the head of the overflow linked list, and its value equals the `clk` from when that entry was inserted.

---

## Bus 4: B_RANGE — Range Checker

**Protocol**: LogUp
**Constraint degree**: **9** (saturated)

**Purpose**: Validates that values lie in [0, 2¹⁶). The decoder's u32 helper columns and the memory chiplet's address delta limbs need range-checking. The range table provides a column V that enumerates all values 0..2¹⁶ with multiplicity M.

**LogUp formulation**: `b' - b = M/(α+V) - Σ(1/(α+lookup_i))`

After clearing the common denominator `(α+V) * Π(α+sv_i) * Π(α+mv_j)` (degree 7), each term in the numerator is multiplied by the remaining denominators, reaching degree 9.

**Boundary**: `b_range[0] = 0`, `b_range[last] = 0`

### Entries

| Entry | Direction | Flag | Flag Deg | Denominator | Description |
|-------|-----------|------|:--------:|-------------|-------------|
| Range response | response | `M` (multiplicity column) | 1 | `α + V` | Range table entry: V is the value being range-checked, M is how many times it appears |
| Stack lookup 0–3 | request | `u32_rc_op` | 3 | `α + helper[i]` | Decoder helper columns 0–3 holding 16-bit limbs from u32 decomposition |
| Memory lookup 0–1 | request | `chiplets_memory_flag` | 3 | `α + D_i` | Memory delta limbs D0, D1: ensure address differences between consecutive memory accesses fit in 16 bits |

`u32_rc_op = op_bit[6] * (1 - op_bit[5]) * (1 - op_bit[4])`: degree 3, selects the `100` opcode prefix (u32 operations that need range checking).

`chiplets_memory_flag = s0 * s1 * (1 - s2)`: degree 3, selects memory chiplet rows.

**Degree analysis**: under the common denominator (degree 7), a stack lookup term becomes `u32_rc_op(3) * range_check(1) * memory_lookups(2) * remaining_sv(3) = 9`. Similarly, memory lookup terms reach degree 9.

---

## Bus 5: B_HASH_KERNEL — Hash Kernel Virtual Table

**Protocol**: Running Product
**Constraint degree**: **8** (1 degree of slack)

**Purpose**: Aggregates three logically separate tables into a single running product:
1. **Sibling table** — during Merkle root updates (MRUPDATE), the old sibling values are stored and later retrieved for the new path
2. **ACE memory reads** — the ACE chiplet reads memory words/elements; these requests go through this bus
3. **Log-precompile transcript** — tracks capacity state transitions for the LOG_PRECOMPILE operation

All three sub-tables are mutually exclusive (different chiplet selectors activate different rows), so they can safely share one running product column.

**Boundary**: `p[0] = 1`, `p[last]` checked via `aux_finals`

### Sibling Table Entries

During Merkle tree operations, the hasher processes paths in 32-cycle rounds. At cycle-row 0 (start of a round), MV/MU flags determine whether a sibling is being stored or retrieved. The sibling is selected from the hasher state based on a bit `b = node_index - 2*node_index_next` which indicates which half of the rate contains the sibling.

| Operation | Direction | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|-----------|------|:--------:|---------------------|:-------:|:---------:|
| MV (old path, row 0) | response | `is_hasher * f_mv(cycle_0, s0, s1, s2)` | 5 | `encode_sparse(sibling_word, node_index)` — conditional on bit b: selects h[4..7] if b=0, h[0..3] if b=1 | 2 | **7** |
| MVA (old path, row 31) | response | `is_hasher * f_mva(cycle_31, ...)` | 5 | Same, using next-row hasher state | 2 | **7** |
| MU (new path, row 0) | request | `is_hasher * f_mu(cycle_0, ...)` | 5 | Retrieves sibling (same encoding as MV) | 2 | **7** |
| MUA (new path, row 31) | request | `is_hasher * f_mua(cycle_31, ...)` | 5 | Same, using next-row hasher state | 2 | **7** |

**Why message degree is 2**: the conditional select `encode_b0 * (1 - b) + encode_b1 * b` multiplies a degree-1 encoding by a degree-1 bit, producing degree 2.

### ACE Memory Entries

| Operation | Direction | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|-----------|------|:--------:|---------------------|:-------:|:---------:|
| ACE word read | request | `is_ace_row * (1 - block_sel)` | 5 | `encode([MEMORY_READ_WORD_LABEL, ctx, ptr, clk, v0_0, v0_1, v1_0, v1_1])` — reads a 4-element word from memory for the ACE circuit | 1 | **6** |
| ACE element read | request | `is_ace_row * block_sel` | 5 | `encode([MEMORY_READ_ELEMENT_LABEL, ctx, ptr, clk, element])` — reads a single element; element is computed from instruction IDs | 1 | **6** |

### Log Precompile Entries

| Operation | Direction | Flag | Flag Deg | Message Description | Msg Deg | Entry Deg |
|-----------|-----------|------|:--------:|---------------------|:-------:|:---------:|
| CAP_PREV | request | `f_logprecompile` | 5 | `encode([LOG_PRECOMPILE_LABEL, cap_prev[0..3]])` — removes the previous capacity state from helper registers | 1 | **6** |
| CAP_NEXT | response | `f_logprecompile` | 5 | `encode([LOG_PRECOMPILE_LABEL, cap_next[0..3]])` — inserts the new capacity state from next-row stack | 1 | **6** |

**Remaining capacity**: with max entry degree 7 and constraint degree 8, there is 1 degree of slack. Simple entries (flag degree ≤ 7, message degree 1) could be added without exceeding 9. However, adding another entry with a conditional-select message (degree 2) gated by a degree-5 flag would exactly saturate at degree 8 — still fine but no further room. Adding a multi-message product entry would exceed the budget.

---

## Bus 6: B_CHIPLETS — Main Chiplets Bus

**Protocol**: Running Product
**Constraint degree**: **9** (saturated)

**Purpose**: The central communication channel between the VM's execution engine (decoder, stack) and all specialized chiplets (hasher, bitwise, memory, ACE, kernel ROM). Each VM operation that needs chiplet services sends a request message; the chiplet's response rows provide matching responses. The running product ensures request and response multisets are equal.

**Boundary**: `b[0] = 1`, `b[last] = reduced_kernel_digests` — the kernel ROM's INIT_LABEL responses multiply in kernel procedure hashes, so the final value is not 1 but the product of all kernel digest encodings, verified against public inputs.

### Request Entries (VM operations → chiplets)

Each request message encodes what the VM needs from a chiplet. Operations that interact with multiple chiplets (e.g., CALL needs hasher + memory for FMP init) send a **product of multiple messages**, which adds their degrees.

#### Hasher Requests

These use the standard chiplets bus layout (β⁰=label, β¹=addr, β²=node_index, β³..=state).

| Operation | Flag Deg | Sub-messages | Description | Msg Deg | Entry Deg |
|-----------|:--------:|:------------:|-------------|:-------:|:---------:|
| HPERM | 5 | input × output | Full Poseidon2 permutation on stack[0..11]. Input msg: `[LINEAR_HASH+16, addr, 0, state_in[0..11]]`. Output msg: `[RETURN_STATE+32, addr+31, 0, state_out[0..11]]`. | 2 | **7** |
| MPVERIFY | 5 | input × output | Merkle path verify. Input: `[MP_VERIFY+16, addr, node_index, node_value[0..3]]`. Output: `[RETURN_HASH+32, addr+depth*32-1, 0, root[0..3]]`. | 2 | **7** |
| MRUPDATE | 4 | old_in × old_out × new_in × new_out | Merkle root update. Four word-level messages: old node verify + new node insert. | 4 | **8** |

**Label system**: hasher transition labels encode the operation and whether it's an input (+16) or output (+32) message. E.g., `LINEAR_HASH_LABEL = 3`, so input label = 19, output label for state return = `RETURN_STATE_LABEL + 32 = 9 + 32 = 41`.

#### Control Block Requests

Control-flow operations (JOIN, SPLIT, LOOP, etc.) request the hasher chiplet to hash their child blocks.

| Operation | Flag Deg | Sub-messages | Description | Msg Deg | Entry Deg |
|-----------|:--------:|:------------:|-------------|:-------:|:---------:|
| JOIN | 5 | 1 | `[LINEAR_HASH+16, addr', 0, h[0..7], 0, opcode, 0, 0]` — hasher state = rate (child hashes) + capacity (opcode as domain) | 1 | **6** |
| SPLIT | 5 | 1 | Same format | 1 | **6** |
| LOOP | 5 | 1 | Same format | 1 | **6** |
| SPAN | 5 | 1 | `[LINEAR_HASH+16, addr', 0, h[0..7], 0, 0, 0, 0]` — capacity all zeros (no domain separation) | 1 | **6** |
| RESPAN | 4 | 1 | `[LINEAR_HASH+32, addr'-1, 0, h[0..7]]` — rate-only absorption message (11 elements) | 1 | **5** |
| END | 4 | 1 | `[RETURN_HASH+32, addr+31, 0, digest[0..3]]` — digest-only word message (7 elements) | 1 | **5** |
| CALL | 4 | control × fmp_write | Control block hash + memory write to initialize FMP in new context | 2 | **6** |
| DYN | 5 | control_zeros × callee_read | Hash with zero state + memory word read for callee hash from stack[0] | 2 | **7** |
| DYNCALL | 5 | control_zeros × callee_read × fmp_write | Three sub-messages: hash + callee read + FMP init | 3 | **8** |
| SYSCALL | 4 | control × kernel_lookup | Control block hash + kernel ROM lookup (verifies procedure is in kernel) | 2 | **6** |

**How multiple sub-messages work**: when an operation interacts with multiple chiplets in one cycle, the request is the *product* of individual messages. Each chiplet row produces one response that matches one sub-message. The multiset protocol ensures all sub-messages find matching responses.

#### Memory Requests

These use a different layout from the hasher: `[label, ctx, addr, clk, data...]`.

| Operation | Flag Deg | Sub-messages | Description | Msg Deg | Entry Deg |
|-----------|:--------:|:------------:|-------------|:-------:|:---------:|
| MLOAD | 7 | 1 | `[READ_ELEM_LABEL, ctx, stack[0], clk, next_stack[0]]` — read one element | 1 | **8** |
| MSTORE | 7 | 1 | `[WRITE_ELEM_LABEL, ctx, stack[0], clk, stack[1]]` — write one element | 1 | **8** |
| MLOADW | 7 | 1 | `[READ_WORD_LABEL, ctx, stack[0], clk, next_stack[0..3]]` — read 4-element word | 1 | **8** |
| MSTOREW | 7 | 1 | `[WRITE_WORD_LABEL, ctx, stack[0], clk, stack[1..4]]` — write 4-element word | 1 | **8** |
| HORNERBASE | 5 | msg₀ × msg₁ | Two element reads for Horner evaluation points from helper registers | 2 | **7** |
| HORNEREXT | 5 | 1 | One word read for extended evaluation point | 1 | **6** |
| MSTREAM | 5 | msg₁ × msg₂ | Two word reads at consecutive addresses (addr, addr+4) into stack[0..7] | 2 | **7** |
| PIPE | 5 | msg₁ × msg₂ | Two word writes from stack at consecutive addresses | 2 | **7** |
| CRYPTOSTREAM | 4 | read₁ × read₂ × write₁ × write₂ | Two word reads (plaintext) + two word writes (ciphertext), with cipher = plain + rate | 4 | **8** |

**Memory label encoding**: `label = 4 + 8*is_read + 16*is_word`. This gives WRITE_ELEM=4, READ_ELEM=12, WRITE_WORD=20, READ_WORD=28.

#### Bitwise Requests

| Operation | Flag Deg | Description | Msg Deg | Entry Deg |
|-----------|:--------:|-------------|:-------:|:---------:|
| U32AND | 7 | `[BITWISE_AND_LABEL, a, b, z]` where a,b from stack, z from next_stack[0] | 1 | **8** |
| U32XOR | 7 | `[BITWISE_XOR_LABEL, a, b, z]` | 1 | **8** |

#### ACE and Log Precompile Requests

| Operation | Flag Deg | Sub-messages | Description | Msg Deg | Entry Deg |
|-----------|:--------:|:------------:|-------------|:-------:|:---------:|
| EVALCIRCUIT | 5 | 1 | `[ACE_INIT_LABEL, clk, ctx, ptr, num_read_rows, num_eval_rows]` — initiate ACE circuit evaluation | 1 | **6** |
| LOGPRECOMPILE | 5 | input × output | Two full-state hasher messages: absorb [COMM, TAG, CAP_PREV] → produce [R0, R1, CAP_NEXT] | 2 | **7** |

### Response Entries (chiplet rows → bus)

Each chiplet row that services a request emits a response message with the same encoding.

#### Hasher Chiplet Responses

The hasher has 7 response flags, activated at cycle positions 0 (init) and 31 (output) with different selector combinations:

| Flag | When | Description | Msg Deg | Entry Deg |
|------|------|-------------|:-------:|:---------:|
| f_bp | cycle 0, s=[1,0,0] | Linear hash / 2-to-1 hash init — full 15-element state message | 1 | **6** |
| f_mp | cycle 0, s=[1,0,1] | Merkle path verify init — word message with conditional leaf select | 2 | **7** |
| f_mv | cycle 0, s=[1,1,0] | Merkle root update (old path) init — conditional leaf word | 2 | **7** |
| f_mu | cycle 0, s=[1,1,1] | Merkle root update (new path) init — conditional leaf word | 2 | **7** |
| f_hout | cycle 31, s=[0,0,0] | Return hash — 7-element word message with digest from RATE0 | 1 | **6** |
| f_sout | cycle 31, s=[0,0,1] | Return full state — 15-element message | 1 | **6** |
| f_abp | cycle 31, s=[1,0,0] | Absorption — rate message with next-row's rate elements | 1 | **6** |

All hasher flags are degree 5: `is_hasher(1) * cycle_marker(1) * s0(1) * s1_term(1) * s2_term(1)`.

#### Other Chiplet Responses

| Chiplet | Flag | Flag Deg | Description | Msg Deg | Entry Deg |
|---------|------|:--------:|-------------|:-------:|:---------:|
| Bitwise | `is_bitwise * (1 - k_transition)` | 4 | Last row of 8-cycle: `[label, a, b, z]`. Label is degree 2 (computed from AND/XOR selector). | 2 | **6** |
| Memory | `s0 * s1 * (1 - s2)` | 3 | Every row: `[label, ctx, addr, clk, data...]`. Label (degree 2) and element selection (degree 3 from idx0*idx1 multiplexing) make msg degree 3. | 3 | **6** |
| ACE | `is_ace_row * start_sel` | 5 | Start rows only: `[ACE_INIT_LABEL, clk, ctx, ptr, num_read, num_eval]` | 1 | **6** |
| Kernel ROM | `s0*s1*s2*s3*(1-s4)` | 5 | `[label, digest[0..3]]`. Label is degree 2 (s_first selects INIT vs CALL label). | 2 | **7** |

**Memory response label computation**: `label = (1-is_read)*write_label + is_read*read_label` where each sub-label is `(1-is_word)*elem_label + is_word*word_label`. This creates a degree-2 label expression (product of two binary trace columns). The element selection `v0*(1-idx0)*(1-idx1) + v1*idx0*(1-idx1) + ...` for single-element access has degree 3 (column × idx0 × idx1).

---

## Bus 7: V_WIRING — ACE Wiring

**Protocol**: LogUp
**Constraint degree**: **8** (1 degree of slack)

**Purpose**: Verifies the wiring of arithmetic circuits evaluated by the ACE chiplet. Every node `(id, value)` produced in the DAG must be consumed the correct number of times by downstream gates.

**Wire encoding**: `alpha + beta^0*clk + beta^1*ctx + beta^2*id + beta^3*v0 + beta^4*v1`

where `(v0, v1)` are the two coefficients of a quadratic extension field element.

**Constraint form**: LogUp with common denominator `wire_0 * wire_1 * wire_2` (degree 3).

**Boundary**: `v[0] = 0`, `v[last]` checked via `aux_finals`

### Entries

| Block Type | Entry | Direction | Multiplicity | Description |
|------------|-------|:---------:|:------------:|-------------|
| READ (sblock=0) | wire_0 | insert | m0 | Node 0 output: inserted m0 times (fan-out count) |
| READ (sblock=0) | wire_1 | insert | m1 | Node 1 output: inserted m1 times |
| EVAL (sblock=1) | wire_0 | insert | m0 | Gate output: inserted m0 times (fan-out of gate result) |
| EVAL (sblock=1) | wire_1 | remove | 1 | Gate input 1: consumed once |
| EVAL (sblock=1) | wire_2 | remove | 1 | Gate input 2: consumed once |

The constraint `delta * common_den = rhs` has: `rhs = read_terms * read_gate + eval_terms * eval_gate`. Each gate is `ace_flag(4) * block_selector(1) = degree 5`. Each term under the common denominator is degree 3. So `rhs` reaches `5 + 3 = 8`.

---

## Degree Summary and Capacity Analysis

| Bus | Index | Protocol | Constraint Deg | Slack | Degree-Limiting Entry |
|-----|:-----:|----------|:--------------:|:-----:|----------------------|
| P1_BLOCK_STACK | 0 | Running Product | **7** | **2** | Degree-5 flags × degree-1 messages |
| P2_BLOCK_HASH | 1 | Running Product | **9** | 0 | END request: `is_first_child` (deg 4) in message × `is_end` (deg 4) flag |
| P3_OP_GROUP | 2 | Running Product | **9** | 0 | g8 batch: 7-message product (deg 7) + `c0` flag (deg 1) |
| P1_STACK | 3 | Running Product | **9** | 0 | `left_shift * overflow` (deg 7) flag |
| B_RANGE | 4 | LogUp | **9** | 0 | Common denominator clearing (7 lookup terms) |
| B_HASH_KERNEL | 5 | Running Product | **8** | **1** | Sibling conditional-select (msg deg 2) × hasher flag (deg 5) |
| B_CHIPLETS | 6 | Running Product | **9** | 0 | Memory ops: deg-7 flags × deg-1 msg; MRUPDATE/DYNCALL/CRYPTOSTREAM: deg-4 flags × deg-4 msg products |
| V_WIRING | 7 | LogUp | **8** | **1** | Gate terms (deg 3) × ace_flag (deg 5) |

### Where Degree 9 Comes From

The saturated buses reach degree 9 through different mechanisms:

- **P2_BLOCK_HASH**: the END operation needs `is_first_child`, which is computed from next-row op flags. This is the most "accidental" degree-9 — a helper column for `is_first_child` would free 3 degrees.
- **P3_OP_GROUP**: the 8-group batch inserts 7 messages as a product. This is inherent to the protocol design (an 8-group span block needs 7 table entries at once).
- **P1_STACK**: the overflow condition `(b0-16)*h0` costs 2 degrees on top of the 5-degree shift flags.
- **B_RANGE**: 7 lookup terms sharing a common denominator is a LogUp design constraint. Reducing the number of lookups would lower the degree.
- **B_CHIPLETS**: degree-7 memory op flags (MLOAD et al.) use all available budget. These operations use 7 opcode bits because they are in the 0–63 opcode range (the "simple" operations that don't benefit from degree-reduction helpers).

### What the Slack Means

**P1_BLOCK_STACK (slack = 2)**: Could add entries with up to degree-8 entry degree. This means:
- A new degree-5 flag with a 3-message product (deg 5+3=8) would fit.
- A new degree-7 flag with a single message (deg 7+1=8) would fit.
- Even two new entries of degree 8 each — the constraint takes the max, not a sum.

**B_HASH_KERNEL (slack = 1)**: Could add entries with up to degree-8 entry degree. A degree-5 flag with a 3-message product (5+3=8) or a degree-7 flag with a single message (7+1=8) would fit.

**V_WIRING (slack = 1)**: Since this is LogUp, adding more wire entries would increase the common denominator degree, which would likely push the constraint beyond 9. The slack isn't as easily usable as for running-product buses.

---

## Research: Splitting Buses by Trace Region

### Motivation

Currently, some bus constraints read columns from both the main trace and the chiplet trace in the same constraint polynomial. If we could split bus interactions into two sets — one touching only main-trace columns, the other touching only chiplet-trace columns — each set could be evaluated independently. This is a prerequisite for proving the two trace regions in separate AIR instances or with separate commitment rounds.

Since all running products / LogUp sums are checked at the boundary (final row values), there is no fundamental need for related entries to share the same auxiliary column. Two columns whose final values multiply to the expected result carry the same cryptographic guarantee as one column.

### Trace Boundary

The execution trace has this layout:

```
 [0..6)    [6..30)     [30..49)   [49..51)       [51..71)
  system    decoder      stack     range check     chiplets
  ├─────── MAIN TRACE ────────┤   ├── range ──┤   ├─ CHIPLET TRACE ─┤
```

- **Main trace** (columns 0–48): system (clk, ctx, fn_hash), decoder (addr, op_bits, hasher_state, helpers, batch flags, ...), stack (s0–s15, b0, b1, h0)
- **Range trace** (columns 49–50): V (value), M (multiplicity) — logically part of the range checker, sits between main and chiplets
- **Chiplet trace** (columns 51–70): shared selector columns (s0–s4), then hasher / bitwise / memory / ACE / kernel ROM sub-traces (multiplexed, one active per row)

Important: the decoder's `hasher_state[0..7]` columns (indices 14–21 globally) are **main trace** columns. They are distinct from the hasher chiplet's state columns (indices ~56–67). The decoder copies hash results into its own columns; the chiplet operates on its own columns. The bus is what ensures they agree.

### Classification of Existing Buses

For each bus, we classify every entry by which trace region it reads:

| Bus | Entry | Reads From | Classification |
|-----|-------|------------|:--------------:|
| **P1_BLOCK_STACK** | all entries | decoder, stack, system, fn_hash | **Main only** |
| **P2_BLOCK_HASH** | all entries | decoder, stack (incl. next-row op_flags) | **Main only** |
| **P3_OP_GROUP** | all entries | decoder, stack | **Main only** |
| **P1_STACK** | all entries | system (clk), stack (s15, b0, b1, h0), decoder (hasher_state[5] for DYNCALL) | **Main only** |
| **B_RANGE** | stack lookups (×4) | decoder op_bits, decoder helpers | **Main only** |
| **B_RANGE** | memory lookups (×2) | chiplet selectors (s0,s1,s2), chiplet memory D0/D1 | **Chiplet only** |
| **B_RANGE** | range response (×1) | range V, range M | **Range only** |
| **B_HASH_KERNEL** | sibling table (MU/MUA/MV/MVA) | chiplet hasher columns | **Chiplet only** |
| **B_HASH_KERNEL** | ACE memory reads | chiplet ACE columns | **Chiplet only** |
| **B_HASH_KERNEL** | log precompile | decoder helpers, stack (next-row), op_flags | **Main only** |
| **B_CHIPLETS** | all requests (26 ops) | system (ctx, clk), decoder (addr, hasher_state, helpers), stack | **Main only** |
| **B_CHIPLETS** | all responses (hasher, bitwise, memory, ACE, kernel ROM) | chiplet columns | **Chiplet only** |
| **V_WIRING** | all entries | chiplet ACE columns | **Chiplet only** |

Three buses need splitting: **B_CHIPLETS**, **B_RANGE**, and **B_HASH_KERNEL**. The other five are already single-region.

### Proposed Decomposition

#### Buses that stay unchanged

These buses already read from a single trace region and need no changes:

| Aux Column | Bus | Region | Notes |
|:----------:|-----|--------|-------|
| m0 | P1_BLOCK_STACK | Main | Running product, degree 7 |
| m1 | P2_BLOCK_HASH | Main | Running product, degree 9 |
| m2 | P3_OP_GROUP | Main | Running product, degree 9 |
| m3 | P1_STACK | Main | Running product, degree 9 |
| c0 | V_WIRING | Chiplet | LogUp, degree 8 |

#### B_CHIPLETS → split into request column (main) + response column (chiplet)

Currently B_CHIPLETS is one running product column where: `p' * request = p * response`. The request side reads main-trace columns, the response side reads chiplet columns.

**Split into two columns:**

- **m4 (main trace)**: accumulates requests only

  ```
  m4' = m4 * request
  ```

  where `request = Σ(flag_i * msg_i) + (1 - Σflags)`. All flags are op_flags (main trace), all messages read from system/decoder/stack (main trace). The constraint reads NO chiplet columns.

  Degree: same as current request side = **9** (from MLOAD etc. at entry degree 8, plus aux col = 9).

- **c1 (chiplet trace)**: accumulates responses only

  ```
  c1' = c1 * response
  ```

  where `response = Σ(chiplet_flag_j * msg_j) + (1 - Σflags)`. All flags are chiplet selectors (chiplet trace), all messages read from chiplet columns.

  Degree: same as current response side. The highest response entry is degree 7 (kernel ROM at flag 5 + msg 2). So c1 constraint degree = **1 + 7 = 8**.

  **Reasoning**: the response side currently contributes degree 7 entries (e.g., hasher f_mp at degree 7, kernel ROM at degree 7). The request side drives the overall degree to 9 (via MLOAD etc. at degree 8). Splitting means the chiplet column is only degree 8 — gaining 1 degree of slack.

- **Boundary check**: the verifier checks `m4[last] * kernel_init_correction = c1[last]`. The kernel ROM INIT_LABEL responses (which currently make `b_chiplets[last] = reduced_kernel_digests` instead of 1) go into c1, so c1's final value encodes those digests. m4's final value is the product of all requests. The verifier confirms they match.

**Message inventory for each column:**

*m4 (main-trace requests):*

| Operation | Message Schema | Data Source |
|-----------|---------------|-------------|
| HPERM | `hasher_msg(input_state) * hasher_msg(output_state)` | stack[0..11], next_stack[0..11], decoder helpers |
| MPVERIFY | `hasher_word_msg(node) * hasher_word_msg(root)` | stack[0..9], decoder helpers |
| MRUPDATE | 4 × `hasher_word_msg(...)` | stack[0..13], next_stack[0..3], decoder helpers |
| JOIN/SPLIT/LOOP | `hasher_msg(h[0..7], opcode)` | decoder addr/hasher_state |
| SPAN | `hasher_msg(h[0..7], zeros)` | decoder addr/hasher_state |
| RESPAN | `hasher_rate_msg(h[0..7])` | decoder addr/hasher_state |
| END | `hasher_word_msg(digest)` | decoder addr/hasher_state |
| CALL | `control_block_msg * fmp_write_msg` | decoder, system ctx, stack |
| DYN | `control_block_zeros_msg * callee_read_msg` | decoder, system, stack |
| DYNCALL | `control_zeros * callee_read * fmp_write` | decoder, system, stack |
| SYSCALL | `control_block_msg * kernel_rom_msg` | decoder hasher_state |
| MLOAD/MSTORE | `[label, ctx, addr, clk, element]` | system ctx/clk, stack |
| MLOADW/MSTOREW | `[label, ctx, addr, clk, word]` | system ctx/clk, stack |
| HORNERBASE | 2 × `[label, ctx, addr, clk, elem]` | system, stack, decoder helpers |
| HORNEREXT | `[label, ctx, addr, clk, word]` | system, stack, decoder helpers |
| MSTREAM/PIPE | 2 × `[label, ctx, addr, clk, word]` | system, stack |
| CRYPTOSTREAM | 4 × `[label, ctx, addr, clk, word]` | system, stack |
| U32AND/U32XOR | `[label, a, b, z]` | stack, next_stack |
| EVALCIRCUIT | `[label, clk, ctx, ptr, num_read, num_eval]` | system, stack |
| LOGPRECOMPILE | `hasher_msg(input) * hasher_msg(output)` | decoder helpers, stack |

*c1 (chiplet-trace responses):*

| Chiplet | Message Schema | Data Source |
|---------|---------------|-------------|
| Hasher (7 flags) | `hasher_msg(state)` or `hasher_word_msg(word)` or `hasher_rate_msg(rate)` | hasher chiplet columns |
| Bitwise | `[label, a, b, z]` | bitwise chiplet columns |
| Memory | `[label, ctx, addr, clk, data]` | memory chiplet columns |
| ACE | `[label, clk, ctx, ptr, num_read, num_eval]` | ACE chiplet columns |
| Kernel ROM | `[label, digest[0..3]]` | kernel ROM chiplet columns |

#### B_RANGE → split into main + chiplet + range columns

The range bus is LogUp: `b' - b = responses - requests`. The entries naturally group into three trace regions:

- **m5 (main trace)**: accumulates stack lookup requests

  ```
  m5' - m5 = - Σ_{i=0..3} (u32_rc_op / (α + helper[i]))
  ```

  Reads: decoder op_bits (for `u32_rc_op` flag), decoder helper columns (for lookup values). All main trace.

  After clearing the common denominator `sv0*sv1*sv2*sv3` (degree 4): `(m5' - m5) * sv0*sv1*sv2*sv3 = -u32_rc_op * (sv1*sv2*sv3 + sv0*sv2*sv3 + sv0*sv1*sv3 + sv0*sv1*sv2)`.

  Degree: `m5' * sv_product` is 1 + 4 = 5. The RHS is `u32_rc_op(3) * sv_triple(3) = 6`. Overall: **max(5, 6) = 6**. This is much lower than the current degree 9 — the high degree came from combining all 7 denominators into one polynomial.

- **c2 (chiplet trace)**: accumulates memory lookup requests

  ```
  c2' - c2 = - Σ_{j=0..1} (chiplets_memory_flag / (α + D_j))
  ```

  Reads: chiplet selectors s0/s1/s2, chiplet memory D0/D1. All chiplet trace.

  Common denominator `mv0*mv1` (degree 2): degree = max(1+2, 3+1) = **4**. Very cheap.

- **r0 (range trace)**: accumulates range responses

  ```
  r0' - r0 = M / (α + V)
  ```

  Reads: range M, range V. Range trace only.

  Common denominator `(α+V)` (degree 1): degree = max(1+1, 1) = **2**. Trivially cheap.

  **Note**: the range trace is only 2 columns. Whether it gets its own aux column or shares with one of the other regions is a design choice. Since range V/M sit between main and chiplet traces in the layout, it could be assigned to either side. If assigned to the main side: merge r0 into m5 by including the range response in the main-trace LogUp. The common denominator would then be `(α+V) * Π(α+helper[i])` (degree 5), and the constraint degree becomes ~8. Still fits.

  **Boundary**: `m5[last] + c2[last] + r0[last] = 0` (or `m5[last] + c2[last] = 0` if range response is merged into m5).

**Observation**: splitting the range bus dramatically reduces degree per column. The current degree-9 constraint was forced by having 7 denominators in one polynomial. With the split, the main-trace column is degree 6 and the chiplet column is degree 4.

#### B_HASH_KERNEL → split into main + chiplet columns

The hash kernel bus combines three logically separate tables. By trace region:

- **Chiplet entries**: sibling table (MV/MVA/MU/MUA) and ACE memory reads — all read from chiplet hasher/ACE columns.
- **Main entries**: log precompile (CAP_PREV/CAP_NEXT) — reads from decoder helpers and stack columns.

**Split into two columns:**

- **c3 (chiplet trace)**: accumulates sibling table + ACE memory entries

  ```
  c3' * requests_chiplet = c3 * responses_chiplet
  ```

  Degree: max entry is sibling at degree 7 → constraint degree **8** (same as current).

- **m6 (main trace)**: accumulates log precompile entries

  ```
  m6' * request_logpre = m6 * response_logpre
  ```

  The log precompile has two entries per row (request removes CAP_PREV, response inserts CAP_NEXT), both gated by `f_logprecompile` (degree 5), with degree-1 messages. Entry degree = 6 → constraint degree = **7**.

  **Alternatively**: since the log precompile entries are simple (degree 7 constraint, two entries), they could potentially be merged into an existing main-trace column that has slack. P1_BLOCK_STACK is degree 7 with 2 degrees of slack. However, merging unrelated tables into one running product changes the final value check and adds conceptual complexity. A dedicated column is cleaner.

- **Boundary**: `c3[last] * m6[last] = expected` where expected matches the original B_HASH_KERNEL final value.

### Summary: New Auxiliary Column Layout

| Column | Region | Bus Content | Protocol | Est. Degree |
|:------:|--------|-------------|----------|:-----------:|
| m0 | Main | P1_BLOCK_STACK | Running Product | 7 |
| m1 | Main | P2_BLOCK_HASH | Running Product | 9 |
| m2 | Main | P3_OP_GROUP | Running Product | 9 |
| m3 | Main | P1_STACK | Running Product | 9 |
| m4 | Main | B_CHIPLETS requests | Running Product | 9 |
| m5 | Main | B_RANGE stack lookups (+ range response?) | LogUp | 6 (or 8 with range) |
| m6 | Main | B_HASH_KERNEL log precompile | Running Product | 7 |
| c0 | Chiplet | V_WIRING | LogUp | 8 |
| c1 | Chiplet | B_CHIPLETS responses | Running Product | 8 |
| c2 | Chiplet | B_RANGE memory lookups | LogUp | 4 |
| c3 | Chiplet | B_HASH_KERNEL sibling + ACE memory | Running Product | 8 |
| (r0) | Range | B_RANGE range responses | LogUp | 2 |

**Column count**: 7 main + 4 chiplet + (1 range) = **12** total, up from 8. If range response is merged into m5, it's **11** columns.

**Tradeoff**: 3 extra auxiliary columns, but each column's constraint touches only one trace region. The chiplet-side columns all have significant degree slack (4, 8, 8 vs the degree-9 cap).

### Cross-Region Boundary Checks

The split introduces 3 new cross-column relationships that the verifier must check:

1. **B_CHIPLETS**: `m4[last] * kernel_correction = c1[last]`
   - `kernel_correction` is computed from public inputs (kernel procedure digests), same as the current `reduced_kernel_digests`

2. **B_RANGE**: `m5[last] + c2[last] (+ r0[last]) = 0`
   - LogUp: the sum of all entries across all columns must be zero

3. **B_HASH_KERNEL**: `c3[last] * m6[last] = expected`
   - The expected value comes from the current B_HASH_KERNEL final value computation in `reduced_aux_values`

These checks happen in the `reduced_aux_values` function, which already performs boundary verification for the current 8 columns. The split doesn't change the verification model — it just adds more final-value equations.

### Open Questions

1. **Where does the range trace go?** The range checker columns (V, M) sit at indices 49–50, between main and chiplet traces. If we're strict about the split, the range response column (r0) needs to be assigned to one side. Merging into m5 seems natural (the stack lookups and range responses are both part of the same LogUp identity).

2. **Could m6 (log precompile) merge into m0 (P1_BLOCK_STACK)?** Both are main-trace running products with degree ≤ 7. Merging would save a column. The cost: the final value becomes a product of both tables' contributions, complicating the verifier's boundary check slightly. The op_flags that gate log precompile entries are mutually exclusive with block stack entries (LOGPRECOMPILE never happens at the same cycle as JOIN/SPLIT/etc.), so the running product would just interleave the two tables' entries.

3. **Could the chiplet-side columns merge?** c1 (chiplet bus responses, degree 8), c2 (memory range lookups, degree 4), and c3 (sibling + ACE, degree 8) are all on the chiplet trace. They could potentially share columns if we're OK with mixing running products and LogUp. However, mixing protocols in one column is non-standard and complicates the final value check. Keeping them separate is cleaner.

4. **Does the split change the prover's work?** Each auxiliary column requires the prover to compute a running product or LogUp accumulator. With 11–12 columns instead of 8, the prover does ~40% more auxiliary trace work. However, the auxiliary trace is typically much cheaper than the main trace commitment, so this is likely acceptable.

---

## Research: Message Inventory for All-LogUp Formulation

### Goal

If we transition all buses to LogUp (no more running products), column assignment is no longer dictated by "which table does this entry belong to." Instead, the question becomes: **which entries can share a LogUp column without exceeding the degree budget?**

In LogUp, each column accumulates:Here is the follow-up explanation of how the lookup constraint is derived, and how to count degrees for packing.

# Deriving the normalized lookup constraint

We start from one accumulator column with running value `acc`, next-row value `acc_next`, and define

Delta = acc_next - acc

A lookup contribution is a rational sum of reduced interactions:

sum_i (m_i / d_i)

where:
- `m_i` is the multiplicity expression
- `d_i` is the reduced denominator expression

The intended update is:

Delta = sum_i (m_i / d_i)

To turn this into a polynomial constraint, we clear denominators.

Let

D = product_i d_i

and for each interaction `i`, let

P_i = product of all d_j except d_i

Then multiplying both sides by `D` gives:

D * Delta - sum_i (m_i * P_i) = 0

This is the normalized batch constraint.

Equivalently:
- `D` is the total denominator product
- `N = sum_i (m_i * P_i)` is the normalized numerator
- the constraint is

  D * Delta - N = 0

# Why this is the right formula

Because:

D * (m_i / d_i) = m_i * (D / d_i) = m_i * P_i

So clearing denominators preserves the intended rational identity.

# Selector-gated batches

Now suppose a whole batch is guarded by selector `s`.

Then the intended behavior is:
- if `s = 1`, apply the batch update
- if `s = 0`, batch contributes nothing

Inside a group, batches are mutually exclusive alternatives, so each batch contributes through selector-gated terms.

For one batch with normalized pair `(D_B, N_B)`, the group accumulates terms like:

s * D_B
s * N_B

The inactive case is handled at the group level by adding:

1 - sum(selectors in group)

to the group denominator factor.

So a finalized group is represented by:

U_G = (1 - S_G) + sum_batches (s_B * D_B)
V_G = sum_batches (s_B * N_B)

where

S_G = sum_batches s_B

Then the group contributes the effective normalized factor:

U_G * Delta - V_G

Interpretation:
- if no batch is active, `U_G = 1` and `V_G = 0`, so the group contributes just `Delta`
- if one batch is active, `U_G` and `V_G` become that batch’s normalized pair

# Combining groups into one column

Different groups may all contribute in the same row.

Suppose a column contains groups `G_1, ..., G_t`.
Each group is represented by a pair `(U_j, V_j)`.

The intended update is that all group contributions add together rationally.
Rather than materializing all cross terms explicitly, we combine groups incrementally as normalized pairs.

If the current accumulated column state is:

T_D * Delta - T_N

and the next group contributes:

U * Delta - V

then the combined normalized pair is:

T_D' = T_D * U
T_N' = T_N * U + T_D * V

So after processing all groups, the final column constraint is:

T_D * Delta - T_N = 0

This is just repeated denominator clearing.

# Why group costs add across a column

Because when combining two normalized factors:

(D1 * Delta - N1)
(D2 * Delta - N2)

the combined denominator multiplies:

D_total = D1 * D2

and the combined numerator gets terms multiplied by the other denominator.
So degrees add across independent groups.

That is the core reason packing is additive across groups.

# Degree counting for one batch

For a batch with interactions `(m_1, d_1), ..., (m_n, d_n)`:

D = product_i d_i
N = sum_i (m_i * P_i)

where `P_i` is the product of all `d_j` except `d_i`.

Define:
- `deg(m_i)` = degree of multiplicity `m_i`
- `deg(d_i)` = degree of denominator `d_i`
- `deg(Delta)` = degree of `acc_next - acc`

Then:

deg(D) = sum_i deg(d_i)

For each term in `N`:

deg(m_i * P_i) = deg(m_i) + sum_{j != i} deg(d_j)

So:

deg(N) = max_i [ deg(m_i) + sum_{j != i} deg(d_j) ]

The normalized batch constraint is:

D * Delta - N

Therefore its degree is:

deg(batch_norm) = max( deg(D) + deg(Delta), deg(N) )

That is the true polynomial degree of the batch before selector gating.

# Degree counting for a selector-gated batch

If a batch is guarded by selector `s_B`, then its contribution to a group is through:

s_B * D_B
s_B * N_B

So the gated batch cost is:

deg(batch_gated) = deg(s_B) + max( deg(D_B), deg(N_B) )

Equivalently, since:

deg(batch_norm) = max( deg(D_B) + deg(Delta), deg(N_B) )

the group-side cost excludes the final outer `Delta`, so for planning use:

cost(batch in group) = deg(s_B) + max( deg(D_B), deg(N_B) )

# Degree counting for a group

A group contains mutually exclusive batches.
Only one batch in the group can be active in a row.

That means alternatives inside the group do NOT add in degree.
Instead, the group cost is the worst alternative.

So for group `G` with batches `B_1, ..., B_k`:

cost(group) = max_r cost(batch B_r in group)

Important:
- group cost is a MAX over mutually exclusive alternatives
- not a sum

This is exactly why grouping is valuable.

# Degree counting for a column

A column contains independent groups that may all contribute in the same row.

So if groups `G_1, ..., G_t` are packed into one column, the degree is:

deg(column) = deg(Delta) + sum_j cost(G_j)

In the common case `deg(Delta) = 1`, this becomes:

deg(column) = 1 + sum_j cost(G_j)

This is the packing rule.

A candidate set of groups fits in one column iff:

deg(Delta) + sum_j cost(G_j) <= D_max

# Why optimal packing should use this rule

When alternatives are mutually exclusive:
- keeping them in the same group costs the maximum batch cost among them

When groups are independent:
- putting them in the same column adds their costs

So the planner should optimize by:
1. identifying mutually exclusive alternatives and grouping them
2. computing each group cost as a max
3. packing independent groups into columns by additive cost

This is the key principle:

- MAX within a group
- SUM across groups in a column

# What is bad for degree

It is bad to flatten mutually exclusive alternatives into one batch.

If several alternatives are flattened into one batch, their denominators all enter the same total denominator product `D`, so the degree grows like the sum of all those alternatives.

This destroys the main degree-saving benefit of grouping.

So the planner should avoid flattening across mutually exclusive alternatives whenever possible.

# Practical packing rule

For each candidate group:
- compute `cost(group)`

Then fill columns greedily or otherwise using:

current_column_degree = deg(Delta) + sum(cost(group already in column))

A new group fits iff:

current_column_degree + cost(new_group) <= D_max

If not, start a new column.

# Summary

The lookup constraint is derived by:
- writing the intended rational accumulator update
- multiplying by the product of denominators
- getting a normalized polynomial constraint of the form

  D * Delta - N = 0

Degrees should be counted as:
- batch: from actual normalized denominator/numerator degrees
- group: max over mutually exclusive batches
- column: sum over independent groups, plus the final `Delta`

So the planner should reason with:

- normalized batch degree
- grouped max
- columnwise sum

This is the right abstraction for minimizing the number of columns under a degree bound.
```
v' - v = Σ_i (numerator_i / denominator_i)
```

After clearing the common denominator D = Π den_i, the constraint becomes:
```
(v' - v) * D = Σ_i (num_i * Π_{j≠i} den_j)
```

If there are k denominator terms (each degree 1), the constraint degree is:
```
degree = max(1 + k, max_flag_deg + k - 1)
```

The degree-9 limit gives: **k ≤ min(8, 10 - max_flag_deg)**.

| Max flag degree in column | Max denominator terms (k) |
|:-------------------------:|:-------------------------:|
| 7 | 3 |
| 6 | 4 |
| 5 | 5 |
| 4 | 6 |
| 3 | 7 |
| 2 | 8 |
| 1 | 8 |

This is the fundamental packing constraint. A column with a degree-7 flag can afford only 3 denominator terms total. A column with only degree-4 flags can afford 6.

### Why mutual exclusivity matters

If entries A and B have **mutually exclusive** flags (never both nonzero on the same row), they share the same "slot" in the flag×denominator budget — at most one fires per row, so the degree is `max(deg_A, deg_B)` for the flag, not `deg_A + deg_B`. However, their denominators still both appear in the common denominator D, each contributing +1 to k.

If entries A and B have the **same flag** and the **same denominator**, they can be merged into one term with a combined numerator: `(num_A + num_B) / den`. This doesn't increase k at all.

If entries fire **simultaneously** (both flags nonzero on the same row), they must have separate denominator terms in D, and the degree cost is additive: both denominators contribute to k.

So the strategy is:
1. **Identify entries that fire simultaneously** — they MUST occupy separate denominator slots in D.
2. **Count the maximum simultaneous slots per row** — this is the minimum k for the column.
3. **Check that max_flag_deg + k - 1 ≤ 9.**

### Activation model

The main trace has one opcode executing per cycle. Within a cycle, multiple bus entries may fire simultaneously if they belong to different logical tables. The following non-opcode conditions can also fire independently:

| Condition | Flag expression | Degree | When it fires |
|-----------|----------------|:------:|---------------|
| Opcode = X | `op_flag_X` | 4–7 | Exactly one per cycle |
| In-span group decode | `sp * (gc - gc')` | 2 | Any cycle inside SPAN where group count decrements |
| u32 range check | `u32_rc_op` = op_bit6 * !op_bit5 * !op_bit4 | 3 | Opcodes 64–79 (U32ADD..U32MADD) |

The opcode flag, the group decode flag, and the range check flag can all be nonzero on the same row (e.g., a U32ADD inside a SPAN at a group boundary). But u32_rc_op is actually implied by the opcode — it's nonzero exactly when the opcode is in range 64–79. So it's not independent; it's a coarser filter over the same opcodes.

On the chiplet trace, one chiplet is active per row, and within each chiplet, specific sub-flags select the row type.

### Main-trace message inventory by opcode

The range trace (V, M columns) is assigned to the main side.

For each opcode, we list every message that fires on the main trace. Messages from different logical buses (p1, p2, p3, chiplets-request, range, hash-kernel-logpre) are shown together because they all fire simultaneously and would all need denominator slots in a shared LogUp column.

In the table below, "messages" counts distinct denominator terms. A product of N sub-messages (like HPERM = input × output) becomes N separate LogUp terms. Insertions count as +1/msg, removals as -1/msg.

#### Control flow opcodes

| Opcode | Flag Deg | p1_block_stack | p2_block_hash | p3_op_group | chiplets_req | other | Total msgs |
|--------|:--------:|:--------------:|:-------------:|:-----------:|:------------:|:-----:|:----------:|
| **JOIN** | 5 | +1 (push) | +1, +1 (left, right) | — | 1 (hasher) | — | **4** |
| **SPLIT** | 5 | +1 | +1 (cond select, msg deg 2) | — | 1 (hasher) | — | **3** |
| **LOOP** | 5 | +1 | +1 (conditional on s0) | — | 1 (hasher) | — | **3** |
| **REPEAT** | 4 | — | +1 | — | — | — | **1** |
| **SPAN** | 5 | +1 | — | +1..+7 (batch groups) | 1 (hasher) | — | **3–9** |
| **RESPAN** | 4 | +1 (push), −1 (pop) | — | +1..+7 (batch groups) | 1 (rate msg) | — | **4–10** |
| **END** | 4 | −1 (pop) | −1 (pop, msg deg 4) | — | 1 (digest) | — | **3** |
| **CALL** | 4 | +1 | +1 | — | 1 (hasher), 1 (fmp_write) | — | **4** |
| **SYSCALL** | 4 | +1 | +1 | — | 1 (hasher), 1 (kernel_rom) | — | **4** |
| **DYN** | 5 | +1 | +1 | — | 1 (hasher_zeros), 1 (callee_read) | — | **4** |
| **DYNCALL** | 5 | +1 | +1 | — | 1 (zeros), 1 (callee_read), 1 (fmp_write) | — | **5** |
| **HALT** | 4 | — | — | — | — | — | **0** |

#### Memory opcodes

| Opcode | Flag Deg | chiplets_req | Total msgs |
|--------|:--------:|:------------:|:----------:|
| **MLOAD** | 7 | 1 (elem read) | **1** |
| **MSTORE** | 7 | 1 (elem write) | **1** |
| **MLOADW** | 7 | 1 (word read) | **1** |
| **MSTOREW** | 7 | 1 (word write) | **1** |

#### Hasher opcodes

| Opcode | Flag Deg | chiplets_req | Total msgs |
|--------|:--------:|:------------:|:----------:|
| **HPERM** | 5 | 2 (input + output hasher msgs) | **2** |
| **MPVERIFY** | 5 | 2 (input + output word msgs) | **2** |
| **MRUPDATE** | 4 | 4 (old_in + old_out + new_in + new_out) | **4** |

#### Multi-memory opcodes

| Opcode | Flag Deg | chiplets_req | Total msgs |
|--------|:--------:|:------------:|:----------:|
| **MSTREAM** | 5 | 2 (word_read × 2) | **2** |
| **PIPE** | 5 | 2 (word_write × 2) | **2** |
| **CRYPTOSTREAM** | 4 | 4 (read × 2 + write × 2) | **4** |
| **HORNERBASE** | 5 | 2 (elem_read × 2) | **2** |
| **HORNEREXT** | 5 | 1 (word_read) | **1** |

#### Bitwise opcodes

| Opcode | Flag Deg | chiplets_req | Total msgs |
|--------|:--------:|:------------:|:----------:|
| **U32AND** | 7 | 1 (bitwise) | **1** |
| **U32XOR** | 7 | 1 (bitwise) | **1** |

#### ACE/log opcodes

| Opcode | Flag Deg | chiplets_req | hash_kernel | Total msgs |
|--------|:--------:|:------------:|:-----------:|:----------:|
| **EVALCIRCUIT** | 5 | 1 (ace_init) | — | **1** |
| **LOGPRECOMPILE** | 5 | 2 (hasher input + output) | +1 (cap_next), −1 (cap_prev) | **4** |

#### u32 arithmetic opcodes (64–79)

These fire B_RANGE stack lookups in addition to their own entries. Most have no chiplets bus entry.

| Opcode | Flag Deg | range_stack_lookups | Total msgs |
|--------|:--------:|:-------------------:|:----------:|
| **U32ADD..U32MADD** | 6 | 4 (sv0..sv3) | **4** |

#### In-span group decode (overlaps with any in-span opcode)

| Condition | Flag Deg | p3_op_group | Total msgs |
|-----------|:--------:|:-----------:|:----------:|
| `sp * (gc - gc')` | 2 | −1 (group removal) | **1** |

This fires simultaneously with whatever opcode is executing inside the span. So for an opcode like MLOAD inside a span at a group boundary, the total is: 1 (chiplets) + 1 (group decode) = 2 messages.

### Chiplet-trace message inventory by row type

On the chiplet trace, exactly one chiplet is active per row. The entries are responses (to B_CHIPLETS), plus any additional bus entries tied to that chiplet.

| Row Type | Selector | Entries | Total msgs |
|----------|----------|---------|:----------:|
| **Hasher: f_bp** (init, cycle 0) | hasher, s=[1,0,0] | B_CHIPLETS response (full state msg) | **1** |
| **Hasher: f_mp** (Merkle verify) | hasher, s=[1,0,1] | B_CHIPLETS response (word, cond select msg deg 2) | **1** |
| **Hasher: f_mv** (MR update old) | hasher, s=[1,1,0] | B_CHIPLETS response (word, cond select) + B_HASH_KERNEL sibling response (cond select) | **2** |
| **Hasher: f_mu** (MR update new) | hasher, s=[1,1,1] | B_CHIPLETS response (word, cond select) + B_HASH_KERNEL sibling request (cond select) | **2** |
| **Hasher: f_mva** (MR old, row 31) | hasher, cycle 31 | B_HASH_KERNEL sibling response (cond select) | **1** |
| **Hasher: f_mua** (MR new, row 31) | hasher, cycle 31 | B_HASH_KERNEL sibling request (cond select) | **1** |
| **Hasher: f_hout** (return hash) | hasher, s=[0,0,0], cycle 31 | B_CHIPLETS response (word msg) | **1** |
| **Hasher: f_sout** (return state) | hasher, s=[0,0,1], cycle 31 | B_CHIPLETS response (full state msg) | **1** |
| **Hasher: f_abp** (absorption) | hasher, s=[1,0,0], cycle 31 | B_CHIPLETS response (rate msg) | **1** |
| **Hasher: other rows** | hasher, mid-cycle | (no bus entries) | **0** |
| **Bitwise: last of 8-cycle** | bitwise, k_transition=0 | B_CHIPLETS response (bitwise msg, msg deg 2) | **1** |
| **Bitwise: other rows** | bitwise, mid-cycle | (no bus entries) | **0** |
| **Memory: every row** | memory | B_CHIPLETS response (memory msg, msg deg 3) + B_RANGE 2 memory lookups (D0, D1) | **3** |
| **ACE: start row** | ACE, start_sel=1 | B_CHIPLETS response (ace_init msg) + B_HASH_KERNEL ACE entry | **2** |
| **ACE: read row** | ACE, sblock=0 | B_HASH_KERNEL ACE word read + V_WIRING (2 wire inserts) | **3** |
| **ACE: eval row** | ACE, sblock=1 | B_HASH_KERNEL ACE elem read + V_WIRING (1 insert + 2 removes) | **4** |
| **Kernel ROM: every row** | kernel ROM | B_CHIPLETS response (kernel msg, msg deg 2) | **1** |

All hasher/bitwise/memory/ACE/kernel ROM row types are mutually exclusive (chiplet selectors).

Within ACE rows, the V_WIRING entries use a LogUp formulation with 3 wire denominators (already degree 8). If wiring stays in its own column, that's fine. If merged with other ACE entries, the denominator count grows.

---

## Research: All-LogUp Column Packing via Batch/Group/Column Model

### Cost model

We use the batch/group/column framework for packing lookup interactions into auxiliary accumulator columns under degree bound D_max = 9.

A **reduced interaction** is a fraction `m / d` where `m` is the multiplicity expression and `d = alpha + linear_combination(values)` is the reduced denominator. Importantly, `deg(d)` can be > 1 when the values inside the encoding are higher-degree expressions (conditional selects, computed opcodes, etc.). Similarly, `deg(m)` can be > 0 when the multiplicity is a trace expression rather than a constant.

**Batch**: interactions simultaneously active on the same row. A batch with interactions `(m_1, d_1), ..., (m_n, d_n)` has normalized constraint `D · Δ − N = 0` where:
- `D = Π d_i`, with `deg(D) = Σ deg(d_i)`
- `N = Σ_i (m_i · P_i)` where `P_i = Π_{j≠i} d_j`, with `deg(N) = max_i(deg(m_i) + Σ_{j≠i} deg(d_j))`
- `deg(Δ) = 1`

The normalized batch degree is:

```
deg(batch_norm) = max(deg(D) + deg(Δ), deg(N))
```

**Common case**: when all `m_i` are constants (multiplicity ±1), `deg(N) = deg(D) − min_i(deg(d_i))`. Since `deg(d_i) ≥ 1`, we get `deg(N) ≤ deg(D) − 1 < deg(D) + 1`, so the batch norm simplifies to `deg(D) + 1`.

**Exception**: when a multiplicity has `deg(m_i) > 0` (e.g., range response where M is a trace column with deg 1), the `deg(N)` term can dominate. The full `max(deg(D) + 1, deg(N))` must be checked.

**Selector-gated batch cost**: a batch guarded by selector `s` contributes to a group with cost:

```
cost(batch in group) = deg(s) + max(deg(D), deg(N))
```

This strips the `deg(Δ)` factor (which is applied once at the column level).

**Group**: mutually exclusive batches. Cost = `max` over batches:

```
cost(group) = max_r cost(batch B_r in group)
```

This is a `max`, not a sum — at most one batch is active per row.

**Column**: independent groups, all potentially active on the same row. Costs add:

```
deg(column) = deg(Δ) + Σ_j cost(G_j) ≤ D_max
```

So a group with cost C consumes C out of the budget `D_max - 1 = 8`.

### Main-trace interaction inventory

For each opcode, we list all interactions that fire simultaneously on the main trace, with their degrees. Each opcode is one **batch**; all opcodes together form one **group** (since opcodes are mutually exclusive).

Notation: each interaction is `(m, d)` with `deg(m)` and `deg(d)`. We compute `deg_D = Σ deg(d_i)`.

#### Control-flow opcodes

**JOIN** (selector deg 5):
- p1_block_stack push: m=+1 (deg 0), d=encode([block_id', parent_id, 0]) → deg(d)=1
- p2_block_hash left child: m=+1 (deg 0), d=encode([parent, h0..3, 1, 0]) → deg(d)=1
- p2_block_hash right child: m=+1 (deg 0), d=encode([parent, h4..7, 0, 0]) → deg(d)=1
- chiplets_req hasher: m=−1 (deg 0), d=hasher_msg([label, addr', 0, h[0..7], 0, opcode, 0, 0]) → deg(d)=1
- `deg(D) = 4`, `deg(N) = max_i(0 + 3) = 3`, `max(D, N) = 4`, `cost = 5 + 4 = 9`

**SPLIT** (selector deg 5):
- p1_block_stack push: deg(d)=1
- p2_block_hash child: d=encode([parent, s0*h0+(1-s0)*h4, ..., 0, 0]) → deg(d)=**2** (conditional select)
- chiplets_req hasher: deg(d)=1
- `deg(D) = 1+2+1 = 4`, `deg(N) = max(0+3, 0+2, 0+3) = 3`, `max(D, N) = 4`, `cost = 5 + 4 = 9`

**LOOP** (selector for the p2 entry is `is_loop * s0`, deg **6**; p1 and chiplets use `is_loop` deg 5):
- p1_block_stack push: sel=is_loop(5), deg(d)=1
- p2_block_hash body (conditional on s0=1): sel=is_loop*s0(6), deg(d)=1
- chiplets_req hasher: sel=is_loop(5), deg(d)=1

This is tricky: p2 only fires when s0=1, but p1 and chiplets always fire on LOOP. So p2 is in a DIFFERENT batch than p1+chiplets on LOOP rows. More precisely, on a LOOP row:
- p1 + chiplets always fire (batch A, sel=is_loop deg 5, deg_D=2)
- p2 fires only when s0=1 (batch B, sel=is_loop*s0 deg 6, deg_D=1)

These two batches are NOT mutually exclusive — both fire when s0=1. They are two independent **groups** contributing to the same row. Total column cost from this row: cost(group_A containing batch_A) + cost(group_B containing batch_B) = (5+2) + (6+1) = 7 + 7 = 14 → column degree = 1 + 14 = 15. Way over budget.

This means p2_block_hash must be in a SEPARATE column from p1+chiplets, even on LOOP rows. The LOOP-with-s0 analysis confirms what we already know: p2 needs its own column.

For the remainder, we analyze each opcode assuming p1 and p2 are in their own columns:

**LOOP** (without p2): sel=5, chiplets_req(1). deg_D=1, cost=5+1=6. But wait — p1 also fires. If p1 is in a separate column, the chiplets-request column sees only 1 interaction. cost=5+1=6.

**REPEAT** (selector deg 4): only p2 fires. In p2's column: cost=4+1=5.

**SPAN** (selector deg 5, p3 in own column):
- p1_block_stack push: deg(d)=1 → in p1 column
- chiplets_req hasher: deg(d)=1 → in chiplets-req column
- p3 insertions: 1–7 groups → in p3 column
- Per-column cost: p1 sees 5+1=6, chiplets-req sees 5+1=6, p3 sees up to 1+7=8.

**RESPAN** (selector deg 4, p3 in own column):
- p1 push: deg(d)=1 → in p1 column
- p1 pop: deg(d)=1 → in p1 column (same column, simultaneous with push → batch of 2)
- chiplets_req rate msg: deg(d)=1 → in chiplets-req column
- p3 insertions: → in p3 column
- p1 column batch: 2 interactions, deg_D=2, cost=4+2=6.

**END** (selector deg 4):
- p1_block_stack pop: deg(d)=1 → in p1 column, cost=4+1=5
- p2_block_hash pop: m=−1 (deg 0), deg(d)=**4** (is_first_child from next-row op flags) → in p2 column. `deg(D)=4, deg(N)=0, max=4`, cost=4+4=**8**
- chiplets_req digest: deg(d)=1 → in chiplets-req column, cost=4+1=5

**CALL** (selector deg 4):
- p1 push: deg(d)=1 → p1 column
- p2 push: deg(d)=1 → p2 column
- chiplets_req hasher + fmp_write: batch of 2, deg_D=2, cost=4+2=6

**SYSCALL** (selector deg 4):
- p1 push, p2 push → own columns
- chiplets_req hasher + kernel_rom: batch of 2, deg_D=2, cost=4+2=6

**DYN** (selector deg 5):
- p1 push, p2 push → own columns
- chiplets_req zeros_hasher + callee_read: batch of 2, deg_D=2, cost=5+2=7

**DYNCALL** (selector deg 5):
- p1 push, p2 push → own columns
- chiplets_req zeros + callee_read + fmp_write: batch of 3, deg_D=3, cost=5+3=**8**

**HALT** (selector deg 4): no interactions, cost=0.

#### Memory opcodes

**MLOAD/MSTORE** (selector deg 7):
- chiplets_req mem_element: deg(d)=1, cost=7+1=**8**

**MLOADW/MSTOREW** (selector deg 7):
- chiplets_req mem_word: deg(d)=1, cost=7+1=**8**

#### Hasher opcodes

**HPERM** (selector deg 5):
- chiplets_req hasher_in + hasher_out: batch of 2, deg_D=2, cost=5+2=7

**MPVERIFY** (selector deg 5):
- chiplets_req word_in + word_out: batch of 2, deg_D=2, cost=5+2=7

**MRUPDATE** (selector deg 4):
- chiplets_req: 4 word messages, batch of 4, deg_D=4, cost=4+4=**8**

#### Multi-memory opcodes

**MSTREAM/PIPE** (selector deg 5): batch of 2, cost=5+2=7
**CRYPTOSTREAM** (selector deg 4): batch of 4, cost=4+4=**8**
**HORNERBASE** (selector deg 5): batch of 2, cost=5+2=7
**HORNEREXT** (selector deg 5): 1 interaction, cost=5+1=6

#### Bitwise opcodes

**U32AND/U32XOR** (selector deg 7): 1 interaction, deg(d)=1, cost=7+1=**8**

#### ACE/log opcodes

**EVALCIRCUIT** (selector deg 5): 1 interaction, cost=5+1=6

**LOGPRECOMPILE** (selector deg 5):
- chiplets_req hasher_in + hasher_out: batch of 2, deg_D=2, cost=5+2=7 (in chiplets-req column)
- hash_kernel cap_prev + cap_next: batch of 2, deg_D=2, cost=5+2=7 (in hash-kernel column)

#### Non-opcode overlapping entries

**In-span group decode** (selector `sp * (gc-gc')`, deg 2): 1 interaction, deg(d)=1 when all message elements are degree 1... but `group_value = is_push(5) * s0' + (1-is_push(5)) * (h0'*128+opcode')` has deg 6. So deg(d)=**6**, cost=2+6=**8**.

Wait — this needs careful checking. The denominator is `encode([block_id, gc, group_value])`. `block_id` and `gc` are degree-1 trace columns. `group_value` is degree 6 (from `is_push * s0'`). So `deg(d) = max(1, 1, 6) = 6`. Cost = 2 + 6 = **8**.

This fires simultaneously with whatever opcode is inside the span. It forms its own independent group, adding its cost to the column.

**Range stack lookups** (selector `u32_rc_op`, deg 3): 4 simultaneous interactions, each with deg(d)=1. Batch of 4, deg_D=4, cost=3+4=**7**.

These fire on opcodes 64–79 (U32ADD..U32MADD). Those opcodes have no chiplets-bus entries. So on a u32 arithmetic row inside a span, the active groups are: the opcode group (cost 0, no chiplets entry), plus range lookups (cost 7), plus maybe group decode (cost 8).

**Range response** (selector = M column, deg 1): 1 interaction, deg(d)=1, cost=1+1=**2**.

### Main-trace group costs and column assignment

We have these independent groups on the main trace, with their costs:

| Group | Mutual Exclusivity | Cost | Notes |
|-------|-------------------|:----:|-------|
| G_p1: block stack entries | opcodes are ME within this group | **6** | Worst: RESPAN batch of 2 (cost 4+2=6) or DYNCALL (5+1=6) |
| G_p2: block hash entries | opcodes are ME within this group | **8** | Worst: END with deg(d)=4 (cost 4+4=8) |
| G_chip: chiplets request entries | opcodes are ME within this group | **8** | Worst: MLOAD/U32AND at 7+1=8, DYNCALL at 5+3=8, MRUPDATE/CRYPTO at 4+4=8 |
| G_p3: op group entries | batches ME (g8/g4/g2 insertions vs removal) | **8** | Worst: g8 (sel=c0 deg 1, 7 msgs → 1+7=8) or removal (sel=sp*(gc-gc') deg 2, deg(d)=6 → 2+6=8) |
| G_range: range stack lookups | single batch (4 lookups) | **7** | sel=u32_rc_op(deg 3), 4×(m=−1, d=α+helper, deg(d)=1). D=4, N=3. max=4. cost=3+4=7 |
| G_range_resp: range response | single batch | **1** | sel=1(deg 0), m=M(deg 1), d=α+V(deg 1). D=1, N=1. max(D,N)=1. cost=0+1=1 |
| G_hk_main: hash kernel logpre | single batch (2 entries) | **7** | sel=f_logprecompile(deg 5), 2×(m=±1, deg(d)=1). D=2, N=1. max=2. cost=5+2=7 |
| ~~G_group_decode~~ | — | — | Merged into G_p3 (group removal is ME with insertions — different rows) |

Groups that can be **simultaneously active** on the same row (and therefore MUST be in different columns or fit additively in one column):

- Any opcode's entries + G_group_decode (inside SPAN)
- U32 arithmetic opcode's entries + G_range + G_group_decode (inside SPAN)
- G_range_resp fires on every row (range table provides values continuously)

Applying the packing rule: `deg(column) = 1 + Σ cost(groups_in_column) ≤ 9`, so the budget per column is 8.

**Overlap matrix** — pairs that fire simultaneously (and thus cost SUM when sharing a column):

| | G_p1 | G_p2 | G_chip | G_hk_main | G_p3 | G_range | G_range_resp |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| G_p1 | — | ✓ | ✓ | | ✓ | | ✓ |
| G_p2 | ✓ | — | ✓ | | | | ✓ |
| G_chip | ✓ | ✓ | — | ✓ (LOGPRE) | ✓ | | ✓ |
| G_hk_main | | | ✓ | — | | **ME** (opcodes) | ✓ |
| G_p3 | ✓ | | ✓ | | — | | ✓ |
| G_range | | | | **ME** | | — | ✓ |
| G_range_resp | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | — |

Key ME relationship enabling a merge:
- **G_hk_main ↔ G_range**: LOGPRECOMPILE and u32 arithmetic are different opcodes.

**Packing derivation:**

G_chip(8) + G_hk_main(7) overlap (LOGPRECOMPILE) → sum = 15 → separate columns.
G_hk_main(7) + G_range(7) are ME (different opcodes) → one group, cost = max(7,7) = 7.
G_range_resp(1) overlaps with everything but costs only 1 → absorb into cheapest column.

| Column | Groups | How costs combine | Total cost | Degree |
|:------:|--------|:------------------|:----------:|:------:|
| M1 | G_p1 + G_range_resp | Sum (overlap) | 6 + 1 = 7 | **8** |
| M2 | G_p2 | Single group | 8 | **9** |
| M3 | G_chip | Single group | 8 | **9** |
| M4 | {G_hk_main, G_range} | Max (ME opcodes) | max(7, 7) = 7 | **8** |
| M5 | G_p3 | Single group (insertions + removal are ME batches) | 8 | **9** |

**5 main-trace columns.**

### Chiplet-trace interaction inventory

On the chiplet trace, exactly one chiplet is active per row. Within each chiplet, specific sub-flags select the row type. All chiplet responses form one big mutually exclusive group.

However, some chiplet rows have additional interactions from hash_kernel or V_WIRING that fire simultaneously with the chiplet response. These are independent groups.

| Row Type | Flag (deg) | Chiplet response (deg(d)) | Hash kernel entries | Wiring entries |
|----------|:----------:|:-------------------------:|:-------------------:|:--------------:|
| Hasher f_bp (init) | 5 | 1 | — | — |
| Hasher f_mp (Merkle verify) | 5 | **2** (conditional leaf) | — | — |
| Hasher f_mv (MR old, row 0) | 5 | **2** (conditional leaf) | sibling resp, deg(d)=**2** | — |
| Hasher f_mu (MR new, row 0) | 5 | **2** (conditional leaf) | sibling req, deg(d)=**2** | — |
| Hasher f_mva (MR old, row 31) | 5 | — (no chiplet resp) | sibling resp, deg(d)=**2** | — |
| Hasher f_mua (MR new, row 31) | 5 | — (no chiplet resp) | sibling req, deg(d)=**2** | — |
| Hasher f_hout (return hash) | 5 | 1 | — | — |
| Hasher f_sout (return state) | 5 | 1 | — | — |
| Hasher f_abp (absorption) | 5 | 1 | — | — |
| Bitwise (last of 8-cycle) | 4 | **2** (computed label) | — | — |
| Memory (every row) | 3 | **3** (label + elem select) | — range: 2 lookups, deg(d)=1 each | — |
| ACE start | 5 | 1 | ACE entry, deg(d)=1 | — |
| ACE read | ~5 | — | ACE word read, deg(d)=1 | 2 wire inserts |
| ACE eval | ~5 | — | ACE elem read, deg(d)=1 | 3 wire entries |
| Kernel ROM | 5 | **2** (computed label) | — | — |

Define chiplet-trace groups:

**G_chip_resp**: all chiplet responses (mutually exclusive).
- Worst batch: memory response, sel=3, deg(d)=3. Cost = 3 + 3 = **6**.
- Hasher f_mv: sel=5, deg(d)=2. Cost = 5 + 2 = 7. Actually higher!
- Kernel ROM: sel=5, deg(d)=2. Cost = 5 + 2 = 7.
- Overall group cost: max across batches = **7**.

**G_hk_chip**: hash kernel chiplet entries (sibling table + ACE memory). Mutually exclusive within (different chiplet sub-rows).
- Sibling (MV/MU/MVA/MUA): sel=5, deg(d)=2. Cost = 5 + 2 = 7.
- ACE word read: sel=5, deg(d)=1. Cost = 5 + 1 = 6.
- ACE elem read: sel=5, deg(d)=1. Cost = 5 + 1 = 6.
- Overall group cost: **7**.

**G_range_chip**: range memory lookups (D0, D1 on memory rows). 2 simultaneous interactions.
- sel=chiplets_memory_flag (deg 3), 2 interactions each deg(d)=1. deg_D=2.
- Cost = 3 + 2 = **5**.

**G_wiring**: V_WIRING entries on ACE rows. Up to 3 simultaneous wire entries on EVAL rows.
- sel=ace_flag*is_eval (deg 5), 3 entries each deg(d)=1. deg_D=3.
- Cost = 5 + 3 = **8**.

Which groups overlap?
- G_chip_resp + G_hk_chip: overlap on hasher MV/MU rows (response + sibling). Simultaneous → costs add.
- G_chip_resp + G_range_chip: overlap on memory rows (response + D0/D1). Simultaneous → costs add.
- G_hk_chip + G_wiring: overlap on ACE rows (ACE memory read + wire entries). Simultaneous → costs add.
- G_chip_resp + G_wiring: ACE start row has both response and wiring (if wiring is active on start rows). Need to check... V_WIRING fires on all ACE rows. ACE start has a chiplet response. So yes, overlap.

Packing attempts:

**All in one column**: G_chip_resp(7) + G_hk_chip(7) + G_range_chip(5) + G_wiring(8) = 27. Column degree 28. Obviously not.

**Strategy**: separate groups that overlap into different columns.

On memory rows: G_chip_resp + G_range_chip fire. Cost = 7 + 5 = 12. Over budget.
On hasher MV/MU rows: G_chip_resp + G_hk_chip fire. Cost = 7 + 7 = 14. Over budget.
On ACE rows: G_hk_chip + G_wiring fire. Cost = 7 + 8 = 15. Over budget.

Each pair of overlapping groups blows the budget. Each needs its own column:

| Column | Groups | Worst-case cost | Degree |
|:------:|--------|:---------------:|:------:|
| C1 | G_chip_resp | 7 | **8** |
| C2 | G_hk_chip | 7 | **8** |
| C3 | G_range_chip | 5 | **6** |
| C4 | G_wiring | 8 | **9** |

Can we merge any? G_range_chip (cost 5) only overlaps with G_chip_resp (memory rows). If we keep them separate, C3 has lots of slack. Could G_range_chip merge with G_hk_chip? They overlap on... do they? G_range_chip fires on memory rows, G_hk_chip fires on hasher/ACE rows. Different chiplets → mutually exclusive! Group cost = max(5, 7) = 7. Column degree = 8. ✓

| Column | Groups | Cost | Degree |
|:------:|--------|:----:|:------:|
| C1 | G_chip_resp | 7 | **8** |
| C2 | G_hk_chip + G_range_chip (ME chiplets → one group) | max(7, 5) = 7 | **8** |
| C3 | G_wiring | 8 | **9** |

**3 chiplet-trace columns.**

But wait: can G_wiring merge with anything? G_wiring fires on ACE rows. G_chip_resp has ACE start batch (cost 5+1=6). They overlap on ACE start rows. Can't merge.

G_wiring and G_range_chip overlap? G_wiring on ACE rows, G_range_chip on memory rows. Different chiplets → ME! Could merge: max(8, 5) = 8, degree 9. But G_wiring is already in its own column at degree 9. Moving G_range_chip into it doesn't help (max stays 8 since G_hk_chip at 7 was the driver).

Actually, let's try: C2 = G_hk_chip + G_range_chip + G_wiring — are they all ME?
- G_hk_chip fires on hasher + ACE rows
- G_wiring fires on ACE rows
- They OVERLAP on ACE rows! Costs add: 7 + 8 = 15. No.

So the best we can do is:

| Column | Groups | Cost | Degree |
|:------:|--------|:----:|:------:|
| C1 | G_chip_resp | 7 | **8** |
| C2 | G_hk_chip + G_range_chip | max(7, 5) = 7 | **8** |
| C3 | G_wiring | 8 | **9** |

### Summary: all-LogUp column layout

| Column | Region | Groups | Cost | Degree |
|:------:|--------|--------|:----:|:------:|
| M1 | Main | G_p1 (block stack) + G_range_resp | 6 + 1 = 7 | **8** |
| M2 | Main | G_p2 (block hash) | 8 | **9** |
| M3 | Main | G_chip (chiplets requests) | 8 | **9** |
| M4 | Main | G_hk_main (logpre) + G_range (stack lookups) (ME opcodes) | max(7, 7) = 7 | **8** |
| M5 | Main | G_p3 (op group) | 8 | **9** |
| C1 | Chiplet | G_chip_resp (all chiplet responses) | 7 | **8** |
| C2 | Chiplet | G_hk_chip (sibling + ACE mem) + G_range_chip (memory D0/D1) (ME chiplets) | max(7, 5) = 7 | **8** |
| C3 | Chiplet | G_wiring | 8 | **9** |

**Total: 5 main + 3 chiplet = 8 columns.** Same count as today, with uniform LogUp and clean trace-region separation.

### Degree budget utilization

| Column | Degree | Slack | Bottleneck |
|:------:|:------:|:-----:|------------|
| M1 | 8 | 1 | p1 RESPAN (batch of 2 push+pop, sel=4, deg_D=2) or DYNCALL (sel=5, deg_D=1) |
| M2 | 9 | 0 | END p2 pop: sel=4, deg(d)=4 from is_first_child → cost = 4+4 = 8 |
| M3 | 9 | 0 | MLOAD/U32AND (sel=7, deg(d)=1) or DYNCALL (sel=5, 3 msgs) or MRUPDATE (sel=4, 4 msgs) |
| M4 | 8 | 1 | LOGPRE hk entries (sel=5, batch of 2) or u32 range lookups (sel=3, batch of 4) |
| M5 | 9 | 0 | g8 batch: sel=c0(1), 7 interactions each deg(d)=1 → cost = 1+7 = 8 |
| C1 | 8 | 1 | Hasher f_mv (sel=5, deg(d)=2 conditional leaf) or kernel ROM (sel=5, deg(d)=2 computed label) |
| C2 | 8 | 1 | Sibling (sel=5, deg(d)=2 conditional bit select) |
| C3 | 9 | 0 | ACE eval (sel=5, 3 wire denominator terms) |

Four columns at degree 9 (M2, M3, M5, C3), four at degree 8 (M1, M4, C1, C2) with 1 degree slack each. The saturated columns are driven by: END's degree-4 `is_first_child` message (M2), degree-7 opcode flags (M3), g8 batch of 7 denominator products (M5), and ACE eval with 3 wire terms (C3).

### Comparison to current layout

| Metric | Current (8 cols, mixed protocols) | Proposed (8 cols, all-LogUp) |
|--------|:-:|:-:|
| Total columns | 8 | 8 |
| Max degree | 9 | 9 |
| Columns at degree 9 | 5 | 4 |
| Columns at degree 8 | 2 | 4 |
| Columns at degree 7 | 1 | 0 |
| Protocol | 6 running product + 2 LogUp | 8 LogUp |
| Trace-region separation | No (3 buses cross boundary) | Yes (all single-region) |

The all-LogUp layout achieves trace-region separation with the same column count. The degree distribution shifts: fewer columns are saturated at 9, more have 1 degree of slack. This headroom comes from the batch/group model avoiding unnecessary degree inflation from the naive common-denominator approach.
