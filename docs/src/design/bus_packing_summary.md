Suppose we want one accumulator update on a row of the form

$\partial = \sum_g R_g$

where each $g$ is an independent set, and each set contains several **mutually exclusive** batches.

We assume:
- $\partial := \mathrm{acc}_{next} - \mathrm{acc}$
- each selector is boolean
- inside each set $g$, the selectors are mutually exclusive, i.e. at most one batch is active
- different sets are independent, so several sets may contribute on the same row

The goal is to represent each set by one rational pair $(U_g, V_g)$ such that

$\partial = \sum_g \frac{V_g}{U_g}$

and then combine all sets into one final normalized constraint.

---

# 1. One batch of simultaneous interactions

First consider one batch $b$ with simultaneous interactions

$\sum_{i \in b} \frac{m_{b,i}}{v_{b,i}}$

where:
- $m_{b,i}$ is the multiplicity / numerator expression
- $v_{b,i}$ is the reduced denominator expression

Define the normalized fraction for this batch by

$D_b := \prod_{i \in b} v_{b,i}$

$N_b := \sum_{i \in b} m_{b,i} \prod_{k \in b,\, k \neq i} v_{b,k}$

so that

$\sum_{i \in b} \frac{m_{b,i}}{v_{b,i}} = \frac{N_b}{D_b}$

Equivalently, this can be built iteratively by

$N_0 = 0,\quad D_0 = 1$

$N_{j+1} = N_j v_j + m_j D_j$

$D_{j+1} = D_j v_j$

and then $(N_b, D_b)$ is the final pair.

The batch constraint, if this were the only contribution, would be

$\partial D_b - N_b = 0$

Degrees:
- $\deg(D_b) = \sum_{i \in b} \deg(v_{b,i})$
- $\deg(N_b) = \max_{i \in b} \left( \deg(m_{b,i}) + \sum_{k \in b,\, k \neq i} \deg(v_{b,k}) \right)$

Hence the batch constraint degree is

$\deg(\partial D_b - N_b) = \max(1 + \deg(D_b), \deg(N_b))$

since $\deg(\partial)=1$.

---

# 2. One set of mutually exclusive batches

Now fix one set $g$.

Suppose this set contains batches indexed by $r$, with mutually exclusive selectors $s_{g,r}$.
Batch $r$ contributes the rational value

$\frac{N_{g,r}}{D_{g,r}}$

where $(N_{g,r}, D_{g,r})$ is computed as above from the simultaneous interactions inside that batch.

Because the selectors are mutually exclusive, the whole set can be compressed into one rational pair $(U_g, V_g)$ defined by

$U_g := 1 + \sum_r s_{g,r}(D_{g,r} - 1)$

$V_g := \sum_r s_{g,r} N_{g,r}$

This works because:
- if no selector is active, then $U_g = 1$ and $V_g = 0$, so the contribution is $0$
- if exactly one selector $s_{g,r}=1$, then $U_g = D_{g,r}$ and $V_g = N_{g,r}$, so the contribution is $N_{g,r}/D_{g,r}$

Thus the rational contribution of set $g$ is

$R_g = \frac{V_g}{U_g}$

If this were the only set, the constraint would be

$\partial U_g - V_g = 0$

Degrees of the set-level pair:
- $\deg(U_g) = \max_r \left( \deg(s_{g,r}) + \deg(D_{g,r}) \right)$
- $\deg(V_g) = \max_r \left( \deg(s_{g,r}) + \deg(N_{g,r}) \right)$

Hence the single-set constraint degree is

$\deg(\partial U_g - V_g) = \max(1 + \deg(U_g), \deg(V_g))$

Important: this requires the selectors in the set to be **mutually exclusive**, not merely linearly independent.

---

# 3. Combining multiple independent sets

Now suppose we have several independent sets $g = 1,\dots,t$, each giving one pair $(U_g, V_g)$ and contribution

$R_g = \frac{V_g}{U_g}$

Then the intended update is

$\partial = \sum_{g=1}^t \frac{V_g}{U_g}$

To obtain one normalized constraint, combine the pairs by clearing denominators.

Define the total denominator

$U := \prod_{g=1}^t U_g$

and the total numerator

$V := \sum_{g=1}^t V_g \prod_{h \neq g} U_h$

Then

$\sum_{g=1}^t \frac{V_g}{U_g} = \frac{V}{U}$

so the final normalized constraint is

$\partial U - V = 0$

This is the full constraint for multiple independent sets packed into one accumulator.

Equivalent iterative combination rule:
if a current accumulated pair is $(U,V)$ and we add one more set $(\widetilde U, \widetilde V)$, then the updated pair is

$U' = U \widetilde U$

$V' = V \widetilde U + \widetilde V U$

starting from

$U^{(0)} = 1,\quad V^{(0)} = 0$

This is often the cleanest way to implement the algebra.

---

# 4. Degrees of the combined representation

For each set $g$, define

$a_g := \deg(U_g)$

$b_g := \deg(V_g)$

Then the combined pair satisfies

$\deg(U) = \sum_{g=1}^t a_g$

and

$\deg(V) \le \max_{g=1}^t \left( b_g + \sum_{h \neq g} a_h \right)$

Therefore the final constraint degree is

$\deg(\partial U - V) = \max\left( 1 + \sum_{g=1}^t a_g,\; \max_{g=1}^t \left( b_g + \sum_{h \neq g} a_h \right) \right)$

This is the general degree formula for packing several independent mutually-exclusive sets into one accumulator column.

---

# 5. Degrees of the components in expanded form

For each set $g$ and each batch $r$ in that set:

Batch denominator degree:
$\deg(D_{g,r}) = \sum_{i \in (g,r)} \deg(v_{g,r,i})$

Batch numerator degree:
$\deg(N_{g,r}) = \max_{i \in (g,r)} \left( \deg(m_{g,r,i}) + \sum_{k \in (g,r),\, k \neq i} \deg(v_{g,r,k}) \right)$

Set-level denominator degree:
$\deg(U_g) = \max_r \left( \deg(s_{g,r}) + \deg(D_{g,r}) \right)$

Set-level numerator degree:
$\deg(V_g) = \max_r \left( \deg(s_{g,r}) + \deg(N_{g,r}) \right)$

Combined denominator degree:
$\deg(U) = \sum_g \deg(U_g)$

Combined numerator degree:
$\deg(V) \le \max_g \left( \deg(V_g) + \sum_{h \neq g} \deg(U_h) \right)$

Final constraint degree:
$\deg(\partial U - V) = \max(1 + \deg(U), \deg(V))$

---

# 6. Common simplification

Often one has

$\deg(N_{g,r}) \le \deg(D_{g,r})$

for example when multiplicities are constant or lower-degree than the denominators.

In that common case,

$\deg(V_g) \le \deg(U_g)$

and therefore the final degree simplifies to

$\deg(\partial U - V) = 1 + \sum_g \deg(U_g)$

This is the additive packing rule:
- take the worst mutually-exclusive batch inside each set
- then sum those set costs across independent sets
- and finally add the outer $1$ for $\partial$

---

# 7. Conceptual summary

- A batch of simultaneous interactions is normalized into one pair $(N_b, D_b)$.
- A set of mutually exclusive batches is compressed into one pair $(U_g, V_g)$ using selectors.
- Multiple independent sets are combined by the usual rational-sum rule into one final pair $(U,V)$.
- The final constraint is always of the form

$\partial U - V = 0$

The correct planning abstraction is therefore:
- within a batch: simultaneous denominators add into $D_b$
- within a mutually-exclusive set: take the selector-gated max via $(U_g, V_g)$
- across independent sets: combine pairs additively as rationals, which multiplies the $U_g$'s and gives the mixed numerator formula for $V$

This is the right algebraic model for degree accounting and column packing.



# All-LogUp Bus Column Packing — Audit Summary

This document summarizes the proposed all-LogUp column packing for the Miden VM AIR, with degree bounds verified symbolically in `air/src/constraints/degree_audit.rs`.

## Cost Model

A LogUp accumulator column enforces `Δ = Σ (m_i / d_i)` where Δ = acc_next − acc. After clearing denominators: `D · Δ − N = 0`.

**Batch**: interactions simultaneously active on the same row.
```
cost(batch) = deg(selector) + max(deg(D), deg(N))
```
where `deg(D) = Σ deg(d_i)` and `deg(N) = max_i(deg(m_i) + Σ_{j≠i} deg(d_j))`.

**Group**: mutually exclusive batches. `cost(group) = max over batches`.

**Column**: independent groups. `deg(column) = deg(Δ) + Σ cost(groups) ≤ 9`.

## Flag Degrees (verified symbolically)

| Flag | Degree | Category |
|------|:------:|----------|
| MLOAD, MSTORE, MLOADW, MSTOREW, U32AND, U32XOR | 7 | Opcode (0–63) |
| right_shift | 6 | Composite |
| HPERM, MPVERIFY, SPLIT, LOOP, SPAN, JOIN, DYN, DYNCALL, EVALCIRCUIT, LOGPRECOMPILE, HORNERBASE, HORNEREXT, MSTREAM, PIPE, PUSH | 5 | Opcode (80–95) |
| control_flow | 5 | Composite |
| left_shift | 5 | Composite |
| MRUPDATE, CALL, SYSCALL, END, REPEAT, RESPAN, HALT, CRYPTOSTREAM | 4 | Opcode (96–127) |
| u32_rc_op = b6·(1−b5)·(1−b4) | 3 | Prefix selector |
| chiplets_memory_flag = s0·s1·(1−s2) | 3 | Chiplet selector |
| f_dg = sp·(gc−gc') | 2 | In-span group decode |
| overflow = (b0−16)·h0 | 2 | Stack depth test |

## Denominator Degrees (verified symbolically)

Most messages encode trace columns via `α + Σ β^i · col_i`, giving deg(d) = 1. Exceptions:

| Message | deg(d) | Reason |
|---------|:------:|--------|
| P2 SPLIT | 2 | Conditional select: `s0·h0 + (1−s0)·h4` |
| P2 END | 4 | `is_first_child = 1 − end_next − repeat_next − halt_next` (next-row flags each deg 4) |
| P3 group removal | 6 | `group_value = is_push(5)·s0' + (1−is_push)·(h0'·128+opcode')` |
| Hash kernel sibling | 2 | `encode_b0·(1−b) + encode_b1·b` (conditional on bit) |
| Memory chiplet response | 3 | Label computation (deg 2) + element mux `v_i·idx0·idx1` (deg 3) |
| Bitwise chiplet response | 2 | Label = `(1−sel)·AND_LABEL + sel·XOR_LABEL` |
| Kernel ROM response | 2 | Label = `s_first·INIT + (1−s_first)·CALL` |

## Mutual Exclusivity Proofs

The column packing relies on certain flags being mutually exclusive (ME). Each ME claim is enforced by AIR constraints:

| ME Claim | Enforcing Constraint | Degree |
|----------|---------------------|:------:|
| At most one opcode per row | 7 binary constraints: `b_i·(b_i−1) = 0` for each op bit | 2 |
| sp ∈ {0,1} (in-span vs control-flow) | `sp·(sp−1) = 0` | 2 |
| At most one chiplet per row | Hierarchical binary: `s0·(s0−1)=0`, `s0·s1·(s1−1)=0`, etc. | 2–5 |
| Hasher sub-flags ME | Selector patterns `(s1,s2)` cover all 4 combinations; cycle markers are periodic | 4 |
| Batch sizes ME | Binary: `c_i·(c_i−1)=0`; sum: `f_span+f_respan = f_g1+f_g2+f_g4+f_g8` | 2, 5 |
| P3 insertions vs removal | Insertions on SPAN/RESPAN (block boundary); removal on in-span decode (different rows) | Structural |
| G_logcap vs G_rstack | LOGPRECOMPILE and u32 arithmetic are different opcodes (ME by op bits) | 2 |

## Groups and Their Costs

### Main trace groups

| Group | Batches (worst case) | Cost | Key batch |
|-------|---------------------|:----:|-----------|
| **G_bstack** (block stack) | RESPAN push+pop: sel=4, 2×deg(d)=1 → 4+2=6 | **6** | |
| **G_bqueue** (block hash) | END: sel=4, deg(d)=4 → 4+4=8 | **8** | is_first_child inflates denominator |
| **G_creq** (chiplet requests) | MLOAD: sel=7, deg(d)=1 → 7+1=8 | **8** | Degree-7 flag is the bottleneck |
| **G_opgrp** (op group) | g8: sel=1, 7×deg(d)=1 → 1+7=8 | **8** | 7 simultaneous group insertions |
| **G_rstack** (range stack) | sel=3, 4×deg(d)=1 → 3+4=7 | **7** | 4 helper column lookups |
| **G_rtable** (range resp) | sel=0, m=M(deg 1), deg(d)=1 → 0+1=1 | **1** | Always active, costs 1 |
| **G_logcap** (logpre) | sel=5, 2×deg(d)=1 → 5+2=7 | **7** | cap_prev + cap_next |

### Chiplet trace groups

| Group | Batches (worst case) | Cost | Key batch |
|-------|---------------------|:----:|-----------|
| **G_cresp** (all responses) | Hasher f_mv: sel=5, deg(d)=2 → 5+2=7 | **7** | Conditional leaf select |
| **G_sibace** (sibling+ACE mem) | Sibling: sel=5, deg(d)=2 → 5+2=7 | **7** | Conditional bit select |
| **G_rmem** (mem D0/D1) | sel=3, 2×deg(d)=1 → 3+2=5 | **5** | |
| **G_wiring** (ACE wiring) | EVAL: sel=5, 3×deg(d)=1 → 5+3=8 | **8** | 3 wire terms |

## Column Assignment

### Overlap constraints

Groups that fire simultaneously must go in different columns (or their costs add). Key overlaps:

- G_bstack + G_bqueue + G_creq all fire on control-flow opcodes
- G_creq + G_logcap fire on LOGPRECOMPILE
- G_opgrp + G_bstack + G_creq fire on SPAN/RESPAN
- G_rtable fires every row

Key ME merges (groups that never fire on the same row → cost = max, not sum):

- **{G_logcap, G_rstack}**: LOGPRECOMPILE and u32 arithmetic are different opcodes
- **{G_sibace, G_rmem}**: hasher/ACE and memory are different chiplets

### Final layout

| Column | Region | Groups | How combined | Cost | Degree |
|:------:|--------|--------|:-------------|:----:|:------:|
| **M1** | Main | G_bstack + G_rtable | Sum (overlap) | 6 + 1 = 7 | **8** |
| **M2** | Main | G_bqueue | Single | 8 | **9** |
| **M3** | Main | G_creq | Single | 8 | **9** |
| **M4** | Main | {G_logcap, G_rstack} | Max (ME) | max(7,7) = 7 | **8** |
| **M5** | Main | G_opgrp | Single | 8 | **9** |
| **C1** | Chiplet | G_cresp | Single | 7 | **8** |
| **C2** | Chiplet | {G_sibace, G_rmem} | Max (ME) | max(7,5) = 7 | **8** |
| **C3** | Chiplet | G_wiring | Single | 8 | **9** |

**Total: 5 main + 3 chiplet = 8 columns.** All ≤ degree 9.

### Degree budget utilization

| Column | Degree | Slack | Bottleneck |
|:------:|:------:|:-----:|------------|
| M1 | 8 | 1 | G_bstack RESPAN batch (sel=4, deg_D=2) |
| M2 | 9 | 0 | G_bqueue END (sel=4, deg(d)=4 from is_first_child) |
| M3 | 9 | 0 | G_creq MLOAD/U32AND (sel=7, deg(d)=1) |
| M4 | 8 | 1 | G_logcap LOGPRE (sel=5, deg_D=2) or G_rstack (sel=3, deg_D=4) |
| M5 | 9 | 0 | G_opgrp g8 batch (sel=1, deg_D=7) |
| C1 | 8 | 1 | G_cresp hasher f_mv (sel=5, deg(d)=2) |
| C2 | 8 | 1 | G_sibace sibling (sel=5, deg(d)=2) |
| C3 | 9 | 0 | G_wiring EVAL (sel=5, 3 wire terms) |

4 columns at degree 9, 4 at degree 8. Same total count as the current 8-column layout, but with uniform LogUp protocol and clean main/chiplet trace separation.

## Verification

All degree claims are verified by `air/src/constraints/degree_audit.rs` which:

1. **Part 1**: Constructs every flag from symbolic trace variables and asserts `degree_multiple()` matches
2. **Part 2**: Constructs every message encoding and asserts denominator degrees
3. **Part 3**: Computes `cost(batch) = deg(s) + max(deg(D), deg(N))` for every batch and verifies column packing
4. **Part 4**: Verifies that ME claims are backed by binary constraints on the relevant flag variables

Run: `cargo test -p miden-air --lib degree_audit -- --nocapture`

---

# 8. Complete interaction inventory

This section lists every bus interaction in the Miden VM, organized into sets and batches following the notation from sections 1–7 above. We then compute all degrees and derive the column assignment.

## 8.1 Notation

Each interaction is a triple $(s, m, v)$:
- $s$ = selector (boolean, controls whether this interaction fires)
- $m$ = multiplicity ($+1$ for insert, $-1$ for remove, or a trace column for variable multiplicity)
- $v$ = reduced denominator ($\alpha + \sum \beta^i \cdot \text{elem}_i$)

A **batch** is a set of interactions that fire simultaneously when their shared selector is active.

A **set** is a collection of ME batches (at most one batch active per row).

Multiple sets can fire on the same row. A **column** contains one or more sets whose pair costs add.

For all interactions below, $\deg(m) = 0$ (constant $\pm 1$) unless explicitly noted. The common simplification from §6 applies: when $\deg(N_b) \le \deg(D_b)$ for every batch, $\deg(V_g) \le \deg(U_g)$, and the column degree reduces to $1 + \sum_g a_g$ where $a_g = \deg(U_g)$.

## 8.2 Main trace interactions

### Set $G_\text{bstack}$: Block stack table

Selectors are opcode flags (mutually exclusive by op-bit binary constraints).

| Batch (selector $s$) | $\deg(s)$ | Interactions | $\deg(D)$ | $\deg(N)$ | $a = \deg(s) + \deg(D)$ |
|---|:---:|---|:---:|:---:|:---:|
| JOIN ($s_\text{join}$) | 5 | $(+1,\; v_\text{push})$ with $\deg(v)=1$ | 1 | 0 | **6** |
| SPLIT ($s_\text{split}$) | 5 | $(+1,\; v_\text{push})$ | 1 | 0 | **6** |
| SPAN ($s_\text{span}$) | 5 | $(+1,\; v_\text{push})$ | 1 | 0 | **6** |
| DYN ($s_\text{dyn}$) | 5 | $(+1,\; v_\text{push})$ | 1 | 0 | **6** |
| LOOP ($s_\text{loop}$) | 5 | $(+1,\; v_\text{push})$ with $\deg(v)=1$ (is\_loop = $s_0$, a trace column) | 1 | 0 | **6** |
| DYNCALL ($s_\text{dyncall}$) | 5 | $(+1,\; v_\text{push})$ | 1 | 0 | **6** |
| CALL ($s_\text{call}$) | 4 | $(+1,\; v_\text{push\_full})$, all elements are trace cols | 1 | 0 | **5** |
| SYSCALL ($s_\text{syscall}$) | 4 | $(+1,\; v_\text{push\_full})$ | 1 | 0 | **5** |
| RESPAN ($s_\text{respan}$) | 4 | $(+1,\; v_\text{push}),\; (-1,\; v_\text{pop})$ — simultaneous push and pop | 2 | 1 | **6** |
| END ($s_\text{end}$) | 4 | $(-1,\; v_\text{pop})$; simple or full depending on call context | 1 | 0 | **5** |

All messages are `encode(trace_cols)` with $\deg(v) = 1$. The RESPAN batch is the costliest because it has two simultaneous interactions (push + pop), giving $\deg(D) = 2$.

$$a_{G_\text{bstack}} = \max(\ldots) = 6$$

### Set $G_\text{bqueue}$: Block hash table

Selectors are opcode flags (ME).

| Batch | $\deg(s)$ | Interactions $(m, v)$ | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| JOIN | 5 | $(+1, v_\text{left}),\; (+1, v_\text{right})$ — two children | 1, 1 | 2 | **7** |
| SPLIT | 5 | $(+1, v_\text{cond})$ where $v$ contains $s_0 h_i + (1{-}s_0) h_{i+4}$ | **2** | 2 | **7** |
| LOOP | 6 | $(+1, v_\text{body})$ — selector is $s_\text{loop} \cdot s_0$ | 1 | 1 | **7** |
| REPEAT | 4 | $(+1, v_\text{body})$ | 1 | 1 | **5** |
| DYN | 5 | $(+1, v_\text{child})$ | 1 | 1 | **6** |
| DYNCALL | 5 | $(+1, v_\text{child})$ | 1 | 1 | **6** |
| CALL | 4 | $(+1, v_\text{child})$ | 1 | 1 | **5** |
| SYSCALL | 4 | $(+1, v_\text{child})$ | 1 | 1 | **5** |
| END | 4 | $(-1, v_\text{end})$ where $v$ contains `is_first_child` (deg 4) | **4** | 4 | **8** |

Notes:
- JOIN has two simultaneous interactions ($n=2$ in the batch), making $\deg(D) = 2$.
- SPLIT has one interaction but $\deg(v) = 2$ from the conditional element select.
- LOOP has $\deg(s) = 6$ because the p2 entry only fires when $s_0 = 1$ (entering loop body), so the effective selector is $s_\text{loop} \cdot s_0$.
- END has $\deg(v) = 4$ because the `is_first_child` field is computed from next-row degree-4 op flags.

$$a_{G_\text{bqueue}} = 8 \quad \text{(driven by END)}$$

### Set $G_\text{creq}$: Chiplets bus requests

Selectors are opcode flags (ME). Each batch sends requests to one or more chiplets. Multiple sub-messages in a batch means multiple interactions.

| Batch | $\deg(s)$ | Interactions (count $n$) | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| JOIN | 5 | 1 hasher state msg | 1 | 1 | **6** |
| SPLIT | 5 | 1 hasher state msg | 1 | 1 | **6** |
| LOOP | 5 | 1 hasher state msg | 1 | 1 | **6** |
| SPAN | 5 | 1 hasher state msg | 1 | 1 | **6** |
| RESPAN | 4 | 1 hasher rate msg | 1 | 1 | **5** |
| END | 4 | 1 hasher digest msg | 1 | 1 | **5** |
| CALL | 4 | 1 hasher msg + 1 fmp\_write msg | 1, 1 | 2 | **6** |
| SYSCALL | 4 | 1 hasher msg + 1 kernel\_rom msg | 1, 1 | 2 | **6** |
| DYN | 5 | 1 hasher\_zeros msg + 1 callee\_read msg | 1, 1 | 2 | **7** |
| DYNCALL | 5 | 1 hasher\_zeros + 1 callee\_read + 1 fmp\_write | 1, 1, 1 | 3 | **8** |
| HPERM | 5 | 1 hasher\_in + 1 hasher\_out | 1, 1 | 2 | **7** |
| MPVERIFY | 5 | 1 word\_in + 1 word\_out | 1, 1 | 2 | **7** |
| MRUPDATE | 4 | 4 word messages (old in/out + new in/out) | 1×4 | 4 | **8** |
| MLOAD | 7 | 1 memory element msg | 1 | 1 | **8** |
| MSTORE | 7 | 1 memory element msg | 1 | 1 | **8** |
| MLOADW | 7 | 1 memory word msg | 1 | 1 | **8** |
| MSTOREW | 7 | 1 memory word msg | 1 | 1 | **8** |
| U32AND | 7 | 1 bitwise msg | 1 | 1 | **8** |
| U32XOR | 7 | 1 bitwise msg | 1 | 1 | **8** |
| HBASE | 5 | 2 element read msgs | 1, 1 | 2 | **7** |
| HEXT | 5 | 1 word read msg | 1 | 1 | **6** |
| MSTREAM | 5 | 2 word read msgs | 1, 1 | 2 | **7** |
| PIPE | 5 | 2 word write msgs | 1, 1 | 2 | **7** |
| CRYPTO | 4 | 4 word msgs (2 read + 2 write) | 1×4 | 4 | **8** |
| EVAL | 5 | 1 ACE init msg | 1 | 1 | **6** |
| LOGPRE | 5 | 1 hasher\_in + 1 hasher\_out | 1, 1 | 2 | **7** |

All chiplets-request messages encode trace columns with $\deg(v) = 1$. The cost differences come from (a) the selector degree and (b) how many sub-messages an opcode sends.

$$a_{G_\text{creq}} = 8 \quad \text{(driven by MLOAD, U32AND, DYNCALL, MRUPDATE, CRYPTOSTREAM, all at 8)}$$

Remark: the degree-8 batches reach it through two different mechanisms:
- MLOAD/U32AND: high selector degree (7) × single message
- DYNCALL/MRUPDATE/CRYPTO: lower selector degree (4–5) × multiple simultaneous messages

### Set $G_\text{opgrp}$: Op group table

This set has two kinds of batches (ME: insertions happen on SPAN/RESPAN cycles, removal happens on in-span decode cycles):

| Batch | $\deg(s)$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $\deg(N)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|:---:|
| g8 insert (SPAN/RESPAN) | 1 | 7 group messages $(+1, v_j)$ | 1×7 | 7 | 6 | **8** |
| g4 insert | 3 | 3 group messages | 1×3 | 3 | 2 | **6** |
| g2 insert | 3 | 1 group message | 1 | 1 | 0 | **4** |
| g1 insert | — | none (first group decoded immediately) | — | — | — | — |
| removal | 2 | $(-1, v_\text{remove})$ where $v$ has $\deg = 6$ | **6** | 6 | 0 | **8** |

The g8 batch has 7 simultaneous interactions because an 8-group batch inserts 7 entries at once (the first group is decoded immediately). With $n = 7$ degree-1 denominators: $\deg(D) = 7$, and $\deg(N) = \max_i(0 + 6) = 6 < 7$, so $a = 1 + 7 = 8$.

The removal denominator has $\deg(v) = 6$ because the `group_value` field contains `is_push(deg 5) * s0'` which is degree 6 inside the encoding.

$$a_{G_\text{opgrp}} = 8 \quad \text{(driven by g8 and removal, both at 8)}$$

### Set $G_\text{rstack}$: Range checker stack lookups

A single batch on u32 arithmetic opcodes (64–79):

| Batch | $\deg(s)$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| u32 arith | 3 | 4 lookups $(-1, \alpha + \text{helper}_i)$ | 1×4 | 4 | **7** |

The selector $s_\text{u32\_rc} = b_6 (1{-}b_5)(1{-}b_4)$ has degree 3.

$$a_{G_\text{rstack}} = 7$$

### Set $G_\text{range\_resp}$: Range table response

Always active (selector = 1, degree 0). **This is the one case where $\deg(m) > 0$.**

| Batch | $\deg(s)$ | Interactions | $\deg(m)$ | $\deg(v)$ | $\deg(D)$ | $\deg(N)$ | $a$ | $b$ |
|---|:---:|---|:---:|:---:|:---:|:---:|:---:|:---:|
| range resp | 0 | $(M, \alpha + V)$ where $M$ is trace col | **1** | 1 | 1 | **1** | **1** | **1** |

Here $\deg(N) = \deg(m) + 0 = 1$ (single interaction, $P_i$ is empty product). And $\deg(D) = 1$. So $a = 0 + \deg(D) = 1$ and $b = 0 + \deg(N) = 1$.

Since $b = a = 1$, the common simplification still holds: $\deg(V_g) = b = 1 = a = \deg(U_g)$. The packing cost is $a = 1$.

$$a_{G_\text{range\_resp}} = 1$$

### Set $G_\text{hk\_main}$: Hash kernel (main-trace side)

A single batch on LOGPRECOMPILE:

| Batch | $\deg(s)$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| LOGPRE | 5 | $(-1, v_\text{cap\_prev}),\; (+1, v_\text{cap\_next})$ | 1, 1 | 2 | **7** |

$$a_{G_\text{hk\_main}} = 7$$

### Summary of main-trace sets

| Set | $a_g = \deg(U_g)$ | $b_g = \deg(V_g)$ | $b_g \le a_g$? |
|-----|:------------------:|:------------------:|:--------------:|
| $G_\text{bstack}$ | 6 | 5 | ✓ |
| $G_\text{bqueue}$ | 8 | 8 | = |
| $G_\text{creq}$ | 8 | 7 | ✓ |
| $G_\text{opgrp}$ | 8 | 7 | ✓ |
| $G_\text{rstack}$ | 7 | 6 | ✓ |
| $G_\text{range\_resp}$ | 1 | 1 | = |
| $G_\text{hk\_main}$ | 7 | 7 | = |

The common simplification (§6) applies: $b_g \le a_g$ for all sets. Therefore:

$$\deg(\text{column}) = 1 + \sum_{g \in \text{column}} a_g$$

## 8.3 Chiplet trace interactions

### Set $G_\text{chip\_resp}$: All chiplet responses

Selectors are chiplet sub-flags (ME by chiplet selector hierarchy).

| Batch (chiplet row type) | $\deg(s)$ | Interactions | $\deg(v)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| Hasher f\_bp (linear hash init) | 5 | $(+1, v_\text{state})$ full 15-element msg | 1 | 1 | **6** |
| Hasher f\_mp (Merkle verify) | 5 | $(+1, v_\text{leaf})$ conditional select | **2** | 2 | **7** |
| Hasher f\_mv (MR update old, row 0) | 5 | $(+1, v_\text{leaf})$ conditional select | **2** | 2 | **7** |
| Hasher f\_mu (MR update new, row 0) | 5 | $(+1, v_\text{leaf})$ conditional select | **2** | 2 | **7** |
| Hasher f\_hout (return hash) | 5 | $(+1, v_\text{digest})$ | 1 | 1 | **6** |
| Hasher f\_sout (return state) | 5 | $(+1, v_\text{state})$ | 1 | 1 | **6** |
| Hasher f\_abp (absorption) | 5 | $(+1, v_\text{rate})$ | 1 | 1 | **6** |
| Bitwise (last of 8-cycle) | 4 | $(+1, v_\text{bw})$ with computed label | **2** | 2 | **6** |
| Memory (every row) | 3 | $(+1, v_\text{mem})$ with label + element mux | **3** | 3 | **6** |
| ACE (start row) | 5 | $(+1, v_\text{ace})$ | 1 | 1 | **6** |
| Kernel ROM (every row) | 5 | $(+1, v_\text{kr})$ with computed label | **2** | 2 | **7** |

The three degree-2 denominators come from conditional computations inside the message:
- Hasher leaf: `bit = node_index − 2·node_index_next` (deg 1) selects between two rate halves → the encoded message has $\deg(v) = 2$
- Bitwise label: `(1−sel)·AND_LABEL + sel·XOR_LABEL` → $\deg = 2$
- Kernel ROM label: `s_first·INIT + (1−s_first)·CALL` → $\deg = 2$

The memory response has $\deg(v) = 3$ from element selection: `v_0(1−idx_0)(1−idx_1) + v_1·idx_0(1−idx_1) + ...`.

$$a_{G_\text{chip\_resp}} = 7 \quad \text{(driven by hasher f\_mp/f\_mv/f\_mu and kernel ROM)}$$

**Message-sharing observation**: the hasher f\_mv and f\_mu batches use the exact same conditional-select message encoding as the hash-kernel sibling table entries (in set $G_\text{hk\_chip}$ below). If these were in the same column, the sibling interaction and the chiplet response would share the denominator $v_\text{leaf}$, and the batch could combine them as $(+1 - 1, v_\text{leaf})$ or similar. However, since the sibling entry has $m = +1$ (insert) on MV rows and $m = -1$ (remove) on MU rows while the response always has $m = +1$, they cannot simplify to zero. The message IS the same polynomial but the multiplicities differ. In any case, this merging is only possible if we keep them in the same column — otherwise, each column sees its own interaction.

### Set $G_\text{hk\_chip}$: Hash kernel (chiplet side)

Selectors are hasher sub-flags and ACE sub-flags (ME, since hasher and ACE are different chiplets, and within hasher the cycle/selector combinations are ME).

| Batch | $\deg(s)$ | Interactions | $\deg(v)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| Hasher MV (sibling, old path, row 0) | 5 | $(+1, v_\text{sib})$ conditional select | **2** | 2 | **7** |
| Hasher MVA (sibling, old path, row 31) | 5 | $(+1, v_\text{sib'})$ | **2** | 2 | **7** |
| Hasher MU (sibling, new path, row 0) | 5 | $(-1, v_\text{sib})$ | **2** | 2 | **7** |
| Hasher MUA (sibling, new path, row 31) | 5 | $(-1, v_\text{sib'})$ | **2** | 2 | **7** |
| ACE word read | 5 | $(-1, v_\text{ace\_word})$ | 1 | 1 | **6** |
| ACE element read | 5 | $(-1, v_\text{ace\_elem})$ | 1 | 1 | **6** |

$$a_{G_\text{hk\_chip}} = 7 \quad \text{(driven by sibling entries)}$$

### Set $G_\text{range\_chip}$: Range checker memory lookups

A single batch on memory chiplet rows:

| Batch | $\deg(s)$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| Memory range | 3 | $(-1, \alpha{+}D_0),\; (-1, \alpha{+}D_1)$ | 1, 1 | 2 | **5** |

$$a_{G_\text{range\_chip}} = 5$$

### Set $G_\text{wiring}$: ACE wiring

Selectors are ACE block-type flags (ME: READ vs EVAL).

| Batch | $\deg(s)$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $a$ |
|---|:---:|---|:---:|:---:|:---:|
| READ | 5 | $(m_0, v_\text{wire0}),\; (m_1, v_\text{wire1})$ where $m_0, m_1$ are trace cols | 1, 1 | 2 | **7** |
| EVAL | 5 | $(m_0, v_\text{wire0}),\; (-1, v_\text{wire1}),\; (-1, v_\text{wire2})$ | 1, 1, 1 | 3 | **8** |

Note: on READ rows, the multiplicities $m_0, m_1$ are trace columns ($\deg(m) = 1$). We need to check whether $\deg(N) > \deg(D)$ in this batch:
- $\deg(D) = 2$
- $\deg(N) = \max(\deg(m_0) + \deg(v_1),\; \deg(m_1) + \deg(v_0)) = \max(1+1, 1+1) = 2$
- So $\deg(N) = \deg(D)$, and $b = \deg(s) + \deg(N) = 5 + 2 = 7 = a$. The simplification holds.

For EVAL: $m_0$ is a trace column too, so $\deg(N) = \max(1+2, 0+2, 0+2) = 3 = \deg(D)$. Again $b = a$.

$$a_{G_\text{wiring}} = 8 \quad \text{(driven by EVAL with 3 wires)}$$

### Summary of chiplet-trace sets

| Set | $a_g$ | $b_g$ | $b_g \le a_g$? |
|-----|:------:|:------:|:--------------:|
| $G_\text{chip\_resp}$ | 7 | 6 | ✓ |
| $G_\text{hk\_chip}$ | 7 | 7 | = |
| $G_\text{range\_chip}$ | 5 | 4 | ✓ |
| $G_\text{wiring}$ | 8 | 8 | = |

The common simplification holds for all chiplet sets.

## 8.4 Overlap analysis: which sets fire on the same row?

Two sets **overlap** if there exists any row where both have an active batch. Overlapping sets assigned to the same column have their $a_g$ values **summed**. Non-overlapping (ME) sets in the same column have their $a_g$ values combined by **max**.

### Main trace overlaps

The main trace has one opcode per row. Sets overlap when their batches activate on the same opcodes.

| Pair | Overlap? | Witness row (if overlap) |
|------|:--------:|-------------------------|
| $G_\text{bstack}$ + $G_\text{bqueue}$ | **Yes** | JOIN fires both |
| $G_\text{bstack}$ + $G_\text{creq}$ | **Yes** | JOIN fires both |
| $G_\text{bstack}$ + $G_\text{opgrp}$ | **Yes** | SPAN/RESPAN fire both |
| $G_\text{bqueue}$ + $G_\text{creq}$ | **Yes** | JOIN fires both |
| $G_\text{creq}$ + $G_\text{hk\_main}$ | **Yes** | LOGPRECOMPILE fires both |
| $G_\text{creq}$ + $G_\text{opgrp}$ | **Yes** | SPAN fires both |
| $G_\text{hk\_main}$ + $G_\text{rstack}$ | **No (ME)** | Different opcodes (LOGPRE vs u32 arith) |
| $G_\text{range\_resp}$ + anything | **Yes** | Active every row |

The remaining pairs not listed are either obviously overlapping (any pair containing $G_\text{creq}$, since $G_\text{creq}$ fires on almost every opcode) or ME (because one set fires only on a narrow opcode range that doesn't intersect the other).

$G_\text{rstack}$ fires only on u32 arithmetic opcodes (64–79). It does NOT overlap with $G_\text{bstack}$, $G_\text{bqueue}$, or $G_\text{opgrp}$ (those fire on control-flow opcodes, which are in the 80–127 range). It does not overlap with $G_\text{creq}$ either — u32 arithmetic opcodes do not send chiplets bus requests (only U32AND/U32XOR do, and those are in the 0–63 range, not 64–79).

### Chiplet trace overlaps

| Pair | Overlap? | Witness row |
|------|:--------:|-------------|
| $G_\text{chip\_resp}$ + $G_\text{hk\_chip}$ | **Yes** | Hasher f\_mv row has both a chiplet response and a sibling entry |
| $G_\text{chip\_resp}$ + $G_\text{range\_chip}$ | **Yes** | Memory rows have both response and range lookups |
| $G_\text{chip\_resp}$ + $G_\text{wiring}$ | **Yes** | ACE start row has both response and wiring |
| $G_\text{hk\_chip}$ + $G_\text{wiring}$ | **Yes** | ACE read/eval rows have both hash-kernel and wiring entries |
| $G_\text{hk\_chip}$ + $G_\text{range\_chip}$ | **No (ME)** | Hasher/ACE rows vs memory rows — different chiplets |
| $G_\text{range\_chip}$ + $G_\text{wiring}$ | **No (ME)** | Memory rows vs ACE rows — different chiplets |

## 8.5 Column assignment

Given the degree budget $D_\text{max} = 9$, each column must satisfy:

$$1 + \sum_{g \in \text{column}} a_g \le 9 \quad \Leftrightarrow \quad \sum a_g \le 8$$

For ME sets in the same column, they form a single combined set with $a = \max(a_g)$ rather than $\sum$.

### Main trace columns

The overlapping sets $G_\text{bstack}$, $G_\text{bqueue}$, $G_\text{creq}$ all fire on control-flow opcodes. If we put any two in the same column, their costs add. Since $a_\text{p1} + a_\text{p2} = 6 + 8 = 14 > 8$, they cannot share. Similarly $a_\text{p2} + a_\text{chip} = 16$, $a_\text{p1} + a_\text{chip} = 14$. **Each of $G_\text{bstack}$, $G_\text{bqueue}$, $G_\text{creq}$ needs its own column** (or to share only with non-overlapping cheap sets).

$G_\text{opgrp}$ overlaps with $G_\text{bstack}$ and $G_\text{creq}$ (on SPAN/RESPAN), so it also needs its own column.

$G_\text{hk\_main}$ and $G_\text{rstack}$ are ME (different opcodes). They can merge:
$$a_{\{G_\text{hk\_main}, G_\text{rstack}\}} = \max(7, 7) = 7$$

$G_\text{range\_resp}$ (cost 1) overlaps with everything. Best placed in the column with the most slack. $G_\text{bstack}$ has $a = 6$, so $6 + 1 = 7 \le 8$. ✓

| Column | Sets | Computation | $\sum a$ | Degree |
|:------:|------|-------------|:--------:|:------:|
| **M1** | $G_\text{bstack}$ $+$ $G_\text{range\_resp}$ | sum (overlap) | $6 + 1 = 7$ | **8** |
| **M2** | $G_\text{bqueue}$ | single | $8$ | **9** |
| **M3** | $G_\text{creq}$ | single | $8$ | **9** |
| **M4** | $\{G_\text{hk\_main}, G_\text{rstack}\}$ | max (ME) | $\max(7,7) = 7$ | **8** |
| **M5** | $G_\text{opgrp}$ | single | $8$ | **9** |

### Chiplet trace columns

$G_\text{chip\_resp}$ overlaps with $G_\text{hk\_chip}$ (hasher MV/MU rows), with $G_\text{range\_chip}$ (memory rows), and with $G_\text{wiring}$ (ACE rows). Since $a_\text{chip\_resp} + a_\text{hk\_chip} = 7 + 7 = 14 > 8$, they cannot share.

$G_\text{hk\_chip}$ and $G_\text{range\_chip}$ are ME (different chiplets: hasher/ACE vs memory). They merge:
$$a_{\{G_\text{hk\_chip}, G_\text{range\_chip}\}} = \max(7, 5) = 7$$

$G_\text{wiring}$ overlaps with $G_\text{hk\_chip}$ (ACE rows), so it cannot share with the merged set.

| Column | Sets | Computation | $\sum a$ | Degree |
|:------:|------|-------------|:--------:|:------:|
| **C1** | $G_\text{chip\_resp}$ | single | $7$ | **8** |
| **C2** | $\{G_\text{hk\_chip}, G_\text{range\_chip}\}$ | max (ME) | $\max(7,5) = 7$ | **8** |
| **C3** | $G_\text{wiring}$ | single | $8$ | **9** |

### Final layout

| Column | Region | Sets packed | $\sum a_g$ | Degree |
|:------:|--------|-------------|:----------:|:------:|
| M1 | Main | $G_\text{bstack} + G_\text{range\_resp}$ | 7 | **8** |
| M2 | Main | $G_\text{bqueue}$ | 8 | **9** |
| M3 | Main | $G_\text{creq}$ | 8 | **9** |
| M4 | Main | $\{G_\text{hk\_main}, G_\text{rstack}\}$ | 7 | **8** |
| M5 | Main | $G_\text{opgrp}$ | 8 | **9** |
| C1 | Chiplet | $G_\text{chip\_resp}$ | 7 | **8** |
| C2 | Chiplet | $\{G_\text{hk\_chip}, G_\text{range\_chip}\}$ | 7 | **8** |
| C3 | Chiplet | $G_\text{wiring}$ | 8 | **9** |

**8 columns total** (5 main + 3 chiplet). 4 saturated at degree 9, 4 with 1 degree of slack.

This packing is **tight**: no two currently-separate columns can merge without exceeding degree 9. The bottlenecks are:
- M2: the END batch in $G_\text{bqueue}$ with $\deg(v) = 4$ (is\_first\_child)
- M3: degree-7 opcode selectors (MLOAD etc.)
- M5: the g8 batch with 7 simultaneous interactions
- C3: ACE EVAL with 3 simultaneous wire interactions

Each of these is a structural property of the current instruction set. Reducing any would require either adding helper columns (to pre-compute high-degree sub-expressions) or redesigning the affected operations.

---

# 9. Simplified inventory via selector merging

When ME batches in a set share the same denominator polynomial $v$, their fractions combine:

$$\frac{s_1}{v} + \frac{s_2}{v} = \frac{s_1 + s_2}{v}$$

Since $s_1, s_2$ are ME booleans, $s_1 + s_2$ is still boolean with $\deg(s_1 + s_2) = \max(\deg(s_1), \deg(s_2))$. This collapses many batches into one and reveals the true combinatorial structure.

We also define combined selectors for readability. Each combined selector is boolean (ME components sum to at most 1).

## 9.1 Combined selectors

**Main trace selectors** (from opcode flags — ME by op-bit binary constraints):

| Symbol | Definition | $\deg$ | Meaning |
|--------|-----------|:------:|---------|
| $f_\text{blk}$ | $s_\text{join} + s_\text{split} + s_\text{span} + s_\text{dyn}$ | 5 | Block start with simple push |
| $f_\text{ctx}$ | $s_\text{call} + s_\text{syscall}$ | 4 | Context-saving call (full push) |
| $f_\text{child}$ | $s_\text{dyn} + s_\text{dyncall} + s_\text{call} + s_\text{syscall}$ | 5 | Single child hash enqueue |
| $f_\text{body}$ | $s_\text{loop} \cdot s_0 + s_\text{repeat}$ | 6 | Loop body enqueue (conditional on $s_0$ for LOOP) |
| $f_\text{1mem}$ | $s_\text{mload} + s_\text{mstore}$ | 7 | Single memory element access |
| $f_\text{1word}$ | $s_\text{mloadw} + s_\text{mstorew}$ | 7 | Single memory word access |
| $f_\text{2mem}$ | $s_\text{mstream} + s_\text{pipe}$ | 5 | Double memory word access |
| $f_\text{2hash}$ | $s_\text{hperm} + s_\text{logpre}$ | 5 | Double hasher invocation (in + out) |
| $f_\text{bw}$ | $s_\text{u32and} + s_\text{u32xor}$ | 7 | Bitwise operation |

**Chiplet selectors** (from chiplet hierarchy — ME by selector binary constraints):

| Symbol | Definition | $\deg$ | Meaning |
|--------|-----------|:------:|---------|
| $f_\text{h:init}$ | hasher flag: $\text{cyc}_0 \cdot s_0 \cdot \bar s_1 \cdot \bar s_2$ | 5 | Hasher linear-hash start |
| $f_\text{h:leaf}$ | hasher flag: $\text{cyc}_0 \cdot s_0 \cdot (s_1 + s_2)$ variants | 5 | Hasher Merkle leaf (f\_mp, f\_mv, f\_mu — 3 ME sub-batches) |
| $f_\text{h:out}$ | hasher flag: $\text{cyc}_{31} \cdot \bar s_0$ variants | 5 | Hasher return (f\_hout, f\_sout — 2 ME sub-batches) |
| $f_\text{h:abs}$ | hasher flag: $\text{cyc}_{31} \cdot s_0 \cdot \bar s_1 \cdot \bar s_2$ | 5 | Hasher absorption |
| $f_\text{h:sib}$ | hasher MV/MU/MVA/MUA variants | 5 | Merkle sibling insert/remove |
| $f_\text{mem}$ | $s_0 \cdot s_1 \cdot \bar s_2$ | 3 | Memory chiplet row |
| $f_\text{bw:last}$ | $s_0 \cdot \bar s_1 \cdot \bar k_\text{tr}$ | 4 | Bitwise last-of-cycle row |
| $f_\text{ace}$ | $s_0 \cdot s_1 \cdot s_2 \cdot \bar s_3$ | 4 | ACE chiplet row |
| $f_\text{kr}$ | $s_0 \cdot s_1 \cdot s_2 \cdot s_3 \cdot \bar s_4$ | 5 | Kernel ROM row |

## 9.2 Merged interaction tables

Below, each row is one **merged fraction** $m/v$ with its effective selector. Within a set, all fractions are ME (so the set cost is the max). Fractions are ordered by decreasing $\deg(s) + \deg(v)$ so the costliest entries are at the top.

Convention: $\deg(m) = 0$ (constant $\pm 1$) unless marked. When $\deg(m) = 0$ and $n=1$: $\deg(N) = 0$, $\deg(D) = \deg(v)$, and the batch cost is $\deg(s) + \deg(v)$.

### $G_\text{bstack}$: Block stack (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message $v$ | $\deg(v)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $f_\text{blk}$ = join+split+span+dyn | 5 | 1 | $[\text{addr'}, \text{addr}, 0]$ — simple push | 1 | **6** |
| $s_\text{loop}$ | 5 | 1 | $[\text{addr'}, \text{addr}, s_0]$ | 1 | **6** |
| $s_\text{dyncall}$ | 5 | 1 | $[\text{addr'}, \text{addr}, 0, \text{ctx}, h_4, h_5, \text{fh}]$ | 1 | **6** |
| $s_\text{respan}$ | 4 | 2 | push: $[\text{addr'}, h_1', 0]$; pop: $[\text{addr}, h_1', 0]$ | 1, 1 | **6** |
| $f_\text{ctx}$ = call+syscall | 4 | 1 | $[\text{addr'}, \text{addr}, 0, \text{ctx}, b_0, b_1, \text{fh}]$ — context push | 1 | **5** |
| $s_\text{end}$ | 4 | 1 | $[\text{addr}, \text{addr'}, \text{is\_loop\_flag}, \ldots]$ — pop (simple or full) | 1 | **5** |

$$\boxed{a_{G_\text{bstack}} = 6}$$

Note: END has two sub-cases (simple pop with $\deg(v)=1$ and full pop with $\deg(v)=1$) depending on call context. Both have cost 5. They share selector $s_\text{end}$ but different $v$, so they don't merge — they remain ME sub-batches within the END batch. The set cost is still 6 (driven by the top four rows).

### $G_\text{bqueue}$: Block hash queue (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message $v$ | $\deg(v)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $s_\text{join}$ | 5 | 2 | $v_\text{left}, v_\text{right}$ — two children | 1, 1 | **7** |
| $s_\text{split}$ | 5 | 1 | $[\text{parent}, s_0 h_i + (1{-}s_0) h_{i+4}, 0, 0]$ | **2** | **7** |
| $f_\text{body}$ = loop·s₀ + repeat | 6 | 1 | $[\text{parent}, h_{0..3}, 0, 1]$ — loop body | 1 | **7** |
| $f_\text{child}$ = dyn+dyncall+call+syscall | 5 | 1 | $[\text{parent}, h_{0..3}, 0, 0]$ — single child | 1 | **6** |
| $s_\text{end}$ | 4 | 1 | $[\text{parent'}, h_{0..3}, \text{is\_first\_child}, \text{is\_loop\_body}]$ | **4** | **8** |

$$\boxed{a_{G_\text{bqueue}} = 8}$$

Merges applied:
- DYN+DYNCALL+CALL+SYSCALL share $v_\text{child} = [\text{parent}, h_{0..3}, 0, 0]$ → combined selector $f_\text{child}$ (deg 5)
- LOOP (conditional on $s_0$) + REPEAT share $v_\text{body} = [\text{parent}, h_{0..3}, 0, 1]$ → combined selector $f_\text{body}$ (deg 6)

The END batch has $\deg(v) = 4$ from the `is_first_child` computation (next-row degree-4 flags). This is the cost driver for the entire set.

### $G_\text{creq}$: Chiplets requests (main trace)

Each opcode sends a distinct message to the chiplets (different labels, different source columns). No merging applies — each batch has a unique denominator polynomial.

| Selector $s$ | $\deg(s)$ | $n$ | Message(s) | $\sum\deg(v_i)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $f_\text{1mem}$ = mload+mstore | 7 | 1 | mem element msg | 1 | **8** |
| $f_\text{1word}$ = mloadw+mstorew | 7 | 1 | mem word msg | 1 | **8** |
| $f_\text{bw}$ = u32and+u32xor | 7 | 1 | bitwise msg | 1 | **8** |
| $s_\text{dyncall}$ | 5 | 3 | hasher\_zeros + callee\_read + fmp\_write | 3 | **8** |
| $s_\text{mrupdate}$ | 4 | 4 | 4 hasher word msgs | 4 | **8** |
| $s_\text{crypto}$ | 4 | 4 | 4 mem word msgs | 4 | **8** |
| $s_\text{dyn}$ | 5 | 2 | hasher\_zeros + callee\_read | 2 | **7** |
| $s_\text{hperm}$ | 5 | 2 | hasher\_in + hasher\_out | 2 | **7** |
| $s_\text{mpverify}$ | 5 | 2 | word\_in + word\_out | 2 | **7** |
| $f_\text{2mem}$ = mstream+pipe | 5 | 2 | 2 mem word msgs | 2 | **7** |
| $s_\text{hbase}$ | 5 | 2 | 2 elem read msgs | 2 | **7** |
| $s_\text{logpre}$ | 5 | 2 | hasher\_in + hasher\_out | 2 | **7** |
| $s_\text{join}$ | 5 | 1 | hasher state msg | 1 | **6** |
| $s_\text{split}$ | 5 | 1 | hasher state msg | 1 | **6** |
| $s_\text{loop}$ | 5 | 1 | hasher state msg | 1 | **6** |
| $s_\text{span}$ | 5 | 1 | hasher state msg | 1 | **6** |
| $s_\text{eval}$ | 5 | 1 | ACE init msg | 1 | **6** |
| $s_\text{hext}$ | 5 | 1 | mem word msg | 1 | **6** |
| $s_\text{call}$ | 4 | 2 | hasher + fmp\_write | 2 | **6** |
| $s_\text{syscall}$ | 4 | 2 | hasher + kernel\_rom | 2 | **6** |
| $s_\text{respan}$ | 4 | 1 | hasher rate msg | 1 | **5** |
| $s_\text{end}$ | 4 | 1 | hasher digest msg | 1 | **5** |

$$\boxed{a_{G_\text{creq}} = 8}$$

Note: even though $f_\text{1mem}$ combines MLOAD+MSTORE (they share the same polynomial form `compute_memory_element_request`... actually no, MLOAD passes `is_read=true` and MSTORE passes `is_read=false`, giving different labels in the encoding — they are DIFFERENT polynomials). Let me correct: MLOAD and MSTORE have different label constants in their messages, so they don't share $v$. Same for MLOADW/MSTOREW (different labels). Same for U32AND/U32XOR (different labels).

So in $G_\text{creq}$, the only merges that apply are between opcodes that call the exact same `compute_*` function with the same parameters. Checking the code: JOIN/SPLIT/LOOP each call `compute_control_block_request` with different `ControlBlockOp` variants (which embed different opcode constants). These are different polynomials. **No merging applies in $G_\text{creq}$.**

The combined selectors $f_\text{1mem}$, $f_\text{1word}$, $f_\text{bw}$ cannot merge the messages — they only help notational grouping since the batches have the same cost. I'll keep them for readability but mark that the messages are actually distinct.

Corrected table — replacing combined selectors with individual ones where messages differ:

| Selector $s$ | $\deg(s)$ | $n$ | Description | $\sum\deg(v_i)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $s_\text{mload}$, $s_\text{mstore}$, $s_\text{mloadw}$, $s_\text{mstorew}$, $s_\text{u32and}$, $s_\text{u32xor}$ (each) | 7 | 1 | single chiplet msg (unique per opcode) | 1 | **8** |
| $s_\text{dyncall}$ | 5 | 3 | hasher\_zeros + callee\_read + fmp\_write | 3 | **8** |
| $s_\text{mrupdate}$ | 4 | 4 | 4 hasher word msgs | 4 | **8** |
| $s_\text{crypto}$ | 4 | 4 | 4 mem word msgs | 4 | **8** |
| (8 opcodes, each deg 5, $n$=2) | 5 | 2 | pairs of chiplet msgs | 2 | **7** |
| (6 opcodes, each deg 5, $n$=1) | 5 | 1 | single chiplet msg | 1 | **6** |
| $s_\text{call}$, $s_\text{syscall}$ (each) | 4 | 2 | hasher + extra msg | 2 | **6** |
| $s_\text{respan}$, $s_\text{end}$ (each) | 4 | 1 | single hasher msg | 1 | **5** |

$$\boxed{a_{G_\text{creq}} = 8}$$

The cost is 8, driven by six different mechanisms that all land at exactly 8.

### $G_\text{opgrp}$: Op group table (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message(s) | $\deg(v_i)$ | $\deg(D)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|
| $c_0$ (g8 batch) | 1 | 7 | 7 group msgs, each $\deg(v) = 1$ | 1×7 | 7 | **8** |
| $f_\text{dg} = \text{sp} \cdot (\text{gc} - \text{gc}')$ | 2 | 1 | group removal, $\deg(v) = 6$ | 6 | 6 | **8** |
| $(1{-}c_0) c_1 (1{-}c_2)$ (g4) | 3 | 3 | 3 group msgs | 1×3 | 3 | **6** |
| $(1{-}c_0)(1{-}c_1) c_2$ (g2) | 3 | 1 | 1 group msg | 1 | 1 | **4** |

$$\boxed{a_{G_\text{opgrp}} = 8}$$

Two different mechanisms both reach cost 8: the g8 batch (many simultaneous interactions) and the removal batch (high-degree denominator).

### $G_\text{rs}$: Range stack lookups (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message(s) | $\deg(v_i)$ | $\deg(D)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|
| $f_\text{u32rc} = b_6 \bar b_5 \bar b_4$ | 3 | 4 | $\alpha + \text{helper}_i$ for $i \in \{0..3\}$ | 1×4 | 4 | **7** |

$$\boxed{a_{G_\text{rs}} = 7}$$

### $G_\text{rtable}$: Range table response (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | $(m, v)$ | $\deg(m)$ | $\deg(v)$ | $\deg(D)$ | $\deg(N)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|:---:|:---:|
| $1$ (always) | 0 | 1 | $(M, \alpha{+}V)$ | **1** | 1 | 1 | **1** | **1** |

$$\boxed{a_{G_\text{rtable}} = 1}$$

The only interaction with non-constant multiplicity. $\deg(N) = \deg(m) = 1 = \deg(D)$, so $b = a$. The common simplification holds.

### $G_\text{logcap}$: Log-precompile capacity (main trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message(s) | $\deg(v_i)$ | $\deg(D)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|
| $s_\text{logpre}$ | 5 | 2 | $v_\text{cap\_prev}$ (remove), $v_\text{cap\_next}$ (insert) | 1, 1 | 2 | **7** |

$$\boxed{a_{G_\text{logcap}} = 7}$$

### $G_\text{cresp}$: Chiplet responses (chiplet trace)

All chiplet row types are ME. Where noted, sub-batches within a hasher flag share a message and can merge.

| Selector $s$ | $\deg(s)$ | $n$ | Message $v$ | $\deg(v)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $f_\text{h:leaf}$ (f\_mp, f\_mv, f\_mu — 3 ME sub-batches) | 5 | 1 | conditional leaf word | **2** | **7** |
| $f_\text{kr}$ | 5 | 1 | kernel ROM msg (computed label) | **2** | **7** |
| $f_\text{h:init}$ | 5 | 1 | full state msg | 1 | **6** |
| $f_\text{h:out}$ (f\_hout + f\_sout — 2 ME sub-batches) | 5 | 1 | digest or full state | 1 | **6** |
| $f_\text{h:abs}$ | 5 | 1 | rate msg | 1 | **6** |
| $f_\text{ace:start}$ | 5 | 1 | ACE init msg | 1 | **6** |
| $f_\text{bw:last}$ | 4 | 1 | bitwise msg (computed label) | **2** | **6** |
| $f_\text{mem}$ | 3 | 1 | memory msg (label+elem select) | **3** | **6** |

$$\boxed{a_{G_\text{cresp}} = 7}$$

Note on $f_\text{h:leaf}$: the three Merkle-leaf hasher flags (f\_mp, f\_mv, f\_mu) are ME and all use the same conditional-select encoding `encode_b0·(1−b) + encode_b1·b`. As individual batches they'd each have cost $5 + 2 = 7$. As merged sub-batches with combined selector, the cost is the same (max, not sum). The merge doesn't save degree — it just simplifies notation.

### $G_\text{sibace}$: Sibling table + ACE memory (chiplet trace)

Hasher sibling flags and ACE flags are ME (different chiplets or different cycle positions).

| Selector $s$ | $\deg(s)$ | $n$ | Message $v$ | $\deg(v)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|
| $f_\text{h:sib}$ (MV, MU, MVA, MUA — 4 ME sub-batches) | 5 | 1 | sibling word (conditional select) | **2** | **7** |
| $f_\text{ace:read}$ | 5 | 1 | ACE word read msg | 1 | **6** |
| $f_\text{ace:eval}$ | 5 | 1 | ACE element read msg | 1 | **6** |

$$\boxed{a_{G_\text{sibace}} = 7}$$

### $G_\text{rmem}$: Range memory lookups (chiplet trace)

| Selector $s$ | $\deg(s)$ | $n$ | Message(s) | $\deg(v_i)$ | $\deg(D)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|
| $f_\text{mem}$ | 3 | 2 | $\alpha{+}D_0$, $\alpha{+}D_1$ | 1, 1 | 2 | **5** |

$$\boxed{a_{G_\text{rmem}} = 5}$$

### $G_\text{wiring}$: ACE wiring (chiplet trace)

| Selector $s$ | $\deg(s)$ | $n$ | Interactions | $\deg(v_i)$ | $\deg(D)$ | $\deg(N)$ | Cost |
|---|:---:|:---:|---|:---:|:---:|:---:|:---:|
| $f_\text{ace:eval}$ | 5 | 3 | $(m_0, w_0), (-1, w_1), (-1, w_2)$; $\deg(m_0)=1$ | 1, 1, 1 | 3 | **3** | **8** |
| $f_\text{ace:read}$ | 5 | 2 | $(m_0, w_0), (m_1, w_1)$; $\deg(m_i)=1$ | 1, 1 | 2 | **2** | **7** |

$$\boxed{a_{G_\text{wiring}} = 8}$$

Note: $\deg(N) = \deg(D)$ in both batches (checked in the wiring audit: $\deg(m_0) + \sum_{j \ne 0} \deg(w_j) = 1 + 2 = 3 = \deg(D)$). So $b = a$ and the common simplification holds.

## 9.3 Summary of all sets

| Set | Symbol | Region | $a_g$ | Bottleneck |
|-----|--------|--------|:-----:|-----------|
| Block stack | $G_\text{bstack}$ | Main | **6** | $f_\text{blk}$(5) + $\deg(v)$=1; RESPAN(4) + $\deg(D)$=2 |
| Block hash queue | $G_\text{bqueue}$ | Main | **8** | END: $s$(4) + $\deg(v)$=4 from `is_first_child` |
| Chiplets requests | $G_\text{creq}$ | Main | **8** | Six batches at 8 (high flags or multi-msg) |
| Op group | $G_\text{opgrp}$ | Main | **8** | g8 batch: $s$(1) + $\deg(D)$=7; removal: $s$(2) + $\deg(v)$=6 |
| Range stack | $G_\text{rs}$ | Main | **7** | $s$(3) + $\deg(D)$=4 |
| Range table | $G_\text{rtable}$ | Main | **1** | Always-on, $\deg(m)=1$ |
| Log capacity | $G_\text{logcap}$ | Main | **7** | $s$(5) + $\deg(D)$=2 |
| Chiplet responses | $G_\text{cresp}$ | Chiplet | **7** | Hasher leaf(5) + $\deg(v)$=2; kernel ROM(5) + $\deg(v)$=2 |
| Sibling + ACE mem | $G_\text{sibace}$ | Chiplet | **7** | Sibling: $s$(5) + $\deg(v)$=2 |
| Range memory | $G_\text{rmem}$ | Chiplet | **5** | $s$(3) + $\deg(D)$=2 |
| Wiring | $G_\text{wiring}$ | Chiplet | **8** | EVAL: $s$(5) + $\deg(D)$=3 |

## 9.4 Overlap and column assignment

Two sets that fire on the same row contribute their $a_g$ values **additively** in a column. ME sets contribute via **max**. The budget per column is $\sum a_g \le 8$ (since final degree $= 1 + \sum a_g \le 9$).

**Main trace overlaps** (sets that fire on the same row):

$G_\text{bstack}$, $G_\text{bqueue}$, $G_\text{creq}$ all fire on control-flow opcodes (JOIN, CALL, etc.). Any pair sums to $\ge 14$. **Must be in separate columns.**

$G_\text{opgrp}$ fires on SPAN/RESPAN (overlaps with $G_\text{bstack}$, $G_\text{creq}$). Sum $\ge 14$. **Separate column.**

$G_\text{rtable}$ (cost 1) fires every row. It can fit wherever there is room.

$G_\text{logcap}$ and $G_\text{rs}$ fire on different opcodes (LOGPRECOMPILE vs u32 arith). **ME** → one group, cost $\max(7, 7) = 7$.

**Main packing:**

| Column | Sets | Rule | $\sum a_g$ | $\deg$ |
|:------:|------|------|:----------:|:------:|
| M1 | $G_\text{bstack} + G_\text{rtable}$ | Sum | $6 + 1 = 7$ | **8** |
| M2 | $G_\text{bqueue}$ | — | $8$ | **9** |
| M3 | $G_\text{creq}$ | — | $8$ | **9** |
| M4 | $\{G_\text{logcap}, G_\text{rs}\}$ | Max (ME) | $\max(7, 7) = 7$ | **8** |
| M5 | $G_\text{opgrp}$ | — | $8$ | **9** |

**Chiplet trace overlaps:**

$G_\text{cresp}$ + $G_\text{sibace}$: overlap on hasher MV/MU rows (response + sibling). Sum $= 14$. **Separate.**

$G_\text{cresp}$ + $G_\text{rmem}$: overlap on memory rows. Sum $= 12$. **Separate.**

$G_\text{sibace}$ + $G_\text{rmem}$: hasher/ACE vs memory → different chiplets. **ME** → one group, cost $\max(7, 5) = 7$.

$G_\text{wiring}$ + $G_\text{sibace}$: overlap on ACE rows. Sum $= 15$. **Separate.**

**Chiplet packing:**

| Column | Sets | Rule | $\sum a_g$ | $\deg$ |
|:------:|------|------|:----------:|:------:|
| C1 | $G_\text{cresp}$ | — | $7$ | **8** |
| C2 | $\{G_\text{sibace}, G_\text{rmem}\}$ | Max (ME) | $\max(7, 5) = 7$ | **8** |
| C3 | $G_\text{wiring}$ | — | $8$ | **9** |

## 9.5 Final column layout

| Column | Region | Content | $\sum a_g$ | Degree | Slack |
|:------:|--------|---------|:----------:|:------:|:-----:|
| **M1** | Main | $G_\text{bstack}$ (block stack) $+$ $G_\text{rtable}$ (range table response) | 7 | **8** | 1 |
| **M2** | Main | $G_\text{bqueue}$ (block hash queue) | 8 | **9** | 0 |
| **M3** | Main | $G_\text{creq}$ (chiplet requests) | 8 | **9** | 0 |
| **M4** | Main | $\{G_\text{logcap}, G_\text{rs}\}$ (log capacity ∥ range stack) | 7 | **8** | 1 |
| **M5** | Main | $G_\text{opgrp}$ (op groups) | 8 | **9** | 0 |
| **C1** | Chiplet | $G_\text{cresp}$ (chiplet responses) | 7 | **8** | 1 |
| **C2** | Chiplet | $\{G_\text{sibace}, G_\text{rmem}\}$ (sibling+ACE ∥ range memory) | 7 | **8** | 1 |
| **C3** | Chiplet | $G_\text{wiring}$ (wiring) | 8 | **9** | 0 |

**8 columns** (5 main + 3 chiplet). Degree budget: 4 columns at 9 (saturated), 4 at 8 (1 slack).
