# Constraint Changes

Cumulative record of constraint polynomial changes across the simplification
refactor. Fingerprints are polynomial evaluations at a deterministic random
point (Schwartz-Zippel over ~64-bit field). Same fingerprint = same polynomial.

If regenerating after a rebase, re-run the constraint recorder rather than
resolving merge conflicts in this file.

---

## 1. refactor: inline tagged_assert_zero variants, remove tagging indirection

**No constraint changes.** (441 base + 24 ext)

---
## 2. refactor: inline trivial assert wrappers in stack and decoder modules

**No constraint changes.** (441 base + 24 ext)

---
## 3. refactor: remove empty section headers and apply lint fixes

**No constraint changes.** (441 base + 24 ext)

---
## 4. refactor: remove constraint tagging infrastructure

**No constraint changes.** (441 base + 24 ext)

---
## 5. refactor: introduce MidenAirBuilder trait alias

**No constraint changes.** (441 base + 24 ext)

---
## 6. refactor: remove unused decoder constants and inline last assert wrapper

**No constraint changes.** (441 base + 24 ext)

---
## 7. refactor: remove dead code and unnecessary allow(dead_code) annotations

**No constraint changes.** (441 base + 24 ext)

---
## 8. refactor: remove unnecessary clone() calls on Copy types

**No constraint changes.** (441 base + 24 ext)

---
## 9. refactor: use semantic assertion methods in constraint code

**No constraint changes.** (441 base + 24 ext)

---
## 10. refactor: inline field constants and centralize in constants.rs

**No constraint changes.** (441 base + 24 ext)

---
## 11. refactor: introduce BoolNot trait for boolean negation in constraints

**No constraint changes.** (441 base + 24 ext)

---
## 12. refactor: defer Var-to-Expr conversions and simplify array construction

**No constraint changes.** (441 base + 24 ext)

---
## 13. refactor: add ChipletFlags/ChipletSelectors structs with precomputed flags

**No constraint changes.** (441 base + 24 ext)

---
## 14. refactor: thread ChipletSelectors through all constraint and bus functions

**18 updated** | 447 unchanged

Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent.

<details>
<summary>18 constraint changes</summary>

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/ace.rs:161` | `chiplets/ace.rs:136` | ace.rs:161→136. Gate recomputed: `ace_flag * flag_ace_last * sstart` → `ace_last * sstart`. `ace_last` is precomputed as `is_ace * s_n'`, replacing the inline `ace_flag * flag_ace_last` product. Equivalent. |
| 2 | `chiplets/ace.rs:163` | `chiplets/ace.rs:138` | ace.rs:163→138. Gate recomputed: `ace_flag * flag_ace_next * sstart * sstart_next` → `ace_transition * sstart * sstart_next`. `ace_transition` replaces `ace_flag * flag_ace_next`. Equivalent. |
| 3 | `chiplets/ace.rs:169` | `chiplets/ace.rs:142` | ace.rs:169→142. Gate recomputed: `ace_flag * flag_ace_next * f_next * sblock * sblock_next.not()` → `ace_transition * f_next * sblock * sblock_next.not()`. Same substitution as :163. Equivalent. |
| 4 | `chiplets/ace.rs:200` | `chiplets/ace.rs:168` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 5 | `chiplets/ace.rs:201` | `chiplets/ace.rs:169` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 6 | `chiplets/ace.rs:202` | `chiplets/ace.rs:170` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 7 | `chiplets/ace.rs:203` | `chiplets/ace.rs:171` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 8 | `chiplets/ace.rs:220` | `chiplets/ace.rs:188` | ace.rs:220→188. Gate recomputed: `is_transition * ace_flag * f_read * (selected - n_eval)` → `ace_transition * f_read * (selected - n_eval)`. `ace_transition = is_transition_flag * s012 * (1-s3')` replaces the manual `is_transition * ace_flag` product. Equivalent. |
| 9 | `chiplets/ace.rs:265` | `chiplets/ace.rs:231` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 10 | `chiplets/kernel_rom.rs:100` | `chiplets/kernel_rom.rs:92` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 11 | `chiplets/kernel_rom.rs:101` | `chiplets/kernel_rom.rs:93` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 12 | `chiplets/kernel_rom.rs:102` | `chiplets/kernel_rom.rs:94` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 13 | `chiplets/kernel_rom.rs:103` | `chiplets/kernel_rom.rs:95` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 14 | `chiplets/kernel_rom.rs:119` | `chiplets/kernel_rom.rs:105` | kernel_rom.rs:119→105. Lost `when_transition()` factor: `builder.when_transition().when(flag_next_row_first_kernel_rom).assert_one(sfirst_next)` → `builder.when(flag_next_row_first_kernel_rom).assert_one(sfirst_next)`. The `when_transition()` factor was folded into `flag_next_row_first_kernel_rom` which is now precomputed as `is_ace_last * (1-s4')`, already incorporating the transition-relevant gating. Equivalent. |
| 15 | `chiplets/memory.rs:138` | `chiplets/memory.rs:127` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 16 | `chiplets/memory.rs:139` | `chiplets/memory.rs:128` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 17 | `chiplets/memory.rs:140` | `chiplets/memory.rs:129` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |
| 18 | `chiplets/memory.rs:141` | `chiplets/memory.rs:130` | Identical assertion expressions; fingerprints changed because scoped builder gates were recomputed using precomputed `ChipletSelectors` products instead of inline `ace_flag * ...` / `is_transition * ...` expressions. 13 of 18 constraints fall into this category across ace.rs (5), kernel_rom.rs (4), memory.rs (4). Equivalent. |

</details>

---
## 15. refactor: enforce all chiplet selectors are 1 in last row

**5 added** | 465 unchanged

5 new last-row constraints enforce chiplet selectors s0–s4 equal 1 at the final trace row (`builder.when_last_row().assert_one(sel[i])` for i in 0..5). Source-extraction artifact: 3 of 5 expressions display the `let builder = &mut builder.when_last_row()` binding instead of the actual `builder.assert_one(sel[i])` call; all 5 fingerprints correspond to genuine `assert_one` assertions on distinct selector columns.

**Added:**

| # | Location | Expression |
|---|----------|------------|
| 1 | `chiplets/selectors.rs:147` | `let mut last = builder.when_last_row();` |
| 2 | `chiplets/selectors.rs:148` | `let mut last = builder.when_last_row();` |
| 3 | `chiplets/selectors.rs:149` | `let mut last = builder.when_last_row();` |
| 4 | `chiplets/selectors.rs:150` | `last.assert_one(local.chiplets[4]);` |
| 5 | `chiplets/selectors.rs:151` | `last.assert_one(local.chiplets[4]);` |

---
## 16. refactor: remove when_transition from chiplet constraints

**61 updated** | 409 unchanged

> `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant.

<details>
<summary>61 constraint changes</summary>

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/ace.rs:146` | `chiplets/ace.rs:144` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 2 | `chiplets/ace.rs:213` | `chiplets/ace.rs:211` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 3 | `chiplets/ace.rs:214` | `chiplets/ace.rs:212` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 4 | `chiplets/ace.rs:215` | `chiplets/ace.rs:213` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 5 | `chiplets/hasher/merkle.rs:71` | `chiplets/hasher/merkle.rs:70` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 6 | `chiplets/hasher/merkle.rs:83` | `chiplets/hasher/merkle.rs:80` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 7 | `chiplets/hasher/merkle.rs:123` | `chiplets/hasher/merkle.rs:120` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 8 | `chiplets/hasher/merkle.rs:123` | `chiplets/hasher/merkle.rs:120` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 9 | `chiplets/hasher/merkle.rs:123` | `chiplets/hasher/merkle.rs:120` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 10 | `chiplets/hasher/merkle.rs:123` | `chiplets/hasher/merkle.rs:120` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 11 | `chiplets/hasher/merkle.rs:134` | `chiplets/hasher/merkle.rs:131` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 12 | `chiplets/hasher/merkle.rs:134` | `chiplets/hasher/merkle.rs:131` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 13 | `chiplets/hasher/merkle.rs:134` | `chiplets/hasher/merkle.rs:131` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 14 | `chiplets/hasher/merkle.rs:134` | `chiplets/hasher/merkle.rs:131` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 15 | `chiplets/hasher/merkle.rs:141` | `chiplets/hasher/merkle.rs:138` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 16 | `chiplets/hasher/merkle.rs:141` | `chiplets/hasher/merkle.rs:138` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 17 | `chiplets/hasher/merkle.rs:141` | `chiplets/hasher/merkle.rs:138` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 18 | `chiplets/hasher/merkle.rs:141` | `chiplets/hasher/merkle.rs:138` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 19 | `chiplets/hasher/selectors.rs:67` | `chiplets/hasher/selectors.rs:66` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 20 | `chiplets/hasher/selectors.rs:67` | `chiplets/hasher/selectors.rs:66` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 21 | `chiplets/hasher/selectors.rs:75` | `chiplets/hasher/selectors.rs:74` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 22 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 23 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 24 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 25 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 26 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 27 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 28 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 29 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 30 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 31 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 32 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 33 | `chiplets/hasher/state.rs:86` | `chiplets/hasher/state.rs:83` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 34 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 35 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 36 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 37 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 38 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 39 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 40 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 41 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 42 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 43 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 44 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 45 | `chiplets/hasher/state.rs:93` | `chiplets/hasher/state.rs:88` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 46 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 47 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 48 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 49 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 50 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 51 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 52 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 53 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 54 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 55 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 56 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 57 | `chiplets/hasher/state.rs:100` | `chiplets/hasher/state.rs:93` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 58 | `chiplets/hasher/state.rs:120` | `chiplets/hasher/state.rs:113` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 59 | `chiplets/hasher/state.rs:120` | `chiplets/hasher/state.rs:113` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 60 | `chiplets/hasher/state.rs:120` | `chiplets/hasher/state.rs:113` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |
| 61 | `chiplets/hasher/state.rs:120` | `chiplets/hasher/state.rs:113` | `when_transition()` guard removed from all chiplet constraints. 61 constraints across ace.rs (4), hasher/merkle.rs (14), hasher/selectors.rs (3), hasher/state.rs (36 — init/ext/int permutation steps × 12 lanes + 4 ABP capacity). Each constraint polynomial lost its `(1 − z_last)` factor. Soundness preserved because `39e1e3a01f` enforces all selectors = 1 on the last row → every chiplet `is_active` flag vanishes there → constraints auto-zero without the explicit transition guard. Polynomially non-equivalent but semantically equivalent under the last-row invariant. |

</details>

---
## 17. refactor: add per-bus domain separation to Challenges encoding

**8 updated** | 462 unchanged

> **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code.

<details>
<summary>8 constraint changes</summary>

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/bus/chiplets.rs:330` | `chiplets/bus/chiplets.rs:331` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 2 | `chiplets/bus/hash_kernel.rs:264` | `chiplets/bus/hash_kernel.rs:275` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 3 | `chiplets/bus/wiring.rs:147` | `chiplets/bus/wiring.rs:148` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 4 | `decoder/bus.rs:430` | `decoder/bus.rs:441` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 5 | `decoder/bus.rs:656` | `decoder/bus.rs:667` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 6 | `decoder/bus.rs:850` | `decoder/bus.rs:861` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 7 | `range/bus.rs:127` | `range/bus.rs:129` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |
| 8 | `stack/bus.rs:133` | `stack/bus.rs:135` | **Intentional non-equivalent change.** Per-bus domain tag added to `Challenges` encoding. 8 bus constraints affected: chiplets bus (1), hash_kernel bus (1), wiring bus (1), decoder bus (3), range bus (1), stack bus (1). Each polynomial now includes a distinct domain separator constant. Source expressions are identical before/after — the change is in how `Challenges` computes the encoding, not in the assertion code. |

</details>

---
## 18. refactor: narrow per-chiplet constraint functions to &ChipletFlags

**No constraint changes.** (446 base + 24 ext)

---
## 19. refactor: inline small constraint helper functions

**1 updated** | 469 unchanged

Helper `enforce_decoder_selector` inlined into call site. Expression restructured: `assert_zero(ONE - sp - ctrl_flag)` → `assert_one(sp + control_flow())`. Polynomial sign-flipped (`-(1 - sp - ctrl)` vs `sp + ctrl - 1`) but both assert the same zero. Moved from decoder/mod.rs:699 to decoder/mod.rs:132.

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `decoder/mod.rs:699` | `decoder/mod.rs:132` | Helper `enforce_decoder_selector` inlined into call site. Expression restructured: `assert_zero(ONE - sp - ctrl_flag)` → `assert_one(sp + control_flow())`. Polynomial sign-flipped (`-(1 - sp - ctrl)` vs `sp + ctrl - 1`) but both assert the same zero. Moved from decoder/mod.rs:699 to decoder/mod.rs:132. |

---
## 20. refactor: add typed column structs, col map, and Borrow impls

**No constraint changes.** (446 base + 24 ext)

---
## 21. refactor: wire MainCols into eval() — MainTraceRow becomes type alias

**No constraint changes.** (446 base + 24 ext)

---
## 22. refactor: migrate range constraints to named struct fields

**No constraint changes.** (446 base + 24 ext)

---
## 23. refactor: migrate decoder constraints to DecoderCols named fields

**No constraint changes.** (446 base + 24 ext)

---
## 24. refactor: migrate stack constraints to StackCols named fields

**No constraint changes.** (446 base + 24 ext)

---
## 25. refactor: migrate bitwise chiplet constraints to BitwiseCols

**No constraint changes.** (446 base + 24 ext)

---
## 26. refactor: migrate hasher + memory chiplet constraints to typed cols

**No constraint changes.** (446 base + 24 ext)

---
## 27. refactor: migrate ACE chiplet constraints to AceCols

**No constraint changes.** (446 base + 24 ext)

---
## 28. refactor: migrate kernel ROM constraints to KernelRomCols

**No constraint changes.** (446 base + 24 ext)

---
## 29. refactor: migrate chiplet bus wiring + hash_kernel to typed cols

**No constraint changes.** (446 base + 24 ext)

---
## 30. refactor: migrate chiplets bus constraints to typed column structs

**No constraint changes.** (446 base + 24 ext)

---
## 31. refactor: post-review cleanup of typed column structs

**No constraint changes.** (446 base + 24 ext)

---
## 32. refactor: add typed chiplet accessors to MainCols, eliminate raw chiplets access

**No constraint changes.** (446 base + 24 ext)

---
## 33. chore: format imports in chiplet constraint files

**No constraint changes.** (446 base + 24 ext)

---
## 34. refactor: split chiplets bus into requests/responses modules, reduce cloning

**No constraint changes.** (446 base + 24 ext)

---
## 35. refactor: apply constraint style rules — when() decomposition, semantic assertions

**10 updated** | 460 unchanged

Sign flip: `assert_zero(gate * x.not())` → `when(gate).assert_one(x)`. Polynomial negated but equivalent.

<details>
<summary>10 constraint changes</summary>

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/ace.rs:121` | `chiplets/ace.rs:132` | ace.rs:121→132. Gate extraction: `assert_zero(ace_transition * f_next * sblock * sblock_next.not())` → `when(ace_transition).when(f_next).when(sblock).assert_one(sblock_next)`. Sign flip + compound gate decomposed into `when()` chain. Equivalent. |
| 2 | `chiplets/ace.rs:125` | `chiplets/ace.rs:136` | ace.rs:125→136. Gate extraction: `assert_zero(ace_flag * f_end * sblock.not())` → `when(ace_flag).when(f_end).assert_one(sblock)`. Sign flip + gate decomposition. Equivalent. |
| 3 | `decoder/mod.rs:129` | `decoder/mod.rs:129` | decoder:129. Sign flip: `when_transition().assert_zero(span_flag * sp_next.not())` → `when_transition().when(span_flag).assert_one(sp_next)`. Equivalent. |
| 4 | `decoder/mod.rs:133` | `decoder/mod.rs:133` | decoder:133. Sign flip: `when_transition().assert_zero(respan_flag * sp_next.not())` → `when_transition().when(respan_flag).assert_one(sp_next)`. Equivalent. |
| 5 | `decoder/mod.rs:217` | `decoder/mod.rs:225` | decoder:217→225. Gate extraction into `when(f_repeat)` scope: `assert_zero(f_repeat * s0.not())` → `when(f_repeat).assert_one(s0)`. Sign flip + gate moved to scoped builder. Equivalent. |
| 6 | `decoder/mod.rs:218` | `decoder/mod.rs:226` | decoder:218→226. Gate extraction into `when(f_repeat)` scope: `assert_zero(f_repeat * is_loop_body.not())` → `when(f_repeat).assert_one(is_loop_body)`. Sign flip + gate moved to scoped builder. Equivalent. |
| 7 | `decoder/mod.rs:237` | `decoder/mod.rs:245` | decoder:237→245. Sign flip: `when_transition().assert_zero(f_halt * f_halt_next.not())` → `when_transition().when(f_halt).assert_one(f_halt_next)`. Equivalent. |
| 8 | `stack/ops/mod.rs:313` | `stack/ops/mod.rs:227` | stack/ops:313→227 (CSWAP). Gained `is_transition` factor: gate `builder.is_transition() * is_cswap` was manually computed, now `when_transition()` hoisted to function scope. Polynomial restructured but algebraically identical — `is_transition * is_cswap` present in both. Equivalent. |
| 9 | `stack/ops/mod.rs:324` | `stack/ops/mod.rs:237` | stack/ops:324→237 (CSWAPW). Gained `is_transition` factor: same restructuring as CSWAP — manually computed `builder.is_transition() * is_cswapw` gate replaced by function-level `when_transition()`. Algebraically identical. Equivalent. |
| 10 | `stack/ops/mod.rs:341` | `stack/ops/mod.rs:253` | stack/ops:341→253 (ASSERT). **Gained `is_transition` factor** not present before. Before: `when(is_assert).assert_one(s0)` (all rows). After: `when_transition().when(is_assert).assert_one(s0)` (transition rows only). Semantically equivalent because `is_assert` is an op flag that is zero on the last row (no operation executes there), so the constraint was already vacuous on the last row. |

</details>

---
## 36. refactor: flatten single-file stack constraint modules into sibling files

**No constraint changes.** (446 base + 24 ext)

---
## 37. refactor: type ACE shared columns into named fields with QuadFeltExpr

**7 updated** | 463 unchanged

ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent.

<details>
<summary>7 constraint changes</summary>

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/ace.rs:132` | `chiplets/ace.rs:108` | ace.rs:132→108. Sign flip: `assert_one(sblock_next)` → `assert_zero(f_read_next)` where `f_read_next = 1 - sblock_next`. `assert_one(x)` = `assert_zero(1-x)`. Equivalent. |
| 2 | `chiplets/ace.rs:136` | `ext_field.rs:155` | ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent. |
| 3 | `chiplets/ace.rs:196` | `ext_field.rs:154` | ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent. |
| 4 | `chiplets/ace.rs:197` | `ext_field.rs:155` | ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent. |
| 5 | `chiplets/ace.rs:208` | `ext_field.rs:154` | ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent. |
| 6 | `chiplets/ace.rs:209` | `chiplets/ace.rs:202` | ACE shared columns restructured from flat `shared[10]` array to named fields with `QuadFeltExpr<T>`. 4 of 7 constraints moved into `assert_eq_quad()` via `QuadFeltAirBuilder` — source extraction artifact shows `self.assert_eq(lhs.N, rhs.N)` at ext_field.rs instead of the call site. The underlying assertions are identical: per-component `assert_eq` / `assert_zero` pairs, with the gate changed from `ace_flag * f_end` to `is_last + is_transition * sstart_next` (see per-constraint entries below for gate equivalence). Equivalent. |
| 7 | `chiplets/ace.rs:210` | `chiplets/ace.rs:208` | ace.rs:210→208. Column rename: `assert_zero(id0)` → `assert_zero(local.id_0)`. Same column (`shared[0]` = `id_0`). Gate changed from `ace_flag * f_end` to new `f_end` (see be0e→820472 entry for gate equivalence proof). Equivalent. |

</details>

---
## 38. refactor: type periodic columns into named structs and simplify chiplet constraints

**5 updated** | 465 unchanged

kernel_rom.rs:70-73→62-65. Identical assertion expressions (`assert_eq(krom_next.root[i], krom.root[i])`); fingerprints changed because the upstream gate lost a redundant `(1 - s4')` factor. Old gate: `flags.is_transition * (1 - s4') * (1 - s_first')`. New gate: `flags.is_transition * (1 - s_first')`. Since `flags.is_transition` for kernel_rom already includes `(1 - s4')` (from selectors.rs:193: `kernel_rom_transition = is_transition_flag * s0123 * not_s4_next`), the old code was squaring `(1 - s4')²` which equals `(1 - s4')` on binary values. Polynomial changed (lost squared factor) but semantically equivalent on valid traces.

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/bitwise.rs:146` | `chiplets/bitwise.rs:122` | bitwise.rs:146→122. Sign flip: `assert_eq(prev_output_next, output)` → `assert_eq(output, prev_output_next)`. `assert_eq(a, b)` is `assert_zero(a - b)` so swapping arguments negates the polynomial. Equivalent. |
| 2 | `chiplets/kernel_rom.rs:70` | `chiplets/kernel_rom.rs:62` | kernel_rom.rs:70-73→62-65. Identical assertion expressions (`assert_eq(krom_next.root[i], krom.root[i])`); fingerprints changed because the upstream gate lost a redundant `(1 - s4')` factor. Old gate: `flags.is_transition * (1 - s4') * (1 - s_first')`. New gate: `flags.is_transition * (1 - s_first')`. Since `flags.is_transition` for kernel_rom already includes `(1 - s4')` (from selectors.rs:193: `kernel_rom_transition = is_transition_flag * s0123 * not_s4_next`), the old code was squaring `(1 - s4')²` which equals `(1 - s4')` on binary values. Polynomial changed (lost squared factor) but semantically equivalent on valid traces. |
| 3 | `chiplets/kernel_rom.rs:71` | `chiplets/kernel_rom.rs:63` | kernel_rom.rs:70-73→62-65. Identical assertion expressions (`assert_eq(krom_next.root[i], krom.root[i])`); fingerprints changed because the upstream gate lost a redundant `(1 - s4')` factor. Old gate: `flags.is_transition * (1 - s4') * (1 - s_first')`. New gate: `flags.is_transition * (1 - s_first')`. Since `flags.is_transition` for kernel_rom already includes `(1 - s4')` (from selectors.rs:193: `kernel_rom_transition = is_transition_flag * s0123 * not_s4_next`), the old code was squaring `(1 - s4')²` which equals `(1 - s4')` on binary values. Polynomial changed (lost squared factor) but semantically equivalent on valid traces. |
| 4 | `chiplets/kernel_rom.rs:72` | `chiplets/kernel_rom.rs:64` | kernel_rom.rs:70-73→62-65. Identical assertion expressions (`assert_eq(krom_next.root[i], krom.root[i])`); fingerprints changed because the upstream gate lost a redundant `(1 - s4')` factor. Old gate: `flags.is_transition * (1 - s4') * (1 - s_first')`. New gate: `flags.is_transition * (1 - s_first')`. Since `flags.is_transition` for kernel_rom already includes `(1 - s4')` (from selectors.rs:193: `kernel_rom_transition = is_transition_flag * s0123 * not_s4_next`), the old code was squaring `(1 - s4')²` which equals `(1 - s4')` on binary values. Polynomial changed (lost squared factor) but semantically equivalent on valid traces. |
| 5 | `chiplets/kernel_rom.rs:73` | `chiplets/kernel_rom.rs:65` | kernel_rom.rs:70-73→62-65. Identical assertion expressions (`assert_eq(krom_next.root[i], krom.root[i])`); fingerprints changed because the upstream gate lost a redundant `(1 - s4')` factor. Old gate: `flags.is_transition * (1 - s4') * (1 - s_first')`. New gate: `flags.is_transition * (1 - s_first')`. Since `flags.is_transition` for kernel_rom already includes `(1 - s4')` (from selectors.rs:193: `kernel_rom_transition = is_transition_flag * s0123 * not_s4_next`), the old code was squaring `(1 - s4')²` which equals `(1 - s4')` on binary values. Polynomial changed (lost squared factor) but semantically equivalent on valid traces. |

---
## 39. refactor: simplify op_flags with bit-selector pattern and iterative expansion

**4 updated** | 466 unchanged

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `stack/general.rs:76` | `stack/general.rs:76` |  |
| 2 | `stack/general.rs:76` | `stack/general.rs:76` |  |
| 3 | `stack/general.rs:76` | `stack/general.rs:76` |  |
| 4 | `stack/general.rs:76` | `stack/general.rs:76` |  |

---
## 40. refactor: use Algebra trait bound and remove op_flags indirection

**No constraint changes.** (446 base + 24 ext)

---
## 41. fix: use core::array for no-std compatibility

**No constraint changes.** (446 base + 24 ext)

---
## 42. refactor(decoder): improve readability of composite flags

**No constraint changes.** (446 base + 24 ext)

---
## 43. refactor(decoder): inline all constraint helpers into enforce_main and rewrite documentation

**3 updated** | 467 unchanged

**Updated:**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `decoder/mod.rs:173` | `decoder/mod.rs:208` |  |
| 2 | `decoder/mod.rs:180` | `decoder/mod.rs:214` |  |
| 3 | `decoder/mod.rs:181` | `decoder/mod.rs:213` |  |

---
---
## (merge) Merge origin/next into constraint-simplification

Merge pulled in `origin/next` including PR #2927 (Hasher chiplet redesign) and other upstream work. Base constraint count jumped from 446 to 509 (+63) due to the hasher redesign introducing new structural constraints. This merge is treated as the new baseline for subsequent entries — the merge delta itself is not decomposed here because it spans many unrelated upstream commits and is already covered by their respective PRs.


---
## 44. refactor: unify periodic column generation with typed struct constructors

**No constraint changes.** (509 base + 26 ext)


---
## 45. refactor: split hasher chiplet into controller and permutation sub-modules

**122 updated | 2 removed | 4 added** (511 base + 26 ext)

**Split hasher chiplet into controller + permutation sub-modules.** The single `chiplets[0]` hasher selector is replaced by two physical selectors `s_ctrl = chiplets[0]` and `s_perm = chiplets[20]`, with a virtual `s0 = 1 - (s_ctrl + s_perm)` replacing the direct column for all other chiplets. `ControllerCols` and `PermutationCols` become two disjoint logical overlays over the same 24 physical chiplet columns. The bulk of the 122 updated fingerprints fall into **category 3 (identical assertion source, upstream gate recomputed)**: every constraint in `chiplets/ace.rs`, `chiplets/bitwise.rs`, `chiplets/memory.rs`, `chiplets/kernel_rom.rs`, `chiplets/bus/{chiplets,hash_kernel,wiring}.rs`, `chiplets/ext_field.rs`, and `range/bus.rs` that reads `ChipletFlags.is_active` (or `is_transition`, `is_last`, `next_is_first`) picks up a new polynomial because the underlying `s0` expression is now `1 - s_ctrl - s_perm` rather than a raw column. Assertion text is byte-identical across the split; only the composed gate polynomial differs. **Plus** two intentional non-equivalent groups (see per-constraint entries below): (a) four new selector-transition rules enforcing the tri-state partition ordering `ctrl...ctrl, perm...perm, s0...s0`, (b) three new Permutation chiplet structural confinement constraints forcing the controller-only extra columns (`_is_boundary`, `_direction_bit`, `_mrupdate_id`) to zero on permutation rows, plus one new permutation cycle-end constraint. **Plus** a restored stability gate on `s1..s4` (the merge baseline had shifted prefix gates that rejected every valid trace) and a padding-stability guard fix that adds `is_transition` to avoid reading S-box witnesses on the last padding row. Net delta: 509 → 511 base constraints (+2).

113 of the 122 updated entries are category-3 (identical source, upstream gate recomputed) and fall under the narrative above; they are omitted from the table below. The 9 non-trivial entries are listed:

**Updated (non-trivial):**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/hasher/merkle.rs:147` | `chiplets/selectors.rs:174` | **Intentional non-equivalent.** New transition rule `when(s0).assert_zero(s_perm_next)` at `chiplets/selectors.rs:174` — once in the `s0` region, `s_perm` cannot reappear. Companion to the previous entry. Paired by the differ with another old capacity-zeroing assertion from `enforce_merkle_input_state:147` (same imperfect-pairing pattern). |
| 2 | `chiplets/hasher/merkle.rs:147` | `chiplets/selectors.rs:173` | **Intentional non-equivalent.** New transition rule `when(s0).assert_zero(s_ctrl_next)` at `chiplets/selectors.rs:173` — once in the `s0` region (bitwise/memory/ace/kernel_rom), `s_ctrl` cannot reappear. Paired by the differ with one of the four old Merkle-input capacity-zeroing assertions `gate * c` from `enforce_merkle_input_state:147`. Imperfect pairing — both use `assert_zero(...)` but are semantically unrelated. The 4 old capacity-zero constraints correspond to 4 new `assert_zero(c)` assertions at `hasher_control/merkle.rs:74` (same polynomials up to gate-factoring, hence equivalent); the differ scattered them across 2 new capacity slots (the remaining 2 are in the ADDED section below) and 2 new selector-transition rules by similarity.  |
| 3 | `chiplets/hasher/mod.rs:227` | `chiplets/selectors.rs:154` | **Intentional non-equivalent.** New `builder.assert_bool(s_ctrl.clone())` at `chiplets/selectors.rs:154` — booleanity for the new `s_ctrl` physical selector. The differ paired this with an unrelated old constraint `hasher_flag * cols.perm_seg * cols.mrupdate_id` (the old permutation-segment-forbids-mrupdate assertion) from `enforce_mrupdate_id_constraints:227`. Both sides are truly different constraints — the differ's similarity heuristic just grabbed the next `assert_zero/assert_bool`-shaped expression in the same file. The OLD constraint was replaced by the new Permutation chiplet confinement constraints (see permutation/mod.rs:79-81 entries below); this NEW constraint has no old analogue. (Source extractor bug: the extracted text shows `s_ctrl_or_s_perm` instead of `s_ctrl` because the backward-search heuristic grabbed the wrong line.) |
| 4 | `chiplets/hasher/selectors.rs:98` | `chiplets/selectors.rs:155` | **Intentional non-equivalent.** New `builder.assert_bool(s_perm.clone())` at `chiplets/selectors.rs:155` — booleanity for the new `s_perm` physical selector (which didn't exist in the merge baseline). Paired with an unrelated old constraint `(1 - hasher_flag) * cols.perm_seg` from `enforce_perm_seg_constraints:98`. Imperfect pairing — the OLD constraint was an orthogonality assertion between `hasher_flag` and `perm_seg` that no longer has meaning after the split. |
| 5 | `chiplets/hasher/selectors.rs:101` | `chiplets/permutation/mod.rs:79` | **Intentional non-equivalent.** New Permutation chiplet structural confinement `when(flags.is_active).assert_zero(cols._direction_bit)` at `chiplets/permutation/mod.rs:79` — forces the controller-only `direction_bit` column to be zero on permutation rows, required by the dual-overlay column layout where `ControllerCols.direction_bit` and some permutation column share the same physical column. Paired by the differ with old `hasher_flag * cols.perm_seg * (cols.perm_seg - 1)` from `enforce_perm_seg_constraints:101` — imperfect pairing, the OLD was a `perm_seg` booleanity assertion that no longer exists. |
| 6 | `chiplets/hasher/selectors.rs:108` | `chiplets/permutation/mod.rs:80` | **Intentional non-equivalent.** New Permutation chiplet structural confinement `when(flags.is_active).assert_zero(cols._mrupdate_id)` at `chiplets/permutation/mod.rs:80` — forces the controller-only `mrupdate_id` column to be zero on permutation rows. Paired with old `hasher_flag * hasher_flag_next * cols.perm_seg * (1 - cols_next.perm_seg)` from `enforce_perm_seg_constraints:108` — the OLD was a perm-segment continuity assertion eliminated by the new sub-chiplet structure. |
| 7 | `chiplets/hasher/selectors.rs:237` | `chiplets/permutation/mod.rs:81` | **Intentional non-equivalent.** New Permutation chiplet structural confinement `when(flags.is_active).assert_zero(cols._is_boundary)` at `chiplets/permutation/mod.rs:81` — forces the controller-only `is_boundary` column to be zero on permutation rows. Paired with old `hasher_flag * cols.s0 * cols.is_boundary * (cols.is_boundary - 1)` from `enforce_lifecycle_booleanity:237` — the OLD was an input-row is_boundary booleanity that now lives at `hasher_control/mod.rs:113` (and is further hoisted in db23d39db to `is_active` scope; see db23d39db0 per-constraint entry below). (Source extractor bug: extracted text shows `_mrupdate_id` instead of `_is_boundary` because lines 80 and 81 are adjacent confinement asserts and the backward-search heuristic picks the wrong line.) |
| 8 | `chiplets/hasher/selectors.rs:308` | `chiplets/selectors.rs:163` | **Intentional non-equivalent.** New transition rule `when(s_ctrl).assert_one(s_ctrl_or_s_perm_next)` at `chiplets/selectors.rs:163` — a controller row must be followed by another controller or permutation row. Part of the new tri-state partition's transition system enforcing the trace ordering `ctrl...ctrl, perm...perm, s0...s0`. Paired by the differ with an unrelated old `padding_flag * next_is_controller * cols_next.s0` assertion from `enforce_controller_pairing:308` — a similar-shaped constraint but with totally different semantics. The OLD constraint's obligation (no input row at the ctrl→perm boundary) is now enforced in the db23d39db0 commit via `when(is_last).assert_zero(is_input)`. |
| 9 | `chiplets/hasher/selectors.rs:311` | `chiplets/selectors.rs:167` | **Intentional non-equivalent.** New transition rule `when(s_perm).assert_zero(s_ctrl_next)` at `chiplets/selectors.rs:167` — a permutation row cannot be followed by a controller row. Part of the new trace ordering enforcement. Paired with old `padding_flag * next_is_controller * (1 - cols_next.s1)` from `enforce_controller_pairing:311` — imperfect pairing, unrelated semantics. |

**Removed:**

| # | Location | Expression |
|---|----------|------------|
| 1 | `chiplets/hasher/selectors.rs:245` | `builder.assert_zero( hasher_flag * (AB::Expr::ONE - cols.s0.clone()) * (AB::Expr::ONE - cols.s1.clone()) * cols.is_boundary.clone() * (cols.is_boundary.clone() - AB::Expr::ONE), );` |
| 2 | `chiplets/hasher/selectors.rs:117` | `builder.assert_zero( hasher_flag.clone() * hasher_flag_next.clone() * (AB::Expr::ONE - cols.perm_seg.clone()) * cols_next.perm_seg.clone() * not_boundary.clone(), );` |

**Added:**

| # | Location | Expression |
|---|----------|------------|
| 1 | `chiplets/hasher_control/merkle.rs:74` | `builder.assert_zero(c);` |
| 2 | `chiplets/hasher_control/merkle.rs:74` | `builder.assert_zero(c);` |
| 3 | `chiplets/hasher_control/merkle.rs:74` | `builder.assert_zero(c);` |
| 4 | `chiplets/permutation/mod.rs:108` | `builder.when(flags.is_last.clone()).assert_zero(not_cycle_end);` |


---
## 46. refactor: restructure hasher controller constraints by operation lifetime

**8 updated | 3 removed | 1 added** (509 base + 26 ext)

**Lifetime-based restructure of hasher controller constraints.** Collapses `hasher_control/merkle.rs` into `hasher_control/mod.rs` and reorganizes every controller constraint under the narrative order `trace skeleton → operation start → sponge ops → merkle ops → operation end`. Refactors `ControllerFlags` into a pure row-kind naming layer with no chiplet-level scope; every call site combines `ChipletFlags × ControllerFlags` by multiplication at the `when()` level. 8 updated + 3 removed + 1 added, net -2 constraints (511 → 509). The -2 delta comes from consolidating two old pair-of-assertion forms (input→output adjacency and padding stability) each into a single `assert_one(product)` form (-1 each). See per-constraint entries for the semantic breakdown.

**Updated (non-trivial):**

| # | Before | After | Interpretation |
|---|--------|-------|----------------|
| 1 | `chiplets/hasher_control/merkle.rs:95` | `chiplets/hasher_control/mod.rs:174` | **Imperfect pairing across semantically distinct constraints (category 1 effects on both sides).** OLD: `when(cf.on_output).assert_bool(cols.is_boundary)` at `hasher_control/merkle.rs:95` — output-row is_boundary booleanity. This assertion was absorbed into the hoisted `when(is_active).assert_bool(is_boundary)` at `hasher_control/mod.rs:111` (see separate entry). NEW: `when(is_transition).when(is_input).assert_one(is_output_next)` at `hasher_control/mod.rs:174` — the consolidated single-assertion form of input→output adjacency, replacing the old two-assertion form (`assert_zero(s0_next)` + `assert_zero(s1_next)` under `when(on_input)`). Both sides are independently semantically equivalent to their respective old forms; the differ just paired them because they're spatially adjacent in the function body. |
| 2 | `chiplets/hasher_control/merkle.rs:196` | `chiplets/hasher_control/mod.rs:314` | **Intentional non-equivalent change.** Merkle digest-routing constraint, lane 0. The new form at `hasher_control/mod.rs:314` uses `merkle_next_lite = s1' + s2'` (degree 1, non-boolean: MU gives 2) instead of the old `is_merkle_input_next` (degree 3: `s0' * (s1' + s2' - s1'*s2')`) as the gating selector, plus a sign flip rewriting the assertion from `assert_zero(gate * (rate0_next - rate0_curr + b*(rate1_next - rate0_next)))` to `when(gate).assert_eq(rate0_curr, rate0_next + b*(rate1_next - rate0_next))`. **Degree reduction is required** to fit within the system's degree-9 cap: the old composite gate `is_active(1) * is_output(2) * !is_boundary(1) * is_merkle_input_next(3) * inner(2)` was at the cap, and the new inlined form needs headroom for the rewritten inner. **Soundness** (also documented in the `merkle_next_lite` comment in `hasher_control/flags.rs`): a malicious prover could mislabel a Merkle input as sponge (`s0'=1, s1'=s2'=0`) to zero `merkle_next_lite` and bypass routing. This is caught by the bus — any `(s0'=1, s1'=0, s2'=0)` input row fires the sponge bus message path with no matching decoder request, so the bus proof fails. Applies to all 4 digest-routing lanes (the differ paired them imperfectly across this and three other UPDATED entries below). |
| 3 | `chiplets/hasher_control/mod.rs:100` | `chiplets/hasher_control/mod.rs:314` | **Intentional non-equivalent — imperfect pairing.** This row's NEW side (`hasher_control/mod.rs:314`, the digest-routing `assert_eq`) is one of the 4 Merkle digest-routing lanes that switched to `merkle_next_lite` (see previous entry for the full soundness argument). The OLD side `assert_zero(cols_next.s1)` from `hasher_control/mod.rs:100` is the SECOND half of the old two-assertion form of input→output adjacency (the other half was `assert_zero(cols_next.s0)` on line 101) — it was replaced by the consolidated single-assertion form `when(is_input).assert_one(is_output_next)` at `hasher_control/mod.rs:174` (listed as a separate UPDATED row). The differ paired them because both are `assert_zero/assert_eq`-shaped constraints with nearby line numbers. |
| 4 | `chiplets/hasher_control/mod.rs:101` | `chiplets/hasher_control/mod.rs:314` | **Intentional non-equivalent — imperfect pairing.** Same as previous entry: NEW side is a digest-routing lane (intentional `merkle_next_lite` substitution), OLD side `assert_zero(cols_next.s1)` at `hasher_control/mod.rs:101` was part of the old two-assertion input→output adjacency form. Duplicated fingerprint because the old code had the assertion twice (once per row context). Consolidated into the single `when(is_input).assert_one(is_output_next)` form. |
| 5 | `chiplets/hasher_control/mod.rs:113` | `chiplets/hasher_control/mod.rs:111` | **is_boundary booleanity hoisted (category 2).** Old: `when(cf.on_input).assert_bool(cols.is_boundary)` at `hasher_control/mod.rs:113` — only enforced on input rows. New: `when(chiplet.is_active).assert_bool(cols.is_boundary)` at `hasher_control/mod.rs:111` — enforced on all controller rows. Category 2 guard change relying on an invariant: on padding rows, padding confinement already forces `is_boundary = 0`, so the extra booleanity assertion on padding rows is a no-op; on output rows, `is_boundary` marks end-of-operation so booleanity is wanted there too. The new gate is a strict superset of the old gate but asserts the same invariant. Equivalent. |
| 6 | `chiplets/hasher_control/mod.rs:134` | `chiplets/hasher_control/mod.rs:125` | **Output non-adjacency gate simplification (category 1).** Old: `when(cf.is_transition).when(cf.on_output).assert_zero(cf.f_output_next)` at `hasher_control/mod.rs:134`. New: `when(chiplet.is_transition).when(rows.is_output).assert_zero(rows.is_output_next)` at `hasher_control/mod.rs:125`. The old `cf.on_output = is_active * (1-s0) * (1-s1)` included an `is_active` factor that was redundant because `is_transition = is_active * is_active'` already contains it. Removing the redundant factor produces a different polynomial (`is_active² * rest` vs `is_active * rest`) but identical semantics on valid traces since `is_active` is boolean. Equivalent. |
| 7 | `chiplets/hasher_control/mod.rs:152` | `chiplets/hasher_control/mod.rs:163` | **Intentional new constraint.** NEW: `when(chiplet.is_last).assert_zero(rows.is_input)` at `hasher_control/mod.rs:163` — forbids the last controller row from being an input row. Without this, the input→output adjacency rule (which relies on `s_ctrl'` being set on the next row so that `cols_next.s0/s1` are boolean) would have a hole at the ctrl→perm boundary: an input row at the last controller position could point at a permutation row whose `s0/s1/s2` are S-box witnesses (not binary selectors). This new constraint closes the hole. OLD: `assert_zero(cols_next.s0)` at `hasher_control/mod.rs:152` — was part of the old two-assertion input→output adjacency form, now consolidated (see previous entries). The differ paired them because both are `assert_zero(...)` shapes referring to `s0/is_input`. |
| 8 | `chiplets/hasher_control/mod.rs:155` | `chiplets/hasher_control/mod.rs:314` | **Intentional non-equivalent — imperfect pairing.** NEW side is the 4th digest-routing lane (intentional `merkle_next_lite` substitution). OLD side `assert_one(cols_next.s1)` at `hasher_control/mod.rs:155` was part of the OLD two-assertion form of padding stability (asserting `s1_next = 1` on padding rows); that assertion was consolidated into the single-assertion form `when(is_padding).assert_one(is_padding_next)` listed in the ADDED section below. |

**Removed:**

| # | Location | Expression |
|---|----------|------------|
| 1 | `chiplets/hasher_control/merkle.rs:196` | `builder.assert_zero( gate.clone() * (AB::Expr::from(rate0_next[j]) - AB::Expr::from(rate0_curr[j]) + b.clone() * (AB::Expr::from(rate1_next[j]) - AB::Expr::from(rate0_next[j]))), );` |
| 2 | `chiplets/hasher_control/merkle.rs:196` | `builder.assert_zero( gate.clone() * (AB::Expr::from(rate0_next[j]) - AB::Expr::from(rate0_curr[j]) + b.clone() * (AB::Expr::from(rate1_next[j]) - AB::Expr::from(rate0_next[j]))), );` |
| 3 | `chiplets/hasher_control/merkle.rs:196` | `builder.assert_zero( gate.clone() * (AB::Expr::from(rate0_next[j]) - AB::Expr::from(rate0_curr[j]) + b.clone() * (AB::Expr::from(rate1_next[j]) - AB::Expr::from(rate0_next[j]))), );` |

**Added:**

| # | Location | Expression |
|---|----------|------------|
| 1 | `chiplets/hasher_control/mod.rs:139` | `builder .when(chiplet.is_transition.clone()) .when(rows.is_padding.clone()) .assert_one(rows.is_padding_next.clone());` |



---
