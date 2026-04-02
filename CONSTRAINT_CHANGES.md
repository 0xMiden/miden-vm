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
