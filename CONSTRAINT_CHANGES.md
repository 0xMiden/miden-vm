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
