# Documentation Updates Required for Plonky3 Migration

This document tracks documentation that needs to be updated following the Plonky3 migration.

## 🔴 Critical - Immediate Changes Required

### 1. `prover/README.md` (Line 2)

**Current (INCORRECT):**
```markdown
This crate contains the Miden VM prover, which proves correct execution of Miden VM.
Internally, the prover uses [Miden processor](../processor/) to execute the programs,
and then relies on the [Winterfell](https://github.com/novifinancial/winterfell) prover
to generate STARK proofs.
```

**Should be:**
```markdown
This crate contains the Miden VM prover, which proves correct execution of Miden VM.
Internally, the prover uses [Miden processor](../processor/) to execute the programs,
and then uses [Plonky3](https://github.com/0xMiden/Plonky3) to generate STARK proofs.
```

### 2. `air/src/proof.rs` (Lines 66, 74)

**Current:**
```rust
/// TODO(Al): Migrate security estimator from Winterfell to 0xMiden/Plonky3
/// The previous Winterfell implementation (commented out above) should serve as a reference
```

**Action:** Remove or update TODO comments about Winterfell migration status

### 3. `prover/README.md` - Add STARK Backend Section

**Add after line 41:**
```markdown
## STARK Backend

The prover uses [Plonky3](https://github.com/0xMiden/Plonky3), a modular STARK proving framework that supports:

- **Multiple hash functions**: BLAKE3, Keccak, RPO256, Poseidon2, RPX256
- **Configurable security levels**: 96-bit or 128-bit
- **Efficient recursive proofs**: Using arithmetization-friendly hash functions
- **Parallel proof generation**: Multi-threaded via rayon

STARK configurations are defined in the `miden-air` crate and shared between the prover and verifier, ensuring consistency across the system.

### Hash Function Selection

Different hash functions offer different tradeoffs:
- **BLAKE3/Keccak**: Fast proving, larger proofs, not efficient for recursion
- **RPO256/Poseidon2/RPX256**: Slower proving, smaller proofs, efficient for recursive verification in Miden VM
```

## 🟡 Medium Priority - Add Plonky3 Information

### 4. `air/README.md` - Add Backend Information

**Add new section before "License":**
```markdown
## STARK Backend

Miden VM AIR is designed to be backend-agnostic, but currently uses [Plonky3](https://github.com/0xMiden/Plonky3) as the STARK proving system. Plonky3 provides:

- Modular polynomial commitment schemes
- Multiple hash function backends (BLAKE3, Keccak, RPO, Poseidon2, RPX)
- High-performance field arithmetic optimized for modern CPUs
- Support for both native and recursive proof verification

The AIR constraints defined in this crate are evaluated by Plonky3's prover to generate execution proofs.
```

### 5. `verifier/README.md` - Add Backend Information

**Add after the description:**
```markdown
## STARK Verification

The verifier uses [Plonky3](https://github.com/0xMiden/Plonky3) to verify STARK proofs. The verification process checks:

1. Correct commitment to the execution trace
2. Proper evaluation of AIR constraints
3. Valid FRI protocol execution for polynomial commitment verification

The verifier is completely independent of the prover crate, depending only on `miden-air` for shared types and configurations.
```

### 6. Main `README.md` - Update Prover Section

**Location:** Around line 135 (performance section)

**Add paragraph:**
```markdown
### STARK Proving System

Miden VM uses [Plonky3](https://github.com/0xMiden/Plonky3), a next-generation STARK proving framework that provides modular backends and high performance. The migration from Winterfell to Plonky3 enables better extensibility and maintainability while maintaining strong security guarantees.
```

### 7. `MIGRATION_NOTES.md` - Update or Archive

**Options:**
1. **Update to completion status** - Change from "in progress" to "completed"
2. **Move to `docs/architecture/plonky3-migration.md`** - Archive as historical reference
3. **Delete** - If no longer needed post-migration

**Recommendation:** Move to `docs/architecture/` and add completion summary

## 🟢 Low Priority - Code Comments

### 8. Code Comment Reviews

Review these files for outdated Winterfell references in comments:

- [ ] `processor/src/trace/mod.rs` - Check for Winterfell references
- [ ] `core/src/program.rs` - Check for legacy prover mentions
- [ ] `crates/assembly-syntax/src/library/mod.rs` - Update if needed
- [ ] `crates/test-serde-macros/src/lib.rs` - Update if needed

**Search command:**
```bash
grep -rn "winterfell\|Winterfell" --include="*.rs" processor/ core/ crates/
```

## 📚 Optional Enhancements

### 9. Create Architecture Documentation

**New file:** `docs/architecture/proving-system.md`

Document:
- Dependency structure (processor → air ← verifier, prover)
- AuxTraceBuilder trait pattern (dependency inversion)
- Config module sharing strategy
- Format conversion (row-major ↔ column-major)
- Why verifier doesn't depend on processor/prover

### 10. Create Migration Guide

**New file:** `docs/architecture/winterfell-to-plonky3.md`

Document for future reference:
- What changed in the migration
- API differences between Winterfell and Plonky3
- Architectural improvements made
- Performance implications
- Breaking changes (if any for users)

## Checklist for Completion

- [ ] Fix prover/README.md Winterfell reference
- [ ] Update/remove air/src/proof.rs TODOs
- [ ] Add STARK backend section to prover/README.md
- [ ] Add backend info to air/README.md
- [ ] Add verification info to verifier/README.md
- [ ] Update main README.md with Plonky3 mention
- [ ] Update or archive MIGRATION_NOTES.md
- [ ] Review code comments in processor/core/crates
- [ ] (Optional) Create architecture documentation
- [ ] (Optional) Create migration guide

## Notes

- All example code in READMEs appears to use current API (verified)
- External links to StarkWare blog posts are still relevant (generic AIR concepts)
- Documentation about FRI and STARK theory can remain unchanged
- AuxTraceBuilder dependency inversion is already well-documented in code

---

**Document created:** 2025-12-15
**Status:** Pending implementation
**Related PR:** [Insert PR number when created]
