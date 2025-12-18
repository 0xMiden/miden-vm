# Plonky3 Migration - Follow-up GitHub Issues

This document contains follow-up issues to be created after the Plonky3 migration PR is merged.

**Note:** Issues #3 and #4 from the original list were addressed in the migration PR.

---

## Issue 1: Implement Security Level Estimator for Plonky3

**Title:** `[air] Implement security level estimator for Plonky3 proofs`

**Labels:** `enhancement`, `plonky3`

**Description:**
The `ExecutionProof::security_level()` method currently returns a hardcoded value of 96 bits. We need to implement a proper security estimator that calculates the actual conjectured security level based on proof parameters.

**Location:** `air/src/proof.rs:64-78`

**Current code:**
```rust
/// Returns conjectured security level of this proof in bits.
///
/// TODO(Al): Migrate security estimator from Winterfell to 0xMiden/Plonky3
///
/// Currently returns a hardcoded 128 bits. Once the security estimator is implemented
/// in Plonky3, this should calculate the actual conjectured security level based on:
/// - Proof parameters (FRI folding factor, number of queries, etc.)
/// - Hash function collision resistance
/// - Field size and extension degree
pub fn security_level(&self) -> u32 {
    96
}
```

**Tasks:**
- [ ] Implement security estimator in `0xMiden/Plonky3` or port from Winterfell
- [ ] Update `security_level()` to use the actual calculation
- [ ] Add tests for different hash function configurations

---

## Issue 2: Add Blake3_192 Support to Plonky3

**Title:** `[plonky3] Add CryptographicHasher<u8, [u8; 24]> trait impl for Blake3_192`

**Labels:** `enhancement`, `plonky3`, `upstream`

**Repository:** `0xMiden/Plonky3`

**Description:**
Blake3_192 currently falls back to using Blake3_256 configuration because Plonky3 lacks the `CryptographicHasher<u8, [u8; 24]>` trait implementation for 24-byte (192-bit) output.

**Locations:**
- `air/src/config/blake3.rs:5`
- `prover/src/lib.rs:82-85`

**Current workaround:**
```rust
HashFunction::Blake3_192 => {
    // TODO: Blake3_192 currently uses Blake3_256 config (32-byte output instead of
    // 24-byte). Proper 192-bit support requires Plonky3 to implement
    // CryptographicHasher<u8, [u8; 24]> for Blake3.
    let config = miden_air::config::create_blake3_256_config();
    // ...
}
```

**Tasks:**
- [ ] Add `CryptographicHasher<u8, [u8; 24]>` impl for Blake3 in Plonky3
- [ ] Create `create_blake3_192_config()` in `air/src/config/blake3.rs`
- [ ] Update prover and verifier to use the correct config

---

## Issue 3: Add Documentation to Hasher Trace Module

**Title:** `[air] Add documentation to hasher trace module`

**Labels:** `documentation`

**Description:**
The hasher trace module is missing documentation.

**Location:** `air/src/trace/chiplets/hasher.rs:1`

**Tasks:**
- [ ] Add module-level documentation explaining the hasher trace structure
- [ ] Document the trace selectors and their purpose

---

## Issue 4: Rename "Hasher State" to "Shared Columns"

**Title:** `[air] Rename decoder "hasher state" to "shared columns"`

**Labels:** `refactor`, `documentation`

**Description:**
The decoder module uses "hasher state" terminology which may be confusing. Consider renaming to "shared columns" for clarity.

**Location:** `air/src/trace/decoder/mod.rs:22`

**Current comment:**
```rust
// TODO: probably rename "hasher state" to something like "shared columns".
```

---

## Issue 5: Add Documentation to Trace Utils

**Title:** `[processor] Add documentation to trace utils module`

**Labels:** `documentation`

**Description:**
The trace utils module is missing documentation.

**Location:** `processor/src/trace/utils.rs:15`

---

## Issue 6: Implement MerkleStore::has_path() Method

**Title:** `[processor] Implement MerkleStore::has_path() method`

**Labels:** `enhancement`

**Description:**
The advice provider has a TODO to switch to `MerkleStore::has_path()` once implemented.

**Location:** `processor/src/host/advice/mod.rs:290`

**Current code:**
```rust
// TODO: switch to `MerkleStore::has_path()` once this method is implemented
```

---

## Issue 7: Parallelize Hasher Trace Column Copying

**Title:** `[processor] Parallelize hasher trace column copying`

**Labels:** `performance`, `enhancement`

**Description:**
The hasher trace building could be optimized by parallelizing column copying operations.

**Locations:**
- `processor/src/chiplets/hasher/trace.rs:144`
- `processor/src/chiplets/bitwise/mod.rs:172`

**Current comments:**
```rust
// TODO: this can be parallelized to copy columns in multiple threads
```

---

## Issue 8: Reorganize Hasher Module Code

**Title:** `[processor] Move hasher helper code to separate file`

**Labels:** `refactor`

**Description:**
Some code in the hasher module should be moved to a separate file for better organization.

**Location:** `processor/src/chiplets/hasher/mod.rs:418`

**Current comment:**
```rust
// TODO: Move these to another file.
```

---

## Issue 9: Use Batch Inversion in Memory Chiplet

**Title:** `[processor] Use batch inversion in memory chiplet for efficiency`

**Labels:** `performance`, `enhancement`

**Description:**
The memory chiplet could be more efficient by using batch inversion instead of individual inversions.

**Location:** `processor/src/chiplets/memory/mod.rs:368`

**Current comment:**
```rust
// TODO: switch to batch inversion to improve efficiency.
```

---

## ~~Issue 10: Remove is_first_child Field from BlockStack~~ (INVALID)

**Status:** INVALID - The TODO comment is misleading. The `is_first_child` field is **actively used** in the block hash table auxiliary trace builder (`processor/src/decoder/aux_trace/block_hash_table.rs`). The field should NOT be removed; instead, the TODO comment should be removed.

**Location:** `processor/src/decoder/block_stack.rs:113`

---

## Issue 11: Get Operation Info from Decoder Trace

**Title:** `[processor] Consider getting operation info from decoder trace`

**Labels:** `refactor`, `enhancement`

**Description:**
It might be better to get operation information from the decoder trace rather than the current approach.

**Location:** `processor/src/decoder/mod.rs:851`

**Current comment:**
```rust
/// TODO: it might be better to get the operation information from the decoder trace, rather
```

---

## Issue 12: Fix Block Hash Table TODO

**Title:** `[processor] Address block hash table aux trace TODO`

**Labels:** `enhancement`

**Description:**
There's an unfinished TODO in the block hash table auxiliary trace builder.

**Location:** `processor/src/decoder/aux_trace/block_hash_table.rs:141`

---

## Issue 13: Change Stack Depth Types to u32

**Title:** `[processor] Change stack depth types from usize to u32`

**Labels:** `refactor`, `type-safety`

**Description:**
Stack depth fields should use `u32` instead of `usize` for consistency and type safety.

**Locations:**
- `processor/src/stack/trace.rs:310` - `init_depth`
- `processor/src/stack/mod.rs:198` - `active_depth`

**Current comments:**
```rust
// TODO: change type of `init_depth` to `u32`
// TODO: change type of `active_depth` to `u32`
```

---

## Issue 14: Optimize Range Checker Data Structure

**Title:** `[processor] Optimize range checker to use struct instead of vectors`

**Labels:** `performance`, `refactor`

**Description:**
The range checker could be optimized by using a struct instead of vectors.

**Location:** `processor/src/range/mod.rs:84`

**Current comment:**
```rust
// TODO: optimize this to use a struct instead of vectors, e.g.:
```

---

## Priority Order

1. **High Priority** (blocking or user-facing):
   - Issue 1: Security level estimator
   - Issue 2: Blake3_192 support

2. **Medium Priority** (code quality):
   - Issue 13: Type consistency

3. **Low Priority** (performance/cleanup):
   - Issues 7, 9, 14: Performance optimizations
   - Issue 5: Documentation
   - Issues 8, 11, 12: Code organization

## Completed in Migration PR

- ~~Issue 3~~: Hasher trace module documentation
- ~~Issue 4~~: Clarified "hasher state" comment in decoder

## Invalid Issues

- ~~Issue 10~~: The `is_first_child` field is actively used; TODO comment is incorrect

---

# Upstream Issues

These issues need to be addressed in external repositories.

---

## Upstream Issue 1: Remove winter-utils from Plonky3

**Title:** `Remove winter-utils dependency from p3-goldilocks`

**Repository:** `0xMiden/Plonky3`

**Labels:** `cleanup`, `dependencies`

**Description:**
The `p3-goldilocks` crate still depends on `winter-utils v0.13.1`, which is the only remaining Winterfell dependency in the Miden ecosystem after the Plonky3 migration.

**Dependency chain:**
```
winter-utils v0.13.1
└── p3-goldilocks (0xMiden/Plonky3, branch zz/migrate-plonky3)
    └── miden-crypto (branch al-e2e-plonky3)
        └── miden-vm (all crates)
```

**Tasks:**
- [ ] Identify what `winter-utils` is used for in `p3-goldilocks`
- [ ] Replace with native implementations or `miden-crypto` utilities
- [ ] Remove the dependency

---

## Upstream Issue 2: Remove or Fix Legacy STARK Tests

**Title:** `[core-lib] Remove or port legacy STARK tests to Plonky3`

**Labels:** `cleanup`, `testing`

**Description:**
The `crates/lib/core/tests/` directory contains legacy STARK tests that:
1. Use `winter_fri` and `winter_air` directly
2. Are behind the `legacy-stark-tests` feature flag
3. **Do not compile** (17 errors due to API changes)

**Affected files:**
- `crates/lib/core/tests/pcs/fri/channel.rs`
- `crates/lib/core/tests/pcs/fri/verifier_fri_e2f4.rs`
- `crates/lib/core/tests/stark/verifier_recursive/channel.rs`
- `crates/lib/core/tests/stark/verifier_recursive/mod.rs`
- `crates/lib/core/tests/stark/mod.rs`

**Options:**
1. **Remove** - If these tests are no longer relevant after Plonky3 migration
2. **Port** - Rewrite tests to use Plonky3 APIs instead of Winterfell

**Tasks:**
- [ ] Determine if these tests provide value post-migration
- [ ] Either delete or port to Plonky3
- [ ] Remove `legacy-stark-tests` feature flag if tests are removed

---

## Upstream Issue 3: Update ByteWriter Panic Comment

**Title:** `Update or remove Winterfell reference in ByteWriter panic comment`

**Labels:** `documentation`, `cleanup`

**Description:**
There's a comment referencing Winterfell that should be updated since the serialization now comes from `miden-crypto`:

**Location:** `crates/assembly-syntax/src/library/mod.rs:416`

**Current comment:**
```rust
// NOTE: We catch panics due to i/o errors here due to the fact that the ByteWriter
// trait does not provide fallible APIs, so WriteAdapter will panic if the underlying
// writes fail. This needs to be addressed in winterfell at some point
```

**Action:** Update to reference `miden-crypto` or remove the Winterfell mention since the trait now comes from `miden-crypto::utils`.

---

## Upstream Issue 4: Rename Plonky3 Crates to Avoid Name Conflicts

**Title:** `Rename miden-prover and miden-air to avoid conflicts with miden-vm crates`

**Repository:** `0xMiden/Plonky3`

**Labels:** `breaking-change`, `naming`

**Description:**
The `0xMiden/Plonky3` fork contains crates named `miden-prover` and `miden-air`, which conflict with the crate names used in `miden-vm`. This naming collision causes confusion and potential issues when both repositories are used together.

**Proposed renaming:**
- `miden-prover` → `miden-p3-prover` (or `miden-prover-p3`)
- `miden-air` → `miden-p3-air` (or `miden-air-p3`)

**Rationale:**
1. Avoids name collision with `miden-vm/prover` and `miden-vm/air` crates
2. Makes it clear these are Plonky3-specific implementations
3. Follows common naming conventions for framework-specific adapters

**Tasks:**
- [ ] Rename `miden-prover` crate in 0xMiden/Plonky3
- [ ] Rename `miden-air` crate in 0xMiden/Plonky3
- [ ] Update all internal references
- [ ] Update miden-vm to use the new crate names

---

## Upstream Issue 5: FRI Octary Folding Causes RootMismatch Errors

**Title:** `FRI verification fails with octary folding (log_folding_factor > 1)`

**Repository:** `0xMiden/Plonky3`

**Labels:** `bug`, `fri`

**Description:**
Using `log_folding_factor: 3` (octary folding, fold by 8 each round) in FRI parameters causes `RootMismatch` errors during proof verification. Currently all configs are forced to use `log_folding_factor: 1` (binary folding) as a workaround.

**Affected locations in miden-vm:**
- `air/src/config/blake3.rs:84-88`
- `air/src/config/poseidon2.rs:84-88`
- `air/src/config/rpx.rs:86-90`

**Current workaround:**
```rust
let fri_config = FriParameters {
    // ...
    log_folding_factor: 1, /* Binary folding 
                            * NOTE:  (log_folding_factor: 3) causes
                            * RootMismatch errors in verification. */
};
```

**Impact:**
- Larger proof sizes (more FRI rounds with binary folding)
- Slower verification (more rounds to process)

**Tasks:**
- [ ] Investigate root cause of RootMismatch with higher folding arities
- [ ] Fix FRI folding logic to support `log_folding_factor > 1`
- [ ] Add tests for various folding arities
