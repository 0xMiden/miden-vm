# PR #2472 Review Comments and Responses

## Summary

Review: https://github.com/0xMiden/miden-vm/pull/2472#pullrequestreview-3588590434

Reviewer's main points:
1. Use Plonky3's inversion and transposition
2. Run clippy to fix formatting (unused parentheses)
3. Some changes can likely be reverted (residues of merges)

---

## Individual Comments

### 1. `prover/Cargo.toml:18` - Add `p3-maybe-rayon/parallel` to concurrent feature

**Comment:**
> `maybe-rayon` has the `parallel` feature that we may want to enable. All of these crates re-export it, but since they all depend on `maybe-rayon`, setting the feature only once there is enough to enable it for all upstream crates.

**Suggestion:**
```toml
concurrent = ["std", "miden-processor/concurrent", "p3-maybe-rayon/parallel"]
```

**Response:** DONE. Added `p3-maybe-rayon/parallel` to the concurrent feature.

---

### 2. `verifier/src/lib.rs:173,176` - Rename error variants

**Suggestion:**
```rust
#[error("the input {0} is not a valid field element")]
InputNotFieldElement(u64),
/// A public output value is not a valid field element.
#[error("the output {0} is not a valid field element")]
OutputNotFieldElement(u64),
```

**Response:** KEPT ORIGINAL. The original error variant names `InputNotFieldElement` and `OutputNotFieldElement` were already correct and have been preserved.

---

### 3. `verifier/src/lib.rs:170` - Use `#[source]` instead of `#[from]`

**Suggestion:**
```rust
PrecompileVerification(#[source] PrecompileVerificationError),
```

**Response:** NOT CHANGED. The `#[from]` attribute is required because the code uses `?` operator for automatic error conversion (line 81: `registry.requests_transcript(&precompile_requests)?`). Using `#[source]` would break this conversion and cause a compilation error.

---

### 4. `verifier/src/lib.rs:81` - Revert changes

**Comment:**
> In this file overall there are a few changes that could be reverted as they shouldn't have an impact on verification.

**Response:** MINIMIZED. The verifier file has been cleaned up to minimize unnecessary changes:

**Preserved from original:**
- `mod exports` structure
- `_commitment` variable name
- Original doc comments for `verify_with_precompiles`
- Original error variant names
- Original code comments

**Removed (unnecessary):**
- `DetailedError` variant (was unused and new)

**Only essential migration changes retained:**
- Imports: winter_verifier → miden_prover_p3
- Removed Winterfell-specific exports (`AcceptableOptions`, `VerifierError`, `FieldElement`, `StarkField`)
- New `verify_stark` helper using Plonky3's verify API
- `ProgramVerificationError` no longer wraps `VerifierError` (type doesn't exist in Plonky3)

---

### 5. `processor/src/lib.rs:43` - Use Plonky3's transpose

**Comment:**
> We could re-use [plonky3's transpose](https://github.com/Plonky3/Plonky3/blob/bbae683521fb5109da6935a877c708aeb8669a64/matrix/src/dense.rs#L557)

**Response:** DONE. Modified `prover/src/trace_adapter.rs` to use Plonky3's `RowMajorMatrix::transpose()` method instead of our custom implementation.

---

### 6. `processor/src/utils.rs:53` - Use Plonky3's batch_inverse

**Comment:**
> Can we re-use [plonky3's batch_inverse](https://github.com/Plonky3/Plonky3/blob/bfb90eb5efc935d5ab763f4393b340c85c567fbb/field/src/batch_inverse.rs#L21)

**Response:** NOT CHANGED.

**Reason:** Our implementation handles zeros, while Plonky3's `batch_multiplicative_inverse` explicitly panics on zeros (documented: "This will panic if any of the inputs is zero"). Neither upstream Plonky3 nor our fork provides a zero-handling variant.

**Why zeros are legitimate in our use case:**

In `processor/src/stack/trace.rs:228`, the H0 helper column stores:
```rust
stack_depth - Felt::from(MIN_STACK_DEPTH as u32)  // i.e., stack_depth - 16
```

When `stack_depth == 16` (the minimum stack depth), this value is **ZERO**. The code comment at line 206-207 explicitly confirms this design: "any ZERO in the vector will remain unchanged".

Using Plonky3's batch inversion would cause panics on valid execution traces whenever the stack is at minimum depth. Our implementation correctly handles this by leaving zeros unchanged.

---

### 7. `processor/src/errors.rs:249` - Note about panics

**Comment:**
> Just making a note, but plonky3 prover likes to panic, but we could try to return some errors in the future.

**Response:** Acknowledged. This is a note for future improvement, no immediate action required.

---

### 8. `processor/src/trace/mod.rs:378` - Remove random rows comment

**Comment:**
> Should we remove the comments in this file that say that we removed random rows?

**Response:** KEPT. The comment "Random-row padding is no longer required now that we rely on Plonky3's static degree analysis" provides useful context for anyone reviewing the code in the future, explaining why the old padding approach was changed.

---

### 9. `processor/src/trace/tests/chiplets/memory.rs:253` - Use `.double()`

**Suggestion:**
```rust
word + idx1.double() + idx0
```

**Response:** DONE. Changed `word + idx1 * Felt::from_u16(2) + idx0` to `word + idx1.double() + idx0`.

---

### 10. `processor/src/system/tests.rs:12` - Was this change necessary?

**Comment about `max_cycles = 2048`**

**Response:** YES, NECESSARY. `MIN_TRACE_LEN` is now 2048 due to Plonky3's FRI implementation requirements. Tests need to use at least this value.

---

### 11. `processor/src/stack/trace.rs:208` - Use Plonky3's `_general` inversion

**Comment:**
> I think we can still use plonky3's inversion here, but the `_general` one which would ignore zeros

**Response:** NOT CHANGED.

Plonky3's `batch_multiplicative_inverse_general` does **not** ignore zeros - it's just a more flexible version that accepts a custom inversion function, but still panics on zeros. The documentation states: "This will panic if any of the inputs is zero."

Neither upstream Plonky3 nor our fork provides any zero-handling variant. See comment #6 for details on why zeros are legitimate in our traces.

---

### 12. `processor/src/stack/tests.rs:200` - Revert?

**Code:** `let _ = stack.start_context();`

**Response:** CANNOT REVERT. `start_context()` returns `(usize, Felt)` and `Felt` has `#[must_use]`. Without `let _ =`, the compiler warns: "unused `miden_air::Felt` in tuple element 1 that must be used". This is not a Plonky3 migration change - `start_context()` already returned this tuple on the `next` branch.

---

### 13. `processor/src/stack/aux_trace.rs:110` - Simplify multiplication

**Suggestion:**
```rust
alphas[0] + alphas[1] * self.clk + alphas[2] * self.val + alphas[3] * self.prev
```

**Response:** DONE. Simplified `.mul()` calls to `*` operator.

---

### 14. `processor/src/range/aux_trace.rs:127` - Simplify multiplication

**Suggestion:**
```rust
b_range[b_range_idx] = b_range[row_idx] + value * *multiplicity;
```

**Response:** DONE. Changed `value.mul(*multiplicity)` to `*value * *multiplicity` (note: `value` is `&E`, so we need `*value`).

---

### 15. `processor/src/processor/operations/fri_ops.rs:139` - Remove parentheses

**Suggestion:**
```rust
let ev = alpha * x_inv;
```

**Response:** DONE. Removed unnecessary parentheses around `x_inv`.

---

### 16. `processor/src/processor/operations/fri_ops.rs:150` - Remove parentheses

**Suggestion:**
```rust
let tmp1 = fold2(values[1], values[3], ev * TAU_INV);
```

**Response:** DONE. Removed unnecessary parentheses around `TAU_INV`.

---

### 17. `processor/src/processor/operations/fri_ops.rs:158` - Remove parentheses

**Suggestion:**
```rust
(f_x + f_neg_x + ((f_x - f_neg_x) * ep)) * TWO_INV
```

**Response:** DONE. Simplified to `(f_x + f_neg_x + (f_x - f_neg_x) * ep) * TWO_INV`.

---

### 18. `processor/src/processor/operations/field_ops.rs:72` - Revert?

**Code:** `let _ = assert_binary(b, err_ctx)?;`

**Response:** CANNOT REVERT. `assert_binary()` returns `Result<Felt, ExecutionError>`. The `?` propagates any error, and `let _ =` is necessary to explicitly ignore the returned `Felt` value. This silences the "unused value" warning that `#[must_use]` would trigger.

---

### 19. `processor/src/parallel/core_trace_fragment/mod.rs:325` - Revert?

**Code:** `let _ = self.context.state.stack.start_context();`

**Response:** CANNOT REVERT. Same as comment #12 - `Felt` has `#[must_use]`, so `let _ =` is required to silence the compiler warning.

---

### 20. `prover/src/trace_adapter.rs:36` - Use `extend_from_slice`

**Suggestion:**
```rust
col_major_data.extend_from_slice(trace.main_trace.get_column(col_idx));
```

**Response:** DONE. Replaced `extend(column.iter().cloned())` with `extend_from_slice(column)`.

---

### 21. `prover/src/trace_adapter.rs:41` - Use Plonky3's transpose

**Suggestion:**
```rust
let col_major_matrix = RowMajorMatrix::new(col_major_data, trace_len);
col_major_matrix.transpose()
```

**Response:** DONE. Rewrote both `execution_trace_to_row_major` and `aux_trace_to_row_major` to use Plonky3's optimized `transpose()` method.

---

### 22. `prover/src/trace_adapter.rs:69` - Apply same as above

**Response:** DONE. Applied the same transpose pattern to `aux_trace_to_row_major`.

---

### 23. `prover/src/public_inputs.rs:40` - Inline method

**Comment:**
> Is this method necessary? It seems like it could be inlined

**Response:** DONE. Removed entirely - see #24.

---

### 24. `prover/src/public_inputs.rs:64` - Move to ExecutionTrace

**Comment:**
> This could be a method on ExecutionTrace

**Response:** DONE. Added `ExecutionTrace::to_public_values()` method in `processor/src/trace/mod.rs`. Removed `prover/src/public_inputs.rs` entirely - the module is no longer needed.

---

### 25. `prover/src/lib.rs:80` - Panic question

**Comment:**
> Should we just panic here?

**Response:** DONE. Changed `HashFunction::Blake3_192` to panic with "Blake3_192 is not yet supported" instead of silently using Blake3_256 config.

---

### 26. Snapshot trace length (64 -> 2048)

**Comment:**
> Trace length goes from 64 to 2048; is this because Plonky3 requires a trace length minimum of 2048?

**Response from PR:** "Indeed, the minimal trace length has changed to 2048. This is due to some short-comings of the current FRI implementation, which should hopefully be resolved soon."

---

### 27. `air/src/trace/chiplets/hasher.rs:121` - Revert `#[allow]` to `#[expect]`

**Comment:**
> revert

**Response:** DONE. Reverted `#[allow(clippy::identity_op)]` back to `#[expect(clippy::identity_op)]`.

---

### 28. `air/src/lib.rs:61` - Restore doc comment on `PublicInputs::new()`

**Comment:**
> revert?

**Response:** DONE. Restored the doc comment for `PublicInputs::new()`.

---

### 29. `air/src/proof.rs:19-20` - Restore derives and remove unnecessary serde bound

**Comment:**
> Do we need this? And should re keep the old derives

**Response:** DONE.
- Restored the old derives (`Debug, Clone, PartialEq, Eq`) on `ExecutionProof`
- Removed unnecessary `#[serde(bound = "")]` from both `ExecutionProof` and `HashFunction` (neither has generic type parameters)

---

### 30. `air/Cargo.toml:40` - Make `p3-dft/parallel` feature conditional

**Comment:**
> Same comment about the feature being tied to maybe-rayon

**Response:** DONE.
- Added `concurrent` feature to `miden-air` that enables `p3-maybe-rayon/parallel` and `p3-dft/parallel`
- Removed unconditional `features = ["parallel"]` from `p3-dft`
- Added `p3-maybe-rayon` as a dependency

---

### 31. `air/README.md:7` - Restore AIR component documentation

**Comment:**
> Should we revert ?

**Response:** DONE. Restored the removed documentation bullet points for decoder and stack AIR components.

---

### 32. `core/benches/mast_forest_merge.rs:44` - Restore explicit MastForestParams fields

**Comment:**
> Revert?

**Response:** DONE. Restored the explicit field values instead of `..Default::default()`. Now matches `next` branch exactly.

---

### 33. Remove `felt_from_u64_checked` - Use Plonky3's `from_canonical_checked`

**Comment:**
> We don't need `felt_from_u64_checked` because of Plonky3's `QuotientMap::from_canonical_checked`

**Response:** DONE.
- Removed `felt_from_u64_checked` function from `core/src/lib.rs`
- Updated `core/src/stack/inputs.rs` to use `Felt::from_canonical_checked()` directly
- Updated `miden-vm/src/internal.rs` to use `Felt::from_canonical_checked()` directly
- Added `QuotientMap` re-export to `miden-crypto` (pushed to `al-e2e-plonky3` branch)
- Added `QuotientMap` re-export to `miden-core`

---

### 34. `core/src/stack/outputs.rs:71` - Restore doc comment for `get_stack_word_be`

**Comment:**
> Revert

**Response:** DONE. Restored the original doc comment for `get_stack_word_be`.

---

## Summary of Actions

| Category | Count |
|----------|-------|
| DONE | 22 |
| NOT CHANGED (with justification) | 3 |
| CANNOT REVERT (necessary API changes) | 4 |
| ACKNOWLEDGED (no action needed) | 1 |

### Files Modified

- `prover/Cargo.toml` - Added `p3-maybe-rayon/parallel` to concurrent feature
- `prover/src/lib.rs` - Use `trace.to_public_values()` directly, removed public_inputs module
- `prover/src/public_inputs.rs` - **DELETED** (moved to ExecutionTrace)
- `prover/src/trace_adapter.rs` - Use Plonky3's transpose
- `prover/tests/integration_test.rs` - Use `trace.to_public_values()`
- `processor/src/trace/mod.rs` - Added `to_public_values()` method, simplified comment
- `processor/src/trace/tests/chiplets/memory.rs` - Use `.double()`
- `processor/src/stack/aux_trace.rs` - Simplify multiplication
- `processor/src/range/aux_trace.rs` - Simplify multiplication
- `processor/src/processor/operations/fri_ops.rs` - Remove unnecessary parentheses
- `verifier/src/lib.rs` - Minimized migration changes
- `air/src/trace/chiplets/hasher.rs` - Reverted `#[allow]` to `#[expect]`
- `air/src/lib.rs` - Restored doc comment on `PublicInputs::new()`
- `air/src/proof.rs` - Restored derives on `ExecutionProof`, removed unnecessary `#[serde(bound = "")]`
- `air/Cargo.toml` - Added `concurrent` feature, made `p3-dft/parallel` conditional
- `air/README.md` - Restored AIR component documentation (decoder, stack)
- `core/benches/mast_forest_merge.rs` - Restored explicit MastForestParams fields
- `core/src/lib.rs` - Removed `felt_from_u64_checked`, added `QuotientMap` re-export
- `core/src/stack/inputs.rs` - Use `Felt::from_canonical_checked()` directly
- `miden-vm/src/internal.rs` - Use `Felt::from_canonical_checked()` directly
- `core/src/stack/outputs.rs` - Restored doc comment for `get_stack_word_be`
