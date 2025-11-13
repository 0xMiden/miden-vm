# PR Review: Error Handling Refactor

**Branch**: `adr1anh/errctx-next` vs `next`
**Date**: 2025-11-10
**Changes**: 69 files, 1,686 additions, 1,737 deletions

---

## Executive Summary

This PR implements a **two-tier error boundary pattern** that separates:
- **What went wrong** (OperationError - context-free logic errors)
- **Where it went wrong** (ExecutionError - diagnostic source context)

**Overall Assessment**: ✅ Architecture is excellent, implementation is solid, but test ergonomics need improvement.

---

## Architecture Review

### The Two-Tier Pattern

```rust
// Inner: Context-free logical errors
pub enum OperationError {
    DivideByZero,
    FailedAssertion { err_code: Felt, err_msg: Option<Arc<str>> },
    NotU32Values { values: Vec<Felt>, err_code: Felt },
    MemoryError(MemoryError),
    // ... 20+ variants
}

// Outer: User-facing with diagnostics
pub enum ExecutionError {
    // With source context
    OperationError {
        clk: RowIndex,
        label: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        err: Box<OperationError>,
    },
    // Without source context (external loads, etc)
    OperationErrorNoContext {
        clk: RowIndex,
        err: Box<OperationError>,
    },
    // Program-level errors
    CycleLimitExceeded(u32),
    DuplicateEventHandler(EventName),
    // ...
}
```

### Error Context System

**Boundary Pattern**:
```rust
// Create context at boundary
let err_ctx = err_ctx!(program, node, host, self.clk());

// Wrap errors when crossing boundary
some_operation()
    .map_exec_err(&err_ctx)?
```

**ResultOpErrExt Trait**:
```rust
pub trait ResultOpErrExt<T> {
    fn map_exec_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError>;
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError>;
}
```

✅ **Strengths**:
- Clean separation of concerns
- Operations are truly context-free
- Consistent pattern applied across all boundaries
- Feature flag ready (`no_err_ctx`)
- No loss of diagnostic information

---

## Critical Analysis

### 1. Test Matching Verbosity ⚠️

**Problem**: Tests became significantly more verbose

**Before** (1 line):
```rust
ExecutionError::DivideByZero { clk, .. } if clk == RowIndex::from(6)
```

**After** (3+ lines):
```rust
ExecutionError::OperationError { clk, ref err, .. }
| ExecutionError::OperationErrorNoContext { clk, ref err, .. }
    if clk == RowIndex::from(6)
    && matches!(err.as_ref(), OperationError::DivideByZero)
```

**Impact**:
- Every test that checks errors needs this verbose pattern
- Copy-paste errors more likely
- Harder to read and maintain

**Root Cause**: Must match both `OperationError` (with context) and `OperationErrorNoContext` variants.

### 2. Lost Test Coverage for Error Fields ⚠️

**Problem**: Tests stopped checking specific error fields

**Example** - FailedAssertion:
```rust
// Before: Direct field access
ExecutionError::FailedAssertion { clk, err_code, err_msg, .. }
    if clk == RowIndex::from(21)
    && err_code == ZERO
    && err_msg.is_none()

// After: Only checks clock, ignores err_code and err_msg
ExecutionError::OperationError { clk, ref err, .. }
| ExecutionError::OperationErrorNoContext { clk, ref err, .. }
    if clk == RowIndex::from(21)
    && matches!(err.as_ref(), OperationError::FailedAssertion { .. })
```

**Impact**: Tests are weaker - don't verify error details beyond variant type.

**Solution**: Use nested patterns to check fields:
```rust
if clk == RowIndex::from(21)
    && matches!(err.as_ref(), OperationError::FailedAssertion { err_code, err_msg }
        if *err_code == ZERO && err_msg.is_none())
```

### 3. No Test Coverage for Source Location 📝

**Observation**: Integration tests don't check `label` or `source_file` fields anymore.

**Old tests checked**:
- `clk` ✅ Still checked
- `label` ❌ Not checked anymore
- `source_file` ❌ Not checked anymore

**New unit tests added** in `processor/src/tests/mod.rs`:
- Test missing source scenarios
- Test `OperationErrorNoContext` variant
- Good coverage for the "no context available" path

**Gap**: No integration tests verify that source location is correctly attached when available.

### 4. MemoryError Simplification ✅

**Excellent change** - removed embedded source context:

**Before**:
```rust
pub enum MemoryError {
    AddressOutOfBounds {
        label: SourceSpan,
        source_file: Option<Arc<SourceFile>>,
        addr: u64,
    },
    // ...
}
```

**After**:
```rust
pub enum MemoryError {
    AddressOutOfBounds { addr: u64 },
    // ...
}
```

Context is now added at the boundary, not embedded in the error. This is the right pattern.

---

## Decoder Changes Review

**File**: `processor/src/decoder/mod.rs`
**Changes**: 54 additions, 44 deletions

### Pattern Applied Consistently ✅

All boundary methods now:
1. Take `err_ctx: &impl ErrorContext` parameter
2. Use `.map_exec_err(&err_ctx)` to wrap errors
3. Convert `MastNodeNotFoundInForest` from ExecutionError to OperationError

**Example**:
```rust
// start_join_node, start_split_node, start_loop_node, etc:
pub fn start_join_node(
    &mut self,
    node_id: MastNodeId,
    program: &MastForest,
    err_ctx: &impl ErrorContext,  // NEW
) -> Result<(), ExecutionError> {
    let join_node = program
        .get_node_by_id(node_id)
        .ok_or(OperationError::MastNodeNotFoundInForest(node_id))
        .map_exec_err(err_ctx)?;  // NEW: wrap at boundary
    // ...
}
```

### Special Cases Handled Correctly ✅

**Stack depth validation** for call/dyncall:
```rust
let expected_depth = stack.depth();
if actual_depth != expected_depth {
    return Err(OperationError::InvalidStackDepthOnReturn {
        expected: expected_depth,
        actual: actual_depth,
    })
    .map_exec_err(err_ctx);
}
```

This is correct - it's a boundary validation, not an operation error.

**Loop condition errors** - creates fresh context for each iteration:
```rust
// In execute_loop_node:
let err_ctx = err_ctx!(program, loop_node, host, self.system.clk());
self.decoder.start_loop_body()?;
```

✅ **Assessment**: Decoder changes are well-designed and consistent.

---

## Simplification Opportunities

### 1. Test Helper Functions (HIGH PRIORITY)

**Add to `processor/src/tests/mod.rs`**:

```rust
/// Assert that result is an operation error at expected clock with specific check
pub fn assert_operation_error_at<F>(
    result: Result<StackOutputs, ExecutionError>,
    expected_clk: RowIndex,
    check: F,
) where
    F: FnOnce(&OperationError) -> bool,
{
    let err = result.expect_err("expected error");
    match err {
        ExecutionError::OperationError { clk, err, .. }
        | ExecutionError::OperationErrorNoContext { clk, err, .. } => {
            assert_eq!(clk, expected_clk, "unexpected clock cycle");
            assert!(check(err.as_ref()), "operation error check failed: {:?}", err);
        }
        other => panic!("expected operation error, got {:?}", other),
    }
}

/// Common error type assertions
pub fn assert_divide_by_zero(result: Result<_, ExecutionError>, clk: RowIndex) {
    assert_operation_error_at(result, clk, |err| {
        matches!(err, OperationError::DivideByZero)
    });
}

pub fn assert_not_u32_values(
    result: Result<_, ExecutionError>,
    clk: RowIndex,
    expected_values: Vec<Felt>,
    expected_err_code: Felt,
) {
    assert_operation_error_at(result, clk, |err| {
        matches!(err, OperationError::NotU32Values { values, err_code }
            if *values == expected_values && *err_code == expected_err_code)
    });
}

pub fn assert_failed_assertion(
    result: Result<_, ExecutionError>,
    clk: RowIndex,
    expected_err_code: Felt,
    expected_err_msg: Option<&str>,
) {
    assert_operation_error_at(result, clk, |err| {
        matches!(err, OperationError::FailedAssertion { err_code, err_msg }
            if *err_code == expected_err_code
            && err_msg.as_ref().map(|s| s.as_ref()) == expected_err_msg)
    });
}
```

**Benefits**:
- Reduces 3-line pattern to 1-line function call
- Ensures consistent checking
- Easier to add more checks (like verifying all fields)
- Clear intent

**Usage**:
```rust
expect_op_error_matches!(
    test.run(),
    clk = RowIndex::from(6),
    OperationError::DivideByZero
);
```

### 2. ExecutionError Helper Methods (MEDIUM PRIORITY)

**Add to `processor/src/errors.rs`**:

```rust
impl ExecutionError {
    /// Returns the operation error and clock cycle if this is an operation error
    pub fn operation_error(&self) -> Option<(RowIndex, &OperationError)> {
        match self {
            ExecutionError::OperationError { clk, err, .. }
            | ExecutionError::OperationErrorNoContext { clk, err, .. } =>
                Some((*clk, err.as_ref())),
            _ => None,
        }
    }

    /// Returns true if this is a specific operation error type
    pub fn is_operation_error<F>(&self, check: F) -> bool
    where
        F: FnOnce(&OperationError) -> bool,
    {
        self.operation_error().map_or(false, |(_, err)| check(err))
    }

    /// Returns the clock cycle for any error type that has one
    pub fn clock(&self) -> Option<RowIndex> {
        match self {
            ExecutionError::OperationError { clk, .. }
            | ExecutionError::OperationErrorNoContext { clk, .. }
            | ExecutionError::FailedToParseAdviceMap { clk, .. }
            | ExecutionError::FailedToLoadProgram { clk, .. } => Some(*clk),
            _ => None,
        }
    }
}
```

**Benefits**:
- Makes it easier to inspect errors
- Centralizes the "match both variants" pattern
- Can be used in both tests and user code

### 3. Macro Improvements (LOW PRIORITY)

**Option**: Create specialized macro for operation errors:

```rust
macro_rules! assert_op_error {
    ($result:expr, $clk:expr, $err_pattern:pat $(if $guard:expr)?) => {
        match $result.expect_err("expected error") {
            ExecutionError::OperationError { clk, ref err, .. }
            | ExecutionError::OperationErrorNoContext { clk, ref err, .. }
                if clk == $clk && matches!(err.as_ref(), $err_pattern $(if $guard)?) => {},
            other => panic!("unexpected error: {:?}", other),
        }
    };
}
```

**Assessment**: Helper functions are better - more flexible and type-safe.

---

## Test Coverage Audit

### What Tests Check Now

✅ **Clock cycle** - all tests verify `clk` field
✅ **Error variant** - all tests check the OperationError variant
⚠️ **Error fields** - only some tests check specific error fields (err_code, err_msg, values, etc)
❌ **Source location** - no integration tests verify `label` or `source_file`

### Examples of Weak Tests

**Example 1** - Only checks variant:
```rust
// From stdlib/tests/crypto/falcon.rs
if clk == RowIndex::from(3202)
    && matches!(err.as_ref(), OperationError::FailedAssertion { .. })
    //                                                          ^^^^
    //                                                     Should check err_code and err_msg!
```

**Example 2** - Only checks variant:
```rust
// From miden-vm/tests/integration/operations/io_ops/adv_ops.rs
if clk == RowIndex::from(6)
    && matches!(err.as_ref(), OperationError::AdviceError(AdviceError::StackReadFailed))
    // Good! This one is complete - StackReadFailed has no fields
```

### Recommendation: Strengthen Tests

For each test, verify ALL relevant fields:
- `FailedAssertion` → check `err_code` and `err_msg`
- `NotU32Values` → check `values` (length at minimum) and `err_code`
- `MemoryError` → check specific variant and its fields
- etc.

---

## Diagnostic Information Audit

### ✅ No Information Lost

All diagnostic information is preserved, just structured differently:

**Before**: Embedded in error variants
```rust
ExecutionError::DivideByZero {
    clk: RowIndex,
    label: SourceSpan,
    source_file: Option<Arc<SourceFile>>,
}
```

**After**: Wrapped at boundaries
```rust
ExecutionError::OperationError {
    clk: RowIndex,
    label: SourceSpan,
    source_file: Option<Arc<SourceFile>>,
    err: Box<OperationError>,  // Contains DivideByZero
}
```

**Information preserved**:
- ✅ Clock cycle: In ExecutionError variants
- ✅ Source location: In `OperationError` variant (when available)
- ✅ Error details: In boxed OperationError
- ✅ Help text: Via `#[diagnostic(help(...))]` attributes
- ✅ Error chains: Via `#[source]` attribute on boxed error

### Improvement: Better Error Messages

The refactor actually **improves** diagnostics:

1. **Clear error chains**: Using `#[source]` attribute properly
2. **Helpful messages**: Good use of `#[diagnostic(help(...))]`
3. **Distinction**: Clear difference between "no context available" vs "error occurred"

---

## Specific File Changes

### processor/src/errors.rs
**Lines**: 324 added, 397 deleted
**Assessment**: ✅ Well-structured, good use of error handling patterns

**Key improvements**:
- Cleaner enum definitions
- Better `Display` implementations
- Proper use of `#[source]` and `#[diagnostic]` attributes

### processor/src/lib.rs
**Lines**: 92 added, 69 deleted
**Assessment**: ✅ Consistent application of boundary pattern

**Pattern**:
```rust
// Create context once at boundary
let err_ctx = err_ctx!(program, node, host, self.system.clk());

// Use context for all operations in scope
self.decoder.start_join_node(node_id, program, &err_ctx)?;
```

### processor/src/fast/memory.rs
**Lines**: 19 added, 51 deleted
**Assessment**: ✅ Significant simplification

**Before**: Complex error wrapping inline
**After**: Clean boundary wrapping with `.map_exec_err(&err_ctx)`

### processor/src/chiplets/memory/errors.rs
**Lines**: 16 added, 55 deleted
**Assessment**: ✅ Excellent simplification

Removed embedded source context from MemoryError variants. This is the correct pattern.

### processor/src/tests/mod.rs
**Lines**: 291 added, 60 deleted
**Assessment**: ✅ Good coverage of edge cases

**New tests**:
- `test_missing_source_span_in_memory_read_ops`
- `test_missing_source_span_in_div`
- `test_missing_source_span_in_not_u32_value`
- `test_missing_source_span_in_mem_storew_invalid_alignment`

These verify the `OperationErrorNoContext` path works correctly.

---

## Issues Found

### 1. Test Verbosity (HIGH)
**Issue**: Every test matching operation errors requires 3+ lines
**Impact**: Maintenance burden, readability
**Fix**: Add helper functions (see "Simplification Opportunities")

### 2. Weak Test Coverage (MEDIUM)
**Issue**: Tests only check error variant, not fields
**Impact**: Missing bugs in error field values
**Fix**: Audit tests and add field checks, use helper functions that enforce checking

### 3. No Source Location Tests (LOW)
**Issue**: No integration tests verify `label`/`source_file` attachment
**Impact**: Could break source location attachment without detection
**Fix**: Add integration tests that verify source context when available

### 4. Inconsistent Field Checking (LOW)
**Issue**: Some tests check all fields, some don't
**Impact**: Inconsistent test quality
**Fix**: Establish convention - helper functions enforce it

---

## Recommendations

### Immediate (Block Merge)
1. ✅ **Architecture** - No changes needed
2. ✅ **Decoder** - No changes needed
3. ✅ **Error definitions** - No changes needed

### High Priority (Before Merge)
1. **Add test helper functions** (1-2 hours)
   - `assert_operation_error_at`
   - `assert_divide_by_zero`
   - `assert_failed_assertion`
   - `assert_not_u32_values`
   - More as needed

2. **Add ExecutionError helper methods** (30 minutes)
   - `operation_error()` method
   - `is_operation_error()` method
   - `clock()` method

3. **Strengthen weak tests** (2-3 hours)
   - Audit all tests for field checking
   - Add nested `matches!` patterns for error fields
   - Focus on `FailedAssertion` and `NotU32Values` tests

### Medium Priority (Follow-up PR)
1. **Add source location integration tests** (1-2 hours)
2. **Create testing guide** documenting error assertion patterns (1 hour)
3. **Refactor tests to use helper functions** across all test files (3-4 hours)

### Low Priority (Future)
1. Consider extracting error context creation into helper methods on Processor
2. Document the two-tier pattern in design docs

---

## Conclusion

**Overall**: ✅ Excellent refactor with minor test ergonomics issues

**Architecture**: 10/10 - Clean, consistent, well-designed
**Implementation**: 9/10 - Thorough and correct
**Tests**: 7/10 - Functional but verbose, some gaps in field checking
**Documentation**: 8/10 - Good inline docs, could use design doc

**Recommend**:
- Add helper functions (high priority)
- Strengthen test assertions (high priority)
- Then merge

**No concerns about**:
- Diagnostic information loss (none)
- Error context handling (well-designed)
- Decoder changes (appropriate)
- Backwards compatibility (not a concern per user)

The refactor significantly improves the error handling architecture. With the recommended test improvements, this will be production-ready.


Here is Claude's plan:
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
Refactoring Opportunities Plan

Summary of Analysis

Analyzed 69 files with 2037 insertions and 1788 deletions against next. The recent error handling overhaul
was very successful, creating a solid foundation for incremental improvements.

High-Priority Refactorings (Performance & Code Quality)

1. Box Large Error Variant - MerklePathVerificationFailed

Impact: Reduces OperationError enum size significantly
- Current size: ~80+ bytes (Word + Felt + Word + Felt + Option<Arc>)
- Location: processor/src/errors.rs:203-218
- Benefits: Smaller stack frames, better cache locality

2. Optimize require_u32_operands! Macro

Impact: Removes allocation from hot path
- Current: Allocates Vec on success path
- Location: processor/src/operations/u32_ops.rs:13-34
- Solution: Check validity first, allocate only on error path
- Alternative: Use SmallVec<[Felt; 4]> for stack allocation

3. Extract Duplicated Macro

Impact: Eliminates code duplication
- require_u32_operands! exists in BOTH slow and fast processor
- Locations: operations/u32_ops.rs:13-35 AND processor/operations/u32_ops.rs:16-33
- Solution: Move to operations/utils.rs (currently only 13 lines)

Medium-Priority Refactorings (API Ergonomics)

4. Create SubsystemErrorExt Trait

Impact: Reduces boilerplate in 50+ call sites
- Pattern: Repeated .map_err(OperationError::MemoryError)?
- Solution: Add .map_memory_err(), .map_advice_err() helper methods
- Similar to existing ResultOpErrExt pattern

5. Add Binary Validation Helpers

Impact: Reduces repetitive validation code
- Pattern: Repeated assert_binary(stack.get(0)), assert_binary(stack.get(1))
- Solution: assert_binary_pair(), assert_binary_triple() helpers

Low-Priority Improvements

6. Selective Inlining

Impact: Potential performance gains (needs profiling)
- Candidates: assert_binary(), small error construction helpers
- Action: Profile first, add #[inline(always)] where beneficial

7. Documentation & Best Practices

Impact: Guides future development
- Document error wrapping patterns for new subsystems
- Add lint recommendations for .map_exec_err_with_host() preference

Recommendation

Start with items 1-3 (High Priority) as they have clear benefits with low risk. These are natural
follow-ups to the completed error handling overhaul.
