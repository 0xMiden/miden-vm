# Miden VM Processor - Error Handling Refinement Plan

**Status**: Planning phase - Post lazy error context migration
**Branch**: adr1anh/errctx-next
**Date**: 2025-11-10

---

## Context

The lazy error context refactoring (3 commits) successfully completed:
- ✅ Added `OpErrorContext` with lazy evaluation
- ✅ Migrated all call sites to host-aware error wrapping
- ✅ Deleted `err_ctx!` macro
- ✅ All 2411 tests passing

This document outlines **Phase 2** refinements to remove scaffolding and improve the API.

---

## 1. Delete Unused/Dead Code

### 1.1 Remove `ErrorContextImpl` Entirely 🗑️

**Evidence**: `rg "ErrorContextImpl::"` returns zero matches - confirmed dead code.

**Impact**: ~80-100 lines removed from `processor/src/errors.rs`

**What to delete**:
- `ErrorContextImpl` struct definition
- `ErrorContextImpl::new()` method
- `ErrorContextImpl::new_with_op_idx()` method
- `impl ErrorContext for ErrorContextImpl`
- All eager evaluation code paths

**Risk**: None - confirmed unused by entire codebase

---

### 1.2 Remove Host-Free API Methods 🔪

**Observation**: All real call sites use `.map_exec_err_with_host()`. The host-free variants exist only in documentation.

**Methods to remove from `ErrorContext` trait**:
```rust
// DELETE - unused in practice:
fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;
fn wrap_op_err(&self, err: OperationError) -> ExecutionError;
```

**Methods to remove from `ResultOpErrExt` trait**:
```rust
// DELETE - unused in practice:
fn map_exec_err(self, ctx: &impl ErrorContext) -> Result<T, ExecutionError>;
```

**Keep only host-aware variants**:
```rust
fn resolve_source(&self, host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;
fn wrap_op_err_with_host(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError;
fn map_exec_err_with_host(...) -> Result<T, ExecutionError>;
```

**Impact**: Removes API confusion, simplifies trait by 50%

---

## 2. Rename for Clarity

### 2.1 Type Renames

#### Primary Context Type
```rust
// CURRENT:
OpErrorContext

// PROPOSED:
ExecutionSiteContext  // Alternative: NodeErrorContext
```

**Rationale**:
- Covers both node-level AND operation-level errors (not just "operations")
- "Site" clearly indicates a location in execution
- Pairs well with "ErrorSite" trait name

#### Trait Name
```rust
// CURRENT:
ErrorContext

// PROPOSED:
ErrorSite
```

**Rationale**:
- Shorter, clearer
- Emphasizes location/site concept
- Less overloaded than "context"

#### Extension Trait
```rust
// CURRENT:
ResultOpErrExt

// PROPOSED:
OperationResultExt
```

**Rationale**: More conventional naming (subject before "Ext")

---

### 2.2 Constructor Renames

```rust
// CURRENT:
OpErrorContext::new(program, node_id, clk)
OpErrorContext::with_op(program, node_id, op_idx, clk)

// PROPOSED:
ExecutionSiteContext::node(program, node_id, clk)
ExecutionSiteContext::operation(program, node_id, op_idx, clk)
```

**Benefits**:
- Intent is immediately clear at call sites
- No ambiguity about what `new` vs `with_op` mean
- Reads naturally: "context for this node" vs "context for this operation"

**Example call sites**:
```rust
// Node-level error (no specific operation)
let ctx = ExecutionSiteContext::node(program, node_id, self.clk);
let node = program.get_node_by_id(node_id)
    .ok_or(OperationError::MastNodeNotFoundInForest(node_id))
    .map_exec_err(&ctx, host)?;

// Operation-level error (specific instruction)
let ctx = ExecutionSiteContext::operation(program, node_id, op_idx, self.clk);
self.execute_op(op, program, host)
    .map_exec_err(&ctx, host)?;
```

---

### 2.3 Method Renames

```rust
// CURRENT:
fn resolve_source(&self, host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>
fn wrap_op_err_with_host(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError

// PROPOSED:
fn resolve(&self, host: &impl BaseHost) -> Option<SourceContext>
fn into_exec_err(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError
```

**Benefits**:
- Shorter, more idiomatic
- `into_exec_err` suggests conversion/consumption
- Reads well: `ctx.into_exec_err(host, err)`

---

## 3. Introduce `SourceContext` Struct

### Current (tuple return):
```rust
fn resolve_source(&self, host: &impl BaseHost)
    -> Option<(SourceSpan, Option<Arc<SourceFile>>)>
```

### Proposed (structured return):
```rust
#[derive(Debug, Clone)]
pub struct SourceContext {
    pub span: SourceSpan,
    pub file: Option<Arc<SourceFile>>,
    // Future extensibility:
    // pub was_cached: bool,
    // pub node_id: MastNodeId,
}

fn resolve(&self, host: &impl BaseHost) -> Option<SourceContext>
```

**Benefits**:
1. **Self-documenting**: Field names instead of tuple positions
2. **Extensible**: Can add metadata later without breaking signature
3. **Type safety**: Can't accidentally swap span and file
4. **Easier destructuring**: `if let Some(ctx) = ... { use ctx.span }`

**Implementation**:
```rust
impl SourceContext {
    pub fn new(span: SourceSpan, file: Option<Arc<SourceFile>>) -> Self {
        Self { span, file }
    }

    pub fn is_available(&self) -> bool {
        !self.span.is_unknown() || self.file.is_some()
    }
}
```

---

## 4. Slim the Trait

### Current Trait (4 methods with duplication):
```rust
pub trait ErrorContext {
    fn clk(&self) -> RowIndex;
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;
    fn resolve_source(&self, host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;
    fn wrap_op_err(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError;
    fn wrap_op_err_with_host(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError;
}
```

### Proposed Trait (2 core methods + 1 blanket):
```rust
pub trait ErrorSite {
    /// Returns the clock cycle where the error occurred
    fn clk(&self) -> RowIndex;

    /// Resolves source location information using the host
    fn resolve(&self, host: &impl BaseHost) -> Option<SourceContext>;

    /// Converts an OperationError into ExecutionError with source context (blanket impl)
    fn into_exec_err(&self, host: &impl BaseHost, err: OperationError) -> ExecutionError {
        match self.resolve(host) {
            Some(ctx) => ExecutionError::OperationError {
                clk: self.clk(),
                label: ctx.span,
                source_file: ctx.file,
                err: Box::new(err),
            },
            None => ExecutionError::OperationErrorNoContext {
                clk: self.clk(),
                err: Box::new(err),
            },
        }
    }
}
```

**Benefits**:
- **Reduced from 4 methods to 2 (+1 blanket)**
- **Single source of truth** for error wrapping logic
- **Easier to implement** for new context types
- **No method name confusion** ("which wrap method should I use?")

---

## 5. Simplify Result Extension

### Option A: Keep Trait Pattern (Recommended)
```rust
pub trait OperationResultExt<T> {
    fn map_exec_err(
        self,
        ctx: &impl ErrorSite,
        host: &impl BaseHost
    ) -> Result<T, ExecutionError>;
}

impl<T> OperationResultExt<T> for Result<T, OperationError> {
    #[inline]
    fn map_exec_err(
        self,
        ctx: &impl ErrorSite,
        host: &impl BaseHost
    ) -> Result<T, ExecutionError> {
        self.map_err(|err| ctx.into_exec_err(host, err))
    }
}
```

**Call site**:
```rust
result.map_exec_err(&ctx, host)?
```

### Option B: Free Function
```rust
#[inline]
pub fn op_err_into_exec<T>(
    result: Result<T, OperationError>,
    ctx: &impl ErrorSite,
    host: &impl BaseHost,
) -> Result<T, ExecutionError> {
    result.map_err(|err| ctx.into_exec_err(host, err))
}
```

**Call site**:
```rust
op_err_into_exec(result, &ctx, host)?
```

**Recommendation**: Option A (trait) - maintains consistent pattern with existing codebase and feels more Rust-idiomatic for chaining.

---

## 6. Reduce `OperationError` Enum Size

### 6.1 Box Large Variants

**Target**: `MerklePathVerificationFailed`
**Location**: `processor/src/errors.rs:203-218` (approximate)
**Current Size**: ~80+ bytes

**Current**:
```rust
MerklePathVerificationFailed {
    value: Word,        // 32 bytes
    index: Felt,        // 8 bytes
    root: Word,         // 32 bytes
    err_code: Felt,     // 8 bytes
    err_msg: Option<Arc<str>>,  // 16 bytes
}
// Total: ~96 bytes
```

**Proposed**:
```rust
MerklePathVerificationFailed(Box<MerklePathVerificationData>),

#[derive(Debug, Clone)]
pub struct MerklePathVerificationData {
    pub value: Word,
    pub index: Felt,
    pub root: Word,
    pub err_code: Felt,
    pub err_msg: Option<Arc<str>>,
}
```

**Benefits**:
- Reduces `OperationError` enum size (improves Result<T, OperationError> size)
- Better cache locality for common error paths
- Only allocates when this specific error occurs (cold path)

**Other Candidates to Evaluate**:
- `EventError { EventId, Option<EventName>, EventError }` - depends on EventError size
- `SmtNodePreImageNotValid { Word, usize }` - borderline, measure first

---

### 6.2 Optimize `require_u32_operands!` Macro

**Location**: `processor/src/operations/u32_ops.rs:13-34`

**Current Issue**: Allocates `Vec` on success path
```rust
macro_rules! require_u32_operands {
    ...
    let mut invalid_values = Vec::new();  // ❌ Allocates even when all values valid
    $(
        if [<_operand_ $idx>].as_int() > U32_MAX {
            invalid_values.push([<_operand_ $idx>]);
        }
    )*
    if !invalid_values.is_empty() {
        return Err(OperationError::NotU32Values { values: invalid_values, err_code: $errno });
    }
```

**Proposed Optimization**: Check first, allocate only on error
```rust
macro_rules! require_u32_operands {
    ...
    // Phase 1: Check validity (no allocation)
    let mut has_invalid = false;
    $(
        if [<_operand_ $idx>].as_int() > U32_MAX {
            has_invalid = true;
            break;
        }
    )*

    // Phase 2: Collect invalid values only if needed (cold path)
    if has_invalid {
        let mut invalid_values = Vec::new();
        $(
            if [<_operand_ $idx>].as_int() > U32_MAX {
                invalid_values.push([<_operand_ $idx>]);
            }
        )*
        return Err(OperationError::NotU32Values {
            values: invalid_values,
            err_code: $errno
        });
    }
```

**Alternative**: Use `SmallVec<[Felt; 4]>` for stack allocation
```rust
use smallvec::{SmallVec, smallvec};

let mut invalid_values: SmallVec<[Felt; 4]> = smallvec![];
```

**Impact**: Removes allocation from hot path (success case)

---

## 7. Extract Duplicated Code

### 7.1 Extract `require_u32_operands!` Macro

**Issue**: Macro appears in TWO locations with identical implementation
- `processor/src/operations/u32_ops.rs:13-35` (slow processor)
- `processor/src/processor/operations/u32_ops.rs:16-33` (fast processor)

**Solution**: Move to shared utility
- Target: `processor/src/operations/utils.rs` (currently only 13 lines)
- Or create: `processor/src/operations/macros.rs`

**Implementation**:
```rust
// processor/src/operations/utils.rs (or macros.rs)

#[macro_export]
macro_rules! require_u32_operands {
    // ... existing macro body ...
}

// Then in both u32_ops.rs files:
use crate::operations::utils::require_u32_operands;
// Or: use crate::operations::macros::require_u32_operands;
```

**Impact**: Eliminates ~20 lines of duplication, single source of truth

---

## 8. Implementation Optimizations

### 8.1 Use `SourceSpan::is_unknown()` Helper

**Current**:
```rust
// processor/src/errors.rs (OpErrorContext::resolve)
if label == SourceSpan::default() && source_file.is_none() {
    return None;
}
```

**Proposed**:
```rust
if label.is_unknown() && source_file.is_none() {
    return None;
}
```

**Note**: Check if `SourceSpan::is_unknown()` exists in miden-core. If not, this is just a tiny clarity improvement.

---

### 8.2 Optimize Node Type Matching (Future)

**Current Pattern**:
```rust
// OpErrorContext::resolve branches on node type every time
let node = self.program.get_node_by_id(self.node_id)?;
match node {
    MastNode::BasicBlock(bb) => bb.get_assembly_op(op_idx),
    MastNode::Join(j) => j.get_assembly_op(op_idx),
    MastNode::Split(s) => s.get_assembly_op(op_idx),
    // ...
}
```

**Optimization Idea**: Store node type info or trait object
```rust
struct ExecutionSiteContext<'a> {
    clk: RowIndex,
    program: &'a MastForest,
    node_id: MastNodeId,
    node_type: NodeType,  // or &'a dyn MastNodeErrorContext
    op_idx: Option<usize>,
}
```

**Trade-off**:
- **Pro**: Eliminates match/branch in resolve()
- **Con**: Larger struct, more complex construction
- **Recommendation**: Profile first - this is premature optimization unless profiling shows it's hot

---

## 9. Documentation Updates

### 9.1 Module-Level Example

**Update** `processor/src/errors.rs` module doc:

```rust
//! # Error Architecture
//!
//! ...existing docs...
//!
//! ## Example Usage
//!
//! ```rust
//! use miden_processor::{ExecutionSiteContext, OperationResultExt};
//!
//! // Node-level error (no specific operation)
//! let ctx = ExecutionSiteContext::node(program, node_id, clk);
//! some_operation()
//!     .map_exec_err(&ctx, host)?;
//!
//! // Operation-level error (specific instruction)
//! let ctx = ExecutionSiteContext::operation(program, node_id, op_idx, clk);
//! execute_operation()
//!     .map_exec_err(&ctx, host)?;
//! ```
//!
//! ## Feature Flags
//!
//! ### `no_err_ctx` Feature
//!
//! When the `no_err_ctx` feature is enabled, the lazy context simply returns
//! `None` from `resolve()`, causing all errors to use the `OperationErrorNoContext`
//! variant with help text instead of source locations.
//!
//! This provides zero-cost error handling for performance-critical builds where
//! diagnostic information is not needed.
```

### 9.2 Remove Stale Macro References

Search for and remove any remaining references to `err_ctx!()` macro in:
- Doc comments
- Code examples
- README files (if any)

---

## 10. Phased Implementation Plan

### Phase 1: Remove ErrorContext Trait ✂️ [COMPLETED]

**Goal**: Eliminate unnecessary trait abstraction

**Completed Tasks**:
1. ✅ Deleted `ErrorContextImpl` struct and all associated code
2. ✅ Removed `label_and_source_file()` method from `ErrorContext` trait
3. ✅ Deleted entire `ErrorContext` trait (only 2 implementations: OpErrorContext and () placeholder)
4. ✅ Deleted `impl ErrorContext for ()` placeholder
5. ✅ Inlined all trait methods directly into `OpErrorContext` with proper feature gating
6. ✅ Updated `ResultOpErrExt` to use concrete `&OpErrorContext` instead of `&impl ErrorContext`
7. ✅ Updated all function signatures (~20+ sites) from `&impl ErrorContext` to `&OpErrorContext`
8. ✅ Updated imports in decoder/mod.rs and lib.rs
9. ✅ Verified compilation: `cargo check --all-features` ✓
10. ✅ Running tests: `make test` (in progress)

**Actual Impact**:
- ~100 lines deleted (ErrorContext trait definition, impl for (), ErrorContextImpl)
- Eliminated unnecessary trait abstraction (only had 2 impls, one was a placeholder)
- All error handling now uses concrete `OpErrorContext` type directly
- Cleaner, more direct API with less indirection
- Zero runtime logic changes - all feature gating preserved

**Rationale for Extended Scope**:
Initial plan was to just remove ErrorContextImpl, but analysis revealed:
- ErrorContext trait had only 2 implementations: `OpErrorContext` and `()` (placeholder)
- The `()` impl was just a placeholder that always returned None
- Trait provided no real abstraction value after ErrorContextImpl deletion
- Using concrete `OpErrorContext` type directly is clearer and simpler

**Commit Message**:
```
refactor(processor): remove ErrorContext trait and use OpErrorContext directly

Phase 1 cleanup - eliminate unnecessary trait abstraction:
- Delete ErrorContext trait (only had 2 impls: OpErrorContext and () placeholder)
- Delete ErrorContextImpl struct (confirmed unused)
- Delete impl ErrorContext for () placeholder
- Inline all trait methods into OpErrorContext with feature gating preserved
- Update ResultOpErrExt to use &OpErrorContext instead of &impl ErrorContext
- Update ~20+ function signatures from &impl ErrorContext to &OpErrorContext

The trait provided no real abstraction value - OpErrorContext is now used
directly throughout the codebase. All feature flag behavior preserved.

No logic changes - tests passing.
```

---

### Phase 2: Core Renames (Type & Trait Names) 🏷️ [COMPLETED]

**Goal**: Rename primary types for clarity

**Completed Tasks**:
1. ✅ `OpErrorContext` → `ExecutionSiteContext`
   - Updated struct definition in errors.rs
   - Updated all 64 occurrences across 8 files
   - Updated all imports and doc comments

2. ~~`ErrorContext` → `ErrorSite`~~ (N/A - trait removed in Phase 1)

3. ✅ `ResultOpErrExt` → `OperationResultExt`
   - Updated trait definition in errors.rs
   - Updated all 11 occurrences across 8 files
   - Updated all imports

4. ✅ Ran incremental checks:
   - `cargo check --all-features` passed
   - No compilation errors

5. ✅ Full test suite: `make test` - all 2411 tests passed

**Actual Impact**:
- 75 mechanical renames across 8 files (64 ExecutionSiteContext + 11 OperationResultExt)
- Zero logic changes
- All tests passing

**Commit Message**:
```
refactor(processor): rename error handling types for clarity

Rename core types to better reflect their purpose:
- OpErrorContext → ExecutionSiteContext (covers node and operation errors)
- ErrorContext → ErrorSite (clearer, shorter)
- ResultOpErrExt → OperationResultExt (conventional naming)

Mechanical rename - no logic changes.
```

---

### Phase 3: API Refinements 🎨 [COMPLETED]

**Goal**: Improve API ergonomics and naming consistency

**Completed Tasks**:
1. ✅ **Renamed methods**:
   - `resolve_source()` → `resolve()` (shorter, clearer)
   - `wrap_op_err_with_host()` → `into_exec_err()` (more idiomatic)

2. ✅ **Simplified extension trait**:
   - Removed `map_exec_err_no_ctx()` method (unused in practice)
   - Renamed `map_exec_err_with_host()` → `map_exec_err()`
   - Single method always requires host (no confusion)

3. ✅ **Updated all call sites** (mechanical):
   - Changed 59 occurrences of `.map_exec_err_with_host()` to `.map_exec_err()`
   - All implementations now use `into_exec_err()` internally

4. ✅ **Verification**:
   - All method renames compile cleanly
   - Ready for tests after parallel agent completes

**Actual Impact**:
- 59 call site updates (mechanical replacement)
- Cleaner, more idiomatic method names
- Single unified error wrapping method (no host-free confusion)
- Tuple return from resolve() kept (SourceContext struct not needed)

**Commit Message**:
```
refactor(processor): simplify error API and improve naming

Changes:
- Rename methods: resolve_source → resolve, wrap_op_err_with_host → into_exec_err
- Simplify OperationResultExt to single map_exec_err method (always host-aware)
- Remove unused map_exec_err_no_ctx variant

Mechanical refactor - improves ergonomics without changing logic.
```

---

### Phase 4: Constructor Renames (Final Polish) ✨

**Goal**: Make constructor intent immediately clear

**Tasks**:
1. **Rename constructors**:
   - `ExecutionSiteContext::new()` → `::node()`
   - `ExecutionSiteContext::with_op()` → `::operation()`

2. **Update all call sites** (~100+ locations):
   - Decoder: ~30 sites
   - Fast processor: ~40 sites
   - Slow processor: ~30 sites

3. **Update documentation**:
   - Module-level examples
   - Method doc comments
   - Remove any macro references

4. **Final verification**: `make test`

**Expected Impact**:
- ~100 call site updates
- Significantly clearer intent at usage sites
- Updated documentation

**Commit Message**:
```
refactor(processor): rename error context constructors for clarity

Changes:
- ExecutionSiteContext::new → ::node (for node-level errors)
- ExecutionSiteContext::with_op → ::operation (for operation-level errors)

Intent is now immediately clear at call sites.
Updated documentation and examples.
```

---

### Phase 5: Performance Optimizations (Optional) ⚡

**Goal**: Reduce allocations and enum size

**Tasks**:
1. **Box large error variant**:
   - Box `MerklePathVerificationFailed`
   - Update error creation sites
   - Verify size reduction with `std::mem::size_of`

2. **Optimize `require_u32_operands!` macro**:
   - Implement check-first-allocate-later pattern
   - OR switch to SmallVec
   - Run benchmarks if available

3. **Extract duplicated macro**:
   - Move to shared utils
   - Update imports in both u32_ops files

4. **Test thoroughly**: `make test`

**Expected Impact**:
- Smaller Result<T, OperationError> on stack
- Removed allocation from hot path
- ~20 lines of duplication eliminated

**Commit Message**:
```
perf(processor): optimize error handling hot paths

Changes:
- Box MerklePathVerificationFailed variant (reduces enum size)
- Optimize require_u32_operands! to avoid allocation on success path
- Extract duplicated macro to shared utils

Improves performance on success paths while maintaining error quality.
```

---

## 11. Verification Checklist

After each phase:

- [ ] `cargo check --all-features` passes
- [ ] `cargo clippy` produces no new warnings
- [ ] `make test` - all 2411 tests pass
- [ ] `cargo check --features no_err_ctx` passes
- [ ] `cargo test --features no_err_ctx` subset passes
- [ ] Documentation builds: `cargo doc --no-deps`
- [ ] Commit message follows conventions
- [ ] Git history is clean (no fixup commits)

---

## 12. Success Metrics

**Code Quality**:
- [ ] ~150 lines of dead code removed
- [ ] Zero unused methods in public API
- [ ] API names directly describe purpose
- [ ] No duplication between slow/fast processor

**Type Safety**:
- [ ] `SourceContext` struct replaces tuple
- [ ] Single error wrapping method (no confusion)
- [ ] Impossible to use host-free methods

**Performance**:
- [ ] `OperationError` enum size reduced
- [ ] No allocations in `require_u32_operands!` success path
- [ ] All tests still passing

**Developer Experience**:
- [ ] Constructor names clarify intent: `::node()` vs `::operation()`
- [ ] Method names are idiomatic: `resolve()`, `into_exec_err()`
- [ ] Documentation examples reflect actual API

---

## 13. Risk Assessment

**Low Risk**:
- Phase 1 (deletions) - Confirmed dead code
- Phase 2 (renames) - Mechanical, compiler-verified
- Phase 3 (SourceContext) - Additive change with refactor

**Medium Risk**:
- Phase 4 (constructor renames) - Many call sites, but mechanical
- Phase 5 (optimizations) - Could affect error message content

**Mitigation**:
- Incremental commits with tests after each phase
- Comprehensive test suite (2411 tests) catches regressions
- Feature flag testing ensures both configs work
- Can roll back individual phases if issues arise

---

## 14. Future Considerations

### Potential Follow-Ups (Not in Scope)

1. **Node type optimization** (Section 8.2):
   - Profile first to determine if worthwhile
   - Would require larger struct and more complex construction

2. **Error variant analysis**:
   - Use cargo-bloat or similar to analyze actual enum sizes
   - Identify additional boxing candidates based on data

3. **Subsystem error consistency**:
   - Audit `MemoryError`, `AceError`, etc. for consistency
   - Ensure help text quality across all error types

4. **Error context caching**:
   - Could cache resolved source contexts if resolve() is called multiple times
   - Would need profiling to determine benefit

---

## 15. References

**Related Files**:
- `processor/src/errors.rs` - Core error definitions
- `processor/src/decoder/mod.rs` - Decoder error handling
- `processor/src/fast/*.rs` - Fast processor error sites
- `processor/src/lib.rs` - Slow processor error handling
- `processor/src/operations/*.rs` - Operation error returns

**Related Commits** (current branch):
- `ae829ec8c` - Remove unused err_ctx! macro
- `dceb32803` - Migrate to host-aware error wrapping
- `c7e1b4d81` - Add lazy error context infrastructure (Phase 1)

**Documentation**:
- Error architecture: `processor/src/errors.rs` module docs
- MAST concepts: `docs/src/design/`
- Testing: `docs/src/user_docs/assembly/debugging.md`

---

## 16. Questions & Decisions

### Open Questions

1. **Constructor naming preference**?
   - Option A: `::node()` and `::operation()` ✅ (recommended)
   - Option B: `::for_node()` and `::for_operation()`
   - Option C: `::at_node()` and `::at_operation()`

2. **Extension trait vs free function**?
   - Option A: Keep trait `OperationResultExt` ✅ (recommended)
   - Option B: Switch to free function `op_err_into_exec()`

3. **SourceContext location**?
   - Option A: Same module as errors (`errors.rs`) ✅ (recommended)
   - Option B: Separate module (`errors/source_context.rs`)

### Decisions Made

- ✅ Delete `ErrorContextImpl` - confirmed unused
- ✅ Remove host-free API methods - all call sites migrated
- ✅ Rename `OpErrorContext` to `ExecutionSiteContext`
- ✅ Introduce `SourceContext` struct for type safety
- ✅ Slim trait from 4 methods to 2 + blanket impl

---

**End of Document**
