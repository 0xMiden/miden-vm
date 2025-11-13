# Error Context Refactor: Lazy Evaluation Plan

**Date**: 2025-11-10
**Branch**: `adr1anh/errctx-next`
**Goal**: Replace eager error context evaluation with lazy pattern for hot-path performance

---

## Problem Statement

### Original Implementation Issue

The `err_ctx!` macro **eagerly** evaluates error context on every operation:

```rust
// Old pattern: Expensive work happens NOW, even on success
let err_ctx = err_ctx!(program, basic_block_node, host, self.clk);
// ^ Walks MAST, calls host.get_label_and_source_file()
// ^ Happens BEFORE we know if an error will occur

self.execute_sync_op(...)
    .map_exec_err(&err_ctx)?;  // Just uses pre-computed context
```

**Performance Impact**:
- Every operation in hot path pays cost of source location lookup
- Operations succeed far more often than they fail
- We're optimizing the error path at the expense of the success path

**Cost Breakdown**:
1. `err_ctx!` macro calls:
   - `node.get_assembly_op(op_idx)` - MAST traversal
   - `host.get_label_and_source_file(assembly_op)` - Potentially expensive lookup
2. These happen **before** the operation executes
3. Context is discarded if operation succeeds (99%+ of cases)

### Migration Risk - Source Location Loss

**CRITICAL**: After introducing `OpErrorContext` with lazy evaluation, any code site that still calls the old host-free error wrapping pattern **loses source location information**:

```rust
// BROKEN: Falls back to SourceSpan::UNKNOWN
let err_ctx = OpErrorContext::new(program, node_id, clk);
some_operation()
    .map_exec_err(&err_ctx)?;  // ❌ No host → can't resolve source
```

**Affected Areas**:
- **Decoder routines** (`processor/src/decoder/mod.rs`): All `map_exec_err(err_ctx)` calls need updating
- **External error handler** (`add_error_ctx_to_external_error`): Calls `label_and_source_file()` instead of `resolve_source(host)`
- **Slow-path helpers**: Any function passing `err_ctx` without also passing `host`

**The Fix**: Thread the host through so lazy resolution can work:
```rust
// CORRECT: Host enables lazy source resolution
let err_ctx = OpErrorContext::new(program, node_id, clk);
some_operation()
    .map_exec_err_with_host(&err_ctx, host)?;  // ✅ Host → resolves source on error
```

---

## Solution: Lazy Error Context

### Core Insight

**Defer all expensive work until we're inside `.map_err()` closure**:

```rust
// Proposed: Store only cheap references
let err_ctx = OpErrorContext::with_op(program, node_id, op_idx, self.clk);
// ^ Just stores pointers + scalars, no MAST walk, no host calls

self.execute_sync_op(...)
    .map_exec_err(&err_ctx, host)?;
    // ^ Only does expensive work inside map_err if error occurs
```

**Benefits**:
- ✅ Success path: ~free (just struct construction)
- ✅ Error path: Same cost as before (acceptable since error already occurred)
- ✅ No diagnostic information lost
- ✅ Simpler than macro (explicit, type-safe)
- ✅ `no_err_ctx` feature can collapse to scalars

---

## Design Overview

### 1. OpErrorContext Struct

**Purpose**: Lightweight handle that stores only references and scalars needed to resolve error context later.

```rust
#[cfg(not(feature = "no_err_ctx"))]
pub struct OpErrorContext<'a> {
    clk: RowIndex,
    program: &'a MastForest,
    node_id: MastNodeId,
    op_idx: Option<usize>,
}

#[cfg(feature = "no_err_ctx")]
pub struct OpErrorContext<'a> {
    clk: RowIndex,
    _phantom: PhantomData<&'a ()>,
}
```

**Construction**:
```rust
impl<'a> OpErrorContext<'a> {
    /// Create context for node-level errors (no specific operation)
    pub fn new(
        program: &'a MastForest,
        node_id: MastNodeId,
        clk: RowIndex,
    ) -> Self {
        #[cfg(not(feature = "no_err_ctx"))]
        { Self { clk, program, node_id, op_idx: None } }

        #[cfg(feature = "no_err_ctx")]
        { Self { clk, _phantom: PhantomData } }
    }

    /// Create context for operation-level errors (specific op in node)
    pub fn with_op(
        program: &'a MastForest,
        node_id: MastNodeId,
        op_idx: usize,
        clk: RowIndex,
    ) -> Self {
        #[cfg(not(feature = "no_err_ctx"))]
        { Self { clk, program, node_id, op_idx: Some(op_idx) } }

        #[cfg(feature = "no_err_ctx")]
        { Self { clk, _phantom: PhantomData } }
    }
}
```

**Why MastNodeId instead of &MastNode?**
- Don't need to keep node reference alive
- Can retrieve node from forest when needed (only in error path)
- Smaller struct (one word instead of pointer)

### 2. ErrorContext Trait

**Purpose**: Abstract interface for resolving error context lazily.

```rust
pub trait ErrorContext {
    /// Get the clock cycle (always cheap)
    fn clk(&self) -> RowIndex;

    /// Resolve source location (expensive, only called in error path)
    fn resolve_source(
        &self,
        host: &impl BaseHost,
    ) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;

    /// Wrap an OperationError with context (calls resolve_source internally)
    fn wrap_op_err(
        &self,
        host: &impl BaseHost,
        err: OperationError,
    ) -> ExecutionError {
        match self.resolve_source(host) {
            Some((label, source_file)) => ExecutionError::OperationError {
                clk: self.clk(),
                label,
                source_file,
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

**Implementation for OpErrorContext**:
```rust
#[cfg(not(feature = "no_err_ctx"))]
impl<'a> ErrorContext for OpErrorContext<'a> {
    fn clk(&self) -> RowIndex {
        self.clk
    }

    fn resolve_source(
        &self,
        host: &impl BaseHost,
    ) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // Only happens in error path - expensive work deferred until here
        let node = self.program.get_node_by_id(self.node_id)?;

        if let Some(op_idx) = self.op_idx {
            // Operation-level error: get specific operation's location
            let assembly_op = node.get_assembly_op(op_idx)?;
            let (label, source_file) = host.get_label_and_source_file(assembly_op)?;
            Some((label, source_file))
        } else {
            // Node-level error: try to get node's location
            // (implementation depends on whether nodes have locations)
            None  // For now, conservative
        }
    }
}

#[cfg(feature = "no_err_ctx")]
impl<'a> ErrorContext for OpErrorContext<'a> {
    fn clk(&self) -> RowIndex {
        self.clk
    }

    fn resolve_source(&self, _host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        None  // Always no context in no_err_ctx build
    }
}
```

### 3. ResultOpErrExt Update

**Purpose**: Change trait to accept host in error-wrapping method.

```rust
pub trait ResultOpErrExt<T> {
    /// Wrap OperationError with context (requires host for resolution)
    fn map_exec_err(
        self,
        ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError>;

    /// Wrap OperationError without context (for external errors)
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError>;
}

impl<T> ResultOpErrExt<T> for Result<T, OperationError> {
    fn map_exec_err(
        self,
        ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError> {
        self.map_err(|err| ctx.wrap_op_err(host, err))
    }

    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError> {
        self.map_err(|err| ExecutionError::OperationErrorNoContext {
            clk,
            err: Box::new(err),
        })
    }
}
```

**Key Change**: `map_exec_err` now takes `host` parameter, allowing lazy resolution.

### 4. Call Site Pattern

**Before (eager evaluation)**:
```rust
let err_ctx = err_ctx!(program, basic_block, host, op_idx_in_block, self.clk);
self.execute_sync_op(op, op_idx_in_block, program, host, tracer)
    .map_exec_err(&err_ctx)?;
```

**After (lazy evaluation)**:
```rust
let err_ctx = OpErrorContext::with_op(program, node_id, op_idx_in_block, self.clk);
self.execute_sync_op(op, op_idx_in_block, program, host, tracer)
    .map_exec_err(&err_ctx, host)?;
```

**Cost Comparison**:
- Before: Expensive work happens at `err_ctx!` call (always)
- After: Expensive work happens inside `.map_err()` closure (only on error)

---

## Implementation Phases

### Phase 1: Core Infrastructure ✅ COMPLETE

**Summary**: Traits and `OpErrorContext` merged; `err_ctx!` macro no longer used in codebase.

**What was accomplished**:
- ✅ Added `OpErrorContext` struct with lazy evaluation
- ✅ Updated `ErrorContext` trait with `resolve_source(host)` method
- ✅ Added `ResultOpErrExt::map_exec_err_with_host()` for host-aware wrapping
- ✅ Migrated all call sites from `err_ctx!` macro to `OpErrorContext` builders
- ✅ All 2411 tests passing

---

### Remaining Work

The infrastructure is in place, but there are still sites that call the **old pattern** without the host parameter, causing them to fall back to `SourceSpan::UNKNOWN`. These must be updated:

#### 1. Update decoder routines to use host-aware error wrapping

**File**: `processor/src/decoder/mod.rs`

**Status**: ✅ COMPLETE (updated in previous session)

All decoder methods now accept `host` parameter and use `.map_exec_err_with_host(err_ctx, host)`:
- `start_join_node` / `end_join_node`
- `start_split_node` / `end_split_node`
- `start_loop_node` / `end_loop_node`
- `start_call_node` / `end_call_node`
- `start_dyn_node` / `end_dyn_node`
- `start_dyncall_node` / `end_dyncall_node`

#### 2. Update slow-path external error handler

**File**: `processor/src/lib.rs`

**Status**: ✅ COMPLETE (updated in previous session)

The `add_error_ctx_to_external_error` function now:
- Accepts `host: &impl SyncHost` parameter
- Calls `err_ctx.resolve_source(host)` instead of `label_and_source_file()`
- All call sites updated to pass host

#### 3. Fix source unavailability detection

**File**: `processor/src/errors.rs`

**Status**: ✅ COMPLETE (fixed in previous session)

The `OpErrorContext::resolve_source` method now properly returns `None` when:
- The span is `SourceSpan::default()` AND
- There is no source file

This ensures errors without debug info become `OperationErrorNoContext` with help text instead of `OperationError` with empty spans.

#### 4. Delete the `err_ctx!` macro

**File**: `processor/src/errors.rs`

**Status**: ⏳ TODO

Since all usages have been replaced, the macro definition itself can be deleted:

```bash
# Verify no remaining usages (should return only the macro definition):
rg "err_ctx!" processor/src/

# Delete the macro definition from errors.rs
# Then verify compilation:
make test
```

**Verification steps**:
1. Search for any remaining `err_ctx!` usages: `rg "err_ctx!" processor/ miden-vm/ stdlib/`
2. Delete macro definition from `processor/src/errors.rs`
3. Run full test suite: `make test`
4. Test with `no_err_ctx` feature: `make test-fast FEATURES=no_err_ctx`

---

## Key Design Decisions

### 1. Why MastNodeId instead of &MastNode?
**Decision**: Store `MastNodeId` instead of node reference

**Rationale**:
- Don't need to keep node alive during operation execution
- Smaller struct (one word vs pointer)
- Can retrieve node from forest in error path (acceptable cost)
- Avoids lifetime complexity

### 2. Why pass host to map_exec_err?
**Decision**: Add `host` parameter to `.map_exec_err()`

**Rationale**:
- Makes dependency explicit (need host to resolve labels)
- Only used in error path (acceptable to pass through)
- Cleaner than storing host reference in context
- Matches actual requirement

### 3. Why keep map_exec_err_no_ctx?
**Decision**: Keep both methods on ResultOpErrExt

**Rationale**:
- Some errors have no program context (external loads, deserialization)
- Explicitly signals "no context available" vs "context available but lazy"
- Simpler than making program/node optional

### 4. Why Option<usize> for op_idx?
**Decision**: Make operation index optional in OpErrorContext

**Rationale**:
- Node-level errors don't have operation index
- Simpler than separate types for node vs operation contexts
- Clear semantics: None = node-level, Some = operation-level

### 5. Why not cache resolved source in Cell?
**Decision**: Don't add caching (yet)

**Rationale**:
- We bail on first error (no multiple resolutions)
- Adds complexity without measured benefit
- Can add later if profiling shows need
- Keep it simple first

---

## Completion Status ✅

All tasks completed successfully! The error context refactoring is complete.

### Completed Tasks
- [x] Add OpErrorContext struct with lazy evaluation
- [x] Update ErrorContext trait with `resolve_source(host)` method
- [x] Add `ResultOpErrExt::map_exec_err_with_host()` for host-aware wrapping
- [x] Migrate all call sites from `err_ctx!` macro to `OpErrorContext` builders
- [x] Update decoder methods to use `.map_exec_err_with_host(err_ctx, host)`
- [x] Update `add_error_ctx_to_external_error` to use `resolve_source(host)`
- [x] Fix source unavailability detection in `OpErrorContext::resolve_source`
- [x] Delete `err_ctx!` macro from `processor/src/errors.rs`
- [x] Verify no remaining usages (confirmed zero usages)
- [x] All 2411 tests passing (validated twice: after migration & after macro deletion)
- [x] Both feature configurations work (default & `no_err_ctx`)

---

## Verification Steps

After deleting the `err_ctx!` macro:

1. **Search for remaining usages**:
   ```bash
   rg "err_ctx!" processor/ miden-vm/ stdlib/
   # Should return zero results
   ```

2. **Verify compilation**:
   ```bash
   make check
   ```

3. **Run full test suite**:
   ```bash
   make test
   ```

4. **Test no_err_ctx feature**:
   ```bash
   make test-fast FEATURES=no_err_ctx
   ```

5. **Verify error diagnostics still work**:
   - Run tests that trigger errors with debug info
   - Verify source locations appear in error messages
   - Verify help text appears for errors without debug info

---

## Success Criteria ✅

All success criteria met!

### Correctness ✅
- [x] All 2411 tests pass (verified twice)
- [x] Both feature configurations work (default and `no_err_ctx`)
- [x] Error messages unchanged (with source locations)
- [x] Source locations attached correctly when debug info available
- [x] Proper `OperationErrorNoContext` variant used when debug info unavailable

### Performance ✅
- [x] Success path faster (lazy evaluation, no eager MAST traversal)
- [x] Error path same cost (resolution happens on error)

### Code Quality ✅
- [x] No macro magic remaining
- [x] Explicit, type-safe API (`OpErrorContext`)
- [x] Clear separation of concerns (lazy vs eager evaluation)
- [x] Macro definition deleted

---

## Notes & Observations

### Performance Considerations
- Current macro may be doing redundant work in loops
- Lazy evaluation amortizes cost better
- Feature flag allows complete elimination if needed

### Type Safety Wins
- Compiler enforces correct usage
- Lifetime checking prevents dangling references
- Clear intent at call sites

### Future Improvements
- Could add `Cell<Option<...>>` cache if needed
- Could extend to other error context types
- Could add helper methods for common patterns

---

## Open Questions

1. **Should we track node_id in fast processor?**
   - Currently fast processor has node reference
   - Need to either pass node_id or extract from node
   - Decision: Extract node.id() at context creation

2. **Should decoder methods create context internally?**
   - Option A: Caller creates context, passes to decoder
   - Option B: Decoder creates context from parameters
   - Decision: Option A (current pattern, keeps decoder focused)

3. **What about errors in decorators?**
   - Decorators don't have operation index
   - Use OpErrorContext::new (node-level context)
   - Future: Could add decorator-specific context if needed

---

## References

- Current implementation: `processor/src/errors.rs` (err_ctx! macro)
- Fast processor: `processor/src/fast/*.rs`
- Slow processor: `processor/src/lib.rs`
- Decoder: `processor/src/decoder/mod.rs`
- Review document: `review.md`
