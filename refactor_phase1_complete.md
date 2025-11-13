# Phase 1 Complete: Lazy Error Context Infrastructure

**Date**: 2025-11-10
**Status**: ✅ Complete

---

## Summary

Successfully implemented the core infrastructure for lazy error context evaluation. All new types and traits are in place, both feature configurations compile successfully.

##Changes Made

### 1. Updated `ErrorContext` Trait

**File**: `processor/src/errors.rs` (lines 333-417)

Added two new methods to support lazy evaluation:

```rust
pub trait ErrorContext {
    // Existing methods:
    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)>;
    fn clk(&self) -> RowIndex;
    fn wrap_op_err(&self, err: OperationError) -> ExecutionError;

    // NEW: Resolve source with host (for lazy contexts)
    fn resolve_source(&self, host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // Default impl delegates to label_and_source_file() for backwards compatibility
    }

    // NEW: Wrap error with host (for lazy contexts)
    fn wrap_op_err_with_host(
        &self,
        host: &impl BaseHost,
        err: OperationError,
    ) -> ExecutionError {
        // Uses resolve_source() for full resolution
    }
}
```

**Design**: Default implementations preserve backwards compatibility with existing `ErrorContextImpl`.

### 2. Added `OpErrorContext<'a>` Struct

**File**: `processor/src/errors.rs` (lines 445-684)

Lightweight handle for lazy source location resolution:

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

**Key Features**:
- Stores only references and scalars (~32 bytes on 64-bit)
- No MAST traversal or host lookups until error occurs
- `op_idx: Option<usize>` handles both node-level and operation-level errors
- Feature flag support: collapses to just clock cycle in `no_err_ctx` mode

**Constructors**:
- `OpErrorContext::new(program, node_id, clk)` - for node-level errors
- `OpErrorContext::with_op(program, node_id, op_idx, clk)` - for operation-level errors

### 3. Implemented `ErrorContext` for `OpErrorContext`

**File**: `processor/src/errors.rs` (lines 620-684)

Two implementations depending on feature flag:

#### Default Configuration (`not(feature = "no_err_ctx")`)

```rust
impl<'a> ErrorContext for OpErrorContext<'a> {
    fn clk(&self) -> RowIndex { self.clk }

    fn label_and_source_file(&self) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // Backwards compat: returns UNKNOWN span (can't resolve without host)
    }

    fn resolve_source(&self, host: &impl BaseHost) -> Option<(SourceSpan, Option<Arc<SourceFile>>)> {
        // LAZY EVALUATION HAPPENS HERE
        let node = self.program.get_node_by_id(self.node_id)?;

        if let Some(op_idx) = self.op_idx {
            // Dispatch through MastNode enum to get assembly op
            let assembly_op = match node {
                MastNode::Block(n) => n.get_assembly_op(self.program, Some(op_idx)),
                MastNode::Join(n) => n.get_assembly_op(self.program, Some(op_idx)),
                // ... all variants
            }?;
            let location = assembly_op.location()?;
            // NOW we resolve with host (only in error path)
            let (label, source_file) = host.get_label_and_source_file(location);
            Some((label, source_file))
        } else {
            None
        }
    }
}
```

**Performance**:
- `clk()`: O(1) - just returns field
- `label_and_source_file()`: Cheap but returns UNKNOWN span
- `resolve_source()`: Expensive but only called in error path

#### `no_err_ctx` Configuration

```rust
impl<'a> ErrorContext for OpErrorContext<'a> {
    fn clk(&self) -> RowIndex { self.clk }
    fn label_and_source_file(&self) -> Option<_> { None }
    fn resolve_source(&self, _host: &impl BaseHost) -> Option<_> { None }
}
```

**Performance**: All methods are trivial - near-zero cost.

### 4. Extended `ResultOpErrExt` Trait

**File**: `processor/src/errors.rs` (lines 689-781)

Added new method for lazy error wrapping:

```rust
pub trait ResultOpErrExt<T> {
    // Existing methods:
    fn map_exec_err_no_ctx(self, clk: RowIndex) -> Result<T, ExecutionError>;
    fn map_exec_err(self, err_ctx: &impl ErrorContext) -> Result<T, ExecutionError>;

    // NEW: Lazy error wrapping with host
    fn map_exec_err_with_host(
        self,
        err_ctx: &impl ErrorContext,
        host: &impl BaseHost,
    ) -> Result<T, ExecutionError>;
}
```

**Usage**:
```rust
// Create cheap context handle
let ctx = OpErrorContext::with_op(program, node_id, op_idx, clk);

// Only pays cost inside map_err closure (error path)
some_operation()
    .map_exec_err_with_host(&ctx, host)?;
```

---

## Compilation Status

### ✅ Default Configuration
```bash
cargo check --package miden-processor
# Result: Compiles successfully with warnings about unused code (expected)
```

### ✅ `no_err_ctx` Feature
```bash
cargo check --package miden-processor --features no_err_ctx
# Result: Compiles successfully with warnings about unused code (expected)
```

**Warnings**: All warnings are about unused code - this is expected since we haven't migrated any call sites yet.

---

## Design Decisions Implemented

### 1. Store `MastNodeId` instead of `&MastNode`
**Rationale**: Don't need to keep node reference alive; can retrieve from forest in error path only.

### 2. Match on `MastNode` enum to access `MastNodeErrorContext` methods
**Issue**: `MastNode` enum doesn't implement `MastNodeErrorContext` directly.
**Solution**: Dispatch through match expression to call method on inner node type.

### 3. Default `resolve_source()` implementation
**Rationale**: Preserves backwards compatibility with `ErrorContextImpl` which eagerly pre-computes context.

### 4. `label_and_source_file()` returns `UNKNOWN` for `OpErrorContext`
**Rationale**: Can't fully resolve without host; callers should use `resolve_source()` or `wrap_op_err_with_host()`.

---

## Performance Characteristics

### Success Path (No Error)
**Before** (with `err_ctx!` macro):
1. Call `node.get_assembly_op()` - MAST traversal
2. Call `host.get_label_and_source_file()` - potentially expensive lookup
3. Store result in `ErrorContextImpl`
4. Execute operation (succeeds)
5. Discard context

**Cost**: Full MAST traversal + host lookup on every operation

**After** (with `OpErrorContext`):
1. Create `OpErrorContext` - store 3-4 scalars/pointers
2. Execute operation (succeeds)
3. Context never resolved

**Cost**: ~4 pointer/scalar stores (essentially free)

### Error Path
**Before** (with `err_ctx!` macro):
1. Pre-computed context already available
2. Wrap error with context

**After** (with `OpErrorContext`):
1. Enter `map_err()` closure
2. Call `resolve_source()`:
   - `get_node_by_id()` - O(log n) lookup
   - Match on node type
   - Call `get_assembly_op()` - MAST traversal
   - Call `host.get_label_and_source_file()` - lookup
3. Wrap error with resolved context

**Cost**: Same as before (acceptable - error already occurred)

###Net Result
- **Success path**: Significantly faster (no expensive work)
- **Error path**: Same cost as before
- **Overall**: Win-win (errors are rare, successes are common)

---

## Next Steps

### Immediate (Phase 2)
1. Migrate one module as pilot (e.g., `fast/basic_block.rs`)
2. Replace `err_ctx!` macro calls with `OpErrorContext::new/with_op`
3. Change `.map_exec_err(&err_ctx)` to `.map_exec_err_with_host(&err_ctx, host)`
4. Verify tests pass

### Then
1. Complete migration of all modules
2. Remove `err_ctx!` macro
3. Run full test suite
4. Document pattern

---

## Files Modified

- `processor/src/errors.rs`: +192 lines, updated trait and added new types

## Verification Commands

```bash
# Check default config
cargo check --package miden-processor

# Check no_err_ctx config
cargo check --package miden-processor --features no_err_ctx

# Both should compile successfully (with warnings about unused code)
```

---

## Phase 1 Checklist

- [x] Add OpErrorContext struct (both feature configs)
- [x] Add OpErrorContext::new and ::with_op constructors
- [x] Update ErrorContext trait with resolve_source
- [x] Implement ErrorContext for OpErrorContext
- [x] Update ResultOpErrExt to take host parameter (new method)
- [x] Add necessary imports
- [x] Verify both feature configs compile
- [x] No breaking changes to existing code

✅ **Phase 1 Complete** - Ready to proceed with Phase 2 (call site migration)
