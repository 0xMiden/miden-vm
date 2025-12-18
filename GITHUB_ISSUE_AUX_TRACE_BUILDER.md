# Refactor: Consider restructuring to eliminate AuxTraceBuilder trait workaround

## Summary

The current Plonky3 migration introduces an `AuxTraceBuilder` trait in `miden-air` as a workaround for a circular dependency. This issue documents the workaround and proposes evaluating whether a cleaner architecture is possible.

## Background

### The Circular Dependency Problem

`ProcessorAir` (in the `miden-air` crate) needs to build auxiliary traces during proving. The actual aux trace building logic lives in `miden-processor` (in the `AuxTraceBuilders` struct and its component builders for decoder, stack, range checker, and chiplets).

If `miden-air` directly depended on `miden-processor` to call this logic:

1. `miden-air` → `miden-processor` (to build aux traces)
2. `miden-processor` → `miden-air` (for trace layout constants, column indices, constraint definitions)
3. Cycle: `miden-air` → `miden-processor` → `miden-air`

### Current Workaround: Dependency Inversion

The cycle is broken using the dependency inversion principle:

1. **`miden-air` defines the trait**: The `AuxTraceBuilder` trait specifies the interface for building auxiliary columns from a main trace and challenges.

2. **`miden-processor` implements the trait**: The `AuxTraceBuilders` struct implements this trait with the actual logic.

3. **Prover injects the implementation**: `ProcessorAir::with_aux_builder(impl)` allows the prover to provide the concrete implementation at runtime.

This way:
- `miden-air` has no dependency on `miden-processor`
- `miden-processor` depends on `miden-air` (to implement the trait)
- The prover wires them together

### Additional Complexity: Matrix Format Adaptation

Plonky3 uses row-major matrices (`RowMajorMatrix<Felt>`) while our existing auxiliary trace building logic uses column-major format (`MainTrace` with `ColMatrix`). The trait implementation also handles this conversion:

```rust
impl<EF: ExtensionField<Felt>> AuxTraceBuilder<EF> for AuxTraceBuilders {
    fn build_aux_columns(
        &self,
        main_trace: &RowMajorMatrix<Felt>,
        challenges: &[EF],
    ) -> RowMajorMatrix<Felt> {
        // Convert row-major to column-major
        let main_trace_col_major = row_major_adapter::row_major_to_main_trace(main_trace);

        // Build aux columns using existing column-major logic
        let aux_columns = self.build_aux_columns(&main_trace_col_major, challenges);

        // Convert back to row-major for Plonky3
        row_major_adapter::aux_columns_to_row_major(aux_columns, main_trace.height())
    }
}
```

## Relevant Files

- `air/src/aux_builder.rs` - Trait definition (`AuxTraceBuilder`)
- `processor/src/trace/mod.rs` - Trait implementation for `AuxTraceBuilders`
- `processor/src/row_major_adapter.rs` - Matrix format conversion utilities

## Potential Future Improvements

1. **Restructure crate dependencies**: Evaluate if aux trace building could be extracted into a separate crate that both `miden-air` and `miden-processor` can depend on.

2. **Native row-major support**: Refactor auxiliary trace builders to work directly with row-major matrices, eliminating the conversion overhead.

3. **Move aux building to air crate**: If the aux building logic can be decoupled from processor internals, it could potentially live directly in `miden-air`.

## Labels

- `refactor`
- `plonky3`
- `architecture`
