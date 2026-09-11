# Miden core fuzzing

This crate tests Miden core deserialization surfaces against bad inputs. It covers `MastForest` and `ExecutionProof` as well as deferred-state proof wire formats.

## Prerequisites

- Rust nightly toolchain
- cargo-fuzz: `cargo install cargo-fuzz`

## Quick start

List all fuzz targets:

```bash
cargo +nightly fuzz list --fuzz-dir tools/miden-core-fuzz
```

Run all targets (5 minutes each):

```bash
make fuzz-all
```

## Fuzz targets

### High-level targets

The **`mast_forest_deserialize`** target tests `MastForest::read_from_bytes` with arbitrary bytes.

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`mast_forest_serde_deserialize`** target tests `MastForest` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run mast_forest_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`mast_forest_validate`** target tests the full untrusted pipeline from decoding through validation.

```bash
cargo +nightly fuzz run mast_forest_validate --fuzz-dir tools/miden-core-fuzz
```

### Core deserialization targets

These targets exercise core deserializers directly.

The **`program_deserialize`** target tests `Program::read_from_bytes`.

```bash
cargo +nightly fuzz run program_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`program_serde_deserialize`** target tests `Program` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run program_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`kernel_deserialize`** target tests `KernelDescriptor::read_from_bytes`.

```bash
cargo +nightly fuzz run kernel_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`kernel_serde_deserialize`** target tests `KernelDescriptor` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run kernel_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`stack_io_deserialize`** target tests `StackInputs` and `StackOutputs` deserialization.

```bash
cargo +nightly fuzz run stack_io_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`advice_inputs_deserialize`** target tests `AdviceInputs` and `AdviceMap` deserialization.

```bash
cargo +nightly fuzz run advice_inputs_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`advice_map_serde_deserialize`** target tests `AdviceMap` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run advice_map_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`operation_deserialize`** target tests `Operation::read_from_bytes`.

```bash
cargo +nightly fuzz run operation_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`operation_serde_deserialize`** target tests `Operation` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run operation_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`execution_proof_deserialize`** target tests canonical `ExecutionProof` decoding without a
registry, including its passive deferred-state proof wire. Successful decodes must encode to the
same bytes and decode to the same proof.

```bash
make fuzz-execution-proof
```

The **`execution_proof_serde_deserialize`** target exercises the derived Serde parsers for
`ExecutionProof` and its `Vec` and `Option` containers. It does not establish proof validity or
claim allocation-bounded generic Serde.

```bash
cargo +nightly fuzz run execution_proof_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`deferred_state_wire_deserialize`** target tests `DeferredStateWire::read_from_bytes`.

```bash
cargo +nightly fuzz run deferred_state_wire_deserialize --fuzz-dir tools/miden-core-fuzz
```

The **`deferred_state_wire_serde_deserialize`** target tests `DeferredStateWire` JSON deserialization via `serde_json`.

```bash
cargo +nightly fuzz run deferred_state_wire_serde_deserialize --fuzz-dir tools/miden-core-fuzz
```

### Package deserialization targets

These targets exercise package deserializers used by `.masp`.

The **`package_deserialize`** target tests `Package::read_from_bytes`.

```bash
cargo +nightly fuzz run package_deserialize --fuzz-dir tools/miden-core-fuzz
```

### Component targets

These fuzz internal structures through the MastForest deserialization path:

The **`basic_block_data`** target covers operation batches, including their index pointer and padded group data.

```bash
cargo +nightly fuzz run basic_block_data --fuzz-dir tools/miden-core-fuzz
```

The **`debug_info`** target covers debug string tables and CSR structures with their error codes.

```bash
cargo +nightly fuzz run debug_info --fuzz-dir tools/miden-core-fuzz
```

The **`mast_node_info`** target covers node type discriminants and digests in a fixed 40-byte structure.

```bash
cargo +nightly fuzz run mast_node_info --fuzz-dir tools/miden-core-fuzz
```

## Seed corpus

Generate seed files from valid serializations:

```bash
make fuzz-seeds
```

Seeds go to `tools/miden-core-fuzz/corpus/<target-name>/`.

## Coverage

Generate coverage report:

```bash
make fuzz-coverage
```

This runs `cargo fuzz coverage` for the main targets and outputs coverage data to `tools/miden-core-fuzz/coverage/`.

## Artifacts

Crash-inducing inputs go to `tools/miden-core-fuzz/artifacts/<target-name>/`. To reproduce:

```bash
cargo +nightly fuzz run <target-name> --fuzz-dir tools/miden-core-fuzz artifacts/<target-name>/crash-XXX
```

Example:

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir tools/miden-core-fuzz artifacts/mast_forest_deserialize/crash-da39a3ee5e6b4b0d
```

## Attack surfaces

Where we expect malicious inputs to cause problems:

- Header magic and metadata parsing
- Node count bounds (rejection of excessive allocations)
- Procedure roots deserialization
- Basic block operation batches and padded groups
- MastNodeInfo type discriminants and child data
- DebugInfo decorators and string-table CSR data
- Hash verification in validation
- Deferred-state proof wire parsing and JSON deserialization

## Safety properties

Deserialization must never panic on any input. Fuzzing also checks for memory safety bugs and undefined behavior. `UntrustedMastForest::validate()` must reject every invalid forest.
