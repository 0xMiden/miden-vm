# MastForest Fuzzing

This crate tests MastForest deserialization and validation against bad inputs.

## Prerequisites

- Rust nightly toolchain
- cargo-fuzz: `cargo install cargo-fuzz`

## Quick Start

List all fuzz targets:

```bash
cargo +nightly fuzz list --fuzz-dir miden-core-fuzz
```

Run all targets (5 minutes each):

```bash
make fuzz-all
```

## Fuzz Targets

### High-Level Targets

**`mast_forest_deserialize`** — Tests `MastForest::read_from_bytes` with arbitrary bytes.

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir miden-core-fuzz
```

**`mast_forest_validate`** — Tests the full untrusted pipeline: deserialize then validate.

```bash
cargo +nightly fuzz run mast_forest_validate --fuzz-dir miden-core-fuzz
```

### Component Targets

These fuzz internal structures through the MastForest deserialization path:

**`basic_block_data`** — Operation batches (indptr, padding, group data).

```bash
cargo +nightly fuzz run basic_block_data --fuzz-dir miden-core-fuzz
```

**`debug_info`** — Decorators, string table, CSR structures, error codes.

```bash
cargo +nightly fuzz run debug_info --fuzz-dir miden-core-fuzz
```

**`mast_node_info`** — Node type discriminants and digests (40-byte fixed structure).

```bash
cargo +nightly fuzz run mast_node_info --fuzz-dir miden-core-fuzz
```

## Seed Corpus

Generate seed files from valid serializations:

```bash
make fuzz-seeds
```

Seeds go to `miden-core-fuzz/corpus/<target-name>/`.

## Coverage

Generate coverage report:

```bash
make fuzz-coverage
```

This runs `cargo fuzz coverage` for the main targets and outputs coverage data to `miden-core-fuzz/coverage/`.

## Artifacts

Crash-inducing inputs go to `miden-core-fuzz/artifacts/<target-name>/`. To reproduce:

```bash
cargo +nightly fuzz run <target-name> --fuzz-dir miden-core-fuzz artifacts/<target-name>/crash-XXX
```

Example:

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir miden-core-fuzz artifacts/mast_forest_deserialize/crash-da39a3ee5e6b4b0d
```

## Attack Surfaces

Where we expect malicious inputs to cause problems:

- Header parsing (magic, flags, version)
- Node count bounds (rejection of excessive allocations)
- Procedure roots deserialization
- Basic block data (operation batches, padding, groups)
- MastNodeInfo (type discriminants, child IDs, digests)
- DebugInfo (decorators, strings, CSR structures)
- Hash verification in validation

## What We're Testing

1. **No panics** — Deserialization never panics on any input
2. **No crashes** — No undefined behavior, buffer overflows, or memory corruption
3. **Resource limits** — Excessive allocations rejected early
4. **Validation completeness** — `UntrustedMastForest::validate()` catches all invalid forests
