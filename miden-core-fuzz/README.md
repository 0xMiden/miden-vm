# MastForest Fuzzing

This crate contains fuzz targets for testing MastForest deserialization and validation against adversarial inputs.

## Prerequisites

- Rust nightly toolchain
- cargo-fuzz: `cargo install cargo-fuzz`

## Running Fuzz Targets

### MastForest Deserialization

Tests `MastForest::read_from_bytes` with arbitrary byte sequences:

```bash
cargo +nightly fuzz run mast_forest_deserialize --fuzz-dir miden-core-fuzz
```

### UntrustedMastForest Validation

Tests the full untrusted deserialization + validation pipeline:

```bash
cargo +nightly fuzz run mast_forest_validate --fuzz-dir miden-core-fuzz
```

### All Targets

```bash
make fuzz-all
```

## Seed Corpus

Generate seed files from valid serializations:

```bash
make fuzz-seeds
```

Seeds are stored in `miden-core-fuzz/corpus/`.

## Coverage

Generate coverage report:

```bash
make fuzz-coverage
```

## Artifacts

Crash-inducing inputs are saved to `miden-core-fuzz/artifacts/`. To reproduce:

```bash
cargo +nightly fuzz run mast_forest_deserialize miden-core-fuzz/artifacts/mast_forest_deserialize/crash-XXX
```

## What We're Testing

1. **No panics**: Deserialization should never panic on any input
2. **No crashes**: No undefined behavior, buffer overflows, or memory corruption
3. **Resource limits**: Excessive allocations should be rejected early
4. **Validation completeness**: `UntrustedMastForest::validate()` catches all invalid forests

## Attack Surfaces

- Header parsing (magic, flags, version)
- Node count bounds checking
- Procedure roots deserialization
- Basic block data (operation batches, padding, groups)
- MastNodeInfo (type discriminants, child IDs, digests)
- DebugInfo (decorators, strings, CSR structures)
- Hash verification in validation
