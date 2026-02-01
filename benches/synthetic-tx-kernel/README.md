# Synthetic Transaction Kernel Benchmarks

This crate generates synthetic benchmarks that mirror the transaction kernel from miden-base,
enabling fast feedback for VM developers without requiring the full miden-base dependency.

## Overview

The benchmark system works by:

1. **Profile Export** (in miden-base): The transaction kernel benchmark exports a VM profile
describing its instruction mix, operation counts, and cycle breakdown.

2. **Profile Consumption** (in miden-vm): This crate reads the profile and generates Miden
assembly code that replicates the same workload characteristics.

3. **Benchmark Execution**: Criterion.rs runs the generated benchmarks for statistical rigor.

## Usage

### Running Benchmarks

```bash
# Run component benchmarks (isolated operations)
cargo bench -p synthetic-tx-kernel --bench component_benchmarks

# Run synthetic kernel benchmark (representative workload)
cargo bench -p synthetic-tx-kernel --bench synthetic_kernel
```

### Updating the Profile

When the transaction kernel in miden-base changes:

1. Run benchmarks in miden-base:
```bash
cd /path/to/miden-base
cargo run --bin bench-transaction --features concurrent
```

2. Copy the generated profile:
```bash
cp bench-tx-vm-profile.json /path/to/miden-vm/benches/synthetic-tx-kernel/profiles/
```

3. Update the symlink:
```bash
cd /path/to/miden-vm/benches/synthetic-tx-kernel/profiles
ln -sf bench-tx-vm-profile.json latest.json
```

4. Commit the new profile in miden-vm.

## Profile Format

Profiles are JSON files with the following structure:

```json
{
  "profile_version": "1.0",
  "source": "miden-base/bin/bench-transaction",
  "timestamp": "2025-01-31T...",
  "miden_vm_version": "0.20.0",
  "transaction_kernel": {
    "total_cycles": 73123,
    "phases": { ... },
    "instruction_mix": {
      "arithmetic": 0.05,
      "hashing": 0.45,
      "memory": 0.08,
      "control_flow": 0.05,
      "signature_verify": 0.37
    }
  }
}
```

## Architecture

- `src/profile.rs`: Profile data structures
- `src/generator.rs`: MASM code generation from profiles
- `src/validator.rs`: Profile validation and comparison
- `benches/component_benchmarks.rs`: Isolated operation benchmarks
- `benches/synthetic_kernel.rs`: Representative workload benchmark
- `profiles/`: Checked-in VM profiles from miden-base
