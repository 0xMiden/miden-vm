This directory contains a set of example MASM programs, along with files that describe the inputs to the stack and advice provider.

Those files are also used for benchmarking.

## Available Examples

- **`debug/`** - Demonstrates debugging instructions and stack inspection
- **`events/`** - Enhanced event system examples with hierarchical EventIds
- **`fib/`** - Fibonacci sequence computation
- **`hashing/`** - Various cryptographic hashing examples (Blake3, SHA256)
- **`merkle_store/`** - Merkle tree operations and storage
- **`nprime/`** - Prime number computation algorithms

## Running Examples

To run any example:

```bash
# Basic execution
miden-vm run -a <example>/<example>.masm

# With input file
miden-vm run -a <example>/<example>.masm -i <example>/<example>.inputs

# With tracing enabled
miden-vm run -a <example>/<example>.masm -t

# Generate proof
miden-vm prove -a <example>/<example>.masm -i <example>/<example>.inputs
```

## Event System Examples

The `events/` directory demonstrates the enhanced event system:

```bash
# Run event examples
miden-vm run -a events/enhanced_events_demo.masm

# Analyze events in programs
miden-vm events list -a events/enhanced_events_demo.masm
miden-vm events validate -a events/enhanced_events_demo.masm
```

See individual example directories for specific documentation and usage instructions.
