# WASM Prover Test

Minimal test harness to verify the Miden VM prover works in WASM (browser) environments.

## Prerequisites

```bash
# Install wasm-pack
cargo install wasm-pack

# Install a browser driver (one of):
brew install geckodriver    # Firefox
brew install chromedriver   # Chrome

# If chromedriver is quarantined on macOS:
xattr -d com.apple.quarantine $(which chromedriver)
```

## Running

```bash
cd crates/wasm-prover-test

# Firefox (recommended)
wasm-pack test --firefox --headless --release

# Chrome
wasm-pack test --chrome --headless --release
```

`--release` is required because the debug WASM binary exceeds the browser's local variable limit.

## What it tests

- `prove_minimal_program` - Tiny program, verifies basic prove() works in WASM
- `prove_fibonacci_blake3` - Fibonacci (1000 iters) with Blake3 hash, exercises FRI grinding via `SerializingChallenger64`
- `prove_fibonacci_rpo` - Same program with RPO hash, exercises FRI grinding via `DuplexChallenger` (SIMD path)

## Known issue: `usize` truncation on wasm32

The `p3-challenger` crate casts `F::ORDER_U64` (a 64-bit field order) to `usize`, which truncates on `wasm32` where `usize` is 32 bits. This causes:

- **Blake3 path**: `assert!((1 << bits) <= F::ORDER_U64 as usize)` fails because the truncated order is smaller than `2^16`
- **RPO path**: `(F::ORDER_U64 as usize).div_ceil(lanes)` truncates the search space, so `grind()` never finds a valid witness

The `p3-challenger-patch/` directory contains a local fix that keeps all arithmetic in `u64`. Apply it via the `[patch.crates-io]` in `Cargo.toml`.
