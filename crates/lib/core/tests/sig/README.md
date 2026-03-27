# Signature verifier (MASM) — tests and benches

This folder is the main entrypoint for the STARK signature verifier tests and benchmarks. It covers:

- Rust transcript replay and proof packing
- MASM execution (single and batch)
- Proving benchmarks for the batch verifier

## Benchmarks

P3 Poseidon2 (prove‑only):

```bash
RUSTFLAGS="-C target-cpu=native" \
SIG_BATCH_BENCH_HASHER=p3 \
SIG_BATCH_BENCH_MIN_K=0 SIG_BATCH_BENCH_MAX_K=3 SIG_BATCH_BENCH_RUNS=3 \
cargo test --release -p miden-core-lib --features miden-prover/concurrent \
bench_prove_sig_batch_shared_message -- --ignored --nocapture
```

miden‑crypto Poseidon2 (normal path):

```bash
RUSTFLAGS="-C target-cpu=native" \
SIG_BATCH_BENCH_HASHER=miden \
SIG_BATCH_BENCH_MIN_K=0 SIG_BATCH_BENCH_MAX_K=3 SIG_BATCH_BENCH_RUNS=3 \
cargo test --release -p miden-core-lib --features miden-prover/concurrent \
bench_prove_sig_batch_shared_message -- --ignored --nocapture
```

### Bench environment knobs

- `SIG_BATCH_BENCH_HASHER`: `p3` or `miden`
- `SIG_BATCH_BENCH_MIN_K` / `SIG_BATCH_BENCH_MAX_K`: size sweep over `2^k` signatures
- `SIG_BATCH_BENCH_RUNS`: runs per `k`
- `RUSTFLAGS="-C target-cpu=native"`: enable CPU-specific optimizations
- `--features miden-prover/concurrent`: enable parallel proving

## Module overview

| File | Purpose |
|------|---------|
| `mod.rs` | Top-level helpers: test message generation, signing/verifying wrappers |
| `fixtures.rs` | Builds the full advice inputs (stack, Merkle store, advice map) for a signature proof |
| `conversions.rs` | Safe `Goldilocks <-> Felt` and `QuadExt <-> QuadFelt` conversions |
| `transcript.rs` | Mirrors the `miden-signature` Fiat-Shamir transcript using Miden's Poseidon2 |
| `rpo_air.rs` | The RPO signature AIR definition and ACE circuit generation |
| `circuit_gen.rs` | ACE circuit layout for the OOD check |
| `integration.rs` | End-to-end tests (sign -> build advice -> execute in VM) |
| `bench.rs` | Proving benchmarks for batch signature verification |
| `p3_poseidon2.rs` | Alternate prover backend using Plonky3's Poseidon2 (faster proving) |

## Dependencies

- [`miden-signature`](https://github.com/0xMiden/miden-signature) -- the STARK-based signature scheme
- [`0xMiden/Plonky3`](https://github.com/0xMiden/Plonky3/tree/fix/goldilocks-binext3-v0.5.1) -- patched p3 0.5 with `BinomiallyExtendable<3>` for Goldilocks
