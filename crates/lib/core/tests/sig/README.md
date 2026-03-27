# Signature verifier (MASM) — tests and benches

This folder is the main entrypoint for the STARK signature verifier tests and benchmarks. It covers:

- Rust transcript replay and proof packing
- MASM execution (single and batch)
- Proving benchmarks for the batch verifier

If you’re new to this code, start with the integration tests below.

## Quick start

Run the core integration tests:

```bash
cargo test -p miden-core-lib sig::integration
```

Run the instance‑seed guard test (keeps MASM constants in sync with Rust):

```bash
cargo test -p miden-core-lib --test core-lib sig::transcript::tests::instance_seed_matches_masm_constants
```

## Benchmarks

These are slow in debug builds. Always run in release and enable concurrency.

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

## Where to look next

- `integration.rs` — end‑to‑end tests and the batch proving benchmark
- `transcript.rs` — MASM‑matching transcript model and seed guard
- `circuit_gen.rs` — ACE circuit layout for the OOD check
