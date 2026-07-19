# Signature verifier (MASM) — tests

Tests for the STARK signature verifier (`asm/sig/`), covering:

- Rust transcript replay and proof packing
- MASM execution: single, batch, and negative tests (bad grinding nonces,
  OOD point in the trace domain, tampered leaves)
- ACE circuit generation for the OOD constraint check
- Proving throughput benchmark for signature aggregation

## Module overview

| File | Purpose |
|------|---------|
| `mod.rs` | Top-level helpers: test messages, keygen seeds, sign/verify wrappers |
| `fixtures.rs` | Builds the full advice inputs (stack, Merkle store, advice map) for a signature proof |
| `conversions.rs` | `Goldilocks <-> Felt` and `QuadExt <-> QuadFelt` conversions + rate-aligned absorb/advice packing |
| `transcript.rs` | Mirrors miden-signature's Fiat-Shamir transcript over Miden's Poseidon2 |
| `circuit_gen.rs` | ACE circuit generation for the OOD check (constants, ops, commitment hash) |
| `integration.rs` | End-to-end tests: sign → pack advice → execute in the VM |
| `bench.rs` | `#[ignore]`d aggregation benchmark (`bench_prove_sig_batch_shared_message`) |

## Dependencies

- [`miden-signature`](https://github.com/0xMiden/miden-signature) — the STARK-based
  signature scheme (path dependency; uses upstream Plonky3 0.6, same as this workspace)
