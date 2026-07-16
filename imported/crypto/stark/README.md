# Miden Plonky3

Miden-specific [Plonky3](https://github.com/Plonky3/Plonky3) crates.

The current focus of this workspace is a *lifted STARK* prover/verifier stack:
multi-trace proofs where traces of different heights are presented to the PCS
and verifier as a single uniform-height object via virtual lifting.

## Lifted STARK Stack

```text
miden-lifted-stark               (prover, verifier, PCS, LMCS, shared types)
├── miden-lifted-air             (AIR traits + symbolic analysis)
├── miden-stark-transcript       (Fiat-Shamir channels)
├── miden-stateful-hasher        (stateful hashers for LMCS)
└── miden-bench                  (profiling binary)
```

## Workspace Crates

| Crate | Purpose |
|------|---------|
| `miden-lifted-stark` | Lifted STARK prover, verifier, PCS, LMCS, and shared types |
| `miden-lifted-air` | Lifted AIR traits and symbolic constraint analysis |
| `miden-stark-transcript` | Transcript channels (`ProverTranscript`, `VerifierTranscript`) |
| `miden-stateful-hasher` | Stateful hashers used by LMCS |
| `miden-bench` | Profiling binary for lifted and batch STARK runs |

## Docs

- `miden-lifted-stark/README.md` (protocol-level overview)
- `miden-lifted-stark/src/prover/README.md`, `src/verifier/README.md` (per-side detail + lifting math)
- `SECURITY.md` (audit/review guide; transcript and composition notes)

## Where To Start (Code)

- Protocol flow: `miden-lifted-stark/src/prover/mod.rs` and `miden-lifted-stark/src/verifier/mod.rs`
- PCS layer: `miden-lifted-stark/src/pcs/prover.rs` and `miden-lifted-stark/src/pcs/verifier.rs`
- Commitment layer: `miden-lifted-stark/src/lmcs/mod.rs` and `miden-lifted-stark/src/lmcs/lifted_tree.rs`
- Math background: the "Mathematical background" in `miden-lifted-stark/src/prover/README.md` and `miden-lifted-stark/src/verifier/README.md`

## Build / Test

```bash
make check
make test
make test-parallel
make lint
make doc
```

## Run An Example

```bash
cargo run -p miden-bench --features concurrent --release -- keccak:15
```

## Security Disclaimer

This code is research/prototype quality and has not been independently audited.
Do not treat any default parameters as production-ready.

## License

Any contribution intentionally submitted for inclusion in this repository, as defined in the Apache-2.0 license, shall be dual licensed under the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses, without any additional terms or conditions.
