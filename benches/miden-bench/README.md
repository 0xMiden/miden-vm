# Lifted STARK profiling

The profiling binary proves configurable dummy Miden AIR instances. Each instance
has one degree-9 product constraint, configurable main width (at least 9), and
configurable extension-field auxiliary width. It approximates a workload shape;
it does not execute a VM program.

```sh
# Default: miden:18, main width 51, auxiliary width 8, log_blowup 3.
cargo run -p miden-bench --features concurrent --release

# Two trace heights and widths, with the default auxiliary width.
cargo run -p miden-bench --features concurrent --release -- miden:18:51 miden:19:20

# Explicit main/auxiliary widths and full tracing output.
cargo run -p miden-bench --features concurrent --release -- -v miden:15:24:4

# Select the commitment hash while keeping the same AIR workload.
cargo run -p miden-bench --features concurrent --release -- -H blake3 miden:15
```

Trace arguments use `miden:LOG_HEIGHT[:WIDTH[:AUX_COLS]]`; `m` is a short alias.
The commitment choices are `eidos` (default), `keccak`, `blake3` and
`blake3-192`. Seed, PCS parameters, verbosity and `--no-verify` retain their
existing meanings. Use `--help` for the full option list.

The batch-STARK comparison backend and upstream Keccak/Blake3 AIR workloads
have been retired. Their CLI mode/workload selectors are no longer accepted.
The upstream Poseidon2 AIR fixture wrapper is also retired; commitment hash
implementations and test configurations remain available.

The standalone benchmark targets remain `quotient_commit`, `merkle_commit`,
`deep_quotient`, `pcs`, `pcs_trace` and `per_air_degree_opt`. The core
`miden-stark` targets `fri_fold` and `mmcs_compare` also remain. These commands
and targets are documented entrypoints; no benchmark execution is implied.
