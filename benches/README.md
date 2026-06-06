# Benchmarks

This directory holds benchmark crates that are not tied to one published package.

## SMT CodSpeed Benchmarks

The `smt-codspeed` crate runs wall-time CodSpeed benchmarks for sparse Merkle tree
operations in `miden-crypto`.

Run the benchmarks locally with:

```sh
cargo codspeed build --measurement-mode walltime --profile optimized -p miden-crypto-smt-codspeed-bench --bench smt_codspeed
cargo codspeed run --measurement-mode walltime -p miden-crypto-smt-codspeed-bench --bench smt_codspeed
```

The `codspeed` workflow runs the same crate on `main`, `next`, and manual
workflow dispatches. CodSpeed results are available from the workflow run and
from the CodSpeed dashboard for this repository.
