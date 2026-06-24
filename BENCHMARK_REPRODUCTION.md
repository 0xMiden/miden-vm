# BlakeG vs Poseidon2 Benchmark Reproduction

This note records the commands used to reproduce the synthetic transaction and
recursive verifier benchmark tables for the BlakeG/Eidos branch and the
Poseidon2 `next` baseline.

## Branches

Use two independent VM checkouts:

- BlakeG/Eidos: `0xMiden/miden-vm`, branch `al-blakeg-final`
- Poseidon2 baseline: `0xMiden/miden-vm`, branch `al-next-bench`

The BlakeG branch uses these git dependencies:

- `miden-crypto` and `miden-serde-utils`: `0xMiden/crypto`, branch `al-blakeg-final`
- `Al-Kindi-0/midenc-hir-type`, branch `al-blakeg-final`

## Auth Comparison

Run these from the BlakeG/Eidos checkout after cloning both repositories.

Falcon:

```sh
scripts/bench_auth_compare.sh \
  --poseidon-root ../miden-vm-next-bench \
  --auth falcon \
  --fri-queries 27 \
  --synth-repeat 10 \
  --recursive-repeat 10 \
  --warmup 1 \
  --threads 16 \
  --out-root bench-results/auth-compare-falcon-r10
```

ECDSA:

```sh
scripts/bench_auth_compare.sh \
  --poseidon-root ../miden-vm-next-bench \
  --auth ecdsa \
  --fri-queries 27 \
  --synth-repeat 10 \
  --recursive-repeat 10 \
  --warmup 1 \
  --threads 16 \
  --out-root bench-results/auth-compare-ecdsa-r10
```

Each command runs:

- synthetic proving for `create-single-p2id-note`, `consume-single-p2id-note`,
  and `consume-two-p2id-notes`;
- recursive proving for `consume-single-p2id-note` and
  `consume-two-p2id-notes`;
- both BlakeG/Eidos and Poseidon2.

The combined comparison tables are written to:

```text
bench-results/auth-compare-falcon-r10/latest/summary.md
bench-results/auth-compare-ecdsa-r10/latest/summary.md
```

To run both auth variants in one invocation, omit `--auth` and choose a single
output root:

```sh
scripts/bench_auth_compare.sh \
  --poseidon-root ../miden-vm-next-bench \
  --fri-queries 27 \
  --synth-repeat 10 \
  --recursive-repeat 10 \
  --warmup 1 \
  --threads 16 \
  --out-root bench-results/auth-compare-r10
```

## BlakeG/Eidos Suite

The standalone BlakeG suite defaults to the ECDSA P2ID fixtures. Use the auth
comparison script above when you need Falcon and ECDSA tables side by side.

```sh
git clone git@github.com:0xMiden/miden-vm.git miden-vm-blakeg-final
cd miden-vm-blakeg-final
git checkout al-blakeg-final

scripts/bench_blakeg_suite.sh \
  --fri-queries 27 \
  --synth-repeat 10 \
  --recursive-repeat 10 \
  --warmup 1 \
  --threads 16 \
  --out-root bench-results/blakeg-suite-r10
```

The combined summary is written to:

```text
bench-results/blakeg-suite-r10/<timestamp>/summary.md
```

The synthetic and recursive raw tables are:

```text
bench-results/blakeg-suite-r10/<timestamp>/synthetic/latest/results.tsv
bench-results/blakeg-suite-r10/<timestamp>/recursive/latest/results.tsv
```

## Poseidon2 Baseline Suite

The standalone Poseidon2 suite uses the same default ECDSA P2ID fixture set.

```sh
git clone git@github.com:0xMiden/miden-vm.git miden-vm-next-bench
cd miden-vm-next-bench
git checkout al-next-bench

scripts/bench_poseidon2_suite.sh \
  --fri-queries 27 \
  --synth-repeat 10 \
  --recursive-repeat 10 \
  --warmup 1 \
  --threads 16 \
  --out-root bench-results/poseidon2-suite-r10
```

The combined summary is written to:

```text
bench-results/poseidon2-suite-r10/<timestamp>/summary.md
```

The synthetic and recursive raw tables are:

```text
bench-results/poseidon2-suite-r10/<timestamp>/synthetic/latest/results.tsv
bench-results/poseidon2-suite-r10/<timestamp>/recursive/latest/results.tsv
```

## Quick Smoke Test

Use this when checking that the scripts and dependencies work from a clean
checkout without running the full benchmark.

Combined smoke from the BlakeG checkout:

```sh
scripts/bench_auth_compare.sh \
  --poseidon-root ../miden-vm-next-bench \
  --auth ecdsa \
  --recursive-proof-counts 2 \
  --fri-queries 27 \
  --synth-repeat 1 \
  --recursive-repeat 1 \
  --warmup 0 \
  --threads 4 \
  --build-jobs 2 \
  --out-root bench-results/auth-compare-smoke
```

BlakeG smoke from the BlakeG checkout:

```sh
scripts/bench_blakeg_suite.sh \
  --synth-fixtures create-single-p2id-note-falcon \
  --recursive-fixtures consume-single-p2id-note-falcon \
  --recursive-proof-counts 2 \
  --fri-queries 27 \
  --synth-repeat 1 \
  --recursive-repeat 1 \
  --warmup 0 \
  --threads 4 \
  --build-jobs 2 \
  --out-root bench-results/blakeg-suite-smoke
```

Poseidon2 smoke from the Poseidon2 checkout:

```sh
scripts/bench_poseidon2_suite.sh \
  --synth-fixtures create-single-p2id-note-falcon \
  --recursive-fixtures consume-single-p2id-note-falcon \
  --recursive-proof-counts 2 \
  --fri-queries 27 \
  --synth-repeat 1 \
  --recursive-repeat 1 \
  --warmup 0 \
  --threads 4 \
  --build-jobs 2 \
  --out-root bench-results/poseidon2-suite-smoke
```
