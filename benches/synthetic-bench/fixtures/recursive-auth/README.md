# Recursive auth comparison

This directory contains fixed synthetic MASM fixtures for comparing recursive verification of a
single P2ID note authenticated with Falcon versus ECDSA. The fixtures are generated from the
producer snapshot scenarios named:

- `consume single P2ID note with Falcon signing`
- `consume single P2ID note with ECDSA signing`

Run the comparison from the workspace root:

```sh
benches/synthetic-bench/scripts/bench_recursive_auth_compare.sh
```

Useful knobs:

```sh
PROVE_REPEATS=10 PROOF_COUNTS=2,3,4,5,6,7,8 \
  benches/synthetic-bench/scripts/bench_recursive_auth_compare.sh
```

The script uses fresh proof caches under its output directory, so stale local proofs cannot affect
the result.
