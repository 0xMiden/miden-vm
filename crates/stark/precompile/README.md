# miden-precompile-stark

STARK proving, verification, runtime setup, and recursive advice for the Miden precompile
relation. Authored AIR semantics, production evaluators, compiled geometry, embedded ACE
instructions, and accepted protocol identities remain in `miden-air-definitions` and `miden-air`.

Native verification is available with `default-features = false` and requires neither `std` nor
prover implementation dependencies. The default `std` feature caches setup bundles and exposes
`recursive::PvmRecursiveVerifierInputs`, which adapts Eidos proofs for the in-VM PVM verifier.
Neither path symbolically captures AIRs at runtime.

Enable `prover` for `prover::prove_precompiles(Vec<PrecompileWitness>, HashFunction)` and its
explicit-limits/budget variants. Each witness is prepared independently before private session
lowering shares computations. Root order and repetitions are preserved, and empty batches or
batches above `MAX_PRECOMPILE_ROOTS` are rejected. The memory budget is checked after import and
before trace allocation; it does not bound preparation or session construction.

`verifier::verify_deferred` verifies a serialized STARK against an explicit aggregate root and
returns authenticated security parameters. Execution-root coverage and minimum-security acceptance
remain application policy. `setup` owns config construction, preprocessing caches, runtime
security calculations, and (with `prover`) the proving-memory model.

The `fixture-tools` feature enables the `pvm-proof-fixture` maintenance binary. Independent AIR
capture, setup-pin, proof-fixture, and recursive-verifier checks remain available in the crate's
existing tests.

The `constants-tools` feature enables the PVM MASM parameter and artifact generator. See
[Maintaining recursive-verifier MASM](../../lib/core/RECURSIVE_VERIFIER.md) for source ownership
and the edit/regenerate/test workflow.
