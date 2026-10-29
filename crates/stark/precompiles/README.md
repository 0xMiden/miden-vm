# miden-precompiles-stark

STARK proving, verification, runtime setup, and recursive advice for the Miden precompile
relation. Authored AIRs live in `miden_air_definitions::precompiles`; `miden_air::precompiles`
supplies production evaluators, geometry, embedded ACE instructions, and the identity pins consumed
by the recursive verifier.

Native verification is available with `default-features = false` and requires neither `std` nor
prover implementation dependencies. The default `std` feature exposes
`recursive::PvmRecursiveVerifierInputs`, which adapts Eidos proofs for the in-VM PVM verifier.
Neither path symbolically captures AIRs at runtime.

Enable `prover` for `prover::prove_precompiles(Vec<PrecompileWitness>, HashFunction)` and its
variants that accept explicit work limits and memory budgets. Witnesses are prepared and admitted
independently, then combined in a proving session that shares repeated computations.
Root order and repetitions are preserved, and empty batches or batches above `MAX_PRECOMPILE_ROOTS`
are rejected. The memory budget bounds conservative reservations for preparation and session
construction, then the modelled proving peak before trace allocation.

`verifier::verify_deferred` verifies a serialized STARK against an explicit aggregate root and
returns authenticated security parameters. The caller enforces execution-root coverage and
minimum-security requirements. `setup` supplies configuration factories, preprocessing caches,
native setup commitments, and PVM security parameters. Proving uses the shared
`miden_stark::memory` estimator.

The `fixture-tools` feature enables the `pvm-proof-fixture` binary for regenerating and checking
the proof fixture.

The `constants-tools` feature enables the PVM MASM parameter and artifact generator. See
[Maintaining recursive-verifier MASM](../../lib/core/RECURSIVE_VERIFIER.md) for source ownership
and regeneration commands.

Generic configuration factories and transcript observation come from `miden_stark::config`.
The accepted PVM PCS preset comes from `miden_air::precompiles::policy`; the backend's
`setup::config::eidos_config` supplies the PVM transcript domain.
