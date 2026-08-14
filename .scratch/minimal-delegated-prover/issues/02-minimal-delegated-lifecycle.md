# 02 — Complete one proof through the minimal delegated lifecycle

**What to build:** Make one execution work through the complete supported lifecycle—VM-first proving, passive transport, explicit hydration, precompile proving, completion, and final verification—while `prove_full` continues proving directly from the in-memory witness. Artifact construction and attachment preserve representation; `Verifier::verify` alone establishes proof shape, root policy, coverage, aggregate folding, and cryptographic validity.

**Blocked by:** 01 — Replace hydrated proof transport with passive wire.

**Status:** resolved

- [ ] Preserve exactly the supported prover façade: `Prover::{prove, prove_full, prove_precompile}`; VM-only proving remains private backend implementation.
- [ ] `Prover::prove` proves the VM and converts its singleton hydrated state to passive canonical wire when work remains; settled executions become complete immediately.
- [ ] `Prover::prove_full` proves retained precompile work directly from the in-memory witness without a wire round trip.
- [ ] `Prover::prove_precompile` borrows a valid witness and creates one precompile STARK with passive ordered metadata infallibly.
- [ ] Make `VmProof` and `PrecompileProof` transparent, unvalidated transport records with public fields; remove their redundant constructors and field accessors, plus `aggregate_root` and unused `into_parts`. Keep the existing `StarkProof` private-field constructor/accessor interface unchanged.
- [ ] Remove `ExecutionProof::{new_deferred, new_complete, validate_structure, precompile_wire}` without aliases, wrappers, extension traits, or renamed equivalents.
- [ ] Make `ExecutionProof::complete` perform only the deferred-to-complete transition and reject an already-complete proof; it does not check shape, root equality, root coverage, aggregate folding, or cryptography.
- [ ] Move all execution-proof shape checks to `Verifier::verify`: empty/excessive/`TRUE_DIGEST` roots, missing or unexpected precompile proofs, VM-root coverage, aggregate-root folding, and VM/precompile STARK verification.
- [ ] Deferred verification verifies the VM STARK and returns only its authenticated outstanding precompile root; it does not hydrate the passive wire or claim settlement.
- [ ] Complete and `prove_full` proofs verify to complete outcomes.
- [ ] Keep `VerificationOutcome` root-only, `Copy`, and `#[must_use]`, with only the necessary root-level accessors.
- [ ] Use public `VmProof` and `PrecompileProof` fields directly across crates; do not retain their field accessors as hidden plumbing. Keep `StarkProof` callers on its existing constructor/accessors. Retain only technically necessary witness accessors as `#[doc(hidden)]` backend plumbing and identify every concrete caller; do not reorganize crates.
- [ ] Tests demonstrate the singleton lifecycle end to end, malformed public variants surviving transport but failing verification, transition-only completion, and cryptographically invalid artifacts failing at verification.
- [ ] Delete duplicate constructor, decoder, completion, artifact, and verifier-local validity paths in this ticket; `Verifier::verify` is the sole proof-validity seam.
- [ ] Do not add a proof builder, lifecycle machine, validation module, policy object, error layer, adapter, dependency, feature flag, or compatibility surface.
- [ ] Keep canonical minimum sizing honest for transparent records: 2-byte `StarkProof`, 34-byte `VmProof`, 3-byte representable `PrecompileProof`, 35-byte verifier-valid singleton, and 71-byte two-singleton vector.
- [ ] Record incremental and cumulative production deltas, public-symbol changes, concept changes, validity-seam changes, and retained hidden plumbing against `12fee12d2`.
- [ ] The cumulative production Rust/MASM delta remains strictly net-negative and the public interface strictly smaller. Every production addition must identify the larger implementation it replaces; otherwise stop and report the blocker.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

Implemented a single authoritative verification seam and contracted proof artifacts without changing crate architecture. `VmProof` and `PrecompileProof` are transparent public-field transport records; `StarkProof` deliberately retains its existing constructor/accessor interface. Checked proof constructors, structural validation, aggregate-root helpers, proof field accessors, shallow prover packaging helpers, and redundant witness accessors were deleted.

`ExecutionProof::complete` now only performs the deferred-to-complete transition and rejects an already-complete proof. `Verifier::verify` directly owns proof presence, root-list shape, settled-root policy, root coverage, ordered aggregate folding, VM STARK verification, and precompile STARK verification. Deferred verification ignores passive wire and returns only the VM-authenticated outstanding root.

Ticket delta: 14 tracked files changed with 370 additions and 682 deletions (net −312 raw lines). Cumulatively from `12fee12d2`, tickets 01–02 remain strongly net-negative.

Validation was intentionally focused:

- `cargo check -p miden-vm --all-targets --features concurrent,executable,internal,testing` passed.
- Six cheap core/verifier tests for completion, canonical minima, malformed transport, coverage, and verifier-owned shape policy passed.
- One proof-heavy singleton delegated lifecycle test passed with `RAYON_NUM_THREADS=8` and `--test-threads 1`; it reused generated artifacts to cover unrelated passive wire and invalid precompile STARK rejection without generating extra proofs.
- The 64 MiB directly constructed VM-proof regression remains compiled but was intentionally excluded from the battery-sensitive focused run.
