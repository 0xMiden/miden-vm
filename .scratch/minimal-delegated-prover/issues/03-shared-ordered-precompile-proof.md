# 03 — Reuse one ordered merged precompile proof

**What to build:** Transport two deferred proofs, hydrate both passive wires, merge singleton witnesses in exact order `[one, one, two]`, prove the merged witness once, attach the resulting precompile proof to both compatible execution proofs, and verify both successfully. Ordering and duplicate multiplicity remain authenticated obligations rather than an unordered set.

**Blocked by:** 02 — Complete one proof through the minimal delegated lifecycle.

**Status:** resolved

- [ ] `PrecompileWitness::merge(Vec<PrecompileWitness>)` preserves exact input order and duplicate root multiplicity.
- [ ] Empty input is rejected; one singleton input is an identity; every non-singleton input, including an already merged witness, is rejected.
- [ ] Merge enforces fixed `MAX_PRECOMPILE_ROOTS` and `MAX_DEFERRED_ELEMENTS` limits without adding configurable policy.
- [ ] Content-addressed DAG nodes may be deduplicated while importing, but proof-significant root occurrences are never deduplicated.
- [ ] Aggregate-root semantics are an ordered left reduction beginning with the first root, not a fold seeded with `TRUE_DIGEST`.
- [ ] Verification uses membership for each execution’s single VM-authenticated root. The complete ordered metadata, including duplicate occurrences, determines the aggregate root verified by the precompile STARK; compatible extra roots are accepted, and occurrences are not consumed across independent verifications.
- [ ] One `PrecompileProof` generated from `[one, one, two]` can complete and verify both compatible VM proofs without reproving precompile work.
- [ ] Verifier regressions reject empty, excessive, settled, missing, unexpected, uncovered, misordered, insufficient-duplicate, incorrectly folded, and cryptographically invalid precompile artifacts.
- [ ] Merge regressions cover order sensitivity, duplicates, singleton identity, empty input, recursive/non-singleton input, excessive roots, excessive elements, and the distinction between node deduplication and root multiplicity.
- [ ] Delete any alternate merge, coverage, root-folding, or aggregate-validation path made redundant by the authoritative implementation.
- [ ] Do not add batch proof types, batch proving methods, settlement envelopes, aggregate-policy types, generic collection frameworks, adapters, dependencies, feature flags, or compatibility wrappers.
- [ ] Record incremental and cumulative production deltas, public-symbol changes, concept changes, and validity-seam changes against `12fee12d2`.
- [ ] The cumulative production Rust/MASM delta remains strictly net-negative and the public interface strictly smaller. Every production addition must replace more old implementation; otherwise stop and report the blocker.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

No production change was necessary. Existing `PrecompileWitness::merge`, `DeferredState::merge`, `Prover::prove_precompile`, and `Verifier::verify` already preserve ordered metadata, duplicate occurrences, fixed limits, aggregate folding, and stateless single-root membership coverage.

Added one proof-heavy end-to-end tracer bullet: transport two deferred proofs, hydrate both wires, merge `[one, one, two]`, generate one shared precompile proof, attach it through `ExecutionProof::complete` to both compatible executions, and verify both. The same generated artifacts also retain the ticket-02 assertions that deferred verification ignores passive wire and invalid precompile STARKs fail at verification.

Clarified the local specification: duplicate occurrences influence ordered aggregate metadata and the STARK statement, but are not consumed across independent verification calls. Stateful occurrence settlement remains out of scope.

Validation: the single focused `miden-vm` lifecycle test passed with `RAYON_NUM_THREADS=8` and `--test-threads 1`. No other proof-generating tests were run.
