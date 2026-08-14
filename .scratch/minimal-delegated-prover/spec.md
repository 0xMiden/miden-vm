# Minimal Delegated-Prover Interface

Status: ready-for-agent

## Problem Statement

PR #3437 introduced a composable proving lifecycle, but the branch at `origin/adr1anh/prover-api` still exposes a broader and more coupled interface than delegated proving requires. Deferred execution proofs retain hydrated witnesses, proof decoding depends on a precompile registry, canonical encoding can fail, structural policy is split across constructors, decoding, and verification, and witness bytes are treated as a transport format. This makes passive transport, independent precompile proving, and artifact reuse harder to reason about and gives callers multiple overlapping validity seams.

The relaunch must preserve the useful workflow—VM-first proving, passive transport, hydration with bundled semantics, ordered witness aggregation, one reusable precompile proof, completion, and final verification—while minimizing the public interface and keeping security policy at the verification boundary.

The implementation must start cleanly from the fetched `origin/adr1anh/prover-api` tip `12fee12d24b2d7a894e030723d5ef25087e73394`. It must not copy, patch forward, or incrementally clean the detached prototype commits ending at `4b42edb73`; that prototype may be inspected only as behavioral and review evidence. Work on this issue must not commit, push, mutate PR #3437, post review replies, or resolve review threads.

## Solution

Represent deferred work in an execution proof as passive canonical wire data rather than a hydrated witness. Expose one façade hydration function that applies the bundled precompile registry, reconstructs and semantically validates the deferred state, and returns a singleton precompile witness. Allow callers to merge singleton witnesses in exact input order, preserving duplicate obligations, and prove the merged witness once. The resulting precompile proof can complete every compatible deferred execution proof before normal verification.

Keep canonical proof decoding registry-free and encoding infallible. Treat canonical decoding and direct Serde as representation-preserving transport rather than proof validity. Enforce fixed declaration limits early in canonical decoders, but do not claim that generic derived Serde decoding is allocation-bounded.

Make `Verifier::verify` the authoritative structural and cryptographic seam. It validates proof shape, root policy and coverage, aggregate-root folding, proof presence, and each STARK. Successful verification of a deferred proof authenticates only the outstanding VM precompile root; successful verification of a complete proof authenticates that no obligation remains.

Restore the recursive verifier’s content-addressed request packaging: derive the request key from the claim commitment and verifier identity, register the proof package in the advice map, fetch it with `adv.push_mapval`, and call `verify_vm_proof` without copying 40 proof values into claim memory.

## Simplification Mandate

This work is a deletion and simplification project, not an opportunity to redesign the prover system. A behaviorally correct implementation that adds net production code or introduces additional concepts does not satisfy this specification.

The following are hard acceptance gates:

1. **Production code must be net-negative.** Against baseline `12fee12d24b2d7a894e030723d5ef25087e73394`, the final aggregate line delta across affected production Rust and MASM sources must contain more deletions than additions. Tests, benchmarks, examples, fuzz targets, generated files, lockfiles, and documentation are reported separately and cannot offset production growth.
2. **The public interface must strictly shrink.** The final public delegated-prover interface is the explicit interface listed in this specification. Removed public methods, constructors, decoders, accessors, transport formats, and exports must not survive as deprecated aliases, compatibility wrappers, extension traits, or renamed equivalents.
3. **Concept count must not grow.** Do not add proof types, witness types, transport types, registries, configuration objects, policy objects, adapters, traits, modules, lifecycle states, error layers, or architectural seams. The requested hydration function is a façade operation over existing types, not a new abstraction layer.
4. **No pass-through implementation.** Do not add wrappers or helpers that merely forward to another function, rename an existing operation, or relocate complexity without deleting it. Keep a helper only when it hides repeated, non-trivial behavior and reduces total implementation and caller knowledge.
5. **Replace; do not layer.** When responsibility moves to `Verifier::verify`, delete the old constructor, decoder, completion, and artifact validation paths. When wire hydration becomes explicit, delete witness byte transport and registry-aware proof decoding. When direct Serde derives are introduced, delete the custom visitors they replace.
6. **One authoritative seam per concern.** Canonical decoding checks syntax and fixed declaration ceilings. Bundled hydration validates wire semantics. `Verifier::verify` alone validates execution-proof shape, root policy and coverage, aggregate folding, and cryptography. No concern may be checked through a second public path for convenience.
7. **No speculative generality.** Do not add generic registries, configurable limits, batch facilities, reusable policy engines, abstract factories, generic transport frameworks, or extension points for hypothetical callers.
8. **No new dependencies or feature flags.** The simplification must use existing dependencies and feature structure. A new dependency or feature flag fails this specification unless it is technically unavoidable and approved by the user before implementation.
9. **Prefer deletion over accommodation.** Update current in-repository callers to the smaller interface rather than preserving redundant interfaces for compatibility. Preserve only the technically necessary cross-crate plumbing explicitly allowed by this specification, keep it `#[doc(hidden)]`, and do not broaden it.
10. **Do not game the metric.** Net-negative lines are a guardrail, not permission to compress code, combine unrelated statements, remove useful tests or documentation, weaken diagnostics, or make control flow harder to read. The reduction must come from deleting concepts, duplicate checks, custom serialization machinery, redundant transport, and obsolete interface surface.
11. **Stop if simplification is not achieved.** If the final production delta is not net-negative, or if a new concept is believed necessary, implementation is not complete. Report the blocker and obtain explicit user approval; do not rationalize the growth after the fact.

The final report must include a simplification ledger comparing the implementation with `12fee12d2`: production additions and deletions, tests/documentation additions and deletions reported separately, public symbols removed and added, concepts removed and added, and any retained hidden plumbing with its concrete cross-crate caller. The expected result is net deletion, fewer public symbols, fewer validity paths, and no new architectural layer.

## User Stories

1. As an execution prover, I want `Prover::prove` to prove the VM first, so that precompile proving can be delegated independently.
2. As an execution prover, I want an execution with no outstanding precompile work to produce a complete proof immediately, so that callers do not need a special settlement step.
3. As a delegated-proving caller, I want a deferred execution proof to carry passive wire data, so that it can cross process and trust boundaries without carrying hydrated runtime state.
4. As a transport caller, I want execution-proof encoding to be infallible, so that a proof artifact can always be serialized after construction.
5. As a transport caller, I want execution-proof decoding to require only bytes, so that transport is independent of registry selection and runtime hydration.
6. As a transport caller, I want canonical round trips for every proof and wire artifact, so that equivalent artifacts have a deterministic binary representation.
7. As a Serde consumer, I want proof and wire artifacts to use their derived Serde representations, so that there is no parallel visitor implementation to maintain.
8. As a security reviewer, I want canonical decoders to reject oversized declared STARK payloads before allocating their payload buffers, so that malformed declarations cannot bypass the fixed STARK ceiling.
9. As a security reviewer, I want canonical decoders to reject oversized declared root lists before allocating them, so that aggregate-root work is capped at the fixed root ceiling.
10. As a security reviewer, I want canonical deferred-wire decoding to reject oversized declared element collections before allocating them, so that wire transport respects the fixed deferred-state ceiling.
11. As a Serde consumer, I want documentation to avoid promising allocation-bounded generic deserialization, so that direct derives are not mistaken for hardened untrusted-input decoders.
12. As an ordinary Miden VM caller, I want one façade helper to hydrate a deferred wire with the bundled registry, so that I do not need to assemble registry plumbing myself.
13. As an ordinary Miden VM caller, I want hydration to reconstruct and semantically validate the deferred state, so that malformed or invalid wire data cannot become a proving witness.
14. As an API consumer, I want the façade hydration helper to be the only public witness factory, so that all ordinary witnesses enter through one supported validity seam.
15. As a delegated precompile prover, I want hydration to return a singleton witness, so that merge inputs have an unambiguous obligation identity.
16. As a delegated precompile prover, I want to merge a vector of witnesses, so that one precompile proof can cover multiple deferred VM proofs.
17. As a protocol caller, I want merge order to be preserved, so that aggregate roots retain their defined left-fold semantics.
18. As a protocol caller, I want duplicate roots to retain their multiplicity, so that repeated obligations consume repeated proof-root occurrences.
19. As a protocol caller, I want a one-witness merge to be the singleton identity, so that generic collection code does not need a special case.
20. As a security reviewer, I want empty witness merges rejected, so that no synthetic aggregate obligation can be created without an execution root.
21. As a security reviewer, I want non-singleton and recursively merged inputs rejected, so that aggregation has one well-defined level and ordering.
22. As a security reviewer, I want witness merging to enforce the fixed root and hydrated-element ceilings, so that aggregate proving remains bounded.
23. As a delegated precompile prover, I want `Prover::prove_precompile` to accept a valid singleton or merged witness, so that precompile proving is independent of VM proving.
24. As a delegated precompile prover, I want proof metadata construction to be infallible, so that proving cannot fail after a valid STARK and ordered roots already exist.
25. As a delegated-proving caller, I want one precompile proof to be reusable across compatible deferred execution proofs, so that shared precompile work is proved once rather than once per VM proof.
26. As a delegated-proving caller, I want `ExecutionProof::complete` to perform only the deferred-to-complete state transition, so that attachment is separate from verification policy.
27. As an API caller, I want completion of an already-complete proof rejected, so that lifecycle misuse is reported clearly.
28. As an API caller, I want malformed public proof variants to remain representable and transportable, so that decoding does not masquerade as verification.
29. As a verifier caller, I want `Verifier::verify` to reject empty and excessive precompile root lists, so that aggregate metadata is structurally valid.
30. As a verifier caller, I want `Verifier::verify` to reject `TRUE_DIGEST` as a constituent precompile root, so that settled state cannot be presented as an outstanding obligation.
31. As a verifier caller, I want `Verifier::verify` to reject missing precompile proofs for non-settled VM roots, so that outstanding work cannot be silently omitted.
32. As a verifier caller, I want `Verifier::verify` to reject unexpected precompile proofs for settled VM roots, so that completed artifacts have one canonical meaning.
33. As a verifier caller, I want `Verifier::verify` to check VM-root coverage against ordered proof roots with duplicate multiplicity, so that a shared proof authenticates exactly the required obligation occurrences.
34. As a verifier caller, I want compatible extra roots in a shared proof to be accepted, so that one ordered aggregate proof can complete multiple individual deferred proofs.
35. As a verifier caller, I want aggregate roots folded according to the protocol definition before precompile STARK verification, so that proof metadata and the cryptographic statement agree.
36. As a verifier caller, I want VM and precompile STARKs verified at one public seam, so that successful verification has a clear authenticated meaning.
37. As a verifier caller, I want deferred verification to return only the authenticated outstanding VM root, so that an incomplete outcome cannot expose unauthenticated witness or proof state.
38. As a verifier caller, I want complete and fully proved executions to return complete outcomes, so that settled state is easy to distinguish from deferred state.
39. As a library caller, I want `VerificationOutcome` to be root-only and `Copy`, so that it remains a small value result without artifact ownership.
40. As a CLI user, I want proof commands to use infallible encoding and explicit hydration, so that command behavior matches the supported façade.
41. As a benchmark maintainer, I want benchmark fixtures and caches to use the same proof lifecycle and transport API, so that benchmarks exercise supported behavior.
42. As a recursive-verifier caller, I want request inputs keyed by claim commitment and verifier identity, so that proof packages are content-addressed and claim-bound.
43. As a recursive-verifier caller, I want the proof stream registered under the derived request key and fetched through the advice map, so that producer and consumer use one coherent request ABI.
44. As a recursive-verifier caller, I want claim material handled separately from the proof stream, so that proof values are not erroneously copied into claim memory.
45. As a recursive-verifier caller, I want the recursive VM verifier to return the authenticated deferred root, so that recursive VM verification does not pretend to settle precompile obligations.
46. As a documentation reader, I want delegated proving described as transport, hydration, ordered merge, one proof, completion, and final verification, so that examples teach the supported lifecycle.
47. As a reviewer, I want an unposted response packet for every unresolved or stale PR thread, so that the relaunch can answer prior feedback without mutating the existing PR.
48. As a reviewer, I want each packet entry to preserve exact reviewer text, thread state, current code context, disposition, and a copy-ready reply, so that responses are auditable and ready to post later.
49. As a maintainer, I want focused regressions at the public lifecycle seam plus narrow decoder, hydration, merge, verifier, and recursive seams, so that behavior is protected without coupling tests to implementation details.
50. As a maintainer, I want affected-package lint, formatting, and focused tests to pass before relaunch, so that the clean implementation is reviewable.

## Implementation Decisions

- The clean implementation baseline is the fetched `origin/adr1anh/prover-api` commit `12fee12d24b2d7a894e030723d5ef25087e73394`.
- The detached prototype ending at `4b42edb73` is evidence only. Its commits must not be copied, cherry-picked, rebased, or incrementally cleaned into the relaunch.
- The delegated lifecycle is: passive canonical wire transport, bundled-registry hydration, ordered singleton-witness merge, one reusable precompile proof, completion of compatible execution proofs, and final verification.
- `ExecutionProof` retains its public variants and has exactly these lifecycle shapes:
  - `Deferred` contains a VM proof and `DeferredStateWire`.
  - `Complete` contains a VM proof and an optional precompile proof.
- The supported prover façade is `Prover::{prove, prove_full, prove_precompile}`. VM-only proving remains private backend implementation, not a delegated public endpoint.
- `Prover::prove` converts the execution witness’s singleton hydrated deferred state into passive canonical wire before returning a deferred proof.
- `Prover::prove_full` proves directly from the in-memory witness and does not round-trip through wire hydration.
- `Prover::prove_precompile` borrows a singleton or valid ordered-merge witness, creates one precompile STARK, and attaches ordered root metadata infallibly.
- The sole public hydration helper is `precompile_witness_from_wire(&DeferredStateWire)` in the `miden-vm` façade. It uses the bundled precompile registry, rehydrates the state, performs semantic validation, and returns a singleton `PrecompileWitness`.
- Witness byte transport is removed. Callers transport `DeferredStateWire` as part of `ExecutionProof` and explicitly hydrate it when proving is required.
- `DeferredStateWire.entries` is private. `WireEntry` is crate plumbing and is not re-exported as a public construction API.
- `PrecompileWitness::merge(Vec<PrecompileWitness>)` preserves exact input order and duplicate root multiplicity.
- Witness merging rejects empty input, rejects every non-singleton input including recursively merged witnesses, treats a one-element merge as identity, and enforces `MAX_PRECOMPILE_ROOTS` and `MAX_DEFERRED_ELEMENTS`.
- Content-addressed DAG nodes may be deduplicated while merging, but proof-significant root occurrences must never be deduplicated.
- Aggregate-root folding is an ordered left reduction beginning with the first constituent root. It is not seeded with `TRUE_DIGEST`.
- A precompile proof covers the single VM-authenticated root of an individual execution through membership in its ordered root metadata. The full ordered sequence, including duplicate occurrences, determines the aggregate root verified by the precompile STARK. Verification is stateless: occurrences are not consumed across independent executions, and compatible extra roots allow one aggregate proof to complete multiple proofs.
- `ExecutionProof::to_bytes` is infallible.
- `ExecutionProof::read_from_bytes(&[u8])` is registry-free and preserves the represented public variant. The redundant façade decoder is removed.
- `ExecutionProof::{new_deferred, new_complete, validate_structure, precompile_wire}` are removed.
- `ExecutionProof::complete` performs only the deferred-to-complete transition and rejects an already-complete proof. It does not validate proof shape, root equality, root coverage, or cryptography.
- `VmProof` and `PrecompileProof` are transparent, unvalidated transport records with public fields. Their redundant constructors and field accessors are removed. `aggregate_root` and unused `into_parts` are also removed. `StarkProof` keeps its existing private fields, constructor, and accessors; this simplification does not churn the STARK-proof interface.
- `VmProof` and `PrecompileProof` need no cross-crate field-access plumbing because they expose their transport fields directly. `StarkProof` retains its existing interface. Only technically necessary witness accessors remain as `#[doc(hidden)]` backend plumbing.
- `StarkProof`, `VmProof`, `PrecompileProof`, `WireEntry`, and `DeferredStateWire` derive Serde directly. Custom Serde visitors for these artifacts are removed.
- Direct Serde represents artifacts but is not the authoritative validity seam. Generic derived Serde must not be documented as allocation-bounded.
- Canonical decoders retain early declaration checks for `MAX_STARK_PROOF_BYTES`, `MAX_PRECOMPILE_ROOTS`, and `MAX_DEFERRED_ELEMENTS` before allocating the declared collection or payload.
- Canonical minimum encoded sizes remain accurate for transparent transport records: `StarkProof` is 2 bytes, `VmProof` is 34 bytes, and `PrecompileProof` is 3 bytes because an empty-root record is representable until verification. The smallest verifier-valid singleton `PrecompileProof` is 35 bytes. A vector containing two valid singleton precompile proofs has a 71-byte shortest canonical encoding and must decode with that exact budget.
- `Verifier::verify` is the authoritative structural-validity and cryptographic seam. Constructors, completion, canonical decoding, and Serde do not establish proof validity.
- Verification rejects empty or excessive precompile root metadata, `TRUE_DIGEST` constituent roots, a missing precompile proof for outstanding VM work, an unexpected precompile proof for a settled VM root, insufficient or misordered root coverage, incorrect aggregate-root folding, and invalid VM or precompile STARKs.
- Verification of a deferred proof verifies the VM STARK and returns only its authenticated outstanding precompile root. It does not hydrate or validate the passive wire as a witness and does not claim the obligation is settled.
- Verification of a complete proof checks all applicable shape, coverage, folding, and STARK requirements and returns a complete outcome.
- `VerificationOutcome` remains `#[must_use]`, root-only, and `Copy`, with accessors for completion, outstanding root, and any existing root-only verification metadata that remains technically necessary.
- `MAX_PRECOMPILE_ROOTS` remains fixed at 4,096, `MAX_DEFERRED_ELEMENTS` remains fixed at `1 << 20`, and `MAX_STARK_PROOF_BYTES` remains 64 MiB per inner STARK.
- These fixed ceilings are hard library safety limits. Configurable protocol, whole-envelope, ingestion, or lower aggregate resource policy remains separate work tracked by #3458 and must not be claimed as solved here.
- The CLI, benchmarks, recursive input packaging, façade exports, fuzz/round-trip coverage, and delegated-proving documentation are migrated to infallible execution-proof encoding and explicit wire hydration.
- Recursive request input generation is restored around the content-addressed contract: claim commitment and verifier identity derive `proof_request_key`; the proof stream is registered as an advice map value; the consumer fetches it with `adv.push_mapval`; then `verify_vm_proof` verifies it.
- Request packaging leaves the proof stream unchanged, stores the claim preimage separately under the claim commitment, and does not perform the erroneous 40-value advice copy.
- Recursive verification selects the VM proof component and returns its authenticated outstanding deferred root; it does not recursively verify or settle the precompile proof.
- The response packet is generated through read-only PR inspection and remains unposted. It includes every unresolved inline thread and every outdated/stale inline thread, plus relevant non-inline lifecycle and aggregate-policy review comments.
- Each response-packet entry includes reviewer and exact text, resolved/outdated state when GitHub provides it, original and current context, classification as live/implemented/obsolete/resolved, resolution status against the clean implementation, evidence, and a copy-ready reply.
- The packet explicitly covers minimum canonical sizes, merge order and duplicate multiplicity, singleton and recursive-merge rules, ordered coverage, generic Serde allocation limitations, prover lifecycle, fixed versus configurable aggregate-root policy, and recursive request packaging.
- Work on this issue does not commit, push, modify PR #3437, post replies, resolve/minimize threads, or otherwise mutate GitHub review state.
- This issue does not introduce a new architectural layer. Existing crate boundaries are retained, with only the minimal hidden plumbing required to support the façade.
- The implementation must produce a strictly negative production-code line delta against `12fee12d2`; growth in tests or documentation is accounted for separately and cannot satisfy this gate.
- The implementation must delete more public interface than it adds. The only new public operation authorized by this specification is the bundled-registry hydration helper; all other public changes either retain an explicitly listed interface or remove one.
- Every newly introduced private function, type, module, error variant, or accessor must replace duplicated behavior and contribute to a net reduction. A private abstraction that only moves or renames existing complexity is prohibited.
- No compatibility layer is retained for removed constructors, witness serialization, registry-aware proof decoding, the façade decoder, proof-shape validation, aggregate-root access, or `WireEntry` construction/export.
- No new dependency, feature flag, crate, module layer, trait abstraction, configuration object, or generic policy mechanism is introduced.
- The final implementation report includes the required simplification ledger. Missing evidence of net deletion and interface reduction means the issue is incomplete.

## Testing Decisions

- Tests should assert externally observable lifecycle, transport, hydration, merge, verification, and recursive-request behavior. They should not duplicate private prover internals or assert incidental storage layout beyond public canonical-format contracts.
- The highest acceptance seam is an end-to-end delegated regression through the `miden-vm` façade: create two deferred execution proofs, encode and decode them, hydrate both passive wires, merge witnesses in the order `[one, one, two]`, prove the merged witness once, attach the same resulting precompile proof to both compatible execution proofs, and verify both successfully.
- The same end-to-end seam must show that deferred verification returns a root-only incomplete outcome and that completed and `prove_full` proofs return complete outcomes.
- Proof tests cover canonical and direct-Serde round trips for `StarkProof`, `VmProof`, `PrecompileProof`, and every `ExecutionProof` public variant, including representable malformed cross-artifact shapes whose rejection belongs to verification.
- Wire tests cover canonical and direct-Serde round trips for `WireEntry` and `DeferredStateWire` without exposing `WireEntry` as a public construction API.
- Canonical decoder tests declare oversized STARK payloads, precompile-root vectors, and deferred-wire element collections and assert rejection before payload/collection allocation.
- Minimum-size tests assert 2-byte `StarkProof`, 34-byte `VmProof`, 3-byte representable `PrecompileProof`, 35-byte verifier-valid singleton `PrecompileProof`, and successful exact-budget decoding of the 71-byte two-singleton vector.
- Serde tests assert representation round trips only. No test or documentation should infer bounded allocation from a derived generic deserializer.
- Hydration tests call the public façade helper with bundled-registry wires, accept well-formed supported wires, reject malformed canonical structures, reject unknown or semantically invalid bundled precompile data, and return singleton witnesses.
- Public-API coverage confirms no witness byte transport or redundant façade execution-proof decoder remains, `DeferredStateWire.entries` is private, and `WireEntry` is not publicly re-exported as a construction API.
- Merge tests cover empty rejection, one-input identity, exact order sensitivity, duplicate multiplicity, `[one, one, two]`, recursive/non-singleton rejection, excessive root count, and excessive total hydrated elements.
- Merge tests distinguish DAG-node deduplication from root-occurrence multiplicity.
- Precompile proving tests cover singleton and merged witnesses, one proof carrying exact ordered root metadata, and reuse of that proof across multiple compatible execution proofs.
- Completion tests assert only lifecycle behavior: deferred becomes complete and already-complete is rejected. Malformed root coverage is deliberately accepted by attachment and rejected by verification.
- Verifier tests construct public variants directly and reject empty roots, more than `MAX_PRECOMPILE_ROOTS`, `TRUE_DIGEST` roots, missing precompile proof, unexpected precompile proof, uncovered or misordered VM roots, insufficient duplicate multiplicity, incorrect aggregate-root folding, oversized/invalid inner proofs, and cryptographically invalid VM and precompile STARKs.
- Verifier tests accept single-root membership with compatible extra roots, proving that a larger shared precompile proof can complete each covered execution proof independently. Order and duplicate metadata are protected by the aggregate fold and STARK rather than by a stateful occurrence-consumption policy.
- Existing prover route tests continue comparing buffered and overlapped trace construction through supported public behavior.
- Recursive packaging tests verify that native and MASM request-key derivation match, the proof package is registered under the derived key, `adv.push_mapval` retrieves it, claim substitution fails, and no 40-value proof-stream copy occurs.
- The two existing recursive proof-request regressions for equal heights and hash-heavy divergent heights must pass. They currently fail at the fetched PR tip and are not considered resolved until rerun successfully.
- Focused core proof/wire, witness, prover, verifier, and `miden-vm` lifecycle tests run with the repository’s prescribed `cargo nextest` commands and package features.
- Proof-heavy selected tests use `RAYON_NUM_THREADS=8`; multiple proof-heavy tests also use `--test-threads 1` as required by repository workflow guidance.
- The affected packages run Clippy with warnings denied, followed by nightly formatting verification.
- The final change receives a two-axis review against this specification and repository standards. Validation results must be reported accurately; unrelated failures are recorded rather than silently fixed.
- Before validation is considered complete, compare the working implementation to `12fee12d2` and report line additions and deletions for production Rust and MASM separately from tests, benchmarks, examples, fuzz targets, generated files, lockfiles, and documentation.
- The production Rust and MASM subtotal must be strictly net-negative. If it is zero or positive, the implementation fails the simplification gate even when all behavioral tests pass.
- Perform a public-interface audit against `12fee12d2`. List every removed and added public symbol and confirm that no removed interface survives through an alias, wrapper, trait, re-export, or equivalent replacement.
- Perform a concept audit listing added and removed types, modules, lifecycle states, errors, configuration mechanisms, serialization paths, and validity seams. The audit must show fewer concepts overall and no new architectural layer.
- Review every production addition and identify the requirement it implements and the older code it replaces. Additions without a direct requirement and a corresponding deletion are removed.
- Confirm that tests and documentation were not deleted or weakened merely to obtain the negative line delta, and that source formatting or readability was not degraded to game the metric.

## Out of Scope

- Batch proof types or batch proving methods.
- A delegated VM-worker transport API or public `prove_vm` method.
- Custom registry selection in the public `miden-vm` façade.
- Configurable root, element, proof, envelope, or ingestion limits.
- A new protocol settlement envelope.
- Whole-execution-proof byte limits beyond the specified fixed per-component and collection ceilings.
- Resolving the broader resource-policy work tracked by #3458.
- New registry identity models.
- New architectural layers or crate reorganization.
- Making `ExecutionProof` opaque or removing its public variants.
- Additional public API removals inferred beyond the explicit interface trim.
- Replacement Serde fuzzing or claims that generic derived Serde is safe for arbitrary untrusted allocation patterns.
- Recursive verification of precompile STARKs.
- Posting review responses, resolving or minimizing threads, editing PR #3437, committing, pushing, or otherwise publishing implementation changes.
- Refactors whose primary result is moving, renaming, wrapping, generalizing, or reorganizing existing code without deleting behavior or caller knowledge.
- Compatibility shims for any removed interface.
- New helper modules, traits, policy types, adapters, or configuration mechanisms intended to make the design more extensible.
- Any implementation with a zero or positive production-code line delta against `12fee12d2`, unless the user explicitly changes this specification before implementation.

## Further Notes

- This interface-trim specification supersedes the older cleanup brief and the current PR description wherever they conflict.
- The latest fetched branch tip was verified as `12fee12d24b2d7a894e030723d5ef25087e73394` before publication.
- The current PR description still documents witness-carrying deferred proofs, registry-aware proof decoding, fallible witness/proof encoding, and constructor-owned validation; those are not the target interface.
- Review inspection found nine inline threads: five unresolved and four resolved. The required packet includes all five unresolved threads and all five outdated/stale threads; because two categories overlap, that is eight inline packet entries. It also includes the non-inline prover-lifecycle question and aggregate-policy summary.
- Prior review feedback established the numeric minimum canonical sizes, exact merge and coverage semantics, the distinction between hard ceilings and configurable policy, and the recursive request ABI. The clean implementation should preserve those conclusions while applying the newer decisions to derive Serde directly and move structural validity fully into verification.
- All issue-tracker output for this effort stays under `.scratch/minimal-delegated-prover/`. GitHub issues and PR state are changed only when the user explicitly requests it.
- “Minimal” means measurably smaller than `12fee12d2`: fewer production lines, fewer public symbols, fewer concepts, and fewer validity seams. Behavioral equivalence alone is insufficient.
- Ticket generation must carry the Simplification Mandate into every implementation ticket. No ticket may describe additive architecture or leave deletion and interface-reduction work to an unspecified cleanup ticket.

## Comments

- The simplification mandate was strengthened after specification synthesis: net production deletion and strict interface reduction are release gates, not preferences.
