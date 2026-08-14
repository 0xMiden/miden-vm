# 06 — Validate simplification and prepare the local review packet

**What to build:** Prove that the completed relaunch is behaviorally correct and measurably simpler than `12fee12d2`, then prepare a complete, unposted local response packet for the existing PR review history. This ticket validates prior deletion work; it must not become a deferred cleanup or a place to add architecture.

**Blocked by:** 05 — Contract every supported caller onto the minimal interface.

**Status:** resolved

- [x] Run the two recursive proof-request regressions and the focused core proof/wire, witness, prover, verifier, and `miden-vm` lifecycle tests using the repository-prescribed `cargo nextest` commands and package features.
- [x] Use `RAYON_NUM_THREADS=8` for selected proof-heavy tests and `--test-threads 1` when multiple proof-heavy tests run together, following repository workflow guidance.
- [x] Run affected-package Clippy with warnings denied and `cargo +nightly fmt --all --check`.
- [x] Run a two-axis review against repository standards and the complete local specification.
- [x] Produce the final simplification ledger against `12fee12d2`, reporting production Rust/MASM additions and deletions separately from tests, benchmarks, examples, fuzz targets, generated files, lockfiles, and documentation.
- [x] The production Rust/MASM subtotal is strictly net-negative. Zero or positive fails the effort even if all behavioral tests pass.
- [x] Audit the public interface: list every removed and added public symbol and confirm that removed interfaces do not survive through aliases, wrappers, traits, re-exports, deprecations, or renamed equivalents.
- [x] Audit concepts and seams: list added and removed types, modules, lifecycle states, errors, configuration mechanisms, serialization paths, and validity seams; demonstrate fewer concepts overall and no new architectural layer.
- [x] Audit every production addition, identify its requirement and the larger old implementation it replaced, and remove additions with no direct requirement and corresponding deletion.
- [x] List every retained `#[doc(hidden)]` accessor and its concrete cross-crate caller; remove any plumbing without a demonstrated caller.
- [x] Confirm that tests and documentation were not weakened or deleted to obtain the negative delta and that formatting or control flow was not compressed to game the metric.
- [x] Through read-only PR inspection, prepare one unposted packet entry for every unresolved or outdated/stale inline thread, plus relevant non-inline lifecycle and aggregate-policy review comments.
- [x] Every packet entry includes exact reviewer text, author, resolved/outdated state when available, original and current context, live/implemented/obsolete/resolved classification, evidence, resolution status against current code, and a copy-ready reply.
- [x] The packet explicitly covers 2/34/35-byte proof minima, the 71-byte two-proof vector, merge ordering and duplicates, singleton/recursive-merge rules, ordered coverage, generic Serde allocation limitations, prover lifecycle, fixed versus configurable aggregate-root policy, and recursive request packaging without the 40-value copy.
- [x] Store the simplification ledger and response packet only in the local effort workspace; do not post them or mutate GitHub.
- [x] If any simplification gate fails, reopen the relevant blocking ticket or report the blocker. Do not add a cleanup abstraction or rationalize net growth in this validation ticket.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

The final local evidence is stored in `../simplification-ledger.md` and
`../review-response-packet.md`. Against `12fee12d2`, semantic production Rust/MASM is
`+230 / -1,102 = -872`; all tracked categories total `+775 / -2,280 = -1,505`. Against the
whole-feature parent `5deb424f3`, semantic production is narrowly net-negative at
`+1,386 / -1,397 = -11`; the ledger records the embedded-test classifier and the positive naive
path-only count explicitly.

The review packet covers the 10-thread unresolved/outdated union and two relevant non-inline
comments. It remains local and unposted. No GitHub state was changed.

Validation passed for the two recursive proof-request regressions, focused core/wire/witness/prover/
verifier and delegated lifecycle regressions, the shared `[one, one, two]` proof lifecycle, the two
final proof-heavy lifecycle smoke tests, the standalone proof trailing-byte regression, and the
cumulative merge element-limit regression. The final
`RUSTFLAGS="-D warnings" cargo +stable xclippy && cargo +nightly fmt --all --check` command passed.
Both final blocker-only reviewers reported no release blockers.

Local commits are unsigned because the configured signing agent was unavailable. No changes were
pushed, and PR #3437, its replies, and its review threads were not modified.
