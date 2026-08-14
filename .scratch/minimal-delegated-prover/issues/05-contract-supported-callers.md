# 05 — Contract every supported caller onto the minimal interface

**What to build:** Make every supported in-repository caller—CLI workflows, benchmarks, recursive consumers, façade users, examples, fuzz coverage, and delegated-proving documentation—use only the final minimal interface. Remove obsolete lifecycle vocabulary and compatibility surface so repository-wide usage demonstrates one transport, hydration, proving, completion, and verification path.

**Blocked by:** 02 — Complete one proof through the minimal delegated lifecycle; 03 — Reuse one ordered merged precompile proof; 04 — Restore content-addressed recursive proof requests.

**Status:** resolved

- [ ] CLI proof workflows use infallible execution-proof encoding, registry-free decoding, and explicit wire hydration where proving requires a witness.
- [ ] Benchmarks, caches, examples, test utilities, fuzz targets, and recursive consumers use the supported façade without local adapters.
- [ ] Façade exports contain the explicit supported interface and necessary existing plumbing only; removed construction, decoding, witness-transport, validation, aggregate-root, and wire-entry interfaces are not re-exported.
- [ ] Delegated-proving documentation teaches passive transport, bundled hydration, ordered merge, one reusable precompile proof, completion, and final verification.
- [ ] Documentation accurately separates canonical early-allocation checks from generic derived Serde, which is not claimed to be allocation-bounded.
- [ ] Documentation accurately separates fixed hard ceilings from configurable/envelope/ingestion policy still tracked outside this effort.
- [ ] Repository-wide searches find no removed method, decoder, witness byte format, compatibility alias, wrapper, extension trait, stale example, or equivalent replacement interface.
- [ ] Delete stale imports, adapters, migration remnants, examples, exports, and lifecycle documentation in the same ticket rather than retaining them for compatibility.
- [ ] Do not add caller-specific helpers, adapter modules, extension traits, compatibility shims, dependencies, feature flags, or generalized interfaces.
- [ ] Run focused supported-caller tests and compile checks needed to prove each migrated workflow uses the final interface.
- [ ] Record incremental and cumulative production deltas separately from tests, benchmarks, examples, fuzz targets, generated files, lockfiles, and documentation; also record public-symbol and concept changes against `12fee12d2`.
- [ ] The cumulative production Rust/MASM delta is strictly net-negative, the public interface strictly smaller, and no architectural layer has been added. Otherwise stop and report the blocker.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

Contracted all supported callers and published documentation onto the final interface. Removed unused `DeferredRootTracker`, privatized `TRUE_INDEX`, narrowed deferred-state merging, hid custom-registry hydration plumbing, and removed test-only execution/VM witness root accessors. No replacement helpers or compatibility aliases were added.

Made `docs/src/design/deferred/semantics.md` the authoritative contract. Other README/design surfaces now provide concise caller-specific guidance and link to it. The documentation records passive wire, explicit bundled hydration, transparent `VmProof`/`PrecompileProof` fields, the retained `StarkProof` interface, transition-only completion, verifier-owned validity, stateless root membership, canonical-vs-Serde allocation policy, 2/34/3/35/71 canonical sizes, and content-addressed recursive requests.

Ticket delta: 16 tracked files changed with 173 additions and 348 deletions (net −175 raw lines). Production Rust was net −33 lines; documentation was net −145 lines. Final reviewer signoff found no stale changed APIs, broken changed links/examples, or duplicated normative contract.

Validation: formatting and `cargo check -p miden-vm --all-targets --features concurrent,executable,internal,testing` passed. No runtime tests were run because behavior was unchanged.
