# Miden Precompiles Plan

This document tracks the `miden-precompiles` work across the stacked branches built on top of
#3170 (`adr1anh/deferred/framework`). It records the design context, decisions already made, and
the intended sequencing so each branch can stay reviewable.

## Context

The deferred framework work started with two related branches:

- #3170 (`adr1anh/deferred/framework`) adds the generic deferred-DAG framework in
  `miden_core::deferred` and aligns the existing `LOGPRECOMPILE` transcript fold with the
  framework `AND` domain.
- #3172 (`adr1anh/deferred/migrate`) migrates production precompiles to the deferred-DAG proof
  model, but it does so by moving concrete production semantics into `miden-core-lib`.

Issue #2282 points in a different long-term direction: concrete precompile and PVM work should
have a first-class top-level crate. The generic framework belongs in `miden-core`, while concrete
precompile semantics, MASM wrappers, registries, and later PVM proving work should live in
`miden-precompiles`.

The current plan is therefore to treat #3172 (`adr1anh/deferred/migrate`) as source material, not
as the final branch shape. We are rebuilding that migration in smaller branches on top of
#3170 (`adr1anh/deferred/framework`) and the `precompiles/crate` scaffold.

We considered moving the legacy request-list production precompiles into `precompiles/` before
adopting the deferred framework. We rejected that sequence because it would create a throwaway
crate boundary around the old `PrecompileRequest` / `PrecompileVerifier` architecture, add
unnecessary dependency pressure, and then immediately rewrite the same code into deferred-DAG
semantics.

## Resolved Decisions

- Use a top-level `precompiles/` crate, not `crates/precompiles/`.
- Cargo package name: `miden-precompiles`.
- MASM package name: `miden-precompiles`.
- MASM namespace: `miden::precompiles`.
- Use the current package abstraction, not the removed MASM `Library` abstraction:
  `miden-project.toml`, `Package`, `Package::write_masp_file`, embedded `.masp`,
  `package() -> Arc<Package>`, and `mast_forest()`.
- `miden-core` owns the generic deferred framework:
  `Tag`, `Node`, `Payload`, `DeferredState`, `DeferredStateWire`, `Precompile`,
  `PrecompileRegistry`, and generic processor/system-event machinery.
- `miden-precompiles` owns concrete deferred precompile semantics, MASM wrappers, registries, and
  future PVM work.
- The processor remains generic. It should carry installed registries and update deferred state,
  but it should not know which concrete precompiles exist.
- It is acceptable on this tracking branch to duplicate the generic deferred MASM helpers under
  `miden::precompiles::sys` instead of introducing a MASM package dependency on
  `miden::core::sys` or moving helpers immediately.
- The keccak256 + sha512 hash family is the first concrete vertical slice, landing together so the
  shared base has two real consumers. It exercises chunks, deferred evaluation/logging, registry
  installation, and MASM package loading without the extra complexity of signature precompile
  layouts.
- The hash precompiles share a generic base (a `HashFunction` trait + `HashPrecompile<H>`); each
  hash is a thin spec (name, digest width, byte-level hash) plus a MASM wrapper.
- The canonical digest node uses a uniform `ceil(DIGEST_FELTS / 8)`-chunk encoding for every width
  (256-bit → one chunk, 512-bit → two), so there is no `Value`-vs-`Chunks` special case.
- MASM hash wrappers write the digest to a caller-provided memory pointer
  (`[out_ptr, ...] -> [...]`), keeping the operand stack net-neutral, and share a `register_preimage`
  helper under `miden::precompiles::crypto::hashes`.
- Processor/prover/verifier proof-wire support comes after the first concrete precompile package
  slice. That gives the proof plumbing a small real vertical test instead of abstract-only
  coverage.
- #3176 (`al/ecdsa-k256-on-vm`) stays independent for now. It is later source material for K1,
  SZ-modmul, and ECDSA work.
- PVM AIR/trace/proving work from `precompile-experiments` is deferred until the crate/package and
  proof-wire boundaries are stable.

## Current Scaffold: `precompiles/crate`

This branch establishes the crate and package boundary without migrating any production
precompile.

Completed:

- Added the `miden-precompiles` Rust crate under top-level `precompiles/`.
- Added a buildable MASM package `miden-precompiles` under `precompiles/asm`.
- Exported the namespace `miden::precompiles`.
- Added `PrecompilesLibrary`, which embeds and loads `miden-precompiles.masp`.
- Added `package()`, `mast_forest()`, `Default`, `AsRef<Package>`, and
  `From<&PrecompilesLibrary> for HostLibrary`.
- Added an empty `registry() -> PrecompileRegistry`.
- Duplicated deferred MASM helpers under `miden::precompiles::sys`:
  `register_expr`, `register_data`, `log_node_digest`, and the legacy request-list helper
  `log_precompile_request`.
- Added focused package smoke tests for deserialization, exported paths, dynamic linking, and host
  loading.

Explicitly not done here:

- No concrete precompile migration.
- No `ExecutionProof` changes.
- No `verify_with_precompiles`.
- No proof-wire plumbing.
- No legacy request-list deletion.
- No #3176 (`al/ecdsa-k256-on-vm`) material.
- No PVM AIR/proving import.

## Planned Stack

```text
#3170 (`adr1anh/deferred/framework`)
└── precompiles/crate
    └── precompiles/hash
        └── precompiles/proof-wire
            └── precompiles/signatures
                └── precompiles/remove-legacy
```

This stack can be adjusted as the work unfolds, but each branch should remain a coherent review
unit.

## Branch Scopes

### `precompiles/hash`

Port the Keccak-256 and SHA-512 deferred precompiles from #3172
(`adr1anh/deferred/migrate`) into `miden-precompiles`, on a shared hash-precompile base.

In scope:

- Shared byte/chunk codec and a generic hash-precompile base (a `HashFunction` trait +
  `HashPrecompile<H>`); each hash is a thin spec.
- `Keccak256Precompile` and `Sha512Precompile`; `registry()` installs both.
- MASM wrappers under `::miden::precompiles::crypto::hashes::{keccak256,sha512}`, sharing a
  `register_preimage` helper and writing the digest to a caller-provided memory pointer.
- Uniform `ceil(DIGEST_FELTS / 8)`-chunk digest encoding.
- Focused tests for Rust semantics, registry installation, package exports, dynamic linking, and
  execution/deferred-state behavior.

Out of scope:

- ECDSA or EdDSA.
- Proof-wire support.
- Legacy request-list deletion.
- #3176 (`al/ecdsa-k256-on-vm`) material.

### `precompiles/proof-wire`

Add the generic proof-model cutover using the hash package slice as the real vertical test.

In scope:

- `ExecutionProof` carries `DeferredStateWire`.
- Trace/prover serializes final deferred state under the registry used during execution.
- Verifier rehydrates the wire under a supplied `PrecompileRegistry`.
- `miden-vm` API/CLI support for loading `PrecompilesLibrary` where needed.
- End-to-end prove/verify coverage for a program using a hash precompile (keccak256 or sha512).

Out of scope:

- Adding concrete precompiles beyond the hash family.
- #3176 (`al/ecdsa-k256-on-vm`) material.
- PVM proof import.

### `precompiles/signatures`

Port the migrated ECDSA-k256-keccak and EdDSA-Ed25519 deferred precompiles from
#3172 (`adr1anh/deferred/migrate`).

Design intent: these two signatures are deliberately minimal. Each is a single opaque `verify`
predicate that defers the entire check to a host-side `miden-crypto` call — a placeholder for the
eventual decomposition into raw elliptic-curve group precompiles, at which point `verify` becomes a
DAG of group-operation nodes rather than one host call. This crate is a work-in-progress testbed for
the precompile VM, so the signature surface stays bare-bones (just `verify_prehash`); richer,
ergonomic wrappers (`verify` and friends) are layered on once the group precompiles and the
cross-package MASM-helper story exist. Simplifications that keep the core predicate logic easy to
iterate are preferred over completeness.

Completed:

- `EcdsaK256KeccakPrecompile` and `EddsaEd25519Precompile` Rust semantics under
  `precompiles/src/dsa`, each a single `verify` predicate over a fixed 5-chunk (40-felt) calldata
  buffer (`pk || digest || sig`), reusing the shared byte/chunk codec.
- Preserved the migration hardening: `decode` rejects nonzero unused tag args, ECDSA rejects nonzero
  pad regions, and the codec rejects non-canonical (nonzero trailing-pad) witnesses.
- `verify_prehash` MASM wrappers under
  `::miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}`: register the buffer as the
  `verify` data node (digest derived in-circuit, predicate evaluated eagerly so a bad signature traps
  during `register_data`) and fold the node digest into the deferred root. Eager registration makes
  a separate `adv.evaluate_deferred` step unnecessary.
- `registry()` installs both signatures; focused Rust semantic tests, MASM id-pinning tests, package
  export tests, and execution tests (valid signature verifies and advances the deferred root;
  tampered signature traps).

Deferred:

- The high-level `verify` wrappers (commit the public key via `poseidon2::hash_elements`, hash the
  message, assemble the buffer, then call `verify_prehash`). They depend on `poseidon2::hash_elements`
  and `word::store_word_u32s_le`, which live in the `miden::core` MASM package; the standalone
  `miden::precompiles` package would have to either depend on `miden::core` or duplicate those
  helpers. That cross-package-helper decision is tracked under Open Questions and is left for a
  follow-up.

Out of scope:

- #3176 (`al/ecdsa-k256-on-vm`) K1/SZ optimizations.
- PVM proof work.

### `precompiles/remove-legacy`

Remove the old production request-list precompile path after replacement branches are working.

In scope:

- Remove legacy production `PrecompileRequest` proof witness plumbing.
- Remove old production request handlers for Keccak, SHA-512, ECDSA, and EdDSA.
- Remove stale request-list fuzz targets and docs.
- Update examples/docs to point at `miden-precompiles`.

Out of scope:

- New concrete precompile implementations.
- PVM proof work.

### Later: #3176 (`al/ecdsa-k256-on-vm`)

Use #3176 (`al/ecdsa-k256-on-vm`) as source material after the migrated production precompile
stack is stable. That branch is valuable for more than native secp256k1 ECDSA: it is also a
worked example of how to make advice-heavy arithmetic production-grade by combining a narrow public
MASM interface, host hints, in-VM binding checks, generated arithmetic verifiers, and adversarial
tests.

Likely work:

- K1 field/scalar/group MASM helpers.
- SZ-modmul codegen.
- Native secp256k1 ECDSA support.
- Deciding which pieces belong as reusable MASM helpers versus concrete PVM-backed precompile
  logic.

Interesting pieces to port or adapt:

- **Hint-and-check arithmetic pattern.** The SZ modular multiplication verifier checks host-supplied
  quotient/result/carry witnesses in the VM instead of trusting advice. U256 deferred wrappers use a
  similar discipline at the DAG boundary: any wrapper that consumes advice should re-register the
  advised value and log an equality predicate tying it to the original digest.
- **Generated verifier code for repetitive arithmetic.** The `miden-sz-codegen` approach keeps
  repetitive MASM verifier logic reproducible and pinned by structural tests. If U256 gains native
  modular operations, division witnesses, or field-specific reductions, generate the checker MASM
  rather than hand-maintaining long stack programs.
- **Transcript pinning.** The SZ checker precomputes modulus-specific transcript state and then
  absorbs only per-instance witnesses online. Deferred wrappers should follow the same principle:
  tags, precompile ids, and fixed statement shape are pinned in MASM constants/tests; only dynamic
  operands and witnesses are streamed.
- **Advice trap suites.** The K1 branch tests mutated witness paths directly (bad decompression,
  invalid carries, malformed modmul witnesses). Every advice-consuming precompile wrapper should
  have negative tests that mutate each advice segment independently and assert execution traps or
  deferred verification fails.
- **Layered MASM API.** The K1 branch separates scalar, base-field, point, and signature helpers.
  For U256 this argues for keeping digest-level arithmetic wrappers small and adding reusable lower
  layers only when they serve multiple precompiles (for example modular U256, field-specific U256,
  or group-coordinate wrappers).
- **Codegen pin tests.** Generated or pinned MASM constants should be checked against Rust-derived
  values. For U256 this includes precompile ids, tag discriminants, constant digests, and any future
  generated verifier body hashes or fixture snapshots.

### Later: PVM Proof Work

Port PVM AIR/trace/proving work from `precompile-experiments` after the crate/package/proof-wire
boundary is stable.

Likely work:

- PVM chiplets and relation registry.
- Trace and witness generation.
- PVM proof production and verification.
- Integration between final deferred state/wire commitments and PVM proofs.

## Testing Policy

Tests should match the branch layer.

- `precompiles/crate`: package deserialization, export lookup, dynamic linking, host loading, and
  empty-registry smoke tests.
- Concrete precompile branches: focused Rust semantics, registry installation, MASM package export,
  dynamic linking, and execution/deferred-state tests.
- `precompiles/proof-wire`: prove/verify tests using one concrete precompile, initially Keccak.
- Later branches should add tests for their own concrete precompile only.

For every precompile with MASM wrappers, use the following test ladder:

1. **Pure Rust semantics.** Unit-test tag decoding, canonical payload validation, successful
   evaluation, and error cases (bad tag args, malformed payload, missing children, failed
   predicate, divide-by-zero, bad signature, etc.). These tests should not assemble MASM.
2. **Pinned interface constants.** Assert MASM precompile ids, tag ids, constant digests, and any
   generated verifier snapshots match the Rust source of truth. This catches silent drift in public
   stack contracts.
3. **Package exports and linking.** Assert each public wrapper path exists in the compiled package,
   can be dynamically linked by the assembler, and can be loaded into `DefaultHost`.
4. **Wrapper happy paths.** Execute small programs on `FastProcessor` with the real
   `PrecompilesLibrary` and `registry()`. Check the user-visible stack/memory contract and inspect
   deferred state when useful (registered original node, canonical node, logged equality root).
5. **Advice binding and negative paths.** For wrappers that call `adv.evaluate_deferred`,
   `adv.register_deferred_data`, or precompile-specific advice events, add tests that tamper with
   each advice segment or registered memory region and assert that execution traps or deferred
   verification rejects. This is the main lesson from the K1/SZ tests: every host hint needs an
   independent in-VM binding check and a regression test proving the binding is live.
6. **Proof-wire coverage.** Once proof-wire support is in place, keep at least one prove/verify test
   per precompile family and one negative wire/statement test. Do not duplicate every vector from
   Rust and wrapper layers at proof level.
7. **Generated-code tests.** If a wrapper or verifier is generated, include structural tests for the
   generator, checked-in snapshot/pin tests for generated MASM, and one end-to-end execution test
   proving the generated procedure is callable.

Avoid:

- Exhaustive duplicate vector suites in every layer.
- Wrapper tests that only prove the program does not trap while ignoring stack/memory/deferred-state
  outputs.
- Trusting advice in tests without a matching tamper case.
- Vacuous error tests that only assert an obvious rejection round-trips.
- Proof tests before the proof-wire branch.
- Broad workspace churn in narrow precompile slices.

## Open Questions

- Where should duplicated MASM deferred helpers eventually live?
- Should `::miden::core` retain compatibility aliases for moved precompile wrappers?
- What is the final `miden-vm` API/CLI shape for loading `PrecompilesLibrary`?
- When should `verify_with_precompiles` become public versus hidden behind higher-level package
  loading?
- How should PVM proof APIs attach once `precompile-experiments` is ported?
- When, if ever, should `miden-precompiles` split into smaller crates?
