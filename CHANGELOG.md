# Changelog

## v0.28.0 (unreleased)

#### Changes

- [BREAKING] Renamed module and kernel metadata APIs from `ModuleInfo`/`Kernel` to `ModuleDescriptor`/`KernelDescriptor`, including matching module descriptor method names ([#3356](https://github.com/0xMiden/miden-vm/pull/3356)).
- Aligned workspace crate versions at `0.28.0`, except `midenc-hir-type`, so VM and crypto crates release as one version line.
- Imported the Miden crypto crates, benches, fuzz targets, and Wycheproof tests into this workspace ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- [BREAKING] Restored `AeadPoseidon2::key_from_bytes` to upstream canonical-Felt decoding. The SHA-256 KDF that briefly appeared on this branch is removed; keys persisted under the KDF contract must be re-derived ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Restored the `ExactSizeIterator` impl on `miden-serde-utils::ReadManyIter`, matching upstream, and corrected `size_hint` to advertise the exact remaining count ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Documented the `SharedSecret` zeroization contract on the k256 and x25519 ECDH paths: the type now holds owned `[u8; 32]` bytes and zeroizes on drop ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Hardened `Randomizable::from_random_bytes` to return `None` on short slices instead of panicking ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Capped `BudgetedReader::max_alloc` at `0` for zero-sized elements, so a length-prefixed `Vec<ZST>` can no longer claim `u64::MAX` elements (deliberate, documented divergence from upstream) ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Split package serialization assembly tests into their own module ([#3083](https://github.com/0xMiden/miden-vm/pull/3083)).
- Added the `miden-precompiles` crate with the official deferred precompile registry used by the VM/prover/verifier path ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Migrated proof-bound precompiles to the deferred-DAG proof wire. `ExecutionProof` now carries a `DeferredStateWire`, proof serialization is incompatible with previous proof-bound precompile requests, and verification rehydrates the wire under the built-in `miden_precompiles::registry()` before binding the resulting deferred root to the STARK public inputs ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Replaced the legacy proof-bound precompile request/transcript model with the deferred-DAG framework in `miden_core::deferred`; the old request/transcript API has been removed in favor of `Node`, `Tag`, `DeferredState`, `DeferredStateWire`, `Precompile`, and `PrecompileRegistry` ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Replaced precompile request count/calldata execution limits with deferred-state element budgeting. Use `ExecutionOptions::with_max_deferred_elements(...)` and `verify_with_max_deferred_elements(...)` for non-default deferred-state budgets ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Removed the `miden::core::crypto::dsa::eddsa_ed25519` MASM module, Rust handler, docs, and tests. EdDSA support is temporarily removed from core-lib and will be reintroduced once it is supported by the precompiles prover ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Removed the `miden::core::crypto::hashes::sha512` MASM module, Rust handler, docs, and tests. SHA-512 support is temporarily removed from core-lib and will be reintroduced once it is supported by the precompiles prover ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Changed the `miden::core::crypto::dsa::ecdsa_k256_keccak` advice/signature ABI to `QX[8] || QY[8] || SIG_R[8] || SIG_S[8]` as little-endian u32 field elements. Existing 65-byte signature advice must be re-encoded as `(r, s)` limbs without a recovery byte ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Removed the public `miden::core::crypto::dsa::ecdsa_k256_keccak::verify_prehash` and raw `miden::precompiles::crypto::dsa::ecdsa_secp256k1::assert_verify_prehash` ECDSA prehash verifier entrypoints. ECDSA K256 Keccak verification is now exposed only through the high-level `verify` procedure, whose implementation inlines the verifier, loads signature scalars directly from advice, and avoids the raw prehash memory ABI ([#3222](https://github.com/0xMiden/miden-vm/pull/3222)).
- [BREAKING] Split Poseidon2 permutation rows out of `ChipletsAir` into `Poseidon2PermutationAir`, and updated the recursive verifier ACE registry for three AIRs ([#3345](https://github.com/0xMiden/miden-vm/pull/3345)).
- [BREAKING] Optimized the recursive verifier MASM by changing `fri_ext2fold4` to accept a natural coset index and return a loop-ready stack layout for FRI layer folding ([#3349](https://github.com/0xMiden/miden-vm/pull/3349)).
- [BREAKING] Add missing constraint in Bitwise chiplet ([#3386](https://github.com/0xMiden/miden-vm/pull/3386)).
- [BREAKING] Fixed a soundness gap in the chiplets AIR where a chiplet section's first-row initialization was skipped when the preceding section was empty. A program that uses memory but performs no `u32and`/`u32xor` operations produces an empty bitwise section, which caused the memory chiplet to skip its "values not being written must be zero" reset; a malicious prover could exploit this to forge a read of never-written memory. Each section's first row is now identified from the chiplet selectors at the boundary rather than from the previous chiplet's last row, so the initialization holds no matter which preceding sections are empty. The ACE section-start reset was hardened the same way as a precaution ([#3387](https://github.com/0xMiden/miden-vm/pull/3387)).
- [BREAKING] Optimize periodic columns evaluation for fewer ACE gates ([#3347](https://github.com/0xMiden/miden-vm/pull/3347)).
- Added `Package::get_export_node()` and `Package::procedures_with_attribute()` APIs ([#3320](https://github.com/0xMiden/miden-vm/issues/3320)).

#### Fixes

- Validated `SectionId` on deserialization: `Section::read_from()` now rejects invalid identifiers and the `serde` path delegates to `FromStr`, keeping both readers on the same invariant ([#3277](https://github.com/0xMiden/miden-vm/pull/3277)).
- Fixed `hash_elements_in_domain(&[], d)` colliding with `hash_elements_in_domain(&[ZERO; RATE_WIDTH], d)` for nonzero `d`, by absorbing a `ONE` padding marker on the empty-input branch ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Fixed `hash_bytes(&[])` returning `Word::default()`; the empty-bytes input now absorbs a padding marker and permutes, producing a nonzero digest consistent with the 10\* sponge padding rule ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Fixed a latent `CryptoBox` (IES) key-derivation bug: HKDF-SHA256 output is now reduced into canonical Felts via `AeadScheme::key_from_uniform_bytes` instead of being fed into canonical decoding, which rejected noncanonical limbs at ~2^-30 per key ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Hardened `AeadPoseidon2` and `XChaCha` decrypt paths against malleable ciphertexts by rejecting trailing bytes after a valid `EncryptedData` encoding ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Hardened Falcon signature deserialization against short buffers and rejected trailing bytes in `SignaturePoly::read_from_bytes` ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Fixed `ReadAdapter` buffer position not being reset when the local buffer drained to empty during `read_slice` ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Restored compact SMT serialization budgets so an empty-subtree-only `NodeValue` can be read under a tight budget ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Built the crypto SVE archive from target cfg (`CARGO_CFG_TARGET_ARCH` / `CARGO_CFG_TARGET_FEATURE`) instead of `#[cfg(target_feature = "sve")]`, which does not fire in build scripts ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).
- Qualified the word-wrapper derive macro's emitted `String` as `alloc::string::String` and wrapped the impl in `const _: () = { extern crate alloc; ... }` for `no_std` and `#![no_implicit_prelude]` consumers ([#3366](https://github.com/0xMiden/miden-vm/pull/3366)).

## miden-vm v0.25.5 (2026-07-16)

- Use `Package::read_from_bytes_trusted` when loading preassembled packages from registry/cache during project assembly

## miden-vm v0.25.4 (2026-07-16)

- Add package post-processing hooks to the `ProjectSourceProvider` trait ([#3375](https://github.com/0xMiden/miden-vm/pull/3375)).
- Expose some assembler configuration methods, and `ProjectAssembler::assemble_source_project` ([#3383](https://github.com/0xMiden/miden-vm/pull/3383)).

## miden-vm v0.25.3 (2026-07-12)

- Update `wincode` dependency to v0.5.5.

## miden-vm v0.25.2 (2026-07-11)

- Support constructing initial `ResumeContext` for execution stepping from a `Package`, in order to ensure debug context is correctly initialized

## miden-vm v0.25.1 (2026-07-10)

- `ResumeContext` now makes the debug info it carries available to users beyond the `miden-processor` crate itself ([#3355](https://github.com/0xMiden/miden-vm/pull/3355))

## miden-vm v0.25.0 (2026-07-09)

#### Changes

- Added a Blake3 pure execution benchmark axis and reduced processor benchmark compile time by relaxing forced inlining in execution helpers ([#3289](https://github.com/0xMiden/miden-vm/pull/3289)).
- Documented that `smt::peek` is a fast, untrusted advice lookup, and that caller code must verify the returned value before relying on it ([#3297](https://github.com/0xMiden/miden-vm/pull/3297)).
- Clarified MAST node equality coverage by using structural `PartialEq` directly in merge tests ([#3298](https://github.com/0xMiden/miden-vm/pull/3298)).
- Documented the `sorted_array` lookup sortedness contract and added linear assertion helpers for proving word, key, and half-key ordering ([#3308](https://github.com/0xMiden/miden-vm/pull/3308)).
- Tightened LogUp lookup AIR docs and comments, removed unused operation-flag accessors, and added block-hash/op-group selector coverage ([#3309](https://github.com/0xMiden/miden-vm/pull/3309)).
- [BREAKING] Optimize constraint evaluation step by dropping redundant transition guards on op-flag-gated constraints ([#3319](https://github.com/0xMiden/miden-vm/pull/3319)).
- Fixed a panic (or silent miscompile in release builds) when assembling a procedure declaring more locals than the maximum representable during frame-pointer codegen; such procedures are now rejected with a diagnostic error ([#3332](https://github.com/0xMiden/miden-vm/pull/3332)).
- [BREAKING] Bound dense `MastForest` and package digests to stored roots, external dependencies, and advice, rejected non-canonical dense forest payloads, and moved dense forest construction to `DenseMastForestBuilder` ([#3334](https://github.com/0xMiden/miden-vm/pull/3334)).
- Made `make clippy` and `make lint` deny warnings so local linting fails on the same Clippy warnings as CI ([#3257](https://github.com/0xMiden/miden-vm/issues/3257)).
- [BREAKING] Optimize constraint evaluation step by merging one-hot gated stack op constraints ([#3333](https://github.com/0xMiden/miden-vm/issues/3333)).
- [BREAKING] Removed `MastForest::compact`; MAST construction should deduplicate through builders or explicit `MastForest::merge` calls instead ([#3318](https://github.com/0xMiden/miden-vm/pull/3318)).
- [BREAKING] Changed the ECDSA K256 Keccak public key commitment format to use affine public key coordinates (`qx_le_u32[8] || qy_le_u32[8]`) instead of compressed SEC1 public key bytes, aligning the core wrapper with the `miden-crypto` commitment format discussed in [0xMiden/crypto#1075](https://github.com/0xMiden/crypto/issues/1075). Existing public key commitments must be regenerated with `PublicKey::to_commitment()` ([#3342](https://github.com/0xMiden/miden-vm/pull/3342)).

## miden-crypto v0.28.0 (2026-07-03)

- Added a zeroizing read helper for deserializing sensitive material, fixing secret-key read buffers that were not wiped on error paths (ECDSA) or at all (Falcon, Poseidon2 AEAD) ([#1057](https://github.com/0xMiden/crypto/pull/1057)).
- [BREAKING] Rename miden-lifted-stark `parallel` feature to `concurrent` and make it a default one ([#1073](https://github.com/0xMiden/crypto/issues/1073)).
- Parallelize aux trace building for faster proving ([#1074](https://github.com/0xMiden/crypto/issues/1074)).
- [BREAKING] Changed ECDSA-k256 public-key commitments to hash native affine-coordinate limbs (`qx || qy`, little-endian `u32` limbs) while keeping compressed SEC1 serialization unchanged ([#1075](https://github.com/0xMiden/crypto/issues/1075)).
- Fixed SMT leaf advice decoding by rebuilding decoded entries through `SmtLeaf::new`, so decoded entries must match the supplied leaf index ([#1076](https://github.com/0xMiden/crypto/pull/1076)).
- Made `Felt::from_{u8, u16, u32}` const and added `Felt::MAX` ([#1081](https://github.com/0xMiden/crypto/pull/1081)).

## miden-vm v0.24.2 (2026-07-01)

- Reduced optimized benchmark build time by relaxing forced inlining in processor execution helpers ([#3292](https://github.com/0xMiden/miden-vm/pull/3292)).
- Added no-op handlers for readonly debugger events to `CoreLibrary::handlers`, so hosts that load the core library can execute programs emitting those events without registering no-op handlers manually ([#3305](https://github.com/0xMiden/miden-vm/pull/3305)).
- Added trusted sparse MAST forest serialization for trace replay payloads ([#3313](https://github.com/0xMiden/miden-vm/pull/3313)).

## miden-vm v0.24.0 (2026-06-24)

#### Enhancements

- Brought the core-lib `u256` module to full parity with the `u64` and `u128` modules ([#3167](https://github.com/0xMiden/miden-vm/pull/3167)).
- Added an event-based `miden::core::debug` module providing `print_*` procedures for print-style debugging of the operand stack, memory, advice stack, and advice map ([#3169](https://github.com/0xMiden/miden-vm/issues/3169)).
- Added `miden::core::debug::print_mem_addr` for printing a single memory cell (combine with `locaddr` to print a procedure local) ([#3203](https://github.com/0xMiden/miden-vm/issues/3203)).
- Exposed a new parser function for parsing inline MASM blocks as CST or AST. ([#3211](https://github.com/0xMiden/miden-vm/pull/3211)).
- Project assembly can now be extended with support for source languages other than MASM via `ProjectSourceProvider` implementations ([#3216](https://github.com/0xMiden/miden-vm/pull/3216)).
- Added enum and `u256` records to `.debug_types` metadata so debuggers can preserve those type identities ([#3227](https://github.com/0xMiden/miden-vm/pull/3227)).
- Added `do <block> while <cond> end` syntax ([#3232](https://github.com/0xMiden/miden-vm/pull/3232)).

#### Changes

- Aligned replay stack word access bounds with `StackInterface`, allowing the maximum valid start index for word reads and writes ([#3014](https://github.com/0xMiden/miden-vm/pull/3014)).
- [BREAKING] Split the execution AIR into Core + Chiplets AIRs ([#3115](https://github.com/0xMiden/miden-vm/pull/3115)).
- Improved performances of auxiliary trace generation ([#3119](https://github.com/0xMiden/miden-vm/pull/3119)).
- [BREAKING] Simplified `MastForestBuilder` around builder-local refs and immutable finalized `MastForest`s ([#3139](https://github.com/0xMiden/miden-vm/pull/3139)).
- [BREAKING] Enabled `clippy::unnecessary_wraps` lint and removed all unnecessary `Option`/`Result` wrappings across the workspace ([#3143](https://github.com/0xMiden/miden-vm/pull/3143)).
- [BREAKING] Complete adapting trace generation to row-major ([#3171](https://github.com/0xMiden/miden-vm/pull/3171)).
- [BREAKING] Changed semantics of `LoopNode` to unconditionally enter loops ([#3187](https://github.com/0xMiden/miden-vm/pull/3187)).
- [BREAKING] Unified `OnceLockCompat` behavior across `std` and `no_std` ([#3188](https://github.com/0xMiden/miden-vm/pull/3188)).
- [BREAKING] Removed `prettier::pretty_print_csv`, `MastNodeId::from_usize_safe`, `DecoratorId::from_u32_bounded`, `OpBatch::end_indices`, — unused private API ([#3197](https://github.com/0xMiden/miden-vm/pull/3197)).
- Added a `RELEASE_PROCEDURE` file ([#3199](https://github.com/0xMiden/miden-vm/pull/3199)).
- [BREAKING] Removed `debug.*` decorators in favor of `miden::core::debug` procedures, and bumped the MAST wire format to `0.0.4` ([#3201](https://github.com/0xMiden/miden-vm/pull/3201)).
- [BREAKING] Cleaned up `Processor` trait by moving methods into their corresponding sub-interface ([#3202](https://github.com/0xMiden/miden-vm/pull/3202)).
- [BREAKING] Removed MASM `trace` decorators, remaining decorator execution scaffolding, the CLI `--trace` flag, trace-specific processor and host APIs, and decorator wire slots from the unreleased MAST format `0.0.4` ([#3208](https://github.com/0xMiden/miden-vm/pull/3208)).
- [BREAKING] Targets specified in `miden-project.toml` must now always provide a `path` key, though it may refer to files with extensions other than `.masm`, such as the case in Rust projects ([#3216](https://github.com/0xMiden/miden-vm/pull/3216))
- [BREAKING] `ProjectAssembler::assemble_with_sources` has been removed - projects require assembly from the filesystem going forward ([#3216](https://github.com/0xMiden/miden-vm/pull/3216)).
- Improved O(n²) to O(log n) name conflict checks in `Module::define_*` methods by introducing a `BTreeMap` name index; also narrowed `items_mut()` to return an iterator instead of `&mut Vec<Export>` to preserve the index invariant ([#3218](https://github.com/0xMiden/miden-vm/pull/3218)).
- [BREAKING] Imports in MASM may no longer refer to other imports in scope. Imports are now resolved in the global namespace (i.e. as if the path is absolute). The sole exception to this are imports which are submodule-relative - these now require an explicit `self::` prefix to tell the assembler that these should be resolved relative to a specific submodule. See ([#3220](https://github.com/0xMiden/miden-vm/pull/3220)).or `use {item1, item2 as alias} from some::module`, and may have `pub` visibility. See ([#3220](https://github.com/0xMiden/miden-vm/pull/3220)).
- [BREAKING] Re-exports in MASM (i.e. `pub use ...`) may no longer re-export modules. Normal imports (i.e. `use ...`) are not affected by this change. See ([#3220](https://github.com/0xMiden/miden-vm/pull/3220)).
- [BREAKING] `miden-vm bundle` now treats the `--kernel` option as a flag; when set, it expects the file path given to `bundle` to be the path to the root module of the kernel, and the support library for the kernel is derived from explicit submodule declarations in that module.
- [BREAKING] Assert the outer-LogUp boundary in MASM & restructure kernel public inputs ([#3256](https://github.com/0xMiden/miden-vm/pull/3256)).
- Reordered the chiplets trace columns and renamed the chiplet selectors to `s_00`/`s_01` ([#3266](https://github.com/0xMiden/miden-vm/pull/3266)).
- [BREAKING] Miden Assembly module structure must now be explicitly declared via `mod name`/`pub mod name`. The assembler will now ensure that only modules declared in this way are included in an artifact. For more details, see ([#3220](https://github.com/0xMiden/miden-vm/pull/3220)).
- Removed the legacy LALRPOP parser backend.
- [BREAKING] `Assembler::compile_and_statically_link_from_dir` is now `Assembler::compile_and_statically_link_from_root`, this is related to the change to MASM module structure mentioned above.
- [BREAKING] Moved debug info ownership out of `MastForest` and into package debug sections, adding source-node debug metadata that preserves distinct source occurrences after MAST node deduplication ([#3221](https://github.com/0xMiden/miden-vm/pull/3221)).
- Bounded `FastProcessor` memory growth with a configurable `ExecutionOptions::max_memory_elements` limit, rejecting writes to arbitrarily many unique addresses that could otherwise exhaust host memory ([#3226](https://github.com/0xMiden/miden-vm/pull/3226)).
- [BREAKING] Update `miden-crypto` and `miden-lifted-stark` dependencies to v0.26 ([#3228](https://github.com/0xMiden/miden-vm/pull/3228)).
- Cleaned up processor error handling for diagnostics, malformed MAST loading, and binary-value checks ([#3230](https://github.com/0xMiden/miden-vm/pull/3230)).
- [BREAKING] Import syntax in MASM has changed to be more explicit in distinguishing item vs module imports. Module imports are of the form `use some::module` or `use some::module as alias`, and may not have `pub` visibility; while item imports are of the form `use {item} from some::module` 
- Moved `proptest` test support behind optional features so `rand` 0.9 is not in the default dependency tree ([#3241](https://github.com/0xMiden/miden-vm/pull/3241)).
- Sped-up native verifier by skipping symbolic recomputation of constraint degree ([#3242](https://github.com/0xMiden/miden-vm/pull/3242)).
- Optimize Public Inputs absorption in recursive verifier ([#3243](https://github.com/0xMiden/miden-vm/pull/3243)).
- Reordered the chiplets trace columns and renamed the chiplet selectors to `s_00`/`s_01` ([#3266](https://github.com/0xMiden/miden-vm/pull/3266)).
- Bumped MSRV from 1.90 to 1.96 and replaced local `assert_matches!` macro with `core::assert_matches` ([#3267](https://github.com/0xMiden/miden-vm/pull/3267)).
- [BREAKING] Removed the stripped `MastForest` serialization mode. Normal forest bytes now describe execution data only ([#3268](https://github.com/0xMiden/miden-vm/pull/3268)).
- [BREAKING] Bump Plonky3 related dependencies to fix NEON arithmetic bug ([#3272](https://github.com/0xMiden/miden-vm/pull/3272)).
- [BREAKING] Bump Plonky3 and miden-crypto related dependencies ([#3275](https://github.com/0xMiden/miden-vm/pull/3275)).
- Imported `midenc-hir-type` as a released workspace crate.
- Added release tooling for publishing selected workspace crates.

#### Fixes

- Preserved `AssemblyOp` source mappings when merging `MastForest`s, preventing source-location loss after node deduplication ([#2958](https://github.com/0xMiden/miden-vm/pull/2958)).
- [BREAKING] Replaced the Poseidon2 sponge precompile transcript with a 2-to-1 hash folding scheme; the rolling state is itself a complete digest at every step, removing `finalize()` and `PrecompileTranscriptDigest`. The `log_precompile` opcode is reshaped accordingly (helper/stack rename STMNT placed at stack[4..8]) and the MASM `log_precompile_request` wrapper now computes STMNT via `hmerge`. RELATION_DIGEST bumped ([#3100](https://github.com/0xMiden/miden-vm/pull/3100)).
- Made AEAD decrypt verify the input ciphertext as well as the tag ([#3147](https://github.com/0xMiden/miden-vm/pull/3147)).
- Replaced `bincode` proof serialization with `wincode` and bounded verifier-side STARK proof deserialization to 64 MiB ([#3148](https://github.com/0xMiden/miden-vm/pull/3148)).
- Fixed MASM tooling edge cases around atomic file writes, source URI paths, package loading, local registry state, diagnostics, generated MASM memory addresses, and CST `$...` special identifiers ([#3178](https://github.com/0xMiden/miden-vm/pull/3178)).
- [BREAKING] Made `miden-vm run` and `miden-vm prove` fail when the inferred `.inputs` file is missing ([#3236](https://github.com/0xMiden/miden-vm/pull/3236)).
- Rejected empty query regions in the standalone FRI verifier ([#3237](https://github.com/0xMiden/miden-vm/pull/3237)).
- Pinned the initial AIR system context and function hash to zero, preventing forged caller hashes at row 0 ([#3240](https://github.com/0xMiden/miden-vm/pull/3240)).
- Preserved `LOGPRECOMPILE` tail stack slots in the AIR, preventing forged values in `stack[12..15]` ([#3244](https://github.com/0xMiden/miden-vm/pull/3244)).
- Bound memory AIR word addresses to their range-checked decomposition limbs ([#3245](https://github.com/0xMiden/miden-vm/pull/3245)).
- [BREAKING] Removed the test-only `frie2f4::preprocess` helper from corelib exports ([#3248](https://github.com/0xMiden/miden-vm/pull/3248)).
- Rejected oversized AEAD decrypt outputs before reading ciphertext or running host-side decryption ([#3252](https://github.com/0xMiden/miden-vm/pull/3252)).
- [BREAKING] Bounded deferred precompile request growth by request count and total calldata bytes in `AdviceProvider` ([#3260](https://github.com/0xMiden/miden-vm/pull/3260)).
- [BREAKING] Bounded advice Merkle store growth by internal node count during setup and execution ([#3264](https://github.com/0xMiden/miden-vm/pull/3264)).
- Fixed MASM tooling edge cases around atomic file writes, source URI paths, package loading, local registry state, diagnostics, generated MASM memory addresses, and CST `$...` special identifiers ([#3178](https://github.com/0xMiden/miden-vm/pull/3178)).
- [BREAKING] Removed the public `eddsa_ed25519::verify_prehash` entrypoint and bound EdDSA precompile verification to the signed message ([#3254](https://github.com/0xMiden/miden-vm/pull/3254)).
- Rejected SMT multi-leaf preimages with duplicate or unsorted keys before lookup or update logic runs ([#3255](https://github.com/0xMiden/miden-vm/pull/3255)).
- Replaced `bincode` proof serialization with `wincode` and bounded verifier-side STARK proof deserialization to 64 MiB ([#3148](https://github.com/0xMiden/miden-vm/pull/3148)).
- [BREAKING] Made `miden-vm run` and `miden-vm prove` fail when the inferred `.inputs` file is missing ([#3236](https://github.com/0xMiden/miden-vm/pull/3236)).
- [BREAKING] Replaced the Poseidon2 sponge precompile transcript with a 2-to-1 hash folding scheme; the rolling state is itself a complete digest at every step, removing `finalize()` and `PrecompileTranscriptDigest`. The `log_precompile` opcode is reshaped accordingly (helper/stack rename, STMNT placed at stack[4..8]) and the MASM `log_precompile_request` wrapper now computes STMNT via `hmerge`. RELATION_DIGEST bumped ([#3100](https://github.com/0xMiden/miden-vm/pull/3100)).
- Preserved `AssemblyOp` source mappings when merging `MastForest`s, preventing source-location loss after node deduplication ([#2958](https://github.com/0xMiden/miden-vm/pull/2958)).
- Made AEAD decrypt verify the input ciphertext as well as the tag ([#3147](https://github.com/0xMiden/miden-vm/pull/3147)).
- Removed overly aggressive validation check that prevented defining virtual executable targets in Miden projects
- Constrained Core AIR stack routes for control and stream operations, preventing unconstrained stack values across `SYSCALL`, `EVALCIRCUIT`, `CALLER`, `MSTREAM`, `PIPE`, `REPEAT`, `SWAPW2`, and `SWAPW3` ([#3249](https://github.com/0xMiden/miden-vm/pull/3249)).
- Rejected oversized AEAD decrypt outputs before reading ciphertext or running host-side decryption ([#3252](https://github.com/0xMiden/miden-vm/pull/3252)).
- Preserved semantic type expressions when converting concrete types back to assembly syntax, keeping wide-integer primitives and named struct metadata intact ([#3253](https://github.com/0xMiden/miden-vm/pull/3253)).
- [BREAKING] Removed the public `eddsa_ed25519::verify_prehash` entrypoint and bound EdDSA precompile verification to the signed message ([#3254](https://github.com/0xMiden/miden-vm/pull/3254)).
- [BREAKING] Bounded deferred precompile request growth by request count and total calldata bytes in `AdviceProvider` ([#3260](https://github.com/0xMiden/miden-vm/pull/3260)).
- Stack depth limits now properly include all active contexts' overflow stacks ([#3261](https://github.com/0xMiden/miden-vm/pull/3261)).
- [BREAKING] Bounded advice Merkle store growth by internal node count during setup and execution ([#3264](https://github.com/0xMiden/miden-vm/pull/3264)).
- Removed overly aggressive validation check that prevented defining virtual executable targets in Miden projects.
- Bounded debug-info section deserialization so malformed lengths cannot exhaust memory ([#3279](https://github.com/0xMiden/miden-vm/pull/3279)).

## miden-vm v0.23.4 (2026-06-23)

- Preserved semantic struct and field names when emitting debug types, so debug dumps no longer fall back to anonymous struct metadata ([#3269](https://github.com/0xMiden/miden-vm/pull/3269)).
- Fixed parallel trace generation for `while.true` loops that exit before entering the body and are followed by another block ([#3278](https://github.com/0xMiden/miden-vm/pull/3278)).

#### midenc-hir-type history before import

The following entries come from the standalone `midenc-hir-type` changelog before the crate moved into this workspace.

##### 0.8.0

- Updated `miden-serde-utils` to 0.27.0.

##### 0.7.0 (2026-06-03)

- Scoped the `miden-serde-utils` update to the dependency only.

##### 0.6.1 (2026-05-04)

- Updated `miden-serde-utils` to 0.25.0.

##### 0.6.0 (2026-04-22)

- Updated `Cargo.lock` for release.
- Updated `miden-serde-utils` to 0.24.

##### 0.5.4 (2026-04-21)

- Updated `miden-serde-utils` to 0.24.

##### 0.5.3 (2026-03-19)

- Enforced the depth limit for nested enum type deserialization.
- Added the missing deserialization path for `TypeRepr::BigEndian`.
- Ensured `--locked` is used when installing `cargo-make`.
- Installed `cargo-nextest` with `--locked` in CI.

##### 0.5.2 (2026-03-16)

- Implemented `miden-serde-utils` serialization for types.

##### 0.5.1 (2026-03-13)

- Fixed `format-rust` so it uses nightly.
- Bumped the Rust toolchain to 1.92.
- Set CI workflow permissions.

##### 0.4.3 (2025-11-05)

- Reverted docs migration changes from the compiler repo.
- Added a README docs section.

##### 0.4.2

- Added `TypeRepr::BigEndian` as a temporary way to represent legacy protocol library types.

##### 0.4.0 (2025-08-15)

- Updated the Rust toolchain to nightly 2025-07-20.

##### 0.0.8 (2025-04-24)

- Cleaned up `hir-type` for use outside the compiler.
- Implemented the pretty-print trait for `Symbol` and `Type`.
- Treated warnings as compiler errors.
- Updated the Rust toolchain and cleaned up dependencies.
- Implemented HIR dialect ops and the remaining core IR infrastructure.

##### 0.0.7 (2024-09-17)

- Fixed new clippy warnings.

##### 0.0.6 (2024-09-06)

- Switched all crates to a single workspace version, 0.0.5.

##### 0.0.3 (2024-08-30)

- Fixed broken return via pointer transformation.

##### 0.0.2 (2024-08-28)

- Implemented the packaging prototype.

##### 0.0.1 (2024-07-18)

- Drafted Miden ABI function type encoding and retrieval.
- Introduced Miden ABI component imports.
- Introduced `CanonicalOptions` in IR and translated Wasm.
- Implemented a new S-expression format for HIR.
- Rewrote type layout code.
- Refactored type layout primitives.
- Defined type compatibility for operators.
- Added the type representation enum.
- Implemented inline assembly.
- Distinguished signed and unsigned types.
- Distinguished native and emulated pointers.
- Fixed `i1` widening casts.
- Fixed the felt representation mismatch between Rust and Miden.
- Fixed wrong entries in the operand compatibility matrix.
- Used stabilized `next_multiple_of` in `Alignable`.
- Switched the text form of `MidenAbiFunctionType` to S-expressions.
- Set crate versions to 0.0.0 and made test crates private.
- Added the `miden-hir-type` crate description.
- Prefixed the relevant crates with `midenc-`.
- Added `FunctionType::abi` and removed the redundant function type.
- Added Wasm component translation support to integration tests.
- Added formatter config and formatted most crates.
- Moved `LiftedFunctionType` to `miden-hir-type`.
- Added guides for compiling Rust to MASM.
- Split up the HIR crate.
- Added initial usage instructions.

## miden-crypto v0.27.0 (2026-06-19)

- [BREAKING] Upgraded the RustCrypto and dalek stack: `der`, `hkdf`, `sha2`, `sha3`, `k256`, `curve25519-dalek`, `ed25519-dalek`, and `x25519-dalek` ([#1045](https://github.com/0xMiden/crypto/pull/1045)).
- Added `Display` (`0x`-prefixed lowercase hex) for the public key and signature types of all DSA schemes ([#1048](https://github.com/0xMiden/crypto/pull/1048)).
- Added doctests for ECDSA signature serialization, sponge state sizing, SMT sorted entries, and lifted AIR Fiat-Shamir docs ([#1049](https://github.com/0xMiden/crypto/pull/1049)).
- Upgraded `chacha20poly1305` to the current RustCrypto AEAD release line and added Wycheproof checks for ECDH and Ed25519 paths ([#1052](https://github.com/0xMiden/crypto/pull/1052)).
- [BREAKING] Bumped Plonky3 upstream dependencies to v0.6.0 ([#1053](https://github.com/0xMiden/crypto/pull/1053)).
- Use faster DFT algorithm for `PeriodicPolys` ([#1054](https://github.com/0xMiden/crypto/pull/1054)).
- Improved LargeSmt RocksDB defaults, added per-DB memory-budget controls, and exposed durability mode selection ([#1056](https://github.com/0xMiden/crypto/pull/1056)).
- [BREAKING] Make `Felt::Packing` resolve to the SIMD-packed `PackedFelt` from Plonky3 ([#1060](https://github.com/0xMiden/crypto/pull/1060)).
- perf: factor the DEEP barycentric inner loop to drop the per-row `xᵢ · qᵢ` base×extension multiplication ([#1064](https://github.com/0xMiden/crypto/issues/1064)).
- Added release tooling for publishing an explicit package list instead of always publishing the full workspace.

## miden-crypto v0.26.0 (2026-06-02)

- [BREAKING] Extracted `BackendReader`, allowing `LargeSmtForest<S>` to work with read-only storage backends ([#986](https://github.com/0xMiden/crypto/pull/986)).
- Optimized prover quotient evaluation by evaluating each AIR's quotient on its native coset (size `n_j · D_j`) and lifting per-AIR, instead of always on the global maximum coset; constraint division is fused into the constraint evaluation loop ([#991](https://github.com/0xMiden/crypto/pull/991)).
- [BREAKING] Replaced the per-AIR witness/aux-builder proving model (`AirInstance`, `AirWitness`, `AuxBuilder`, `prove_multi` / `verify_multi`) with a `MultiAir` trait that owns its AIRs (each builds its own aux trace via `LiftedAir::build_aux_trace`), plus validated `Statement` / `ProverStatement` structs carried by `ProverInstance` / `VerifierInstance`. `LiftedAir::reduced_aux_values` and `num_var_len_public_inputs` are replaced by `MultiAir::eval_external`, which returns the cross-AIR external assertions as a flat list of extension-field values that must equal zero, fed by an `aux_inputs` slice whose schema each `MultiAir` owns and validates ([#992](https://github.com/0xMiden/crypto/pull/992)).
- [BREAKING] Refactored `miden-lifted-stark::domain` around a uniform `Coset` trait shared by `TwoAdicSubgroup` and `TwoAdicCoset`, slimmed the `LiftedDomain` surface (drops dead getters, removes silently-dispatched `points`/`bit_reversed_points`/`vanishing_at` in favour of explicit `trace_subgroup()` / `lde_coset()` access), made `LiftedDomain` constructors fallible, moved selector logic onto `LiftedDomain`, and changed `log_blowup` to return `u8` ([#993](https://github.com/0xMiden/crypto/pull/993)).
- [BREAKING] Upgraded direct `rand` dependencies to 0.10, updating RNG trait bounds and removing direct `rand_hc` usage ([#995](https://github.com/0xMiden/crypto/pull/995)).
- [BREAKING] Reorganized `miden-lifted-stark` internals: consolidated `align`, `bitrev`, `horner`, and `packing` helpers under a new `util` module; removed the legacy `fri::*` re-export facade ([#1000](https://github.com/0xMiden/crypto/pull/1000)).
- perf: fuse per-group accumulator and defer allocations ([#1008](https://github.com/0xMiden/crypto/pull/1008)).
- [BREAKING] Reduced `LargeSmt<S>` cache depth from 24 to 16 levels ([#1011](https://github.com/0xMiden/crypto/pull/1011)).
- [BREAKING] Implemented two-phase commit_mutations() / apply_mutations()-style API for `LargeSmtForest` ([#1018](https://github.com/0xMiden/crypto/pull/1018)).
- [BREAKING] Tightened the `miden-lifted-stark` public API surface: dropped the wide crate-root re-export list (callers now import from `miden_lifted_stark::air` and `miden_lifted_stark::{lmcs, pcs, proof, prover, verifier}` directly), demoted internal submodules to `pub(crate)`/`pub(super)`, and folded the `transcript` module into `proof` (`TranscriptChallenger` / `TranscriptData` / `TranscriptError` are re-exported there). Renamed the proof artifact types — `StarkProof` → `StarkProofData` (wire artifact) and `StarkTranscript` → `StarkProof` (parsed view, built via `StarkProof::from_data`) — and `*::from_verifier_channel` → `*::read_from_channel` on the PCS sub-proofs. Dropped the panicking domain constructors (`TwoAdicCoset::unshifted`, `LiftedDomain::{canonical, sub_domain}`) in favour of the fallible `try_*` variants ([#1020](https://github.com/0xMiden/crypto/pull/1020)).
- [BREAKING] Added reusable preprocessed trace setup artifacts for Lifted STARKs: AIRs can declare fixed preprocessed columns, provers build and reuse a `Preprocessed` commitment bundle, and verifier instances receive the trusted preprocessed commitment ([#1021](https://github.com/0xMiden/crypto/pull/1021)).
- [BREAKING] Fixed RocksDB CLI safety, non-canonical serde input handling, and qualified `WordWrapper` derive paths ([#1022](https://github.com/0xMiden/crypto/pull/1022)).
- [BREAKING] Simplify `LargeSmtForest` backend API ([#1030](https://github.com/0xMiden/crypto/pull/1030)).
- [BREAKING] Made `LargeSmt` leaf/entry/inner node iterators fallible ([#1032](https://github.com/0xMiden/crypto/pull/1032)).

## miden-vm v0.23.3 (2026-05-27)

- Pure version bump to attach build artifacts to the release.

## miden-vm v0.23.2 (2026-05-25)

- Restored `DebugVarInfo::set_value_location` and `DebugVarLocation::FrameBase` for debug metadata compatibility ([#3189](https://github.com/0xMiden/miden-vm/pull/3189)).
## Unreleased

#### Features

- Added authenticated rooted Merkle-frontier support to the core MMR (`mmr::root`, `mmr::root_with_len`, `mmr::unpack_frontier`) ([#3184](https://github.com/0xMiden/miden-vm/pull/3184)).

## miden-crypto v0.25.1 (2026-05-21)

- Fixed `miden-lifted-stark` builds when `p3-maybe-rayon/parallel` is enabled without `miden-lifted-stark/parallel` ([#1023](https://github.com/0xMiden/crypto/pull/1023)).

## miden-vm v0.23.1 (2026-05-20)

- Restored metadata-neutral MAST node identity so public procedure roots do not depend on debug/decorator metadata shape; this reopens debug metadata precision issues from #2955 and #3054.

## miden-vm v0.23.0 (2026-05-09)

#### Features

- Added the `miden-vm-synthetic-bench` crate for VM-level proving regression detection driven by row-count snapshots from an external producer ([#3024](https://github.com/0xMiden/miden-vm/pull/3024)).
- Implemented the `miden-registry` tool for managing a local filesystem-based package registry. This is intended to help us explore what package management in Miden projects might look like with a central registry for sharing packages, without needing to go all-in on implementing one. [#2881](https://github.com/0xMiden/miden-vm/pull/2881).
- Introduce `SparseMastForest`, and use it to shrink the size of `TraceGenerationContext` [#3105](https://github.com/0xMiden/miden-vm/pull/3105).

#### Enhancements

- Implemented new lossless parser for Miden Assembly sources ([#2906](https://github.com/0xMiden/miden-vm/pull/2906))
- Created new `miden-format` tool for formatting Miden Assembly sources while preserving comments and certain whitespace choices ([#2906](https://github.com/0xMiden/miden-vm/pull/2906))
- Switched the default parser backend for Miden Assembly to use the new lossless parser ([#2907](https://github.com/0xMiden/miden-vm/pull/2907))

#### Fixes

- Fixed quote-equivalent path ambiguity in library deserialization and linker symbol resolution ([#2836](https://github.com/0xMiden/miden-vm/pull/2836)).
- Memoized semantic constant evaluation in `AnalysisContext` to prevent exponential work from shared constant-dependency graphs during parsing and semantic analysis ([#2858](https://github.com/0xMiden/miden-vm/pull/2858)).
- Treat serialized libraries and kernel libraries as untrusted MAST forests during deserialization, rejecting spoofed node digests ([#2863](https://github.com/0xMiden/miden-vm/pull/2863)).
- Reverted `InvokeKind::ProcRef` back to `InvokeKind::Exec` in `visit_mut_procref` and added an explanatory comment (#2893).
- Return typed cycle errors for self-recursive and rootless procedure call graphs, and roll back linker state on failure ([#2899](https://github.com/0xMiden/miden-vm/pull/2899)).
- [BREAKING] Reject oversized modules at resolver construction instead of building partial resolver state or panicking ([#2899](https://github.com/0xMiden/miden-vm/pull/2899)).
- Return a normal assembly error when `pub use <digest> -> <name>` does not resolve to an exported procedure ([#2899](https://github.com/0xMiden/miden-vm/pull/2899)).
- [BREAKING] Reject non-procedure invoke targets during semantic analysis, and return an assembly error instead of panicking if one still reaches assembly ([#2899](https://github.com/0xMiden/miden-vm/pull/2899)).
- Rejected non-syscall references to exported kernel procedures in the linker ([#2902](https://github.com/0xMiden/miden-vm/issues/2902)).
- Added `Package::content_digest()` to identify package contents without changing the MAST digest, including manifest data and semantic package metadata ([#2909](https://github.com/0xMiden/miden-vm/pull/2909)).
- Fixed `FastProcessor` so `after_exit` trace decorators execute when tracing is enabled without debug mode, and added a tracing-only regression test.
- Fixed the release dry-run publish cycle between `miden-air` and `miden-ace-codegen`, and preserved leaf-only DAG imports with explicit snapshots ([#2931](https://github.com/0xMiden/miden-vm/pull/2931)).
- Library deserialization now rejects exports whose `MastNodeId` is not a procedure root, closing a silent-failure path ([#2933](https://github.com/0xMiden/miden-vm/pull/2933)).
- Replaced unsound `ptr::read` with safe unbox in panic recovery, removing UB from potential double-drop ([#2934](https://github.com/0xMiden/miden-vm/pull/2934)).
- Fixed debug-only underflow in memory range-check trace generation when the first memory access is at `clk = 0` ([#2976](https://github.com/0xMiden/miden-vm/pull/2976)).
- Reverted the `MainTrace` typed row storage change that caused a large `blake3_1to1` trace-building regression ([#2949](https://github.com/0xMiden/miden-vm/pull/2949)).
- Fixed Falcon `mod_12289` remainder validation and `u64::rotr` overflow handling for rotations by `0` and `32` ([#2968](https://github.com/0xMiden/miden-vm/pull/2968)).
- Hardened SHA256 message word range checks and U32ADD/U32ADD3 carry constraints, updating recursive verifier relation digest artifacts ([#3021](https://github.com/0xMiden/miden-vm/pull/3021)).
- [BREAKING] Removed internal `_impl` precompile helpers from the core-lib API, hardened proof deserialization and debug storage errors, and added u256 regression vectors ([#3026](https://github.com/0xMiden/miden-vm/pull/3026)).
- Fixed `u256::wrapping_mul` so it preserves caller stack values below its operands ([#3071](https://github.com/0xMiden/miden-vm/pull/3071)).
- Fixed host event and advice-mutation diagnostics to point to the triggering `emit.event(...)` instruction ([#3042](https://github.com/0xMiden/miden-vm/pull/3042)).
- Fixed debug-only underflow in memory range-check trace generation when the first memory access is at `clk = 0` ([#2976](https://github.com/0xMiden/miden-vm/pull/2976)).
- Replaced unsound `ptr::read` with safe unbox in panic recovery, removing UB from potential double-drop ([#2934](https://github.com/0xMiden/miden-vm/pull/2934)).
- Library deserialization now rejects exports whose `MastNodeId` is not a procedure root, closing a silent-failure path ([#2933](https://github.com/0xMiden/miden-vm/pull/2933)).
- Reverted `InvokeKind::ProcRef` back to `InvokeKind::Exec` in `visit_mut_procref` and added an explanatory comment (#2893).
- Fixed the release dry-run publish cycle between `miden-air` and `miden-ace-codegen`, and preserved leaf-only DAG imports with explicit snapshots ([#2931](https://github.com/0xMiden/miden-vm/pull/2931)).
- Added regression coverage for the exact `max_num_continuations` continuation-stack boundary ([#2995](https://github.com/0xMiden/miden-vm/pull/2995)).
- Fixed AEAD padding handling so encrypt does not overwrite memory next to the plaintext buffer and decrypt leaves the plaintext output tail untouched ([#3008](https://github.com/0xMiden/miden-vm/pull/3008)).
- Hardened SHA256 message word range checks and U32ADD/U32ADD3 carry constraints, updating recursive verifier relation digest artifacts ([#3021](https://github.com/0xMiden/miden-vm/pull/3021)).
- [BREAKING] Removed internal `_impl` precompile helpers from the core-lib API, hardened proof deserialization and debug storage errors, and added u256 regression vectors ([#3026](https://github.com/0xMiden/miden-vm/pull/3026)).
- Fixed host event and advice-mutation diagnostics to point to the triggering `emit.event(...)` instruction ([#3042](https://github.com/0xMiden/miden-vm/pull/3042)).
- Fixed MAST compaction after debug info is cleared so compiler-generated packages do not grow ([#3044](https://github.com/0xMiden/miden-vm/pull/3044)).
- Fixed missing `smt::set` validations in corelib ([#3049](https://github.com/0xMiden/miden-vm/pull/3049)).
- Added bounds checks for non-deterministic `maybe_value_ptr`/`maybe_key_ptr` hints in `sorted_array::find_word` and `find_partial_key_value` ([#3051](https://github.com/0xMiden/miden-vm/pull/3051)).
- Fixed same-digest procedure selection so static linking and library-to-executable package conversion preserve the selected procedure's debug metadata ([#3054](https://github.com/0xMiden/miden-vm/pull/3054)).
- Canonicalized `PathBuf::try_from(String)` to match `TryFrom<&str>`/`FromStr`, so semantically equivalent quoted path components compare and hash consistently.
- Fixed `u256::wrapping_mul` so it preserves caller stack values below its operands ([#3071](https://github.com/0xMiden/miden-vm/pull/3071)).
- Rejected empty kernel packages before linking so malformed dependency metadata returns a structured package error instead of reaching the linker's non-empty-kernel assertion ([#3082](https://github.com/0xMiden/miden-vm/pull/3082)).
- [BREAKING] Bounded the live advice map by total field elements during execution; advice-provider setup now returns an error when initial advice exceeds this limit ([#3085](https://github.com/0xMiden/miden-vm/pull/3085)).
- Fixed `FastProcessor` stack growth so operand stack depth is bounded by `ExecutionOptions::max_stack_depth` instead of the internal buffer size ([#3086](https://github.com/0xMiden/miden-vm/pull/3086)).
- Hardened MAST forest and package byte-slice deserialization against fuzzed length fields ([#3088](https://github.com/0xMiden/miden-vm/pull/3088)).
- [BREAKING] Fixed project artifact reuse to ignore unrelated manifest fields, rejected private cross-module imports, and kept signature-only type imports live ([#3091](https://github.com/0xMiden/miden-vm/pull/3091)).
- Rejected private type references in exported procedure signatures, including transitive aliases and same-module absolute paths ([#3273](https://github.com/0xMiden/miden-vm/pull/3273)).
- Fixed stale `ReplayProcessor` doc comment links to `ExecutionTracer` after module-structure refactors.

#### Changes

- [BREAKING] The `Library` struct was removed, along with related APIs, in favor of `Package` and `Package`-oriented APIs ([#3106](https://github.com/0xMiden/miden-vm/pull/3106))
- [BREAKING] The `Package` struct no longer implements `serde`-based deserialization
- [BREAKING] Refactored MAST forest serialization around fixed-layout full, stripped, and hashless sections, and bumped the MAST wire format to `0.0.3` ([#2765](https://github.com/0xMiden/miden-vm/pull/2765)).
- Optimized call graph topological sort from O(V\*E) to O(V + E) by pre-computing in-degrees ([#2830](https://github.com/0xMiden/miden-vm/pull/2830)).
- [BREAKING] Cleaned up the unreleased MAST forest wire format, with stable node IDs and stricter untrusted validation ([#3055](https://github.com/0xMiden/miden-vm/pull/3055)).
- [BREAKING] Refined MAST forest read policies with trusted wire-backed views, options-based untrusted reads, and separate wire and validation budgets ([#3077](https://github.com/0xMiden/miden-vm/pull/3077)).
- Documented sortedness precondition more prominently for sorted array operations ([#2832](https://github.com/0xMiden/miden-vm/pull/2832)).
- Removed AIR constraint tagging instrumentation, applied a uniform constraint description style across components, and optimized constraint evaluation ([#2856](https://github.com/0xMiden/miden-vm/pull/2856)).
- Clarified `/` and `//` division semantics in constant expressions ([#3113](https://github.com/0xMiden/miden-vm/pull/3113)).
- [BREAKING] Updated the Miden crypto stack to `miden-crypto` and `miden-lifted-stark` v0.24, and switched digest-ordering code to `Word`'s native lexicographic ordering ([#3039](https://github.com/0xMiden/miden-vm/pull/3039)).
- Borrowed operation slices in basic-block batching helpers to avoid cloning in the fingerprinting path ([#2994](https://github.com/0xMiden/miden-vm/pull/2994)).
- [BREAKING] Sync execution and proving APIs now require `SyncHost`; async `Host`, `execute`, and `prove` remain available ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- [BREAKING] `miden_processor::execute()` and `execute_sync()` now return `ExecutionOutput`; trace building remains explicit via `execute_trace_inputs*()` and `trace::build_trace()` ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- [BREAKING] Removed the deprecated `FastProcessor::execute_sync_mut()` alias; `execute_mut_sync()` is now the only sync mutable-execution entrypoint ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- [BREAKING] Removed the deprecated `FastProcessor::execute_for_trace_sync()` and `execute_for_trace()` wrappers; use `execute_trace_inputs_sync()` or `execute_trace_inputs()` instead ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- [BREAKING] Removed the deprecated unbound `TraceBuildInputs::new()` and `TraceBuildInputs::from_program()` constructors; use `execute_trace_inputs_sync()` or `execute_trace_inputs()` instead ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- Added `prove_from_trace_sync(...)` for proving from pre-executed trace inputs ([#2865](https://github.com/0xMiden/miden-vm/pull/2865)).
- [BREAKING] Removed the immediate form of `adv_push` (`adv_push.N`); use N consecutive `adv_push` instructions (or `repeat.N adv_push end` for large N) instead ([#2900](https://github.com/0xMiden/miden-vm/pull/2900)).
- Added `FastProcessor::into_parts()` to extract advice provider, memory, and precompile transcript after step-based execution ([#2901](https://github.com/0xMiden/miden-vm/pull/2901)).
- Redesigned the hasher chiplet to use a controller/permutation split architecture with permutation calls deduplication ([#2927](https://github.com/0xMiden/miden-vm/pull/2927)).
- Documented that enum variants are module-level constants and must be unique within a module ([#2932])((https://github.com/0xMiden/miden-vm/pull/2932)).
- Refactor trace generation to row-major format ([#2937](https://github.com/0xMiden/miden-vm/pull/2937)).
- Documented non-overlap requirement for `memcopy_words`, `memcopy_elements`, and AEAD encrypt/decrypt procedures ([#2941](https://github.com/0xMiden/miden-vm/pull/2941)).
- [BREAKING] Reduced the prove-from-trace API to post-execution trace inputs: `TraceBuildInputs` no longer carries full execution output, `prove_from_trace_sync()` takes `TraceProvingInputs`, and `ProvingOptions` no longer include `ExecutionOptions` ([#2948](https://github.com/0xMiden/miden-vm/pull/2948)).
- Follow-up refactoring + couple perf improvements on trace generation ([#2953](https://github.com/0xMiden/miden-vm/pull/2953)).
- Added chainable `Test` builders for common test setup in `miden-utils-testing` ([#2957](https://github.com/0xMiden/miden-vm/pull/2957)).
- Added fuzz coverage for package semantic deserialization and project parsing, loading, and assembly ([#3015](https://github.com/0xMiden/miden-vm/pull/3015)).
- Added regression coverage for chiplet-request opcode flag parity between the prover boolean fast path and polynomial AIR construction ([#3117](https://github.com/0xMiden/miden-vm/pull/3117)).
- Made serde opt-in for package crates, and added macro-based binary and serde roundtrip tests for Arbitrary serialization types ([#3058](https://github.com/0xMiden/miden-vm/pull/3058)).
- Speed-up AUX range check trace generation by changing divisors to a flat Vec layout ([#2966](https://github.com/0xMiden/miden-vm/pull/2966)).
- Optimized call graph topological sort from O(V\*E) to O(V + E) by pre-computing in-degrees ([#2830](https://github.com/0xMiden/miden-vm/pull/2830)).
- Removed AIR constraint tagging instrumentation, applied a uniform constraint description style across components, and optimized constraint evaluation ([#2856](https://github.com/0xMiden/miden-vm/pull/2856)).
- [BREAKING] Unified all auxiliary-trace buses under a single declarative LogUp `LookupAir` shared by the verifier, prover aux-trace generator, and recursive ACE circuit; reduced committed boundary values to one per trace ([#2962](https://github.com/0xMiden/miden-vm/pull/2962)).
- Collapsed the kernel ROM chiplet to one row per digest with a LogUp multiplicity, eliminating duplicate-callsite rows ([#2962](https://github.com/0xMiden/miden-vm/pull/2962)).
- Speed-up AUX range check trace generation by changing divisors to a flat Vec layout ([#2966](https://github.com/0xMiden/miden-vm/pull/2966)).
- Added deterministic regression vectors for `math::u256` core-lib tests and replaced `BigUint`-based expectations with an in-test `U256` model ([#2974](https://github.com/0xMiden/miden-vm/pull/2974)).
- Borrowed operation slices in basic-block batching helpers to avoid cloning in the fingerprinting path ([#2994](https://github.com/0xMiden/miden-vm/pull/2994)).
- Clarified that `mmr::get` fails for positions outside the current MMR rather than returning a sentinel value ([#3001](https://github.com/0xMiden/miden-vm/issues/3001)).
- Added fuzz coverage for package semantic deserialization and project parsing, loading, and assembly ([#3015](https://github.com/0xMiden/miden-vm/pull/3015)).
- Aligned AEAD key/nonce stack-order documentation and handler comments with the runtime contract ([#3036](https://github.com/0xMiden/miden-vm/pull/3036)).
- [BREAKING] Updated the Miden crypto stack to `miden-crypto` and `miden-lifted-stark` v0.24, and switched digest-ordering code to `Word`'s native lexicographic ordering ([#3039](https://github.com/0xMiden/miden-vm/pull/3039)).
- Cached repeated test compilations to speed up assembler tests without changing coverage, and fixed the core library build watch path ([#3047](https://github.com/0xMiden/miden-vm/pull/3047)).
- Made serde opt-in for package crates, and added macro-based binary and serde roundtrip tests for Arbitrary serialization types ([#3058](https://github.com/0xMiden/miden-vm/pull/3058)).
- Corrected memory trace delta encoding comments to match first-row and same-word clock delta behavior ([#3062](https://github.com/0xMiden/miden-vm/pull/3062)).
- Aligned `core_lib::math::u256` user docs with unified LE stack limb ordering (`a0/b0` on top), removing conflicting `[b7..b0, a7..a0]` notation ([#3066](https://github.com/0xMiden/miden-vm/pull/3066)).
- Made all internal `core::math` procedures natively little-endian ([#3084](https://github.com/0xMiden/miden-vm/pull/3084)).
- [BREAKING] Updated the Miden crypto stack to `miden-crypto` v0.25, and switched SMT leaf hashing to use Poseidon2 domain separation so masm-side leaf digests match `SmtLeaf::hash()` ([#3095](https://github.com/0xMiden/miden-vm/pull/3095)).
- [BREAKING] Reject post-last operation-indexed decorators in block assembly and serialized MAST forests; use `after_exit` for decorators that run after a block exits ([#3114](https://github.com/0xMiden/miden-vm/pull/3114)).
- [BREAKING] Removed `Continuation::AfterExitDecoratorsBasicBlock`. New MAST merges operation-indexed decorators at the post-last-op sentinel index into `after_exit` at build time; execution uses `AfterExitDecorators` only, with legacy forests still supported ([#2633](https://github.com/0xMiden/miden-vm/issues/2633)).
- Drop dead `clk` argument from u32 range-check ([#3135](https://github.com/0xMiden/miden-vm/issues/3135)).
- Added binary artifact compilation to CI to aid `midenup`'s installation speed ([#3029](https://github.com/0xMiden/miden-vm/pull/3029)).

## miden-crypto v0.25.0 (2026-05-01)

- [BREAKING] Changed the serialization format of `PartialSmt` to be more compact on the wire ([#957](https://github.com/0xMiden/crypto/pull/957)).
- [BREAKING] Changed `SmtLeaf::hash` to perform domain-separated hashing, reducing the risk of a collision with the hash of an inner node. ([#962](https://github.com/0xMiden/crypto/pull/962)).
- [BREAKING] Extracted `SmtStorageReader` and `SparseMerkleTreeReader`, allowing `LargeSmt<S>` to work with read-only storage backends ([#967](https://github.com/0xMiden/crypto/pull/967)).
- Added domain-separated hashing support for elements to `AlgebraicSpoonge` as `hash_elements_in_domain(...)` ([#978](https://github.com/0xMiden/crypto/pull/978)).
- Added `Signature::from_der()` for EdDSA signatures ([#979](https://github.com/0xMiden/crypto/pull/979)).
- Fixed `SimpleSmt::set_subtree()` to clear stale leaves and inner nodes in the replaced subtree region ([#981](https://github.com/0xMiden/crypto/pull/981)).
- Fixed `SliceReader` bounds checking to reject overflowing read lengths ([#987](https://github.com/0xMiden/crypto/pull/987)).

## miden-vm v0.22.3 (2026-05-01)

- Change value of `Path::MAX_COMPONENT_LENGTH` to `u16::MAX - 2` [#3087](https://github.com/0xMiden/miden-vm/pull/3087)

## miden-vm v0.22.2 (2026-04-28)

- Improve debug var loc tracking ([#2955](https://github.com/0xMiden/miden-vm/pull/2955)).

## miden-crypto v0.24.0 (2026-04-19)

- [BREAKING] Removed `AlgebraicSponge::merge_with_int()` method ([#894](https://github.com/0xMiden/crypto/pull/894)).
- [BREAKING] Updated `Poseidon2` instance to match Plonky3 one ([#905](https://github.com/0xMiden/crypto/pull/905)).
- Added `LargeSmtForest::add_lineages` which provides an efficient means of adding multiple new lineages at once ([#910](https://github.com/0xMiden/crypto/pull/910)).
- Added the ability to configure the sync-to-disk behavior of the persistent backend using its config ([#912](https://github.com/0xMiden/crypto/pull/912)).
- [BREAKING] Removed `WORD_SIZE_FELTS` and `WORD_SIZE_BYTES` from `miden-field` in favor of `Word::NUM_ELEMENTS` and `Word::SERIALIZED_SIZE`, respectively. The values remain the same ([#917](https://github.com/0xMiden/crypto/pull/917)).
- [BREAKING] Removed `WORD_SIZE` from `miden-crypto` in favor of `Word::NUM_ELEMENTS`. Clients will need to update references to the constant, but `Word` will already be in scope as it is re-exported from `miden-crypto` ([#917](https://github.com/0xMiden/crypto/pull/917)).
- [BREAKING] Removed `LexicographicWord` as `Word` itself now implements the correct comparison behavior. Any place where the former is used should be able to seamlessly swap to the latter ([#918](https://github.com/0xMiden/crypto/pull/918)).
- [BREAKING] Removed implementations of `Deref` and `DerefMut` for `Felt` ([#919](https://github.com/0xMiden/crypto/pull/919)).
- Added `Serializable` and `Deserializable` instances for `Arc<str>` ([#920](https://github.com/0xMiden/crypto/pull/920)).
- Optimized batch inversion to use per-chunk scratch space ([#933](https://github.com/0xMiden/crypto/pull/933)).
- [BREAKING] Changed the signature of `Felt::new` to perform reduction, and raise an error if the input is invalid. Retained the old behavior as `Felt::new_unchecked`, as its usage may lead to incorrect results ([#924](https://github.com/0xMiden/crypto/pull/924)).
- Optimized field operations for `Goldilocks` ([#926](https://github.com/0xMiden/crypto/pull/926)).
- [BREAKING] Moved per-instance log trace heights from `AirInstance` into `StarkProof`; `prove_multi` / `verify_multi` now observe them into the Fiat-Shamir challenger internally ([#956](https://github.com/0xMiden/crypto/pull/956)). Consumers on the temporary `(log_trace_height, proof)` serialization path must drop the wrapper and stop pre-observing the height, or it will be bound twice. `StarkProof` no longer exposes per-instance heights directly — parse the proof with `StarkTranscript::from_proof` to read them; `num_traces()` is available for the count.
- [BREAKING] `prove_multi` / `verify_multi` no longer require instances in ascending trace-height order; the prover sorts internally and the proof carries an `air_order` permutation ([#941](https://github.com/0xMiden/crypto/issues/941)). `InstanceShapes::from_trace_heights` now sorts internally and embeds the AIR ordering. `InstanceShapes::observe` renamed to `observe_heights`. The `NotAscending` error variant is removed; `InvalidAirOrder` and `AirOrderLengthMismatch` are added. `AirWitness` now derives `Clone + Copy`. Callers must bind AIR configurations and `air_order` into the Fiat-Shamir challenger — see the prover module-level docs.
- [BREAKING] Split the `SecretKey` type for both ECDSA-k256 and EdDSA-25519 into `SigningKey` and `KeyExchangeKey` to help enforce better practices around key reuse. `SecretKey` is no longer available in the public API; all usages should be moved to one of the new key types ([#965](https://github.com/0xMiden/crypto/pull/965)).
- Reduce repeated history scans in historical `LargeSmtForest::open()` queries ([#971](https://github.com/0xMiden/crypto/pull/971)).

## miden-vm v0.22.1 (2026-04-07)

- Implemented project assembly ([#2877](https://github.com/0xMiden/miden-vm/pull/2877)).
- Added `FastProcessor::into_parts()` to extract advice provider, memory, and precompile transcript after step-based execution ([#2901](https://github.com/0xMiden/miden-vm/pull/2901)).

## miden-vm v0.22.0 (2026-03-19)

#### Enhancements

- Define and implement Miden project file format ([#2510](https://github.com/0xMiden/miden-vm/pull/2510)).
- Added `math::u128` comparison (`lt`, `lte`, `gt`, `gte`), bitwise (`and`, `or`, `xor`, `not`), and shift (`shl`, `shr`, `rotl`, `rotr`) operations ([#2624](https://github.com/0xMiden/miden-vm/pull/2624)).
- [BREAKING] `build_trace()` no longer assumes valid user input ([#2747](https://github.com/0xMiden/miden-vm/pull/2747)).
- Added `math::u128` division operations ([#2776](https://github.com/0xMiden/miden-vm/pull/2776)).
- [BREAKING] Migrated to lifted-STARK backend and `miden-crypto` to v0.23 ([#2783](https://github.com/0xMiden/miden-vm/pull/2783)).

#### Changes

- Consolidated error variants: simplified `AceError` and FRI errors to string-based types, merged `DynamicNodeNotFound`/`NoMastForestWithProcedure` into `ProcedureNotFound`, introduced `HostError` for handler-related variants ([#2675](https://github.com/0xMiden/miden-vm/pull/2675)).
- Added optional tagging instrumentation for AIR constraints (test-only; enables stable ID tracking and OOD parity checks) ([#2713](https://github.com/0xMiden/miden-vm/pull/2713)).
- [BREAKING] `Processor` and `FastProcessor` decorator execution is now immutable ([#2718](https://github.com/0xMiden/miden-vm/pull/2718)).
- [BREAKING] `Tracer` API significantly refactored ([#2720](https://github.com/0xMiden/miden-vm/pull/2720)).
- Added general stack transition constraints (shift/no‑shift) ([#2725](https://github.com/0xMiden/miden-vm/pull/2725)).
- Added stack overflow table constraints ([#2735](https://github.com/0xMiden/miden-vm/pull/2735)).
- Added stack shuffling ops constraints ([#2736](https://github.com/0xMiden/miden-vm/pull/2736)).
- [BREAKING] Renamed `miden::core::crypto::dsa::falcon512poseidon2` module to `falcon512_poseidon2` to align with snake_case naming convention ([#2740](https://github.com/0xMiden/miden-vm/issues/2740)).
- Added `miden-ace-codegen` crate for lowering AIR constraints to ACE circuit format ([#2757](https://github.com/0xMiden/miden-vm/pull/2757)).
- [BREAKING] `Operation` enum now only encodes basic block operations ([#2771](https://github.com/0xMiden/miden-vm/pull/2771)).
- Added AIR constraints for system, range checker, stack, decoder, and chiplets components ([#2772](https://github.com/0xMiden/miden-vm/pull/2772)).
- Added recursion guards for assembly inputs and tests ([#2792](https://github.com/0xMiden/miden-vm/pull/2792)).
- Introduced `build_trace_with_max_len()` which stops building the trace after a given max, and `build_trace()` no longer allocates more than 2^29 rows ([#2809](https://github.com/0xMiden/miden-vm/pull/2809)).
- `DebugHandler`'s default method implementations are now no-ops (instead of prints) ([#2837](https://github.com/0xMiden/miden-vm/pull/2837)).
- Added `ExecutionTrace::check_constraints()` for fast debug constraint checking without STARK proving, and migrated tests from `prove_and_verify` ([#2846](https://github.com/0xMiden/miden-vm/pull/2846)).
- [BREAKING] Updated the dependency on `midenc-hir-type` to 0.5.0, which changes the set of available calling conventions, and adds support for enum types and named struct types. ([#2848](https://github.com/0xMiden/miden-vm/pull/2848))
- [BREAKING] `StructType::new` now expects an optional name to be specified ([#2848](https://github.com/0xMiden/miden-vm/pull/2848))
- [BREAKING] `Variant::new` now expects an optional payload type to be specified ([#2848](https://github.com/0xMiden/miden-vm/pull/2848))
- [BREAKING] Enum types are now exported from libraries as a `midenc_hir_type::EnumType`, rather than the type of the discriminant. ([#2848](https://github.com/0xMiden/miden-vm/pull/2848))
- In `ExecutionTracer`, we no longer record node flags in `CoreTraceFragmentContext` when entering a node (they are redundant) ([#2866](https://github.com/0xMiden/miden-vm/pull/2866))
- Updated the recursive STARK verifier to work with the lifted-STARK / `p3-miden` backend ([#2869](https://github.com/0xMiden/miden-vm/pull/2869)).
- Switched Keccak STARK config to use stateful binary sponge with `[Felt; VECTOR_LEN]` packing, and reorganized `config.rs` into per-hash-family sections ([#2874](https://github.com/0xMiden/miden-vm/pull/2874)).
- Add support to the `Assembler` for assembling Miden projects to Miden packages ([#2877](https://github.com/0xMiden/miden-vm/pull/2877))

#### Fixes

- Fixed `ExecutionTracer` DYNCALL stack-depth off-by-one at `MIN_STACK_DEPTH` ([#2813](https://github.com/0xMiden/miden-vm/issues/2813)).
- Fixed C-like enum validation and constant materialization in `define_enum` ([#2887](https://github.com/0xMiden/miden-vm/pull/2887)).
- **toposort_caller**: Fixed cycle detection in assembly call graph ([#2871](https://github.com/0xMiden/miden-vm/pull/2871)).

- Fixed `Constant::PartialEq` to include `visibility` field in equality comparison, making it consistent with other exportable items (`Procedure`, `TypeAlias`, `EnumType`).
- Cryptostream operation now correctly sends chiplets bus memory requests ([#2686](https://github.com/0xMiden/miden-vm/pull/2686)).
- Fixed a possible panic in decorator serialization ([#2742](https://github.com/0xMiden/miden-vm/pull/2742)).
- Hardened untrusted deserialization by enforcing budgets and depth limits, plus expanded fuzzing coverage ([#2777](https://github.com/0xMiden/miden-vm/pull/2777)).
- Validated push immediate group commitments and slot placement to reject invalid immediates ([#2779](https://github.com/0xMiden/miden-vm/pull/2779)).
- Added documentation for `math::u64` module operations ([#2781](https://github.com/0xMiden/miden-vm/pull/2781)).
- Prevented a trace-generation panic by validating op batch groups in basic blocks ([#2782](https://github.com/0xMiden/miden-vm/pull/2782)).
- Preserved dynexec/dyncall distinction (and digests) when remapping or merging MAST forests ([#2784](https://github.com/0xMiden/miden-vm/pull/2784)).
- Hardened AEAD decrypt size calculations ([#2789](https://github.com/0xMiden/miden-vm/pull/2789)).
- Introduced `FastProcessor` safe stack method accesses for event handlers ([#2797](https://github.com/0xMiden/miden-vm/pull/2797)).
- Fixed a possible u64 overflow issue in `op_eval_circuit()` [#2799](https://github.com/0xMiden/miden-vm/pull/2799).
- `SystemEvent::HpermToMap` handler now computes the correct permutation ([#2801](https://github.com/0xMiden/miden-vm/pull/2801)).
- Hardened MASM parsing and constants handling (lexer invalid-token spans, repeat count bounds, constant range checks, field division folding, and `push.WORD[...]` index validation) ([#2803](https://github.com/0xMiden/miden-vm/pull/2803)).
- Hardened syscall target validation to avoid panic paths and reject invalid digests at assembly time ([#2804](https://github.com/0xMiden/miden-vm/pull/2804)).
- Added bounds to attacker-controlled allocation sizes in advice map and keccak256/sha512 precompiles ([#2805](https://github.com/0xMiden/miden-vm/pull/2805)).
- Hardened boundary and overflow checks for `u64::shr`, `ilog2`, `u32clz`, and Falcon `mod_12289` ([#2808](https://github.com/0xMiden/miden-vm/pull/2808)).
- `build_trace()` no longer panics when no core trace contexts are provided ([#2809](https://github.com/0xMiden/miden-vm/pull/2809)).
- Set a bound on `ContinuationStack` size, checked during execution ([#2825](https://github.com/0xMiden/miden-vm/pull/2825)).
- Hardened basic-block batch validation and decode-time padding checks to reject inconsistent padded groups and prevent raw-helper underflow/panic paths on malformed forests ([#2839](https://github.com/0xMiden/miden-vm/pull/2839)).
- Fixed undefined behavior in parallel trace generation by limiting H0 batch inversion to initialized rows ([#2842](https://github.com/0xMiden/miden-vm/pull/2842)).
- `Visit` and `VisitMut` traits now properly visit enum type discriminant values, as well as the new payload `TypeExpr` when present ([#2848](https://github.com/0xMiden/miden-vm/pull/2848)).
- Enforced canonical kernel procedure-hash validation on binary and serde deserialization paths, and expanded serde deserialization fuzz coverage for related artifact types ([#2849](https://github.com/0xMiden/miden-vm/pull/2849)).
- Fixed constant evaluation across semantic analysis and linking so exported constants no longer retain private local dependencies and cross-module constant chains resolve in the defining module ([#2873](https://github.com/0xMiden/miden-vm/pull/2873)).

## miden-crypto v0.23.0 (2026-03-11)

- Replaced `Subtree` internal storage with bitmask layout ([#784](https://github.com/0xMiden/crypto/pull/784)).
- [BREAKING] Enforced a maximum MMR forest size and made MMR/forest constructors and appends fallible to reject oversized inputs ([#857](https://github.com/0xMiden/crypto/pull/857)).
- [BREAKING] `PartialMmr::open()` now returns `Option<MmrProof>` instead of `Option<MmrPath>` ([#787](https://github.com/0xMiden/crypto/pull/787)).
- [BREAKING] Refactored BLAKE3 to use `Digest<N>` struct, added `Digest192` type alias ([#811](https://github.com/0xMiden/crypto/pull/811)).
- [BREAKING] Added validation to `PartialMmr::from_parts()` and `Deserializable` implementation, added `from_parts_unchecked()` for performance-critical code ([#812](https://github.com/0xMiden/crypto/pull/812)).
- [BREAKING] Removed `hashbrown` dependency and `hashmaps` feature; `Map`/`Set` type aliases are now tied to the `std` feature ([#813](https://github.com/0xMiden/crypto/pull/813)).
- [BREAKING] Renamed `NodeIndex::value()` to `NodeIndex::position()`, `NodeIndex::is_value_odd()` to `NodeIndex::is_position_odd()`, and `LeafIndex::value()` to `LeafIndex::position()` ([#814](https://github.com/0xMiden/crypto/pull/814)).
- Fixed `LargeSmtForest::truncate` to remove emptied lineages from `non_empty_histories` ([#818](https://github.com/0xMiden/crypto/pull/818)).
- [BREAKING] Fixed OOMs in Merkle/SMT deserialization ([#820](https://github.com/0xMiden/crypto/pull/820)).
- Fixed `SmtForest` to remove nodes with zero reference count from store ([#821](https://github.com/0xMiden/crypto/pull/821)).
- Cross-checked RPO test vectors against the Python reference implementation after state layout change ([#822](https://github.com/0xMiden/crypto/pull/822)).
- Fixed tuple `min_serialized_size()` to exclude alignment padding, fixing `BudgetedReader` rejecting valid data ([#827](https://github.com/0xMiden/crypto/pull/827)).
- Fixed possible panic in `XChaCha::decrypt_bytes_with_associated_data` and harden deserialization with fuzzing across 7 new targets ([#836](https://github.com/0xMiden/crypto/pull/836)).
- Added `Signature::from_der()` for ECDSA signatures over secp256k1 ([#842](https://github.com/0xMiden/crypto/pull/842)).
- [BREAKING] Added info context field to secret box, bind IES HKDF info to a stable context string, scheme identifier, and ephemeral public key bytes. ([#843](https://github.com/0xMiden/crypto/pull/843)).
- Use `read_from_bytes_with_budget()` instead of read_from_bytes for deserialization from untrusted sources, setting the budget to the actual input byte slice length. ([#846](https://github.com/0xMiden/crypto/pull/846)).
- [BREAKING] Removed `PartialEq`/`Eq` for AEAD `SecretKey` in non-test builds, fix various hygiene issues in dealing with secret keys ([#849](https://github.com/0xMiden/crypto/pull/849)).
- Added `PublicKey::from_der()` for ECDSA public keys over secp256k1 ([#855](https://github.com/0xMiden/crypto/pull/855)).
- [BREAKING] Fixed `NodeIndex::to_scalar_index()` overflow at depth 64 by returning `Result<u64, MerkleError>` ([#865](https://github.com/0xMiden/crypto/issues/865)).
- [BREAKING] Removed `RpoRandomCoin` and `RpxRandomCoin` and introduced a Poseidon2-based `RandomCoin` ([#871](https://github.com/0xMiden/crypto/pull/871)).
- Harden MerkleStore deserialization and fuzz coverage ([#878](https://github.com/0xMiden/crypto/pull/878)).
- [BREAKING] Upgraded Plonky3 from 0.4.2 to 0.5.0 and replaced `p3-miden-air`, `p3-miden-fri`, and `p3-miden-prover` with the unified `miden-lifted-stark` crate. The `stark` module now re-exports the Lifted STARK proving system from [p3-miden](https://github.com/0xMiden/p3-miden).
- [BREAKING] Changed the `LargeSmtForest::entries` iterator to be fallible by explicitly returning `Result<TreeEntry>` as the iterator item.
- [BREAKING] Updated `SparseMerkleTree` and its implementations to reject batches of key-value pairs that contain more than one instance of any given key. This may cause previously successful operations to now fail if your input batch is not de-duplicated.
- [BREAKING] `SimpleSmt::compute_mutations` now returns a result so it can fail gracefully if the input batch contains duplicate keys.

## miden-vm v0.21.2 (2026-03-04)

- Removes `features = serde` from `miden-core` in `miden-air` to avoid unconditionally enabling the `serde` dependency  ([#2767](https://github.com/0xMiden/miden-vm/pull/2767)).

## miden-crypto v0.22.4 (2026-03-03)

- Make `SmtLeaf::get_value` public ([#872](https://github.com/0xMiden/crypto/pull/872)).

## miden-crypto v0.22.3 (2026-02-24)

- Refactored to introduce a unified `Felt` type for on-chain and off-chain code ([#819](https://github.com/0xMiden/crypto/pull/819)).
- Change `Ord for Word` to use lexicographic ordering ([#847](https://github.com/0xMiden/crypto/pull/847)).
- Add `From<{u8, u16, u32}> for Felt` and `TryFrom<u64> for Felt` ([#848](https://github.com/0xMiden/crypto/pull/848)).

## miden-vm v0.21.1 (2026-02-24)

- Added debug variable tracking for source-level variables via dedicated `DebugVarStorage` (CSR format) in `DebugInfo`, with `DebugVarInfo` describing variable name, type, location, and value location (stack, memory, local, constant, or expression). Also added `debug_types`, `debug_sources`, and `debug_functions` sections in MASP packages for storing type definitions, source file paths, and function metadata respectively, each with its own string table, to support source-level debugging ([#2471](https://github.com/0xMiden/miden-vm/pull/2471)).
- Updated `miden-crypto` to v0.22.3 (with unified `Felt` type) ([#2649](https://github.com/0xMiden/miden-vm/pull/2649))
- Re-exported `Continuation` from `miden-processor` to support the external debugger ([#2683](https://github.com/0xMiden/miden-vm/pull/2683)).
- Fixed `mtree_merge` advice-store root ordering to match `hmerge` operand stack semantics ([#2729](https://github.com/0xMiden/miden-vm/pull/2729)).
- Updated `sorted_array::find_half_key_value` to use little-endian ordering ([#2734](https://github.com/0xMiden/miden-vm/pull/2734)).
- Fixed `Assembler::warnings_as_errors` not being propagated in some methods ([#2737](https://github.com/0xMiden/miden-vm/pull/2737)).

## miden-vm v0.21.0 (2026-02-14)

#### Major breaking changes

- [BREAKING] Changed backend from winterfell to Plonky3 ([#2472](https://github.com/0xMiden/miden-vm/pull/2472)).
- [BREAKING] Removed `Process`, `VmStateIterator` and `miden_processor::execute_iter()` ([#2483](https://github.com/0xMiden/miden-vm/pull/2483)).
- [BREAKING] Removed `miden debug`, `miden analyze` and `miden repl` ([#2483](https://github.com/0xMiden/miden-vm/pull/2483)).
- [BREAKING] Standardized operand-stack ordering around a unified little-endian (LE) convention (low limb/coeff closest to the top). This includes multi-limb integer ops, extension field elements, and streaming memory operations. Also remapped the sponge state and adjusts hperm/digest extraction plus advice hash-insert instructions for consistent LE semantics. ([#2547](https://github.com/0xMiden/miden-vm/pull/2547)).
- [BREAKING] Renamed `u32overflowing_mul` to `u32widening_mul`, `u32overflowing_madd` to `u32widening_madd`, and `math::u64::overflowing_mul` to `math::u64::widening_mul` ([#2584](https://github.com/0xMiden/miden-vm/pull/2584)).
- [BREAKING] Changed the VM’s native hash function from RPO to Poseidon2 ([#2599](https://github.com/0xMiden/miden-vm/pull/2599)).

#### Enhancements

- Added initial `math::u128` functions for lib/core/math runtime. ([#2438](https://github.com/0xMiden/miden-vm/pull/2438)).
- Added constants support as an immediate value of the repeat statement ([#2548](https://github.com/0xMiden/miden-vm/pull/2548)).
- Added `procedure_names` to `DebugInfo` for storing procedure name mappings by MAST root digest, enabling debuggers to resolve human-readable procedure names during execution (#[2474](https://github.com/0xMiden/miden-vm/pull/2474)).
- Added deserialization of the `MastForest` from untrusted sources. Add fuzzing for MastForest deserialization. ([#2590](https://github.com/0xMiden/miden-vm/pull/2590)).
- Added `StackInterface::get_double_word()` method for reading 8 consecutive stack elements ([#2607](https://github.com/0xMiden/miden-vm/pull/2607)).
- Added error messages to asserts in the standard library ([#2650](https://github.com/0xMiden/miden-vm/pull/2650))
- Optimized `ExecutionTracer` to avoid cloning `Vec<OpBatch>` on every basic block entry. ([#2664](https://github.com/0xMiden/miden-vm/pull/2664))

#### Fixes

- Fixed memory chiplet constraint documentation: corrected `f_i` variable definitions, first row flag, and `f_mem_nl` constraint expression ([#2423](https://github.com/0xMiden/miden-vm/pull/2423)).
- Removed the intentional HALT-insertion bug from the parallel trace generation ([#2484](https://github.com/0xMiden/miden-vm/pull/2484)).
- `FastProcessor` now correctly returns an error if the maximum number of cycles was exceeded during execution ([#2537](https://github.com/0xMiden/miden-vm/pull/2537)).
- `FastProcessor` now correctly only executes `trace` decorators when tracing is enabled (with `ExecutionOptions`) ([#2539](https://github.com/0xMiden/miden-vm/pull/2539)).
- Fixed a bug where trace generation would fail if a core trace fragment started on the `END` operation of a loop that was not entered ([#2587](https://github.com/0xMiden/miden-vm/pull/2587)).
- Added missing `as_canonical_u64()` method to `IntValue` in `miden-assembly-syntax`, fixing compilation errors in the generated grammar code ([#2589](https://github.com/0xMiden/miden-vm/pull/2589)).
- Fixed off-by-one error in cycle limit check that caused programs using exactly `max_cycles` cycles to fail ([#2635](https://github.com/0xMiden/miden-vm/pull/2635)).
- Fixed prover log message reporting `main_trace_len()` instead of `trace_len()` for the pre-padding length ([#2671](https://github.com/0xMiden/miden-vm/pull/2671)).
- System event errors now include the operation index, so diagnostics point to the exact emit instruction instead of the first operation in the basic block ([#2672](https://github.com/0xMiden/miden-vm/pull/2672)).
- Added generation of `AssemblyOp` decorators for `JoinNode`s so that error diagnostics can point to the `begin...end` block ([#2674](https://github.com/0xMiden/miden-vm/pull/2674)).
- Renamed snapshot test files to use `__` instead of `::` for Windows compatibility ([#2580](https://github.com/0xMiden/miden-vm/pull/2580)).

#### Changes

- Added `--kernel` flag to CLI commands (`run`, `prove`, `verify`, `debug`) to allow loading custom kernels from `.masm` or `.masp` files ([#2363](https://github.com/0xMiden/miden-vm/pull/2363)).
- Implemented running batch inversion concurrently per fragment in parallel trace generation ([#2405](https://github.com/0xMiden/miden-vm/issues/2405)).
- Added MastForest validation ([#2412](https://github.com/0xMiden/miden-vm/pull/2412)).
- Removed undocumented `err_code` field from `ExecutionError::NotU32Values` ([#2419](https://github.com/0xMiden/miden-vm/pull/2419)).
- [BREAKING] Moved `get_assembly_op` to the `MastForest`, remove trait `MastNodeErrorContext` ([#2430](https://github.com/0xMiden/miden-vm/pull/2430)).
- Added a cached commitment to the `MastForest` ([#2447](https://github.com/0xMiden/miden-vm/pull/2447))
- Moved `bytes_to_packed_u32_elements` to `miden-core::utils` and added `packed_u32_elements_to_bytes` inverse function ([#2458](https://github.com/0xMiden/miden-vm/pull/2458)).
- [BREAKING] Changed serialization of `BasicBlockNode`s to use padded indices ([#2466](https://github.com/0xMiden/miden-vm/pull/2466/)).
- Changed padded serialization of `BasicBlockNode`s to use delta-encoded metadata ([#2469](https://github.com/0xMiden/miden-vm/pull/2469/)).
- Changed (de)serialization of `MastForest` to directly (de)serialize DebugInfo ([#2470](https://github.com/0xMiden/miden-vm/pull/2470/)).
- Added validation of `core_trace_fragment_size` in `ExecutionOptions` ([#2528](https://github.com/0xMiden/miden-vm/pull/2528)).
- Removed `ErrorContext` trait and `err_ctx!` macro; error context is now computed lazily by passing raw parameters to error extension traits ([#2544](https://github.com/0xMiden/miden-vm/pull/2544)).
- Added `MastForest::write_stripped()` to serialize without `DebugInfo` ([#2549](https://github.com/0xMiden/miden-vm/pull/2549)).
- Added API to serialize the `MastForest` without `DebugInfo` ([#2549](https://github.com/0xMiden/miden-vm/pull/2549)).
- [BREAKING] Rename `MastForest::strip_decorators()` to `MastForest::clear_debug_info()` ([#2554](https://github.com/0xMiden/miden-vm/pull/2554)).
- Documented `push.[a,b,c,d]` word literal syntax ([#2556](https://github.com/0xMiden/miden-vm/issues/2556)).
- Use `IndexVec::try_from` instead of pushing elements one by one in `DebugInfo::empty_for_nodes` ([#2559](https://github.com/0xMiden/miden-vm/pull/2559)).
- Changed `assert_u32` helper function to return `u32` instead of `Felt` ([#2575](https://github.com/0xMiden/miden-vm/issues/2575)).
- Made `StackInputs` and `StackOutputs` implement `Copy` trait ([#2581](https://github.com/0xMiden/miden-vm/pull/2581)).
- Added malicious advice provider tests for MASM validation using advice stack initialization ([#2583](https://github.com/0xMiden/miden-vm/pull/2583)).
- [BREAKING] Removed `NodeExecutionState` in favor of `Continuation` ([#2587](https://github.com/0xMiden/miden-vm/pull/2587)).
- [BREAKING] Removed `SyncHost` and `BaseHost`, and renamed `AsyncHost` to `Host` ([#2595](https://github.com/0xMiden/miden-vm/pull/2595)).
- [BREAKING] Moved `ExecutionOptions` to `miden-processor`, `ProvingOptions` to `miden-prove`, and `ExecutionProof` to `miden-core` (all out of `miden-air`) ([#2597](https://github.com/0xMiden/miden-vm/pull/2597)).
- [BREAKING] Removed `on_assert_failed` method from `Host` trait ([#2600](https://github.com/0xMiden/miden-vm/pull/2600)).
- [BREAKING] Added builder methods (`with_advice()`, `with_debugging()`, `with_tracing()`, `with_options()`) directly on `FastProcessor` for fluent configuration. Removed deprecated `new_with_advice_inputs()` and `new_debug()` constructors ([#2602](https://github.com/0xMiden/miden-vm/issues/2602), [#2625](https://github.com/0xMiden/miden-vm/pull/2625)).
- Consolidated testing hosts by merging `TestConsistencyHost` into `TestHost` and reusing the unified host in tests ([#2603](https://github.com/0xMiden/miden-vm/pull/2603)).
- [BREAKING] Converted `ProcessState` to a struct wrapping `FastProcessor`, and rename it to `ProcessorState` ([#2604](https://github.com/0xMiden/miden-vm/pull/2604)).
- [BREAKING] Cleaned up `StackInputs` and `StackOutputs` API, and use `StackInputs` in `FastProcessor` constructors ([#2605](https://github.com/0xMiden/miden-vm/pull/2605)).
- [BREAKING] Separated AsmOp storage from Debug/Trace decorators. ([#2606](https://github.com/0xMiden/miden-vm/pull/2606)).
- [BREAKING] Added widening `u32` add variants and aligned `math::u64/math::u256` APIs and docs with little‑endian stack conventions ([#2614](https://github.com/0xMiden/miden-vm/pull/2614)).
- [BREAKING] Abstracted away program execution using the sans-IO pattern ([#2615](https://github.com/0xMiden/miden-vm/pull/2615)).
- [BREAKING] Removed `PushMany` trait and `new_array_vec()` from `miden-core` ([#2630](https://github.com/0xMiden/miden-vm/pull/2630)).
- [BREAKING] Removed unused `meta` field from `ExecutionTrace` and changed the constructor to take `ProgramInfo` ([#2639](https://github.com/0xMiden/miden-vm/pull/2639)).
- [BREAKING] `Host::on_debug()` and `Host::on_trace()` now take immutable references to `ProcessorState` ([#2639](https://github.com/0xMiden/miden-vm/pull/2639)).
- [BREAKING] Migrated parallel trace generation to use the common `execute_impl()` ([#2642](https://github.com/0xMiden/miden-vm/pull/2642)).
- [BREAKING] Removed unused `should_break` field from `AssemblyOp` decorator ([#2646](https://github.com/0xMiden/miden-vm/pull/2646)).
- [BREAKING] Updated processor module structure ([#2651](https://github.com/0xMiden/miden-vm/pull/2651)).
- [BREAKING] Removed `breakpoint` instruction from assembly ([#2655](https://github.com/0xMiden/miden-vm/pull/2655)).
- Removed FRI domain offset from `fri_ext2fold4` operation for Plonky3 compatibility ([#2670](https://github.com/0xMiden/miden-vm/pull/2670)).
- [BREAKING] Removed `Tracer` arguments from `Processor` methods ([#2676](https://github.com/0xMiden/miden-vm/pull/2676)).

## miden-vm v0.20.6 (2026-02-04)

- Fixed issue with link-time symbol resolution that prevented referencing an imported item as locally-defined, e.g. an import like `use some::module::CONST` used via something like `emit.CONST` would fail to resolve correctly. [#2637](https://github.com/0xMiden/miden-vm/pull/2637)

## miden-vm v0.20.5 (2026-02-02)

- Fixed issue with deserialization of Paths due to lifetime restrictions [#2627](https://github.com/0xMiden/miden-vm/pull/2627)
- Implemented path canonicalization and modified Path/PathBuf APIs to canonicalize paths during construction. This also addressed some issues uncovered during testing where some APIs were not canonicalizing paths, or path-related functions were inconsistent in their behavior due to special-casing that was previously needed [#2627](https://github.com/0xMiden/miden-vm/pull/2627)

## miden-crypto v0.22.2 (2026-02-01)

- Re-exported `p3_keccak::VECTOR_LEN`.

## miden-crypto v0.22.1 (2026-02-01)

- Re-exported additional Plonky3 modules and structs.
- Implemented `batch_inversion_allow_zeros()` function.

## miden-vm v0.20.4 (2026-01-30)

- Fixed issue with handling of quoted components in `PathBuf` [#2618](https://github.com/0xMiden/miden-vm/pull/2618)

## miden-crypto v0.22.0 (2026-01-27)

- Added const-generic `Digest<N>` struct for binary hash functions with `Digest256` and `Digest512` type aliases ([#777](https://github.com/0xMiden/crypto/pull/777)).
- Added `MmrPath::with_forest()` and `MmrProof::with_forest()` to adjust proofs for smaller forests ([#788](https://github.com/0xMiden/crypto/pull/788)).
- [BREAKING] Migrate from RPO to Poseidon2 for AEAD, Falcon DSA, IES, and Merkle trees ([#793](https://github.com/0xMiden/crypto/pull/793)).
- Updated SMT benchmark executable to use Poseidon2 instead of Rpo256 ([#800](https://github.com/0xMiden/crypto/pull/800)).

## miden-vm v0.20.3 (2026-01-27)

- Fixed issue where exports of a Library did not have attributes serialized [#2608](https://github.com/0xMiden/miden-vm/issues/2608)

## miden-crypto v0.21.4 (2026-01-23)

- Fix an issue where `BudgetedReader` rejects valid usize collections with tight budgets ([#798](https://github.com/0xMiden/crypto/pull/798)).

## miden-crypto v0.21.3 (2026-01-21)

- Fix: don't disable WAL during subtree construction in `LargeSmt`'s RocksDB backend ([#794](https://github.com/0xMiden/crypto/pull/794)).

## miden-crypto v0.21.2 (2026-01-20)

- Exported `BudgetedReader` to allow for defense-in-depth against deserialization panics ([#786](https://github.com/0xMiden/crypto/pull/786)).

## miden-crypto v0.21.1 (2026-01-16)

- Changed `SmtForest` so that `EMPTY_WORD` is treated as removals ([#780](https://github.com/0xMiden/crypto/pull/780)).

## miden-crypto v0.21.0 (2026-01-14)

- Use more idiomatic Plonky3 APIs ([#743](https://github.com/0xMiden/crypto/pull/743)).
- [BREAKING] Removed `p3-compat` and `winter-compat` features ([#745](https://github.com/0xMiden/crypto/pull/745)).
- Made concurrent feature interact with plonky3's parallel features, replace homegrown iterator macros with p3-maybe-rayon ([#749](https://github.com/0xMiden/crypto/pull/749)).
- Reduced dependency on std in tests, add test helpers to access Rngs in no-std contexts ([#752](https://github.com/0xMiden/crypto/pull/752)).
- [BREAKING] Changed sponge state layout from `[CAPACITY, RATE1, RATE0]` (BE) to `[RATE0, RATE1, CAPACITY]` (LE) ([#755](https://github.com/0xMiden/crypto/pull/755)).
- [BREAKING] Added length-prefixing to Serializable/Deserializable impls for collections, fuzz deserialization for panics ([#757](https://github.com/0xMiden/crypto/pull/757)).
- Added `SmtLeaf::try_from_elements()` ([#773](https://github.com/0xMiden/crypto/pull/773)).
- Copied `WordWrapper` macro from `miden-base` to `miden-crypto-derive`.

# 0.20.1 (2025-12-29)

- Added more re-exports from Plonky3 dependencies ([#741](https://github.com/0xMiden/crypto/pull/741)).

## miden-vm v0.20.2 (2026-01-05)

- Fixed issue where decorator access was not bypassed properly in release mode ([#2529](https://github.com/0xMiden/miden-vm/pull/2529)).

## miden-crypto v0.20.0 (2025-12-28)

- [BREAKING] Renamed `MmrProof` to `MmrPath`, and introduce a new `MmrProof` with the leaf value included ([#656](https://github.com/0xMiden/crypto/pull/656)).
- Added `+ Sync` bound to `StorageError` and `LargeSmtError` ([#680](https://github.com/0xMiden/crypto/pull/680)).
- [BREAKING] Refactored `SmtProof` verification API to return `Result<(), SmtProofError>` ([#682](https://github.com/0xMiden/crypto/pull/682)).
- Added validation to `PartialMerkleTree::with_leaves()` to reject internal nodes ([#684](https://github.com/0xMiden/crypto/pull/684)).
- Decoupled `PartialSmt` from `Smt` and expanded tracking to include provably empty leaves, allowing updates in empty subtrees ([#691](https://github.com/0xMiden/crypto/pull/691)).
- Added SHA-256 and SHA-512 hash function wrappers ([#692](https://github.com/0xMiden/crypto/pull/692)).
- [BREAKING] Moved `LargeSmt` root ownership from storage to in-memory layer ([#694](https://github.com/0xMiden/crypto/pull/694)).
- Removed use of `transmute()` in blake3 implementation ([#704](https://github.com/0xMiden/crypto/pull/704)).
- [BREAKING] Made `LargeSmt::num_leaves()` and `LargeSmt::num_entries()` infallible ([#708](https://github.com/0xMiden/crypto/pull/708)).
- [BREAKING] Changed `SmtStorage` mutator methods from `&self` to `&mut self` ([#709](https://github.com/0xMiden/crypto/pull/709)).
- `PartialMmr::untrack()` now returns the removed authentication nodes ([#714](https://github.com/0xMiden/crypto/pull/714)).
- [BREAKING] Imported miden-serde-utils crate for serialization ([#715](https://github.com/0xMiden/crypto/pull/715)).
- [BREAKING] Replaced underlying field implementation with Plonky3 backend ([#720](https://github.com/0xMiden/crypto/pull/720)).
- Trimmed down hash benchmarks, restored Poseidon2 testing, removed unnecessary size parameterization from merge benchmarks ([#737](https://github.com/0xMiden/crypto/pull/737))
- [BREAKING] Removed 160-bit variant of the BLAKE3 hash function.

## miden-vm v0.20.1 (2025-12-14)

- Fixed issue where calling procedures from statically linked libraries did not import their decorators ([#2459](https://github.com/0xMiden/miden-vm/pull/2459)).

## miden-vm v0.20.0 (2025-12-05)

#### Enhancements

- Added SHA512 hash precompile in `miden::core::crypto::hashes::sha512` ([#2312](https://github.com/0xMiden/miden-vm/pull/2312)).
- Added EdDSA (Ed25519) signature verification precompile in `miden::core::crypto::dsa::eddsa_ed25519` ([#2312](https://github.com/0xMiden/miden-vm/pull/2312)).
- Added AEAD implementation in the VM using `crypto_stream` instruction ([#2322](https://github.com/0xMiden/miden-vm/pull/2322)).
- Added new `adv.push_mapval_count` instruction ([#2349](https://github.com/0xMiden/miden-vm/pull/2349)).
- Added new `memcopy_elements` procedure for the `std::mem` module ([#2352](https://github.com/0xMiden/miden-vm/pull/2352)).
- Implemented link-time const evaluation; simplified linker implementation and improved consistency of symbol resolution and associated errors ([#2370](https://github.com/0xMiden/miden-vm/pull/2370)).
- Added new `peek` procedure for the `std::collections::smt` module ([#2387](https://github.com/0xMiden/miden-vm/pull/2387)).
- Added new `pad_and_hash_elements` procedure to the `std::crypto::hashes::rpo` module ([#2395](https://github.com/0xMiden/miden-vm/pull/2395)).
- Added padding option for the `adv.push_mapvaln` instruction ([#2398](https://github.com/0xMiden/miden-vm/pull/2398)).
- Added new `FastProcessor::step()` method that executes a single clock cycle ([#2440](https://github.com/0xMiden/miden-vm/pull/2440))

#### Changes

- [BREAKING] Added builder patterns for all `MastNode` types, made naked constructors module-private ([#2259](https://github.com/0xMiden/miden-vm/pull/2259)).
- Extended builder patterns for all `MastNode` types ([#2274](https://github.com/0xMiden/miden-vm/pull/2274)).
- Further extended builder patterns for all `MastNode` types, replace `enum-dispatch` by our own derivations ([#2291](https://github.com/0xMiden/miden-vm/pull/2291)).
- Finished builder pattern conversion and delete old `MastNode` mutable APIs ([#2301](https://github.com/0xMiden/miden-vm/pull/2301)).
- Hoist `BasicBlock` decorator storage to the `MastForest` after insertion in said `MastForest` ([#2310](https://github.com/0xMiden/miden-vm/pull/2310)).
- [BREAKING] hoist before_enter and after_exit decorators to MastForest ([#2323](https://github.com/0xMiden/miden-vm/pull/2323)).
- [BREAKING] Make argument order of `Assembler::compile_and_statically_link_from_dir` consistent with `Assembler::assemble_library_from_dir`.
- [BREAKING] Renamed `Library::get_procedure_root_by_name` to `Library::get_procedure_root_by_path`.
- Added missing implementations of `proptest::Arbitrary` for non-`BasicBlockNode` variants of `MastNode` ([#2335](https://github.com/0xMiden/miden-vm/pull/2335)).
- Fixed `locaddr` alignment when procedure local count is not a multiple of 4 ([#2350](https://github.com/0xMiden/miden-vm/pull/2350)).
- Streamline MastNode APIs and remove redundant parameters from `execute_op_batch` functions ([#2360](https://github.com/0xMiden/miden-vm/pull/2360)).
- [BREAKING] Host debug and trace handlers return dynamic errors ([#2367](https://github.com/0xMiden/miden-vm/pull/2367)).
- [BREAKING] Standardized hash function naming: renamed `hash_2to1` → `merge` and `hash_1to1` → `hash` across all hash modules (blake3, sha256, keccak256, rpo) ([#2381](https://github.com/0xMiden/miden-vm/pull/2381)).
- Consolidate debug information into `DebugInfo` struct ([#2366](https://github.com/0xMiden/miden-vm/issues/2366)).
- Wrapped `hperm` instruction in `rpo::permute` procedure ([#2392](https://github.com/0xMiden/miden-vm/pull/2392)).
- `hash_memory_with_state`, `hash_memory_words`, and `hash_memory_double_words` procedures from the `std::crypto::hashes::rpo` module were renamed to the `hash_elements_with_state`, `hash_words`, and `hash_double_words` respectively ([#2395](https://github.com/0xMiden/miden-vm/pull/2395)).
- [BREAKING] Upgraded `miden-crypto` to 0.19 ([#2399](https://github.com/0xMiden/miden-vm/pull/2399)).
- Added missing modules to libcore documentation ([#2416](https://github.com/0xMiden/miden-vm/pull/2416)).
- Pre-allocate main trace buffer in trace generation ([#2345](https://github.com/0xMiden/miden-vm/pull/2345)).
- Renamed the MASM standard library to "miden::core", the crate to `miden-core-lib`, and various other MASM module refactors ([#2260](https://github.com/0xMiden/miden-vm/issues/2260)) ([#2427](https://github.com/0xMiden/miden-vm/pull/2427)).
- Added a compaction function for achieving maximal sharing out of a `MastForest` with stripped decorators ([#2408](https://github.com/0xMiden/miden-vm/pull/2408)).
- Refactored and remove tech debt from parallel trace generation ([#2382](https://github.com/0xMiden/miden-vm/pull/2382))
- [BREAKING] Added `kind` field to `Package` struct to indicate package type (Executable, AccountComponent, NoteScript, TxScript, AuthComponent) ([#2403](https://github.com/0xMiden/miden-vm/pull/2403)).
- [BREAKING] Made the Assembler work in debug mode, remove optionality ([#2396](https://github.com/0xMiden/miden-vm/pull/2396)).
- [BREAKING] Normalized naming of `verify` procedures of ECDSA precompile ([#2413](https://github.com/0xMiden/miden-vm/issues/2413)).
- Refactored Blake3_256 fingerprints to allocate less ([#2375](https://github.com/0xMiden/miden-vm/pull/2375)).
- [BREAKING] Normalized signature encoding methods in the `dsa` module of the core library.

## miden-crypto v0.19.2 (2025-12-04)

- [BREAKING] Fixed `Signature` serialization by reducing `SIGNATURE_BYTES` to 65 ([#686](https://github.com/0xMiden/crypto/pull/686)).

## miden-crypto v0.19.1 (2025-12-03)

- Fixed `Signature` deserialization missing one byte from serialization ([#687](https://github.com/0xMiden/crypto/pull/687)).

## miden-crypto v0.19.0 (2025-11-30)

- Added `LargeSmt::insert_batch()` for optimized bulk operations ([#597](https://github.com/0xMiden/crypto/issues/597)).
- Added `compute_challenge_k()` and `verify_with_unchecked_k()` methods to separate hashing and EC logic in EdDSA over Ed25519 ([#602](https://github.com/0xMiden/crypto/pull/602)).
- Refactored `LargeSmt::apply_mutations_with_reversion` to use batched storage operations ([#613](https://github.com/0xMiden/crypto/pull/613)).
- Fixed IES sealed box deserialization ([#616](https://github.com/0xMiden/crypto/pull/616)).
- Add serialization of sealing and unsealing keys in IES ([#637](https://github.com/0xMiden/crypto/pull/637)).
- Fixed undefined `BaseElement` in rescue arch optimizations ([#644](https://github.com/0xMiden/crypto/pull/644)).
- Fixed bugs in Merkle tree capacity checks for `SimpleSmt` and `PartialMerkleTree` ([#648](https://github.com/0xMiden/crypto/pull/648)).
- Added `MerkleStore::has_path()` ([#649](https://github.com/0xMiden/crypto/pull/649)).
- Refactored `StorageUpdates` to use explicit `SubtreeUpdate` enum for storage operations ([#654](https://github.com/0xMiden/crypto/issues/654)).
- Refactored `LargeSmt` into smaller focused modules ([#658](https://github.com/0xMiden/crypto/pull/658)).
- [BREAKING] Organized `merkle` module into public submodules (`mmr`, `smt`, `store`) ([#660](https://github.com/0xMiden/crypto/pull/660)).
- Added property-based testing for `LargeSmt` verifying `insert_batch` equivalence with `compute_mutations`+`apply_mutations` ([#667](https://github.com/0xMiden/crypto/pull/667)).
- [BREAKING] Made `LargeSmt::root()` infallible - returns `Word` from the in-memory root and removes storage reads ([#671](https://github.com/0xMiden/crypto/pull/671)).

## miden-crypto v0.18.4 (2025-11-22)

- Fixed serialization of `PartialSmt` panicking in debug mode when it was constructed from only a root ([#662](https://github.com/0xMiden/crypto/pull/662)).

## miden-crypto v0.18.3 (2025-11-22)

- [BREAKING] removed unused 'self' parameter in HasherExt and all its implementations ([#666](https://github.com/0xMiden/crypto/pull/666))

## miden-crypto v0.18.2 (2025-11-08)

- Changed the methodology for computing ECDSA and EdDSA public key commitments ([#643](https://github.com/0xMiden/crypto/pull/643)).

## miden-vm v0.19.1 (2025-11-06)

- Add `verify_ecdsa_k256_keccak` procedure for verifying signatures using the `miden-crypto` format ([#2344](https://github.com/0xMiden/miden-vm/pull/2344)).

## miden-crypto v0.18.1 (2025-11-05)

- [BREAKING] removed un-needed mutability from ECDSA `sign()` function ([#628](https://github.com/0xMiden/crypto/pull/628)).

## miden-vm v0.19.0 (2025-11-02)

#### Enhancements

- Added `std::mem::pipe_double_words_preimage_to_memory`, a version of `pipe_preimage_to_memory` optimized for pairs of words ([#2048](https://github.com/0xMiden/miden-vm/pull/2048)).
- Added support for leaves with multiple pairs in `std::collections::smt::get` ([#2048](https://github.com/0xMiden/miden-vm/pull/2048)).
- Added support for leaves with multiple pairs in `std::collections::smt::set` ([#2248](https://github.com/0xMiden/miden-vm/pull/2248)).
- Made `miden-vm analyze` output analysis even if execution ultimately errored. ([#2204](https://github.com/0xMiden/miden-vm/pull/2204)).
- Allow `CALL` and `DYNCALL` from a syscall context ([#2296](https://github.com/0xMiden/miden-vm/pull/2296))
- Remove operations `FmpUpdate` and `FmpAdd`, as well as columns `fmp` and `in_syscall` ([#2308](https://github.com/0xMiden/miden-vm/pull/2308))
- Reduce the constraints degree of `HORNERBASE` ([#2328](https://github.com/0xMiden/miden-vm/pull/2328))
- [BREAKING] Implement ECDSA precompile ([#2277](https://github.com/0xMiden/miden-vm/pull/2277)).
- Allowed `CALL` and `DYNCALL` from a syscall context ([#2296](https://github.com/0xMiden/miden-vm/pull/2296)).
- Implemented `AdviceProvider::has_merkle_path()` method.

#### Changes

- [BREAKING] Incremented MSRV to 1.90.
- Added `before_enter` and `after_exit` decorator lists to `BasicBlockNode`.([#2167](https://github.com/0xMiden/miden-vm/pull/2167)).
- Fix ability to parse odd-length hex strings ([#2196](https://github.com/0xMiden/miden-vm/pull/2196)).
- Added `proptest`'s `Arbitrary` instances for `BasicBlockNode` and `MastForest` ([#2200](https://github.com/0xMiden/miden-vm/pull/2200)).
- [BREAKING] Fix inconsistencies in debugging instructions ([#2205](https://github.com/0xMiden/miden-vm/pull/2205)).
- Fixed mismatched Push expectations in decoder syscall_block test ([#2207](https://github.com/0xMiden/miden-vm/pull/2207)).
- Added `proptest`'s `Arbitrary` instances for `Program`, fixed `Attribute` serialization ([#2224](https://github.com/0xMiden/miden-vm/pull/2224)).
- [BREAKING] `Memory::read_element()` now requires `&self` instead of `&mut self` ([#2242](https://github.com/0xMiden/miden-vm/pull/2242)).
- Fixed hex word parsing to guard against missing 0x prefix ([#2245](https://github.com/0xMiden/miden-vm/pull/2245)).
- Systematized u32-indexed vectors ([#2254](https://github.com/0xMiden/miden-vm/pull/2254)).
- Introduced a new `build_trace()` which builds the trace in parallel from trace fragment contexts ([#1839](https://github.com/0xMiden/miden-vm/pull/1839)) ([#2188](https://github.com/0xMiden/miden-vm/pull/2188)).
- Moved the `FastProcessor` stack to the heap instead of the (OS thread) stack (#[2271](https://github.com/0xMiden/miden-vm/pull/2271)).
- [BREAKING] Implemented logging of deferred precompile calls in `AdviceProvider` ([#2158](https://github.com/0xMiden/miden-vm/issues/2158)).
- [BREAKING] Added precompile requests to proof ([#2187](https://github.com/0xMiden/miden-vm/issues/2187)).
- `after_exit` decorators execute in the correct sequence in External nodes in the Fast processor ([#2247](https://github.com/0xMiden/miden-vm/pull/2247)).
- Removed O(n log m) iteration in parallel processor (#[2273](https://github.com/0xMiden/miden-vm/pull/2273)).
- [BREAKING] Added `log_precompile` opcode ([#2249](https://github.com/0xMiden/miden-vm/pull/2249)).
- [BREAKING] `BaseHost` now exposes `resolve_event` so hosts can provide event names for diagnostics. Unify `SystemEvent` ID derivation ([#2150](https://github.com/0xMiden/miden-vm/issues/2150)).
- [BREAKING] Deprecated `mem_loadw` and `mem_storew` instructions in favor of explicit endianness variants (`mem_loadw_be`, `mem_loadw_le`, `mem_storew_be`, `mem_storew_le`) ([#2186](https://github.com/0xMiden/miden-vm/issues/2186)).
- [BREAKING] Deprecated `loc_loadw` and `loc_storew` instructions in favor of explicit endianness variants (`loc_loadw_be`, `loc_loadw_le`, `loc_storew_be`, `loc_storew_le`).
- [BREAKING] Added pre/post decorators to BasicBlockNode fingerprint ([#2267](https://github.com/0xMiden/miden-vm/pull/2267)).
- [BREAKING] Added explicit endianness methods `get_stack_word_be()` and `get_stack_word_le()` to stack word accessors, deprecated ambiguous `get_stack_word()` ([#2235](https://github.com/0xMiden/miden-vm/issues/2235)).
- Added missing endianness-aware memory instructions (`mem_loadw_be`, `mem_loadw_le`, `mem_storew_be`, `mem_storew_le`) to Instruction Reference documentation ([#2286](https://github.com/0xMiden/miden-vm/pull/2286)).
- Fixed decorator offset bug in `BasicBlockNode` padding ([#2305](https://github.com/0xMiden/miden-vm/pull/2305)).
- Removed `FmpUpdate` and `FmpAdd` operations, as well as columns `fmp` and `in_syscall` ([#2308](https://github.com/0xMiden/miden-vm/pull/2308)).
- [BREAKING] Updated `miden-crypto` dependency to v0.18 (#[2311](https://github.com/0xMiden/miden-vm/pull/2311)).
- [BREAKING] Refined precompile verification plumbing ([#2325](https://github.com/0xMiden/miden-vm/pull/2325)).

## miden-vm v0.18.3 (2025-10-27)

- Implement `sorted_array::find_half_key_value` (#[2268](https://github.com/0xMiden/miden-vm/pull/2268)).

## miden-crypto v0.18.0 (2025-10-27)

- [BREAKING] Incremented MSRV to 1.90.
- Added implementation of sealed box primitive ([#514](https://github.com/0xMiden/crypto/pull/514)).
- [BREAKING] Added DSA (EdDSA25519) and ECDH (X25519) using Curve25519 ([#537](https://github.com/0xMiden/crypto/pull/537)).
- Added `AVX512` acceleration for RPO and RPX hash functions, including parallelized E-rounds for RPX ([#551](https://github.com/0xMiden/crypto/pull/551)).
- Added `SmtForest` structure ([#563](https://github.com/0xMiden/crypto/pull/563)).
- Added `HasherExt` trait to provide ability to hash using an iterator of slices. ([#565](https://github.com/0xMiden/crypto/pull/565)).
- [BREAKING] Refactor `PartialSmt` to be constructible from a root ([#569](https://github.com/0xMiden/crypto/pull/569)).
- Added `SmtProof::authenticated_nodes()` delegating to `SparseMerklePath::authenticated_nodes` ([#585](https://github.com/0xMiden/crypto/pull/585)).
- Added `Debug`, `Clone`, `Eq` and `PartialEq` derives to secret key structs for DSA-s ([#589](https://github.com/0xMiden/crypto/pull/589)).
- Added zeroization of secret key structs for DSA-s ([#590](https://github.com/0xMiden/crypto/pull/590)).
- Refactored `LargeSmt` to use flat `Vec<Word>` layout for in-memory nodes ([#591](https://github.com/0xMiden/crypto/pull/594)).
- Add benchmarks for ECDSA-k256 and EdDSA-25519 ([#598](https://github.com/0xMiden/crypto/pull/598)).

## miden-crypto v0.17.1 (2025-10-10)

- Support ECDSA signing/verifying with prehashed messages ([#573](https://github.com/0xMiden/crypto/pull/573)).

## miden-vm v0.18.2 (2025-10-10)

- Place the `FastProcessor` stack on the heap instead of the (OS thread) stack (#[2275](https://github.com/0xMiden/miden-vm/pull/2275)).

## miden-vm v0.18.1 (2025-10-02)

- Gate stdlib doc generation in build.rs on `MIDEN_BUILD_STDLIB_DOCS` environment variable ([#2239](https://github.com/0xMiden/miden-vm/pull/2239/)).

## miden-vm v0.18.0 (2025-09-21)

#### Enhancements

- Added slicing for the word constants ([#2057](https://github.com/0xMiden/miden-vm/pull/2057)).
- Added ability to declare word-sized constants from strings ([#2073](https://github.com/0xMiden/miden-vm/pull/2073)).
- Added new `adv.insert_hqword` instruction ([#2097](https://github.com/0xMiden/miden-vm/pull/2097)).
- Added option to use Poseidon2 in proving ([#2098](https://github.com/0xMiden/miden-vm/pull/2098)).
- Reinstate the build of the stdlib's documentation ([#1432](https://github.com/0xmiden/miden-vm/issues/1432)).
- Added `FastProcessor::execute_for_trace()`, which outputs a series of checkpoints necessary to build the trace in parallel ([#2023](https://github.com/0xMiden/miden-vm/pull/2023))
- Introduced `Tracer` trait to allow different ways of tracing program execution, including no tracing ([#2101](https://github.com/0xMiden/miden-vm/pull/2101))
- `FastProcessor::execute_*()` methods now also return the state of the memory in a new `ExecutionOutput` struct ([#2028](https://github.com/0xMiden/miden-vm/pull/2128))
- Removed all stack underflow error cases from `FastProcessor` ([#2173](https://github.com/0xMiden/miden-vm/pull/2173)).
- Added `reversew` and `reversedw` instructions for reversing the order of elements in a word and double word on the stack ([#2125](https://github.com/0xMiden/miden-vm/issues/2125)).
- Added endianness-aware memory instructions: `mem_loadw_be`, `mem_loadw_le`, `mem_storew_be`, and `mem_storew_le` for explicit control over word element ordering in memory operations ([#2125](https://github.com/0xMiden/miden-vm/issues/2125)).
- Added non-deterministic lookup for sorted arrays to stdlib ([#2114](https://github.com/0xMiden/miden-vm/pull/2114)).
- Introduced syntax for expressing type information in MASM ([#2120](https://github.com/0xMiden/miden-vm/pull/2120)).
- Added `reversew` and `reversedw` instructions for reversing the order of elements in a word and double word on the stack ([#2125](https://github.com/0xMiden/miden-vm/issues/2125)).
- Added endianness-aware memory instructions: `mem_loadw_be`, `mem_loadw_le`, `mem_storew_be`, and `mem_storew_le` for explicit control over word element ordering in memory operations ([#2125](https://github.com/0xMiden/miden-vm/issues/2125)).
- `FastProcessor::execute_*()` methods now also return the state of the memory in a new `ExecutionOutput` struct ([#2028](https://github.com/0xMiden/miden-vm/pull/2128)).
- Better document the normalizing behavior of `MastForestMerger::merge` ([#2174](https://github.com/0xMiden/miden-vm/pull/2174)).
- Propagate procedure annotations to `Library` and `Package` metadata ([#2189](https://github.com/0xMiden/miden-vm/pull/2189)).

#### Changes

- Fixed fast loop node not running after-exit decorators when skipping the body (condition == 0) ([#2169](https://github.com/0xMiden/miden-vm/pull/2169)).
- Removed unused `PushU8List`, `PushU16List`, `PushU32List` and `PushFeltList` instructions ([#2057](https://github.com/0xMiden/miden-vm/pull/2057)).
- Removed dedicated `PushU8`, `PushU16`, `PushU32`, `PushFelt`, and `PushWord` assembly instructions. These have been replaced with the generic `Push<Immediate>` instruction which supports all the same functionality through the `IntValue` enum (U8, U16, U32, Felt, Word) ([#2066](https://github.com/0xMiden/miden-vm/issues/2066)).
- [BREAKING] Update miden-crypto dependency to v0.16 (#[2079](https://github.com/0xMiden/miden-vm/pull/2079))
- Made `get_mast_forest()` async again for `AsyncHost` now that basic conditional async support is in place ([#2060](https://github.com/0xMiden/miden-vm/issues/2060)).
- Improved error message of binary operations on U32 values to report both erroneous operands, if applicable. ([#1327](https://github.com/0xMiden/miden-vm/issues/1327)).
- [BREAKING] `emit` no longer takes an immediate and instead gets the event ID from the stack (#[2068](https://github.com/0xMiden/miden-vm/issues/2068)).
- [BREAKING] `Operation::Emit` no longer contains a `u32` parameter, affecting pattern matching and serialization (#[2068](https://github.com/0xMiden/miden-vm/issues/2068)).
- [BREAKING] Host `on_event` methods no longer receive `event_id` parameter; event ID must be read from stack position 0 (#[2068](https://github.com/0xMiden/miden-vm/issues/2068)).
- [BREAKING] `get_stack_word` uses element-aligned indexing instead of word-aligned indexing (#[2068](https://github.com/0xMiden/miden-vm/issues/2068)).
- [BREAKING] Implemented support for `event("event_name")` in MASM (#[2068](https://github.com/0xMiden/miden-vm/issues/2068)).
- Improved representation of `OPbatches` to include padding Noop by default, simplifying fast iteration over program instructions in the processor ([#1815](https://github.com/0xMiden/miden-vm/issues/1815)).
- Changed multiple broken links across the repository ([#2110](https://github.com/0xMiden/miden-vm/pull/2110)).
- Rename `program_execution` benchmark to `program_execution_for_trace`, and benchmark `FastProcessor::execute_for_trace()` instead of `Process::execute()` (#[2131](https://github.com/0xMiden/miden-vm/pull/2131))
- [BREAKING] Initial support for Keccak precompile ([#2103](https://github.com/0xMiden/miden-vm/pull/2103)).
- Refactored `MastNode` to eliminate boilerplate dispatch code ([#2127](https://github.com/0xMiden/miden-vm/pull/2127)).
- [BREAKING] Introduce `EventId` type ([#2137](https://github.com/0xMiden/miden-vm/issues/2137)).
- Added `multicall` support for the CLI ([#1141](https://github.com/0xMiden/miden-vm/pull/2081)).
- Made `miden-prover`'s metal prover async-compatible. ([#2133](https://github.com/0xMiden/miden-vm/pull/2133)).
- Abstracted away the fast processor's operation execution into a new `Processor` trait ([#2141](https://github.com/0xMiden/miden-vm/pull/2141)).
- [BREAKING] Implemented custom section support in package format, and removed `account_component_metadata` field ([#2071](https://github.com/0xMiden/miden-vm/pull/2071)).
- Moved `EMIT` flag to degree 5 bucket ([#2043](https://github.com/0xMiden/miden-vm/issues/2043)).
- [BREAKING] Renumber system event IDs ([#2151](https://github.com/0xMiden/miden-vm/issues/2151)).
- [BREAKING] Update miden-crypto dependency to v0.17 (#[2168](https://github.com/0xMiden/miden-vm/pull/2168)).
- [BREAKING] Moved `u64_div`, `falcon_div` and `smtpeek` system events to stdlib ([#1582](https://github.com/0xMiden/miden-vm/issues/1582)).
- [BREAKING] `MastNode` quality of life improvements ([#2166](https://github.com/0xMiden/miden-vm/pull/2166)).
- Allowed references between constants without requiring them to be declared in a specific order ([#2120](https://github.com/0xMiden/miden-vm/pull/2120)).
- Introduced new `pub proc` syntax for procedure declarations to replace `export` syntax. This change is backwards-compatible. ([#2120](https://github.com/0xMiden/miden-vm/pull/2120)).
- [BREAKING] Disallowed the use of word literals in conjunction with dot-delimited `push` syntax ([#2120](https://github.com/0xMiden/miden-vm/pull/2120)).
- Fixed `RawDecoratorIdIterator` un-padding off-by-one ([#2193](https://github.com/0xMiden/miden-vm/pull/2193)).

## miden-vm v0.17.2 (2025-09-17)

- Hotfix: remove all stack underflow errors ([#2182](https://github.com/0xMiden/miden-vm/pull/2182)).

## miden-crypto v0.17.0 (2025-09-12)

- Added `LargeSmt`, SMT backed by RocksDB ([#438](https://github.com/0xMiden/miden-crypto/pull/438)).
- Added ECDSA and ECDH modules ([#475](https://github.com/0xMiden/crypto/pull/475)).
- added arithmetization oriented authenticated encryption with associated data (AEAD) scheme ([#480](https://github.com/0xMiden/crypto/pull/480)).
- Added XChaCha20-Poly1305 AEAD scheme ([#484](https://github.com/0xMiden/crypto/pull/484)).
- [BREAKING] `SmtLeaf::entries()` now returns a slice ([#521](https://github.com/0xMiden/crypto/pull/521)).

## miden-vm v0.17.1 (2025-08-30)

- added `MastForest::strip_decorators()` ([#2108](https://github.com/0xMiden/miden-vm/pull/2108)).

## miden-crypto v0.16.1 (2025-08-21)

- Fix broken imports in CPU-specific `rescue` implementations (AVX2, SVE) ([#492](https://github.com/0xMiden/crypto/pull/492/)).
- Added `{Smt,PartialSmt}::inner_node_indices` to make inner nodes accessible ([#494](https://github.com/0xMiden/crypto/pull/494)).
- Added various benchmarks & related bench utilities ([#503](https://github.com/0xMiden/crypto/pull/503))

## miden-crypto v0.16.0 (2025-08-15)

- [BREAKING] Incremented MSRV to 1.88.
- Added implementation of Poseidon2 hash function ([#429](https://github.com/0xMiden/crypto/issues/429)).
- [BREAKING] Make Falcon DSA deterministic ([#436](https://github.com/0xMiden/crypto/pull/436)).
- [BREAKING] Remove generics from `MerkleStore` and remove `KvMap` and `RecordingMap` ([#442](https://github.com/0xMiden/crypto/issues/442)).
- [BREAKING] Rename `smt_hashmaps` feature to `hashmaps` ([#442](https://github.com/0xMiden/crypto/issues/442)).
- [BREAKING] Refactor `parse_hex_string_as_word()` to `Word::parse()` ([#450](https://github.com/0xMiden/crypto/issues/450)).
- `Smt.insert_inner_nodes` does not store empty subtrees ([#452](https://github.com/0xMiden/crypto/pull/452)).
- Optimized `Smt::num_entries()` ([#455](https://github.com/0xMiden/crypto/pull/455)).
- [BREAKING] Disallow leaves with more than 2^16 entries ([#455](https://github.com/0xMiden/crypto/pull/455), [#462](https://github.com/0xMiden/crypto/pull/462)).
-  Add ECDSA over secp256k1 curve ([#475](https://github.com/0xMiden/crypto/pull/475)).
- [BREAKING] Modified the public key in Falcon DSA to be the polynomial instead of the commitment ([#460](https://github.com/0xMiden/crypto/pull/460)).
- [BREAKING] Use `SparseMerklePath` in SMT proofs for better memory efficiency ([#477](https://github.com/0xMiden/crypto/pull/477)).
- [BREAKING] Rename `SparseValuePath` to `SimpleSmtProof` ([#477](https://github.com/0xMiden/crypto/pull/477)).
- Validate `NodeIndex` depth ([#482](https://github.com/0xMiden/crypto/pull/482)).
- [BREAKING] Rename `ValuePath` to `MerkleProof` ([#483](https://github.com/0xMiden/crypto/pull/483)).
- Added an implementation of Keccak256 hash function ([#487](https://github.com/0xMiden/crypto/pull/487)).

# 0.15.9 (2025-07-24)

- Added serialization for `Mmr` and `Forest` ([#466](https://github.com/0xMiden/crypto/pull/466)).

# 0.15.8 (2025-07-21)

- Added constructor for `SparseMerklePath` that accepts a bitmask and a vector of nodes ([#457](https://github.com/0xMiden/crypto/pull/457)).

## miden-vm v0.17.0 (2025-08-06)

#### Enhancements

- [BREAKING] Implemented custom Event handlers ([#1584](https://github.com/0xMiden/miden-vm/pull/1584)).
- Implemented `copy_digest` and `hash_memory_double_words` procedures in the `std::crypto::hashes::rpo` module ([#1971](https://github.com/0xMiden/miden-vm/pull/1971)).
- Added `extend_` methods on AdviceProvider [#1982](https://github.com/0xMiden/miden-vm/pull/1982).
- Added new stdlib module `std::word`, containing utilities for manipulating arrays of four fields (words) ([#1996](https://github.com/0xMiden/miden-vm/pull/1996)).
- Added constraints evaluation check to recursive verifier ([#1997](https://github.com/0xMiden/miden-vm/pull/1997)).
- Make recursive verifier in `stdlib` reusable through dynamic procedure execution ([#2008](https://github.com/0xMiden/miden-vm/pull/2008)).
- Added `AdviceProvider::into_parts()` method ([#2024](https://github.com/0xMiden/miden-vm/pull/2024)).
- Added type information to procedures in the AST, `Library`, and `PackageExport` types ([#2028](https://github.com/0xMiden/miden-vm/pull/2028)).
- Added `drop_stack_top` procedure in `std::sys` ([#2031](https://github.com/0xMiden/miden-vm/pull/2031)).

#### Changes

- [BREAKING] Incremented MSRV to 1.88.
- [BREAKING] Implemented preliminary changes for lazy loading of external `MastForest` `AdviceMap`s ([#1949](https://github.com/0xMiden/miden-vm/issues/1949)).
- Enhancement for all benchmarks (incl. `program_execution_fast`) are built and run in a new CI job with required feature flags [(#https://github.com/0xMiden/miden-vm/issues/1964)](https://github.com/0xMiden/miden-vm/issues/1964).
- [BREAKING] Introduced `SourceManagerSync` trait, and remove `Assembler::source_manager()` method [#1966](https://github.com/0xMiden/miden-vm/issues/1966).
- Fixed `ExecutionOptions::default()` to set `max_cycles` correctly to `1 << 29` ([#1969](https://github.com/0xMiden/miden-vm/pull/1969)).
- [BREAKING] Reverted `get_mapped_value` return signature [(#1981)](https://github.com/0xMiden/miden-vm/issues/1981).
- Converted `FastProcessor::execute()` from recursive to iterative execution ([#1989](https://github.com/0xMiden/miden-vm/issues/1989)).
- [BREAKING]: move `std::utils::is_empty_word` to `std::word::eqz`, as part of the new word module [#1996](https://github.com/0xMiden/miden-vm/pull/1996).
- [BREAKING] `{AsyncHost,SyncHost}::on_event` now returns a list of `AdviceProvider` mutations ([#2003](https://github.com/0xMiden/miden-vm/pull/2003)).
- [BREAKING] made `AdviceInputs` field public and removed redundant accessors ([#2009](https://github.com/0xMiden/miden-vm/pull/2009)).
- [BREAKING] Moved the `SourceManager` from the processor to the host [#2019](https://github.com/0xMiden/miden-vm/pull/2019).
- [BREAKING] `FastProcessor::execute()` now also returns the `AdviceProvider` ([#2026](https://github.com/0xMiden/miden-vm/pull/2026)).
- Allowed for 234 "spurious drops" before the fast processor underflows, up from 34 ([#2035](https://github.com/0xMiden/miden-vm/pull/2035)) .
- [BREAKING] `Library::exports` now returns `(&QualifiedProcedureName, &LibraryExport)` rather than just `&QualifiedProcedureName`, to allow callers to extract more useful information ([#2028](https://github.com/0xMiden/miden-vm/pull/2028)).
- [BREAKING] The serialized representation for `Package` was changed to include procedure type information. Older packages will not work with the new serialization code, and vice versa. The version of the binary format was incremented accordingly ([#2028](https://github.com/0xMiden/miden-vm/pull/2028)).
- [BREAKING] Procedure-related metadata types in the `miden-assembly` crate in some cases now require an optional type signature argument. If that information is not available, you can simply pass `None` to retain current behavior ([#2028](https://github.com/0xMiden/miden-vm/pull/2028)).
- Remove basic block clock cycle optimization from `FastProcessor` ([#2054](https://github.com/0xMiden/miden-vm/pull/2054)).

## miden-vm v0.16.4 (2025-07-24)

- Made `AdviceInputs` field public.

## miden-crypto v0.15.7 (2025-07-18)

- Fix empty SMT serialization check in testing mode ([#456](https://github.com/0xMiden/crypto/pull/456)).

## miden-vm v0.16.3 (2025-07-18)

- Add `new_dummy` method on `ExecutionProof` ([#2007](https://github.com/0xMiden/miden-vm/pull/2007)).

## miden-crypto v0.15.6 (2025-07-16)

- Added conversions and serialization for `PartialSmt` ([#451](https://github.com/0xMiden/crypto/pull/451/), [#453](https://github.com/0xMiden/crypto/pull/453/)).

## miden-vm v0.16.2 (2025-07-11)

- Fix `debug::print_vm_stack` which was returning the advice stack instead of the system stack [(#1984)](https://github.com/0xMiden/miden-vm/issues/1984).

## miden-crypto v0.15.5 (2025-07-10)

- Added `empty()` and `is_empty()` methods to `Word`.

## miden-vm v0.16.1 (2025-07-10)

- Make `Process::state()` public and re-introduce `From<&Process> for ProcessState`.
- Return `AdviceProvider` as part of the `ExecutionTrace`.

## miden-vm v0.16.0 (2025-07-08)

#### Enhancements

- Optimized handling of variable length public inputs in the recursive verifier (#1842).
- Simplify processing of OOD evaluations in the recursive verifier (#1848).
- Allowed constants to be declared as words and to be arguments of the `push` instruction (#1855).
- Allowed definition of Advice Map data in MASM programs. The data is loaded by the host before execution (#1862).
- Improved the documentation for the `Assembler` and its APIs to better explain how each affects the final assembled artifact (#1881).
- It is now possible to assemble kernels with multiple modules while allowing those modules to perform kernel-like actions, such as using the `caller` instruction. (#1893).
- Made `ErrorContext` zero-cost ([#1910](https://github.com/0xMiden/miden-vm/issues/1910)).
- Made `FastProcessor` output rich error diagnostics ([#1914](https://github.com/0xMiden/miden-vm/issues/1914)).
- [BREAKING] Make `FastProcessor::execute()` async ([#1933](https://github.com/0xMiden/miden-vm/issues/1933)).
- The `SourceManager` API was improved to be more precise about source file locations (URIs) and language type. This is intended to support the LSP server implementation. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- `SourceManager::update` was added to allow for the LSP server to update documents stored in the source manager based on edits made by the user. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- Implemented a new `adv.has_mapkey` decorator ([#1941](https://github.com/0xMiden/miden-vm/pull/1941)).
- Added `get_procedure_root_by_name` method to the `Library` struct ([#1961](https://github.com/0xMiden/miden-vm/pull/1961)).

#### Changes

- Updated lalrpop dependency to 0.22 (#1865)
- Removed the obsolete `RpoFalcon512` decorator and associated structs (#1872).
- Fixed instructions with errors print without quotes (#1882).
- [BREAKING] Renamed `Assembler::add_module` to `Assembler::compile_and_statically_link` (#1881).
- [BREAKING] Renamed `Assembler::add_modules` to `Assembler::compile_and_statically_link_all` (#1881).
- [BREAKING] Renamed `Assembler::add_modules_from_dir` to `Assembler::compile_and_statically_link_from_dir` (#1881).
- [BREAKING] Removed `Assembler::add_module_with_options` (#1881).
- [BREAKING] Removed `Assembler::add_modules_with_options` (#1881).
- [BREAKING] Renamed `Assembler::add_library` to `Assembler::link_dynamic_library` (#1881).
- [BREAKING] Renamed `Assembler::add_vendored_library` to `Assembler::link_static_library` (#1881).
- [BREAKING] `AssemblyError` was removed, and all uses replaced with `Report` (#1881).
- [BREAKING] `Compile` trait was renamed to `Parse`.
- [BREAKING] `CompileOptions` was renamed to `ParseOptions`.
- Licensed the project under the Apache 2.0 license (in addition to the MIT) (#1883).
- Uniform chiplet bus message flag encoding (#1887).
- [BREAKING] Updated dependencies Winterfell to v0.13 and Crypto to v0.15 (#1896).
- [BREAKING] Converted `AdviceProvider` into a struct ([#1904](https://github.com/0xMiden/miden-vm/issues/1904), [#1905](https://github.com/0xMiden/miden-vm/issues/1905)).
- [BREAKING] `Host::get_mast_forest` takes `&mut self` ([#1902](https://github.com/0xMiden/miden-vm/issues/1902)).
- [BREAKING] `ProcessState` returns `MemoryError` instead of `ExecutionError` ([#1912](https://github.com/0xMiden/miden-vm/issues/1912)).
- [BREAKING] `AdviceProvider` returns its own error type ([#1907](https://github.com/0xMiden/miden-vm/issues/1907).
- Split out the syntax-related aspects of the `miden-assembly` crate into a new crate called `miden-assembly-syntax` ([#1921](https://github.com/0xMiden/miden-vm/pull/1921)).
- Removed the dependency on `miden-assembly` from `miden-mast-package` ([#1921](https://github.com/0xMiden/miden-vm/pull/1921)).
- [BREAKING] Removed `Library::from_dir` in favor of `Assembler::assemble_library_from_dir` ([#1921](https://github.com/0xMiden/miden-vm/pull/1921)).
- [BREAKING] Removed `KernelLibrary::from_dir` in favor of `Assembler::assemble_kernel_from_dir` ([#1921](https://github.com/0xMiden/miden-vm/pull/1921)).
- [BREAKING] Fixed incorrect namespace being set on modules parsed using the `lib_dir` parameter of `KernelLibrary::from_dir`. ([#1921](https://github.com/0xMiden/miden-vm/pull/1921))..
- [BREAKING] The signature of `SourceManager::load` has changed, and now requires a `SourceLanguage` and `Uri` parameter. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- [BREAKING] The signature of `SourceManager::load_from_raw_parts` has changed, and now requires a `Uri` parameter in place of `&str`. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- [BREAKING] The signature of `SourceManager::find` has changed, and now requires a `Uri` parameter in place of `&str`. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- [BREAKING] `SourceManager::get_by_path` was renamed to `get_by_uri`, and now requires a `&Uri` instead of a `&str` for the URI/path parameter ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- [BREAKING] The `path` parameter of `Location` and `FileLineCol` debuginfo types was renamed to `uri`, and changed from `Arc<str>` to `Uri` type. ([#1937](https://github.com/0xMiden/miden-vm/pull/1937)).
- [BREAKING] Move `AdviceProvider` from `Host` to `ProcessState` ([#1923](https://github.com/0xMiden/miden-vm/issues/1923))).
- Removed decorator for interpolating polynomials over degree 2 extension field ([#1875](https://github.com/0xMiden/miden-vm/issues/1875)).
- Removed MASM code for probabilistic NTT ([#1875](https://github.com/0xMiden/miden-vm/issues/1875)).
- Moved implementation of `miden_assembly_syntax::diagnostics` into a new `miden-utils-diagnostics` crate ([#1945](https://github.com/0xMiden/miden-vm/pull/1945)).
- Moved implementation of `miden_core::debuginfo` into a new `miden-debug-types` crate ([#1945](https://github.com/0xMiden/miden-vm/pull/1945)).
- Moved implementation of `miden_core::sync` into a new `miden-utils-sync` crate ([#1945](https://github.com/0xMiden/miden-vm/pull/1945)).
- [BREAKING] Replaced `miden_assembly_syntax::Version` with `semver::Version` ([#1946](https://github.com/0xMiden/miden-vm/pull/1946))

#### Fixes

- Fixed `SourceContent::update` splice logic to prevent panics on single-line edits and respect exclusive end semantics for multi-line edits ([#XXXX](https://github.com/0xMiden/miden-vm/pull/2146)).
- Truncated nprime.masm output stack to prevent overflow during benchmarks ([#1879](https://github.com/0xMiden/miden-vm/issues/1879)).
- Modules can now be provided in any order to the `Assembler`, see #1669 (#1881).
- Addressed bug which caused references to re-exported procedures whose definition internally referred to an aliased module import, to produce an "undefined module" error, see #1451 (#1892).
- The special identifiers for kernel, executable, and anonymous namespaces were not valid MASM syntax (#1893).
- `AdviceProvider`: replace `SimpleAdviceMap` with `AdviceMap` struct from `miden-core` & add `merge_advice_map` to `AdviceProvider` ([#1924](https://github.com/0xMiden/miden-vm/issues/1924) & [#1922](https://github.com/0xMiden/miden-vm/issues/1922)).
- [BREAKING] Disallow usage of the field modulus as an immediate value ([#1938](https://github.com/0xMiden/miden-vm/pull/1938)).

## miden-crypto v0.15.4 (2025-07-07)

- Implemented `LexicographicWord` struct ([#443](https://github.com/0xMiden/crypto/pull/443/)).
- Added `SequentialCommit` trait ([#443](https://github.com/0xMiden/crypto/pull/443/)).

## miden-crypto v0.15.3 (2025-06-18)

- Fixed conversion error from a slice of bytes into `Word`.
- Added from element slice into `Word` conversion.

## miden-crypto v0.15.2 (2025-06-18)

- Added `to_vec()` method to `Word`.

## miden-crypto v0.15.1 (2025-06-18)

- Implemented `DerefMut`, `Index`, and `IndexMut` for `Word` (#434).

## miden-crypto v0.15.0 (2025-06-17)

- [BREAKING] Use a rich newtype for Merkle mountain range types' forest values (#400).
- Allow pre-sorted entries in `Smt` (#406).
- Added module and function documentation. (#408).
- Added default constructors to `MmrPeaks` and `PartialMmr` (#409).
- Added module and function documentation-2 (#410).
- [BREAKING] Replaced `RpoDigest` with `Word` struct (#411).
- Replaced deprecated #[clap(...)] with #[command(...)] and #[arg(...)] (#413).
- [BREAKING] Renamed `MerklePath::inner_nodes()` to `authenticated_nodes()` to better reflect its functionality (#415).
- Added `compute_root()`, `verify()`, and `authenticated_nodes()` to `SparseMerklePath` for parity with `MerklePath` (#415).
- [BREAKING] Replaced `RpxDigest` with `Word` struct (#420).
- Added `word!` macro to `miden-crypto` (#423).
- Added test vectors for RpoFalcon512 (#425).
- [BREAKING] Updated Winterfell dependency to v0.13 and licensed the project under the Apache 2.0 license (in addition to the MIT)(#433).
- [BREAKING] Incremented MSRV to 1.87.

## miden-vm v0.15.0 (2025-06-06)

#### Enhancements

- Add `debug.stack_adv` and `debug.stack_adv.<n>` to help debug the advice stack (#1828).
- Add a complete description of the constraints for `horner_eval_base` and `horner_eval_ext` (#1817).
- Add documentation for ACE chiplet (#1766)
- Add support for setting debugger breakpoints via `breakpoint` instruction (#1860)
- Improve error messages for some procedure locals-related errors (#1863)
- Add range checks to the `push_falcon_mod_result` advice injector to make sure that the inputs are `u32` (#1819).

#### Changes

- [BREAKING] Rename `miden` executable to `miden-vm`
- Improve error messages for some assembler instruction (#1785)
- Remove `idx` column from Kernel ROM chiplet and use chiplet bus for initialization. (#1818)
- [BREAKING] Make `Assembler::source_manager()` be `Send + Sync` (#1822)
- Refactored `ProcedureName` validation logic to improve readability (#1663)
- Simplify and optimize the recursive verifier (#1801).
- Simplify auxiliary randomness generation (#1810).
- Add handling of variable length public inputs to the recursive verifier (#1813).

#### Fixes

- `miden debug` rewind command no longer panics at clock 0 (#1751)
- Prevent overflow in ACE circuit evaluation (#1820)
- `debug.local` decorators no longer panic or print incorrect values (#1859)

## miden-crypto v0.14.1 (2025-05-31)

- Add module and function documentation. (#408).
- Added missing `PartialSmt` APIs (#417).

## miden-vm v0.14.0 (2025-05-08)

#### Enhancements

- Add kernel procedures digests as public inputs to the recursive verifier (#1724).
- add optional `Package::account_component_metadata_bytes` to store serialized `AccountComponentMetadata` (#1731).
- Add `executable` feature to the `make test` and `make test-build` Make commands (#1762).
- Allow asserts instruction to take error messages as strings instead of error codes as Felts (#1771).
- Add arithmetic evaluation chiplet (#1759).
- Update the recursive verifier to use arithmetic evaluation chiplet (#1760).

#### Changes

- Replace deprecated #[clap(...)] with #[command(...)] and #[arg(.…)] (#1794)
- Add pull request template to guide contributors (#1795)
- [BREAKING] `ExecutionOptions::with_debugging()` now takes a boolean parameter (#1761)
- Use `MemoryAddress(u32)` for `VmState` memory addresses instead of plain `u64` (#1758).
- [BREAKING] Improve processor errors for memory and calls (#1717)
- Implement a new fast processor that doesn't generate a trace (#1668)
- `ProcessState::get_stack_state()` now only returns the state of the active context (#1753)
- Change `MastForestBuilder::set_after_exit()` for `append_after_exit()` (#1775)
- Improve processor error diagnostics (#1765)
- Fix source spans associated with assert* and mtree_verify instructions (#1789)
- [BREAKING] Improve the layout of the memory used by the recursive verifier (#1857)

## miden-vm v0.13.2 (2025-04-02)

#### Changes

- Relaxed rules for identifiers created via `Ident::new`, `ProcedureName::new`, `LibraryNamespace::new`, and `Library::new_from_components` (#1735)
- [BREAKING] Renamed `Ident::new_unchecked` and `ProcedureName::new_unchecked` to `from_raw_parts` (#1735).

#### Fixes

- Fixed various issues with pretty printing of Miden Assembly (#1740).

## miden-vm v0.13.1 (2025-03-21) - `stdlib` crate only

#### Enhancements

- Added `prepare_hasher_state` and `hash_memory_with_state` procedures to the `stdlib::crypto::hashes::rpo` module (#1718).

## miden-vm v0.13.0 (2025-03-20)

#### Enhancements

- Added to the `Assembler` the ability to vendor a compiled library.
- [BREAKING] Update CLI to accept masm or masp files as input for all commands (#1683, #1692).
- [BREAKING] Introduced `HORNERBASE`, `HORNEREXT` and removed `RCOMBBASE` instructions (#1656).

#### Changes

- Update minimum supported Rust version to 1.85.
- Change Chiplet Fields to Public (#1629).
- [BREAKING] Updated Winterfell dependency to v0.12 (#1658).
- Introduce `BusDebugger` to facilitate debugging buses (#1664).
- Update Falcon verification procedure to use `HORNERBASE` (#1661).
- Update recursive verifier to use `HORNERBASE` (#1665).
- Fix the docs and implementation of `EXPACC` (#1676).
- Running a call/syscall/dyncall while processing a syscall now results in an error (#1680).
- Using a non-binary value as a loop condition now results in an error (#1685).
- [BREAKING] Remove `Assembler::assemble_common()` from the public interface (#1689).
- Fix `Horner{Base, Ext}` bus requests to memory chiplet (#1689).
- Fix docs on the layout of the auxiliary segment trace (#1694).
- Optimize FRI remainder polynomial check (#1670).
- Remove `FALCON_SIG_TO_STACK` event (#1703).
- Prevent `U64Div` event from crashing processor (#1710).

## miden-crypto v0.14.0 (2025-03-15)

- Added parallel implementation of `Smt::compute_mutations` with better performance (#365).
- Implemented parallel leaf hashing in `Smt::process_sorted_pairs_to_leaves` (#365).
- Removed duplicated check in RpoFalcon512 verification (#368).
- [BREAKING] Updated Winterfell dependency to v0.12 (#374).
- Added debug-only duplicate column check in `build_subtree` (#378).
- Filter out empty values in concurrent version of `Smt::with_entries` to fix a panic (#383).
- Added property-based testing (proptest) and fuzzing for `Smt::with_entries` and `Smt::compute_mutations` (#385).
- Sort keys in a leaf in the concurrent implementation of `Smt::with_entries`, ensuring consistency with the sequential version (#385).
- Skip unchanged leaves in the concurrent implementation of `Smt::compute_mutations` (#385).
- Added range checks to `ntru_gen` for Falcon DSA (#391).
- Optimized duplicate key detection in `Smt::with_entries_concurrent` (#395).
- [BREAKING] Moved `rand` to version `0.9` removing the `try_fill_bytes` method (#398).
- [BREAKING] Increment minimum supported Rust version to 1.85 (#399).
- Added `SparseMerklePath`, a compact representation of `MerklePath` which compacts empty nodes into a bitmask (#389).

## miden-crypto v0.13.3 (2025-02-18)

- Implement `PartialSmt` (#372, #381).
- Fix panic in `PartialMmr::untrack` (#382).

## miden-crypto v0.13.2 (2025-01-24)

- Made `InnerNode` and `NodeMutation` public. Implemented (de)serialization of `LeafIndex` (#367).

## miden-vm v0.12.0 (2025-01-22)

#### Highlights

- [BREAKING] Refactored memory to be element-addressable (#1598).

#### Changes

- [BREAKING] Resolved flag collision in `--verify` command and added functionality for optional input/output files (#1513).
- [BREAKING] Refactored `MastForest` serialization/deserialization to put decorator data at the end of the binary (#1531).
- [BREAKING] Refactored `Process` struct to no longer take ownership of the `Host` (#1571).
- [BREAKING] Converted `ProcessState` from a trait to a struct (#1571).
- [BREAKING] Simplified `Host` and `AdviceProvider` traits (#1572).
- [BREAKING] Updated Winterfell dependency to v0.11 (#1586).
- [BREAKING] Cleaned up benchmarks and examples in the `miden-vm` crate (#1587)
- [BREAKING] Switched to `thiserror` 2.0 derive errors and refactored errors (#1588).
- Moved handling of `FalconSigToStack` event from system event handlers to the `DefaultHost` (#1630).

#### Enhancements

- Added options `--kernel`, `--debug` and `--output` to `miden bundle` (#1447).
- Added `miden_core::mast::MastForest::advice_map` to load it into the advice provider before the `MastForest` execution (#1574).
- Optimized the computation of the DEEP queries in the recursive verifier (#1594).
- Added validity checks for the inputs to the recursive verifier (#1596).
- Allow multiple memory reads in the same clock cycle (#1626)
- Improved Falcon signature verification (#1623).
- Added `miden-mast-package` crate with `Package` type to represent a compiled Miden program/library (#1544).

## miden-crypto v0.13.1 (2024-12-26)

- Generate reverse mutations set on applying of mutations set, implemented serialization of `MutationsSet` (#355).

## miden-crypto v0.13.0 (2024-11-24)

- Fixed a bug in the implementation of `draw_integers` for `RpoRandomCoin` (#343).
- [BREAKING] Refactor error messages and use `thiserror` to derive errors (#344).
- [BREAKING] Updated Winterfell dependency to v0.11 (#346).
- Added support for hashmaps in `Smt` and `SimpleSmt` which gives up to 10x boost in some operations (#363).

## miden-vm v0.11.0 (2024-11-04)

#### Enhancements

- Added `miden_core::utils::sync::racy_lock` module (#1463).
- Updated `miden_core::utils` to re-export `std::sync::LazyLock` and `racy_lock::RacyLock as LazyLock` for std and no_std environments, respectively (#1463).
- Debug instructions can be enabled in the cli `run` command using `--debug` flag (#1502).
- Added support for procedure annotation (attribute) syntax to Miden Assembly (#1510).
- Make `miden-prover::prove()` method conditionally asynchronous (#1563).
- Update and sync the recursive verifier (#1575).

#### Changes

- [BREAKING] Wrapped `MastForest`s in `Program` and `Library` structs in `Arc` (#1465).
- `MastForestBuilder`: use `MastNodeId` instead of MAST root to uniquely identify procedures (#1473).
- Made the undocumented behavior of the VM with regard to undefined behavior of u32 operations, stricter (#1480).
- Introduced the `Emit` instruction (#1496).
- [BREAKING] ExecutionOptions::new constructor requires a boolean to explicitly set debug mode (#1502).
- [BREAKING] The `run` and the `prove` commands in the cli will accept `--trace` flag instead of `--tracing` (#1502).
- Migrated to new padding rule for RPO (#1343).
- Migrated to `miden-crypto` v0.11.0 (#1343).
- Implemented `MastForest` merging (#1534).
- Rename `EqHash` to `MastNodeFingerprint` and make it `pub` (#1539).
- Updated Winterfell dependency to v0.10 (#1533).
- [BREAKING] `DYN` operation now expects a memory address pointing to the procedure hash (#1535).
- [BREAKING] `DYNCALL` operation fixed, and now expects a memory address pointing to the procedure hash (#1535).
- Permit child `MastNodeId`s to exceed the `MastNodeId`s of their parents (#1542).
- Don't validate export names on `Library` deserialization (#1554)
- Compile advice injectors down to `Emit` operations (#1581)

#### Fixes

- Fixed an issue with formatting of blocks in Miden Assembly syntax
- Fixed the construction of the block hash table (#1506)
- Fixed a bug in the block stack table (#1511) (#1512) (#1557)
- Fixed the construction of the chiplets virtual table (#1514) (#1556)
- Fixed the construction of the chiplets bus (#1516) (#1525)
- Decorators are now allowed in empty basic blocks (#1466)
- Return an error if an instruction performs 2 memory accesses at the same memory address in the same cycle (#1561)

## miden-crypto v0.12.0 (2024-10-30)

- [BREAKING] Updated Winterfell dependency to v0.10 (#338).
- Added parallel implementation of `Smt::with_entries()` with significantly better performance when the `concurrent` feature is enabled (#341).

## miden-crypto v0.11.0 (2024-10-17)

- [BREAKING]: renamed `Mmr::open()` into `Mmr::open_at()` and `Mmr::peaks()` into `Mmr::peaks_at()` (#234).
- Added `Mmr::open()` and `Mmr::peaks()` which rely on `Mmr::open_at()` and `Mmr::peaks()` respectively (#234).
- Standardized CI and Makefile across Miden repos (#323).
- Added `Smt::compute_mutations()` and `Smt::apply_mutations()` for validation-checked insertions (#327).
- Changed padding rule for RPO/RPX hash functions (#318).
- [BREAKING] Changed return value of the `Mmr::verify()` and `MerklePath::verify()` from `bool` to `Result<>` (#335).
- Added `is_empty()` functions to the `SimpleSmt` and `Smt` structures. Added `EMPTY_ROOT` constant to the `SparseMerkleTree` trait (#337).

## miden-crypto v0.10.3 (2024-09-25)

- Implement `get_size_hint` for `Smt` (#331).

## miden-crypto v0.10.2 (2024-09-25)

- Implement `get_size_hint` for `RpoDigest` and `RpxDigest` and expose constants for their serialized size (#330).

## miden-crypto v0.10.1 (2024-09-13)

- Added `Serializable` and `Deserializable` implementations for `PartialMmr` and `InOrderIndex` (#329).

## miden-vm v0.10.6 (2024-09-12) - `miden-processor` crate only

#### Enhancements

- Added `PartialEq`, `Eq`, `Serialize` and `Deserialize` to `AdviceMap` and `AdviceInputs` structs (#1494).

## miden-vm v0.10.5 (2024-08-21)

#### Enhancements

- Updated `MastForest::read_from` to deserialize without computing node hashes unnecessarily (#1453).
- Assembler: Merge contiguous basic blocks (#1454).
- Assembler: Add a threshold number of operations after which we stop merging more in the same block (#1461).

#### Changes

- Added `new_unsafe()` constructors to MAST node types which do not compute node hashes (#1453).
- Consolidated `BasicBlockNode` constructors and converted assert flow to `MastForestError::EmptyBasicBlock` (#1453).

#### Fixes

- Fixed an issue with registering non-local procedures in `MemMastForestStore` (#1462).
- Added a check for circular external node lookups in the processor (#1464).

## miden-vm v0.10.4 (2024-08-15) - `miden-processor` crate only

#### Enhancements

- Added support for executing `Dyn` nodes from external MAST forests (#1455).

## miden-vm v0.10.3 (2024-08-13)

#### Enhancements

- Added `with-debug-info` feature to `miden-stdlib` (#1445).
- Added `Assembler::add_modules_from_dir()` method (#1445).
- [BREAKING] Implemented building of multi-module kernels (#1445).

#### Changes

- [BREAKING] Replaced `SourceManager` parameter with `Assembler` in `Library::from_dir` (#1445).
- [BREAKING] Moved `Library` and `KernelLibrary` exports to the root of the `miden-assembly` crate. (#1445).
- [BREAKING] Depth of the input and output stack was restricted to 16 (#1456).

## miden-vm v0.10.2 (2024-08-11)

#### Enhancements

- Removed linear search of trace rows from `BlockHashTableRow::table_init()` (#1439).
- Exposed some pretty printing internals for `MastNode` (#1441).
- Made `KernelLibrary` impl `Clone` and `AsRef<Library>` (#1441).
- Added serialization to the `Program` struct (#1442).

#### Changes

- [BREAKING] Removed serialization of AST structs (#1442).

## miden-vm v0.10.0 (2024-08-06)

#### Features

- Added source location tracking to assembled MAST (#1419).
- Added error codes support for the `mtree_verify` instruction (#1328).
- Added support for immediate values for `lt`, `lte`, `gt`, `gte` comparison instructions (#1346).
- Added support for immediate values for `u32lt`, `u32lte`, `u32gt`, `u32gte`, `u32min` and `u32max` comparison instructions (#1358).
- Added support for the `nop` instruction, which corresponds to the VM opcode of the same name, and has the same semantics.
- Added support for the `if.false` instruction, which can be used in the same manner as `if.true`
- Added support for immediate values for `u32and`, `u32or`, `u32xor` and `u32not` bitwise instructions (#1362).
- [BREAKING] Assembler: add the ability to compile MAST libraries, and to assemble a program using compiled libraries (#1401)

#### Enhancements

- Changed MAST to a table-based representation (#1349).
- Introduced `MastForestStore` (#1359).
- Adjusted prover's metal acceleration code to work with 0.9 versions of the crates (#1357).
- Relaxed the parser to allow one branch of an `if.(true|false)` to be empty.
- Optimized `std::sys::truncate_stuck` procedure (#1384).
- Updated CI and Makefile to standardize it across Miden repositories (#1342).
- Add serialization/deserialization for `MastForest` (#1370).
- Updated CI to support `CHANGELOG.md` modification checking and `no changelog` label (#1406).
- Introduced `MastForestError` to enforce `MastForest` node count invariant (#1394).
- Added functions to `MastForestBuilder` to allow ensuring of nodes with fewer LOC (#1404).
- [BREAKING] Made `Assembler` single-use (#1409).
- Removed `ProcedureCache` from the assembler (#1411).
- Added functions to `MastForest` and `MastForestBuilder` to add and ensure nodes with fewer LOC (#1404, #1412).
- Added `Assembler::assemble_library()` and `Assembler::assemble_kernel()`  (#1413, #1418).
- Added `miden_core::prettier::pretty_print_csv` helper, for formatting of iterators over `PrettyPrint` values as comma-separated items.
- Added source code management primitives in `miden-core` (#1419).
- Added `make test-fast` and `make test-skip-proptests` Makefile targets for faster testing during local development.
- Added `ProgramFile::read_with` constructor that takes a `SourceManager` impl to use for source management.
- Added `RowIndex(u32)` (#1408).

#### Changed

- When using `if.(true|false) .. end`, the parser used to emit an empty block for the branch that was elided. The parser now emits a block containing a single `nop` instruction instead.
- [BREAKING] `internals` configuration feature was renamed to `testing` (#1399).
- The `AssemblyOp` decorator now contains an optional `Location` (#1419)
- The `Assembler` now requires passing in a `Arc<dyn SourceManager>`, for use in rendering diagnostics.
- The `Module::parse_file` and `Module::parse_str` functions have been removed in favor of calling `Module::parser` and then using the `ModuleParser` methods.
- The `Compile` trait now requires passing a `SourceManager` reference along with the item to be compiled.
- Update minimum supported Rust version to 1.80 (#1425).
- Made `debug` mode the default in the CLI. Added `--release` flag to disable debugging instead of having to enable it. (#1728)

## miden-crypto v0.10.0 (2024-08-06)

- Added more `RpoDigest` and `RpxDigest` conversions (#311).
- [BREAKING] Migrated to Winterfell v0.9 (#315).
- Fixed encoding of Falcon secret key (#319).

## miden-vm v0.9.2 (2024-04-25) - `stdlib` crate only

- Skip writing MASM documentation to file when building on docs.rs (#1341).

## miden-vm v0.9.2 (2024-04-25) - `assembly` crate only

- Remove usage of `group_vector_elements()` from `combine_blocks()` (#1331).

## miden-vm v0.9.2 (2024-04-25) - `air` and `processor` crates only

- Allowed enabling debug mode via `ExecutionOptions` (#1316).

## miden-crypto v0.9.3 (2024-04-24)

- Added `RpxRandomCoin` struct (#307).

## miden-crypto v0.9.2 (2024-04-21)

- Implemented serialization for the `Smt` struct (#304).
- Fixed a bug in Falcon signature generation (#305).

## miden-vm v0.9.1 (2024-04-04)

- Added additional trait implementations to error types (#1306).

## miden-vm v0.9.0 (2024-04-03)

#### Packaging

- [BREAKING] The package `miden-vm` crate was renamed from `miden` to `miden-vm`. Now the package and crate names match (#1271).

#### Stdlib

- Added `init_no_padding` procedure to `std::crypto::hashes::native` (#1313).
- [BREAKING] `native` module was renamed to the `rpo`, `hash_memory` procedure was renamed to the `hash_memory_words` (#1368).
- Added `hash_memory` procedure to `std::crypto::hashes::rpo` (#1368).

#### VM Internals

- Removed unused `find_lone_leaf()` function from the Advice Provider (#1262).
- [BREAKING] Changed fields type of the `StackOutputs` struct from `Vec<u64>` to `Vec<Felt>` (#1268).
- [BREAKING] Migrated to `miden-crypto` v0.9.0 (#1287).

## miden-crypto v0.9.1 (2024-04-02)

- Added `num_leaves()` method to `SimpleSmt` (#302).

## miden-crypto v0.9.0 (2024-03-24)

- [BREAKING] Removed deprecated re-exports from liballoc/libstd (#290).
- [BREAKING] Refactored RpoFalcon512 signature to work with pure Rust (#285).
- [BREAKING] Added `RngCore` as supertrait for `FeltRng` (#299).

# 0.8.4 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (`vec` and `format` macros).

# 0.8.3 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (#292).

# 0.8.2 (2024-03-17)

- Updated `no-std` approach to be in sync with winterfell v0.8.3 release (#290).

## miden-vm v0.8.0 (2024-02-26)

#### Assembly

- Expanded capabilities of the `debug` decorator. Added `debug.mem` and `debug.local` variations (#1103).
- Introduced the `emit.<event_id>` assembly instruction (#1119).
- Introduced the `procref.<proc_name>` assembly instruction (#1113).
- Added the ability to use constants as counters in `repeat` loops (#1124).
- [BREAKING] Removed all `checked` versions of the u32 instructions. Renamed all `unchecked` versions (#1115).
- Introduced the `u32clz`, `u32ctz`, `u32clo`, `u32cto` and `ilog2` assembly instructions (#1176).
- Added support for hexadecimal values in constants (#1199).
- Added the `RCombBase` instruction (#1216).

#### Stdlib

- Introduced `std::utils` module with `is_empty_word` procedure. Refactored `std::collections::smt`
  and `std::collections::smt64` to use the procedure (#1107).
- [BREAKING] Removed `checked` versions of the instructions in the `std::math::u64` module (#1142).
- Introduced `clz`, `ctz`, `clo` and `cto` instructions in the `std::math::u64` module (#1179).
- [BREAKING] Refactored `std::collections::smt` to use `SimpleSmt`-based implementation (#1215).
- [BREAKING] Removed `std::collections::smt64` (#1249)

#### VM Internals

- Introduced the `Event` decorator and an associated `on_event` handler on the `Host` trait (#1119).
- Added methods `StackOutputs::get_stack_item()` and `StackOutputs::get_stack_word()` (#1155).
- Added [Tracing](https://crates.io/crates/tracing) logger to the VM (#1139).
- Refactored auxiliary trace construction (#1140).
- [BREAKING] Optimized `u32lt` instruction (#1193)
- Added `on_assert_failed()` method to the Host trait (#1197).
- Added support for handling `trace` instruction in the `Host` interface (#1198).
- Updated Winterfell dependency to v0.8 (#1234).
- Increased min version of `rustc` to 1.75.

#### CLI

- Introduced the `!use` command for the Miden REPL (#1162).
- Introduced a `BLAKE3` hashing example (#1180).

## miden-crypto v0.8.1 (2024-02-21)

- Fixed clippy warnings (#280)

## miden-crypto v0.8.0 (2024-02-14)

- Implemented the `PartialMmr` data structure (#195).
- Implemented RPX hash function (#201).
- Added `FeltRng` and `RpoRandomCoin` (#237).
- Accelerated RPO/RPX hash functions using AVX512 instructions (#234).
- Added `inner_nodes()` method to `PartialMmr` (#238).
- Improved `PartialMmr::apply_delta()` (#242).
- Refactored `SimpleSmt` struct (#245).
- Replaced `TieredSmt` struct with `Smt` struct (#254, #277).
- Updated Winterfell dependency to v0.8 (#275).

## miden-vm v0.7.0 (2023-10-11)

#### Assembly

- Added ability to attach doc comments to re-exported procedures (#994).
- Added support for nested modules (#992).
- Added support for the arithmetic expressions in constant values (#1026).
- Added support for module aliases (#1037).
- Added `adv.insert_hperm` decorator (#1042).
- Added `adv.push_smtpeek` decorator (#1056).
- Added `debug` decorator (#1069).
- Refactored `push` instruction so now it parses long hex string in little-endian (#1076).

#### CLI

- Implemented ability to output compiled `.masb` files to disk (#1102).

#### VM Internals

- Simplified range checker and removed 1 main and 1 auxiliary trace column (#949).
- Migrated range checker lookups to use LogUp and reduced the number of trace columns to 2 main and
  1 auxiliary (#1027).
- Added `get_mapped_values()` and `get_store_subset()` methods to the `AdviceProvider` trait (#987).
- [BREAKING] Added options to specify maximum number of cycles and expected number of cycles for a program (#998).
- Improved handling of invalid/incomplete parameters in `StackOutputs` constructors (#1010).
- Allowed the assembler to produce programs with "phantom" calls (#1019).
- Added `TraceLenSummary` struct which holds information about traces lengths to the `ExecutionTrace` (#1029).
- Imposed the 2^32 limit for the memory addresses used in the memory chiplet (#1049).
- Supported `PartialMerkleTree` as a secret input in `.input` file (#1072).
- [BREAKING] Refactored `AdviceProvider` interface into `Host` interface (#1082).

#### Stdlib

- Completed `std::collections::smt` module by implementing `insert` and `set` procedures (#1036, #1038, #1046).
- Added new module `std::crypto::dsa::rpo_falcon512` to support Falcon signature verification (#1000, #1094)

## miden-crypto v0.7.1 (2023-10-10)

- Fixed RPO Falcon signature build on Windows.

## miden-crypto v0.7.0 (2023-10-06)

- Replaced `MerklePathSet` with `PartialMerkleTree` (#165).
- Implemented clearing of nodes in `TieredSmt` (#173).
- Added ability to generate inclusion proofs for `TieredSmt` (#174).
- Implemented Falcon DSA (#179).
- Added conditional `serde`` support for various structs (#180).
- Implemented benchmarking for `TieredSmt` (#182).
- Added more leaf traversal methods for `MerkleStore` (#185).
- Added SVE acceleration for RPO hash function (#189).

## miden-vm v0.6.1 (2023-06-29)

- Fixed `no-std` compilation for `miden-core`, `miden-assembly`, and `miden-processor` crates.

## miden-vm v0.6.0 (2023-06-28)

#### Assembly

- Added new instructions: `mtree_verify`.
- [BREAKING] Refactored `adv.mem` decorator to use parameters from operand stack instead of immediate values.
- [BREAKING] Refactored `mem_stream` and `adv_pipe` instructions.
- Added constant support for memory operations.
- Enabled incremental compilation via `compile_in_context()` method.
- Exposed ability to compile individual modules publicly via `compile_module()` method.
- [BREAKING] Refactored advice injector instructions.
- Implemented procedure re-exports from modules.

#### CLI

- Implemented support for all types of nondeterministic inputs (advice stack, advice map, and Merkle store).
- Implemented ability to generate proofs suitable for recursion.

#### Stdlib

- Added new module: `std::collections::smt` (only `smt::get` available).
- Added new module: `std::collections::mmr`.
- Added new module: `std::collections::smt64`.
- Added several convenience procedures to `std::mem` module.
- [BREAKING] Added procedures to compute 1-to-1 hashes in `std::crypto::hashes` module and renamed existing procedures to remove ambiguity.
- Greatly optimized recursive STARK verifier (reduced number of cycles by 6x - 8x).

#### VM Internals

- Moved test framework from `miden-vm` crate to `miden-test-utils` crate.
- Updated Winterfell dependency to v0.6.4.
- Added support for GPU acceleration on Apple silicon (Metal).
- Added source locations to all AST nodes.
- Added 8 more instruction slots to the VM (not yet used).
- Completed kernel ROM trace generation.
- Implemented ability to record advice provider requests to the initial dataset via `RecAdviceProvider`.

## miden-crypto v0.6.0 (2023-06-25)

- [BREAKING] Added support for recording capabilities for `MerkleStore` (#162).
- [BREAKING] Refactored Merkle struct APIs to use `RpoDigest` instead of `Word` (#157).
- Added initial implementation of `PartialMerkleTree` (#156).

## miden-crypto v0.5.0 (2023-05-26)

- Implemented `TieredSmt` (#152, #153).
- Implemented ability to extract a subset of a `MerkleStore` (#151).
- Cleaned up `SimpleSmt` interface (#149).
- Decoupled hashing and padding of peaks in `Mmr` (#148).
- Added `inner_nodes()` to `MerkleStore` (#146).

## miden-crypto v0.4.0 (2023-04-21)

- Exported `MmrProof` from the crate (#137).
- Allowed merging of leaves in `MerkleStore` (#138).
- [BREAKING] Refactored how existing data structures are added to `MerkleStore` (#139).

## miden-crypto v0.3.0 (2023-04-07)

- Added `depth` parameter to SMT constructors in `MerkleStore` (#115).
- Optimized MMR peak hashing for Miden VM (#120).
- Added `get_leaf_depth` method to `MerkleStore` (#119).
- Added inner node iterators to `MerkleTree`, `SimpleSmt`, and `Mmr` (#117, #118, #121).

## miden-vm v0.5.0 (2023-03-29)

#### CLI

- Renamed `ProgramInfo` to `ExecutionDetails` since there is another `ProgramInfo` struct in the source code.
- [BREAKING] renamed `stack_init` and `advice_tape` to `operand_stack` and `advice_stack` in input files.
- Enabled specifying additional advice provider inputs (i.e., advice map and Merkle store) via the input files.

#### Assembly

- Added new instructions: `is_odd`, `assert_eqw`, `mtree_merge`.
- [BREAKING] Removed `mtree_cwm` instruction.
- Added `breakpoint` instruction to help with debugging.

#### VM Internals

- [BREAKING] Renamed `Read`, `ReadW` operations into `AdvPop`, `AdvPopW`.
- [BREAKING] Replaced `AdviceSet` with `MerkleStore`.
- Updated Winterfell dependency to v0.6.0.
- [BREAKING] Renamed `Read/ReadW` operations into `AdvPop/AdvPopW`.

## miden-crypto v0.2.0 (2023-03-25)

- Implemented `Mmr` and related structs (#67).
- Implemented `MerkleStore` (#93, #94, #95, #107 #112).
- Added benchmarks for `MerkleStore` vs. other structs (#97).
- Added Merkle path containers (#99).
- Fixed depth handling in `MerklePathSet` (#110).
- Updated Winterfell dependency to v0.6.

## miden-vm v0.4.0 (2023-02-27)

#### Advice provider

- [BREAKING] Converted `AdviceProvider` into a trait which can be provided to the processor.
- Added a decorator for interpolating polynomials over degree 2 extension field (`ext2intt`).
- Added `AdviceSource` enum for greater future flexibility of advice injectors.

#### CLI

- Added `debug` subcommand to enable stepping through program execution forward/backward.
- Added cycle count to the output of program execution.

#### Assembly

- Added support for constant declarations.
- Added new instructions: `clk`, `ext2*`, `fri_ext2fold4`, `hash`, `u32checked_popcnt`, `u32unchecked_popcnt`.
- [BREAKING] Renamed `rpperm` to `hperm` and `rphash` to `hmerge`.
- Removed requirement that code blocks must be non-empty (i.e., allowed empty blocks).
- [BREAKING] Refactored `mtree_set` and `mtree_cwm` instructions to leave the old value on the stack.
- [BREAKING] Replaced `ModuleProvider` with `Library` to improve 3rd party library support.

#### Processor, Prover, and Verifier

- [BREAKING] Refactored `execute()`, `prove()`, `verify()` functions to take `StackInputs` as one of the parameters.
- [BREAKING] Refactored `prove()` function to return `ExecutionProof` (which is a wrapper for `StarkProof`).
- [BREAKING] Refactored `verify()` function to take `ProgramInfo`, `StackInputs`, and `ExecutionProof` as parameters and return a `u32` indicating security level of the verified proof.

#### Stdlib

- Added `std::mem::memcopy` procedure for copying regions of memory.
- Added `std::crypto::fri::frie2f4::verify` for verifying FRI proofs over degree 2 extension field.

#### VM Internals

- [BREAKING] Migrated to Rescue Prime Optimized hash function.
- Updated Winterfell backend to v0.5.1

## miden-crypto v0.1.4 (2023-02-22)

- Re-export winter-crypto Hasher, Digest & ElementHasher (#72)

## miden-crypto v0.1.3 (2023-02-20)

- Updated Winterfell dependency to v0.5.1 (#68)

## miden-crypto v0.1.2 (2023-02-17)

- Fixed `Rpo256::hash` pad that was panicking on input (#44)
- Added `MerklePath` wrapper to encapsulate Merkle opening verification and root computation (#53)
- Added `NodeIndex` Merkle wrapper to encapsulate Merkle tree traversal and mappings (#54)

## miden-crypto v0.1.1 (2023-02-06)

- Introduced `merge_in_domain` for the RPO hash function, to allow using a specified domain value in the second capacity register when hashing two digests together.
- Added a simple sparse Merkle tree implementation.
- Added re-exports of Winterfell RandomCoin and RandomCoinError.

## miden-crypto v0.1.0 (2022-12-02)

- Initial release on crates.io containing the cryptographic primitives used in Miden VM and the Miden Rollup.
- Hash module with the BLAKE3 and Rescue Prime Optimized hash functions.
  - BLAKE3 is implemented with 256-bit, 192-bit, or 160-bit output.
  - RPO is implemented with 256-bit output.
- Merkle module, with a set of data structures related to Merkle trees, implemented using the RPO hash function.

## miden-vm v0.3.0 (2022-11-23)

- Implemented `call` operation for context-isolated function calls.
- Added support for custom kernels.
- Implemented `syscall` operation for kernel calls, and added a new `caller` instruction for accessing the hash of the calling function.
- Implemented `mem_stream` operation for fast hashing of memory regions.
- Implemented `adv_pipe` operation for fast "unhashing" of inputs into memory.
- Added support for unlimited number of stack inputs/outputs.
- [BREAKING] Redesigned Miden assembly input/output instructions for environment, random access memory, local memory, and non-deterministic "advice" inputs.
- [BREAKING] Reordered the output stack for Miden assembly cryptographic operations `mtree_set` and `mtree_get` to improve efficiency.
- Refactored the advice provider to add support for advice maps, and added the `adv.mem` decorator for copying memory regions into the advice map.
- [BREAKING] Refactored the Assembler and added support for module providers. (Standard library is no longer available by default.)
- Implemented AIR constraints for the stack component.
- Added Miden REPL tool.
- Improved performance with various internal refactorings and optimizations.

## miden-vm v0.2.0 (2022-08-08)

- Implemented new decoder which removes limitations on the depth of control flow logic.
- Introduced chiplet architecture to offload complex computations to specialized modules.
- Added read-write random access memory.
- Added support for operations with 32-bit unsigned integers.
- Redesigned advice provider to include Merkle path advice sets.
- Changed base field of the VM to the prime field with modulus 2^64 - 2^32 + 1.

## miden-vm v0.1.0 (2021-11-15)

- Initial release (migration of the original [Distaff VM](https://github.com/GuildOfWeavers/distaff) codebase to [Winterfell](https://github.com/novifinancial/winterfell) backend).
