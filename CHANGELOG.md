## 0.27.0 (TBD)

- [BREAKING] Upgraded the RustCrypto and dalek stack: `der`, `hkdf`, `sha2`, `sha3`, `k256`, `curve25519-dalek`, `ed25519-dalek`, and `x25519-dalek` ([#1045](https://github.com/0xMiden/crypto/pull/1045)).
- Upgraded `chacha20poly1305` to the current RustCrypto AEAD release line and added Wycheproof checks for ECDH and Ed25519 paths ([#1052](https://github.com/0xMiden/crypto/pull/1052)).
- Added `Display` (`0x`-prefixed lowercase hex) for the public key and signature types of all DSA schemes ([#1048](https://github.com/0xMiden/crypto/pull/1048)).
- Use faster DFT algorithm for `PeriodicPolys` ([#1054](https://github.com/0xMiden/crypto/pull/1054)).
- [BREAKING] Bumped Plonky3 upstream dependencies to v0.6.0 ([#1053](https://github.com/0xMiden/crypto/pull/1053)).
- [BREAKING] Make `Felt::Packing` resolve to the SIMD-packed `PackedFelt` from Plonky3 ([#1060](https://github.com/0xMiden/crypto/pull/1060)).
- Improved LargeSmt RocksDB defaults, added per-DB memory-budget controls, and exposed durability mode selection ([#1056](https://github.com/0xMiden/crypto/pull/1056)).
- Added doctests for ECDSA signature serialization, sponge state sizing, SMT sorted entries, and lifted AIR Fiat-Shamir docs ([#1049](https://github.com/0xMiden/crypto/pull/1049)).
- perf: factor the DEEP barycentric inner loop to drop the per-row `xᵢ · qᵢ` base×extension multiplication ([#1064](https://github.com/0xMiden/crypto/issues/1064)).

## 0.26.0 (06-02-2026)

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

## 0.25.1 (2026-05-21)

- Fixed `miden-lifted-stark` builds when `p3-maybe-rayon/parallel` is enabled without `miden-lifted-stark/parallel` ([#1023](https://github.com/0xMiden/crypto/pull/1023)).

## 0.25.0 (2026-05-01)

- [BREAKING] Changed the serialization format of `PartialSmt` to be more compact on the wire ([#957](https://github.com/0xMiden/crypto/pull/957)).
- [BREAKING] Changed `SmtLeaf::hash` to perform domain-separated hashing, reducing the risk of a collision with the hash of an inner node. ([#962](https://github.com/0xMiden/crypto/pull/962)).
- [BREAKING] Extracted `SmtStorageReader` and `SparseMerkleTreeReader`, allowing `LargeSmt<S>` to work with read-only storage backends ([#967](https://github.com/0xMiden/crypto/pull/967)).
- Added domain-separated hashing support for elements to `AlgebraicSpoonge` as `hash_elements_in_domain(...)` ([#978](https://github.com/0xMiden/crypto/pull/978)).
- Added `Signature::from_der()` for EdDSA signatures ([#979](https://github.com/0xMiden/crypto/pull/979)).
- Fixed `SimpleSmt::set_subtree()` to clear stale leaves and inner nodes in the replaced subtree region ([#981](https://github.com/0xMiden/crypto/pull/981)).
- Fixed `SliceReader` bounds checking to reject overflowing read lengths ([#987](https://github.com/0xMiden/crypto/pull/987)).

## 0.24.0 (2026-04-19)

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

## 0.23.0 (2026-03-11)

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

## 0.22.4 (2026-03-03)

- Make `SmtLeaf::get_value` public ([#872](https://github.com/0xMiden/crypto/pull/872)).

## 0.22.3 (2026-02-23)

- Refactored to introduce a unified `Felt` type for on-chain and off-chain code ([#819](https://github.com/0xMiden/crypto/pull/819)).
- Change `Ord for Word` to use lexicographic ordering ([#847](https://github.com/0xMiden/crypto/pull/847)).
- Add `From<{u8, u16, u32}> for Felt` and `TryFrom<u64> for Felt` ([#848](https://github.com/0xMiden/crypto/pull/848)).

## 0.22.2 (2026-02-01)

- Re-exported `p3_keccak::VECTOR_LEN`.

## 0.22.1 (2026-02-01)

- Re-exported additional Plonky3 modules and structs.
- Implemented `batch_inversion_allow_zeros()` function.

## 0.22.0 (2026-01-27)

- Added const-generic `Digest<N>` struct for binary hash functions with `Digest256` and `Digest512` type aliases ([#777](https://github.com/0xMiden/crypto/pull/777)).
- Added `MmrPath::with_forest()` and `MmrProof::with_forest()` to adjust proofs for smaller forests ([#788](https://github.com/0xMiden/crypto/pull/788)).
- [BREAKING] Migrate from RPO to Poseidon2 for AEAD, Falcon DSA, IES, and Merkle trees ([#793](https://github.com/0xMiden/crypto/pull/793)).
- Updated SMT benchmark executable to use Poseidon2 instead of Rpo256 ([#800](https://github.com/0xMiden/crypto/pull/800)).

## 0.21.4 (2026-01-22)

- Fix an issue where `BudgetedReader` rejects valid usize collections with tight budgets ([#798](https://github.com/0xMiden/crypto/pull/798)).

## 0.21.3 (2026-01-21)

- Fix: don't disable WAL during subtree construction in `LargeSmt`'s RocksDB backend ([#794](https://github.com/0xMiden/crypto/pull/794)).

## 0.21.2 (2026-01-20)

- Exported `BudgetedReader` to allow for defense-in-depth against deserialization panics ([#786](https://github.com/0xMiden/crypto/pull/786)).

## 0.21.1 (2026-01-16)

- Changed `SmtForest` so that `EMPTY_WORD` is treated as removals ([#780](https://github.com/0xMiden/crypto/pull/780)).

## 0.21.0 (2026-01-14)

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

## 0.20.0 (2025-12-28)

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

## 0.19.2 (2025-12-04)

- [BREAKING] Fixed `Signature` serialization by reducing `SIGNATURE_BYTES` to 65 ([#686](https://github.com/0xMiden/crypto/pull/686)).

## 0.19.1 (2025-12-04)

- Fixed `Signature` deserialization missing one byte from serialization ([#687](https://github.com/0xMiden/crypto/pull/687)).

## 0.19.0 (2025-11-30)

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

## 0.18.4 (2025-11-22)

- Fixed serialization of `PartialSmt` panicking in debug mode when it was constructed from only a root ([#662](https://github.com/0xMiden/crypto/pull/662)).

## 0.18.3 (2025-11-22)

- [BREAKING] removed unused 'self' parameter in HasherExt and all its implementations ([#666](https://github.com/0xMiden/crypto/pull/666))

## 0.18.2 (2025-11-08)

- Changed the methodology for computing ECDSA and EdDSA public key commitments ([#643](https://github.com/0xMiden/crypto/pull/643)).

## 0.18.1 (2025-11-05)

- [BREAKING] removed un-needed mutability from ECDSA `sign()` function ([#628](https://github.com/0xMiden/crypto/pull/628)).

## 0.18.0 (2025-10-27)

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

## 0.17.1 (2025-10-10)

- Support ECDSA signing/verifying with prehashed messages ([#573](https://github.com/0xMiden/crypto/pull/573)).

## 0.17.0 (2025-09-12)

- Added `LargeSmt`, SMT backed by RocksDB ([#438](https://github.com/0xMiden/miden-crypto/pull/438)).
- Added ECDSA and ECDH modules ([#475](https://github.com/0xMiden/crypto/pull/475)).
- added arithmetization oriented authenticated encryption with associated data (AEAD) scheme ([#480](https://github.com/0xMiden/crypto/pull/480)).
- Added XChaCha20-Poly1305 AEAD scheme ([#484](https://github.com/0xMiden/crypto/pull/484)).
- [BREAKING] `SmtLeaf::entries()` now returns a slice ([#521](https://github.com/0xMiden/crypto/pull/521)).

## 0.16.1 (2025-08-21)

- Fix broken imports in CPU-specific `rescue` implementations (AVX2, SVE) ([#492](https://github.com/0xMiden/crypto/pull/492/)).
- Added `{Smt,PartialSmt}::inner_node_indices` to make inner nodes accessible ([#494](https://github.com/0xMiden/crypto/pull/494)).
- Added various benchmarks & related bench utilities ([#503](https://github.com/0xMiden/crypto/pull/503))

## 0.16.0 (2025-08-15)

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

## 0.15.7 (2025-07-18)

- Fix empty SMT serialization check in testing mode ([#456](https://github.com/0xMiden/crypto/pull/456)).

## 0.15.6 (2025-07-15)

- Added conversions and serialization for `PartialSmt` ([#451](https://github.com/0xMiden/crypto/pull/451/), [#453](https://github.com/0xMiden/crypto/pull/453/)).

## 0.15.5 (2025-07-10)

- Added `empty()` and `is_empty()` methods to `Word`.

## 0.15.4 (2025-07-07)

- Implemented `LexicographicWord` struct ([#443](https://github.com/0xMiden/crypto/pull/443/)).
- Added `SequentialCommit` trait ([#443](https://github.com/0xMiden/crypto/pull/443/)).

## 0.15.3 (2025-06-18)

- Fixed conversion error from a slice of bytes into `Word`.
- Added from element slice into `Word` conversion.

## 0.15.2 (2025-06-18)

- Added `to_vec()` method to `Word`.

## 0.15.1 (2025-06-18)

- Implemented `DerefMut`, `Index`, and `IndexMut` for `Word` (#434).

## 0.15.0 (2025-06-17)

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

## 0.14.1 (2025-05-31)

- Add module and function documentation. (#408).
- Added missing `PartialSmt` APIs (#417).

## 0.14.0 (2025-03-15)

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

## 0.13.3 (2025-02-18)

- Implement `PartialSmt` (#372, #381).
- Fix panic in `PartialMmr::untrack` (#382).

## 0.13.2 (2025-01-24)

- Made `InnerNode` and `NodeMutation` public. Implemented (de)serialization of `LeafIndex` (#367).

## 0.13.1 (2024-12-26)

- Generate reverse mutations set on applying of mutations set, implemented serialization of `MutationsSet` (#355).

## 0.13.0 (2024-11-24)

- Fixed a bug in the implementation of `draw_integers` for `RpoRandomCoin` (#343).
- [BREAKING] Refactor error messages and use `thiserror` to derive errors (#344).
- [BREAKING] Updated Winterfell dependency to v0.11 (#346).
- Added support for hashmaps in `Smt` and `SimpleSmt` which gives up to 10x boost in some operations (#363).

## 0.12.0 (2024-10-30)

- [BREAKING] Updated Winterfell dependency to v0.10 (#338).
- Added parallel implementation of `Smt::with_entries()` with significantly better performance when the `concurrent` feature is enabled (#341).

## 0.11.0 (2024-10-17)

- [BREAKING]: renamed `Mmr::open()` into `Mmr::open_at()` and `Mmr::peaks()` into `Mmr::peaks_at()` (#234).
- Added `Mmr::open()` and `Mmr::peaks()` which rely on `Mmr::open_at()` and `Mmr::peaks()` respectively (#234).
- Standardized CI and Makefile across Miden repos (#323).
- Added `Smt::compute_mutations()` and `Smt::apply_mutations()` for validation-checked insertions (#327).
- Changed padding rule for RPO/RPX hash functions (#318).
- [BREAKING] Changed return value of the `Mmr::verify()` and `MerklePath::verify()` from `bool` to `Result<>` (#335).
- Added `is_empty()` functions to the `SimpleSmt` and `Smt` structures. Added `EMPTY_ROOT` constant to the `SparseMerkleTree` trait (#337).

## 0.10.3 (2024-09-25)

- Implement `get_size_hint` for `Smt` (#331).

## 0.10.2 (2024-09-25)

- Implement `get_size_hint` for `RpoDigest` and `RpxDigest` and expose constants for their serialized size (#330).

## 0.10.1 (2024-09-13)

- Added `Serializable` and `Deserializable` implementations for `PartialMmr` and `InOrderIndex` (#329).

## 0.10.0 (2024-08-06)

- Added more `RpoDigest` and `RpxDigest` conversions (#311).
- [BREAKING] Migrated to Winterfell v0.9 (#315).
- Fixed encoding of Falcon secret key (#319).

## 0.9.3 (2024-04-24)

- Added `RpxRandomCoin` struct (#307).

## 0.9.2 (2024-04-21)

- Implemented serialization for the `Smt` struct (#304).
- Fixed a bug in Falcon signature generation (#305).

## 0.9.1 (2024-04-02)

- Added `num_leaves()` method to `SimpleSmt` (#302).

## 0.9.0 (2024-03-24)

- [BREAKING] Removed deprecated re-exports from liballoc/libstd (#290).
- [BREAKING] Refactored RpoFalcon512 signature to work with pure Rust (#285).
- [BREAKING] Added `RngCore` as supertrait for `FeltRng` (#299).

# 0.8.4 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (`vec` and `format` macros).

# 0.8.3 (2024-03-17)

- Re-added unintentionally removed re-exported liballoc macros (#292).

# 0.8.2 (2024-03-17)

- Updated `no-std` approach to be in sync with winterfell v0.8.3 release (#290).

## 0.8.1 (2024-02-21)

- Fixed clippy warnings (#280)

## 0.8.0 (2024-02-14)

- Implemented the `PartialMmr` data structure (#195).
- Implemented RPX hash function (#201).
- Added `FeltRng` and `RpoRandomCoin` (#237).
- Accelerated RPO/RPX hash functions using AVX512 instructions (#234).
- Added `inner_nodes()` method to `PartialMmr` (#238).
- Improved `PartialMmr::apply_delta()` (#242).
- Refactored `SimpleSmt` struct (#245).
- Replaced `TieredSmt` struct with `Smt` struct (#254, #277).
- Updated Winterfell dependency to v0.8 (#275).

## 0.7.1 (2023-10-10)

- Fixed RPO Falcon signature build on Windows.

## 0.7.0 (2023-10-05)

- Replaced `MerklePathSet` with `PartialMerkleTree` (#165).
- Implemented clearing of nodes in `TieredSmt` (#173).
- Added ability to generate inclusion proofs for `TieredSmt` (#174).
- Implemented Falcon DSA (#179).
- Added conditional `serde`` support for various structs (#180).
- Implemented benchmarking for `TieredSmt` (#182).
- Added more leaf traversal methods for `MerkleStore` (#185).
- Added SVE acceleration for RPO hash function (#189).

## 0.6.0 (2023-06-25)

- [BREAKING] Added support for recording capabilities for `MerkleStore` (#162).
- [BREAKING] Refactored Merkle struct APIs to use `RpoDigest` instead of `Word` (#157).
- Added initial implementation of `PartialMerkleTree` (#156).

## 0.5.0 (2023-05-26)

- Implemented `TieredSmt` (#152, #153).
- Implemented ability to extract a subset of a `MerkleStore` (#151).
- Cleaned up `SimpleSmt` interface (#149).
- Decoupled hashing and padding of peaks in `Mmr` (#148).
- Added `inner_nodes()` to `MerkleStore` (#146).

## 0.4.0 (2023-04-21)

- Exported `MmrProof` from the crate (#137).
- Allowed merging of leaves in `MerkleStore` (#138).
- [BREAKING] Refactored how existing data structures are added to `MerkleStore` (#139).

## 0.3.0 (2023-04-08)

- Added `depth` parameter to SMT constructors in `MerkleStore` (#115).
- Optimized MMR peak hashing for Miden VM (#120).
- Added `get_leaf_depth` method to `MerkleStore` (#119).
- Added inner node iterators to `MerkleTree`, `SimpleSmt`, and `Mmr` (#117, #118, #121).

## 0.2.0 (2023-03-24)

- Implemented `Mmr` and related structs (#67).
- Implemented `MerkleStore` (#93, #94, #95, #107 #112).
- Added benchmarks for `MerkleStore` vs. other structs (#97).
- Added Merkle path containers (#99).
- Fixed depth handling in `MerklePathSet` (#110).
- Updated Winterfell dependency to v0.6.

## 0.1.4 (2023-02-22)

- Re-export winter-crypto Hasher, Digest & ElementHasher (#72)

## 0.1.3 (2023-02-20)

- Updated Winterfell dependency to v0.5.1 (#68)

## 0.1.2 (2023-02-17)

- Fixed `Rpo256::hash` pad that was panicking on input (#44)
- Added `MerklePath` wrapper to encapsulate Merkle opening verification and root computation (#53)
- Added `NodeIndex` Merkle wrapper to encapsulate Merkle tree traversal and mappings (#54)

## 0.1.1 (2023-02-06)

- Introduced `merge_in_domain` for the RPO hash function, to allow using a specified domain value in the second capacity register when hashing two digests together.
- Added a simple sparse Merkle tree implementation.
- Added re-exports of Winterfell RandomCoin and RandomCoinError.

## 0.1.0 (2022-12-02)

- Initial release on crates.io containing the cryptographic primitives used in Miden VM and the Miden Rollup.
- Hash module with the BLAKE3 and Rescue Prime Optimized hash functions.
  - BLAKE3 is implemented with 256-bit, 192-bit, or 160-bit output.
  - RPO is implemented with 256-bit output.
- Merkle module, with a set of data structures related to Merkle trees, implemented using the RPO hash function.
