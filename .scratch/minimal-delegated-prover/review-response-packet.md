# PR #3437 review response packet

Status: local, unposted response packet

Source PR: https://github.com/0xMiden/miden-vm/pull/3437

GitHub state inspected read-only on 2026-08-13:

- PR title: `feat(prover): add composable prover interface`
- GitHub PR head: `12fee12d24b2d7a894e030723d5ef25087e73394`
- local relaunch head: `7009f991f939ab7382d1890b0eb88b9597769247`
- inline scope: the 10-thread union of threads that are unresolved or outdated
- non-inline scope: the prover-lifecycle question and aggregate-policy review summary
- no replies in this packet have been posted
- no GitHub review state has been changed

The `Resolved` and `Outdated` fields below preserve GitHub's observed thread state. “Current
context” refers to the local relaunch worktree. Copy-ready replies describe the relaunch, not the old
PR-head implementation.

## Inline union threads

### 1. `VmProof` minimum canonical size

- **Thread:** `PRRT_kwDOGCM_Is6VIhiN`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3683528448
- **Reviewer:** `huitseeker`
- **Resolved:** `false`
- **Outdated:** `false`
- **Original context:** `core/src/proof.rs`, `VmProof`'s `Deserializable` implementation, originally
  line 207; current GitHub line 174.
- **Classification:** implemented

#### Exact reviewer text

> `Vec<VmProof>` uses `Deserializable::min_serialized_size()` before allocation, and the default is the 64-byte in-memory size even though the shortest encoding is 34 bytes. 
>
> I think we need to override the minima for `StarkProof` and `VmProof` (plus optionally an all-settled batch round-trip test) to keep canonical encodings readable.

The same thread later contains the exact reviewer follow-up:

> I think this concern is still live

#### Current context

`core/src/proof.rs` now defines the minima compositionally:

```rust
impl Deserializable for VmProof {
    // ...
    fn min_serialized_size() -> usize {
        StarkProof::min_serialized_size() + DeferredRoot::min_serialized_size()
    }
}
```

`proof_minimum_serialized_sizes_match_shortest_canonical_encodings` asserts the shortest canonical
`StarkProof` and `VmProof` encodings are 2 and 34 bytes respectively.

#### Resolution against current code

Resolved in the relaunch. The encoded minimum is no longer inherited from in-memory size.

#### Copy-ready reply

> Fixed in the relaunch. `StarkProof::min_serialized_size()` reports its one-byte empty-vector length plus the hash-function tag, and `VmProof` composes that with the 32-byte deferred root. The resulting canonical minima are 2 bytes for `StarkProof` and 34 bytes for `VmProof`.
>
> The focused core regression asserts both reported minima against their shortest canonical encodings.

---

### 2. Bound constituent roots before folding

- **Thread:** `PRRT_kwDOGCM_Is6VIhww`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3683529761
- **Reviewer:** `huitseeker`
- **Resolved:** `true`
- **Outdated:** `true`
- **Original context:** `verifier/src/lib.rs`, aggregate precompile verification, originally line 173.
- **Classification:** implemented; original location obsolete

#### Exact reviewer text

> Could we bound the constituent roots *before* folding them? 
>
> `with_max_proof_size` only limits the STARK bytes. An untrusted proof can add _tons_ of extra roots, pass the shape checks, and make this call run one Poseidon2 fold per root before the byte-size check. 
>
> I think we need a complete-proof byte limit or root-count limit at deserialization.

The same thread later contains the exact reviewer follow-up:

> This concern is still live

#### Current context

`PrecompileProof::read_from` checks `root_count > MAX_PRECOMPILE_ROOTS` before collecting the root
vector. `Verifier::verify` repeats the hard bound for directly constructed public records before
reducing roots. `MAX_PRECOMPILE_ROOTS` is 4,096.

#### Resolution against current code

Resolved by a fixed library safety ceiling at both canonical decoding and verification. A broader
whole-envelope or configurable ingestion policy remains separate from this PR.

#### Copy-ready reply

> Fixed in the relaunch with a hard 4,096-root library safety ceiling. Canonical `PrecompileProof` decoding checks the declared root count before collecting the vector, and `Verifier::verify` enforces the same ceiling for directly constructed public records before aggregate folding.
>
> This bounds allocation and Poseidon2 folding introduced by this proof format. Whole-envelope and lower configurable ingestion policy remain separate concerns rather than being represented by the former per-STARK byte option.

---

### 3. Preserve a real aggregate deferred-state limit

- **Thread:** `PRRT_kwDOGCM_Is6VIiA1`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3683531244
- **Reviewer:** `huitseeker`
- **Resolved:** `true`
- **Outdated:** `true`
- **Original context:** `prover/src/prover.rs`, old batch aggregation reset, originally line 84.
- **Classification:** implemented; old batch API removed

#### Exact reviewer text

> Could this keep a real aggregate limit instead of resetting it to `usize::MAX`?  😱 

#### Current context

The old batch proving method and `set_max_elements(usize::MAX)` reset no longer exist.
`PrecompileWitness::merge(Vec<PrecompileWitness>)` starts with the first bounded hydrated state and
imports every later root-reachable state through `DeferredState::merge`; insertion accounting applies
the fixed `MAX_DEFERRED_ELEMENTS` ceiling cumulatively to the merged state. Root metadata is
separately capped by `MAX_PRECOMPILE_ROOTS`.

#### Resolution against current code

Resolved. Aggregation no longer disables accounting or accepts a caller-supplied unbounded limit.

#### Copy-ready reply

> Fixed in the relaunch. The old batch API and its `usize::MAX` reset are gone. `PrecompileWitness::merge` now preserves the first state's fixed `MAX_DEFERRED_ELEMENTS` budget while importing each later root-reachable state through normal insertion accounting, so the complete merged hydrated state remains bounded cumulatively.
>
> Ordered root metadata has its separate fixed `MAX_PRECOMPILE_ROOTS` ceiling. Shared DAG nodes may deduplicate without cost, but duplicate root occurrences remain proof-significant.

---

### 4. Remove duplicated proof-shape validation

- **Thread:** `PRRT_kwDOGCM_Is6WDV6d`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3705952352
- **Reviewer:** `huitseeker`
- **Resolved:** `true`
- **Outdated:** `true`
- **Original context:** `verifier/src/lib.rs`, verifier-local deferred/complete shape helpers,
  originally line 108.
- **Classification:** implemented with a superseding seam decision

#### Exact reviewer text

> nit: Could we expose one proof-structure validation entry point from `miden-core` and call it here? The helpers in this crate duplicate the invariants already checked in `core/src/proof.rs`, leaving about 40 lines of shape checks that can drift apart.

#### Current context

The relaunch removes constructor-owned and core-owned proof-shape validation rather than exposing a
second public core entry point. `VmProof` and `PrecompileProof` are unvalidated transport records;
`ExecutionProof::complete` performs only the lifecycle transition. `Verifier::verify` is now the
single authoritative seam for root policy, proof presence, coverage, aggregate folding, and
cryptographic checks.

#### Resolution against current code

The drift concern is resolved by deleting the duplicate validity path. The exact proposed direction
is obsolete because validation deliberately lives only in `miden-verifier`.

#### Copy-ready reply

> Addressed in the relaunch by removing the duplicate validity path entirely. `miden-core` proof constructors and completion no longer validate cross-artifact shape; they preserve transport records and lifecycle state only.
>
> `Verifier::verify` is now the one authoritative seam for empty/excessive/settled roots, missing or unexpected precompile proofs, VM-root membership, ordered aggregate folding, and both STARKs. There is no second public proof-structure validator left to drift from it.

---

### 5. `PrecompileProof` minimum and the 71-byte vector

- **Thread:** `PRRT_kwDOGCM_Is6XBEgZ`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3729576052
- **Reviewer:** `huitseeker`
- **Resolved:** `false`
- **Outdated:** `false`
- **Original context:** `core/src/proof.rs`, `PrecompileProof`'s `Deserializable` implementation,
  originally line 263; current GitHub line 266.
- **Classification:** implemented with updated transport semantics

#### Exact reviewer text

> `PrecompileProof` still inherits the 56-byte in-memory default for `min_serialized_size()`, although its smallest valid encoding is 35 bytes. 
>
> This makes the recommended budgeted decoder reject valid collections: two singleton proofs encode in 71 bytes, but `Vec<PrecompileProof>::read_from_bytes_with_budget(..., 71)` fails with `requested 2 elements but reader can provide at most 1`. 
>
> We should override the minimum for the required one-root shape (and optionally add a budgeted two-proof round-trip test).

#### Current context

The relaunch permits malformed proof records to remain representable until verification, so the
canonical transport minimum is 3 bytes: a 2-byte empty `StarkProof` plus a one-byte zero-root vector.
A verifier-valid singleton remains 35 bytes, and a vector containing two shortest singleton records
is 71 bytes. `proof_minimum_serialized_sizes_match_shortest_canonical_encodings` checks all of these
values and decodes the two-record vector with an exact 71-byte budget.

#### Resolution against current code

Resolved. The exact decoder minimum is 3 under the new transport contract, while the reviewer's
35-byte valid singleton and 71-byte two-proof cases are both explicitly protected.

#### Copy-ready reply

> Fixed in the relaunch, with one transport-semantics distinction. `PrecompileProof` is now an unvalidated public transport record, so its canonical representational minimum is 3 bytes: a 2-byte empty `StarkProof` plus an empty root-vector encoding. Verification rejects that empty-root shape.
>
> The shortest verifier-valid singleton remains 35 bytes, and two such records encode in 71 bytes. The focused core test asserts all three values and successfully decodes `Vec<PrecompileProof>` with the exact 71-byte budget.

---

### 6. Stale merge-limit documentation

- **Thread:** `PRRT_kwDOGCM_Is6XBErm`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3729577158
- **Reviewer:** `huitseeker`
- **Resolved:** `false`
- **Outdated:** `true`
- **Original context:** `prover/README.md`, old merge-policy paragraph, originally line 71.
- **Classification:** obsolete and implemented by the relaunch contract

#### Exact reviewer text

> This paragraph now describes the opposite of `74a5bed7`: `PrecompileWitness::merge` requires `max_elements`, enforces it across the whole merged state, and caps the list at `MAX_PRECOMPILE_ROOTS`. 
>
> The same stale policy appears in `docs/src/design/deferred/semantics.md`, and `docs/src/design/stack/precompiles.md` still shows the old one-argument call. 
>
> Can you update all three together?

#### Current context

The relaunch removed the caller-supplied `max_elements` argument. The final API is
`PrecompileWitness::merge(Vec<PrecompileWitness>)`, with fixed hard ceilings
`MAX_DEFERRED_ELEMENTS` and `MAX_PRECOMPILE_ROOTS`. `prover/README.md`,
`docs/src/design/deferred/semantics.md`, and `docs/src/design/stack/precompiles.md` were updated to
describe the same fixed-limit lifecycle and one-argument call.

#### Resolution against current code

Resolved across all three documents, though the final API differs from the intermediate commit
referenced by the review.

#### Copy-ready reply

> Updated together in the relaunch. The intermediate caller-supplied `max_elements` API was removed; `PrecompileWitness::merge` now takes only the witness vector and enforces the fixed `MAX_DEFERRED_ELEMENTS` and `MAX_PRECOMPILE_ROOTS` library safety ceilings internally.
>
> `prover/README.md`, `docs/src/design/deferred/semantics.md`, and `docs/src/design/stack/precompiles.md` now describe that same one-argument API, exact-order/duplicate semantics, and fixed-limit policy.

---

### 7. Generic Serde allocation bounds

- **Thread:** `PRRT_kwDOGCM_Is6XBQsd`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3729650083
- **Reviewer:** `huitseeker`
- **Resolved:** `false`
- **Outdated:** `true`
- **Original context:** `core/src/proof.rs`, custom `Deserialize` for `PrecompileProof`, originally
  line 294.
- **Classification:** implemented via explicit documentation; old custom visitor removed

#### Exact reviewer text

> nit: The 4,096-root check in `from_parts` runs only after this `Vec` has been fully deserialized, so a serde/Postcard caller can reserve and parse more roots than the cap before rejection. 
>
> There's no in-repo serde consumer of `PrecompileProof`, and the standard `ExecutionProof` transport uses the early-checked binary decoder, so this is not currently reachable here. 
>
> Still, could we either use a bounded visitor or document this serde path as trusted-only?

#### Current context

The relaunch deliberately derives Serde as a representation format and deletes the parallel custom
visitor machinery. Canonical binary decoding remains the hardened untrusted-input path and checks
root and payload declarations before allocation. The deferred semantics documentation states that
generic derived Serde is not guaranteed to apply canonical decoder allocation bounds and must not be
treated as a hardened untrusted-input decoder.

#### Resolution against current code

Resolved using the reviewer's documentation option. No bounded generic visitor is claimed.

#### Copy-ready reply

> Addressed using the documentation option. The relaunch derives Serde only as a representation format and explicitly does not claim that generic Serde/Postcard decoding applies the canonical decoder's early allocation bounds.
>
> Hardened untrusted input must use the canonical binary decoders, which check `MAX_STARK_PROOF_BYTES`, `MAX_PRECOMPILE_ROOTS`, and deferred-wire declarations before collecting their payloads. The custom Serde visitors were removed rather than maintaining a second transport implementation.

---

### 8. Recursive request packaging consumes proof felts

- **Thread:** `PRRT_kwDOGCM_Is6YShxO`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3759551522
- **Reviewer:** `huitseeker`
- **Resolved:** `false`
- **Outdated:** `false`
- **Original context:** `miden-vm/tests/integration/prove_verify.rs`, stale 40-felt advice copy,
  line 107.
- **Classification:** implemented

#### Exact reviewer text

> I think here `generate_advice_inputs` puts the claim commitment on the operand stack and only the proof stream on advice. This stale copy consumes the first 40 proof felts, causing both recursive CI tests to fail. Without the copy, this should work calling`verify_vm_proof` directly?

#### Current context

The relaunch restores `generate_request_inputs`. The producer stores the unchanged proof stream in the
advice map under `proof_request_key(verifier_root, claim_commitment)`. The MASM consumer starts from
`CLAIM_COMMITMENT`, derives the same request key, executes `adv.push_mapval`, and then calls
`verify_vm_proof`. The stale `copy_advice_to_mem` procedure and 40-felt copy are gone.

#### Resolution against current code

Resolved. Both equal-height and hash-heavy recursive regressions have been restored around the
content-addressed request flow.

#### Copy-ready reply

> Fixed in the relaunch. The stale 40-felt copy is removed.
>
> Recursive input generation now packages the unchanged proof stream under `proof_request_key(verifier_root, claim_commitment)`. The MASM consumer starts with the claim commitment, derives that key, fetches the proof with `adv.push_mapval`, and calls `verify_vm_proof`. Claim and kernel preimages remain separate content-addressed map entries.

---

### 9. Standalone `VmProof` trailing bytes

- **Thread:** `PRRT_kwDOGCM_Is6Y-uBT`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3776549705
- **Reviewer:** `Al-Kindi-0`
- **Resolved:** `false`
- **Outdated:** `false`
- **Original context:** `core/src/proof.rs`, `VmProof::read_from_bytes`, line 181 on the PR.
- **Classification:** implemented locally

#### Exact reviewer text

> Should this also reject trailing bytes, like `ExecutionProof::read_from_bytes` does?

#### Current context

`VmProof::read_from_bytes` now decodes through the bounded slice reader and rejects the result when
`reader.has_more_bytes()` is true, matching the enclosing `ExecutionProof` full-slice contract.

#### Resolution against current code

Resolved in the local relaunch worktree. The focused standalone proof-decoder regression appends a
byte to a canonical `VmProof` and confirms that decoding fails.

#### Copy-ready reply

> Fixed in the relaunch. `VmProof::read_from_bytes` now rejects trailing bytes after a successfully decoded payload, matching `ExecutionProof::read_from_bytes`.
>
> A focused regression covers the standalone `VmProof` and `PrecompileProof` full-slice contracts together.

---

### 10. Standalone `PrecompileProof` trailing bytes

- **Thread:** `PRRT_kwDOGCM_Is6Y-upK`
- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#discussion_r3776553641
- **Reviewer:** `Al-Kindi-0`
- **Resolved:** `false`
- **Outdated:** `false`
- **Original context:** `core/src/proof.rs`, `PrecompileProof::read_from_bytes`, line 282 on the PR.
- **Classification:** implemented locally

#### Exact reviewer text

> Should this also reject trailing bytes, like `ExecutionProof::read_from_bytes` does?

#### Current context

`PrecompileProof::read_from_bytes` now decodes through the bounded slice reader and rejects the result
when `reader.has_more_bytes()` is true, matching the enclosing `ExecutionProof` full-slice contract.

#### Resolution against current code

Resolved in the local relaunch worktree. The focused standalone proof-decoder regression appends a
byte to a canonical `PrecompileProof` and confirms that decoding fails.

#### Copy-ready reply

> Fixed in the relaunch. `PrecompileProof::read_from_bytes` now rejects trailing bytes after a successfully decoded payload, matching `ExecutionProof::read_from_bytes`.
>
> A focused regression covers the standalone `VmProof` and `PrecompileProof` full-slice contracts together.

## Non-inline comments

### 11. Prover lifecycle: `prove`, `prove_full`, and `prove_vm`

- **Comment:** https://github.com/0xMiden/miden-vm/pull/3437#issuecomment-5171559208
- **Reviewer:** `bobbinth`
- **GitHub form/state:** non-inline PR conversation comment; no resolved/outdated thread state
- **Context:** question on the PR description's public `Prover` interface.
- **Classification:** answered by the relaunch interface trim

#### Exact reviewer text

> ```rust
> impl Prover {
>     pub fn prove(&self, witness: ExecutionWitness) -> Result<ExecutionProof, ProverError>;
>     pub fn prove_full(&self, witness: ExecutionWitness) -> Result<ExecutionProof, ProverError>;
>     pub fn prove_vm(&self, witness: VmWitness) -> Result<VmProof, ProverError>;
>     pub fn prove_precompile(
>         &self,
>         witness: &PrecompileWitness,
>     ) -> Result<PrecompileProof, ProverError>;
> }
> ```
>
> In the above, what's the difference between `prove()`, `prove_full()`, and `prove_vm()`?

#### Current context

The relaunch public façade is intentionally smaller:

- `Prover::prove(ExecutionWitness)` proves the VM and returns `Deferred` with passive wire when
  precompile work remains; no-work execution returns `Complete`.
- `Prover::prove_full(ExecutionWitness)` proves the VM and any precompile witness locally and returns
  `Complete`.
- public `Prover::prove_vm` was removed. VM-only proving remains a private backend step because this
  PR does not define a transportable delegated `VmWitness` worker interface.
- `Prover::prove_precompile(&PrecompileWitness)` is the delegated precompile-proving seam.

#### Resolution against current code

Resolved by removing the ambiguous public `prove_vm` operation and documenting the two supported
execution-witness routes.

#### Copy-ready reply

> The relaunch narrows this interface to remove the ambiguity:
>
> - `prove(ExecutionWitness)` is VM-first. It returns `Complete` immediately when the execution has no deferred work, otherwise `Deferred` carrying passive deferred wire for later hydration and precompile proving.
> - `prove_full(ExecutionWitness)` proves both the VM and any precompile work locally and returns `Complete`.
> - public `prove_vm(VmWitness)` has been removed. VM-only proving remains a private backend step because this PR does not define a supported delegated-VM witness transport.
>
> `prove_precompile(&PrecompileWitness)` remains the independent delegated-precompile seam.

---

### 12. Aggregate-limit review summary

- **Review:** https://github.com/0xMiden/miden-vm/pull/3437#pullrequestreview-4846303652
- **Reviewer:** `huitseeker`
- **GitHub form/state:** non-inline review body; `COMMENTED`; no resolved/outdated thread state
- **Submitted:** `2026-08-03T17:14:32Z`
- **Context:** review summary accompanying the constituent-root and aggregate-state concerns.
- **Classification:** implemented for hard safety bounds; broader policy deliberately separate

#### Exact reviewer text

> I think the aggregate limit issue is still unsolved as well.

#### Current context

The relaunch uses fixed hard library safety ceilings:

- `MAX_PRECOMPILE_ROOTS = 4,096` bounds canonical allocation, direct verification, merge input count,
  and aggregate-root folding.
- `MAX_DEFERRED_ELEMENTS = 1 << 20` bounds hydration and the complete merged deferred state.
- the old `usize::MAX` reset and configurable verifier/prover limit surfaces were deleted.
- whole-envelope, file/network ingestion, and lower configurable acceptance policy are not claimed as
  solved by these fixed component ceilings.

#### Resolution against current code

The unbounded work introduced by the old implementation is resolved. The broader policy question is
kept separate rather than adding another configuration layer to this interface-trim PR.

#### Copy-ready reply

> The relaunch resolves the unbounded aggregate operations with fixed hard library safety ceilings: 4,096 ordered constituent roots and `1 << 20` deferred-state elements.
>
> Root declarations are checked before canonical allocation, direct public records are checked before folding, witness merge input count is bounded, and merged-state imports retain cumulative element accounting. The old `usize::MAX` reset is gone.
>
> These are component safety ceilings, not a claim that whole-envelope, file/network ingestion, or lower configurable acceptance policy is solved in this PR.
