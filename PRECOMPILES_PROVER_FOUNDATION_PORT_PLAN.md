# Precompiles Prover Foundation Port Plan

## Purpose

Port the lower-crate semantic foundations that were discovered on `precompiles/vm-precompiles-prover` onto `precompiles/crate` as focused additive commits, then rebase/clean the prover branch so the prover branch consumes those lower APIs instead of carrying mixed lower-crate fixes.

This is a living orchestration document. Agents should update this document indirectly by reporting findings to the coordinator, who consolidates status here. Do **not** let multiple agents edit this file concurrently.

## Branches and safety refs

Current known branches:

- lower branch: `precompiles/crate`
- source/top branch: `precompiles/vm-precompiles-prover`
- remote source/top branch: `origin/precompiles/vm-precompiles-prover`

Before code edits, create safety refs from a clean worktree:

```bash
git branch backup/precompiles-crate-before-foundation-port precompiles/crate
git branch backup/precompiles-prover-before-foundation-port precompiles/vm-precompiles-prover
git config rerere.enabled true
```

Recommended scratch branches:

```bash
git switch precompiles/crate
git switch -c scratch/precompiles-crate-foundation-port

git switch precompiles/vm-precompiles-prover
git switch -c scratch/precompiles-prover-on-foundations
```

Do not force-push real branch names until the final comparison passes and the owner approves.

## Current orchestration rule

The worktree has local changes. Until a clean scratch worktree/branch is prepared, the first agent wave is **read-only reconnaissance only**.

Agents in wave 1 must not edit files. Their job is to produce concrete implementation notes, file lists, test lists, and risks for their slice.

The coordinator then:

1. consolidates their output into this document;
2. decides exact commit boundaries;
3. prepares a clean scratch branch/worktree;
4. launches edit agents only with disjoint write scopes.

## Desired final shape

```text
precompiles/crate
  + Add canonical deferred byte chunk helper
  + Use fixed bound pointers for uint value tags
  + Use group pointers for curve value tags and generic MSM tags
  + Derive fixed precompile metadata from enums

precompiles/vm-precompiles-prover
  + prover crate/import/integration
  + prover-specific docs/tests/examples
  + prover-specific adaptations to lower APIs
```

## Commit plan for `precompiles/crate`

### Commit A: Add canonical deferred byte chunk helper

Goal: make deferred byte chunk packing canonical in `core/src/deferred/node.rs`.

Expected additions:

- `Node::PACKED_BYTES_PER_CHUNK`
- `Node::chunks_from_bytes(bytes: &[u8]) -> Self`

Expected semantics:

- bytes are packed little-endian into `u32` field elements;
- each `DataChunk` has 8 felts;
- one chunk stores 32 bytes;
- empty input becomes one all-zero chunk;
- result uses framework `Tag::CHUNKS`.

Source reference:

- `6fd0ec64a` lower hunks in `core/src/deferred/node.rs`, `precompiles/src/hash/mod.rs`, `precompiles/src/codec.rs`.

Validation:

- deferred node tests;
- hash precompile tests that consume chunk-list payloads.

### Commit B: Use fixed bound pointers for uint value tags

Goal: change uint `VALUE` tag identity from local domain IDs to VM-owned fixed bound pointers.

Final tag shape:

```text
UINT_VALUE_TAG = [UINT_PRECOMPILE_ID, VALUE_OP_ID, BOUND_PTR, 0]
```

Expected constants:

```rust
U256_BOUND_PTR = 1
K1_BASE_BOUND_PTR = 2
K1_SCALAR_BOUND_PTR = 3
R1_BASE_BOUND_PTR = 4
R1_SCALAR_BOUND_PTR = 5
ED25519_BASE_BOUND_PTR = 6
ED25519_SCALAR_BOUND_PTR = 7
```

Expected APIs:

```rust
impl UintDomain {
    pub const fn bound_ptr(self) -> u32;
    pub const fn from_bound_ptr(ptr: u32) -> Option<Self>;
}
```

Expected behavior:

- `UintPrecompileDescriptor::value_tag(domain)` uses `domain.bound_ptr()`;
- uint decode parses `args[1]` through `UintDomain::from_bound_ptr`;
- binary op tags remain zero-immediate;
- MASM/codegen wording says `BOUND_PTR`, not `DOMAIN_ID`/`MODULUS_ID`;
- tests assert exact tag words and rejection cases.

Source references:

- `8ca896a75` lower uint/codegen hunks;
- `ea5921bb1` descriptor round-trip test hunk.

Validation:

- uint precompile tests;
- codegen descriptor tests;
- MASM codegen tests if present.

### Commit C: Use group pointers for curve value tags and generic MSM tags

Goal: align curve tags with the current prover branch tip. Curve `VALUE` tags carry VM-owned group pointers. Curve `MSM` uses a generic zero-immediate op tag; the pair-list payload length is authoritative and the curve is inferred/validated from the point values.

Final tag shapes:

```text
CURVE_VALUE_TAG = [CURVE_PRECOMPILE_ID, VALUE_OP_ID, GROUP_PTR, 0]
CURVE_MSM_TAG   = [CURVE_PRECOMPILE_ID, MSM_OP_ID,   0,         0]
```

This supersedes the earlier intermediate recommendation of `CURVE_MSM_TAG = [..., MSM_OP_ID, GROUP_PTR, 0]`. The current `precompiles/vm-precompiles-prover` tip includes `ca9da7fad` (`Remove group pointer from curve MSM tag`), so the lower port should match the prover tip unless the owner explicitly decides to diverge.

Expected constants:

```rust
K1_GROUP_PTR = 1
R1_GROUP_PTR = 2
ED25519_SW_GROUP_PTR = 3
```

Use names consistent with the current branch. This branch uses `Ed25519Sw`; do not copy stale twisted-Edwards `Ed25519` assumptions.

Expected APIs:

```rust
impl CodegenCurveId {
    pub const fn group_ptr(self) -> u32;
    pub const fn from_group_ptr(ptr: u32) -> Option<Self>;
}

impl CurveId {
    pub const fn group_ptr(self) -> u32;
    pub const fn from_group_ptr(ptr: u32) -> Option<Self>;
}
```

Expected behavior:

- `CurvePrecompileDescriptor::value_tag(curve)` uses `curve.group_ptr()`;
- `CurvePrecompileDescriptor::msm_tag()` takes no curve/count and returns `op_tag(MSM_OP_ID)`;
- `CurvePrecompile::decode` parses group pointers only for `VALUE`; `MSM` accepts only `[MSM_OP_ID, 0, 0]`;
- `PairList` payload length is authoritative;
- MSM pairs are ordered `(point_digest, scalar_digest)`;
- MSM evaluation infers the curve from the first point value and enforces subsequent point values match it;
- tests assert exact tag words and rejection cases.

Source references:

- final state of `781bc67d0`, `16c5a7d01`, `9911583ee`, and `ca9da7fad`;
- do **not** preserve the intermediate coefficient-pointer value tag shape;
- do **not** preserve the intermediate group-pointer MSM tag shape.

Validation:

- curve precompile tests;
- codegen descriptor tests;
- generated MASM template tests;
- ECDSA/curve integration tests that exercise `msm2`/`msm2_generator`.

### Commit D: Derive fixed precompile metadata from enums

Goal: reduce duplicate hand-maintained fixed metadata so prover code can consume canonical lower metadata.

Expected additions/adaptations:

```rust
impl CodegenCurveId {
    pub const ALL: [Self; 3] = [
        Self::Secp256k1,
        Self::Secp256r1,
        Self::Ed25519Sw,
    ];
}
```

Prefer deriving generated MASM configs from:

- `UintDomain::ALL`
- `CodegenCurveId::ALL`

if doing so keeps code readable and does not cause unrelated churn.

Potential metadata APIs:

```rust
impl CurveId {
    pub fn a_value(self) -> Limbs;
    pub fn b_value(self) -> Limbs;
}
```

For this branch, all three curves should use their short-Weierstrass model constants, including `Ed25519Sw`.

Source reference:

- `50fbd7952`, adapted to current branch naming/model.

Validation:

- codegen tests;
- generated path/title assertions.

## Prover branch rebase/cleanup plan

After the lower scratch branch has the foundation commits and validates:

```bash
git switch scratch/precompiles-prover-on-foundations
git rebase -i --empty=ask --onto scratch/precompiles-crate-foundation-port \
  backup/precompiles-crate-before-foundation-port \
  scratch/precompiles-prover-on-foundations
```

During rebase:

- keep prover crate import/integration commits;
- keep prover-specific docs/tests/examples;
- drop or edit lower-crate semantic hunks that are now in the base;
- let empty commits drop if their lower changes were fully ported;
- preserve prover adaptations to the new lower APIs.

Suspicious lower paths in the final prover diff that need inspection:

```text
core/src/deferred/node.rs
precompiles/codegen/src/descriptors.rs
precompiles/codegen/src/masm.rs
precompiles/codegen/src/templates/*
precompiles/src/math/uint/*
precompiles/src/math/curve/*
precompiles/src/hash/*
```

Expected dominant final prover diff paths:

```text
precompiles-prover/**
Cargo.toml
Cargo.lock
```

## Final comparison against original prover branch

Required comparison commands:

```bash
git range-diff \
  backup/precompiles-crate-before-foundation-port..backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-crate-foundation-port..scratch/precompiles-prover-on-foundations
```

```bash
git diff --stat \
  backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-prover-on-foundations
```

```bash
git diff \
  backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-prover-on-foundations \
  -- precompiles-prover
```

```bash
git diff \
  backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-prover-on-foundations \
  -- \
  core/src/deferred/node.rs \
  precompiles/codegen/src/descriptors.rs \
  precompiles/codegen/src/masm.rs \
  precompiles/codegen/src/templates \
  precompiles/src/math/uint \
  precompiles/src/math/curve \
  precompiles/src/hash
```

Final checklist:

- uint `VALUE_TAG` uses `BOUND_PTR`;
- curve `VALUE_TAG` uses `GROUP_PTR`;
- curve `MSM_TAG` is generic zero-immediate `[CURVE_PRECOMPILE_ID, MSM_OP_ID, 0, 0]`;
- curve `MSM_TAG` does not encode curve or pair count;
- MSM pair order is `(point_digest, scalar_digest)`;
- `Node::chunks_from_bytes` exists and prover uses canonical packing where appropriate;
- fixed metadata comes from lower enums/helpers;
- no stale `Ed25519` twisted-Edwards coefficient logic was copied into `Ed25519Sw`;
- final prover branch preserves prover crate tests/docs/examples/functionality.

## Agent orchestration

### Coordinator responsibilities

The coordinator owns:

- this planning doc;
- commit boundary decisions;
- branch/scratch setup;
- conflict arbitration;
- final `range-diff` and tree comparison;
- deciding when to move real branch names.

Agents should not concurrently edit this document. Agents should report:

- exact files to touch;
- concrete patch strategy;
- tests to run;
- risks/conflicts;
- whether the change is independent or depends on another slice.

### Wave 1: read-only reconnaissance

Status: complete.

| Agent | Scope | Write access | Output expected | Status |
|---|---|---:|---|---|
| A | Deferred byte chunk helper | No | file-level implementation notes and tests | Done |
| B | Uint bound pointers | No | final tag/decode/test patch plan | Done |
| C | Curve group pointers/MSM semantics | No | final tag/decode/test patch plan, Ed25519Sw cautions | Done; update for latest generic MSM tag noted below |
| D | Metadata/codegen enum derivation | No | patch plan and dependency ordering | Done |
| E | Prover rebase/comparison | No | rebase strategy, likely conflicts, comparison checklist | Done |

### Wave 2: lower-branch edit agents

Only start after wave 1 is consolidated and a clean scratch branch/worktree exists.

Recommended disjoint write scopes:

- Agent A: `core/src/deferred/node.rs`, `precompiles/src/hash/*`, related tests.
- Agent B: `precompiles/src/math/uint/*`, uint portions of `precompiles/codegen/src/descriptors.rs`, `precompiles/codegen/src/templates/uint.masm.tpl`, uint tests.
- Agent C: `precompiles/src/math/curve/*`, curve portions of `precompiles/codegen/src/descriptors.rs`, `precompiles/codegen/src/templates/curve.masm.tpl`, curve tests. Target latest prover semantics: value tags carry `GROUP_PTR`; MSM tag is generic zero-immediate.
- Agent D should wait until B/C land, then adjust `precompiles/codegen/src/masm.rs` and metadata iteration.

Because B/C/D all touch `precompiles/codegen/src/descriptors.rs`, do not run them as edit agents at the same time unless their patches are carefully sequenced or pre-split.

### Wave 3: prover rebase agent

Starts after lower branch validation. This agent may edit the prover branch during conflict resolution, but should not change lower semantic APIs except to resolve rebase conflicts by keeping the lower branch version.

## Wave 1 reports

### Agent A: deferred byte chunk helper

Findings:

- `Node::PACKED_BYTES_PER_CHUNK` and `Node::chunks_from_bytes` do not exist on current `precompiles/crate`.
- Duplicate test helper logic exists in `precompiles/src/hash/mod.rs` as `pack_chunks(bytes)`.
- `precompiles/src/codec.rs` hardcodes `BYTES_PER_CHUNK = 32`.

Implementation notes:

- Add `bytes_to_packed_u32_elements` import in `core/src/deferred/node.rs`.
- Add public `Node::PACKED_BYTES_PER_CHUNK` and `Node::chunks_from_bytes(bytes)`.
- Make `precompiles/src/codec.rs::BYTES_PER_CHUNK` derive from `Node::PACKED_BYTES_PER_CHUNK as u32`.
- Replace hash test helper with a wrapper around `Node::chunks_from_bytes`; do not change production hash evaluator in this slice.

Tests:

- `cargo test -p miden-core --lib chunks_from_bytes_packs_little_endian_u32s_and_zero_pads`
- `cargo test -p miden-precompiles --lib hash::keccak256::tests::suite`
- broader: `cargo test -p miden-core --lib deferred::node`, `cargo check -p miden-core -p miden-precompiles`

Status: independent first commit.

### Agent B: uint fixed bound pointers

Findings:

- Current uint `VALUE` tags use local domain IDs: `[UINT_PRECOMPILE_ID, VALUE_OP_ID, DOMAIN_ID, 0]`.
- `UintOp::decode` uses `UintDomain::from_id(args[1])` for `VALUE` and requires zero immediates for binary ops.
- `UintFieldInvHandler` also resolves domains via `from_id` and must be updated.

Implementation notes:

- Add `*_BOUND_PTR` constants in `precompiles/codegen/src/descriptors.rs`.
- Add `UintDomain::bound_ptr()` and `UintDomain::from_bound_ptr()`.
- Change `UintPrecompileDescriptor::value_tag(domain)` to use `Felt::from(domain.bound_ptr())`.
- Change uint decode and field-inv handler to resolve from bound pointer, rejecting oversized felts.
- Re-export bound pointer constants through `precompiles/src/math/uint/domain.rs`, `precompiles/src/math/uint/mod.rs`, and `precompiles/src/lib.rs` if matching source API surface is desired.
- In `precompiles/codegen/src/masm.rs`, replace `MODULUS_ID` template value with `BOUND_PTR`.
- In `precompiles/codegen/src/templates/uint.masm.tpl`, document `VALUE_TAG = [PRECOMPILE_ID, VALUE, BOUND_PTR, 0]` and op tags as zero-immediate.

Tests:

- descriptor test: `UintDomain::ALL` maps to pointers `1..=7`; reject `0` and `8`.
- uint precompile decode test: exact value/op tag words; reject unknown bound ptr, nonzero reserved slot, op tags with bound ptr, oversized ptr.
- run uint/field integration tests; curve integration is also recommended because coordinate/scalar digests change.

Status: can land before curve changes.

### Agent C: curve value group pointers and MSM semantics

Findings:

- Current lower branch uses curve IDs in both value and counted MSM tags:
  - `VALUE = [CURVE_PRECOMPILE_ID, VALUE_OP_ID, CURVE_ID, 0]`
  - `MSM = [CURVE_PRECOMPILE_ID, MSM_OP_ID, CURVE_ID, pair_count]`
- Current lower branch MSM pair order is `(scalar_digest, point_digest)`.
- Current prover branch tip supersedes earlier group-pointer MSM shape:
  - final value tag carries `GROUP_PTR`;
  - final MSM tag is generic zero-immediate `[CURVE_PRECOMPILE_ID, MSM_OP_ID, 0, 0]`;
  - MSM pairs are `(point_digest, scalar_digest)`;
  - MSM evaluation infers/validates the curve from point values.

Implementation notes:

- Add `K1_GROUP_PTR`, `R1_GROUP_PTR`, `ED25519_SW_GROUP_PTR`.
- Add `CodegenCurveId::{group_ptr, from_group_ptr}` and `CurveId::{group_ptr, from_group_ptr}`.
- Change curve `VALUE` decode to parse `args[1]` via `from_group_ptr` and require `args[2] == ZERO`.
- Change `CurvePrecompileDescriptor::msm_tag()` / `CurvePrecompile::msm_tag()` to take no curve/count and return the generic MSM op tag.
- Change `CurveOp::Msm` to carry no curve/count; parse pair-list payload directly.
- Change MSM evaluation and MASM template pair order to `(point_digest, scalar_digest)`.
- Update `curve.masm.tpl`: `VALUE_TAG` uses `GROUP_PTR`; `MSM_TAG` uses zero immediates; `msm_mem` still uses `n` for `register_mem`, but not in the tag.
- Preserve `msm2_generator` external caller contract if possible; internally reorder to pair-list order.

Tests:

- exact value tag word per curve;
- exact generic MSM tag word;
- reject value unknown group ptr / nonzero reserved slot;
- reject MSM with nonzero args, including old counted/group-pointer shapes;
- update all MSM unit tests to `(point, scalar)` order;
- add old-pair-order rejection if practical;
- run curve and ECDSA integration tests.

Status: depends on Commit B only indirectly through changed coordinate/scalar uint digests; implement after uint for easier validation.

### Agent D: metadata/codegen enum derivation

Findings:

- `UintDomain::ALL` already exists.
- `CodegenCurveId::ALL` does not exist.
- `precompiles/codegen/src/masm.rs` still has manual config constants/lists for U256, fields, and curves.

Implementation notes:

- Add `CodegenCurveId::ALL = [Secp256k1, Secp256r1, Ed25519Sw]`.
- Add `UintMasmConfig::new(domain)` and `CurveMasmConfig::new(curve)` if this keeps code readable.
- Generate configs from `UintDomain::ALL` and `CodegenCurveId::ALL`, preserving current paths:
  - `asm/math/u256.masm`
  - `asm/math/field/*.masm`
  - `asm/math/curve/ed25519_sw.masm`
- `CurveId::a_value()` / `b_value()` are not needed for MASM config derivation alone, but may be useful for prover fixed metadata. If added, implement all three via short-Weierstrass `A`/`B`, including `Ed25519Sw`.

Tests:

- `cargo test -p miden-precompiles-codegen`
- if adding curve value accessors: `cargo test -p miden-precompiles --lib fixed_curve_ids_and_generators_validate` and `cargo check -p miden-precompiles --no-default-features`

Status: best after uint/curve tag commits to avoid descriptor/masm conflicts.

### Agent E: prover rebase/comparison

Findings:

- Current source branch is linear and 19 commits ahead of `precompiles/crate`, ending at `b9dc3e587`.
- The branch includes additional commits beyond the earlier review set, especially:
  - `9911583ee Align MSM transcript hashing with VM PairList`
  - `ca9da7fad Remove group pointer from curve MSM tag`
  - `b9dc3e587 Add deferred state session lowering`
- Use `--empty=ask` on the first interactive rebase so commits that become empty are reviewed deliberately.

Recommended scratch setup when clean:

```bash
git branch backup/precompiles-crate-before-foundation-port precompiles/crate
git branch backup/precompiles-prover-before-foundation-port precompiles/vm-precompiles-prover
git branch scratch/precompiles-crate-foundation-port backup/precompiles-crate-before-foundation-port
git branch scratch/precompiles-prover-on-foundations backup/precompiles-prover-before-foundation-port
git config rerere.enabled true
```

Recommended rebase:

```bash
git rebase -i --empty=ask --onto scratch/precompiles-crate-foundation-port \
  backup/precompiles-crate-before-foundation-port \
  scratch/precompiles-prover-on-foundations
```

Likely edit/conflict commits:

- `b9da996a6` uint bound pointer lower hunks;
- `1487b7c55` lower descriptor test and processor trace helper;
- `781bc67d0`, `16c5a7d01`, `9911583ee`, `ca9da7fad` curve/MSM semantics;
- `cd4787843` deferred chunks;
- `98bf4b4e8`, `8fe3ca19e`, `b9dc3e587` fixed metadata/session-lowering lower helpers.

Conflict policy:

- lower semantic APIs come from `scratch/precompiles-crate-foundation-port`;
- prover branch adapts to them and keeps `precompiles-prover/**` payload;
- drop `processor/src/trace/mod.rs` unless a concrete current use appears;
- resolve the curve MSM policy consciously: default now is current prover tip generic MSM tag.

Comparison commands:

```bash
git --no-pager range-diff \
  backup/precompiles-crate-before-foundation-port..backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-crate-foundation-port..scratch/precompiles-prover-on-foundations

git --no-pager diff --stat \
  backup/precompiles-prover-before-foundation-port \
  scratch/precompiles-prover-on-foundations

git --no-pager diff --name-status \
  scratch/precompiles-crate-foundation-port \
  scratch/precompiles-prover-on-foundations \
  -- core/src precompiles/src precompiles/codegen/src precompiles/tests crates/lib/core/tests processor/src
```

Acceptance criteria:

- meaningful prover commits preserved, rewritten, or intentionally dropped;
- final prover diff relative to new lower base dominated by `precompiles-prover/**`, `Cargo.toml`, `Cargo.lock`;
- no stray lower semantic hunks in prover diff unless explicitly approved;
- final branch consumes lower canonical APIs rather than duplicating them.

## Current implementation status

Status: lower-branch foundation port implemented in the current `precompiles/crate` worktree. No commits have been created yet.

Implemented lower-crate changes:

- `core/src/deferred/node.rs`
  - added canonical packed-byte chunk helper: `Node::PACKED_BYTES_PER_CHUNK` and `Node::chunks_from_bytes`;
  - strengthened chunk packing tests for empty, partial, and multi-chunk inputs.
- `precompiles/src/codec.rs` and `precompiles/src/hash/mod.rs`
  - derive chunk sizing from `Node::PACKED_BYTES_PER_CHUNK`;
  - added exact chunk-to-byte decoding helper;
  - added `HashAssertNode`, `HashPrecompile::decode_assert_tag`, and `HashPrecompile::decode_assert_node` for session/lowering consumers;
  - added structural decoder tests to the shared hash test harness.
- `precompiles/codegen/src/descriptors.rs` and uint precompile files
  - added fixed uint bound pointer constants `1..=7`;
  - switched uint `VALUE` tags to `[UINT_PRECOMPILE_ID, VALUE_OP_ID, BOUND_PTR, 0]`;
  - switched uint decoding and field inverse handling to `UintDomain::from_bound_ptr`;
  - removed obsolete uint domain-id metadata APIs after confirming they were unused and absent from the prover branch;
  - added `UintNodeRef` / `UintPrecompile::decode_node` and direct structural decoder tests.
- `precompiles/src/math/curve/*`, `precompiles/codegen/src/descriptors.rs`, and curve MASM template/codegen
  - added curve group/coefficient pointer metadata;
  - switched curve `VALUE` tags to `[CURVE_PRECOMPILE_ID, VALUE_OP_ID, GROUP_PTR, 0]`;
  - switched curve `MSM` to generic zero-immediate `[CURVE_PRECOMPILE_ID, MSM_OP_ID, 0, 0]`;
  - switched MSM pair-list order to `(point_digest, scalar_digest)` and infer/validate curve from point values;
  - added `CurveNodeRef` / `CurvePrecompile::decode_node` and coefficient metadata helpers;
  - preserved `Ed25519Sw` short-Weierstrass coefficient sourcing via `ShortWeierstrassSpec::{A, B}`.
- `precompiles/codegen/src/masm.rs`
  - derives generated uint/curve MASM configs from `UintDomain::ALL` and `CodegenCurveId::ALL`.
- `precompiles/tests/integration/ecdsa_secp256k1.rs`
  - updated the cycle baseline to `1_452`, matching the current prover branch and observed integration run.

Read-only review agents run during implementation:

- curve/MSM/codegen/MASM review: no blockers; confirmed final tag shapes, pair order, and Ed25519-SW coefficient model; flagged stale comments and coefficient test coverage, both addressed.
- uint/hash/chunk review: no blockers; confirmed bound-pointer and hash helper alignment; flagged stale uint metadata docs and structural decoder/chunk test coverage, addressed. The obsolete uint domain-id API was removed after the final prover comparison showed it was absent upstream.

Validation run on this worktree:

```bash
cargo fmt
cargo check -p miden-core -p miden-precompiles -p miden-precompiles-codegen
cargo test -p miden-precompiles-codegen
cargo test -p miden-precompiles --lib
cargo test -p miden-core --lib chunks_from_bytes_packs_little_endian_u32s_and_zero_pads
cargo test -p miden-precompiles --test integration
```

Notes:

- `cargo fmt` succeeds but prints existing stable-rustfmt warnings for nightly-only rustfmt options.
- The first ECDSA integration run failed only on the expected cycle baseline (`1452` observed vs old `1446`). The baseline was checked against `precompiles/vm-precompiles-prover`, updated to `1_452`, and the full integration suite passed afterward.

Comparison against `precompiles/vm-precompiles-prover` lower paths:

```bash
git --no-pager diff --stat precompiles/vm-precompiles-prover -- \
  core/src/deferred/node.rs \
  precompiles/src \
  precompiles/codegen/src \
  precompiles/tests/integration/ecdsa_secp256k1.rs
```

Remaining differences are intentional local refinements rather than missed semantic ports:

- additional structural decoder tests for hash and uint;
- stronger/clearer chunk and coefficient metadata tests;
- clearer MASM template comments for the final group-pointer/generic-MSM tag shapes;
- equivalent `try_from` style in uint field-inverse bound-pointer decoding;
- concrete curve implementation comments updated away from stale “carried in curve precompile tags” wording.
