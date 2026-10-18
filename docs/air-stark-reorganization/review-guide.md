# AIR cleanup: substantive review guide

This branch separates authored AIR, production artifacts, generic STARK machinery, ACE runtime
and the two relation products. `miden_vm::proofs` owns complete/deferred proof composition.
Source tooling renders the existing tracked MASM through typed Askama templates. Ordinary AIR
builds decode a packaged VM Rust evaluator into `OUT_DIR`, without running the AIR compiler.
Most equations, engine internals and trace builders are relocated rather than rewritten.

Circuit, relation and setup identities remain explicit protocol pins. PVM production evaluation
still delegates authored equations. Selected PVM support and shared MASM delivery are described
in the current [generation guide](../masm-verifier-generation.md).

## Compare the complete PR

Use the original PR base and the current checkout, including all follow-up cleanup commits:

```sh
BASE=d13cf936a1f4c4e79ab9571232a8b54de7170633
git log --oneline "$BASE"..HEAD
git -c diff.renameLimit=10000 diff --no-ext-diff --no-textconv --find-renames=50% --find-copies=50% --find-copies-harder --color=always --color-moved=dimmed-zebra --color-moved-ws=allow-indentation-change "$BASE" HEAD -- | less -R
```

Git's rename/copy detection is heuristic and one-to-one; moved-line coloring changes presentation,
not patch content. Review changed imports, features, manifests, templates and surrounding modules
alongside relocated bodies. Keep the complete raw diff as the authority; do not hide whitespace
or normalize source strings to infer equivalence.

The immutable source links below describe the earlier ownership and Rust-delivery implementation
at `fa0afea2716a0a36211fa6e36db5a987f2951210`. Read the current files and full comparison for subsequent
selected-PVM and shared-runtime changes. Historical branch names and validation records describe
past execution, not a checkout to restore. The temporary custom diff parser and snapshot copier
have been removed; Git provides the review view and committed source archives.

## Where the substantive changes are

### 1. Authored versus production AIR, and independent oracles

Previously [air/src/lib.rs][old-air] combined production dispatch, an `eval_handwritten` route
and `HandwrittenMidenAir`. Now [source VM dispatch:837–854][source-eval] always evaluates
authored equations. [Generated VM:24–144][production-vm] owns a distinct enum/conversions,
delegates fixed/periodic/degree metadata and **both cached and uncached auxiliary hooks**, and
dispatches the four staged optimized evaluators. Its [collection:173–221][production-collection]
delegates statement observation/reduction without aliasing the source collection. Public inputs
remain a single source-owned representation. The separate [PVM production type:95–156][production-pvm]
still delegates authored evaluation; this PR does not optimize PVM equations.

Review the routes together with [generated_drift.rs:31–135][drift] and its
[test-local interpreter:142–176][drift-interpreter]: canonical structure/global ordering,
different raw capture routes and four fixed-seed value comparisons are distinct controls.
The [instance-order check:206–208][instance-order] and
[borrowed auxiliary-route checks:18–64][aux-tests] cover delegation/order separately.
These tests preserve independent expectations; relocation of equations alone is not a semantic
change and should not be described as one.

### 2. ACE runtime delivery, processor adapter and explicit acceptance

[ACE exports/features][ace-exports] separate portable codec/layout/records from optional
DAG/capture/compiler functionality. The [canonical codec:90–203][ace-codec] validates shape,
reference order, exact envelope length and canonical field elements. MIDACE-v1 is an artifact
envelope, not a new proof format. Production [VM accessor][vm-artifacts] and
[PVM accessor][pvm-artifacts] decode packaged circuits and check deliberately accepted circuit
commitments; product advice consumes these instead of compiling authored AIR on access.

The processor's former [combined trace implementation][old-processor-trace] splits into
[portable records][ace-records] and a [context/clock/AIR-column adapter:17–131][processor-adapter].
Review error mapping, zero-output enforcement and legacy field/byte order at that boundary.
The new [artifact runtime tests:13–97][artifact-tests] compare all gates/records/fan-out against
a separate packed-instruction interpreter without importing source AIR/compiler APIs.
They test ACE, not Rust zlib decoding. Accepted ACE commitments do not cover external statement
assertions, so statement/layout/security oracles remain necessary.

[air-artifacts.rs:67–212][artifact-cli] requires explicit accepted JSON and checks **both**
circuit and relation identities/round trips before creating outputs. It delivers Rust/ACE plus
separate transport/source hashes; it never accepts new pins. Read the accepted-input policy
in [accepted.rs:20–78][accepted-inputs] alongside that control flow.

### 3. Dependencies, public APIs and proof composition

The [workspace dependencies][workspace-manifest] and owner manifests are substantive review
surfaces. Generic AIR/transcript/capture/config/security live under [STARK exports][stark-exports];
the canonical stateful hasher moves into crypto, eliminating reverse crypto→STARK forwarding.
Core [reexports p3_matrix directly][matrix-exports], preserving the upstream matrix identity.
Do not discard reexports, grouped imports, `pub(in ...)` ancestry changes or dependency edges.

Compare [VM features][vm-features], [PVM features][pvm-features] and [facade features][facade-features]:
native relation verification is available without processor/compiler tooling; VM recursive
support remains `no_std`, PVM recursive support implies `std`; PVM trace is independent of
proving. Products do not depend on each other. Facade defaults explicitly compose execution,
both provers and recursive support. [Source tooling][source-features] alone selects Askama,
capture/compiler and the compressor; [production build dependencies][generated-features]
select only host artifact decoding for ordinary builds. Review full Cargo/lock diffs separately
from relocated Rust paths.

Previously composite proving/verifying lived in [prover/src/prover.rs][old-prover] and
[verifier/src/lib.rs][old-verifier]. New [VM witness/trace APIs:37–47][vm-prover-api] return
`VmProof`, allowing authenticated outstanding work. [VerifiedVm:20–41][verified-vm] reports
security and the outstanding root, rather than asserting completion.
[Relation-only advice:81–95][vm-advice] works directly with `VmProof`; envelope compatibility
forwards to it. [Facade prover:88–181][facade-prover] and
[facade verifier:114–214][facade-verifier] retain complete/deferred coverage, error ordering,
budget and component-security policy; the facade's VM-only convenience still rejects pending
work. The [outstanding-obligation integration test:484–511][relation-test] exercises this distinction.
The [external PVM trace test:14–32][pvm-trace-test] covers release-visible trace/root lowering
without a prover. No new proof/root identity is introduced by these APIs.

### 4. Typed source-owned MASM rendering and protected delivery

The old [core-lib text-replacement renderer][old-renderer] and ACE assembly-string emitters
are replaced by source-owned plans and Askama templates. Read
[VM compile/render:158–235][vm-render] and [PVM compile/render:253–344][pvm-render] with
[typed inputs:16–140][render-input], [plan validation:47–134][render-validation],
[closed stack-movement vocabulary:59–171][sort-plan] and [template bindings/output map][templates].
Compilation retains layout/geometry; pure rendering performs no capture, filesystem access,
setup derivation or pin acceptance. Portable ACE plans do not depend on source or Askama.

[Combined delivery:18–46][combined-delivery] validates both relations before managed writes.
[VM protected full-body checks:687–738][vm-protected] and
[PVM protected checks:451–491][pvm-protected] protect wrappers/config/pins, including body drift
that leaves numeric constants unchanged. [Rejection tests:1236–1305][protected-tests] preserve
managed files, while [live shared-ABI checks:33–52][shared-abi] compare source assumptions with
actual authored STARK constants. These current checks supersede the **historical** gaps in the
original validation narrative. Filesystem write errors are reported; multi-file delivery is
not transactional.

All derived MASM remains tracked in its existing core-lib paths. Review the
[generation guide](../masm-verifier-generation.md) and actual template diff; generated output
being unchanged does not make the renderer rewrite mechanical. Final cleanup removes the
temporary migration harness; independent ACE sorting, numeric/security vectors and actual
MASM execution checks remain the ongoing oracles.

### 5. Exact VM Rust zlib / host build / package delivery

The first ownership commit relocated expanded Rust from `air/src/constraints/generated.rs`.
The newest slice replaces that expanded tracked file with a 48,176-byte package-local zlib.
[build.rs:5–29][build-script] reads the sole blob input, declares Cargo rerun tracking, checks
zlib/Adler integrity, limits expansion to 16 MiB, validates UTF-8 and wraps the exact text in
its former private module. [Production include:17][production-include] consumes the host's
`OUT_DIR` output. Cross compilation does not run target code or AIR capture.

[Source generation/compression:35–85][evaluator-delivery] still captures authored VM AIR,
emits the same evaluator and uses fixed level-9 compression with the pinned `miniz_oxide`
0.8.9. The [manifest:84–89][rust-manifest] distinguishes encoded transport from expanded Rust
source. Independent decoding matches the deleted parent evaluator: **255,008 bytes / 6,555
lines**, SHA-256 `ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
The compressed SHA-256 is `25ab1dcc012358242e825d9ea9aaa6b9390c56c21da970fa99d08da29ec6ee01`.
Review package inclusion of both **build.rs and the zlib blob**, host/target feature separation,
freshness wiring and error handling. No speedup is claimed.

Ordinary decoding checks codec integrity/size/UTF-8, not manifest SHA-256 or appended data after
the first valid zlib stream. Explicit generation/freshness checks enforce canonical whole-blob
identity. The current blob has no trailing data. This division and LR-01 below are material
review limits, not claims of stronger runtime authentication.

## Validation provenance and remaining work

Rust execution below is **previous implementation evidence**, preserved in
[validation.md](validation.md); PR preparation did not rerun Rust suites. The six bounded local
delivery reviews found no confirmed source regression and recorded LR-01. Their private
coordination notes are not part of this PR.

| Slice / evidence | Recorded checks |
| --- | --- |
| [Original reorganization integration](validation.md#final-coordinator-integration-evidence) | Rust 1.99 workspace check; source 339/generated 32, VM product 41/facade 14 tests; real VM/PVM native-MASM verification, lifecycle, relation-only obligations/advice, async/security compatibility; independent setup/freshness; six-package native/wasm/feature/unpacked matrix. These predate compressed Rust delivery. |
| Template and migration cleanup commits | Commit messages record source/template/protected-write and real MASM proof-order checks, freshness, lint and boundary checks. They are prior execution claims, not newly executed here or substitutes for current decoder tests. |
| [Newest Rust delivery](validation.md#rust-evaluator-delivery--2026-10-18) | **38 targeted tests**: drift/order/raw-route 4, ACE runtime 2, source generation/acceptance 27, core freshness/ABI 4, embedded roots 1. Native and wasm no-default AIR checks; canonical generation/freshness; actual packaged/unpacked native/wasm builds and packaged-source artifact check. |
| PR preparation | Verified all 20 entries against the reviewed snapshot before the implementation commit; independent exact zlib-to-parent byte equality; Python boundary check; historically exercised the now-removed diff aid on pinned commits; source-link and scoped-staging checks. No Rust compile/test/regeneration. |

Package compilation uses [prepare-unpacked.py](../../tools/air-stark/prepare-unpacked.py)'s
**explicit local patches for unpublished supporting packages** and a coherent unpacked family.
Archive creation used `--allow-dirty --no-verify --exclude-lockfile`; subsequent actual unpacked
compilation provides build evidence. This is not public-registry release verification.

**LR-01 — P3, nonblocking coverage follow-up:** the actual Rust materializer lacks focused
malformed/truncated/checksum/over-limit/invalid-UTF-8 rejection tests. Replacing bounded inflate
with unbounded inflate would leave current success-path tests green while removing the cap.
No decoder failure was observed. A future harness sharing the real decode/wrap helper, with
fixed rejection fixtures and a small injectable limit, should assert failure before output.
That test/refactor is not implemented in this PR. Cargo rerun-on-touch execution is also not
recorded; input-watch wiring and saved directives were inspected.

No exhaustive workspace test execution, every optional backend/platform, fuzz execution,
MSRV 1.96.1, Windows, public-registry or protocol-upgrade validation is claimed. The original
fresh-snapshot all-target check excluded the unchanged RocksDB SMT benchmark because Clang
headers were unavailable. Whole-workspace formatter success is not claimed; two untouched
baseline files differ from the used nightly formatter. See the evidence appendix for exact
commands, resolved environmental failures and scope.

### Draft publication checks

[Draft PR #4046](https://github.com/0xMiden/miden-vm/pull/4046) targets `next`. Its first CI pass
at `629098d9b717cf3e2441dd82046e42d3f95f4a33` found two facade README links to the retired
prover/verifier directories; the follow-up documentation commit updates those links to current
owners. Two other observed failures remain separate from the local validation above:

- [GitHub signature check](https://github.com/0xMiden/miden-vm/actions/runs/39110902450/job/117626642001):
  all six initial commits contain locally valid SSH signatures, but GitHub reports verification
  reason `no_user` and cannot associate their commit identities with an account. Original commits
  and identities are preserved; this needs account/identity reconciliation, not a claim that
  GitHub verification passed.
- [Fuzz workspace check](https://github.com/0xMiden/miden-vm/actions/runs/39110902929/job/117626643143):
  `tools/miden-core-fuzz` rejects `cargo check --locked` because its lockfile requires an update,
  before compilation. The earlier delivery run deliberately restored an incidental standalone
  fuzz-lock refresh; PR preparation does not silently fold that lock maintenance into this slice.

These are initial CI observations, not a final all-green CI report. Consult the PR checks for
the current run; no source fix, commit rewrite or expansion of the Rust validation matrix is
implied by the documentation preparation.

Before reproducing any Rust compilation, test or generation command, follow applicable
`AGENTS.md`: run `systemd-ac-power` first; proceed on exit 0, otherwise wait for explicit user
approval. Diff inspection requires no Rust execution.

[old-air]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/air/src/lib.rs#L656-L834
[old-processor-trace]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/processor/src/trace/chiplets/ace/trace.rs#L1-L180
[old-prover]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/prover/src/prover.rs#L1-L181
[old-verifier]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/verifier/src/lib.rs#L1-L200
[old-renderer]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/crates/lib/core/src/constraints_regen.rs#L535-L756
[source-eval]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/vm/mod.rs#L837-L854
[production-vm]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/vm/mod.rs#L24-L144
[production-collection]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/vm/mod.rs#L173-L221
[production-pvm]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/precompile.rs#L95-L156
[drift]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/tests/generated_drift.rs#L31-L135
[drift-interpreter]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/tests/generated_drift.rs#L142-L176
[instance-order]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/tests/generated_drift.rs#L206-L208
[aux-tests]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/tests/aux_trace.rs#L18-L64
[ace-exports]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/ace/src/lib.rs#L15-L85
[ace-codec]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/ace/src/encode.rs#L90-L203
[ace-records]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/ace/src/records.rs#L1-L150
[processor-old-records]: https://github.com/0xMiden/miden-vm/blob/c90abdb34e8f1b8f5d03efe0ac5bd11893543991/processor/src/trace/chiplets/ace/trace.rs#L253-L411
[ace-moved-records]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/ace/src/records.rs#L169-L327
[processor-adapter]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/processor/src/trace/chiplets/ace/trace.rs#L17-L131
[vm-artifacts]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/vm/artifacts.rs#L3-L17
[pvm-artifacts]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/precompile/artifacts.rs#L3-L21
[artifact-tests]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/tests/artifact_runtime.rs#L13-L97
[artifact-cli]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/bin/air-artifacts.rs#L67-L212
[accepted-inputs]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/accepted.rs#L20-L78
[workspace-manifest]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/Cargo.toml#L65-L143
[stark-exports]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/core/src/lib.rs#L71-L136
[matrix-exports]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/core/src/utils/mod.rs#L16
[vm-features]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/vm/Cargo.toml#L15-L33
[pvm-features]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/precompile/Cargo.toml#L15-L37
[facade-features]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/miden-vm/Cargo.toml#L51-L81
[source-features]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/Cargo.toml#L25-L49
[generated-features]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/Cargo.toml#L20-L42
[vm-prover-api]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/vm/src/prover.rs#L37-L47
[vm-prover-body]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/vm/src/prover.rs#L48-L146
[verified-vm]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/vm/src/verifier.rs#L20-L41
[vm-advice]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/vm/src/recursive/mod.rs#L81-L95
[facade-prover]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/miden-vm/src/proofs/prover.rs#L88-L181
[facade-verifier]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/miden-vm/src/proofs/verifier.rs#L114-L214
[facade-verifier-tests]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/miden-vm/src/proofs/verifier.rs#L397-L590
[relation-test]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/miden-vm/tests/integration/prove_verify.rs#L484-L511
[pvm-trace-test]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/stark/precompile/tests/trace.rs#L14-L32
[vm-render]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/constraints.rs#L158-L235
[pvm-render]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/precompile.rs#L253-L344
[render-input]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/masm_renderer/input.rs#L16-L140
[render-validation]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/masm_renderer/mod.rs#L47-L134
[sort-plan]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/masm_renderer/proof_order.rs#L59-L171
[templates]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/masm_renderer/templates.rs#L13-L136
[combined-delivery]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/mod.rs#L18-L46
[vm-protected]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/constraints.rs#L687-L738
[pvm-protected]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/precompile.rs#L451-L491
[protected-tests]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/constraints.rs#L1236-L1305
[shared-abi]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/lib/core/tests/stark/ace_circuit.rs#L33-L52
[build-script]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/build.rs#L5-L29
[production-include]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/src/vm/mod.rs#L17
[evaluator-delivery]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/source/src/codegen/evaluator.rs#L35-L85
[rust-manifest]: https://github.com/adr1anh/miden-vm/blob/fa0afea2716a0a36211fa6e36db5a987f2951210/crates/air/generated/artifacts/manifest.json#L84-L89
