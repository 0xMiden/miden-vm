# Implementation validation evidence

The [final replay guide](../air-stark-reorganization.md) defines the final architecture, APIs and commands. This appendix preserves observed execution evidence and material failures. Earlier agent reports reflect interfaces/toolchains at execution time; they are historical evidence, not instructions to restore superseded APIs. In particular, final artifact commands require explicit `--accepted-pins`, and incomplete public pin-acceptance APIs were removed. Temporary paths are reproducible scratch locations, not required private inputs.

## Compiler/render simplification — 2026-10-18

Parent: `ab6e1b073e9ef8698ccbf8d6ddbcf14c069edd58`, branch
`adr1anh/air-codegen-cleanup`. The coordinator inserted this separate authorized commit after
reviewed PVM glue and before selectable variants. It completes the internal error-plumbing
cleanup left by the preceding ACE stage.

VM/PVM `compile`, `compile_and_render`, `render` and source-owned fixed-setup/geometry helpers
return values directly. READ/DEEP/OOD/proof-order planning, scatter construction and Askama
rendering also return direct values, retaining bounds/alignment/occupancy checks as release
assertions and checked arithmetic. The compiler-only reference DAG evaluator likewise returns a
value and asserts bad authored input; its independent algorithm/selected-root semantics remain.
The unused compiler `InvalidInputLength` variant and `RenderError` enum are removed. Error
translation through internal `io::Error`/String and Result propagation is gone. Static packaged
Rust templates are included directly; source adapters move rendered bodies rather than cloning
them. DEEP builds its known four groups directly as an array.

External `EncodedCircuit` decoding/construction/shape validation, guest `EvaluationTrace::do_eval`,
proof/advice validation and CLI filesystem/staleness/accepted-pin/protected-body checks retain
fallible contracts. Both compile/render stages complete before delivery. Existing malformed,
misaligned, overlap, overflow, occupancy and reservation tests now catch/assert panics. A new
compiler-panic-before-write test checks all fifteen managed files remain unchanged; the separate
external rejected-delivery test still exercises accepted JSON and both protected-body failures.

All Rust commands passed their own fresh `systemd-ac-power` gate (exit 0), using Rust 1.99.0
and the cache/debug environment in the replay guide. Logs use
`/tmp/miden-evaluator-delivery-compiler-render-*.log`. Normal replay commands:

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-ace -p miden-air-source -p miden-air -p miden-precompile-stark --features miden-ace/compiler,miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-air-source --features tooling --release --lib --offline --locked codegen
systemd-ac-power && cargo +1.99.0 test -p miden-ace --features compiler --release --lib --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-ace --no-default-features --lib --offline --locked
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 test -p miden-processor --lib --offline --locked trace::chiplets::ace
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib --offline --locked proof_compatibility_roots_match_the_embedded_core_library
for filter in crypto::circuit_evaluation stark::ace_read_check stark::proof_order_maps stark::pvm_wrapper; do
  systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked "$filter" || exit 1
done
for test in stark::stark_verifier_e2f4_small stark::pvm_verifier::pvm_keccak_only_recursive_verifier_cost_is_bounded; do
  systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked "$test" -- --exact || exit 1
done
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --target wasm32-unknown-unknown --no-default-features --offline --locked
```

The final combined suite passed: ACE 67, source 344, generated AIR 41, PVM unit 18 and
historical proofs 4. Existing independent capture/global-order/value/different-route/raw-lowering/
shape/degree/scatter oracles remain. Release codegen tests passed 30; release ACE tests passed
67. ACE no-default unit tests passed 19 after the review-requested test-local std import fix.
Generation and explicit accepted-input artifact checks passed, including independent fresh setup
for all six VM configurations and PVM. No output regeneration was needed.

Processor ACE tests passed 7; actual VM/PVM roots 1; native/MASM circuit evaluation 2; READ
layout 1; generic/VM/PVM proof-order tests 7; full PVM wrapper height/stack/freshness tests 6;
VM and full-relation PVM end-to-end proofs 1 each. The PVM test uses a Keccak-only workload
but still proves the full legacy relation. Native/wasm no-default checks passed for ACE, STARK,
source/generated AIR, both products and facade. Independent coordinator review found no lost
numeric/order checks and confirmed compiler-before-write and external boundary behavior.

Six offline archives and unpacked native/wasm no-default consumption passed for ACE,
generated AIR and both products; unpacked ACE `testing` (including compiler/reference helpers)
also passed. Packaged source tooling independently checked packaged ACE/tables/blob/full manifest
against explicit packaged accepted JSON. All 518 archived source/assets inspected match checkout
bytes; the generated AIR archive was refreshed after a final test-only unused-value warning fix.
The final focused `ace_codegen` suite passed all 8 tests. Replay package consumption with:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives /tmp/air-stark-target/package --output /tmp/air-compiler-render-unpacked
for package in miden-ace miden-air miden-vm-stark miden-precompile-stark; do
  (cd "/tmp/air-compiler-render-unpacked/$package-1.0.0" &&
    systemd-ac-power && cargo +1.99.0 check --no-default-features --offline &&
    systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline) || exit 1
done
(cd /tmp/air-compiler-render-unpacked/miden-ace-1.0.0 &&
  systemd-ac-power && cargo +1.99.0 check --no-default-features --features testing --offline)
(cd /tmp/air-compiler-render-unpacked/miden-air-source-1.0.0 &&
  systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins ../miden-air-1.0.0/protocol/accepted.json ../miden-air-1.0.0/artifacts)
```

The preparation helper patches unpublished support packages explicitly; public-registry publication
is not claimed. Boundary checks pass for six targets/39 packages and isolated native closures;
no dependency/feature or ordinary build compiler activation was added. Stable rustfmt and
`git diff --check` passed. Existing runtime dead-code, source Windows filename and unused local
patch warnings remain. Early mechanical-conversion compile errors were corrected before the
passing suites. The review-requested test-only std import and final unused-value warning are fixed.
No full-workspace/all-feature/Windows or release-profile product proof suite was run. No required
validation gate remained blocked.

Independent parent comparison found all 43 protected paths byte-identical: all source templates,
tracked VM/PVM MASM, both ACE streams, exact-source evaluator blob, degree/metadata tables,
full manifest, accepted JSON/setup/config pins and core proof roots. Exact decompressed evaluator
source stays 255,008 bytes, SHA-256
`ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
No generated-output refresh or pin acceptance was needed. Source equations, ordering, field and
full relation/ACE/setup identities, legacy proof encoding and acceptance are preserved.

## Typed PVM verifier glue — 2026-10-18

Parent: `75da372f7bc54bcb06b23452f8099e7b2a3bff3f`, branch
`adr1anh/air-codegen-cleanup`. This stage adds typed PVM height/boundary/statement/fixed-message
plans and two packaged Askama templates. It keeps the full twelve-AIR relation and the VM's
custom claim observation. Authored glue invariant failures panic with release assertions;
existing renderer, delivery, I/O and accepted-pin Result APIs remain.

Each Rust command passed its own fresh `systemd-ac-power` gate (exit 0). The replay guide's
Rust 1.99.0/cache environment applies, with incremental and DEV/TEST/TEST_DEV debug output off.
Logs use `/tmp/miden-evaluator-delivery-pvm-glue-*.log`. Normal replay commands:

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-air-source -p miden-air -p miden-precompile-stark --features miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-air-source --features tooling --release --lib --offline --locked codegen::masm_renderer::tests::pvm_glue
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::pvm_
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib --offline --locked proof_compatibility_roots_match_the_embedded_core_library
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --target wasm32-unknown-unknown --offline --locked
```

The combined source/artifact suite passed: source 343, generated AIR 41, PVM unit 18 and
historical proof 4 tests. The two new plan tests also passed in release mode. They check legacy
height/push schedules and exact transcript counts, and reject changed statement shapes, boundary
slots/counts and gamma-kernel width. Delivery rejection now checks all fifteen managed outputs,
including both new hooks. Full-module freshness remains separate from independent numerical,
structural/order, raw lowering, symbolic shape/degree and native/MASM oracles.

All 24 core-lib PVM tests passed (309.16 seconds): independent Rust challenger and fixed uint/curve
boundary oracles; transcript framing rejection; one-value boundary scatter under ties and
nonidentity orders; both OOD frames and DEEP queries; per-AIR minimum/maximum, fixed BytePairLut,
non-u32 and caller-stack behavior; complete hook/wrapper source freshness; Keccak, SHA256,
SHA512/mixed and all-precompile proofs; tampering and distinct-order VM/PVM interleaving; mixed
signatures and batch settlement, including wrong/reordered/missing response rejection. Existing
independent expected-value routes were not changed.

The actual VM/PVM root test passed unchanged. Native and wasm32 no-default checks passed for
all seven listed packages. `air-codegen --check --derive-setup` passed, independently deriving all
six VM setups and PVM setup; explicit-input `air-artifacts --check` passed. The VM recursive smoke
check also passed:

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::stark_verifier_e2f4_small -- --exact
```

Six offline archives were created with the normal command:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives /tmp/air-stark-target/package --output /tmp/air-pvm-glue-unpacked
```

The source archive contains 217 files, including all eleven verifier templates and the new typed
plan module. All 213 packaged `src/` and `templates/` files match checkout bytes. Local unpublished
support is patched explicitly by the maintained unpacking helper; public-registry publication is
not claimed. From the unpacked source root, replay:

```sh
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --no-default-features --target wasm32-unknown-unknown --offline
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-codegen --offline -- /path/to/miden-vm --check
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins /tmp/air-pvm-glue-unpacked/miden-air-1.0.0/protocol/accepted.json /tmp/air-pvm-glue-unpacked/miden-air-1.0.0/artifacts
```

All four unpacked-source commands passed: native/wasm no-default compilation, packaged
renderer/template freshness against the checkout, and packaged source generation against the
unpacked generated artifact bundle and its explicit accepted JSON. No production generated
metadata table is an input to those source derivations.

The initial template compile caught reference comparisons in Askama loop conditions; explicit
dereferencing fixed them before the passing suite. One unpacked check accidentally started from
the workspace root and was stopped (no workspace-wide pass claimed). An unpacked `--locked`
attempt rejected the helper's copied baseline lock; normal offline package resolution updates
only the temporary lock, as in earlier package checks. Checkout Cargo manifests/lock are unchanged.
Existing ACE dead-code, source Windows filename, unused local-patch and stable-rustfmt option
warnings remain. No full-workspace/all-feature/Windows testing is claimed.

Parent comparison covers 41 identity/projection files: 38 byte-identical, including accepted
pins, setup constants, ACE streams, evaluator blob, degree/metadata tables, manifest, core proof
roots and every tracked MASM module except the two new generated hook projections. The remaining
three changed files are the source wrapper template and those hooks. The protected tracked PVM
wrapper is byte-identical. Ignoring comments/whitespace and normalizing hex/decimal literals,
all 695 auxiliary-hook and 130 public-hook tokens match the parent. Root checks independently
confirm assembly identity. Equations, field identity, full relation/ACE/setup identities,
proof encoding and acceptance are unchanged. Temporary evidence is in
`/tmp/air-pvm-glue-{identities,instructions}.json`.

## ACE compiler simplification — 2026-10-18

Parent: `cb1c2d83a840e7411de028816651cf7e9dda299e`, branch
`adr1anh/air-codegen-cleanup`. This adapts only #3842's two intended commits against
`98ac6535a67afb67bbe01058518a82eefeb8a47c`. Code-owned DAG construction, emission,
selected-root evaluation and encoding return values directly; invariant violations panic.
Packing checks quadratic-extension degree, alignment, overflow and the strict node-id bound
before allocation. The compiler-only `CompiledCircuit` retains encoding, originating layout and
cached commitment through immutable accessors. Consuming runtime conversion moves the existing
instruction buffer, as the previous encoded conversion already did. The one-use quotient
interpreter and redundant geometry constructor/validation pass were removed with builder order
unchanged. Source rendering-plan/IO/accepted-input validation keeps its Result contracts;
canonical external decoding/construction and guest execution remain fallible.

Every Rust command below uses a fresh successful `systemd-ac-power` gate, Rust 1.99.0 and the
cache/debug environment in the replay guide. Logs use
`/tmp/miden-evaluator-delivery-ace-simplification-*.log`. Replayable commands:

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-ace -p miden-air-source -p miden-air -p miden-precompile-stark --features miden-ace/compiler,miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 test -p miden-processor --lib --offline --locked trace::chiplets::ace
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib --offline --locked proof_compatibility_roots_match_the_embedded_core_library
for filter in crypto::circuit_evaluation stark::ace_read_check; do
  systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked "$filter" || exit 1
done
for test in stark::stark_verifier_e2f4_small stark::pvm_verifier::pvm_keccak_only_recursive_verifier_cost_is_bounded; do
  systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked "$test" -- --exact || exit 1
done
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --target wasm32-unknown-unknown --no-default-features --offline --locked
```

The combined suite passed: ACE 67, source 341, generated AIR 41, PVM unit 18 and historical
proof 4 tests. Existing independent constraint capture/global-order, separately captured values,
different-route evaluation, raw ACE/lowering, degree/metadata/formula and structured-order
oracles remain. New checks cover checked packing overflow before allocation, nonquadratic
encoding rejection and the artifact's layout/commitment/buffer ownership. The existing
non-final-root test now expects a panic; selected-root evaluation still returns an earlier root
even with later operations. Thus it remains independent of runtime padding, which squares the
root and preserves zero-ness rather than arbitrary values.

Fresh `air-codegen --check --derive-setup` reproduced all six VM setup configurations and PVM;
`air-artifacts --check` verified both canonical streams, all tables, exact-source blob and full
manifest against explicit accepted JSON. Processor ACE 7, core-lib actual-root 1, MASM circuit
evaluation 2, READ-layout 1 and VM/PVM end-to-end 1 each passed. The PVM test still proves the
full legacy relation; its Keccak-only workload name does not imply selectable variants.
Native and wasm no-default checks passed for ACE, STARK, source/generated AIR, both products
and the composed facade. Boundary checks confirm ordinary dependency closures exclude
compiler/capture/tooling.

Six offline archives and actual unpacked consumption passed:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives /tmp/air-stark-target/package --output /tmp/air-ace-simplification-unpacked
for package in miden-ace miden-air miden-vm-stark miden-precompile-stark; do
  (cd "/tmp/air-ace-simplification-unpacked/$package-1.0.0" &&
    systemd-ac-power && cargo +1.99.0 check --no-default-features --offline &&
    systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline) || exit 1
done
(cd /tmp/air-ace-simplification-unpacked/miden-ace-1.0.0 &&
  systemd-ac-power && cargo +1.99.0 check --no-default-features --features compiler --offline)
(cd /tmp/air-ace-simplification-unpacked/miden-air-source-1.0.0 &&
  systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins ../miden-air-1.0.0/protocol/accepted.json ../miden-air-1.0.0/artifacts)
```

All 516 archived source/assets inspected match checkout bytes, including the new compiler
artifact module. The helper patches unpublished support dependencies explicitly; public-registry
publication is not claimed. Packaged source tooling independently checked packaged artifacts and
accepted input. Existing runtime dead-code, source Windows filename and unused local-patch
warnings remain. Stable rustfmt formatted owned Rust; repository nightly-only option warnings
remain. `tools/air-stark/check-boundaries.py` and `git diff --check` passed. No new feature,
dependency, ordinary build compiler activation or source/product cycle was introduced.

Release-profile ACE tests also passed (67 tests), with compiler invariant assertions and checked
arithmetic active when debug assertions and overflow checks are disabled. The VM product's
no-std recursive advice path additionally passed native and wasm compilation:

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-ace --features compiler --release --lib --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-vm-stark --no-default-features --features recursive --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-vm-stark --no-default-features --features recursive --target wasm32-unknown-unknown --offline --locked
```

No full-workspace/all-feature/Windows suite or release-profile product proof suite was run.
No required validation gate remained blocked.

Independent comparison with the parent covered 41 protected paths. Thirty-nine are byte-identical,
including both ACE streams, evaluator blob, degree/metadata tables, full manifest, all tracked
VM/PVM MASM, accepted JSON/setup pins and core proof roots. The other two are generated
`config.rs` and its source template: an exact comparison after the single compiler-test callsite
replacement proves all pin values and other text unchanged. Exact evaluator source remains
255,008 bytes, SHA-256 `ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
No generated stream/table/MASM refresh or pin acceptance was necessary.

## Derived AIR metadata — 2026-10-18

Parent: `6d5dbfecfecd8f2c8b72c107aae4c08f4ab1905a`, branch
`adr1anh/air-codegen-cleanup`. New canonical per-AIR tables carry raw widths, assertion counts
and lookup facts; degrees reuse the preceding stage's table. Production width accessors and
canonical security wrappers consume these facts through const slice geometry. Source keeps
independent symbolic/counting oracles, lower shape-parameterized security helpers and memory
models. Its redundant VM degree override and override test were removed. Newly derived numeric
shape/alignment/coefficient snapshots were replaced by independent schema/symbolic/formula checks;
authored design tests, memory/overflow regressions and fixed-point/rounding references remain.
SHA256 components are checked against the authored PCS blowup budget, independently of the
aggregate relation maximum. No optional PVM relation or new circuit/layout table is introduced.

All Rust compilation/test/generation/package commands passed a fresh `systemd-ac-power` gate
(exit 0), with Rust 1.99.0 and the cache/debug environment in the replay guide. Execution logs
use `/tmp/miden-evaluator-delivery-derived-metadata-*.log`; these ordinary commands replay the
checks without the private logging wrapper:

```sh
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --write
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --write --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 test -p miden-air-source -p miden-air --features miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --test protocol_history --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::security
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::stark_verifier_e2f4_small -- --exact
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::pvm_verifier::pvm_keccak_only_recursive_verifier_cost_is_bounded -- --exact
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --target wasm32-unknown-unknown --no-default-features --offline --locked
```

Results: final source suite 341 passed; production AIR 41 passed, including five new metadata
checks and all previous independent structural/global-order/value/different-route/raw-ACE/degree
oracles. New checks cover canonical and single/reordered slices, separate padding and extension
expansion at alignments 1/8/17, quotient/batching/DEEP formulas, actual security wrapper routing,
const use, freshness, empty/zero alignment and overflow/u32 narrowing rejection. The sixteen
core security tests include fixed-point boundary math and exhaustive native/MASM grids. Both
actual roots, VM/PVM native/MASM proofs, four historical/current PVM tests, no-default native
and wasm checks passed. Setup derivation independently reproduced all six VM configurations
and PVM. Final ordinary freshness was repeated after removing the source degree override and
formatting the new table output; degree/ACE/setup identities remained unchanged.

Six offline archives and actual unpacked consumption passed:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives /tmp/air-stark-target/package --output /tmp/air-derived-metadata-unpacked
for package in miden-air miden-vm-stark miden-precompile-stark; do
  (cd "/tmp/air-derived-metadata-unpacked/$package-1.0.0" &&
    systemd-ac-power && cargo +1.99.0 check --no-default-features --offline &&
    systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline) || exit 1
done
cd /tmp/air-derived-metadata-unpacked/miden-air-source-1.0.0
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins ../miden-air-1.0.0/protocol/accepted.json ../miden-air-1.0.0/artifacts
```

The preparation helper requires a fresh destination and explicitly patches unpublished support
packages; public-registry publication is not claimed. All 503 packaged source/build/readme/test/
template/artifact/pin files inspected match checkout bytes. Packaged source tooling independently
verified packaged tables, exact-source blob, ACE and manifest against packaged accepted JSON.
Existing ACE dead-code, Windows reserved-filename and unused local-patch warnings remain.

Independent Python comparison against the parent found all 37 protected files byte-identical:
old degree tables, ACE streams, evaluator blob, accepted JSON/Rust pins, core proof roots,
all tracked VM/PVM MASM and source templates. Every prior manifest value is unchanged; only
`air_metadata_tables` is added. Exact evaluator text remains 255,008 bytes, SHA-256
`ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
The VM/PVM metadata tables are 1,553/2,051 bytes, SHA-256 respectively
`83b0bf3da3a0af5ed8d1ae869685c7490a43ab9623a0f6904c702a295f548852` and
`81bd0e5f67a2c8eafd9ae24299c3601d6a79820ffc5e83a8773d4df3de8f5bee`.
`tools/air-stark/check-boundaries.py` and `git diff --check` passed. No new dependency or feature
was added; ordinary closures still exclude tooling/capture/compiler. Stable rustfmt formatted
owned Rust files, with the repository's existing nightly-option warnings. Initial development
builds exposed missing imports (`MAX_MESSAGE_WIDTH`, Eidos support and fixed math); those were
corrected before the passing final checks. Full-workspace/all-feature/Windows/release-profile
suites were not run. No required validation gate remained blocked.

## Degree tables — 2026-10-18

Parent: `a7405c5524244916df9c4295c4fc34d2ff3fac2d`, branch
`adr1anh/air-codegen-cleanup`. Production VM/PVM `constraint_degree()` now reads generated
identity-keyed base/extension tables through const `Air::degrees()`. Authored equations and
generic STARK analysis are unchanged. The source generator derives raw multiples from captured
constraints; independent expectations use a fresh authored symbolic pass. Tests also cover
generic VM fields, reversed PVM lookup order, const calls, selectors, periodic values, advisory
hints and empty assertion classes. Mathematical probe formulas remain explicit; canonical AIR
degree values are not duplicated as manually maintained test snapshots.

Every Rust command below passed a fresh `systemd-ac-power` gate (exit 0) and used Rust 1.99.0
with the cache/debug environment documented in the replay guide. Logs use prefix
`/tmp/miden-evaluator-delivery-degree-tables-`; replay uses the ordinary commands below.

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-air --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-air --test degree_tables --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-air-source --features tooling --lib --offline --locked codegen::constraints::tests
systemd-ac-power && cargo +1.99.0 test -p miden-air-source --features tooling --lib --offline --locked degree
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --write
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- "$PWD" --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --write --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --test protocol_history --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib proof_compatibility_roots_match_the_embedded_core_library --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::stark_verifier_e2f4_small -- --exact
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --target wasm32-unknown-unknown --no-default-features --offline --locked
```

Results: all 36 production AIR tests passed; the focused four degree tests passed again after
review removed redundant canonical numeric assertions. Ten source delivery tests passed,
including rejected-write preservation of all eleven managed outputs (both degree files now
included); twenty authored degree tests passed. All four PVM historical/current proof tests,
the actual VM/PVM root check, and the VM native-to-MASM end-to-end test passed. Fresh setup
derivation checks all six VM configurations and PVM. Initial new-test compilation exposed a
missing `WindowAccess` import and a missing generic boundary-value clone; both were fixed
before these passing runs.

Packaging and unpacked consumption also passed:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout "$PWD" --archives /tmp/air-stark-target/package --output /tmp/air-degree-tables-unpacked
cd /tmp/air-degree-tables-unpacked/miden-air-1.0.0
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline
cd ../miden-air-source-1.0.0
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins ../miden-air-1.0.0/protocol/accepted.json ../miden-air-1.0.0/artifacts
```

The helper requires a fresh output directory and explicit local patches for unpublished
supporting packages; this is offline package validation, not public-registry publication.
Packaged runtime/compiler source, templates, pins and artifacts matched checkout bytes. The
production package was refreshed after the final test-only review adjustment. Existing ACE
runtime dead-code warnings, unused local-patch warnings and source Windows reserved-filename
warnings remain. Full-workspace/all-feature/Windows tests and a fresh PVM MASM end-to-end run
were not performed in this stage.

Independent Python comparison found 35 protected files byte-identical to the parent: both ACE
streams, the Rust blob, accepted JSON/Rust pins, core proof roots, all tracked VM/PVM MASM and
all source templates. Decompressed evaluator text remains exactly 255,008 bytes with SHA-256
`ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
Every pre-existing manifest value is identical; only degree-table metadata was added.
VM/PVM degree files are 673/1,254 bytes, SHA-256 respectively
`9f8ea9220e8cceb7f59777dcba04d51d6eddc6b698521179111e6140f4ba8380` and
`1b351b769ee6a89e1d3b1eb916610384eff07897bdb89cb42bca0cd17c3ab6ed`.
`python3 tools/air-stark/check-boundaries.py` and `git diff --check` passed. Ordinary consumer
feature closures still exclude source tooling, STARK capture and the ACE compiler.

## Rust evaluator delivery — 2026-10-18

Parent: `6a9111888001d07aa8a861d20541c3ee80e140a3`, shared checkout
`/path/to/miden-vm`. The user authorized moving expanded Rust out of
Git while retaining checked-in MASM for the compiler team. No commit, branch change or
protocol-repository edit was made. All Rust compilation/test/generation commands below had a
fresh successful `systemd-ac-power` gate and used declared Rust 1.99.0 with the environment in
the next section. Temporary logs have prefix `/tmp/miden-evaluator-delivery-`.

The zlib artifact is 48,176 bytes. Python's independent zlib decoder and all inspected
materialized native/wasm/package outputs preserve the original 255,008-byte, 6,555-line Rust
source exactly, within the added module wrapper. Source SHA-256:
`ea2030b72b0683755d6669dc694150eb7ff6ca842b70afe6997603c4003b2850`.
Artifact SHA-256:
`25ab1dcc012358242e825d9ea9aaa6b9390c56c21da970fa99d08da29ec6ee01`.
Baseline fingerprints confirm every tracked MASM file, both ACE blobs and accepted JSON are
unchanged. The embedded compatibility-root test also passed.

Run these from the shared checkout, with the environment below and a fresh AC gate before
each Rust command:

| Command after `cargo +1.99.0` | Result |
| --- | --- |
| `run -p miden-air-source --features tooling --bin air-codegen --offline -- "$PWD" --write` | Passed; stages the compressed Rust and identical tracked MASM |
| `run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"` | Passed; Rust/ACE bundle and manifest delivered |
| `test -p miden-air --test generated_drift --test artifact_runtime --offline` | 4 independent drift/order/routing tests + 2 runtime ACE tests passed |
| `test -p miden-air-source --features tooling --lib --offline codegen::` | 27 generation/acceptance/protected-delivery tests passed |
| `test -p miden-core-lib --test core-lib --offline --locked stark::ace_circuit::` | 4 freshness/ABI/security tests passed |
| `test -p miden-core-lib --lib --offline --locked proof_compatibility_roots_match_the_embedded_core_library` | 1 root check passed |
| `check -p miden-air --no-default-features --offline --locked` | Passed |
| `check -p miden-air --target wasm32-unknown-unknown --no-default-features --offline --locked` | Passed; decoder executes on host |
| `run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts"` | Passed; all three blobs and manifest fresh |

`python3 tools/air-stark/check-boundaries.py` and the actual no-default normal/build Cargo tree
passed: no source tooling, STARK capture, ACE compiler or Askama in ordinary AIR builds;
`miniz_oxide/with-alloc` is a host build dependency. Changed Rust files pass formatter check
with the installed nightly rustfmt `bff8e12ff5` (2026-08-26); the separately pinned
`nightly-2026-10-09` whole-workspace formatter was not run. `git diff --check` passed.

Packaging used the existing six-package command from the original validation, with
`--allow-dirty --no-verify --exclude-lockfile --offline --locked`. Archive inspection confirms
the new build script, blob and manifest match the checkout and expanded `src/vm/generated.rs`
is absent. A fresh extraction was prepared with:

```sh
python3 tools/air-stark/prepare-unpacked.py \
  --checkout "$PWD" \
  --archives /tmp/air-stark-target/package \
  --output /tmp/miden-evaluator-delivery-packaged
```

The unpacked `miden-air-1.0.0` native `cargo +1.99.0 check --no-default-features --offline`
and `cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline`
both passed. The unpacked source's `air-artifacts --check` also passed against the unpacked accepted
JSON and artifact directory, with `--no-default-features --features tooling`. These checks use
the helper's explicit local patches for unpublished supporting packages; they do not claim
public-registry release verification. Package-local build inputs are actually compiled, not
merely inventoried. Existing ACE dead-code and reserved-Windows-name warnings remain.

Material environment failures: initial generator and core-test builds exhausted the temporary
quota. After confirming no compiler/build output was active, obsolete repository test/CLI
binaries and pre-change libraries for five large local packages were removed from the temporary
target cache. Current outputs, registry inputs and source were retained; both commands then
passed. A standalone fuzz lock refresh only removed three unrelated preexisting stale edges,
so that incidental change was restored; the codec is unselected by that workspace.

## Final coordinator integration evidence

All compilation, tests, generation and package compilation below were preceded by a fresh `systemd-ac-power` result of **0**. No battery override, sudo, push, publication or protocol-repository edit occurred. Final Rust commands used the declared 1.99.0 toolchain and this environment:

```sh
export RUSTUP_HOME=/tmp/air-stark-rustup
export CARGO_HOME=/tmp/air-stark-cargo
export CARGO_TARGET_DIR=/tmp/air-stark-target
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_TEST_DEV_DEBUG=0
```

The commands in the next table omit only the common leading `systemd-ac-power &&`. Exit status was 0 for every row. Durations are test execution times except where a check/build duration is specified. The log names identify captured evidence from this run; reproducing the commands is sufficient without those temporary logs.

| Command | Observed result / captured log |
| --- | --- |
| `cargo +1.99.0 check --workspace --offline` | Passed, 26.71s; `air-stark-workspace-check.log` |
| `cargo +1.99.0 test -p miden-vm-stark --lib --features prover --offline` | 41 passed, 105.76s; `air-stark-vm-product-tests.log` |
| `cargo +1.99.0 test -p miden-vm --lib --offline` | 14 passed, 3.69s; `air-stark-facade-tests.log` |
| `cargo +1.99.0 test -p miden-core-lib --lib --offline` | 5 passed, 0.13s, including actual assembled/declared roots; `air-stark-core-lib-tests.log` |
| `cargo +1.99.0 test -p miden-core-lib --test core-lib stark::stark_verifier_e2f4_small --offline` | Real VM native/MASM verification: 1 passed, 5.34s; `air-stark-native-masm-tests.log` |
| `cargo +1.99.0 test -p miden-core-lib --test core-lib stark::pvm_verifier::pvm_keccak_only_recursive_verifier_cost_is_bounded --offline` | Real PVM native/MASM verification and recursive trace bound: 1 passed, 4.30s; `air-stark-pvm-native-masm-tests.log` |
| `cargo +1.99.0 test -p miden-vm --test miden-cli prove_verify::prover_api_lifecycle --offline` | 4 passed, 143.32s; `air-stark-lifecycle-tests.log` |
| `cargo +1.99.0 test -p miden-vm --test miden-cli relation_vm_proof_and_advice_preserve_outstanding_obligations --offline` | 1 passed, 26.40s; `air-stark-independent-vm-tests.log` |
| `cargo +1.99.0 test -p miden-vm --test proofs_async_compat --test security_reexports --offline` | Async 2 passed, 49.44s; public security type 1 passed; `air-stark-async-security-tests.log` |
| `cargo +1.99.0 test -p miden-air-source -p miden-air --tests --features miden-air-source/tooling --offline` | Final source 339 passed, 1.91s; generated 32 passed across lib/ACE/runtime/aux/capture/drift suites; `air-stark-final-air-tests.log` |
| `cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline -- "$PWD" --check` | Final source/template/generated projections unchanged, build 4.96s; `air-stark-final-codegen-check.log` |
| `cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --accepted-pins "$PWD/crates/air/generated/protocol/accepted.json" "$PWD/crates/air/generated/artifacts" --check` | Final authored candidate, explicit accepted circuit/relation identities, streams and manifest agree; build 4.41s; `air-stark-final-artifacts-check.log` |

Earlier full source generation with `--check --derive-setup` also passed, independently deriving the six VM configurations and PVM Eidos setup without product caches. Final cheap checks were repeated after acceptance-API removal and formatting; those edits did not change setup equations or accepted values. Source tests increase from earlier 336 to final 339 because the combined source/generated run unifies additive arbitrary/testing serialization features.

The four original lifecycle tests cover facade VM-only proving with no work, rejection with pending work, deferred/complete/batched proofs, ordered repeated obligation roots, transport and per-component security policy, and buffered/overlapped proving. The new relation-only test constructs a VM proof with outstanding obligations, authenticates a nontrivial root equal to the witness root, and compares direct `for_vm_request` advice with envelope compatibility advice. Product verification does not claim that those obligations are discharged. The two async tests retain original async-only host-event and sync/async-equivalence controls.

Final generated test counts: library 9, ACE 8, independent artifact runtime 2, auxiliary trace 2, capture 7, drift 4. Runtime artifact tests import no source/compiler, compare all wire/value/id/multiplicity/output records against a separate packed-instruction interpreter for three deterministic inputs, and check accepted commitments and serialization. Structural/global-order/sampled-value/different-route and native/MASM oracles remain independently connected.

### Fresh workspace and package delivery

The historical snapshot helper (`git show 3effa09b6:tools/air-stark/snapshot-workspace.py`) copied 3,343 current tracked/unignored files into a Git-free snapshot. It includes uncommitted implementation, excludes private/control/target directories and rejects unsafe destinations/symlinks. From the original worktree, with the environment above and fresh AC gate:

```sh
systemd-ac-power && cargo +1.99.0 check --manifest-path /tmp/air-stark-clean-workspace-final/Cargo.toml --workspace --all-targets --exclude miden-crypto-smt-codspeed-bench --locked --offline
```

Passed, 50.73s; `/tmp/air-stark-clean-workspace-final-check.log`. This verifies all applicable workspace libraries/binaries/tests/benches in the snapshot, excluding exactly the unrelated optional RocksDB SMT benchmark described below. It does not execute every workspace test.

All six final target archives were regenerated together after source cleanup and formatting. Actual native/wasm no-default, host capture/compiler/tooling, product std/recursive, active feature-tree and packaged-source-to-packaged-artifact checks passed. The final coherent archive table and commands are retained in the delivery report below. `tools/air-stark/prepare-unpacked.py` is the checked reproducible preparation helper; the recipe does not depend on a private temporary script. The harness explicitly patches unpublished support packages locally and copies the root lock. It leaves shipped target manifests untouched and does not establish public-registry release verification.

### Preservation and non-Rust checks

- Python TOML comparison of root Cargo.lock registry entries against `git show HEAD:Cargo.lock`: no registry package additions/removals/version/checksum changes. Local package names/dependencies change with ownership. Standalone fuzz lockfiles were reconciled separately.
- `git diff HEAD -- core/src/proof.rs crates/lib/core/asm`: empty. Proof transport/declared roots and authored MASM bytes are unchanged; moved PVM historical fixture bytes and all numeric snapshot bodies remain unchanged. Main guide records accepted digests and artifact hashes. Full source setup derivation and actual assembled-root tests supply independent semantic checks.
- `python3 tools/air-stark/check-boundaries.py`: passed, six target packages, 39 workspace packages, acyclic ownership and modeled isolated verifier closures. Actual Cargo normal/build trees corroborate the model for products none/std/recursive and facade none/std: no processor/compiler/capture/tooling in native verifier use, no product peer dependency.
- `python3 -m unittest discover -s scripts/tests -v`: 11 passed; `bash -n scripts/bench_eidos_vs_poseidon2.sh`: passed. Makefile commands were dry-run reviewed; dry runs are not counted as compilation.
- `git diff --check`: passed after final documentation integration. Local Markdown links in the final guide/evidence resolve.

### Material integration failures and limits

These failures were repaired before final successful checks unless explicitly described as environmental limits:

1. Moved Rust lexical visibility paths and feature-gated test helpers initially failed compilation. Owners fixed actual lexical module ancestors and additive test imports, rather than masking them through reexports. Lower/source reports retain detailed evidence.
2. Product integration found missing VM engine/security imports, facade recursive reexport gating, and PVM `[u64; 4]` accepted-pin versus field-Word conversion. Imports/gates were corrected; pin conversion uses the same canonical accepted values. Current native/no-default/wasm/MASM tests pass.
3. The first snapshot/all-target check caught the moved async test's missing Tokio macro and debug-type dev features. Those dev requirements moved with the test. Final async execution and fresh snapshot check both pass.
4. Mixed debug/incremental builds exceeded temporary disk quota at about 11 GiB. All agents stopped before deleting only task-generated target output; subsequent builds used the recorded reduced-debug environment. No source/user cache/artifact was removed.
5. Initial unpacked product resolution collided between checkout processor's optional path dependencies and unpacked target package identities. The reviewed helper mirrors the optional processor support manifest and redirects target paths to one coherent archive set; final unpacked checks pass. This is harness setup, not a production dependency change.
6. Audit found incomplete public `accept_pins` helpers that could leave explicit accepted/template inputs stale. No callers existed; the coordinator removed the helpers and all boolean pin-writing branches. Final source CLI and package checks pass. Future pin acceptance requires a separately complete protocol/release workflow. Earlier source-report descriptions of these helpers are superseded.
7. Audit found stale Makefile artifact syntax; it now uses explicit `protocol/accepted.json` and `generated/artifacts`. Final CLI checks pass with that interface.
8. Broad all-target checking including unchanged `miden-crypto-smt-codspeed-bench` fails in `librocksdb-sys` bindgen because Clang/system headers (`stdbool.h`) are unavailable. The benchmark alone enables this dev backend. The final fresh snapshot matrix excludes exactly that package and passes; the excluded target remains unverified. No root installation or benchmark/source feature workaround was introduced.
9. Whole-workspace nightly formatter check reports only two untouched baseline files: `crates/assembly-syntax/src/ast/tests.rs` and `crates/crypto/benches/common/macros.rs`. Implementation formatting was applied; unrelated files were restored to HEAD. Formatter: rustfmt 1.10.0-nightly `bff8e12ff5` (2026-08-26). Whole-workspace fmt success is not claimed.

No exhaustive all-workspace test execution, all optional backends/platforms, fuzz execution, MSRV 1.96.1, Windows support or public-registry verification is claimed. No golden was removed and no protocol upgrade was performed.

## Post-validation read-only MASM generation coverage clarification

The subsequent design discussion did not change source or rerun Rust. Inspection of `constraints.rs`, `precompile.rs`, `air-codegen.rs`, Makefile and CI confirmed that CI already invokes source generation checks; most generated outputs are checked byte for byte. The final guide's follow-up section records two coverage gaps: full VM wrapper/config template bodies are not compared, and a copied STARK constants pointer/alignment input is not checked against live assembly. Those gaps do not negate the recorded artifact/protocol/native-MASM passes. A template and its tracked derived output are normal staged generation, not inherently competing sources. Earlier broad criticism of template/output duplication and implied absence of freshness enforcement is superseded by this precise assessment. The user requested that the cleanup be researched and planned collaboratively in a new chat before implementation.

## Retained owner evidence

The following reports are retained as execution evidence. The final architecture/commands above and in the replay guide override interim interface descriptions and pending entries.


### Lower support

### Lower STARK integration evidence

Toolchain used: `cargo +1.98.1` (coordinator verified declared 1.99 toolchain unavailable); baseline remains c90abdb34e8f1b8f5d03efe0ac5bd11893543991.
Environment for Rust commands: `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target`.

- `rustfmt +1.98.1 --edition 2024 crates/stark/core/src/lib.rs crates/crypto/src/hasher/mod.rs crates/crypto/src/hash/eidos/lmcs.rs crates/crypto/src/hash/eidos/mod.rs crates/crypto/benches/eidos_challenger.rs`: exit 0. Parser/format validation only; stable rustfmt warns that repository nightly-only formatting options are unavailable. External consumer files similarly parsed/formatted with `--config skip_children=true`.
- `git diff --check`: exit 0 at lower-support source integration.
- `python3 tools/air-stark/check-boundaries.py`: exit 0, `PASS: six target packages, 39 workspace packages, acyclic ownership routes and isolated native verifier feature closures` after coordinator manifest integration.
- Static source retention audit: every original Eidos LMCS test/helper name retained across crypto primitives and moved STARK engine tests. The actual-baseline lifted-STARK preprocessed test file remains byte-identical after planned module import rewrites, including `auxiliary_construction_reuses_one_preprocessed_bundle_across_proofs` added since the investigation baseline.
- `systemd-ac-power`: exit 0 immediately before `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-stark --no-default-features --features capture --offline`: exit 0, dev profile, finished 2.27s.
- `systemd-ac-power`: exit 0 immediately before `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 test -p miden-stark --lib --features testing,capture --offline`: exit 0; 155 tests passed, 0 failed/ignored; compile 35.11s, tests 0.49s. Covers original engine/FRI/lookup/IR/emitter tests and both moved Eidos LMCS regressions, including upstream cached-aux setup reuse.

Material implementation failure caught and repaired before compilation: security extraction initially used a repeated struct-field doc line as its end marker, leaving a partial struct. Reconstructed from `git show HEAD:air/src/security.rs`, used the complete unique item boundary, and ran rustfmt parse validation. No protocol behavior changed; all generic methods and source relation tests retained. Replay the final semantic split by complete Rust items rather than repeated comments.

- `systemd-ac-power`: exit 0 immediately before `CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 test -p miden-crypto --lib hash::eidos::lmcs --no-default-features --features std --offline`: exit 0, 10 tests passed; 823 filtered, 0 failures; compile 8.77s, tests 0.00s. One unused trait import left behind by moving engine tests was subsequently removed (no semantic change).

Declared toolchain became available during integration: coordinator installed Rust 1.99.0 under `/tmp/air-stark-rustup`. Subsequent Rust commands add `RUSTUP_HOME=/tmp/air-stark-rustup` and use `cargo +1.99.0`.

- `systemd-ac-power`: exit 0 immediately before `RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 check -p miden-stark --no-default-features --target wasm32-unknown-unknown --offline`: exit 0, dev profile, 7.65s.
- `systemd-ac-power`: exit 0 immediately before `RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 check -p miden-stark --no-default-features --offline`: exit 0, dev profile, 1.62s.

Consumer/build metadata audit changes: Makefile lower support tests now exercise the merged engine with testing/capture features; familiar test-prover/test-verifier targets select VM product roles; fixtures select precompile product; VM generation/check targets call source-owned CLIs with explicit roots, and expensive setup checks have an explicit separate target. `rustfmt.toml` ignores the actual new generated evaluator path. Main README has six-package paths; CI Eidos classifier uses core/STARK ownership paths, and main test job runs the static boundary checker. Benchmark profiling patches anchor on dev-dependencies rather than a removed package name and recognize both old and new tracing targets for baseline comparisons.

Non-Rust consumer validation: `make -n test-lifted-stark test-prover test-verifier regenerate-constraints check-constraints check-constraint-setup check-pvm-constants check-pvm-proof-fixture check-air-stark-boundaries` exit 0 (dry-run only; commands reviewed, not compiled/executed). `bash -n scripts/bench_eidos_vs_poseidon2.sh` exit 0. `python3 -m unittest discover -s scripts/tests -v` exit 0, 11 tests passed. `git diff --check` exit 0.

Release-policy source and release metadata scripts select Cargo workspace packages dynamically; no hard-coded removed package names needed changing. Historical changelog entries/frozen investigation references intentionally preserve old names. Standalone fuzz Cargo.lock files still contained old packages at audit time and are coordinator-owned.

Coordinator disk-cleanup hold: all lower-agent Rust commands had completed before target-directory cleanup was requested. No additional Rust commands launched during the hold.


### Source and generated AIR

### AIR split and source generation replay input

#### Exact ownership/path/API map

| Old path/API | Final owner/path/API | Semantic edit |
|---|---|---|
| air/src/lib.rs and authored constraints/trace/proof_order/memory/security | crates/air/source/src/vm/{mod.rs,constraints,trace,proof_order.rs,memory.rs,security.rs} | Authored ordinary vm::Air/MultiAir; root schema/trait and MidenAir/MidenMultiAir compatibility aliases. Generic lookup/config/security lower first. |
| HandwrittenMidenAir(air), air.eval_handwritten | miden_air_source::vm::Air; source::vm::AIRS | Wrapper and evaluation switch removed. Source LiftedAir eval directly authored under every feature. |
| air/src/constraints/generated.rs | crates/air/generated/src/vm/generated.rs | Existing optimized evaluator retained from actual c90 baseline; lower STARK imports only. |
| MidenAir production | miden_air::vm::Air; root MidenAir alias | Distinct enum; eval calls generated module. Air::source() and From conversions preserve variant identity. |
| MidenMultiAir production | miden_air::vm::MultiAir; root MidenMultiAir alias | Owns production AIRS; delegates source observation/external reduction/input sizes. |
| ordinary source vm::Air/MultiAir | miden_air_source::vm::{Air,MultiAir} | Independent authored types; source and production both pin stable four-instance order. |
| miden_air::PublicInputs | miden_air_source::vm::PublicInputs; generated module/root reexport | Identical source-owned representation and serialization; no protocol edit. |
| miden_air::MultiAir trait | miden_stark::air::MultiAir plus root compatibility reexports | Concrete collections module-qualified; canonical trait lower. |
| crates/precompiles-air/src/** | crates/air/source/src/precompile/** | Original PVM crate paths qualify crate::precompile::*; old miden_air shared imports use local vm or lower STARK. All current equations/schedules/trace/fixed/aux semantics retained. |
| ChipletAir/ChipletMultiAir | source/generated::precompile::{Air,MultiAir}; Chiplet aliases retained | Production identity distinct; first-version production dispatch honestly delegates authored source. |
| PVM root Vec input | source/generated::precompile::PublicInputs | Source-owned root Word wrapper with new/root/to_air_inputs; exact existing four-felt order; no new serialization. |
| precompiles-air/src/preprocessed.rs | coordinator product setup module | Copied intact via /tmp/air-stark-pvm-preprocessed.rs; source no setup/cache dependency. |
| air/src/config.rs accepted pins | generated/src/config.rs (coordinator) | Source retains preset + lower factories. PVM pins similarly generated/precompile/{protocol,stark_config,ace_constants}.rs. |
| air/src/ace/** generation | source/src/vm/ace/** [tooling] | Direct authored AIRS capture; generated production vm::ace runtime accessor reserved coordinator and overrides source wildcard. |
| core-lib/src/{evaluator_regen,constraints_regen}.rs | source/src/codegen/{evaluator,constraints}.rs [tooling] | Independent source capture, explicit destination/workspace &Path, package-local semantic templates. Old core-lib files thin wrappers retain old API/bin signatures. |
| precompile product/src/{ace_constants_regen,pvm_ood_frames}.rs | source/src/codegen/{precompile,pvm_ood_frames}.rs [tooling] | PVM driver/render/property tests source-owned; product command thin wrapper. Independent lower Preprocessed build uses source MultiAir scratch statement, never product cache. |

Production BaseAir forwards schema/fixed/periodic behavior. Production LiftedAir explicitly forwards BOTH cached and uncached aux hooks, max periodic length, challenge/aux counts, declared degree; VM eval alone uses optimized Rust. Production LookupAir delegates via source trait bound without exposing private builder interfaces. Production/source ProofOrder adapters have their own enums and identical stable tags.

#### Ordered replay rules

1. Lower generic owners and canonical field/matrix identities must exist before source integration. Source imports miden_stark::{air,lookup,config,security,capture::ir}; no crypto reverse STARK forwarding.
2. Move actual newer baseline authored files; preserve source semantics rather than copy older investigation files. Strip crate-level alloc/std attributes from moved module and place them only source crate root.
3. Rust visibility restrictions require canonical lexical ancestor paths: every pub(in crate::constraints[::lookup]) becomes pub(in crate::vm::constraints[::lookup]). A root use alias cannot satisfy pub(in).
4. Remove generated module from source constraints. Remove Handwritten wrapper and source/generated evaluation switch. Generation consumes source::vm::AIRS directly; paired drift tests may use production air.source().
5. Create distinct production enum/collection and explicit delegates, not a source type alias. PublicInputs/schema are source identities deliberately reexported. VM ordinary collections are generic over ExtensionField; callers can use LiftedAir<Felt,QuadFelt> UFCS.
6. Qualify PVM local crate paths and visibility scopes. Shared Eidos source equations remain local vm modules, without generated dependency. Keep PVM trace helpers cohesive. Move only committed setup/cache out to product.
7. Root accepted pins generated-owned; source tooling takes package-local copied explicit accepted-input fragments. Templates/inputs shipped source/templates, no renderer reads sibling output as its input. Actual destination checks read only explicit caller workspace paths.
8. Source codegen::evaluator::{generate(),run(destination,Mode)} emits production Rust. VM constraints::{compile_and_render(PreprocessedCommitments),derive_setup_commitments(digest),check_setup(root),run(root,Mode),accept_pins(root)} separates rendering/fresh setup/check/acceptance. PVM counterparts use explicit setup Word and derive_setup_commitment(digest).
9. Source bin `air-codegen <workspace-root> [--check|--write] [--derive-setup]` drives Rust + VM/PVM MASM. Default Check. Ordinary Write updates generated Rust/layout/ood/deep/evaluator projections, skips relation/config/protocol pin files. Optional derive-setup checks independently recomputed setup. Pin acceptance exists only explicit API; CLI cannot accept pins. ACE canonical stream generation remains source bin air-artifacts, coordinator/ACE owner.
10. Preserve old header generation labels for exact baseline rendered bytes; operational replay commands are source bin names above, not historical header strings. Revisit headers together with package command migration later.

#### Preserved checks and snapshot rules

Move air/tests to generated/tests. generated_drift retains canonical structural/global-order equality, independently captured sampled values, and raw different-route anti-tautology guard; add source/generated AIRS pairing. constraint_capture captures source AIRS only and compares source/production fixed layout. ACE tests preserve authored IR versus independent symbolic-tree node/order/layout routes, all proof orders, circuit digest and staged runtime comparison. Two VM-specific lower lookup regressions moved generated/tests/aux_trace.rs; preserve production cached/uncached/source delegates against slow fraction accumulation and malformed-window rejection. PVM source fixed-table/cached-dispatch tests retained. No golden removed.

Column snapshot values unchanged; filenames change from miden_air__constraints__ to miden_air_source__vm__constraints__ for new insta module path. VM pin/circuit snapshot moved to generated config and stays miden_air__config__tests__relation_digest_matches_current_air.snap. Merged PVM tests require VM Eidos testing helpers cfg(any(test,feature=testing)); this only exposes test helpers in unit builds.

#### Decisions/revisit triggers

- Compatibility root aliases retained: remove only after actual downstream consumer migration and intentional API scheduling.
- Production PVM delegated authored eval is provisional; optimize only with independent emitter/drift coverage.
- Package-local MASM scaffolds initially copied accepted current files; static numeric layout/codec oracles remain. Revisit if upstream hook ownership changes or packaging uncovers missing inputs.
- Explicit staged accepted setup input is not fresh setup derivation; independent --derive-setup required to make that claim. Review pin inputs only upon intentional protocol acceptance.
- `std` does not enable tooling. Source tooling additive; production canonical streams built ahead of use.

#### Validation evidence / failures

All Rust commands preceded fresh systemd-ac-power exit0. First source no-default used installed1.98.1 before declared1.99 available; toolchain file never changed. Final commands use RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 and cargo +1.99.0 --offline.

- source no-default: initial38 lexical pub(in) errors, canonical vm ancestor fixed; rerun passed9.82s.
- source tooling check: malformed template-map removal fixed; then missing alloc ToString import fixed; passed5.94s declared1.99.
- source lib/tooling tests: initial merged unit scopes/testing-helper cfg errors fixed. After task target quota cleanup/reduced-debug rebuild:322 passed,0 failed,0 ignored; test run1.09s/build5.28s.
- PVM generation extraction adds tests after322-pass; fresh source unit run pending.
- Direct rustfmt parsed changed source/codegen/test files; stable versions ignored repo nightly-only options. No full fmt-check claim.
- All remaining generated parity/CLI setup/artifact/product/native checks pending coordinator/agent ledger at initial report completion; append actual results rather than infer them.

#### Final validation additions

- After PVM renderer transfer, source lib/tooling suite passed336/336 (4.16s build,1.12s run). Initial copied constants-tools cfg prevented helper availability inside already-tooling module; redundant cfg removed. PVM preprocessed geometry initializer omission from integration restored.
- `cargo +1.99.0 test -p miden-air --tests --offline` passed all32: lib9, ace_codegen8, artifact_runtime2, aux_trace2, constraint_capture7, generated_drift4 (7.33s build; individual runs0.10–0.57s). Initial generated config format macro import was integrated by root; moved aux integration alloc import fixed; unused imports removed. No generated semantic/golden changed.
- Cheap source CLI `cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline -- /path/to/miden-vm --check` passed. Initial newly added whole-config byte comparison falsely rejected rustfmt wrapping of the32-byte Blake setup array. Replaced it with strict canonical numeric array parsing for all8 accepted VM arrays, retaining accepted/source-derived comparison while tolerating Rust formatting. Malformed/missing/duplicate declarations fail closed.
- Full source CLI same command plus `--derive-setup` passed exit0. This independently recomputed six VM setup commitment configurations and PVM Eidos setup using source MultiAir/lower Preprocessed, then checked all accepted circuit/relation/setup/shape/layout/MASM outputs. No writes/pin acceptance invoked.
- Targeted source `cargo +1.99.0 test -p miden-air-source --lib --features tooling accepted_pin_reader --offline` passed1/1 (336 filtered,3.36s build), covering wrapped Rust arrays/Felt constructors and malformed/missing/duplicate cases. Source total coverage337 tests across full336-suite + this new targeted test.
- Source package `cargo +1.99.0 package -p miden-air-source --allow-dirty --no-verify --exclude-lockfile --offline --locked` passed:199 files,2.0MiB/474.2KiB compressed. Warnings: inherited PVM aux.rs basenames reserved on Windows. Generated package same command `-p miden-air` passed:26 files,497.1KiB/150.0KiB compressed. `--exclude-lockfile` avoids Cargo attempting unpublished peer packages from registry; no publication performed.
- Safe extraction/local prerelease peer-patch script: `/tmp/air-stark-prepare-air-packages.py`. Unpacked roots `/tmp/air-stark-packaged-air-check/{miden-air-source,miden-air}-1.0.0`, archives `/tmp/air-stark-target/package/{miden-air-source,miden-air}-1.0.0.crate`. Copy exact checkout Cargo.lock; normalized extracted manifests patched to local peer packages (actual package names, not workspace aliases). Generated uses PACKAGED source. Source contains12 shipped template files; generated contains protocol/accepted.json and all canonical stream/manifest files.
- Unpacked source workdir `cargo +1.99.0 check --no-default-features --features tooling --offline` passed3.10s; unpacked generated workdir `cargo +1.99.0 check --no-default-features --offline` passed3.10s. Logs `/tmp/air-stark-{source,generated}-packaged-check.log`. Unused local peer patches warn but do not enter closure. Lower unpublished peers supplied from checkout; source/generated themselves consume only unpacked files.
- Final packaged manifest SHA256 equals current root final `720a45d77e8053ed71ac4581936a43951c2b95ba072f2226f314ae5b823b90d7`; VM/PVM blob SHA256 equal root accepted generated files (`6b63f75e...ca00`, `ada43f60...02e`); source artifact CLI/codegen bytes match checkout. Package snapshots include final accepted JSON and artifact metadata.
- All Rust invocations above freshly gated systemd-ac-power exit0; all final invocations use declared1.99/reduced-debug env documented earlier. All owned compiler/test processes completed successfully.


### ACE runtime, codec, artifacts and package

### ACE implementation validation evidence

All compile/test invocations below used fresh `systemd-ac-power` immediately before Cargo through shell `&&`; exit 0 is evidenced by Cargo starting. No nonzero AC gate occurred. Toolchain is installed 1.98.1, because declared 1.99 is unavailable; coordinator owns the toolchain discrepancy. Commands used:

```sh
systemd-ac-power && CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-ace --no-default-features --offline
```

First attempt exit 101: canonical decoder used trait method `Felt::from_canonical_checked` without importing QuotientMap. Corrected to public canonical-checked `Felt::new(value)` with explicit mapped codec error; compiler-only ToString import gated. Second attempt passed, 9 expected runtime dead-code warnings (compiler constructors/rendering-backed data remain available). This is a material resolved implementation failure, not a baseline failure.

```sh
systemd-ac-power && CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 check -p miden-ace --no-default-features --features compiler --offline
```

Passed. Confirms lower STARK capture IR integration and compiler module split compile coherently.

```sh
systemd-ac-power && CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 test -p miden-ace --no-default-features --offline
```

First attempt exit 101: new selected-root runtime test used QuadFelt::ZERO without PrimeCharacteristicRing in scope. Added the trait import in test module. Second attempt running at ledger creation; final result appended below. Original moved serialization checks and new canonical/selected-root/sequential tests execute in this runtime-only configuration.

Runtime-only test final result: PASS, 19 tests, 0 failures; doc tests 0. Compiler/testing/arbitrary command below PASS, 71 tests, 0 failures; doc tests 0. These include moved arbitrary serialization macros for ReadNode/EvalNode/WireBus/EvaluationTrace.

```sh
systemd-ac-power && CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 test -p miden-ace --features compiler,testing,arbitrary --offline
```

Normal dependency graph evidence (read-only; no compilation): all commands below passed with exact baseline cached dependencies and locked workspace graph. Full outputs captured as `/tmp/miden-ace-{runtime,std,compiler}-tree.txt`.

```sh
CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 tree -p miden-ace --no-default-features -e normal --offline --locked
CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 tree -p miden-ace --no-default-features --features std -e normal --offline --locked
CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.98.1 tree -p miden-ace --no-default-features --features compiler -e normal --offline --locked
```

Runtime tree 345 lines; std tree 360 lines: zero `miden-stark`, source/generated AIR, processor, VM product, PVM product. Compiler tree 396 lines: exactly one miden-stark and zero source/generated AIR, processor or products.

Declared toolchain subsequently installed by root as `RUSTUP_HOME=/tmp/air-stark-rustup`, 1.99.0. Final ACE compiler suite rerun with fresh AC gate:

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 test -p miden-ace --features compiler,testing,arbitrary --offline
```

PASS, 71 tests, 0 failures, no library warnings; doc tests 0.

Processor integration attempt:

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 test -p miden-processor --lib trace::chiplets::ace --offline
```

Exited 101 before tests; pending integration failures outside ACE adapter: staged VM/PVM artifact files not yet generated, ambiguous generated/precompile Air/MultiAir aliases through source wildcard, processor trace/mod.rs test still referring to source config::RELATION_DIGEST. Coordinator and source owner notified; no ACE adapter type/error failures. Retry required after root integration. Gated test-only forwarding instruction imports to avoid ordinary processor unused-import warnings.

#### Packaging and extracted source checks

All package/compile commands below had fresh AC exit 0. Read-only inventory command:

```sh
RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 package -p miden-ace --list --allow-dirty --offline --locked
```

PASS; all runtime/compiler/records/test files included. Initial `cargo package -p miden-ace --allow-dirty --no-verify --offline --locked` failed resolving unpublished `miden-core` from the registry while constructing a package lockfile. Selected first-version package inspection uses `--exclude-lockfile`, with an independently supplied workspace lock during local offline extracted checks:

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 package -p miden-ace --allow-dirty --no-verify --exclude-lockfile --offline --locked
```

PASS: originally 33 files, 294.2 KiB/68.6 KiB compressed. After adding opcode/out-of-range/large-shape malformed tests and root's versioned macro dev dependency, final package PASS: 33 files, 294.9 KiB / 68.6 KiB compressed. Root added version `1.0` to workspace miden-test-serialization-macros because Cargo drops path-only dev dependencies from normalized published manifests; final normalized ACE package retains this dev dependency.

Extracted archive `/tmp/air-stark-target/package/miden-ace-1.0.0.crate` into `/tmp/miden-ace-packaged-check/`. In that extracted package only, added `.cargo/config.toml` `[patch.crates-io]` entries for local lower package paths and copied exact workspace Cargo.lock. Repo manifests/lock untouched. These are dependency replacements for unpublished local packages; this proves shipped ACE inputs/source completeness, not published-registry release verification.

Temporary-check setup failures resolved: initial generated patch key used workspace alias miden-utils-testing but actual package is miden-test-utils (fix: always read `[package].name`); fresh package resolver without baseline lock selected uncached zerocopy-derive0.8.56 (fix: copy baseline lock preserving0.8.55). Final helper patches only these 11 actual lower packages: miden-core, miden-crypto, miden-field, miden-serde-utils, miden-utils-sync, miden-utils-indexing, miden-debug-types, miden-crypto-derive, miden-utils-core-derive, miden-stark, miden-test-serialization-macros.

Before target cleanup, extracted package checks both PASS on1.99:

```sh
cd /tmp/miden-ace-packaged-check/miden-ace-1.0.0
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 check --no-default-features --features compiler --offline
```

#### Final environment after quota repair

One processor test retry failed with OS disk quota122 writing shared `/tmp/air-stark-target` rmeta/incremental files. Coordinator stopped all compilers, deleted only generated target outputs and reopened compile gate with debug/incremental disabled. All subsequent compile/test/package commands use this exact prefix:

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0
```

Processor retry after cleanup revealed another product integration blocker: precompile recursive advice imported cfg-disabled ace_constants::PVM_RELATION_DIGEST. Root corrected it to production generated accepted protocol path. No ACE adapter errors. Final retry running while ledger updated; outcome appended below.

#### Independent staged-artifact runtime oracle

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 test -p miden-air --test artifact_runtime --offline
```

PASS, 2 tests. New generated/tests/artifact_runtime.rs imports no source AIR/capture/compiler APIs; checks canonical bytes and accepted VM/PVM Eidos pins, then interprets raw packed-u64 operations independently and compares every gate/input/output/id/fan-out with runtime EvaluationTrace for three deterministic arbitrary external input sets per relation. It also checks runtime record serialization round trips.

Separate read-only Python structural audit using struct.unpack (independent of Rust decoder) PASS for header/count/length/canonical field bounds/alignment/sequential references. VM:55956bytes,734 READ EF nodes,628 external inputs,212constant felts,6780ops; opcode counts sub/mul/add=890/3313/2577; SHA2566b63f75e5693e894ac5eff9d6db0a25624c48e54a22fba6103156bb03bafca00. PVM:113876bytes,2520READ EF nodes,1904external inputs,1232constant felts,13000ops; opcode counts1507/6262/5231; SHA256ada43f6069bbfab4434b8c18843592067e6b0135f6b85631ef38363b2ea2102e. These SHA256 values fingerprint artifact transport, and are not protocol pins.

#### Final completed checks (declared1.99, debug0/incremental0 environment)

Processor final retry PASS,7tests,0failures (1746filtered), including new independent legacy witness field-order/byte fixture and existing arbitrary wrapper serialization.

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 test -p miden-processor --lib trace::chiplets::ace --offline
```

Final unpacked ACE package tests PASS (latest33-file archive, versioned serialization macro dev dependency retained; local lower patches+baseline lock as above):

```sh
cd /tmp/miden-ace-packaged-check/miden-ace-1.0.0
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 test --no-default-features --offline
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 test --features compiler,testing,arbitrary --offline
```

Runtime19tests and compiler71tests,0failures; doc tests0. Runtime emits existing9compiler-construction/rendering dead-code warnings; compiler suite no library warnings. Includes final explicit rejected opcode3,unresolved/out-of-range wires,2^30shape bounds.

Source-owned artifact generation checked after source owner's PVM tooling extraction became compile-ready. Each cargo run fresh AC exit0:

```sh
cd /path/to/miden-vm
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --check crates/air/generated/artifacts
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write /tmp/miden-air-artifacts-determinism-a
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write /tmp/miden-air-artifacts-determinism-b
```

All3PASS. Independent Python byte equality over both generated directories and staged repo files PASS for each relation. Stable transport fingerprints are the SHA256 values above; candidate Eidos digests exactly retained baseline VM/PVM accepted pins (also checked independently by artifact_runtime test). VM digest display0xc2c2408c6ba7987e98bc22640748803f1cc8590990d6244b911d3172f01cc966; PVM0xf5f361b98d784b1fd3ec103118de3e7042bb46eedf9ddc1a03084ef9c7ec294d. No accepted repo pins/artifacts were written by these validation commands (writes only disposable /tmp dirs).

#### Final manifest-delivery refinement (supersedes earlier CLI syntax)

The final `air-artifacts` interface requires an explicit pin file. Older commands above without `--accepted-pins` now intentionally fail; use this final recipe. Root supplied packaged `crates/air/generated/protocol/accepted.json` with accepted_schema1, baseline, statement_context and per-relation protocol_id/configuration/accepted_circuit_digest/accepted_relation_digest. CLI validates four canonical field integers per digest and canonical protocol ID, derives candidate circuit digest and `miden_stark::config::relation_digest(protocol_id,&circuit_digest)`, compares BOTH relations before any output directory/file mutation, and never accepts/replaces pins.

CLI now coordinates `vm.ace`, `precompile.ace`, and `manifest.json`. Manifest derives shape/size/transportSHA256/evaluator metadata, copies accepted fields, and records candidate circuit+relation digests separately. --check compares JSON semantically; --write canonicalizes pretty JSON with trailing newline and skips equal stream-file writes. Root authorized CLI metadata regeneration after validating both pins; staged .ace bytes stayed unchanged. New manifest2785bytes SHA256720a45d77e8053ed71ac4581936a43951c2b95ba072f2226f314ae5b823b90d7.

All four final Cargo invocations fresh AC exit0,1.99 quota-safe env, PASS:

```sh
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write --accepted-pins crates/air/generated/protocol/accepted.json crates/air/generated/artifacts
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --check --accepted-pins crates/air/generated/protocol/accepted.json crates/air/generated/artifacts
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write --accepted-pins crates/air/generated/protocol/accepted.json /tmp/miden-air-artifacts-determinism-a
systemd-ac-power && RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline -- --write --accepted-pins crates/air/generated/protocol/accepted.json /tmp/miden-air-artifacts-determinism-b
```

Independent Python comparison PASS: each of all3members is byte-identical across both disposable generations and staged repository; every candidate/accepted circuit/relation digest array equals explicit accepted.json values. Original VM/PVM transport sizes/fingerprints unchanged.

Negative CLI contract tests used the already-compiled binary, fresh AC before EACH invocation (all gates0). Every command exited1 as expected and Python asserted each destination directory absent. The two mismatch cases mutated only the PVM accepted field by+1, proving rejection after VM candidate validation produces no partial VM output:

```sh
systemd-ac-power && /tmp/air-stark-target/debug/air-artifacts --write /tmp/miden-artifact-rejected-absent-pins
systemd-ac-power && /tmp/air-stark-target/debug/air-artifacts --write --accepted-pins /tmp/miden-accepted-circuit-mismatch.json /tmp/miden-artifact-rejected-circuit
systemd-ac-power && /tmp/air-stark-target/debug/air-artifacts --write --accepted-pins /tmp/miden-accepted-relation-mismatch.json /tmp/miden-artifact-rejected-relation
systemd-ac-power && /tmp/air-stark-target/debug/air-artifacts --write --accepted-pins /tmp/miden-accepted-noncanonical-field.json /tmp/miden-artifact-rejected-field
```

Fixtures are temporary copies of accepted.json: first mismatch increments precompile accepted_circuit_digest[0], second increments precompile accepted_relation_digest[0], third sets vm accepted_circuit_digest[0]=u64::MAX. They do not edit packaged accepted pins. Expected messages respectively: required flag; candidate circuit digest mismatch/no writes; candidate relation digest mismatch/no writes; noncanonical field integer. No protocol/runtime API or original stream test changed in this refinement.


### Precompile product

### Independent PVM product integration

Owner: lower-support agent, second disjoint assignment. Exclusive product source/tests excluding source-generation handoff files ace_constants_regen.rs and pvm_ood_frames.rs. Coordinator owns all manifests/lockfiles/accepted pins and fixture binary driver copies.

Rust environment for all commands in this assignment:

```sh
RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0 cargo +1.99.0 ... --offline
```

Every Rust command below was immediately preceded by `systemd-ac-power` with exit 0.

- `check -p miden-precompile-stark --no-default-features --offline`: PASS, dev profile 4.90s. Initially two unused prover-only imports; subsequently cfg-gated.
- `check -p miden-precompile-stark --no-default-features --features trace --offline`: PASS, 1.77s. Initially two grouped imports only used by proving; subsequently cfg-gated.
- `check -p miden-precompile-stark --no-default-features --features prover,recursive --offline`: PASS, 6.40s. Product source emits no warnings; inherited ACE runtime dead-code warnings handled by ACE owner.
- `test -p miden-precompile-stark --no-default-features --features trace,std --test protocol_history --test trace --offline`: first attempt failed during parallel source-driver integration (old constants-tools cfg on moved OOD helpers); source owner removed obsolete guards. Re-run PASS, protocol-history4/4 and trace1/1; compile3.75s, history3.76s, trace0.03s. Redundant outer test imports subsequently removed.

Semantic fixes and public API:

- Native verifier remains available with no default features, uses product setup/cache, production PVM AIR, generic STARK and canonical core proof envelope.
- Recursive code directly reads the accepted relation digest via `miden_air::precompile::protocol::PVM_RELATION_DIGEST`; it never needs a compiler-gated constants module. Values unchanged.
- Independent trace path: `miden_precompile_stark::trace::import_witnesses(Vec<PrecompileWitness>) -> Result<WitnessSession, SessionInputError>`. Fixed existing unusable skeleton by making `WitnessSession::roots(&self) -> &[Digest]` and `finish(self) -> SessionTraces` available to external consumers, rather than cfg(test)-only. `SessionTraces::mains` and `public_root` similarly remain available in release; into_mains/air_inputs unchanged.
- New external trace test checks repeated root order, independently computed core aggregate root and source canonical chiplet count/trace heights. Does not call a prover.
- Preserved original canonical PVM ACE shape golden under new crate namespace: old `src/snapshots/miden_precompiles_verifier__ace__tests__pvm_canonical_ace_shape_matches_current_air.snap` -> product `src/snapshots/miden_precompile_stark__ace__tests__pvm_canonical_ace_shape_matches_current_air.snap`. Only source metadata path changes; numbers and assertion unchanged. No golden removed.

Current protocol-history test names preserved: rejects_pinned_old_eidos_proof, rejects_pinned_v0_35_eidos_proof, verifies_pinned_current_eidos_proof, verify_deferred_enforces_fixed_stark_proof_size_ceiling. Fixture bytes/roots unchanged.

- `check -p miden-precompile-stark --no-default-features --features prover --offline`: PASS, 1.85s; independent no_std proving path compiles without requiring std/recursive/compiler.
- `test -p miden-precompile-stark --lib --features prover,recursive budget --offline`: first attempt blocked by coordinator-owned generated PVM artifact commitment check using Word::from([u64;4]); reported required canonical Felt conversion to coordinator, re-run pending.

Additional semantic move rule: product ACE native/MASM oracle paths gain one parent traversal after moving from crates/precompiles-verifier to crates/stark/precompile: CARGO_MANIFEST_DIR/../lib/core/asm/... becomes ../../lib/core/asm/.... Kept all original oracle assertions/names; no source/MASM contents changed.

- Budget test retry after generated guard fix exposed one nested legacy test import and missing tracing/std manifest forwarding. Fixed tests/eidos.rs import to miden_stark::air::ConstraintDegrees; coordinator added tracing/std to product std feature. Final AC-gated `test -p miden-precompile-stark --lib --features prover,recursive budget --offline`: PASS, 5/5 tests, 538 filtered, compile18.29s, tests63.97s. Includes exact modelled peak succeeding, one byte under rejected, typed overflow distinction and rejection before build_trace span.
- AC-gated `test -p miden-precompile-stark --lib --features prover,recursive ace::tests --offline`: PASS, 30/30 tests, 513 filtered, compile0.08s, tests1.83s. The substring also selects trace::tests; all original concrete PVM ACE canonical/differential/order/layout/public-input/aux/fixed/security/MASM/digest oracles pass, including restored exact golden.
- AC-gated `test -p miden-precompile-stark --lib --features prover,recursive recursive::tests --offline`: PASS, 5/5 tests, 538 filtered, compile0.09s, tests0.00s. Covers canonical limb encoding, non-Eidos/oversize/root-count rejection before parsing and request-key packaging.
- AC-gated `PROPTEST_CASES=8 ... test -p miden-precompile-stark --lib --features prover,recursive tests::batch_witness --offline`: PASS, 10/10 tests, 533 filtered; compile0.07s, tests66.03s. Property case count explicitly8, not full default property coverage. Includes ordered/repeated batches proving and native verification, exact root bookkeeping, batch-wide limits, malformed semantics, shared payload shape rejection and bounded fallback lowering.

Final manifest change requested and coordinator-applied: std += ["tracing/std"]. No other product manifest additions were needed by the preserved test code. Final Rust source scan finds no removed lower crate imports in product source/tests.

- AC-gated `check -p miden-precompile-stark --no-default-features --features recursive --offline`: PASS, dev profile4.36s; independent recursive/native configuration excludes trace/prover/compiler from the normal graph.
- Final `python3 tools/air-stark/check-boundaries.py`: PASS, six targets/39 packages, acyclic ownership and isolated native no-default/std/recursive closure checks. `git diff --check`: PASS. Direct Rust1.99 rustfmt parse/format on changed owned product files: exit0, repository nightly-only formatting options skipped by stable rustfmt.

All selected product checks completed; no running Rust processes from this agent and no product-owned unresolved failures. The full543-test product suite was not run; selected current/history/native proving/budget/import/differential/layout/advice oracles above passed. ACE runtime's noncompiler dead-code warnings remained in lower dependencies during recursive-only check; ACE owner/coordinator handles those separately.


### Delivery matrix and unpacked products

### Final isolated/native/portable/package delivery verification

Owner: ACE/runtime agent, delegated by coordinator. No repository Rust source, manifests, lockfiles or accepted inputs were edited by this verification task. The coordinator-approved Python unpack helper was added after independent review and successful checks. All compile and package commands below were prefixed by fresh `systemd-ac-power`; every gate returned0 (Cargo started). No root/sudo operations. Read-only cargo-tree commands do not compile.

Exact declared toolchain1.99.0; host aarch64-unknown-linux-gnu, installed cross target wasm32-unknown-unknown. Quota-safe environment for every Cargo compile/package:

```sh
export RUSTUP_HOME=/tmp/air-stark-rustup
export CARGO_HOME=/tmp/air-stark-cargo
export CARGO_TARGET_DIR=/tmp/air-stark-target
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_TEST_DEV_DEBUG=0
```

Every command is run from the authorized checkout unless an unpacked workdir is stated. Rust caches/targets are disposable; alternate writable paths on replay are valid. All registry resolution uses cached baseline dependency versions; workspace checks include --locked. Temporary unpacked roots have independent copied locks and may prune them while resolving local patches.

#### Final workspace feature/target matrix

All three commands below PASS on declared1.99 (AC0each), logs respectively `/tmp/air-stark-final-native-none.log`, `...-wasm-none.log`, `...-native-std.log`:

```sh
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --target wasm32-unknown-unknown --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --features std --offline --locked
```

These cover all six reorganized packages plus composed facade with no execution/prover feature. Wasm claim is portable no-default configuration, not std/recursive wasm; lower packages do not have a recursive feature.

Isolated native products checked separately to avoid feature-unification concealing unwanted dependencies. Each of these6commands PASS, freshAC0each (logs `/tmp/air-stark-final-{package}-{none,std,recursive}.log`):

```sh
systemd-ac-power && cargo +1.99.0 check -p miden-vm-stark --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-vm-stark --no-default-features --features std --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-vm-stark --no-default-features --features recursive --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-precompile-stark --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-precompile-stark --no-default-features --features std --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-precompile-stark --no-default-features --features recursive --offline --locked
```

Normal+build feature audit (read-only, each passed) repeated the six product configurations above and facade no-default with:

```sh
cargo +1.99.0 tree -p PACKAGE --no-default-features [--features std|recursive] -e normal,build -f '{p} |features={f}' --offline --locked
```

Full trees `/tmp/air-stark-final-tree-{package}-{feature}.txt`. All7trees exclude miden-processor, ACE compiler/testing, STARK capture, and source tooling. VM/PVM product trees exclude the peer product. Facade tree contains both products intentionally. VM no-default491lines/std505/recursive491; PVM none494/std509/recursive509; facade none513. VM recursive retains no_std lower closure; PVM recursive explicitly enables std. Runtime-only dead-code warnings remain from compiler construction/rendering backing types, not compilation errors.

#### Packaging inputs and ordinary offline unpacked consumption

Source/generated package ownership remains source agent/coordinator. ACE packaging/tests were already completed; no ACE repackage repeated here. Product packaging command PASS, AC0:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
```

Inventory: STARK116files1003.6KiB/248.4KiBcompressed; PVM119files2.0MiB/815.1KiBcompressed; VM initially21files157.9KiB/39.0KiB. Root subsequently added relation-only recursive advice `for_vm_request`; VM repackaged with same flags:21files158.2KiB/39.1KiB. All104STARK/16VM/106PVM source files compared byte-for-byte to checkout and matched latest snapshot. PVM package includes exact independent fixture binary314396bytes SHA256bce1b16b48d0237fb0ebaf03a15df4ea7579d7f7c11c3cc4efc35eefc512ad69 and root80bytes SHA256c051116fd989f1d69b147514aa9efe98fb460db293c1964ee1d3984d5f8e082b.

Latest generated helper-domain correction also repackaged by this owner, AC0:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-air --allow-dirty --no-verify --exclude-lockfile --offline --locked
```

PASS26files497.5KiB/150.2KiBcompressed. Generated helper src/precompile/stark_config.rs1078bytes SHA2567957e7e5f65731bfed6cc63e0056507932ea0891ae27a3b48214b9fd890399d3. Packaged protocol/accepted.json1143bytes SHA2563f5c7040239452972e4bceaf89820190195ad69393cf61161476c8941323fd37; manifest2785bytes SHA256720a45d77e8053ed71ac4581936a43951c2b95ba072f2226f314ae5b823b90d7; VM/PVM blobs55956/113876bytes retain prior transport SHA2566b63f75e5693e894ac5eff9d6db0a25624c48e54a22fba6103156bb03bafca00 /ada43f6069bbfab4434b8c18843592067e6b0135f6b85631ef38363b2ea2102e. Source agent's initial package199files includes12local template/input files; final source acceptance-API cleanup archive refresh was pending at that stage; the final coherent refresh below completed it.

Local package verification uses explicit `[patch.crates-io]` for unpublished supporting packages and copied baseline Cargo.lock; no public-registry publication claimed. Initial VM unpacked attempt with checkout processor patch failed package-identity collision: optional processor still resolves checkout path dependencies while VM direct deps select unpacked ACE/source. Resolved with temporary processor support workspace copying only its manifest and symlinking assets; its inherited new-six dependency paths point exactly to unpacked packages. Shipped target Cargo manifests/source files are unchanged. Root repository manifests/lock untouched. This is a local validation harness requirement, not a source dependency cycle or protocol issue.

Initial separate unpacked roots (`/tmp/air-stark-packaged-product-check/{miden-stark,miden-vm-stark,miden-precompile-stark}-1.0.0`) checks PASS after collision repair:

```sh
cd UNPACKED_ROOT
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
```

All3PASS; latest VM recursive also PASS. Unpacked STARK wasm no-default PASS. The final coherent six-package unpack checks below complete this phase. Reproducible helper `/tmp/air-stark-prepare-unpacked-final.py` accepts --checkout/--archives/--output, resolves actual package names/versions, extracts six archives, creates optional processor support workspace, supplies local lower patches, and copies exact baseline locks. Coordinator can check/copy the helper into repo tools/air-stark; final replay must not depend on private chat or /tmp history.

Package-local production fixtures/templates/artifacts are present. PVM authored MASM parity oracles remain downstream repository tests reading core-lib assembly paths, not a claim that every workspace MASM oracle is runnable from a lone PVM archive. Ordinary portable package compilation has no dependency on those dev oracle files.

#### Final coherent six-package snapshot: completed

After the coordinator removed incomplete pin-acceptance APIs and formatted the final sources, all six packages were rebuilt together. This final package set supersedes earlier snapshots. The command passed with a fresh successful AC gate:

```sh
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
```

Final archive inventory:

| Package | Files | Uncompressed | Compressed |
| --- | ---: | ---: | ---: |
| miden-stark | 116 | 1003.5 KiB | 248.4 KiB |
| miden-ace | 33 | 294.9 KiB | 68.6 KiB |
| miden-air-source | 199 | 2.0 MiB | 472.7 KiB |
| miden-air | 26 | 497.6 KiB | 150.2 KiB |
| miden-vm-stark | 21 | 158.2 KiB | 39.1 KiB |
| miden-precompile-stark | 119 | 2.0 MiB | 815.1 KiB |

Source packaging reports inherited Windows reserved-name warnings for `src/precompile/uint/{aux.rs,mul/aux.rs,store_mul/aux.rs}`. Linux/wasm checks below pass; Windows support is not claimed. `--exclude-lockfile --no-verify` avoids resolving unpublished workspace names from the public registry during archive creation. Actual compilation is performed explicitly from extracted package sources afterward.

The unified preparation helper was reviewed independently. Review identified that repeated extraction into a populated directory could retain files removed from a newer archive, weakening shipped-input validation. The helper now refuses any nonempty output directory and refuses output within the source checkout. Both rejection tests passed before copying the exact tested script to `tools/air-stark/prepare-unpacked.py`. It requires Python 3.12+ for `tomllib` and safe `tarfile` extraction filtering. Repository manifests and shipped target manifests remain untouched.

Reproduce preparation using a fresh destination:

```sh
python3 tools/air-stark/prepare-unpacked.py \
  --checkout "$PWD" \
  --archives /tmp/air-stark-target/package \
  --output /tmp/air-stark-packaged-delivery-check
```

All six unpacked target dependencies point to the six package roots under that output. Supporting packages are supplied through explicit local patches. An isolated optional processor support manifest redirects its inherited target dependencies to those same package roots; this avoids Cargo path-identity collisions while leaving processor disabled in verifier graphs. The helper copies the baseline lock into each independent package root. This is offline validation with local unpublished support, not public-registry release verification.

Final coherent checks all passed. Every compile used the declared environment above and a separate successful AC gate. Native no-default checks used the first fresh equivalent output `/tmp/air-stark-packaged-final-check`; wasm and tooling checks used the reviewed helper's fresh `/tmp/air-stark-packaged-delivery-check`. Both outputs extracted the same final archives; all checked source/input/fixture bytes match the checkout exactly.

| Unpacked package | Native no-default | wasm32 no-default | Additional native features |
| --- | --- | --- | --- |
| miden-stark | Pass | Pass | capture: Pass |
| miden-ace | Pass | Pass | compiler: Pass |
| miden-air-source | Pass | Pass | tooling: Pass |
| miden-air | Pass | Pass | Production staged inputs compile without tooling |
| miden-vm-stark | Pass | Pass | std: Pass; recursive: Pass |
| miden-precompile-stark | Pass | Pass | std: Pass; recursive: Pass |

Run the appropriate command from each unpacked package root, with a fresh AC gate each time:

```sh
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --target wasm32-unknown-unknown --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --no-default-features --features FEATURE --offline
```

`FEATURE` is the additional native feature named in the table. Compiler/tooling checks are host tools; wasm checks cover portable runtime/verifier configurations. Logs are `/tmp/air-stark-coherent-unpacked-{package}-{native,wasm,feature}.log`.

The final unpacked source binary also checked the unpacked generated artifact bundle with explicit packaged accepted inputs, without reading checkout generated artifacts:

```sh
cd /tmp/air-stark-packaged-delivery-check/miden-air-source-1.0.0
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins /tmp/air-stark-packaged-delivery-check/miden-air-1.0.0/protocol/accepted.json /tmp/air-stark-packaged-delivery-check/miden-air-1.0.0/artifacts
```

Passed: VM/PVM streams and manifest match authored packaged candidates and explicit packaged circuit/relation pins. Log `/tmp/air-stark-coherent-unpacked-artifacts-check.log`.

Final unpacked normal/build trees for each product with no features, std and recursive all passed the same closure audit: no processor, ACE compiler/testing, STARK capture, source tooling or peer product. Every reorganized package path in each active tree points under `/tmp/air-stark-packaged-delivery-check`, proving the checks consume the shipped package set. The audit ignores warnings for unused local patches and inspects only active package rows (`|features=`). Logs `/tmp/air-stark-coherent-unpacked-tree-{product}-{feature}.txt`.

Byte comparison to the final checkout covered 104 STARK, 29 ACE, 195 source, 17 generated, 16 VM-product and 112 PVM-product source/input/fixture files. Packaged accepted JSON, artifact manifest, VM/PVM canonical blobs and pinned PVM fixture bytes retain the fingerprints recorded above. No accepted value or protocol format changed during validation.


### Independent architecture audit

### Final independent read-only architecture audit

No source edits or Rust compilation/tests performed in this audit assignment. Metadata-only commands used declared Rust/Cargo1.99 and existing offline CARGO_HOME; previous execution evidence remains in the lower/PVM ledgers.

Observed invariants:

- `python3 tools/air-stark/check-boundaries.py`: PASS; six targets,39 workspace packages, no forbidden/cyclic normal/build ownership routes and isolated product native feature closures.
- Actual Cargo resolver: `RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo CARGO_TARGET_DIR=/tmp/air-stark-target cargo +1.99.0 tree -p miden-vm --no-default-features --features std --edges normal,build --prefix none --format '{p} [{f}]' --offline`: source/generated AIR, generic STARK, ACE and both products each report only `[std]`; processor absent. Assembly/core-lib absent. Full output saved `/tmp/air-stark-facade-native-package-features.txt`.
- Final facade `verify_v2`, `validate_precompile`, `preflight_vm_stark`, `preflight_precompile_stark`, `check_security_level` function bodies match baseline `HEAD:verifier/src/lib.rs` after whitespace normalization and renamed PVM crate path. Therefore compatibility/structural/size error precedence, VM authentication+minimum-security-before-deferred-evaluation, ordered repeated root aggregation/coverage and per-component security policy remain intact.
- Source VM eval dispatches authored equations; independent production enum dispatches staged optimized Rust. Both production cached and uncached auxiliary hooks explicitly delegate source semantics. PublicInputs retains source identity. PVM independent production type honestly delegates authored dispatch; optimized PVM Rust remains deferred.
- Accepted circuit/relation/setup pins are absent from ordinary source runtime modules. Source tooling consumes package-local templates/explicit accepted inputs; no generator Rust dependency on products/generated AIR/core-lib. Normal generated artifacts are canonical byte includes, decoded/structurally validated and checked against accepted instruction commitment before runtime consumption. Production advice uses these artifacts rather than AIR-to-ACE builders.
- Core proof/field files show no semantic changes; direct upstream matrix identity is retained through p3_matrix reexports.

Concrete findings raised and coordinator-resolved:

1. VM recursive advice initially accepted only ExecutionProof, forcing relation-only consumers to fabricate envelopes. Coordinator added `RecursiveVerifierInputs::for_vm_request(...,&VmProof,&ExecutionClaim)`, retained acyclic envelope forwarding and passed independent obligation/advice integration; inspected final body delegates directly to the relation-local parser.
2. Source public accept_pins APIs updated generated outputs while leaving accepted template/JSON inputs stale. No repository callers existed. Coordinator removed incomplete public APIs; future protocol acceptance requires explicit synchronized review/update of all accepted input/output surfaces and is outside this reorganization.
3. Makefile artifact calls lagged the new required explicit-input CLI and used package root instead of artifacts directory. Final inspected commands now pass protocol/accepted.json and generated/artifacts.

No further critical architecture/security regression found. Required final follow-up from this audit: run final explicit-input `air-artifacts --check` and, if not already done since CLI change, verify packaged source-tooling inputs. Ordinary current native/proving/order/layout/history tests are recorded separately; this audit does not claim full-workspace/all-feature tests or package verification were run.


## Selectable PVM hash variants — 2026-10-18

Parent `70003939b019f82e6aa7d3386f1e2583c15964ea`, branch `adr1anh/air-codegen-cleanup`.
PR4028 metadata was re-read through the GitHub API: head
`983cf342466efc8da0d7efa03d544c3164a46c36`, base
`21d9f712ab75e49202e51b36a6b4239eeda52064`, unchanged from the briefing. Its hash-mask,
minimal-union, framing and shared-setup semantics were adapted into the current typed Askama and
precompiled-artifact layout. No upstream numeric recursive root was copied.

All Rust commands below used a fresh successful `systemd-ac-power` gate (exit0), the declared
Rust1.99.0 toolchain, and the following environment. The private log wrapper was only a convenience;
the commands are replayable directly.

```sh
export RUSTUP_HOME=/tmp/air-stark-rustup CARGO_HOME=/tmp/air-stark-cargo
export CARGO_TARGET_DIR=/tmp/air-stark-target CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_PROFILE_TEST_DEV_DEBUG=0
systemd-ac-power && cargo +1.99.0 test -p miden-air-source -p miden-air --features miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --features prover,recursive --release --lib --offline --locked tests::pvm_variants -- --test-threads=2
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --features prover,recursive --release --lib --offline --locked tests::pvm_variants::reduced_native_variant_supports_every_commitment_hash -- --exact --nocapture
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --test protocol_history --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-stark --lib --offline --locked preprocessed::tests
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --lib --offline --locked setup::tests::variant_setup_uses_selected_air_order
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::pvm_ -- --test-threads=2
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::pvm_aux_trace::pvm_odd_selected_aux_hook_preserves_alignment_gap_and_independent_boundary -- --exact
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::pvm_wrapper::pvm_selected_wrappers_bind_fixed_height_and_stable_order -- --exact
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --lib --offline --locked proof_compatibility_roots_match_the_embedded_core_library
systemd-ac-power && cargo +1.99.0 test -p miden-vm --test miden-cli --offline --locked delegated_and_batched_precompile_proving_composes_across_transport -- --test-threads=1
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --test core-lib --offline --locked stark::stark_verifier_e2f4_small -- --exact
systemd-ac-power && cargo +1.99.0 test -p miden-air-source --features tooling --release --lib --offline --locked codegen::pvm_variants::tests::reduced_protected_body_drift_prevents_every_managed_write
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- . --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins crates/air/generated/protocol/accepted.json crates/air/generated/artifacts
```

The source/generated suites passed349 source tests and44 generated AIR tests. Independent structural,
value, degree and schema captures remain; new coverage checks all eight selected symbolic/sample
folds and periodic bases, raw packed ACE interpretation and retained shape descriptors, selected
geometry/security at alignments1/8/17, and protected reduced-wrapper rejection before managed writes.
The selected external-reduction equality check is a forwarding check; it is not counted as an
independent numeric reduction oracle.

The core PVM suite passed26 tests in442.11s, including all8 native-to-recursive variants, invalid
selector8, authentic same-count SHA256→SHA512 substitution, mixed precompiles/signatures, every
existing full-height boundary, OOD/DEEP/transcript/scatter checks, VM/PVM interleaving and batch
root/response tampering. The refined odd-count test separately passed after adding comparison of
all eight buffered coin-input cells, alongside CV/counters/lengths. It independently enumerates
fixed UintDomain/CurveId messages, balances nine height-weighted normalized sums, compares a scalar
transcript route and preserves sentinels in both the EF alignment gap and Alpha cells. An additional
all8 wrapper test passed stable(height,canonical-index) maps and fixed BytePairLut rejection. The
live assembled-root test and facade delegated/batched transport composition both passed.

Strict setup selection and Arc sharing/retention tests passed2 lower-engine tests; all8 selected
setup orders passed a product test. Historical native proof tests passed4: the v1.0 full payload
still verifies, and earlier incompatible fixtures remain rejected. Core mask and registry tests
also passed. Release protected-body rejection passed. The recursive bounded-cost test establishes
core rows below70,000 for all8 32-byte cases and a Keccak padded trace at most2^18; no before/after
wall-time or proof-size benchmark was run, and upstream performance claims are not adopted.

The new actual PVM root is `[3574486121566389623, 5820205566457587259,
252779576332978399, 4493818589800250298]`, replacing
`[5590780963878947933, 4630130988127364859, 6407532874471138157,
1323318770910249969]`. The VM root remains
`[6709788805636672991, 3123750071737729735, 9047041766774444338,
8997647198517130739]`. A deliberately failing candidate comparison first exposed the actual
assembled root; the explicit update then passed the live root check. Existing format2 envelopes
naming the old PVM root reject under current-only facade support, even with empty/deferred status.
This is distinct from legacy native inner ALL payload compatibility. No old root was added to
acceptance, historical fixture overwritten, envelope schema changed or protocol checkout edited.

Parent comparison `/tmp/pvm-variants-identities.json` checks28 identity/fixture/MASM files:
27 byte-identical, only full `sys/pvm/mod.masm` deliberately changes. Both full ACE streams, VM
Rust zlib, all four degree/metadata tables, every historical fixture and all14 prior VM/PVM MASM
modules except the dispatching PVM wrapper retain their bytes. Existing VM/full PVM accepted JSON
entries remain unchanged. Seven new ACE streams, descriptors and generated internal MASM modules
are deliberate feature data; accepted JSON and the manifest record exact new identities/hashes.

Native and wasm no-default checks passed all six packages plus facade:

```sh
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --target wasm32-unknown-unknown --offline --locked
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
python3 tools/air-stark/prepare-unpacked.py --checkout . --archives /tmp/air-stark-target/package --output /tmp/air-pvm-variants-unpacked
```

All six offline archives were created. Source ships218 files, including package-local templates,
variant rendering and a self-contained protected-body fixture; generated AIR ships43 files,
including all8 streams and explicit descriptors/accepted identities. Actual unpacked source and
generated AIR both passed native+wasm no-default checks. Packaged source tooling checked all nine
VM/PVM artifact streams, descriptors and manifest against explicit unpacked accepted JSON, and
rendered/checked the complete checkout MASM from its shipped templates. Its protected reduced-body
unit test also passed from the unpacked archive with no compile-time sibling input. To replay,
run these from the appropriate unpacked package root, with a fresh gate per command:

```sh
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --no-default-features --target wasm32-unknown-unknown --offline
# Source package only:
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins /tmp/air-pvm-variants-unpacked/miden-air-1.0.0/protocol/accepted.json /tmp/air-pvm-variants-unpacked/miden-air-1.0.0/artifacts
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-codegen --offline -- /absolute/checkout --check
systemd-ac-power && cargo +1.99.0 test --no-default-features --features tooling --lib --offline codegen::pvm_variants::tests::reduced_protected_body_drift_prevents_every_managed_write
```

Unpacked locks were updated only in temporary directories for local unpublished patches; no
public-registry publication verification is claimed. Boundary audit passed six targets/39 packages.
Existing ACE dead-code, reserved Windows filename and unused local-patch warnings remain. No
all-workspace/all-feature/Windows suite or broad release proof suite was run. An initial native
link attempt hit temporary quota; only obsolete pre-stage workspace build outputs were removed,
leaving registry, source, toolchain and active artifacts intact. The malformed-target facade
invocation was corrected to `miden-cli`; early layout/inference errors were resolved before the
passing checks. Logs are `/tmp/miden-evaluator-delivery-pvm-variants-*.log`.

The focused six-hash release test passed1 in40.73s. The redundant unoptimized variants command
was explicitly stopped at coordinator direction after release passed: six named tests had already
reported success (all8 native/wrong-mask; exact batch union; explicit superset; disabled operations;
malformed public frames; selected lookup balance), while the six-hash test was still running. Its
exit101/SIGINT is recorded as partial/cancelled, never as a completed pass. The complete release
variants suite passed7 in52.44s and is the final native-coverage gate. Final archives were refreshed after formatting;
byte comparison covers104 STARK,28 ACE,214 source,31 generated AIR,16 VM-product and104 PVM-product
shipped src/templates/artifacts/protocol inputs, all identical to checkout.

## Consolidated verifier sharing — 2026-10-18

Parent: `54d29aeb8e7798c3ce456cada01f1e8a161bce00`. This stage shares actual emitted runtime
algorithms across VM/PVM/all eight masks; reduced selections retain wrapper/layout pairs. The
fixed trusted descriptor, count/width kernels, standalone adapters and global delivery preflight
are described in [MASM generation](../masm-verifier-generation.md#shared-runtime-kernels-vm-and-all-eight-pvm-selections).
No Cargo manifest/lock, authored equation, protocol checkout or historical fixture changed.

### Source, assembled representation and cycles

These are separate measurements. Source bytes are actual UTF-8 file lengths, not allocated disk
blocks. The combined inventory includes every new shared module (including the authored registry)
and the same seven VM modules used for the parent comparison.

| Actual source surface | Parent files / bytes | Shared files / bytes |
| --- | ---: | ---: |
| Reduced seven PVM families | 49 / 370790 | 14 / 107987 |
| All PVM families | 56 / 428348 | 21 / 128462 |
| Comparable VM family | 7 / 46900 | 7 / 38588 |
| New common runtime, including registry | 0 / 0 | 10 / 119801 |
| Combined VM + PVM + common runtime | 63 / 475248 | 38 / 286851 |

The combined reduction is 188397 bytes (39.64%); the reduced-only row excludes the common runtime
and must not be presented as a total-runtime comparison. Whole-core serialized `MastForest` is
626942 → 542318 bytes (13.50% smaller). Whole-core serialized package is 18439437 → 15414308 bytes;
it includes manifest/source/debug information and is not an instruction-only size. The assembler
already interns identical execution nodes. No throughput or proof-size improvement is claimed.

| PVM mask, 32-byte input | Parent core rows | Shared core rows | Added rows |
| --- | ---: | ---: | ---: |
| 0 | 52447 | 55091 | 2644 |
| 1 | 58149 | 60790 | 2641 |
| 2 | 55290 | 57779 | 2489 |
| 3 | 60442 | 63039 | 2597 |
| 4 | 55811 | 58354 | 2543 |
| 5 | 60958 | 63583 | 2625 |
| 6 | 57745 | 60382 | 2637 |
| 7 | 62671 | 65425 | 2754 |

The measured 4.3–5.0% PVM core-row cost is deliberately accepted for simpler emitted MASM. All
existing `<70000` bounds and the Keccak padded-trace `<=2^18` bound pass. VM on the **identical
native proof**, linked separately against parent and current packages, uses 43585 → 45828 core
rows (+2243, 5.15%). The parent package was saved before assembly changes. Two-row production OOD
kernels use VM1122 / full-PVM3114 cycles against unchanged1300/3200 budgets. Setup is separately
measured (VM698/PVM1701 cycles); it is staged once before the timed neutral hooks. Hash-chiplet
rows can vary with proof challenges; no general performance claim is inferred from these cases.

### Identities and compatibility

Both roots were independently read from the adapted assembled library, then deliberately accepted
in `core/src/proof.rs`; the embedded-library/root-pin check passes.

| Root | Parent | Accepted shared runtime |
| --- | --- | --- |
| VM | `[6709788805636672991,3123750071737729735,9047041766774444338,8997647198517130739]` | `[2603767543770539887,2276982665163883070,8183189607394765382,6790696423975467021]` |
| PVM | `[3574486121566389623,5820205566457587259,252779576332978399,4493818589800250298]` | `[3482323695689074059,8512759071851127162,3339266452839591316,3848025012586791398]` |

All16 generated artifact members are byte-identical to the parent: nine ACE streams, variant
metadata, evaluator zlib, four degree/metadata tables and manifest. Accepted circuit/relation/setup
pins and evaluator identities remain unchanged. Full independent setup derivation and explicit
accepted-input artifact checks pass. Native ALL inner payloads and the pinned current native
history fixture remain accepted; old incompatible fixtures reject. Execution-envelope support is
current-only: parent VM/PVM root declarations reject before payload verification, including empty
and deferred precompile states. No old supported root, fixture rewrite, transport/schema change or
opaque protocol edit conceals this boundary. Explicit downstream root commitments need updating.

### Replay and completed gates

Every Rust compile/test/generation/package command had a fresh successful `systemd-ac-power`
gate. Rust/Cargo1.99.0; `RUSTUP_HOME=/tmp/air-stark-rustup`, `CARGO_HOME=/tmp/air-stark-cargo`,
`CARGO_TARGET_DIR=/tmp/air-stark-target`, incremental and dev/test debug output disabled. Replay
with those environment paths or an equivalent installed toolchain/cache. Logs are
`/tmp/miden-evaluator-delivery-sharing-*.log`; private orchestration scripts are not required.

```sh
systemd-ac-power && cargo +1.99.0 test -p miden-air-source -p miden-air --features miden-air-source/tooling --lib --tests --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --release --test core-lib stark:: --offline --locked -- --test-threads=2 --nocapture
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --features prover,recursive --release --lib --offline --locked -- --test-threads=2
systemd-ac-power && cargo +1.99.0 test -p miden-core-lib --release --lib proof_compatibility_roots_match_the_embedded_core_library --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-precompile-stark --test protocol_history --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-vm --features prover,recursive --release --lib proofs:: --offline --locked
systemd-ac-power && cargo +1.99.0 test -p miden-vm --release --test miden-cli --offline --locked delegated_and_batched_precompile_proving_composes_across_transport -- --test-threads=1
systemd-ac-power && cargo +1.99.0 test -p miden-stark --lib preprocessed::tests --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --offline --locked
systemd-ac-power && cargo +1.99.0 check -p miden-ace -p miden-stark -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark -p miden-vm --no-default-features --target wasm32-unknown-unknown --offline --locked
systemd-ac-power && cargo +1.99.0 package -p miden-stark -p miden-ace -p miden-air-source -p miden-air -p miden-vm-stark -p miden-precompile-stark --allow-dirty --no-verify --exclude-lockfile --offline --locked
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-codegen --offline --locked -- . --check --derive-setup
systemd-ac-power && cargo +1.99.0 run -p miden-air-source --features tooling --bin air-artifacts --offline --locked -- --check --accepted-pins crates/air/generated/protocol/accepted.json crates/air/generated/artifacts
systemd-ac-power && cargo +1.99.0 fmt --all -- --check
python3 tools/air-stark/check-boundaries.py
```

- Source351 + generated/integration44 pass: independent authored/compiled values, order/degree/
  geometry/security, raw all-eight streams, same-count periodic basis, global reduced body/pin/
  obsolete-copy failure before every shared/full/reduced managed write, deterministic universe.
- Recursive STARK136 pass: VM/all-eight PVM/native-MASM transcripts, fixed uint/curve enumeration,
  wire-order absorption/gather-before-store scatter, odd scalar tail/all buffered coin cells,
  gap+Alpha/root cells, stable order, setup/query/Horner, authentic same-count substitution,
  tampering, height/error/caller stack, VM/PVM coexistence, security and current actual roots.
  Same-context descriptor poison tests cover every80 cells, all masks/VM and outside sentinels.
- Native525 pass;26 existing expensive tests remain ignored. Exact ALL budget boundaries explicitly
  prove ALL to match independently modelled ALL heights; automatic minimal-union/import-before-
  budget behavior remains separately checked. Native history4 and embedded root1 pass.
- Facade15, delegated/batched transport composition1 and preprocessing retention/mapping2 pass.
  Facade checks retain ordered complete root aggregation/repetitions, membership, VM-auth/security/
  deferred error precedence and current-only root declarations for empty and deferred states.
- All seven no-default native and wasm targets pass. The boundary checker passes for six target
  packages/39 resolved packages; format and whitespace checks pass.
- All six offline package archives pass creation. Unpacked source/generated packages pass native
  and wasm no-default checks; packaged source tooling passes artifact verification using packaged
  accepted pins/artifacts, MASM freshness using shipped templates, and the global protected-write
  fixture. Archive src/templates/artifacts/protocol/tests inputs match checkout byte-for-byte:
  source229, generated38, STARK104, ACE28, VM-product16, PVM-product112. All six original manifests
  and READMEs also match; source ships all23 templates.

A final staged whitespace check exposed surplus trailing blank lines in the shared DEEP template
and output. They were normalized before commit. Generation, three shared-runtime lifecycle/
identity/cost tests, all six archives and all unpacked checks were refreshed; actual roots,
serialized MAST/package size and VM core rows remain as reported above. Final source totals include
this cleanup.

Unpacked checks use the existing local unpublished-support patch preparation, not public-registry
release verification. Preparation writes temporary patch configuration, support manifests and package locks. With the same
Cargo environment, replay preparation and run each following Cargo command behind its own fresh
AC gate (replace `CHECKOUT` and `UNPACKED` with absolute paths):

```sh
python3 tools/air-stark/prepare-unpacked.py --checkout CHECKOUT --archives /tmp/air-stark-target/package --output UNPACKED
# In each of UNPACKED/miden-air-source-1.0.0 and UNPACKED/miden-air-1.0.0:
systemd-ac-power && cargo +1.99.0 check --no-default-features --offline
systemd-ac-power && cargo +1.99.0 check --no-default-features --target wasm32-unknown-unknown --offline
# In UNPACKED/miden-air-source-1.0.0:
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-artifacts --offline -- --check --accepted-pins UNPACKED/miden-air-1.0.0/protocol/accepted.json UNPACKED/miden-air-1.0.0/artifacts
systemd-ac-power && cargo +1.99.0 run --no-default-features --features tooling --bin air-codegen --offline -- CHECKOUT --check
systemd-ac-power && cargo +1.99.0 test --no-default-features --features tooling --lib --offline codegen::constraints::tests::rejected_write_delivery_preserves_every_managed_output -- --exact
```

Initial failures were corrected structural harness locations, a template import newline, the
first-zero-store versus final-procref-store adapter, and the inherited ALL-model/minimal-selector
budget test mismatch. An early setup/freshness run raced the final template-newline edit and
rejected staleness; the final complete setup/freshness command passes. These partial/failed runs
are not counted as completed passes. No full workspace/all-feature/Windows run or public-registry
release verification is claimed; ignored expensive native proving tests remain outside this scope.
