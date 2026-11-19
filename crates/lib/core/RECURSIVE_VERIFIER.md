# Recursive verifier design principles

The [VM](asm/sys/vm/mod.masm) and [PVM](asm/sys/pvm/mod.masm) entrypoints supply statements and
relation parameters to the [generic STARK verifier](asm/stark/verifier.masm). Its entry contract
defines the required state and five hooks: public inputs, auxiliary-boundary checks, OOD routing,
constraint evaluation, and DEEP queries.

## Share algorithms; specialize geometry

The generic STARK verifier owns the transcript and verification sequence and calls shared FRI
code. Shared `miden-ace` renderers generate the LogUp, OOD, constraint-evaluation, and DEEP hooks
from relation metadata. Widths, AIR counts, message widths, and preprocessed-tree parameters are
compile-time inputs to these algorithms. Generic MASM must not depend on `sys/vm` or `sys/pvm`.

Relation adapters own statement encoding, trace-height checks, external LogUp boundary corrections,
and the meaning of canonical AIR indices. The common LogUp stage absorbs and weights the auxiliary
sums and asserts that their total plus the relation's boundary correction is zero. The common DEEP
reader hashes, folds, and authenticates each opened row using generated group parameters.

## Derive geometry from native definitions

The generators derive widths, quotient geometry, security metadata, and the ACE circuit from
captured native AIRs and protocol configuration. Cargo builds native evaluators and ACE streams
into `OUT_DIR`. Library builds assemble tracked MASM; regenerate it explicitly from these sources:

| Responsibility | Source |
|---|---|
| AIRs, statements, and bus-message definitions | [AIR source](../../air/source/src/) |
| Common hook renderers and templates | [miden-ace compiler](../../ace/src/compiler/) |
| VM parameters, ACE addresses, and shared FRI parameters | [VM generator](src/constraints_regen.rs) |
| PVM parameters, layout, and boundary instructions | [PVM generator and templates](../../stark/precompiles/src/recursive/) |

An AIR or statement change still requires reviewing the handwritten adapters: `mod.masm`,
`public_inputs.masm`, layout field aliases, and allocation extents in the memory audit. PVM boundary
changes also require reviewing the [fixed-message catalogue](../../air/source/src/precompiles/fixed.rs)
and its generator templates. Keep these dependencies explicit rather than duplicating derived counts.

Shared FRI parameters come from both native presets. Regeneration requires folding factor four,
a common remainder bound, and enough workspace for layers and coefficients. Remainder sizes and
streaming counts are independent of LDE blowup; the complete recursive verifier uses blowup eight,
fixed by `LOG_BLOWUP_FACTOR` in `stark/constants.masm`.

## Give memory a clear owner and checked bounds

Each `verify_proof` call runs in a fresh execution context. Shared and relation-owned allocations
must be disjoint within that context; separate calls can reuse the same addresses.

The [shared layout](asm/stark/constants.masm) owns protocol state, lookup challenges, per-AIR
arrays, and OOD dispatch storage. Relation layouts own statement fields and boundary scratch.
Boundaries within the ACE input vector are generated from its native `InputLayout`. Import
addresses directly from their owning module. Derive OOD dispatch readers and writers from the
same scatter plan.

Fixed anchors leave ample room for circuit growth without moving unrelated state or query scratch.
The ACE challenge and query-row anchors are `12 * 2^20` felts apart; unused address space adds no
VM operations or trace rows. Keep allocation capacity separate from the live AIR count: shared
arrays reserve sixteen entries, while the proof-order encoding supports twelve AIRs because its
permutation tag must fit in a `u32`.

The [placement constructor](../../ace/src/compiler/masm_memory.rs) checks relation extents and
alignment against the shared anchors. The [memory audit](tests/stark_asserts/memory_layout.rs)
checks coverage and disjointness, alias bounds, and the full width of immediate memory accesses.
Documented gaps are not allocations. Dynamic addresses and streaming lengths also need bounds
established by geometry checks and procedure contracts, with execution tests covering their use.

Keep the memory map beside the constants. Sizes count base-field felts and ranges exclude their
upper endpoint; word accesses require four-felt alignment and streaming regions require eight.
Preserve the literal declarations and capacity-comment syntax identified there: generators read them.

## Preserve verification contracts

Procedure contracts should identify caller-owned stack values, memory inputs and outputs, and
scratch lifetimes. Explain non-obvious stack manipulations where they occur. When changing shared
code, check these protocol invariants in both relations:

- Required properties of advice-derived witnesses are enforced by AIR-constrained checks.
- Transcript observations and challenge draws match the native verifier.
- Proof-order maps remain complete, height-sorted permutations; every AIR receives its selectors
  and constraint-folding coefficient.
- Query values remain associated with their indices through DEEP and FRI. Every opened row is
  checked against its authenticated leaf digest, and final folds match remainder evaluations.

Native/MASM parity tests should compare intermediate values where acceptance alone could hide
an error. Rejection tests should identify the intended guard, so a later failure cannot conceal
missing authentication. For optimizations, report cycles per proof and all AIR row counts;
unchanged padded trace dimensions do not establish unchanged prover runtime.

## Review identity changes explicitly

Relation digests, ACE circuit digests, and setup commitments are pinned in the native
[VM configuration](../../air/generated/src/vm/config.rs) and
[PVM protocol](../../air/generated/src/precompiles/protocol.rs). The generators compare compiled
circuit and relation digests with these pins and fail on a mismatch. They read setup commitments
as trusted inputs and never rewrite the pins. Native AIR and STARK tests independently recompute
the identities and setup commitments from authored AIRs and tables.

An intentional relation change updates its pins as an explicit reviewable edit before MASM
regeneration. Check assembled verifier roots against [the root pins](../../../core/src/proof.rs)
and update those pins for intended root changes.

## Change and validate

Regenerate the affected relation from the repository root, or both for shared changes:

| Relation | Regenerate | Check freshness |
|---|---|---|
| VM, including shared FRI parameters | `make regenerate-constraints` | `make check-constraints` |
| PVM | `make regenerate-pvm-constants` | `make check-pvm-constants` |

Inspect generated values and instruction order. Update affected stack contracts, memory maps,
and audit extents. For MASM documentation or export changes, regenerate tracked documentation
with `MIDEN_BUILD_LIB_DOCS=1 cargo build -p miden-core-lib`; a second build should leave it unchanged.

Run relevant native/MASM parity, rejection, layout, and root-consistency tests. Before integration,
run the repository gates, which include the documentation build:

```sh
make format-check
make clippy
make test NEXTEST_PROFILE=ci
```
