# Ownership port decisions

Working notes for the trial port of #4069 onto the pinned #4040 base. Updated
2026-10-21. These notes distinguish agreed work from proposals; they are not a new
protocol design or a request to implement every future idea now.

## Checkpoint

- Worktree: `/home/adrian/.codex/worktrees/4055-on-4040/miden-vm`.
- Branch: `refactor-4055-on-4040`.
- Requested #4040 base: `979065f798568f902b9e30ac9c0188d91618d2ce`.
- Signed discussion checkpoint: `814579e00` (`refactor(air): separate
  authored relations from production adapters`).
- The AIR follow-up below was authorized after discussion and implemented
  as `07a41aec6` on top of this checkpoint. The subsequent shared Eidos tranche
  follows that commit.

## Agreed decisions since the checkpoint

### Preserve build-generated production degree metadata

Keep #4040's production degree tables derived from captured authored AIRs. Keep
source symbolic inference and the independent comparison checks. Do not copy
#4069's manually maintained source degree table or make production degree queries
perform symbolic inference.

Status: the checkpoint already implements this choice; no reversal is needed.

### Use a PVM newtype adapter

Replace the mirrored production `ChipletAir` enum and conversion matches with a
wrapper around the authored PVM AIR, matching the VM adapter pattern. Preserve
#4040's distinct generated PVM evaluation and generated degree dispatch. Reuse
source metadata, lookup and auxiliary-trace construction, and keep all existing
source/generated drift checks independent.

Status: implemented in the AIR follow-up. Production constructors/matches and
generated degree dispatch are adapted; evaluator generation and captured values
are preserved. The small copyable degree-dispatch argument is passed by value.

### Remove the public VM ProofOrder wrapper

Remove VM `ProofOrder` and its public permutation-count constant rather than
relocating them. No production runtime or build consumer uses this wrapper.

Keep source canonical identities/order and production wrapped `AIRS`. Adapt the
existing tests to instance indices. Reuse the core-library test ordering helper
and generic ACE permutation helpers. Preserve the substantive checks: all 24 VM
permutations and distinct fold results, tie-breaking, staged inverse maps,
nonidentity cases, fold coefficients, forged-height behavior, scatter-routing
mutation rejection, and canonical identity pins. Keep independent test oracles
independent of the native engine's ordering implementation.

Status: implemented in the AIR follow-up.

### Generate derived AIR facts; add an inspectable summary later

Derived degrees, counts, shapes, and geometry should be outputs of build-time
derivation from authored AIRs, not manually synchronized tables in implementation
code. Production AIR exposes compiled metadata through a stable runtime API.

A future checked-in summary should show the actual derived values for review,
with a freshness check. It should be an output of the derivation, not another
handwritten input. The user explicitly deferred this artifact work; do not add a
summary generator or expand the generation framework during this port solely for
that future feature.

Keep the current port structured to support that direction. Authored parameters
and explicitly accepted protocol identity pins remain distinct from automatically
derived facts. No decision was made to eliminate production's normal dependency
on source AIR or to generate every auxiliary-trace/lookup implementation.

Status: direction agreed; future summary implementation deferred. The existing
build-generated production metadata remains in place. Placement of remaining
runtime geometry helpers must respect this direction without introducing a new
policy framework.

## Statement ownership decision

Original #4040 behavior, retained by the checkpoint before this follow-up:

- Source owns individual equations, input schemas, canonical identities, lookup
  and boundary definitions, auxiliary-trace construction, complete VM claim
  observation, and complete VM/PVM external assertions.
- Production provides generated evaluator/degree adapters and delegates complete
  statement hooks to source. It owns accepted configuration and identity pins,
  embedded circuit delivery, and generated security metadata.
- Source PVM `RelationProtocol`/`AuxBoundaryPlan` connects native reduction with
  typed verifier generation. Preserve that connection.
- Relation-specific verifier rendering and authored MASM/templates also live
  outside the source AIR crate; do not claim all relation protocol code is
  currently centralized in source.

#4069 moved complete statements to production. That proposal has NOT been
approved for this port. Moving those hooks does not change the normal crate
dependency graph or remove a duplicate algorithm: today's production wrappers
forward to the source implementation.

The user prefers relation logic in source. The agreed refinement is to keep
semantic functions there and expose them through production `MultiAir` types, as
detailed below. Generated evaluator/metadata ownership does not require moving
relation semantics into production.

### Digest dependency findings

The current implementation already supports source-owned complete statements
with production-owned accepted digest values. The source hooks receive a
challenger and append statement values; they do not import the relation digest.
Production configuration initializes that challenger with the accepted digest
before the engine calls the statement hook. Keeping the hooks in source creates
no source-to-production dependency.

The circuit compiler computes the instruction commitment, and the generic STARK
configuration helper computes:

```text
circuit_digest = Eidos(ACE instructions)
relation_digest = Eidos([PROTOCOL_ID, circuit_digest[0..4]])
```

Today the AIR build scripts emit evaluator, degree, geometry, and instruction
artifacts. Accepted Rust circuit/relation/setup values are checked-in pins;
independent checks recompute and compare them. Verifier generation also computes
candidate digests for MASM. It does not silently update accepted identities.

Complete statement observation and external assertions are not captured into the
ACE circuit. Their semantics are versioned explicitly by `PROTOCOL_ID` and
protected by existing native/MASM checks. Moving their implementation to another
crate would not improve digest coverage. Automatically hashing or compiling
those semantics would be a separate protocol change outside this port.

These findings support retaining current source statement hooks in response to
the user's preference. They do not require reversing the earlier production
preset/protocol-ID ownership decision or changing any digest value.

### Approved split: source functions, production MultiAir types

The user further distinguished relation logic from the concrete `MultiAir`
definition: keep the relation functions in source, while production owns the
`MultiAir` types that expose generated production evaluators. This split was
approved for the AIR follow-up. Relation function bodies remain in source.

The bounded implementation extracts existing source hook bodies into functions,
including VM observation, auxiliary-input limits, and VM/PVM external
validation/reduction. Production `MultiAir` trait implementations call those
functions. PVM retains the existing source boundary plan and reduction semantics,
without storing a second complete source `ChipletMultiAir` and AIR vector.

Source tests exercise the functions directly. The independent authored setup
check uses a local test-only AIR-list adapter, while complete ordinary source
`MultiAir` types are removed. STARK's existing default PVM statement encoding and
all native/MASM checks are retained. No new protocol abstraction is introduced.

Neither the current VM/PVM `MultiAir` constructors nor `Statement::new` consumes
a digest. The digest is needed for challenger initialization. Therefore this
split is an ownership/API choice, not a requirement imposed by digest generation.

`accepted_relation_digest` in the discussion was an illustrative variable name;
the actual VM constant is `vm::config::RELATION_DIGEST`, and PVM uses its `PINS`
value. Their hashes are calculated by code; acceptance and editing of the Rust
pin literals are explicit maintainer actions. There is currently no dedicated
command that silently updates those Rust pins. `make regenerate-verifiers`
regenerates MASM, while `make check-verifiers` also executes tests and must stay
deferred until the end of this implementation stack.

## Remaining port work

The completed AIR follow-up combines the PVM newtype and VM `ProofOrder`
removal with the agreed statement direction: source owns semantic functions,
while production owns concrete `MultiAir` adapters. Its scope was explained before
implementation started; it does not move semantic function bodies to production.

Neutral shared Eidos is now implemented, reusing #4069's separation of common
equations/layout/encoding from VM/PVM interface bindings. The extraction preserves
#4040's captured expression forms, instruction identities, and existing checks;
no design deviation required a new decision. This completes the remaining
substantial implemented ownership delta from #4069. Test execution and final
stack validation remain deferred; this is not a claim that integration has been
fully tested.

The checked-in AIR summary is deferred. Expanded artifact generation, changes to
identity acceptance, and automatic binding of statement semantics are outside
this port and are not approved implementation work. Keep existing generated
runtime metadata and cheap helper reuse; do not expand this port merely to
realize the future summary. Backend decisions remain deferred as listed below.

## AIR follow-up validation

- `make lint` passes across all workspace targets and features, including the
  pinned formatter and cargo-shear. There are 25 nonfatal advisory warnings.
- No-default-feature library checks pass for source AIR, production AIR,
  processor, prover, verifier, precompile prover, and precompile verifier.
- Ordinary runtime dependency trees exclude compiler tooling and source/ACE
  compiler feature opt-ins. Removing the VM wrapper also removes production
  AIR's unused normal direct ACE dependency; build and test dependencies remain.
- Nine of ten saved build artifacts are byte-identical to the checkpoint. The
  PVM degree file changes only the match target to the wrapped source enum and
  passes the small copyable adapter by value. Degree values are unchanged.
- Both embedded instruction streams, VM configuration, PVM policy, PVM runtime
  protocol/pins/cache code, verifier-root pins, and both lockfiles are unchanged.
- Independent reviews and static body comparisons preserve statement validation,
  observation, weighting, and boundary arithmetic. All nine VM and four PVM
  source tests retain their fixtures and assertions through function-call
  migration; all-order ACE and recursive-verifier checks remain in place.
- Locked offline core-fuzz manifest metadata (without dependency expansion) and
  diff whitespace checks pass.

These are compilation, lint, dependency, artifact, and static review checks.
Tests have not been executed; execution remains deferred until the stack ends.

## Shared Eidos tranche

`shared::eidos` owns the common compression equations, physical layout, narrow
lookup encoding, rotation relations, and callback-based trace writer. Its code
does not import VM or precompile modules. Both relation adapters use this layer
directly, replacing the previous facade over a shared module that still contained
VM interface code.

The VM adapter owns its controller/AEAD bus messages, two footer lookup columns,
mode and multiplicity columns, footer interface constraints, mode validation, and
mode-aware trace helpers. Its public trace API remains available at the existing
VM paths used by the processor. The existing VM-oriented tests and support move
with this adapter, including PVM's cross-interface constraint checks.

This is an ownership extraction and import migration. Constraint, lookup, and
trace function bodies retain their arithmetic and call order. In particular:

- VM narrow lookups retain negative table multiplicities and `DoubleAnd` XOR;
  PVM retains positive multiplicities and `RepeatedSubtraction` XOR.
- VM keeps its original full-footer assertion order, narrow columns followed by
  footer columns 18 and 19, and inactive auxiliary-column constraints.
- Trace validation and footer callback placement are unchanged. Shared helpers
  reused by the VM adapter become crate-visible rather than being duplicated.

Neither generator nor production adapter requires an interface rewrite. The
canonical authored AIR lists, generated VM/PVM evaluators, build-derived metadata,
precompiled ACE delivery, accepted pins, and tracked verifier artifacts retain
their existing owners.

Validation: `make lint` passes, including all-feature/all-target workspace Clippy,
pinned-nightly formatting, and cargo-shear's 25 nonfatal advisory warnings. All ten
saved generated outputs are byte-identical to `07a41aec6`, including both evaluator
modules, both ACE instruction streams, degree tables, shapes, raw widths, and PVM
protocol metadata. Static comparisons preserve the extracted bodies and moved
test fixtures. No-default-feature library checks also pass for source AIR,
production AIR, processor, prover, verifier, precompile prover, and precompile
verifier. Test execution remains deferred as requested.

If statement ownership is reconsidered, preserve observation order, input
validation, trace-length weighting, once-per-proof boundary corrections, native
and MASM checks, and the independent setup oracle built from authored AIRs. Do
not invent a new protocol-plan abstraction.

Current PCS presets and protocol IDs remain production-owned as agreed in the
earlier STARK tranche. Do not silently reinterpret the latest preference as
authorization to move those policies or change identity pins.

## Continuing constraints

- Discuss each logical implementation commit before starting it; signed commits
  must pass lints. Stop after each completed commit.
- Test execution remains deferred until the implementation stack is complete;
  compiling test targets during linting is allowed.
- Preserve #4040's precompiled ACE delivery and generation/checking paths.
- Backend input boundaries, orchestration, standalone verifier packaging, and
  processor budgeting ownership remain open and outside this ownership port.
- Do not push, publish, edit external PRs, or contact existing threads.
