# AIR and proof ownership decisions

This record tracks the agreed ownership boundaries for the
[#4055 refactor](https://github.com/0xMiden/miden-vm/issues/4055). It describes the target
architecture and the migration steps; some target owners have not been introduced yet.

## Scope

[Huitseeker accepted package ownership changes in objectives 1, 2, 3, and 7](https://github.com/0xMiden/miden-vm/issues/4055#issuecomment-6298892386):
shared STARK ownership, runtime ACE extraction, authored/production AIR organization, and
relation implementation consolidation. Keep the existing constraint compiler and existing
verification protocol, including handwritten Rust and MASM protocol code.

Moving existing relation-specific ACE construction into optional authored tooling is part of
this ownership work. It does not require a new compiler, protocol-plan abstraction, or complete
MASM renderer. Preserve independent evaluator, statement, layout, and native/MASM checks.

The current stack does not adopt binary ACE delivery, a new generated-Rust delivery mechanism,
new relations, proof-format changes, accepted-identity changes, or verifier optimizations.

## Agreed owners

| Responsibility | Target owner | Migration decision |
| --- | --- | --- |
| Authored VM/PVM definitions and shared equations | One `miden-air-source` crate, with `vm`, `precompile`, and `shared` modules | Introduce VM source first; bring PVM and neutral shared support into the same organization afterward. |
| Production evaluation and derived artifacts | `miden-air`, with relation modules | Keep the existing generated evaluator and compiler model. |
| VM `PublicInputs` and AIR-facing packing | `miden-air-source::vm` | Move the existing type and packing beside the authored input schema. |
| VM bus definitions and boundary contributions | `miden-air-source::vm` | Supply the relation contributions used by the final cross-AIR check. |
| `MidenMultiAir` and its complete `MultiAir` implementation | VM STARK backend | Move the type, transcript observation, input validation, and aggregate external LogUp check together during backend consolidation. |
| AIR identities, stable instance order, and relation-specific `ProofOrder` | `miden-air-source::vm` | Keep height sorting, permutation tags, and proof-order mappings together with the stable instance order. Generic ranking/rendering mechanisms retain their shared owners. |
| Stored `AIR_SHAPE` and `LOOKUP_SHAPE` metadata | `miden-air` | Preserve current stored values and independent checks. Emitting this metadata through generation is later work. |
| Accepted relation, ACE circuit, and fixed preprocessed identity pins | `miden-air` | Keep canonical identities beside production artifacts. Backend configuration consumes the pins; preserve every current value. |
| VM-specific runtime security reporting | VM STARK backend | Construct reports from verified proof parameters and production metadata; reusable formulas remain shared. Defer the move to backend consolidation. |
| Relation-specific ACE construction | Optional `miden-air-source` codegen modules | Move existing handwritten capture and circuit construction. Ordinary source consumers do not enable the compiler. |
| Relation configuration and runtime caches | Corresponding STARK backend | The backend selects protocol configuration and owns setup/circuit caches. Leave current owners in place until the backend commits. |
| Processor memory budgeting and its PCS-parameter dependency | Decide implementation during backend consolidation | Leave configuration and budgeting in their current owners for this AIR split; do not move presets into authored source to force an early processor cutover. |
| MASM delivery and assembly | Core-lib tooling | Preserve the existing workflow during ownership migration. |

Shared configuration factories already live in `miden-stark::config`. Relation-specific PCS
defaults remain separate choices, even where VM and PVM currently use identical values.
The future relation implementation crates are referred to here as `miden-vm-stark` and
`miden-precompiles-stark`; final packaging remains subject to the backend checkpoints.

## Deferred decisions and work

- Decide standalone-verifier packaging as late as possible. Preserve the ability to use a verifier
  separately during the earlier refactor; retiring its entrypoint is not already agreed.
- Resolve the processor/configuration/memory-budget dependency when the backend ownership is
  concrete, avoiding a processor-to-backend dependency cycle.
- Consider generation of stored degrees and security-shape metadata in a later change. Production
  AIR is its intended destination; this ownership commit preserves current production and checks.
- Protocol plans and a complete MASM renderer remain deferred. Broader artifact delivery and public
  facade redesign require their own agreed scope.

## Implementation checkpoints

| Commit | Completed work |
| --- | --- |
| `448e5b10a` | Mechanical relocation of AIR, STARK, and ACE crates. |
| `51bbaa741` | Crypto/STARK dependency direction and stateful hashing ownership. |
| `14973c083` | Shared AIR contracts, transcript, lookup support, and configuration factories in `miden-stark`. |
| `f5d348c98` | ACE runtime/compiler separation and shared processor instruction codec. |
| `005ec4dcb` | Authored VM AIR and optional ACE construction in `miden-air-source::vm`, with production evaluation and artifacts in `miden-air::vm`. |

The VM and precompile AIR splits apply the source/production owners above. The precompile
relation continues to evaluate its authored AIRs directly; it does not gain a generated Rust
evaluator. Both relations use neutral Eidos support in `miden-air-source::shared::eidos`, while
retaining their own interfaces and bus namespaces. Canonical precompile identity pins live in
`miden-air::precompile::protocol`; regeneration retains its existing compiler and MASM outputs.
Configuration, memory budgeting,
statement implementation, reporting, and cache relocation remain for the backend commits.
Run lints before each commit, defer test execution
until the end of the stack, and stop for discussion before starting the next commit.
