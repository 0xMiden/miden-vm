//! # ACE, AIR, and STARK API migration
//!
//! The v1.0.0-rc.2 ACE compiler cleanup removes redundant public export paths and makes
//! code-owned compilation return values directly. Import each API from its canonical home:
//!
//! | API | Canonical home |
//! | --- | --- |
//! | Encoded circuits, recursive circuit data, input layouts, and instruction codec | `miden_ace` and `miden_ace::instruction` |
//! | Generic AIR capture, circuit compilation, and MASM rendering | `miden_ace::compiler` (enable `compiler`) |
//! | Authored constraints, trace schemas, public inputs, and relation boundaries | `miden_air_definitions::{vm, precompiles}` |
//! | VM/PVM capture and relation-specific circuit builders | `miden_air_definitions::compiler::{vm, precompiles}` (enable `compiler`) |
//! | Production AIR adapters and generated protocol artifacts | `miden_air::{vm, precompiles}` |
//! | Generic AIR traits, PCS parameters, configurations, and security interfaces | `miden_stark` and its `air`, `pcs`, `config`, and `security` modules |
//! | VM field primitives, field traits, and serialization interfaces | `miden_core`, `miden_core::field`, and `miden_core::serde` |
//!
//! The AIR facades remain useful: import production `MidenAir` and `MidenMultiAir` from
//! `miden_air::vm`, and `ChipletAir` and `ChipletMultiAir` from `miden_air::precompiles`.
//! Use the authored AIRs when capturing constraints for compilation. Normal runtime builds
//! continue to support `no_std` with `alloc`; add the `compiler` feature only where capture or
//! code generation is needed.
//!
//! ## Replacement imports
//!
//! Add a direct Cargo dependency on the crate supplying an API you use. Importing ACE runtime
//! types requires `miden-ace`, without enabling its `compiler` feature.
//!
//! | Removed public path | Replacement |
//! | --- | --- |
//! | `miden_air::vm::Felt` | `miden_core::Felt` |
//! | `miden_air::vm::DeserializationError` | `miden_core::serde::DeserializationError` |
//! | `miden_air::vm::PublicInputs` | `miden_air_definitions::vm::PublicInputs` |
//! | `miden_air::vm::{AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir, LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement}` | The same names under `miden_stark::air` |
//! | `miden_air::vm::StarkConfig` | `miden_stark::StarkConfig` |
//! | `miden_air::vm::debug` | `miden_stark::debug` |
//! | `miden_air::vm::PcsParams`, `miden_air::vm::config::PcsParams`, `miden_air::precompiles::policy::PcsParams` | `miden_stark::pcs::PcsParams` |
//! | `miden_air::vm::config::RelationDigest` | `miden_stark::config::RelationDigest` |
//! | `miden_air::vm::security::{AirShape, LookupShape}`, `miden_air::precompiles::protocol::{AirShape, LookupShape}` | `miden_stark::security::{AirShape, LookupShape}` |
//! | `miden_air::precompiles::air::{ChipletAir, ChipletMultiAir, NUM_CHIPLETS}` | `miden_air::precompiles::{ChipletAir, ChipletMultiAir, NUM_CHIPLETS}` |
//! | `miden_air::precompiles::PVM_RELATION_DIGEST` | `miden_air::precompiles::protocol::PVM_RELATION_DIGEST` |
//! | `miden_air_definitions::compiler::vm::{CapturedAir, CompiledRelation, LayoutKind}` | `miden_ace::compiler::{CapturedAir, CompiledRelation, LayoutKind}` |
//! | `miden_air_definitions::precompiles::ace::LMCS_ALIGNMENT` | `miden_air_definitions::precompiles::relation::LMCS_ALIGNMENT` |
//!
//! The authored VM module also drops its generic core and STARK re-exports:
//!
//! | Removed public path | Replacement |
//! | --- | --- |
//! | `miden_air_definitions::vm::Felt` | `miden_core::Felt` |
//! | `miden_air_definitions::vm::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable}` | The same names under `miden_core::serde` |
//! | `miden_air_definitions::vm::ToElements` | `miden_core::utils::ToElements` |
//! | `miden_air_definitions::vm::{AirBuilder, BaseAir, ConstraintCounts, ConstraintDegrees, ExtensionBuilder, LiftedAir, LiftedAirBuilder, MultiAir, PermutationAirBuilder, ProverStatement, Statement}` | The same names under `miden_stark::air` |
//! | `miden_air_definitions::vm::{StarkConfig, debug}` | The same names under `miden_stark` |
//! | `miden_air_definitions::vm::PcsParams` | `miden_stark::pcs::PcsParams` |
//! | `miden_air_definitions::vm::trace::chiplets::hasher::Word` | `miden_core::Word` |
//!
//! The `miden_air_definitions::{vm, precompiles}::ace` modules are removed. Import the runtime
//! type as `miden_ace::RecursiveAceCircuit`. This also replaces these forwarded names:
//!
//! - `miden_air_definitions::vm::ace::RecursiveAceCircuit`
//! - `miden_air_definitions::precompiles::ace::PvmRecursiveAceCircuit`
//! - `miden_air::vm::ace::RecursiveAceCircuit`
//! - `miden_air::precompiles::protocol::PvmRecursiveAceCircuit`
//! - `miden_vm_stark::setup::ace::RecursiveAceCircuit`
//!
//! Use `miden_air::precompiles::protocol` for PVM circuit, relation, and setup pins. Generic
//! compiler types live under `miden_ace::compiler`, even when a relation-specific builder
//! returns them.
//!
//! ## STARK backend imports
//!
//! The VM and PVM backends retain relation-specific proving, verification, setup, and security
//! functions. Import generic types and execution data from their owners:
//!
//! | Removed public path | Replacement |
//! | --- | --- |
//! | `miden_vm_stark::VmTrace` | `miden_air_definitions::vm::VmTrace` |
//! | `miden_vm_stark::Word`, `miden_precompiles_stark::Word` | `miden_core::Word` |
//! | `miden_vm_stark::AdviceInputs`, `miden_precompiles_stark::AdviceInputs` | `miden_core::advice::AdviceInputs` |
//! | `miden_vm_stark::ExecutionClaim` | `miden_core::program::ExecutionClaim` |
//! | `miden_vm_stark::{ExecutionProof, HashFunction, VmProof}` | The same names under `miden_core::proof` |
//! | `miden_precompiles_stark::{DeferredClaim, DeferredRoot, PrecompileLimits, PrecompileWitness}` | The same names under `miden_core::deferred` |
//! | `miden_precompiles_stark::{HashFunction, PrecompileProof, StarkProof}`, `miden_precompiles_stark::prover::{HashFunction, PrecompileProof, StarkProof}` | The same names under `miden_core::proof` |
//! | `miden_precompiles_stark::ProofSecurityParameters` | `miden_stark::security::ProofSecurityParameters` |
//! | `miden_vm_stark::memory::{ProverMemoryModel, ProvingBudget}` | `miden_stark::memory::{ProverMemoryModel, ProvingBudget}` |
//! | `miden_vm_stark::security::{AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, ProvenSecurityReport, SecurityReport, SecurityTerm}` | The same names under `miden_stark::security` |
//! | `miden_precompiles_stark::setup::security::{AirShape, InstanceShape, LookupShape, ProofSecurityParameters, ProtocolParams, ProvenSecurityReport, SecurityReport, SecurityTerm}` | The same names under `miden_stark::security` |
//! | `miden_vm_stark::security::PcsParams`, `miden_precompiles_stark::setup::security::PcsParams` | `miden_stark::pcs::PcsParams` |
//! | `miden_vm_stark::setup::config::{EidosConfig, RelationDigest}`, `miden_precompiles_stark::setup::config::{EidosConfig, RelationDigest}` | `miden_stark::config::{EidosConfig, RelationDigest}` |
//! | `miden_vm_stark::setup::config::PcsParams`, `miden_precompiles_stark::setup::config::PcsParams` | `miden_stark::pcs::PcsParams` |
//!
//! Keep using the backend's `setup::config::eidos_config` factory when constructing a
//! relation configuration: it supplies the VM or PVM transcript domain. Its behavior is
//! relation-specific even though its argument and return types come from `miden_stark`.
//!
//! ## Compiler return values and failures
//!
//! `miden_ace::AceError` is removed. Code-owned AIR definitions and compiler configurations
//! must satisfy the documented compiler invariants. Invalid definitions or configurations
//! can panic; these APIs no longer return a recoverable compilation error. Evaluation of
//! guest-supplied circuits remains checked by the processor.
//!
//! Remove `?`, `.unwrap()`, `.expect()`, and `AceError` handling from calls that now return
//! their value directly:
//!
//! | API | Return value |
//! | --- | --- |
//! | `miden_ace::compiler::{build_ace_dag_for_air, build_ace_circuit_for_air, build_canonical_multi_air_ace_circuit}` | `AceArtifacts` or `AceCircuit`, as appropriate |
//! | `miden_ace::compiler::CapturedAir::new` | `CapturedAir` |
//! | `miden_ace::compiler::CompiledRelation::from_captured` | `CompiledRelation` |
//! | `miden_ace::compiler::CompiledRelation::build_circuit` | `AceCircuit` |
//! | `miden_ace::compiler::emit_circuit` | `AceCircuit` |
//! | `miden_ace::compiler::AceCircuit::eval` | The extension-field value |
//! | `miden_ace::compiler::AceCircuit::to_ace` | `EncodedCircuit` |
//! | `miden_ace::compiler::{render_masm_aux_trace, render_masm_constraints_eval, render_proof_order_maps}` | `String` |
//! | `miden_ace::compiler::MasmMemoryLayout::new` | `MasmMemoryLayout` |
//! | `miden_ace::compiler::MasmMemoryLayout::input_ptr` | `usize` |
//! | `miden_ace::compiler::OodScatterPlan::new` | `OodScatterPlan` |
//! | `miden_ace::compiler::testing::eval_dag` | The extension-field value |
//! | `miden_air_definitions::compiler::vm::{build_canonical_multi_air_ace_circuit, build_recursive_verifier_ace_circuit}` | `AceCircuit` or `RecursiveAceCircuit`, respectively |
//! | `miden_air_definitions::compiler::precompiles::{build_canonical_precompile_ace_circuit, build_pvm_recursive_verifier_ace_circuit}` | `AceCircuit` or `RecursiveAceCircuit`, respectively |
//! | `miden_air_definitions::compiler::precompiles::CapturedPvmRelation::{new, compile}` | `CapturedPvmRelation` or `CompiledRelation`, respectively |
//!
//! For example, compile and encode an authored AIR with the current API:
//!
//! ```rust,ignore
//! use miden_ace::{
//!     RecursiveAceCircuit,
//!     compiler::{AceConfig, LayoutKind, build_ace_circuit_for_air},
//! };
//! use miden_air_definitions::vm::MidenAir;
//!
//! let config = AceConfig { num_quotient_chunks: 8, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air(&MidenAir::CORE, config);
//! let encoded = circuit.to_ace();
//! let recursive = RecursiveAceCircuit::from(encoded);
//! ```
//!
//! `RecursiveAceCircuit` implements `From<EncodedCircuit>`; use `RecursiveAceCircuit::from`
//! or `.into()`. The blanket `TryFrom` conversion now has error type `Infallible`, so code
//! that names the old conversion's `AceError` must change.
//!
//! `MasmMemoryLayout::input_ptr` computes the address of a compiler-owned input index.
//! Callers must supply a valid index from the matching `InputLayout`, or `layout.total_inputs`
//! to address the start of the instruction stream. The method no longer validates arbitrary
//! indices or returns an error.
//!
//! ## Geometry and relation builders
//!
//! Remove `num_randomness` from `miden_ace::InputCounts` construction and from accesses to
//! `miden_ace::compiler::RelationGeometry`. The compiler uses the fixed alpha/beta challenge
//! pair. Captured AIRs must declare exactly two randomness challenges.
//!
//! Replace `RelationGeometry::validate_masm_layout(&layout)?` with
//! `RelationGeometry::assert_masm_compatible()`. This checks the relation's supported MASM
//! shape. Derive the circuit and layout from the same `CompiledRelation`;
//! `assert_masm_compatible` does not compare a separately supplied layout with the relation.
//!
//! `miden_air_definitions::compiler::vm::recursive_verifier_ace_config` is removed. Use
//! `build_recursive_verifier_ace_circuit()` to obtain the encoded canonical VM circuit.
//! For custom tooling, capture the authored `vm::AIRS` with `CapturedAir`, derive a
//! `CompiledRelation` with the intended trace alignment, and use its geometry and
//! `build_circuit(LayoutKind::Masm)` method. The quotient geometry comes from the captures.
//!
//! ## Owned DAGs and periodic columns
//!
//! Keep a `miden_ace::compiler::AceDag` when transferring a built DAG. The `DagSnapshot`
//! type, `AceDag::into_snapshot`, and `DagBuilder::{from_nodes, from_snapshot, into_nodes}`
//! are removed. Finish a builder with `build(root)` and resume it with
//! `DagBuilder::from_dag(dag)`. The owned DAG preserves node provenance, including DAGs that
//! contain only leaves.
//!
//! Node IDs from the owned DAG remain valid when resuming it. If `AceDag::compact()` removes
//! nodes, it invalidates the old IDs; obtain IDs from the compacted DAG afterward. Arbitrary
//! raw-node import has no supported replacement.
//!
//! `PeriodicColumnData::from_periodic_columns` now borrows `&[Vec<F>]`; pass
//! `&periodic_columns`. The testing-only `build_verifier_dag` accepts
//! `&PeriodicColumnData` instead of an `Option`. For an AIR without periodic columns,
//! construct the periodic data from an empty slice.
//!
//! The testing export `miden_ace::compiler::build_verifier_dag_from_ir` is removed without a
//! public raw-IR replacement. Compile the authored AIR with `build_ace_dag_for_air` or
//! `build_ace_circuit_for_air`, or use `CompiledRelation::build_circuit` for captured AIRs.
//!
//! ## Constraint IR paths
//!
//! The `miden_constraint_compiler::ir::{analyze, capture, graph}` implementation modules are
//! private. Import their public interfaces from `miden_constraint_compiler::ir`:
//!
//! | Old module route | Public names at `miden_constraint_compiler::ir` |
//! | --- | --- |
//! | `ir::analyze` | `OpCounts`, `op_counts` |
//! | `ir::capture` | `CapturedConstraints`, `capture`, `capture_into`, `capture_into_with` |
//! | `ir::graph` | `Class`, `Graph`, `GraphBuilder`, `Leaf`, `Node`, `NodeId`, `OpKind` |
