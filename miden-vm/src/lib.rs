#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

extern crate alloc;

// EXPORTS
// ================================================================================================

pub use {
    miden_assembly as assembly,
    miden_assembly::Assembler,
    miden_assembly::ast::Module,
    miden_assembly::ast::ModuleKind,
    miden_assembly::diagnostics,
};
pub use {
    miden_core::Word,
    miden_core::ZERO,
    miden_core::crypto,
    miden_core::deferred::DeferredRoot,
    miden_core::deferred::IntegrityError,
    miden_core::deferred::PrecompileError,
    miden_core::deferred::PrecompileLimits,
    miden_core::deferred::PrecompileWitness,
    miden_core::deferred::PrecompileWitnessEntry,
    miden_core::deferred::PreparationError,
    miden_core::deferred::WorkClass,
    miden_core::deferred::WorkLimit,
    miden_core::field,
    miden_core::operations::Operation,
    miden_core::program::ExecutionClaim,
    miden_core::program::InputError,
    miden_core::program::KernelDescriptor,
    miden_core::program::Program,
    miden_core::program::ProgramInfo,
    miden_core::program::StackInputs,
    miden_core::program::StackOutputs,
    miden_core::proof::ExecutionProof,
    miden_core::proof::ExecutionProofCompatibility,
    miden_core::proof::ExecutionProofCompatibilityError,
    miden_core::proof::ExecutionProofError,
    miden_core::proof::HashFunction,
    miden_core::proof::PrecompileProof,
    miden_core::proof::PrecompileStatus,
    miden_core::proof::StarkProof,
    miden_core::proof::VmProof,
    miden_core::serde,
    miden_core::utils,
};
pub use {
    miden_core_lib::conjectured_security_estimator_root,
    miden_core_lib::proven_security_estimator_root,
};
pub use {
    miden_precompiles::CURVE_WORK,
    miden_precompiles::HASH_WORK,
    miden_precompiles::MSM_WORK,
    miden_precompiles::UINT_WORK,
    miden_precompiles::default_execution_precompile_limits,
    miden_precompiles::default_verification_precompile_limits,
};
pub use {
    miden_processor::BaseHost,
    miden_processor::DefaultHost,
    miden_processor::ExecutionError,
    miden_processor::ExecutionOptions,
    miden_processor::ExecutionOutput,
    miden_processor::ExecutionWitness,
    miden_processor::FastProcessor,
    miden_processor::FutureMaybeSend,
    miden_processor::Host,
    miden_processor::ProgramExecutor,
    miden_processor::SyncHost,
    miden_processor::VmWitness,
    miden_processor::advice,
    miden_processor::trace,
    miden_processor::trace::VmTrace,
};
pub use {
    miden_prover::PrecompileProvingError,
    miden_prover::Prover,
    miden_prover::ProverError,
    miden_prover::prove_sync,
};
pub use {
    miden_verifier::PrecompileVerificationError,
    miden_verifier::ProofSecurityParameters,
    miden_verifier::ProvenSecurityReport,
    miden_verifier::SecurityReport,
    miden_verifier::StarkVerificationError,
    miden_verifier::VerificationError,
    miden_verifier::VerificationOutcome,
    miden_verifier::Verifier,
};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
