#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod prover;

// EXPORTS
// ================================================================================================
pub use miden_core::{
    Word,
    advice::AdviceInputs,
    deferred::{PrecompileLimits, PrecompileWitness},
    program::{ExecutionClaim, InputError, Program, ProgramInfo, StackInputs, StackOutputs},
    proof::{ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof},
    serde::DeserializationError,
};
pub use miden_precompile_stark::prover::PrecompileProvingError;
pub use miden_processor::{
    ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness, FutureMaybeSend, Host,
    SyncHost, VmWitness,
};
pub use prover::{Prover, ProverError, prove_sync};
