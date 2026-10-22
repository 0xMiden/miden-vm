#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod prover;

// EXPORTS
// ================================================================================================
pub use miden_air::vm::{MidenAir, PublicInputs};
pub use miden_core::{
    proof::{ExecutionProof, HashFunction, PrecompileProof, PrecompileStatus, StarkProof, VmProof},
    serde::DeserializationError,
};
pub use miden_processor::{
    ExecutionClaim, ExecutionError, ExecutionOptions, ExecutionOutput, ExecutionWitness,
    FutureMaybeSend, Host, InputError, PrecompileWitness, ProgramInfo, StackInputs, StackOutputs,
    SyncHost, VmWitness, Word, advice::AdviceInputs, crypto, field, serde, utils,
};
pub use miden_vm_stark::setup::config;
pub use prover::{Prover, ProverError, prove_sync};
