#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use assembly::{
    self, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use processor::{
    AdviceInputs, AdviceProvider, AsmOpInfo, AsyncHost, BaseHost, DefaultHost, ExecutionError,
    ExecutionTrace, Kernel, Operation, Program, ProgramInfo, StackInputs, SyncHost, VmState,
    VmStateIterator, ZERO, crypto, execute, execute_iter, utils,
};
pub use prover::{
    ExecutionProof, FieldExtension, HashFunction, InputError, Proof, ProvingOptions, StackOutputs,
    Word, math, prove,
};
pub use verifier::{VerificationError, verify};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
