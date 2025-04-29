#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use assembly::{
    self, Assembler, AssemblyError,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use processor::{
    AdviceInputs, AdviceProvider, AsmOpInfo, DefaultHost, ExecutionError, ExecutionTrace, Host,
    Kernel, MemAdviceProvider, Operation, Program, ProgramInfo, StackInputs, VmState,
    VmStateIterator, ZERO, crypto, execute, execute_iter, utils,
};
pub use prover::{
    Digest, ExecutionProof, FieldExtension, HashFunction, InputError, ProvingOptions, StackOutputs,
    Word, math, prove,
};
pub use verifier::{VerificationError, verify};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
