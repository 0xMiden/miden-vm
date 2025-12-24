#![cfg_attr(not(feature = "std"), no_std)]
#![doc = include_str!("../README.md")]

// EXPORTS
// ================================================================================================

pub use miden_assembly::{
    self as assembly, Assembler,
    ast::{Module, ModuleKind},
    diagnostics,
};
pub use miden_processor::{
    AdviceInputs, AdviceProvider, AsmOpInfo, AsyncHost, BaseHost, DefaultHost, ExecutionError,
    ExecutionTrace, Kernel, Operation, PrimeField64, Program, ProgramInfo, StackInputs, SyncHost,
    VmState, VmStateIterator, ZERO, crypto, execute, execute_iter, utils,
};
pub use miden_prover::{
    ExecutionProof, HashFunction, InputError, Proof, ProvingOptions, StackOutputs, Word, math,
    prove,
};
pub use miden_verifier::{VerificationError, verify};

// (private) exports
// ================================================================================================

#[cfg(feature = "internal")]
pub mod internal;
