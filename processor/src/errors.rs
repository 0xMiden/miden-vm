use alloc::{boxed::Box, string::String};
use core::error::Error;
use std::{string::ToString, vec::Vec};

use miden_air::RowIndex;
use vm_core::{
    mast::{DecoratorId, MastNodeId},
    stack::MIN_STACK_DEPTH,
    utils::to_hex,
};
use winter_prover::ProverError;

use super::{
    Digest, Felt, QuadFelt, Word,
    crypto::MerkleError,
    system::{FMP_MAX, FMP_MIN},
};
use crate::ContextId;

// TODO(Al)
fn felts_to_hex(elements: &[Felt]) -> Vec<u8> {
    elements.iter().flat_map(|e| e.to_string().into_bytes()).collect()
}
// EXECUTION ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("value for key {} not present in the advice map", to_hex(felts_to_hex(.0)))]
    AdviceMapKeyNotFound(Word),
    #[error("value for key {} already present in the advice map", to_hex(felts_to_hex(.0)))]
    AdviceMapKeyAlreadyPresent(Word),
    #[error("advice stack read failed at step {0}")]
    AdviceStackReadFailed(RowIndex),
    #[error("illegal use of instruction {0} while inside a syscall")]
    CallInSyscall(&'static str),
    #[error("instruction `caller` used outside of kernel context")]
    CallerNotInSyscall,
    #[error("external node with mast root {0} resolved to an external node")]
    CircularExternalNode(Digest),
    #[error("exceeded the allowed number of max cycles {0}")]
    CycleLimitExceeded(u32),
    #[error("decorator id {decorator_id} does not exist in MAST forest")]
    DecoratorNotFoundInForest { decorator_id: DecoratorId },
    #[error("division by zero at clock cycle {0}")]
    DivideByZero(RowIndex),
    #[error("failed to execute the dynamic code block provided by the stack with root {hex}; the block could not be found",
      hex = to_hex(.0.as_bytes())
    )]
    DynamicNodeNotFound(Digest),
    #[error("error during processing of event in on_event handler")]
    EventError(#[source] Box<dyn Error + Send + Sync + 'static>),
    #[error("failed to execute Ext2Intt operation: {0}")]
    Ext2InttError(Ext2InttError),
    #[error("assertion failed at clock cycle {clk} with error code {err_code}{}",
      match err_msg {
        Some(msg) => format!(": {msg}"),
        None => "".into()
      }
    )]
    FailedAssertion {
        clk: RowIndex,
        err_code: u32,
        err_msg: Option<String>,
    },
    #[error(
        "memory address {addr} in context {ctx} was read and written, or written twice, in the same clock cycle {clk}"
    )]
    IllegalMemoryAccess { ctx: ContextId, addr: u32, clk: Felt },
    #[error(
        "Updating FMP register from {0} to {1} failed because {1} is outside of {FMP_MIN}..{FMP_MAX}"
    )]
    InvalidFmpValue(Felt, Felt),
    #[error("FRI domain segment value cannot exceed 3, but was {0}")]
    InvalidFriDomainSegment(u64),
    #[error("degree-respecting projection is inconsistent: expected {0} but was {1}")]
    InvalidFriLayerFolding(QuadFelt, QuadFelt),
    #[error(
        "memory range start address cannot exceed end address, but was ({start_addr}, {end_addr})"
    )]
    InvalidMemoryRange { start_addr: u64, end_addr: u64 },
    #[error("when returning from a call, stack depth must be {MIN_STACK_DEPTH}, but was {0}")]
    InvalidStackDepthOnReturn(usize),
    #[error(
        "provided merkle tree {depth} is out of bounds and cannot be represented as an unsigned 8-bit integer"
    )]
    InvalidMerkleTreeDepth { depth: Felt },
    #[error("provided node index {value} is out of bounds for a merkle tree node at depth {depth}")]
    InvalidMerkleTreeNodeIndex { depth: Felt, value: Felt },
    #[error("attempted to calculate integer logarithm with zero argument at clock cycle {0}")]
    LogArgumentZero(RowIndex),
    #[error("malformed signature key: {0}")]
    MalformedSignatureKey(&'static str),
    #[error(
        "MAST forest in host indexed by procedure root {root_digest} doesn't contain that root"
    )]
    MalformedMastForestInHost { root_digest: Digest },
    #[error("node id {node_id} does not exist in MAST forest")]
    MastNodeNotFoundInForest { node_id: MastNodeId },
    #[error("no MAST forest contains the procedure with root digest {root_digest}")]
    NoMastForestWithProcedure { root_digest: Digest },
    #[error("memory address cannot exceed 2^32 but was {0}")]
    MemoryAddressOutOfBounds(u64),
    #[error(
        "word memory access at address {addr} in context {ctx} is unaligned at clock cycle {clk}"
    )]
    MemoryUnalignedWordAccess { addr: u32, ctx: ContextId, clk: Felt },
    // Note: we need this version as well because to handle advice provider calls, which don't
    // have access to the clock.
    #[error("word access at memory address {addr} in context {ctx} is unaligned")]
    MemoryUnalignedWordAccessNoClk { addr: u32, ctx: ContextId },
    #[error("merkle path verification failed for value {value} at index {index} in the Merkle tree with root {root} (error code: {err_code})", 
      value = to_hex(felts_to_hex(value)),
      root = to_hex(root.as_bytes()),
    )]
    MerklePathVerificationFailed {
        value: Word,
        index: Felt,
        root: Digest,
        err_code: u32,
    },
    #[error("advice provider Merkle store backend lookup failed")]
    MerkleStoreLookupFailed(#[source] MerkleError),
    #[error("advice provider Merkle store backend merge failed")]
    MerkleStoreMergeFailed(#[source] MerkleError),
    #[error("advice provider Merkle store backend update failed")]
    MerkleStoreUpdateFailed(#[source] MerkleError),
    #[error("an operation expected a binary value, but received {0}")]
    NotBinaryValue(Felt),
    #[error("an operation expected a u32 value, but received {0} (error code: {1})")]
    NotU32Value(Felt, Felt),
    #[error("stack should have at most {MIN_STACK_DEPTH} elements at the end of program execution, but had {} elements", MIN_STACK_DEPTH + .0)]
    OutputStackOverflow(usize),
    #[error("a program has already been executed in this process")]
    ProgramAlreadyExecuted,
    #[error("proof generation failed")]
    ProverError(#[source] ProverError),
    #[error("smt node {node_hex} not found", node_hex = to_hex(felts_to_hex(.0)))]
    SmtNodeNotFound(Word),
    #[error("expected pre-image length of node {node_hex} to be a multiple of 8 but was {preimage_len}",
      node_hex = to_hex(felts_to_hex(.0)),
      preimage_len = .1
    )]
    SmtNodePreImageNotValid(Word, usize),
    #[error("syscall failed: procedure with root {hex} was not found in the kernel",
      hex = to_hex(.0.as_bytes())
    )]
    SyscallTargetNotInKernel(Digest),
}

impl From<Ext2InttError> for ExecutionError {
    fn from(value: Ext2InttError) -> Self {
        Self::Ext2InttError(value)
    }
}

// EXT2INTT ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum Ext2InttError {
    #[error("input domain size must be a power of two, but was {0}")]
    DomainSizeNotPowerOf2(u64),
    #[error("input domain size ({0} elements) is too small")]
    DomainSizeTooSmall(u64),
    #[error("address of the last input must be smaller than 2^32, but was {0}")]
    InputEndAddressTooBig(u64),
    #[error("input size must be smaller than 2^32, but was {0}")]
    InputSizeTooBig(u64),
    #[error("address of the first input must be smaller than 2^32, but was {0}")]
    InputStartAddressTooBig(u64),
    #[error("address of the first input is not word aligned: {0}")]
    InputStartNotWordAligned(u64),
    #[error("output size ({0}) cannot be greater than the input size ({1})")]
    OutputSizeTooBig(usize, usize),
    #[error("output size must be greater than 0")]
    OutputSizeIsZero,
    #[error("uninitialized memory at address {0}")]
    UninitializedMemoryAddress(u32),
}

#[cfg(test)]
mod error_assertions {
    use super::*;

    /// Asserts at compile time that the passed error has Send + Sync + 'static bounds.
    fn _assert_error_is_send_sync_static<E: core::error::Error + Send + Sync + 'static>(_: E) {}

    fn _assert_execution_error_bounds(err: ExecutionError) {
        _assert_error_is_send_sync_static(err);
    }
}
