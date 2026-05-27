use alloc::vec::Vec;
use core::fmt;

use miden_crypto::hash::blake::Blake3_256;
use num_traits::ToBytes;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod assembly_op;
pub use assembly_op::AssemblyOp;

mod debug_var;
pub use debug_var::{DebugVarInfo, DebugVarLocation};

use crate::mast::{DecoratedOpLink, DecoratorFingerprint};

// DECORATORS
// ================================================================================================

/// A set of decorators which can be executed by the VM.
///
/// Executing a decorator does not affect the state of the main VM components such as operand stack
/// and memory.
///
/// Executing decorators does not advance the VM clock. As such, many decorators can be executed in
/// a single VM cycle.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub enum Decorator {
    /// Emits a trace to the host.
    Trace(u32),
}

impl Decorator {
    pub fn fingerprint(&self) -> DecoratorFingerprint {
        match self {
            Self::Trace(trace) => Blake3_256::hash(&trace.to_le_bytes()),
        }
    }
}

impl crate::prettier::PrettyPrint for Decorator {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for Decorator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace(trace_id) => write!(f, "trace({trace_id})"),
        }
    }
}

/// Vector consisting of a tuple of operation index (within a span block) and decorator at that
/// index.
pub type DecoratorList = Vec<DecoratedOpLink>;
