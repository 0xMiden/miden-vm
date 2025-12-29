use core::fmt::{self, Display};

use miden_air::{Felt, RowIndex};

// EXECUTION CONTEXT
// ================================================================================================

/// Represents the ID of an execution context
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct ContextId(u32);

impl ContextId {
    /// Returns the root context ID
    pub fn root() -> Self {
        Self(0)
    }

    /// Returns true if the context ID represents the root context
    pub fn is_root(&self) -> bool {
        self.0 == 0
    }
}

impl From<RowIndex> for ContextId {
    fn from(value: RowIndex) -> Self {
        Self(value.as_u32())
    }
}

impl From<u32> for ContextId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<ContextId> for u32 {
    fn from(context_id: ContextId) -> Self {
        context_id.0
    }
}

impl From<ContextId> for u64 {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl From<ContextId> for Felt {
    fn from(context_id: ContextId) -> Self {
        context_id.0.into()
    }
}

impl Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
