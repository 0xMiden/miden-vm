use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod assembly_op;
pub use assembly_op::AssemblyOp;

mod debug_var;
pub use debug_var::{DebugVarInfo, DebugVarLocation};

use crate::mast::{DecoratedOpLink, DecoratorFingerprint};

// DECORATORS
// ================================================================================================

/// A set of decorators which can be attached to MAST nodes.
///
/// All executable decorators have been removed. The type remains so existing MAST debug-info
/// storage can represent an empty decorator table and reject old serialized decorator variants.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub enum Decorator {}

impl Decorator {
    pub fn fingerprint(&self) -> DecoratorFingerprint {
        match *self {}
    }
}

impl crate::prettier::PrettyPrint for Decorator {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for Decorator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

/// Vector consisting of a tuple of operation index (within a span block) and decorator at that
/// index.
pub type DecoratorList = Vec<DecoratedOpLink>;
