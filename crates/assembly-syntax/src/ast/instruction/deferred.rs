use core::fmt;

use miden_core::events::SystemEvent;

// DEFERRED EVENT NODE
// ================================================================================================

/// Instructions which drive the deferred-computation DAG via `SystemEvent` dispatch.
///
/// Each variant maps 1:1 to a `SystemEvent::Deferred*` and lowers to `push.<id>; emit; drop`.
/// The processor reads the tag and payload off the operand stack, mutates the deferred state
/// living on the advice provider, and leaves the stack untouched (the leading `drop` clears the
/// `event_id`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeferredEventNode {
    RegisterLeaf,
    RegisterOp,
    AssertEq,
}

impl From<&DeferredEventNode> for SystemEvent {
    fn from(value: &DeferredEventNode) -> Self {
        match value {
            DeferredEventNode::RegisterLeaf => Self::DeferredRegisterLeaf,
            DeferredEventNode::RegisterOp => Self::DeferredRegisterOp,
            DeferredEventNode::AssertEq => Self::DeferredAssertEq,
        }
    }
}

impl crate::prettier::PrettyPrint for DeferredEventNode {
    fn render(&self) -> crate::prettier::Document {
        crate::prettier::display(self)
    }
}

impl fmt::Display for DeferredEventNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegisterLeaf => write!(f, "register_leaf"),
            Self::RegisterOp => write!(f, "register_op"),
            Self::AssertEq => write!(f, "assert_eq"),
        }
    }
}
