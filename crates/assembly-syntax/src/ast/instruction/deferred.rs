use core::fmt;

use miden_core::events::SystemEvent;

// DEFERRED EVENT NODE
// ================================================================================================

/// MASM instructions which drive the deferred-computation DAG via `SystemEvent` dispatch.
///
/// The single variant lowers to `push.<id>; emit; drop`. The schema's classification of the
/// node decides whether the event records an expression or an assertion — that distinction
/// lives in user code, not in the AST.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeferredEventNode {
    Register,
}

impl From<&DeferredEventNode> for SystemEvent {
    fn from(value: &DeferredEventNode) -> Self {
        match value {
            DeferredEventNode::Register => Self::DeferredRegister,
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
            Self::Register => write!(f, "deferred_register"),
        }
    }
}
