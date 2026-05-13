use core::fmt;

use miden_core::events::SystemEvent;

// DEFERRED EVENT NODE
// ================================================================================================

/// MASM instructions which drive the deferred-computation DAG via `SystemEvent` dispatch.
///
/// Each variant lowers to `push.<id>; emit; drop`. The schema decides what each tag means;
/// the AST is opaque.
///
/// - [`Register`](DeferredEventNode::Register): register a node, classified by the schema as
///   expression or assertion.
/// - [`Evaluate`](DeferredEventNode::Evaluate): evaluate a node and push the canonical
///   `(tag, payload)` onto the advice stack.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeferredEventNode {
    Register,
    Evaluate,
}

impl From<&DeferredEventNode> for SystemEvent {
    fn from(value: &DeferredEventNode) -> Self {
        match value {
            DeferredEventNode::Register => Self::DeferredRegister,
            DeferredEventNode::Evaluate => Self::DeferredEvaluate,
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
            Self::Evaluate => write!(f, "deferred_evaluate"),
        }
    }
}
