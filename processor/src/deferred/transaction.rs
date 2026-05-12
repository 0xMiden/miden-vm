use alloc::vec::Vec;

use miden_core::{
    Felt,
    deferred::{Assertion, Digest, Node},
};

/// A single mutation to apply to [`super::DeferredState`].
///
/// Mutations are queued by event handlers as part of a [`HandlerTransaction`] and applied
/// atomically by [`super::DeferredState::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferredMutation {
    /// Insert a node into the DAG at the given digest.
    ///
    /// Re-inserting an identical node at the same digest is a no-op. Inserting a different node
    /// at an already-occupied digest is rejected as a hash collision.
    InsertNode { digest: Digest, node: Node },

    /// Append an equality assertion in insertion order.
    AppendAssertion(Assertion),
}

/// A single VM-side side effect emitted by an event handler.
///
/// Event handlers cannot mutate the VM directly; they emit these so the host can apply them in
/// its existing mutation loop. v1 ships with a single variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmMutation {
    /// Push the given felts onto the advice stack.
    PushAdvice(Vec<Felt>),
}

/// Batch of mutations produced by a deferred-system event handler.
///
/// Deferred mutations apply atomically to [`super::DeferredState`] via
/// [`super::DeferredState::apply`]. VM mutations are returned to the host alongside, to be
/// applied through the existing host mutation channel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandlerTransaction {
    pub deferred: Vec<DeferredMutation>,
    pub vm: Vec<VmMutation>,
}

impl HandlerTransaction {
    pub fn new() -> Self {
        Self::default()
    }
}
