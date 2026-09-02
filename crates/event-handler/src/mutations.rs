use alloc::vec::Vec;

use miden_core::{
    Felt,
    advice::{AdviceMap, AdviceStack},
    crypto::merkle::InnerNodeInfo,
};

/// A declarative mutation to the processor's advice state.
///
/// The processor validates a handler's complete mutation list before applying the first item, so
/// the list is committed atomically and in the order returned by the handler.
#[derive(Debug, PartialEq, Eq)]
pub enum AdviceMutation {
    /// Prepends values to the advice stack.
    ExtendStack { stack: AdviceStack },
    /// Adds entries to the advice map.
    ExtendMap { map: AdviceMap },
    /// Adds inner nodes to the advice Merkle store.
    ExtendMerkleStore { inner_nodes: Vec<InnerNodeInfo> },
}

impl AdviceMutation {
    /// Extends the advice stack with the typed stack, preserving its top-to-bottom order.
    pub fn extend_advice_stack(stack: AdviceStack) -> Self {
        Self::ExtendStack { stack }
    }

    /// Extends the advice stack with elements ordered from top to bottom.
    pub fn extend_advice_stack_with(elements: impl IntoIterator<Item = Felt>) -> Self {
        Self::ExtendStack { stack: elements.into_iter().collect() }
    }

    /// Extends the advice map.
    pub fn extend_map(map: AdviceMap) -> Self {
        Self::ExtendMap { map }
    }

    /// Extends the advice Merkle store.
    pub fn extend_merkle_store(inner_nodes: impl IntoIterator<Item = InnerNodeInfo>) -> Self {
        Self::ExtendMerkleStore { inner_nodes: Vec::from_iter(inner_nodes) }
    }
}
