use alloc::{sync::Arc, vec::Vec};

// RE-EXPORTS
// ================================================================================================
pub use vm_core::utils::*;
use vm_core::{
    Felt,
    mast::{ExternalNode, MastForest, MastNodeId},
};

use crate::{AsyncHost, ExecutionError, ProcessState, SyncHost};

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the number of rows in the provided execution trace assumed to be in column-major form
/// and contain at least one column.
pub(crate) fn get_trace_len(trace: &[Vec<Felt>]) -> usize {
    trace[0].len()
}

/// Splits an element into two field elements containing 32-bit integer values
#[inline(always)]
pub(crate) fn split_element(value: Felt) -> (Felt, Felt) {
    let value = value.as_int();
    let lo = (value as u32) as u64;
    let hi = value >> 32;
    (Felt::new(hi), Felt::new(lo))
}

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_int());
    (Felt::new(hi as u64), Felt::new(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}

/// Resolves an external node reference to a procedure root using the `MastForest` store in the
/// provided host.
///
/// This helper function is extracted to ensure that [`crate::Process`] and
/// [`crate::fast::FastProcessor`] resolve external nodes in the same way.
pub(crate) fn resolve_external_node(
    process_state: &mut ProcessState<'_>,
    external_node: &ExternalNode,
    host: &impl SyncHost,
) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
    let node_digest = external_node.digest();

    // Check the cache if this procedure has already been called.
    if let Some((node_id, forest)) = process_state.cached_external_procedure(&node_digest) {
        return Ok((node_id, forest));
    }

    let mast_forest = host
        .get_mast_forest(&node_digest)
        .ok_or(ExecutionError::no_mast_forest_with_procedure(node_digest, &()))?;

    // We limit the parts of the program that can be called externally to procedure
    // roots, even though MAST doesn't have that restriction.
    let root_id = mast_forest
        .find_procedure_root(node_digest)
        .ok_or(ExecutionError::malfored_mast_forest_in_host(node_digest, &()))?;

    // if the node that we got by looking up an external reference is also an External
    // node, we are about to enter into an infinite loop - so, return an error
    if mast_forest[root_id].is_external() {
        return Err(ExecutionError::CircularExternalNode(node_digest));
    }

    process_state.advice_provider_mut().add_mast_forest(&mast_forest);

    Ok((root_id, mast_forest))
}

/// Analogous to [`resolve_external_node`], but for asynchronous execution.
pub(crate) async fn resolve_external_node_async(
    process_state: &mut ProcessState<'_>,
    external_node: &ExternalNode,
    host: &mut impl AsyncHost,
) -> Result<(MastNodeId, Arc<MastForest>), ExecutionError> {
    let node_digest = external_node.digest();

    // Check the cache if this procedure has already been called.
    if let Some((node_id, forest)) = process_state.cached_external_procedure(&node_digest) {
        return Ok((node_id, forest));
    }

    let mast_forest = host
        .get_mast_forest(&node_digest)
        .await
        .ok_or(ExecutionError::no_mast_forest_with_procedure(node_digest, &()))?;

    // We limit the parts of the program that can be called externally to procedure
    // roots, even though MAST doesn't have that restriction.
    let root_id = mast_forest
        .find_procedure_root(node_digest)
        .ok_or(ExecutionError::malfored_mast_forest_in_host(node_digest, &()))?;

    // if the node that we got by looking up an external reference is also an External
    // node, we are about to enter into an infinite loop - so, return an error
    if mast_forest[root_id].is_external() {
        return Err(ExecutionError::CircularExternalNode(node_digest));
    }

    process_state.advice_provider_mut().add_mast_forest(&mast_forest);

    Ok((root_id, mast_forest))
}
