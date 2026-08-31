use alloc::{collections::BTreeSet, vec::Vec};

use super::{
    MastForest, MastForestContributor, MastForestError, MastForestParts, MastNode, MastNodeExt,
    MastNodeId, node::MastNodeOrderClass,
};
use crate::utils::{DenseIdMap, Idx, IndexVec};

pub(super) fn validate_mast_forest_parts_bounds(
    parts: &MastForestParts,
) -> Result<(), MastForestError> {
    if parts.nodes.len() > MastForest::MAX_NODES {
        return Err(MastForestError::TooManyNodes);
    }

    let node_count = parts.nodes.len();
    for &root_id in &parts.roots {
        if root_id.to_usize() >= node_count {
            return Err(MastForestError::NodeIdOverflow(root_id, node_count));
        }
    }

    Ok(())
}

/// Canonicalizes dense forest parts and returns the old-to-new node ID remapping.
///
/// The final node order is external nodes sorted by digest, then basic blocks in construction
/// order, then internal nodes with children before parents and construction order as the
/// tie-breaker.
pub(super) fn canonicalize_parts(
    parts: MastForestParts,
) -> Result<(MastForestParts, DenseIdMap<MastNodeId, MastNodeId>), MastForestError> {
    let node_count = parts.nodes.len();
    let ordered_ids = final_dense_node_order(&parts.nodes)?;

    let mut remapping = DenseIdMap::with_len(node_count);
    for (new_index, old_id) in ordered_ids.iter().copied().enumerate() {
        remapping.insert(old_id, MastNodeId::new_unchecked(new_index as u32));
    }

    if ordered_ids
        .iter()
        .enumerate()
        .all(|(index, &old_id)| old_id == MastNodeId::new_unchecked(index as u32))
    {
        debug_assert!(validate_dense_node_order(&parts.nodes).is_ok());
        return Ok((parts, remapping));
    }

    let mut nodes = IndexVec::with_capacity(node_count);
    let empty_forest = MastForest::new();
    for old_id in ordered_ids {
        let node = parts.nodes[old_id].clone();
        let remapped_node =
            node.to_builder(&empty_forest).remap_children(&remapping).build_linked()?;
        nodes
            .push(remapped_node)
            .expect("canonicalized node count was validated before remapping");
    }

    let roots = parts
        .roots
        .into_iter()
        .map(|root_id| {
            remapping
                .get(root_id)
                .ok_or(MastForestError::NodeIdOverflow(root_id, node_count))
        })
        .collect::<Result<Vec<_>, _>>()?;

    debug_assert!(validate_dense_node_order(&nodes).is_ok());

    Ok((
        MastForestParts {
            nodes,
            roots,
            advice_map: parts.advice_map,
        },
        remapping,
    ))
}

fn final_dense_node_order(
    nodes: &IndexVec<MastNodeId, MastNode>,
) -> Result<Vec<MastNodeId>, MastForestError> {
    let node_count = nodes.len();
    let mut external_ids = Vec::new();
    let mut basic_block_ids = Vec::new();
    let mut internal_ids = Vec::new();

    for (index, node) in nodes.iter().enumerate() {
        let node_id = MastNodeId::new_unchecked(index as u32);
        match node.order_class() {
            MastNodeOrderClass::External => external_ids.push(node_id),
            MastNodeOrderClass::BasicBlock => basic_block_ids.push(node_id),
            MastNodeOrderClass::Internal => internal_ids.push(node_id),
        }
    }

    external_ids.sort_by(|&left_id, &right_id| {
        nodes[left_id]
            .digest()
            .cmp(&nodes[right_id].digest())
            .then(left_id.0.cmp(&right_id.0))
    });

    // External nodes are identified only by digest, so duplicate external digests would create two
    // IDs for the same dependency. Reject them before building the final order.
    let mut previous_external_digest = None;
    for &node_id in &external_ids {
        let digest = nodes[node_id].digest();
        if let Some(previous_digest) = previous_external_digest
            && previous_digest >= digest
        {
            return Err(MastForestError::InvalidNodeOrder {
                node_id,
                reason: "external node digests must be strictly increasing".into(),
            });
        }
        previous_external_digest = Some(digest);
    }

    let mut ordered_ids = external_ids;
    let mut ordered = vec![false; node_count];
    ordered_ids.extend(basic_block_ids);
    for &node_id in &ordered_ids {
        ordered[node_id.to_usize()] = true;
    }

    // Internal nodes are emitted once all children already appear in the final order. The ready set
    // is keyed by original node ID, so construction order remains the tie-breaker among all
    // currently-ready internal nodes.
    let mut unresolved_child_counts = vec![0usize; node_count];
    let mut parents_by_child = vec![Vec::new(); node_count];
    for &node_id in &internal_ids {
        nodes[node_id].for_each_child(|child_id| {
            if child_id.to_usize() < node_count && !ordered[child_id.to_usize()] {
                unresolved_child_counts[node_id.to_usize()] += 1;
                parents_by_child[child_id.to_usize()].push(node_id);
            }
        });
    }

    for &node_id in &internal_ids {
        let mut invalid_child = None;
        nodes[node_id].for_each_child(|child_id| {
            if child_id.to_usize() >= node_count {
                invalid_child = Some(child_id);
            }
        });

        if let Some(child_id) = invalid_child {
            return Err(MastForestError::NodeIdOverflow(child_id, node_count));
        }
    }

    let mut ready_internal_ids = BTreeSet::new();
    for &node_id in &internal_ids {
        if unresolved_child_counts[node_id.to_usize()] == 0 {
            ready_internal_ids.insert(node_id);
        }
    }

    let mut ordered_internal_count = 0;
    while let Some(node_id) = ready_internal_ids.pop_first() {
        ordered[node_id.to_usize()] = true;
        ordered_ids.push(node_id);
        ordered_internal_count += 1;

        for parent_id in core::mem::take(&mut parents_by_child[node_id.to_usize()]) {
            let count = &mut unresolved_child_counts[parent_id.to_usize()];
            *count = count.checked_sub(1).expect("ready child must have a pending parent");
            if *count == 0 {
                ready_internal_ids.insert(parent_id);
            }
        }
    }

    if ordered_internal_count != internal_ids.len() {
        let node_id = internal_ids
            .into_iter()
            .find(|node_id| !ordered[node_id.to_usize()])
            .expect("internal cycle must contain a pending node");
        return Err(MastForestError::InvalidNodeOrder {
            node_id,
            reason: "internal nodes must form an acyclic child-before-parent graph".into(),
        });
    }

    Ok(ordered_ids)
}

pub(super) fn validate_dense_node_order(
    nodes: &IndexVec<MastNodeId, MastNode>,
) -> Result<(), MastForestError> {
    let mut previous_class = MastNodeOrderClass::External;
    let mut previous_external_digest = None;

    for (node_index, node) in nodes.iter().enumerate() {
        let node_id = MastNodeId::new_unchecked(node_index as u32);
        let node_class = node.order_class();

        if node_class < previous_class {
            return Err(MastForestError::InvalidNodeOrder {
                node_id,
                reason: format!("node class {node_class:?} appears after {previous_class:?}"),
            });
        }
        previous_class = node_class;

        if let MastNode::External(external_node) = node {
            let digest = external_node.digest();
            if let Some(previous_digest) = previous_external_digest
                && previous_digest >= digest
            {
                return Err(MastForestError::InvalidNodeOrder {
                    node_id,
                    reason: "external node digests must be strictly increasing".into(),
                });
            }
            previous_external_digest = Some(digest);
        }

        let mut forward_child = None;
        node.for_each_child(|child_id| {
            if child_id.0 >= node_id.0 {
                forward_child = Some(child_id);
            }
        });
        if let Some(child_id) = forward_child {
            return Err(MastForestError::ForwardReference(node_id, child_id));
        }
    }

    Ok(())
}
