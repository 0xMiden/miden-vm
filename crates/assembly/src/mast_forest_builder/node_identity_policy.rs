use alloc::{collections::BTreeSet, vec::Vec};

use miden_core::utils::IndexVec;

use super::{MastNodeRef, PendingMastNode};

/// Finalization plan that decides which builder-local records become final forest nodes.
pub(super) struct FinalForestLayout {
    pub(super) procedure_root_refs: Vec<MastNodeRef>,
    pub(super) live_node_refs: Vec<MastNodeRef>,
}

impl FinalForestLayout {
    pub(super) fn plan(
        procedure_root_refs: Vec<MastNodeRef>,
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> Self {
        let node_refs_to_remove = Self::unreachable_node_refs(&procedure_root_refs, nodes);
        let live_node_refs = Self::live_node_refs_in_final_order(nodes, &node_refs_to_remove);
        Self { procedure_root_refs, live_node_refs }
    }

    fn unreachable_node_refs(
        procedure_root_refs: &[MastNodeRef],
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> BTreeSet<MastNodeRef> {
        // Start from every procedure root, not just from an executable entrypoint or static call
        // graph. `dynexec`/`dyncall` nodes do not have child edges to their runtime targets; the
        // processor resolves those targets by looking them up among procedure roots. Therefore, a
        // procedure used only dynamically is live because it remains a procedure root.
        let mut reachable_node_refs = BTreeSet::new();
        let mut worklist = procedure_root_refs.to_vec();

        while let Some(node_ref) = worklist.pop() {
            if reachable_node_refs.insert(node_ref) {
                worklist.extend(nodes[node_ref].child_refs.iter().copied());
            }
        }

        (0..nodes.len())
            .map(|index| MastNodeRef::from(index as u32))
            .filter(|node_ref| !reachable_node_refs.contains(node_ref))
            .collect()
    }

    fn live_node_refs_in_final_order(
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
        node_refs_to_remove: &BTreeSet<MastNodeRef>,
    ) -> Vec<MastNodeRef> {
        let mut live_node_refs = (0..nodes.len())
            .map(|index| MastNodeRef::from(index as u32))
            .filter(|node_ref| !node_refs_to_remove.contains(node_ref))
            .collect::<Vec<_>>();

        let live_node_ref_set = live_node_refs.iter().copied().collect::<BTreeSet<_>>();

        let mut external_node_refs = Vec::new();
        live_node_refs.retain(|node_ref| {
            if nodes[*node_ref].kind.is_external() {
                external_node_refs.push(*node_ref);
                false
            } else {
                true
            }
        });
        external_node_refs.sort_by_key(|node_ref| (nodes[*node_ref].key, *node_ref));

        let mut basic_block_node_refs = Vec::new();
        live_node_refs.retain(|node_ref| {
            if nodes[*node_ref].kind.is_basic_block() {
                basic_block_node_refs.push(*node_ref);
                false
            } else {
                true
            }
        });
        basic_block_node_refs.sort();

        let mut final_order = external_node_refs;
        final_order.extend(basic_block_node_refs);
        let mut emitted_node_refs = final_order.iter().copied().collect::<BTreeSet<_>>();
        let mut remaining_node_refs = live_node_refs.into_iter().collect::<BTreeSet<_>>();

        while !remaining_node_refs.is_empty() {
            let mut ready_node_refs = remaining_node_refs
                .iter()
                .copied()
                .filter(|node_ref| {
                    nodes[*node_ref].child_refs.iter().all(|child_ref| {
                        !live_node_ref_set.contains(child_ref)
                            || emitted_node_refs.contains(child_ref)
                    })
                })
                .collect::<Vec<_>>();

            assert!(
                !ready_node_refs.is_empty(),
                "pending MAST nodes must form an acyclic dependency graph"
            );

            ready_node_refs.sort();
            for node_ref in ready_node_refs {
                remaining_node_refs.remove(&node_ref);
                emitted_node_refs.insert(node_ref);
                final_order.push(node_ref);
            }
        }

        final_order
    }
}
