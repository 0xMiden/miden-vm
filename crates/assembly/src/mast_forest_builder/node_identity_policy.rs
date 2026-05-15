use alloc::{collections::BTreeSet, vec::Vec};

use miden_core::utils::IndexVec;

use super::{DecoratorRef, MastNodeRef, PendingMastNode};

/// Finalization plan that decides which builder-local records become final forest nodes.
pub(super) struct FinalForestLayout {
    pub(super) procedure_root_refs: Vec<MastNodeRef>,
    pub(super) live_node_refs: Vec<MastNodeRef>,
    pub(super) live_decorator_refs: BTreeSet<DecoratorRef>,
}

impl FinalForestLayout {
    pub(super) fn plan(
        procedure_root_refs: Vec<MastNodeRef>,
        removable_node_refs: BTreeSet<MastNodeRef>,
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> Self {
        let node_refs_to_remove =
            Self::node_refs_to_remove(removable_node_refs, &procedure_root_refs, nodes);
        let live_node_refs = Self::live_node_refs_in_final_order(nodes, &node_refs_to_remove);
        let live_decorator_refs = Self::live_decorator_refs(&live_node_refs, nodes);

        Self {
            procedure_root_refs,
            live_node_refs,
            live_decorator_refs,
        }
    }

    fn node_refs_to_remove(
        candidate_node_refs: BTreeSet<MastNodeRef>,
        procedure_root_refs: &[MastNodeRef],
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> BTreeSet<MastNodeRef> {
        // Pruning is intentionally candidate-based. A reachability sweep is only equivalent if it
        // starts from every procedure root in the final forest, not just from the entrypoint or
        // static call graph. `dynexec`/`dyncall` nodes do not have child edges to their runtime
        // targets; the processor resolves the target digest by looking it up among procedure
        // roots. Therefore, a procedure used only dynamically is live because it remains a
        // procedure root even though no static child edge points to it.
        //
        // The builder already knows which refs were made obsolete by local rewrites, such as
        // basic-block merging or decorator cloning. Finalization removes only those candidates,
        // and only after filtering out candidates that are still procedure roots or children of
        // another retained node.
        let mut nodes_to_remove: BTreeSet<MastNodeRef> = candidate_node_refs
            .iter()
            .filter(|&&node_ref| !procedure_root_refs.contains(&node_ref))
            .copied()
            .collect();

        for node in nodes {
            for child_ref in &node.child_refs {
                nodes_to_remove.remove(child_ref);
            }
        }

        nodes_to_remove
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
        external_node_refs.sort_by_key(|node_ref| (nodes[*node_ref].fingerprint, *node_ref));

        let mut final_order = external_node_refs;
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

    fn live_decorator_refs(
        live_node_refs: &[MastNodeRef],
        nodes: &IndexVec<MastNodeRef, PendingMastNode>,
    ) -> BTreeSet<DecoratorRef> {
        live_node_refs
            .iter()
            .flat_map(|node_ref| nodes[*node_ref].decorator_refs.refs())
            .collect()
    }
}
