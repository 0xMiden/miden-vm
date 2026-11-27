use alloc::{collections::BTreeMap, vec, vec::Vec};

use super::{SparseMastForest, SparseNodeSet};
use crate::{
    mast::{
        ExternalNodeBuilder, MastForest, MastForestContributor, MastForestError, MastForestParts,
        MastNodeExt, MastNodeId, Remapping,
    },
    utils::IndexVec,
};

impl SparseMastForest {
    /// Builds a dense forest using only the stored nodes and digests.
    ///
    /// Every full local procedure in [`Self::procedure_roots`] remains a root, once per digest.
    /// The full local body with the lowest source ID supplies the code. A procedure reached
    /// only through a discarded body still has its own root if extraction recorded it in full.
    /// Other descendants used only by the discarded body are omitted. Conversion also follows
    /// parentless entries to preserve disconnected replay components.
    ///
    /// Retained digest-only entries and external nodes share one dense ID per digest. A full
    /// local procedure with that digest takes precedence. Otherwise the result is an external
    /// whose code the caller must make available during execution.
    ///
    /// The returned map translates retained source IDs to dense IDs, including all aliases of
    /// each retained procedure or external. Remapped child references preserve procedure hashes.
    ///
    /// # Errors
    ///
    /// Returns an error if a required child has neither code nor a digest, or if the remapped
    /// nodes do not form a valid dense forest.
    pub fn to_mast_forest_with_externals(
        &self,
    ) -> Result<(MastForest, Remapping), MastForestError> {
        let mut local_roots: Vec<_> = self
            .roots
            .iter()
            .copied()
            .filter(|id| self.nodes.get(id).is_some_and(|node| !node.is_external()))
            .collect();
        local_roots.sort_unstable();
        local_roots.dedup();
        let aliases = self.procedure_aliases(&local_roots);
        local_roots.retain(|id| !aliases.contains_key(id));
        let retained = self.retained_nodes(&local_roots, &aliases)?;

        // Assign every representative a slot before linking. A parent of an external can have a
        // lower source ID than the full procedure that replaces the external.
        if retained.len() > MastForest::MAX_NODES {
            return Err(MastForestError::TooManyNodes);
        }
        let mut ids: Remapping = retained
            .iter()
            .enumerate()
            .map(|(index, &id)| (id, MastNodeId::from(index as u32)))
            .collect();
        for (alias, representative) in aliases {
            if let Some(&id) = ids.get(&representative) {
                ids.insert(alias, id);
            }
        }

        let mut nodes = IndexVec::with_capacity(retained.len());
        let empty_forest = MastForest::new();
        for id in retained {
            let node = match self.nodes.get(&id) {
                Some(node) => {
                    node.clone().to_builder(&empty_forest).remap_children(&ids).build_linked()?
                },
                None => ExternalNodeBuilder::new(self.digests[&id]).build().into(),
            };
            nodes.push(node).map_err(|_| MastForestError::TooManyNodes)?;
        }
        let (forest, final_ids) = MastForest::from_parts_with_id_map(MastForestParts {
            nodes,
            roots: local_roots.into_iter().map(|id| ids[&id]).collect(),
            advice_map: self.advice_map.clone(),
        })?;
        // Building the forest can reorder nodes. Every source ID in the map, including
        // each alias, must point to its node's final position in the returned forest.
        for id in ids.values_mut() {
            *id = final_ids.get(*id).expect("every constructed node has a final dense ID");
        }
        Ok((forest, ids))
    }

    /// Groups only procedure roots and opaque references by digest. Ordinary nodes can carry
    /// different assertion messages at different sites even when their digests agree.
    fn procedure_aliases(&self, local_roots: &[MastNodeId]) -> Remapping {
        let mut first_by_digest = BTreeMap::new();
        let mut aliases = Remapping::new();
        let mut record = |id, digest| {
            let first = *first_by_digest.entry(digest).or_insert(id);
            if first != id {
                aliases.insert(id, first);
            }
        };

        // The first ID recorded for a digest wins. Visit full bodies first so an
        // external with a lower source ID cannot hide code we already have.
        for &id in local_roots {
            record(id, self.nodes[&id].digest());
        }
        for (&id, node) in &self.nodes {
            if node.is_external() {
                record(id, node.digest());
            }
        }
        for (&id, &digest) in &self.digests {
            record(id, digest);
        }
        aliases
    }

    /// Returns the source IDs that need a dense node after resolving `aliases`, in ascending order.
    ///
    /// The walk starts at local roots and at sparse entries with no parent. Starting at those
    /// entries preserves disconnected replay components when a duplicate body is discarded.
    ///
    /// # Errors
    ///
    /// Returns [`MastForestError::NodeIdOverflow`] if a retained node references a child with
    /// neither a stored node nor a digest.
    fn retained_nodes(
        &self,
        local_roots: &[MastNodeId],
        aliases: &Remapping,
    ) -> Result<Vec<MastNodeId>, MastForestError> {
        let mut stored: Vec<_> = self.nodes.keys().chain(self.digests.keys()).copied().collect();
        stored.sort_unstable();
        let first_id = stored.first().map_or(0, |id| id.0);
        // Identify parentless entries before discarding duplicate bodies. Otherwise a
        // child used only by a discarded body would look like a separate replay component.
        let mut has_parent = vec![false; stored.len()];
        let mut missing_child = None;
        for node in self.nodes.values() {
            node.for_each_child(|child| {
                // Source IDs before the first gap index directly into the stored entries.
                // Binary search handles the rest without allocating across gaps.
                let slot = child.0.saturating_sub(first_id) as usize;
                if stored.get(slot) == Some(&child) {
                    has_parent[slot] = true;
                } else if let Ok(slot) = stored.binary_search(&child) {
                    has_parent[slot] = true;
                } else {
                    missing_child = Some(child);
                }
            });
        }

        // Replacing a leaf cannot orphan any descendants. All stored IDs then have an output,
        // and the only missing entries to check are referenced children outside the stored set.
        let replaces_parent = aliases
            .keys()
            .any(|id| self.nodes.get(id).is_some_and(MastNodeExt::has_children));
        if !replaces_parent {
            if let Some(missing) = missing_child {
                return Err(MastForestError::NodeIdOverflow(missing, self.num_nodes()));
            }
            stored.retain(|id| !aliases.contains_key(id));
            return Ok(stored);
        }

        // Replay can record disconnected components. Each parentless entry, as well as each
        // retained local procedure, is a starting point for following the chosen bodies.
        let mut pending = local_roots.to_vec();
        pending.extend(
            stored
                .into_iter()
                .zip(has_parent)
                .filter_map(|(id, has_parent)| (!has_parent).then_some(id)),
        );
        let mut retained = SparseNodeSet::default();
        while let Some(id) = pending.pop() {
            let id = id.remap(aliases);
            if retained.insert(id) {
                if let Some(node) = self.nodes.get(&id) {
                    node.append_children_to(&mut pending);
                } else if !self.digests.contains_key(&id) {
                    return Err(MastForestError::NodeIdOverflow(id, self.num_nodes()));
                }
            }
        }
        Ok(retained.into_ids().collect())
    }
}
