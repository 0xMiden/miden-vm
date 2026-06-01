use alloc::collections::BTreeMap;

use miden_core::utils::{Idx, IndexVec};

/// Assigns finalized metadata IDs to builder-local metadata refs once.
pub(super) struct MetadataRefAllocator<'a, Ref: Idx, Item, FinalId> {
    items_by_ref: &'a IndexVec<Ref, Item>,
    final_id_by_ref: BTreeMap<Ref, FinalId>,
}

impl<'a, Ref, Item, FinalId> MetadataRefAllocator<'a, Ref, Item, FinalId>
where
    Ref: Copy + Idx + Ord,
    Item: Clone,
    FinalId: Copy,
{
    pub(super) fn new(items_by_ref: &'a IndexVec<Ref, Item>) -> Self {
        Self {
            items_by_ref,
            final_id_by_ref: BTreeMap::new(),
        }
    }

    pub(super) fn get_or_insert<E>(
        &mut self,
        item_ref: Ref,
        insert_item: impl FnOnce(Item) -> Result<FinalId, E>,
    ) -> Result<FinalId, E> {
        if let Some(final_id) = self.final_id_by_ref.get(&item_ref).copied() {
            return Ok(final_id);
        }

        let final_id = insert_item(self.items_by_ref[item_ref].clone())?;
        self.final_id_by_ref.insert(item_ref, final_id);
        Ok(final_id)
    }
}
