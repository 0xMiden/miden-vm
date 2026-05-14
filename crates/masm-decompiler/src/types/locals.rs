//! Local slot type state used by intraprocedural type inference.

use std::collections::HashMap;

use super::domain::TypeFact;

/// Local slot types and backward-propagated requirements for one procedure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct LocalState {
    /// Inferred types for local variable slots.
    ///
    /// Updated on `LocalStore`/`LocalStoreW` and read on `LocalLoad`.
    /// The fixed-point loop ensures convergence when stored types change
    /// across iterations.
    types: HashMap<u16, TypeFact>,
    /// Requirements propagated backward to local variable slots.
    requirements: HashMap<u16, TypeFact>,
}

impl LocalState {
    /// Read the inferred type for a local slot.
    pub(super) fn type_for_slot(&self, index: u16) -> TypeFact {
        self.types.get(&index).copied().unwrap_or(TypeFact::Felt)
    }

    /// Read the accumulated requirement for a local slot.
    pub(super) fn requirement_for_slot(&self, index: u16) -> TypeFact {
        self.requirements.get(&index).copied().unwrap_or(TypeFact::Felt)
    }

    /// Record the inferred type for a local variable slot from stored values.
    pub(super) fn record_store_type(&mut self, index: u16, stored_ty: TypeFact) -> bool {
        let current = self.types.get(&index).copied();
        let updated = match current {
            Some(existing) => existing.join(stored_ty),
            None => stored_ty,
        };
        if current != Some(updated) {
            self.types.insert(index, updated);
            true
        } else {
            false
        }
    }

    /// Accumulate a requirement for a local variable slot.
    pub(super) fn require_slot(&mut self, index: u16, req: TypeFact) -> bool {
        let current = self.requirement_for_slot(index);
        let updated = current.glb(req);
        if updated != current {
            self.requirements.insert(index, updated);
            true
        } else {
            false
        }
    }

    /// Join another local state into this one.
    pub(super) fn join_assign(&mut self, other: &Self) -> bool {
        let mut changed = false;
        for (index, stored_ty) in &other.types {
            changed |= self.record_store_type(*index, *stored_ty);
        }
        for (index, req) in &other.requirements {
            changed |= self.require_slot(*index, *req);
        }
        changed
    }
}
