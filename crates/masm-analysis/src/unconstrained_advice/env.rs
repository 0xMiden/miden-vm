//! Abstract environment state for unconstrained-advice analyses.

use std::collections::{HashMap, HashSet};

use masm_decompiler::{Var, VarKey};

use super::{domain::AdviceFact, u32_domain::U32Validity};
use crate::abstract_interp::JoinSemiLattice;

/// Exact witness that a boolean value was computed as `x == 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EqZeroWitness {
    /// Alias identity of the value compared against zero.
    pub(super) value_identity: VarKey,
}

/// Shared flow environment at a program point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Env {
    vars: HashMap<VarKey, AdviceFact>,
    locals: HashMap<u32, AdviceFact>,
    u32_validity: HashMap<VarKey, U32Validity>,
    local_u32_validity: HashMap<u32, U32Validity>,
    u32_valid_identities: HashSet<VarKey>,
    aliases: HashMap<VarKey, VarKey>,
    local_aliases: HashMap<u32, VarKey>,
    zero_tests: HashMap<VarKey, EqZeroWitness>,
    local_zero_tests: HashMap<u32, EqZeroWitness>,
    nonzero_identities: HashSet<VarKey>,
}

impl Env {
    /// Read the current fact for a variable.
    pub(super) fn fact_for_var(&self, var: &Var) -> AdviceFact {
        self.vars
            .get(&VarKey::from_var(var))
            .cloned()
            .unwrap_or_else(AdviceFact::bottom)
    }

    /// Set the current fact for a variable.
    pub(super) fn set_var_fact(&mut self, var: &Var, fact: AdviceFact) {
        self.vars.insert(VarKey::from_var(var), fact);
    }

    /// Read the current `u32` validity fact for a variable.
    pub(super) fn u32_validity_for_var(&self, var: &Var) -> U32Validity {
        let key = VarKey::from_var(var);
        let direct = self.u32_validity.get(&key).copied().unwrap_or(U32Validity::Unknown);
        if direct.is_proven() {
            return direct;
        }

        let identity = self.identity_for_var(var);
        if self.u32_valid_identities.contains(&identity) {
            U32Validity::ProvenU32
        } else {
            U32Validity::Unknown
        }
    }

    /// Set the current `u32` validity fact for a variable.
    pub(super) fn set_var_u32_validity(&mut self, var: &Var, validity: U32Validity) {
        let key = VarKey::from_var(var);
        if validity.is_proven() {
            self.u32_validity.insert(key.clone(), validity);
        } else {
            self.u32_validity.remove(&key);
        }
        let identity = self.identity_for_var(var);
        self.refresh_u32_identity_cache(&identity);
    }

    /// Return the alias identity for a variable.
    pub(super) fn identity_for_var(&self, var: &Var) -> VarKey {
        let key = VarKey::from_var(var);
        self.aliases.get(&key).cloned().unwrap_or(key)
    }

    /// Return the alias identity for a local slot, if known.
    pub(super) fn identity_for_local(&self, slot: u32) -> Option<VarKey> {
        self.local_aliases.get(&slot).cloned()
    }

    /// Set the alias identity for a variable.
    pub(super) fn set_var_identity(&mut self, var: &Var, identity: VarKey) {
        let key = VarKey::from_var(var);
        let old_identity = self.identity_for_var(var);
        if identity == key {
            self.aliases.remove(&key);
        } else {
            self.aliases.insert(key, identity);
        }
        self.refresh_u32_identity_cache(&old_identity);
        self.refresh_u32_identity_cache(&self.identity_for_var(var));
    }

    /// Clear any alias identity for a variable.
    pub(super) fn clear_var_identity(&mut self, var: &Var) {
        let old_identity = self.identity_for_var(var);
        self.aliases.remove(&VarKey::from_var(var));
        self.refresh_u32_identity_cache(&old_identity);
        self.refresh_u32_identity_cache(&self.identity_for_var(var));
    }

    /// Set the alias identity for a local slot.
    pub(super) fn set_local_identity(&mut self, slot: u32, identity: Option<VarKey>) {
        let old_identity = self.identity_for_local(slot);
        match identity {
            Some(identity) => {
                self.local_aliases.insert(slot, identity);
            },
            None => {
                self.local_aliases.remove(&slot);
            },
        }
        if let Some(identity) = old_identity {
            self.refresh_u32_identity_cache(&identity);
        }
        if let Some(identity) = self.identity_for_local(slot) {
            self.refresh_u32_identity_cache(&identity);
        }
    }

    /// Return the zero-test witness for a variable, if any.
    pub(super) fn zero_test_for_var(&self, var: &Var) -> Option<EqZeroWitness> {
        self.zero_tests.get(&VarKey::from_var(var)).cloned()
    }

    /// Return the zero-test witness for a local slot, if any.
    pub(super) fn zero_test_for_local(&self, slot: u32) -> Option<EqZeroWitness> {
        self.local_zero_tests.get(&slot).cloned()
    }

    /// Set the zero-test witness for a variable.
    pub(super) fn set_var_zero_test(&mut self, var: &Var, witness: Option<EqZeroWitness>) {
        match witness {
            Some(witness) => {
                self.zero_tests.insert(VarKey::from_var(var), witness);
            },
            None => {
                self.zero_tests.remove(&VarKey::from_var(var));
            },
        }
    }

    /// Set the zero-test witness for a local slot.
    pub(super) fn set_local_zero_test(&mut self, slot: u32, witness: Option<EqZeroWitness>) {
        match witness {
            Some(witness) => {
                self.local_zero_tests.insert(slot, witness);
            },
            None => {
                self.local_zero_tests.remove(&slot);
            },
        }
    }

    /// Return true if the variable is proven non-zero on the current path.
    pub(super) fn is_var_nonzero(&self, var: &Var) -> bool {
        self.nonzero_identities.contains(&self.identity_for_var(var))
    }

    /// Mark the given alias identity as non-zero on the current path.
    pub(super) fn mark_identity_nonzero(&mut self, identity: VarKey) {
        self.nonzero_identities.insert(identity);
    }

    /// Clear all best-effort metadata for a variable definition.
    pub(super) fn clear_var_metadata(&mut self, var: &Var) {
        self.clear_var_identity(var);
        self.set_var_zero_test(var, None);
    }

    /// Mark a variable as range-checked from this point onward.
    pub(super) fn sanitize_var(&mut self, var: &Var) {
        let identity = self.identity_for_var(var);
        self.set_identity_u32_validity(&identity, U32Validity::ProvenU32);
    }

    /// Read the current fact for a local slot.
    pub(super) fn fact_for_local(&self, slot: u32) -> AdviceFact {
        self.locals.get(&slot).cloned().unwrap_or_else(AdviceFact::bottom)
    }

    /// Read the current `u32` validity fact for a local slot.
    pub(super) fn u32_validity_for_local(&self, slot: u32) -> U32Validity {
        let direct = self.local_u32_validity.get(&slot).copied().unwrap_or(U32Validity::Unknown);
        if direct.is_proven() {
            return direct;
        }

        self.identity_for_local(slot)
            .filter(|identity| self.u32_valid_identities.contains(identity))
            .map(|_| U32Validity::ProvenU32)
            .unwrap_or(U32Validity::Unknown)
    }

    /// Set the current fact for a local slot.
    pub(super) fn set_local_fact(&mut self, slot: u32, fact: AdviceFact) {
        self.locals.insert(slot, fact);
    }

    /// Set the current `u32` validity fact for a local slot.
    pub(super) fn set_local_u32_validity(&mut self, slot: u32, validity: U32Validity) {
        if validity.is_proven() {
            self.local_u32_validity.insert(slot, validity);
        } else {
            self.local_u32_validity.remove(&slot);
        }
        if let Some(identity) = self.identity_for_local(slot) {
            self.refresh_u32_identity_cache(&identity);
        }
    }

    /// Join two environments conservatively.
    pub(super) fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        for (key, fact) in &other.vars {
            let current = joined.vars.get(key).cloned().unwrap_or_else(AdviceFact::bottom);
            joined.vars.insert(key.clone(), current.join(fact));
        }
        for (slot, fact) in &other.locals {
            let current = joined.locals.get(slot).cloned().unwrap_or_else(AdviceFact::bottom);
            joined.locals.insert(*slot, current.join(fact));
        }
        joined.u32_validity = join_u32_validity_maps(&self.u32_validity, &other.u32_validity);
        joined.local_u32_validity =
            join_u32_validity_maps(&self.local_u32_validity, &other.local_u32_validity);
        joined.aliases = agreeing_entries(&self.aliases, &other.aliases);
        joined.local_aliases = agreeing_entries(&self.local_aliases, &other.local_aliases);
        joined.zero_tests = agreeing_entries(&self.zero_tests, &other.zero_tests);
        joined.local_zero_tests = agreeing_entries(&self.local_zero_tests, &other.local_zero_tests);
        joined.nonzero_identities = self
            .nonzero_identities
            .intersection(&other.nonzero_identities)
            .cloned()
            .collect();
        joined.rebuild_u32_identity_cache();
        joined
    }

    /// Set one alias identity to the requested `u32` validity fact.
    fn set_identity_u32_validity(&mut self, identity: &VarKey, validity: U32Validity) {
        if validity.is_proven() {
            self.u32_validity.insert(identity.clone(), validity);
        } else {
            self.u32_validity.remove(identity);
        }
        for key in self
            .aliases
            .iter()
            .filter_map(|(key, alias)| (alias == identity).then_some(key.clone()))
        {
            if validity.is_proven() {
                self.u32_validity.insert(key, validity);
            } else {
                self.u32_validity.remove(&key);
            }
        }
        for (slot, alias) in self.local_aliases.clone() {
            if alias == *identity {
                if validity.is_proven() {
                    self.local_u32_validity.insert(slot, validity);
                } else {
                    self.local_u32_validity.remove(&slot);
                }
            }
        }
        if validity.is_proven() {
            self.u32_valid_identities.insert(identity.clone());
        } else {
            self.u32_valid_identities.remove(identity);
        }
    }

    /// Refresh the cached `u32` proof bit for one alias identity.
    fn refresh_u32_identity_cache(&mut self, identity: &VarKey) {
        let has_proven_var = self
            .u32_validity
            .keys()
            .any(|key| self.aliases.get(key).cloned().unwrap_or_else(|| key.clone()) == *identity);
        let has_proven_local = self
            .local_u32_validity
            .keys()
            .any(|slot| self.local_aliases.get(slot).cloned() == Some(identity.clone()));
        if has_proven_var || has_proven_local {
            self.u32_valid_identities.insert(identity.clone());
        } else {
            self.u32_valid_identities.remove(identity);
        }
    }

    /// Rebuild the alias-identity proof cache from place-level validity facts.
    fn rebuild_u32_identity_cache(&mut self) {
        self.u32_valid_identities.clear();
        let identities = self
            .u32_validity
            .keys()
            .map(|key| self.aliases.get(key).cloned().unwrap_or_else(|| key.clone()))
            .chain(
                self.local_u32_validity
                    .keys()
                    .filter_map(|slot| self.local_aliases.get(slot).cloned()),
            )
            .collect::<Vec<_>>();
        for identity in identities {
            self.refresh_u32_identity_cache(&identity);
        }
    }
}

impl JoinSemiLattice for Env {
    fn join_assign(&mut self, other: &Self) -> bool {
        let joined = self.join(other);
        let changed = *self != joined;
        *self = joined;
        changed
    }
}

/// Retain only entries that are present in both maps with the same value.
fn agreeing_entries<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + Eq,
{
    lhs.iter()
        .filter_map(|(key, value)| {
            rhs.get(key)
                .filter(|other| *other == value)
                .map(|_| (key.clone(), value.clone()))
        })
        .collect()
}

/// Join two sparse `u32` validity maps, treating absent entries as unknown.
fn join_u32_validity_maps<K>(
    lhs: &HashMap<K, U32Validity>,
    rhs: &HashMap<K, U32Validity>,
) -> HashMap<K, U32Validity>
where
    K: Clone + Eq + std::hash::Hash,
{
    lhs.keys()
        .chain(rhs.keys())
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|key| {
            let merged = lhs
                .get(key)
                .copied()
                .unwrap_or(U32Validity::Unknown)
                .join(rhs.get(key).copied().unwrap_or(U32Validity::Unknown));
            merged.is_proven().then_some((key.clone(), merged))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use masm_decompiler::Var;

    use super::*;

    fn var(depth: usize) -> Var {
        Var::new((depth as u64).into(), depth)
    }

    #[test]
    fn join_requires_var_u32_validity_on_both_sides() {
        let value = var(0);
        let mut proven = Env::default();
        proven.set_var_u32_validity(&value, U32Validity::ProvenU32);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_var(&value), U32Validity::ProvenU32);
    }

    #[test]
    fn join_preserves_sanitized_identity_u32_validity_when_both_sides_prove_it() {
        let value = var(0);
        let mut proven = Env::default();
        proven.sanitize_var(&value);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_var(&value), U32Validity::ProvenU32);
    }

    #[test]
    fn join_requires_local_u32_validity_on_both_sides() {
        let mut proven = Env::default();
        proven.set_local_u32_validity(7, U32Validity::ProvenU32);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_local(7), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_local(7), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_local(7), U32Validity::ProvenU32);
    }
}
