//! Abstract memory address identity used by local type inference.

use std::collections::{HashMap, HashSet};

use super::domain::{TypeFact, VarKey};
use crate::ir::{BinOp, Constant, Expr, Var};

/// Upper bound (exclusive) of the valid Miden VM memory address range.
///
/// Memory addresses must be in `[0, 2^32)`. Operations like `mem_load`
/// and `mem_store` trap at runtime if the address is `>= 2^32`.
pub(super) const MAX_MEMORY_ADDRESS: u64 = 1u64 << 32;

/// Abstract memory address identity for type tracking.
///
/// Two memory operations target the same logical address when they share
/// the same `MemAddressKey`. This is necessary because the lifter creates
/// distinct SSA variables for each address operand, even when they refer
/// to the same constant or `locaddr` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum MemAddressKey {
    /// Constant address known to be in the valid memory range `[0, 2^32)`.
    ///
    /// Stored as `u32` to enforce the range invariant at the type level.
    /// Created from `Constant::Felt(n)` assignments where `n < 2^32`.
    Constant(u32),
    /// Local-mapped address (from `locaddr.N`).
    LocalAddr(u16),
    /// Local-mapped address offset by a known constant (from `locaddr.N + k`).
    ///
    /// Only created for `Add` operations (not `Sub`), because field `sub`
    /// computes `(a - b) mod p` which can wrap to addresses outside the
    /// procedure's local frame.
    ///
    /// The absolute address is not known at analysis time, but two operations
    /// sharing the same `(local_index, offset)` target the same location.
    LocalAddrOffset(u16, u32),
}

/// Memory-related fixed-point state for one procedure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct MemoryState {
    /// Maps SSA variables to their abstract memory address identity.
    ///
    /// Populated during inference when a variable is defined as a constant
    /// (`Assign { expr: Constant(Felt(n)) }`) or a `locaddr.N` intrinsic
    /// result. Also propagated through variable copies
    /// (`Assign { expr: Var(src) }`).
    var_address_keys: HashMap<VarKey, MemAddressKey>,
    /// Variables whose memory identity is known to be ambiguous.
    ///
    /// This prevents a conflict found during lattice merge from being re-added
    /// as a concrete identity on the next join.
    ambiguous_address_keys: HashSet<VarKey>,
    /// Inferred types for memory locations, keyed by abstract address.
    mem_types: HashMap<MemAddressKey, TypeFact>,
    /// Requirements propagated backward to memory locations.
    mem_requirements: HashMap<MemAddressKey, TypeFact>,
}

impl MemoryState {
    /// Resolve the abstract memory address key for a variable, if known.
    pub(super) fn address_key_for_var(&self, var: &Var) -> Option<MemAddressKey> {
        let key = VarKey::from_var(var);
        if self.ambiguous_address_keys.contains(&key) {
            None
        } else {
            self.var_address_keys.get(&key).copied()
        }
    }

    /// Associate a variable with an abstract memory address key.
    pub(super) fn set_var_address_key(&mut self, var: &Var, key: MemAddressKey) {
        let var_key = VarKey::from_var(var);
        self.ambiguous_address_keys.remove(&var_key);
        self.var_address_keys.insert(var_key, key);
    }

    /// Copy a source variable's abstract memory address identity to a destination.
    pub(super) fn copy_address_key(&mut self, dest: &Var, src: &Var) {
        if let Some(key) = self.address_key_for_var(src) {
            self.set_var_address_key(dest, key);
        }
    }

    /// Track the abstract memory address identity produced by an assignment.
    pub(super) fn track_assignment_address_key(&mut self, dest: &Var, expr: &Expr) {
        match expr {
            Expr::Constant(Constant::Felt(n)) if *n < MAX_MEMORY_ADDRESS => {
                self.set_var_address_key(dest, MemAddressKey::Constant(*n as u32));
            },
            Expr::Var(src) => {
                self.copy_address_key(dest, src);
            },
            Expr::Binary(BinOp::Add, lhs, rhs) => {
                let key = self
                    .resolve_addr_offset_key(lhs, rhs)
                    .or_else(|| self.resolve_addr_offset_key(rhs, lhs));
                if let Some(key) = key {
                    self.set_var_address_key(dest, key);
                }
            },
            _ => {},
        }
    }

    /// Track `locaddr.N` intrinsic results as local memory address identities.
    pub(super) fn track_locaddr_results(&mut self, name: &str, results: &[Var]) {
        let Some(index_str) = name.strip_prefix("locaddr.") else {
            return;
        };
        let Ok(index) = index_str.parse::<u16>() else {
            return;
        };
        for result in results {
            self.set_var_address_key(result, MemAddressKey::LocalAddr(index));
        }
    }

    /// Read the inferred type for a memory address, if one has been stored.
    pub(super) fn type_for_address(&self, key: MemAddressKey) -> Option<TypeFact> {
        self.mem_types.get(&key).copied()
    }

    /// Read the accumulated requirement for a memory address.
    pub(super) fn requirement_for_address(&self, key: MemAddressKey) -> TypeFact {
        self.mem_requirements.get(&key).copied().unwrap_or(TypeFact::Felt)
    }

    /// Record a type stored to a memory address.
    pub(super) fn record_store_type(&mut self, key: MemAddressKey, stored_ty: TypeFact) -> bool {
        let current = self.mem_types.get(&key).copied();
        let updated = match current {
            Some(existing) => existing.join(stored_ty),
            None => stored_ty,
        };
        if current != Some(updated) {
            self.mem_types.insert(key, updated);
            true
        } else {
            false
        }
    }

    /// Accumulate a requirement for a memory address.
    pub(super) fn require_address(&mut self, key: MemAddressKey, req: TypeFact) -> bool {
        let current = self.requirement_for_address(key);
        let updated = current.glb(req);
        if updated != current {
            self.mem_requirements.insert(key, updated);
            true
        } else {
            false
        }
    }

    /// Accumulate output requirements from values loaded out of a memory address.
    pub(super) fn require_address_from_outputs(
        &mut self,
        key: MemAddressKey,
        requirements: impl IntoIterator<Item = TypeFact>,
    ) -> bool {
        requirements
            .into_iter()
            .filter(|req| *req != TypeFact::Felt)
            .fold(false, |changed, req| self.require_address(key, req) | changed)
    }

    /// Return requirements that must be pushed back to values stored at an address.
    pub(super) fn store_value_requirements<'a>(
        &self,
        key: MemAddressKey,
        values: &'a [Var],
    ) -> impl Iterator<Item = (&'a Var, TypeFact)> {
        let req = self.requirement_for_address(key);
        (req != TypeFact::Felt)
            .then_some(req)
            .into_iter()
            .flat_map(move |req| values.iter().map(move |value| (value, req)))
    }

    /// Propagate a memory address key through a phi when both incoming keys agree.
    pub(super) fn propagate_phi_address_key(&mut self, dest: &Var, lhs: &Var, rhs: &Var) {
        let lhs_key = self.address_key_for_var(lhs);
        let rhs_key = self.address_key_for_var(rhs);
        if let (Some(lk), Some(rk)) = (lhs_key, rhs_key)
            && lk == rk
        {
            self.set_var_address_key(dest, lk);
        }
    }

    /// Resolve a `MemAddressKey` for an address-plus-offset expression.
    ///
    /// Returns `Some(LocalAddrOffset(index, offset))` when `base_expr`
    /// resolves to a `LocalAddr` or `LocalAddrOffset` key and `offset_expr`
    /// is a constant in `[0, 2^32)`. Returns `None` if the accumulated
    /// offset overflows `u32` or the base is not a local address.
    fn resolve_addr_offset_key(
        &self,
        base_expr: &Expr,
        offset_expr: &Expr,
    ) -> Option<MemAddressKey> {
        let base_key = match base_expr {
            Expr::Var(v) => self.address_key_for_var(v)?,
            _ => return None,
        };
        let offset: u32 = match offset_expr {
            Expr::Constant(Constant::Felt(n)) if *n < MAX_MEMORY_ADDRESS => *n as u32,
            Expr::Var(v) => match self.address_key_for_var(v)? {
                MemAddressKey::Constant(n) => n,
                _ => return None,
            },
            _ => return None,
        };
        match base_key {
            MemAddressKey::LocalAddr(index) => Some(MemAddressKey::LocalAddrOffset(index, offset)),
            MemAddressKey::LocalAddrOffset(index, base_offset) => {
                let total = base_offset.checked_add(offset)?;
                Some(MemAddressKey::LocalAddrOffset(index, total))
            },
            MemAddressKey::Constant(_) => None,
        }
    }

    /// Join another memory state into this one.
    pub(super) fn join_assign(&mut self, other: &Self) -> bool {
        let mut changed = false;

        for key in &other.ambiguous_address_keys {
            changed |= self.mark_ambiguous_address_key(key.clone());
        }

        for (var_key, address_key) in &other.var_address_keys {
            if self.ambiguous_address_keys.contains(var_key) {
                continue;
            }
            match self.var_address_keys.get(var_key).copied() {
                Some(existing) if existing == *address_key => {},
                Some(_) => {
                    changed |= self.mark_ambiguous_address_key(var_key.clone());
                },
                None => {
                    self.var_address_keys.insert(var_key.clone(), *address_key);
                    changed = true;
                },
            }
        }

        for (key, ty) in &other.mem_types {
            changed |= self.record_store_type(*key, *ty);
        }

        for (key, req) in &other.mem_requirements {
            changed |= self.require_address(*key, *req);
        }

        changed
    }

    fn mark_ambiguous_address_key(&mut self, key: VarKey) -> bool {
        let removed = self.var_address_keys.remove(&key).is_some();
        let inserted = self.ambiguous_address_keys.insert(key);
        removed || inserted
    }
}
