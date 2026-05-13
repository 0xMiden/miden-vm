//! Abstract memory address identity used by local type inference.

use std::collections::HashMap;

use super::domain::{TypeFact, VarKey};
use crate::ir::Var;

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
    /// Inferred types for memory locations, keyed by abstract address.
    mem_types: HashMap<MemAddressKey, TypeFact>,
    /// Requirements propagated backward to memory locations.
    mem_requirements: HashMap<MemAddressKey, TypeFact>,
}

impl MemoryState {
    /// Resolve the abstract memory address key for a variable, if known.
    pub(super) fn address_key_for_var(&self, var: &Var) -> Option<MemAddressKey> {
        self.var_address_keys.get(&VarKey::from_var(var)).copied()
    }

    /// Associate a variable with an abstract memory address key.
    pub(super) fn set_var_address_key(&mut self, var: &Var, key: MemAddressKey) {
        self.var_address_keys.insert(VarKey::from_var(var), key);
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
}
