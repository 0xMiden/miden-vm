//! Core type-analysis domain.

use std::fmt;

use crate::ir::{IndexExpr, ValueId, Var, VarBase};

/// Internal dataflow fact for the scalar type chain `Bool < U32 < Felt`.
///
/// This type is used within the type analysis pass for lattice-based inference.
/// It is not exposed outside `src/types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum TypeFact {
    /// Generic field element (top of lattice).
    Felt,
    /// 32-bit unsigned integer.
    U32,
    /// Boolean value (bottom of lattice).
    Bool,
}

impl TypeFact {
    /// Numeric rank in the chain `Bool(0) < U32(1) < Felt(2)`.
    const fn rank(self) -> u8 {
        match self {
            Self::Bool => 0,
            Self::U32 => 1,
            Self::Felt => 2,
        }
    }

    /// Least upper bound (join) in the chain lattice.
    ///
    /// Used at control-flow merge points (if-phi, loop-phi).
    pub(super) fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() { self } else { other }
    }

    /// Greatest lower bound (meet/glb) in the chain lattice.
    ///
    /// Used when accumulating evidence about the same SSA value or storage cell.
    pub(super) fn glb(self, other: Self) -> Self {
        if self.rank() <= other.rank() { self } else { other }
    }

    /// Check whether `self` (actual inferred fact) satisfies `req` (expected).
    ///
    /// Returns `true` when `self` is at least as specific as `req`
    /// (i.e. `self <= req` in the lattice order).
    pub(super) fn satisfies(self, req: Self) -> bool {
        self.rank() <= req.rank()
    }

    /// Convert to the public `InferredType` surface type.
    pub(super) fn to_inferred_type(self) -> InferredType {
        match self {
            Self::Felt => InferredType::Felt,
            Self::U32 => InferredType::U32,
            Self::Bool => InferredType::Bool,
        }
    }

    /// Convert to the public `TypeRequirement` surface type.
    pub(super) fn to_requirement(self) -> TypeRequirement {
        match self {
            Self::Felt => TypeRequirement::Felt,
            Self::U32 => TypeRequirement::U32,
            Self::Bool => TypeRequirement::Bool,
        }
    }

    /// Convert from a public `InferredType`.
    pub(super) fn from_inferred_type(ty: InferredType) -> Self {
        match ty {
            InferredType::Felt => Self::Felt,
            InferredType::U32 => Self::U32,
            InferredType::Bool => Self::Bool,
        }
    }

    /// Convert from a public `TypeRequirement`.
    pub(super) fn from_requirement(req: TypeRequirement) -> Self {
        match req {
            TypeRequirement::Felt => Self::Felt,
            TypeRequirement::U32 => Self::U32,
            TypeRequirement::Bool => Self::Bool,
        }
    }
}

/// Conservative type inferred for a stack value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InferredType {
    /// Generic field element.
    Felt,
    /// Boolean value (`0` or `1`).
    Bool,
    /// 32-bit unsigned integer.
    U32,
}

impl fmt::Display for InferredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Felt => write!(f, "Felt"),
            Self::Bool => write!(f, "Bool"),
            Self::U32 => write!(f, "U32"),
        }
    }
}

/// Required type at a use site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeRequirement {
    /// Any value promotable to felt is accepted.
    Felt,
    /// Boolean is required.
    Bool,
    /// U32 is required.
    U32,
}

impl fmt::Display for TypeRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Felt => write!(f, "Felt"),
            Self::Bool => write!(f, "Bool"),
            Self::U32 => write!(f, "U32"),
        }
    }
}

/// Base identity used in type maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarBaseKey {
    /// Concrete SSA value.
    Value(ValueId),
    /// Repeat-loop input identity.
    LoopInput(usize),
}

/// Hashable identity key for a variable version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarKey {
    /// Base identity.
    pub base: VarBaseKey,
    /// SSA subscript.
    pub subscript: IndexExpr,
}

impl VarKey {
    /// Build a key from a variable.
    pub fn from_var(var: &Var) -> Self {
        let base = match var.base {
            VarBase::Value(id) => VarBaseKey::Value(id),
            VarBase::LoopInput { loop_depth } => VarBaseKey::LoopInput(loop_depth),
        };
        Self { base, subscript: var.subscript.clone() }
    }
}
