use miden_crypto::ZERO;

use super::DeferredError;
use crate::Felt;

// TAG CONSTANTS
// ================================================================================================
//
// Tags are four field elements `[t0, t1, t2, t3]` where the first two felts identify the value
// type family (the "type prefix") and the last two identify the operation within that family.
// A bit-packed layout is deliberately punted; constants are kept small so the layout can change
// later by editing this file alone.

/// Value-type family identifier for non-native field arithmetic.
pub const FIELD: Felt = Felt::new_unchecked(1);

/// Sub-family within `FIELD`: the first 256-bit non-native field.
pub const FIELD_0: Felt = Felt::new_unchecked(0);

// Operation suffixes within the `FIELD_0` family.
const OP_LEAF: Felt = Felt::new_unchecked(0);
const OP_ADD: Felt = Felt::new_unchecked(1);
const OP_MUL: Felt = Felt::new_unchecked(2);
const OP_ASSERT_EQ: Felt = Felt::new_unchecked(3);

// TAG KIND
// ================================================================================================

/// Coarse classification of a [`DeferredTag`]. Used by the generic recursion driver to decide
/// whether a node is a leaf (payload is value data), a binary op (payload is two child digests),
/// or an assertion (not a valid node body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagKind {
    Leaf,
    BinaryOp,
    AssertEq,
}

// VALUE TYPE
// ================================================================================================

/// Identifier for a value-type family. One [`crate::deferred::ValueType`] maps to one type handler
/// in the processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValueType {
    Field0,
}

// DEFERRED TAG
// ================================================================================================

/// Enum-backed identifier for every operation the deferred subsystem understands.
///
/// The canonical wire/hash form is `[Felt; 4]` via [`DeferredTag::to_felts`]. The first two felts
/// are the type prefix (which type handler responds), the last two select the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeferredTag {
    Field0Leaf,
    Field0Add,
    Field0Mul,
    Field0AssertEq,
}

impl DeferredTag {
    /// Encodes this tag as 4 field elements.
    pub fn to_felts(self) -> [Felt; 4] {
        match self {
            DeferredTag::Field0Leaf => [FIELD, FIELD_0, OP_LEAF, ZERO],
            DeferredTag::Field0Add => [FIELD, FIELD_0, OP_ADD, ZERO],
            DeferredTag::Field0Mul => [FIELD, FIELD_0, OP_MUL, ZERO],
            DeferredTag::Field0AssertEq => [FIELD, FIELD_0, OP_ASSERT_EQ, ZERO],
        }
    }

    /// Decodes 4 field elements into a known tag.
    pub fn from_felts(t: [Felt; 4]) -> Result<Self, DeferredError> {
        if t[3] != ZERO {
            return Err(DeferredError::InvalidTag);
        }
        if t[0] == FIELD && t[1] == FIELD_0 {
            return match t[2] {
                x if x == OP_LEAF => Ok(DeferredTag::Field0Leaf),
                x if x == OP_ADD => Ok(DeferredTag::Field0Add),
                x if x == OP_MUL => Ok(DeferredTag::Field0Mul),
                x if x == OP_ASSERT_EQ => Ok(DeferredTag::Field0AssertEq),
                _ => Err(DeferredError::InvalidTag),
            };
        }
        Err(DeferredError::InvalidTag)
    }

    /// First two felts of [`Self::to_felts`]; used as the registry key for type-handler dispatch.
    pub fn type_prefix(self) -> [Felt; 2] {
        let f = self.to_felts();
        [f[0], f[1]]
    }

    /// Classification used by the generic evaluation driver.
    pub fn kind(self) -> TagKind {
        match self {
            DeferredTag::Field0Leaf => TagKind::Leaf,
            DeferredTag::Field0Add | DeferredTag::Field0Mul => TagKind::BinaryOp,
            DeferredTag::Field0AssertEq => TagKind::AssertEq,
        }
    }

    /// The value-type family this tag belongs to.
    pub fn value_type(self) -> ValueType {
        match self {
            DeferredTag::Field0Leaf
            | DeferredTag::Field0Add
            | DeferredTag::Field0Mul
            | DeferredTag::Field0AssertEq => ValueType::Field0,
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [DeferredTag; 4] = [
        DeferredTag::Field0Leaf,
        DeferredTag::Field0Add,
        DeferredTag::Field0Mul,
        DeferredTag::Field0AssertEq,
    ];

    #[test]
    fn to_from_felts_roundtrip() {
        for tag in ALL {
            let felts = tag.to_felts();
            assert_eq!(DeferredTag::from_felts(felts).unwrap(), tag);
        }
    }

    #[test]
    fn from_felts_rejects_unknown_prefix() {
        let bad = [Felt::new_unchecked(99), FIELD_0, OP_LEAF, ZERO];
        assert!(matches!(DeferredTag::from_felts(bad), Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn from_felts_rejects_unknown_op_suffix() {
        let bad = [FIELD, FIELD_0, Felt::new_unchecked(99), ZERO];
        assert!(matches!(DeferredTag::from_felts(bad), Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn from_felts_rejects_nonzero_padding() {
        let bad = [FIELD, FIELD_0, OP_LEAF, Felt::new_unchecked(1)];
        assert!(matches!(DeferredTag::from_felts(bad), Err(DeferredError::InvalidTag)));
    }

    #[test]
    fn type_prefix_matches_first_two_felts() {
        for tag in ALL {
            let f = tag.to_felts();
            assert_eq!(tag.type_prefix(), [f[0], f[1]]);
        }
    }

    #[test]
    fn kinds_classified_correctly() {
        assert_eq!(DeferredTag::Field0Leaf.kind(), TagKind::Leaf);
        assert_eq!(DeferredTag::Field0Add.kind(), TagKind::BinaryOp);
        assert_eq!(DeferredTag::Field0Mul.kind(), TagKind::BinaryOp);
        assert_eq!(DeferredTag::Field0AssertEq.kind(), TagKind::AssertEq);
    }
}
