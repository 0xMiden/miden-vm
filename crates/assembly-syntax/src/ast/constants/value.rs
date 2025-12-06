use core::fmt;

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::{SourceSpan, Span, Spanned};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    ast::{HashKind, Ident},
    parser::{IntValue, WordValue},
};

// CONSTANT VALUE
// ================================================================================================

/// Represents a constant value in Miden Assembly syntax.
#[derive(Clone)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ConstantValue {
    /// A literal [`miden_core::Felt`] value.
    Int(Span<IntValue>) = 1,
    /// A plain spanned string.
    String(Ident),
    /// A literal ['WordValue'].
    Word(Span<WordValue>),
    /// A spanned string with a [`HashKind`] showing to which type of value the given string should
    /// be hashed.
    Hash(HashKind, Ident),
}

impl Eq for ConstantValue {}

impl PartialEq for ConstantValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Int(l), Self::Int(y)) => l == y,
            (Self::Int(_), _) => false,
            (Self::Word(l), Self::Word(y)) => l == y,
            (Self::Word(_), _) => false,
            (Self::String(l), Self::String(y)) => l == y,
            (Self::String(_), _) => false,
            (Self::Hash(x_hk, x_i), Self::Hash(y_hk, y_i)) => x_i == y_i && x_hk == y_hk,
            (Self::Hash(..), _) => false,
        }
    }
}

impl core::hash::Hash for ConstantValue {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Int(value) => value.hash(state),
            Self::Word(value) => value.hash(state),
            Self::String(value) => value.hash(state),
            Self::Hash(kind, value) => {
                kind.hash(state);
                value.hash(state);
            },
        }
    }
}

impl fmt::Debug for ConstantValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Int(lit) => fmt::Debug::fmt(&**lit, f),
            Self::Word(lit) => fmt::Debug::fmt(&**lit, f),
            Self::String(name) => fmt::Debug::fmt(&**name, f),
            Self::Hash(hash_kind, str) => fmt::Debug::fmt(&(str, hash_kind), f),
        }
    }
}

impl crate::prettier::PrettyPrint for ConstantValue {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::Int(literal) => literal.render(),
            Self::Word(literal) => literal.render(),
            Self::String(ident) => text(format!("\"{}\"", ident.as_str().escape_debug())),
            Self::Hash(hash_kind, str) => flatten(
                display(hash_kind)
                    + const_text("(")
                    + text(format!("\"{}\"", str.as_str().escape_debug()))
                    + const_text(")"),
            ),
        }
    }
}

impl Spanned for ConstantValue {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Int(spanned) => spanned.span(),
            Self::Word(spanned) => spanned.span(),
            Self::String(spanned) => spanned.span(),
            Self::Hash(_, spanned) => spanned.span(),
        }
    }
}

impl ConstantValue {
    const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

impl Serializable for ConstantValue {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.tag());
        match self {
            Self::Int(value) => value.inner().write_into(target),
            Self::String(id) => id.write_into(target),
            Self::Word(value) => value.inner().write_into(target),
            Self::Hash(kind, id) => {
                kind.write_into(target);
                id.write_into(target);
            },
        }
    }
}

impl Deserializable for ConstantValue {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            1 => IntValue::read_from(source).map(Span::unknown).map(Self::Int),
            2 => Ident::read_from(source).map(Self::String),
            3 => WordValue::read_from(source).map(Span::unknown).map(Self::Word),
            4 => {
                let kind = HashKind::read_from(source)?;
                let id = Ident::read_from(source)?;
                Ok(Self::Hash(kind, id))
            },
            invalid => Err(DeserializationError::InvalidValue(format!(
                "unexpected ConstantValue tag: '{invalid}'"
            ))),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for ConstantValue {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<IntValue>().prop_map(|n| Self::Int(Span::unknown(n))),
            any::<Ident>().prop_map(Self::String),
            any::<WordValue>().prop_map(|word| Self::Word(Span::unknown(word))),
            any::<(HashKind, Ident)>().prop_map(|(kind, s)| Self::Hash(kind, s)),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
