use alloc::{string::String, sync::Arc};

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::{SourceSpan, Span, Spanned};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    Felt,
    ast::Ident,
    parser::{IntValue, WordValue},
    prettier,
};

/// Represents a metadata expression of an [crate::ast::Attribute]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum MetaExpr {
    /// An identifier/keyword, e.g. `inline`
    Ident(Ident),
    /// A decimal or hexadecimal integer value
    Int(Span<IntValue>),
    /// A word-sized value
    Word(Span<WordValue>),
    /// A quoted string or identifier
    String(Ident),
}

impl prettier::PrettyPrint for MetaExpr {
    fn render(&self) -> prettier::Document {
        use prettier::*;

        match self {
            Self::Ident(id) => text(id),
            Self::Int(value) => value.inner().render(),
            Self::Word(value) => display(value),
            Self::String(id) => text(format!("\"{}\"", id.as_str().escape_default())),
        }
    }
}

impl From<Ident> for MetaExpr {
    fn from(value: Ident) -> Self {
        Self::Ident(value)
    }
}

impl From<&str> for MetaExpr {
    fn from(value: &str) -> Self {
        Self::String(Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, Arc::from(value))))
    }
}

impl From<String> for MetaExpr {
    fn from(value: String) -> Self {
        Self::String(Ident::from_raw_parts(Span::new(
            SourceSpan::UNKNOWN,
            Arc::from(value.into_boxed_str()),
        )))
    }
}

impl From<u8> for MetaExpr {
    fn from(value: u8) -> Self {
        Self::Int(Span::new(SourceSpan::UNKNOWN, IntValue::U8(value)))
    }
}

impl From<u16> for MetaExpr {
    fn from(value: u16) -> Self {
        Self::Int(Span::new(SourceSpan::UNKNOWN, IntValue::U16(value)))
    }
}

impl From<u32> for MetaExpr {
    fn from(value: u32) -> Self {
        Self::Int(Span::new(SourceSpan::UNKNOWN, IntValue::U32(value)))
    }
}

impl From<Felt> for MetaExpr {
    fn from(value: Felt) -> Self {
        Self::Int(Span::new(SourceSpan::UNKNOWN, IntValue::Felt(value)))
    }
}

impl From<WordValue> for MetaExpr {
    fn from(value: WordValue) -> Self {
        Self::Word(Span::new(SourceSpan::UNKNOWN, value))
    }
}

impl Spanned for MetaExpr {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Ident(spanned) | Self::String(spanned) => spanned.span(),
            Self::Int(spanned) => spanned.span(),
            Self::Word(spanned) => spanned.span(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for MetaExpr {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<Ident>().prop_map(Self::Ident),
            any::<IntValue>().prop_map(|n| Self::Int(Span::unknown(n))),
            any::<WordValue>().prop_map(|word| Self::Word(Span::unknown(word))),
            any::<Ident>().prop_map(Self::String),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for MetaExpr {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Ident(value) => {
                target.write_u8(0);
                value.write_into(target);
            },
            Self::Int(value) => {
                target.write_u8(1);
                value.inner().write_into(target);
            },
            Self::Word(value) => {
                target.write_u8(2);
                value.inner().write_into(target);
            },
            Self::String(value) => {
                target.write_u8(3);
                value.write_into(target);
            },
        }
    }
}

impl Deserializable for MetaExpr {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use alloc::string::ToString;

        match source.read_u8()? {
            0 => Ident::read_from(source).map(Self::Ident),
            1 => {
                let value = IntValue::read_from(source)?;
                Ok(Self::Int(Span::unknown(value)))
            },
            2 => {
                let value = WordValue::read_from(source)?;
                Ok(Self::Word(Span::unknown(value)))
            },
            3 => {
                let len = source.read_usize()?;
                let bytes = source.read_slice(len)?;
                let id = core::str::from_utf8(bytes)
                    .map_err(|err| DeserializationError::InvalidValue(err.to_string()))?;
                Ok(Self::String(Ident::from_raw_parts(Span::unknown(Arc::from(
                    id.to_string().into_boxed_str(),
                )))))
            },
            n => Err(DeserializationError::InvalidValue(format!(
                "unknown MetaExpr variant tag '{n}'"
            ))),
        }
    }
}
