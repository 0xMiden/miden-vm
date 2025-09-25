mod meta;
mod set;

use core::fmt;

use miden_core::utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable,
};
use miden_debug_types::{SourceSpan, Spanned};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub use self::{
    meta::{BorrowedMeta, Meta, MetaExpr, MetaItem, MetaKeyValue, MetaList},
    set::{AttributeSet, AttributeSetEntry},
};
use crate::{ast::Ident, prettier};

/// An [Attribute] represents some named metadata attached to a Miden Assembly procedure.
///
/// An attribute has no predefined structure per se, but syntactically there are three types:
///
/// * Marker attributes, i.e. just a name and no associated data. Attributes of this type are used
///   to "mark" the item they are attached to with some unique trait or behavior implied by the
///   name. For example, `@inline`. NOTE: `@inline()` is not valid syntax.
///
/// * List attributes, i.e. a name and one or more comma-delimited expressions. Attributes of this
///   type are used for cases where you want to parameterize a marker-like trait. To use a Rust
///   example, `#[derive(Trait)]` is a list attribute, where `derive` is the marker, but we want to
///   instruct whatever processes derives, what traits it needs to derive. The equivalent syntax in
///   Miden Assembly would be `@derive(Trait)`. Lists must always have at least one item.
///
/// * Key-value attributes, i.e. a name and a value. Attributes of this type are used to attach
///   named properties to an item. For example, `@storage(offset = 1)`. Possible value types are:
///   bare identifiers, decimal or hexadecimal integers, and quoted strings.
///
/// There are no restrictions on what attributes can exist or be used. However, there are a set of
/// attributes that the assembler knows about, and acts on, which will be stripped during assembly.
/// Any remaining attributes we don't explicitly handle in the assembler, will be passed along as
/// metadata attached to the procedures in the MAST output by the assembler.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "serde", feature = "arbitrary", test),
    miden_serde_test_macros::serde_test
)]
pub enum Attribute {
    /// A named behavior, trait or action; e.g. `@inline`
    Marker(Ident),
    /// A parameterized behavior, trait or action; e.g. `@inline(always)` or `@derive(Foo, Bar)`
    List(MetaList),
    /// A named property; e.g. `@props(key = "value")`, `@props(a = 1, b = 0x1)`
    KeyValue(MetaKeyValue),
}

impl Attribute {
    /// Create a new [Attribute] with the given metadata.
    ///
    /// The metadata value must be convertible to [Meta].
    ///
    /// For marker attributes, you can either construct the `Marker` variant directly, or pass
    /// either `Meta::Unit` or `None` as the metadata argument.
    ///
    /// If the metadata is empty, a `Marker` attribute will be produced, otherwise the type depends
    /// on the metadata. If the metadata is _not_ key-value shaped, a `List` is produced, otherwise
    /// a `KeyValue`.
    pub fn new(name: Ident, metadata: impl Into<Meta>) -> Self {
        let metadata = metadata.into();
        match metadata {
            Meta::Unit => Self::Marker(name),
            Meta::List(items) => Self::List(MetaList { span: Default::default(), name, items }),
            Meta::KeyValue(items) => {
                Self::KeyValue(MetaKeyValue { span: Default::default(), name, items })
            },
        }
    }

    /// Create a new [Attribute] from an metadata-producing iterator.
    ///
    /// If the iterator is empty, a `Marker` attribute will be produced, otherwise the type depends
    /// on the metadata. If the metadata is _not_ key-value shaped, a `List` is produced, otherwise
    /// a `KeyValue`.
    pub fn from_iter<V, I>(name: Ident, metadata: I) -> Self
    where
        Meta: FromIterator<V>,
        I: IntoIterator<Item = V>,
    {
        Self::new(name, Meta::from_iter(metadata))
    }

    /// Set the source location for this attribute
    pub fn with_span(self, span: SourceSpan) -> Self {
        match self {
            Self::Marker(id) => Self::Marker(id.with_span(span)),
            Self::List(list) => Self::List(list.with_span(span)),
            Self::KeyValue(kv) => Self::KeyValue(kv.with_span(span)),
        }
    }

    /// Get the name of this attribute as a string
    pub fn name(&self) -> &str {
        match self {
            Self::Marker(id) => id.as_str(),
            Self::List(list) => list.name(),
            Self::KeyValue(kv) => kv.name(),
        }
    }

    /// Get the name of this attribute as an [Ident]
    pub fn id(&self) -> Ident {
        match self {
            Self::Marker(id) => id.clone(),
            Self::List(list) => list.id(),
            Self::KeyValue(kv) => kv.id(),
        }
    }

    /// Returns true if this is a marker attribute
    pub fn is_marker(&self) -> bool {
        matches!(self, Self::Marker(_))
    }

    /// Returns true if this is a list attribute
    pub fn is_list(&self) -> bool {
        matches!(self, Self::List(_))
    }

    /// Returns true if this is a key-value attribute
    pub fn is_key_value(&self) -> bool {
        matches!(self, Self::KeyValue(_))
    }

    /// Get the metadata for this attribute
    ///
    /// Returns `None` if this is a marker attribute, and thus has no metadata
    pub fn metadata(&self) -> Option<BorrowedMeta<'_>> {
        match self {
            Self::Marker(_) => None,
            Self::List(list) => Some(BorrowedMeta::List(&list.items)),
            Self::KeyValue(kv) => Some(BorrowedMeta::KeyValue(&kv.items)),
        }
    }
}

impl fmt::Debug for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Marker(id) => f.debug_tuple("Marker").field(&id).finish(),
            Self::List(meta) => f
                .debug_struct("List")
                .field("name", &meta.name)
                .field("items", &meta.items)
                .finish(),
            Self::KeyValue(meta) => f
                .debug_struct("KeyValue")
                .field("name", &meta.name)
                .field("items", &meta.items)
                .finish(),
        }
    }
}

impl fmt::Display for Attribute {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use prettier::PrettyPrint;
        self.pretty_print(f)
    }
}

impl prettier::PrettyPrint for Attribute {
    fn render(&self) -> prettier::Document {
        use prettier::*;
        let doc = text(format!("@{}", &self.name()));
        match self {
            Self::Marker(_) => doc,
            Self::List(meta) => {
                let singleline_items = meta
                    .items
                    .iter()
                    .map(|item| item.render())
                    .reduce(|acc, item| acc + const_text(", ") + item)
                    .unwrap_or(Document::Empty);
                let multiline_items = indent(
                    4,
                    nl() + meta
                        .items
                        .iter()
                        .map(|item| item.render())
                        .reduce(|acc, item| acc + nl() + item)
                        .unwrap_or(Document::Empty),
                ) + nl();
                doc + const_text("(") + (singleline_items | multiline_items) + const_text(")")
            },
            Self::KeyValue(meta) => {
                let singleline_items = meta
                    .items
                    .iter()
                    .map(|(k, v)| text(k) + const_text(" = ") + v.render())
                    .reduce(|acc, item| acc + const_text(", ") + item)
                    .unwrap_or(Document::Empty);
                let multiline_items = indent(
                    4,
                    nl() + meta
                        .items
                        .iter()
                        .map(|(k, v)| text(k) + const_text(" = ") + v.render())
                        .reduce(|acc, item| acc + nl() + item)
                        .unwrap_or(Document::Empty),
                ) + nl();
                doc + const_text("(") + (singleline_items | multiline_items) + const_text(")")
            },
        }
    }
}

impl Spanned for Attribute {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Marker(id) => id.span(),
            Self::List(list) => list.span(),
            Self::KeyValue(kv) => kv.span(),
        }
    }
}

impl From<Ident> for Attribute {
    fn from(value: Ident) -> Self {
        Self::Marker(value)
    }
}

impl<K, V> From<(K, V)> for Attribute
where
    K: Into<Ident>,
    V: Into<MetaExpr>,
{
    fn from(kv: (K, V)) -> Self {
        let (key, value) = kv;
        Self::List(MetaList {
            span: SourceSpan::default(),
            name: key.into(),
            items: vec![value.into()],
        })
    }
}

impl From<MetaList> for Attribute {
    fn from(value: MetaList) -> Self {
        Self::List(value)
    }
}

impl From<MetaKeyValue> for Attribute {
    fn from(value: MetaKeyValue) -> Self {
        Self::KeyValue(value)
    }
}

#[cfg(feature = "arbitrary")]
impl proptest::arbitrary::Arbitrary for Attribute {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<Ident>().prop_map(Self::Marker),
            any::<MetaList>().prop_map(Self::List),
            any::<MetaKeyValue>().prop_map(Self::KeyValue),
        ]
        .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

impl Serializable for Attribute {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            Self::Marker(name) => {
                target.write_u8(0);
                name.write_into(target);
            },
            Self::List(list) => {
                target.write_u8(1);
                list.write_into(target);
            },
            Self::KeyValue(kv) => {
                target.write_u8(1);
                kv.write_into(target);
            },
        }
    }
}

impl Deserializable for Attribute {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        match source.read_u8()? {
            0 => Ident::read_from(source).map(Self::Marker),
            1 => MetaList::read_from(source).map(Self::List),
            2 => MetaKeyValue::read_from(source).map(Self::KeyValue),
            n => Err(DeserializationError::InvalidValue(format!(
                "unknown Attribute variant tag '{n}'"
            ))),
        }
    }
}
