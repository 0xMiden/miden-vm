mod expr;
mod kv;
mod list;

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::fmt;

use miden_debug_types::{SourceSpan, Span};

pub use self::{expr::MetaExpr, kv::MetaKeyValue, list::MetaList};
use crate::{Felt, ast::Ident, parser::WordValue};

/// Represents the metadata provided as arguments to an attribute.
#[derive(Clone, PartialEq, Eq)]
pub enum Meta {
    /// Represents empty metadata, e.g. `@foo`
    Unit,
    /// A list of metadata expressions, e.g. `@foo(a, "some text", 0x01)`
    ///
    /// The list should always have at least one element, and this is guaranteed by the parser.
    List(Vec<MetaExpr>),
    /// A set of uniquely-named metadata expressions, e.g. `@foo(letter = a, text = "some text")`
    ///
    /// The set should always have at least one key-value pair, and this is guaranteed by the
    /// parser.
    KeyValue(BTreeMap<Ident, MetaExpr>),
}
impl Meta {
    /// Borrow the metadata without unwrapping the specific type
    ///
    /// Returns `None` if there is no meaningful metadata
    #[inline]
    pub fn borrow(&self) -> Option<BorrowedMeta<'_>> {
        match self {
            Self::Unit => None,
            Self::List(list) => Some(BorrowedMeta::List(list)),
            Self::KeyValue(kv) => Some(BorrowedMeta::KeyValue(kv)),
        }
    }
}
impl FromIterator<MetaItem> for Meta {
    #[inline]
    fn from_iter<T: IntoIterator<Item = MetaItem>>(iter: T) -> Self {
        let mut iter = iter.into_iter();
        match iter.next() {
            None => Self::Unit,
            Some(MetaItem::Expr(expr)) => Self::List(
                core::iter::once(expr)
                    .chain(iter.map(|item| match item {
                        MetaItem::Expr(expr) => expr,
                        MetaItem::KeyValue(..) => unsafe { core::hint::unreachable_unchecked() },
                    }))
                    .collect(),
            ),
            Some(MetaItem::KeyValue(k, v)) => Self::KeyValue(
                core::iter::once((k, v))
                    .chain(iter.map(|item| match item {
                        MetaItem::KeyValue(k, v) => (k, v),
                        MetaItem::Expr(_) => unsafe { core::hint::unreachable_unchecked() },
                    }))
                    .collect(),
            ),
        }
    }
}

impl FromIterator<MetaExpr> for Meta {
    #[inline]
    fn from_iter<T: IntoIterator<Item = MetaExpr>>(iter: T) -> Self {
        Self::List(iter.into_iter().collect())
    }
}

impl FromIterator<(Ident, MetaExpr)> for Meta {
    #[inline]
    fn from_iter<T: IntoIterator<Item = (Ident, MetaExpr)>>(iter: T) -> Self {
        Self::KeyValue(iter.into_iter().collect())
    }
}

impl<'a> FromIterator<(&'a str, MetaExpr)> for Meta {
    #[inline]
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = (&'a str, MetaExpr)>,
    {
        Self::KeyValue(
            iter.into_iter()
                .map(|(k, v)| {
                    let k = Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, Arc::from(k)));
                    (k, v)
                })
                .collect(),
        )
    }
}

impl<I, V> From<I> for Meta
where
    Meta: FromIterator<V>,
    I: IntoIterator<Item = V>,
{
    #[inline]
    fn from(iter: I) -> Self {
        Self::from_iter(iter)
    }
}

/// Represents a reference to the metadata for an [super::Attribute]
///
/// See [Meta] for what metadata is represented, and its syntax.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum BorrowedMeta<'a> {
    /// A list of metadata expressions
    List(&'a [MetaExpr]),
    /// A list of uniquely-named metadata expressions
    KeyValue(&'a BTreeMap<Ident, MetaExpr>),
}
impl fmt::Debug for BorrowedMeta<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::List(items) => write!(f, "{items:#?}"),
            Self::KeyValue(items) => write!(f, "{items:#?}"),
        }
    }
}

/// Represents a single metadata item provided as an argument to an attribute.
///
/// For example, the `foo` attribute in `@foo(bar, baz)` has two metadata items, both of `Expr`
/// type, which compose a `
#[derive(Clone, PartialEq, Eq)]
pub enum MetaItem {
    /// A metadata expression, e.g. `"some text"` in `@foo("some text")`
    ///
    /// This represents the element type for `Meta::List`-based attributes.
    Expr(MetaExpr),
    /// A named metadata expression, e.g. `letter = a` in `@foo(letter = a)`
    ///
    /// This represents the element type for `Meta::KeyValue`-based attributes.
    KeyValue(Ident, MetaExpr),
}

impl MetaItem {
    /// Unwrap this item to extract the contained [MetaExpr].
    ///
    /// Panics if this item is not the `Expr` variant.
    #[inline]
    #[track_caller]
    pub fn unwrap_expr(self) -> MetaExpr {
        match self {
            Self::Expr(expr) => expr,
            Self::KeyValue(..) => unreachable!("tried to unwrap key-value as expression"),
        }
    }

    /// Unwrap this item to extract the contained key-value pair.
    ///
    /// Panics if this item is not the `KeyValue` variant.
    #[inline]
    #[track_caller]
    pub fn unwrap_key_value(self) -> (Ident, MetaExpr) {
        match self {
            Self::KeyValue(k, v) => (k, v),
            Self::Expr(_) => unreachable!("tried to unwrap expression as key-value"),
        }
    }
}

impl From<Ident> for MetaItem {
    fn from(value: Ident) -> Self {
        Self::Expr(MetaExpr::Ident(value))
    }
}

impl From<&str> for MetaItem {
    fn from(value: &str) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<String> for MetaItem {
    fn from(value: String) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<u8> for MetaItem {
    fn from(value: u8) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<u16> for MetaItem {
    fn from(value: u16) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<u32> for MetaItem {
    fn from(value: u32) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<Felt> for MetaItem {
    fn from(value: Felt) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl From<WordValue> for MetaItem {
    fn from(value: WordValue) -> Self {
        Self::Expr(MetaExpr::from(value))
    }
}

impl<V> From<(Ident, V)> for MetaItem
where
    V: Into<MetaExpr>,
{
    fn from(entry: (Ident, V)) -> Self {
        let (key, value) = entry;
        Self::KeyValue(key, value.into())
    }
}

impl<V> From<(&str, V)> for MetaItem
where
    V: Into<MetaExpr>,
{
    fn from(entry: (&str, V)) -> Self {
        let (key, value) = entry;
        let key = Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, Arc::from(key)));
        Self::KeyValue(key, value.into())
    }
}

impl<V> From<(String, V)> for MetaItem
where
    V: Into<MetaExpr>,
{
    fn from(entry: (String, V)) -> Self {
        let (key, value) = entry;
        let key =
            Ident::from_raw_parts(Span::new(SourceSpan::UNKNOWN, Arc::from(key.into_boxed_str())));
        Self::KeyValue(key, value.into())
    }
}
