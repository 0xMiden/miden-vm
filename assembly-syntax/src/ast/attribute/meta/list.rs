use alloc::vec::Vec;

use miden_debuginfo::{SourceSpan, Spanned};

use super::MetaExpr;
use crate::ast::Ident;

/// Represents the metadata of a named list [crate::ast::Attribute], i.e. `@name(item0, .., itemN)`
#[derive(Clone)]
pub struct MetaList {
    pub span: SourceSpan,
    /// The identifier used as the name of this attribute
    pub name: Ident,
    /// The list of items representing the value of this attribute - will always contain at least
    /// one element when parsed.
    pub items: Vec<MetaExpr>,
}

impl Spanned for MetaList {
    #[inline(always)]
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl MetaList {
    pub fn new<I>(name: Ident, items: I) -> Self
    where
        I: IntoIterator<Item = MetaExpr>,
    {
        Self {
            span: SourceSpan::default(),
            name,
            items: items.into_iter().collect(),
        }
    }

    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Get the name of this attribute as a string
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Get the name of this attribute as an [Ident]
    pub fn id(&self) -> Ident {
        self.name.clone()
    }

    /// Returns true if the metadata list is empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the number of items in the metadata list
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Get the metadata list as a slice
    #[inline]
    pub fn as_slice(&self) -> &[MetaExpr] {
        self.items.as_slice()
    }

    /// Get the metadata list as a mutable slice
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [MetaExpr] {
        self.items.as_mut_slice()
    }
}

impl Eq for MetaList {}

impl PartialEq for MetaList {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.items == other.items
    }
}

impl PartialOrd for MetaList {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MetaList {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.name.cmp(&other.name).then_with(|| self.items.cmp(&other.items))
    }
}

impl core::hash::Hash for MetaList {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.items.hash(state);
    }
}
