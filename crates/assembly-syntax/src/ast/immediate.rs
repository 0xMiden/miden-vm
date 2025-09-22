use alloc::sync::Arc;
use core::fmt;

use miden_debug_types::{SourceSpan, Span, Spanned};

use crate::{Felt, ast::Ident};

/// An 8-bit unsigned immediate
pub type ImmU8 = Immediate<u8>;

/// A 16-bit unsigned immediate
pub type ImmU16 = Immediate<u16>;

/// A 32-bit unsigned immediate
pub type ImmU32 = Immediate<u32>;

/// A field element immediate
pub type ImmFelt = Immediate<Felt>;

/// The type of error messages used in MASM assertions.
pub type ErrorMsg = Immediate<Arc<str>>;

/// Represents an instruction immediate, e.g. `add.1` or `add.CONST`
pub enum Immediate<T> {
    /// A literal integer value, either decimal or hex-encoded
    Value(Span<T>),
    /// A constant identifier
    ///
    /// This must refer to a constant definition in the current module.
    ///
    /// All immediates of this type are folded to `Value` during
    /// semantic analysis, once all constant definitions are evaluated.
    Constant(Ident),
}

/// All immediates
impl<T> Immediate<T> {
    pub fn is_literal(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Override the source span of this immediate with `span`
    pub fn with_span(self, span: SourceSpan) -> Self {
        match self {
            Self::Constant(id) => Self::Constant(id.with_span(span)),
            Self::Value(value) => Self::Value(Span::new(span, value.into_inner())),
        }
    }

    /// Transform the type of this immediate from T to U, using `map`
    pub fn map<U, F>(self, map: F) -> Immediate<U>
    where
        F: FnMut(T) -> U,
    {
        match self {
            Self::Constant(id) => Immediate::Constant(id),
            Self::Value(value) => Immediate::Value(value.map(map)),
        }
    }
}

/// Copy-able immediates (in practice, all of them)
impl<T: Copy> Immediate<T> {
    pub fn expect_value(&self) -> T {
        match self {
            Self::Value(value) => value.into_inner(),
            Self::Constant(name) => panic!("tried to unwrap unresolved constant: '{name}'"),
        }
    }

    pub fn expect_spanned_value(&self) -> Span<T> {
        match self {
            Self::Value(value) => *value,
            Self::Constant(name) => panic!("tried to unwrap unresolved constant: '{name}'"),
        }
    }
}

impl Immediate<Arc<str>> {
    pub fn expect_string(&self) -> Arc<str> {
        match self {
            Self::Value(value) => value.clone().into_inner(),
            Self::Constant(name) => panic!("tried to unwrap unresolved constant: '{name}'"),
        }
    }
}

impl<T> Spanned for Immediate<T> {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Value(spanned) => spanned.span(),
            Self::Constant(spanned) => spanned.span(),
        }
    }
}

impl<T> From<T> for Immediate<T> {
    fn from(value: T) -> Self {
        Self::Value(Span::unknown(value))
    }
}

impl<T> From<Span<T>> for Immediate<T> {
    fn from(value: Span<T>) -> Self {
        Self::Value(value)
    }
}

impl<T: Clone> Clone for Immediate<T> {
    fn clone(&self) -> Self {
        match self {
            Self::Value(value) => Self::Value(value.clone()),
            Self::Constant(name) => Self::Constant(name.clone()),
        }
    }
}

impl<T: Eq> Eq for Immediate<T> {}

impl<T: PartialEq> PartialEq for Immediate<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Value(l), Self::Value(r)) => l == r,
            (Self::Constant(l), Self::Constant(r)) => l == r,
            _ => false,
        }
    }
}

impl<T: PartialEq> PartialEq<T> for Immediate<T> {
    fn eq(&self, other: &T) -> bool {
        match self {
            Self::Value(l) => l == other,
            _ => false,
        }
    }
}

impl<T: core::hash::Hash> core::hash::Hash for Immediate<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Value(v) => v.hash(state),
            Self::Constant(name) => name.hash(state),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Immediate<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Value(value) if f.alternate() => write!(f, "Value({value:#?})"),
            Self::Value(value) => write!(f, "Value({value:?})"),
            Self::Constant(name) => write!(f, "Constant({name})"),
        }
    }
}

impl<T: fmt::Display> fmt::Display for Immediate<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Value(value) => write!(f, "{value}"),
            Self::Constant(name) => write!(f, "{name}"),
        }
    }
}

impl<T: crate::prettier::PrettyPrint> crate::prettier::PrettyPrint for Immediate<T> {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::Value(value) => value.render(),
            Self::Constant(name) => text(name),
        }
    }
}
