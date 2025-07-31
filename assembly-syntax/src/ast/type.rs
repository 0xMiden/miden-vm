use alloc::{string::String, vec::Vec};

use miden_debug_types::{SourceSpan, Span, Spanned};
pub use midenc_hir_type as types;
use midenc_hir_type::Type;

use super::{ConstantExpr, DocString, Ident};

/// An abstraction over the different types of type declarations allowed in Miden Assembly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDecl {
    /// A named type, i.e. a type alias
    Alias(TypeAlias),
    /// A C-like enumeration type with associated constants
    Enum(EnumType),
}

impl TypeDecl {
    pub fn name(&self) -> &Ident {
        match self {
            Self::Alias(ty) => &ty.name,
            Self::Enum(ty) => &ty.name,
        }
    }

    pub fn ty(&self) -> &Type {
        match self {
            Self::Alias(ty) => &ty.ty,
            Self::Enum(ty) => &ty.ty,
        }
    }
}

impl Spanned for TypeDecl {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Alias(spanned) => spanned.span,
            Self::Enum(spanned) => spanned.span,
        }
    }
}

impl From<TypeAlias> for TypeDecl {
    fn from(value: TypeAlias) -> Self {
        Self::Alias(value)
    }
}

impl From<EnumType> for TypeDecl {
    fn from(value: EnumType) -> Self {
        Self::Enum(value)
    }
}

/// A [TypeAlias] represents a named [Type].
///
/// Type aliases correspond to type declarations in Miden Assembly source files. They are called
/// aliases, rather than declarations, as the type system for Miden Assembly is structural, rather
/// than nominal, and so two aliases with the same underlying type are considered equivalent.
#[derive(Debug, Clone)]
pub struct TypeAlias {
    span: SourceSpan,
    /// The documentation string attached to this definition.
    docs: Option<DocString>,
    /// The name of this type alias
    pub name: Ident,
    /// The concrete underlying type
    pub ty: Type,
}

impl TypeAlias {
    /// Create a new type alias from a name and type
    pub fn new(name: Ident, ty: Type) -> Self {
        Self { span: name.span(), docs: None, name, ty }
    }

    /// Adds documentation to this type alias
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Set the source span
    #[inline]
    pub fn set_span(&mut self, span: SourceSpan) {
        self.span = span;
    }
}

impl Spanned for TypeAlias {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for TypeAlias {}

impl PartialEq for TypeAlias {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.docs == other.docs && self.ty == other.ty
    }
}

impl core::hash::Hash for TypeAlias {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let Self { span: _, docs, name, ty } = self;
        docs.hash(state);
        name.hash(state);
        ty.hash(state);
    }
}

/// A combined type alias and constant declaration corresponding to a C-like enumeration.
///
/// C-style enumerations are effectively a type alias for an integer type with a limited set of
/// valid values with associated names (referred to as _variants_ of the enum type).
///
/// In Miden Assembly, these provide a means for a procedure to declare that it expects an argument
/// of the underlying integral type, but that values other than those of the declared variants are
/// illegal/invalid. Currently, these are unchecked, and are only used to convey semantic
/// information. In the future, we may perform static analysis to try and identify invalid instances
/// of the enumeration when derived from a constant.
#[derive(Debug, Clone)]
pub struct EnumType {
    span: SourceSpan,
    /// The documentation string attached to this definition.
    docs: Option<DocString>,
    /// The enum name
    name: Ident,
    /// The type of the discriminant value used for this enum's variants
    ///
    /// NOTE: The type must be an integral value, and this is enforced by [`Self::new`].
    ty: Type,
    /// The enum variants
    variants: Vec<Variant>,
}

impl EnumType {
    /// Construct a new enum type with the given name and variants
    ///
    /// The caller is assumed to have already validated that `ty` is an integral type, and this
    /// function will assert that this is the case.
    pub fn new(name: Ident, ty: Type, variants: impl IntoIterator<Item = Variant>) -> Self {
        assert!(ty.is_integer(), "only integer types are allowed in enum type definitions");
        Self {
            span: name.span(),
            docs: None,
            name,
            ty,
            variants: Vec::from_iter(variants),
        }
    }

    /// Adds documentation to this enum declaration.
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Override the default source span
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Set the source span
    pub fn set_span(&mut self, span: SourceSpan) {
        self.span = span;
    }

    /// Get the name of this enum type
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Get the concrete type of this enum's variants
    pub fn ty(&self) -> &Type {
        &self.ty
    }

    /// Get the variants of this enum type
    pub fn variants(&self) -> &[Variant] {
        &self.variants
    }

    /// Split this definition into its type alias and variant parts
    pub fn into_parts(self) -> (TypeAlias, Vec<Variant>) {
        let Self { span, docs, name, ty, variants } = self;
        let alias = TypeAlias { span, docs, name, ty };
        (alias, variants)
    }
}

impl Spanned for EnumType {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for EnumType {}

impl PartialEq for EnumType {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.docs == other.docs
            && self.ty == other.ty
            && self.variants == other.variants
    }
}

impl core::hash::Hash for EnumType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let Self { span: _, docs, name, ty, variants } = self;
        docs.hash(state);
        name.hash(state);
        ty.hash(state);
        variants.hash(state);
    }
}

/// A variant of an [EnumType].
///
/// See the [EnumType] docs for more information.
#[derive(Debug, Clone)]
pub struct Variant {
    pub span: SourceSpan,
    /// The documentation string attached to the constant derived from this variant.
    pub docs: Option<DocString>,
    /// The name of this enum variant
    pub name: Ident,
    /// The discriminant value associated with this variant
    pub discriminant: ConstantExpr,
}

impl Variant {
    /// Construct a new variant of an [EnumType], with the given name and discriminant value.
    pub fn new(name: Ident, discriminant: impl Into<ConstantExpr>) -> Self {
        Self {
            span: name.span(),
            docs: None,
            name,
            discriminant: discriminant.into(),
        }
    }

    /// Adds documentation to this variant
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }
}

impl Spanned for Variant {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl Eq for Variant {}

impl PartialEq for Variant {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.discriminant == other.discriminant
            && self.docs == other.docs
    }
}

impl core::hash::Hash for Variant {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        let Self { span: _, docs, name, discriminant } = self;
        docs.hash(state);
        name.hash(state);
        discriminant.hash(state);
    }
}
