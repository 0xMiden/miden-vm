use alloc::{boxed::Box, string::String, vec::Vec};

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
    /// Get the name assigned to this type declaration
    pub fn name(&self) -> &Ident {
        match self {
            Self::Alias(ty) => &ty.name,
            Self::Enum(ty) => &ty.name,
        }
    }

    /// Get the type expression associated with this declaration
    pub fn ty(&self) -> TypeExpr {
        match self {
            Self::Alias(ty) => ty.ty.clone(),
            Self::Enum(ty) => TypeExpr::Primitive(Span::new(ty.span, ty.ty.clone())),
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

/// A procedure type signature
#[derive(Debug, Clone)]
pub struct FunctionType {
    pub span: SourceSpan,
    pub cc: types::CallConv,
    pub args: Vec<TypeExpr>,
    pub results: Vec<TypeExpr>,
}

impl Eq for FunctionType {}

impl PartialEq for FunctionType {
    fn eq(&self, other: &Self) -> bool {
        self.cc == other.cc && self.args == other.args && self.results == other.results
    }
}

impl core::hash::Hash for FunctionType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.cc.hash(state);
        self.args.hash(state);
        self.results.hash(state);
    }
}

impl Spanned for FunctionType {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl FunctionType {
    pub fn new(cc: types::CallConv, args: Vec<TypeExpr>, results: Vec<TypeExpr>) -> Self {
        Self {
            span: SourceSpan::UNKNOWN,
            cc,
            args,
            results,
        }
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

/// A syntax-level type expression (i.e. primitive type, reference to nominal type, etc.)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TypeExpr {
    /// A primitive integral type, e.g. `i1`, `u16`
    Primitive(Span<Type>),
    /// A pointer type expression, e.g. `*u8`
    Ptr(Span<Box<TypeExpr>>),
    /// An array type expression, e.g. `[u8; 32]`
    Array(ArrayType),
    /// A struct type expression, e.g. `struct { a: u32 }`
    Struct(StructType),
    /// A reference to a type aliased by name, e.g. `Foo`
    Ref(Ident),
}

impl From<Type> for TypeExpr {
    fn from(ty: Type) -> Self {
        match ty {
            Type::Array(t) => Self::Array(ArrayType::new(t.element_type().clone().into(), t.len())),
            Type::Struct(t) => {
                Self::Struct(StructType::new(t.fields().iter().enumerate().map(|(i, ft)| {
                    let name = Ident::new(format!("field{i}")).unwrap();
                    StructField {
                        span: SourceSpan::UNKNOWN,
                        name,
                        ty: ft.ty.clone().into(),
                    }
                })))
            },
            Type::Ptr(t) => Self::Ptr(Span::unknown(Box::new(t.pointee().clone().into()))),
            Type::Function(_) => {
                Self::Ptr(Span::unknown(Box::new(TypeExpr::Primitive(Span::unknown(Type::U8)))))
            },
            Type::List(t) => Self::Ptr(Span::unknown(Box::new((*t).clone().into()))),
            Type::I128 | Type::U128 => Self::Array(ArrayType::new(Type::U32.into(), 4)),
            Type::I64 | Type::U64 => Self::Array(ArrayType::new(Type::U32.into(), 2)),
            Type::Unknown | Type::Never | Type::F64 => panic!("unrepresentable type value: {ty}"),
            ty => Self::Primitive(Span::unknown(ty)),
        }
    }
}

impl Spanned for TypeExpr {
    fn span(&self) -> SourceSpan {
        match self {
            Self::Primitive(spanned) => spanned.span(),
            Self::Ptr(spanned) => spanned.span(),
            Self::Array(spanned) => spanned.span(),
            Self::Struct(spanned) => spanned.span(),
            Self::Ref(spanned) => spanned.span(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ArrayType {
    pub span: SourceSpan,
    pub elem: Box<TypeExpr>,
    pub arity: usize,
}

impl Eq for ArrayType {}

impl PartialEq for ArrayType {
    fn eq(&self, other: &Self) -> bool {
        self.arity == other.arity && self.elem == other.elem
    }
}

impl core::hash::Hash for ArrayType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.elem.hash(state);
        self.arity.hash(state);
    }
}

impl Spanned for ArrayType {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl ArrayType {
    pub fn new(elem: TypeExpr, arity: usize) -> Self {
        Self {
            span: SourceSpan::UNKNOWN,
            elem: Box::new(elem),
            arity,
        }
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

#[derive(Debug, Clone)]
pub struct StructType {
    pub span: SourceSpan,
    pub fields: Vec<StructField>,
}

impl Eq for StructType {}

impl PartialEq for StructType {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}

impl core::hash::Hash for StructType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.fields.hash(state);
    }
}

impl Spanned for StructType {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl StructType {
    pub fn new(fields: impl IntoIterator<Item = StructField>) -> Self {
        Self {
            span: SourceSpan::UNKNOWN,
            fields: fields.into_iter().collect(),
        }
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

#[derive(Debug, Clone)]
pub struct StructField {
    pub span: SourceSpan,
    pub name: Ident,
    pub ty: TypeExpr,
}

impl Eq for StructField {}

impl PartialEq for StructField {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.ty == other.ty
    }
}

impl core::hash::Hash for StructField {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.ty.hash(state);
    }
}

impl Spanned for StructField {
    fn span(&self) -> SourceSpan {
        self.span
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
    pub ty: TypeExpr,
}

impl TypeAlias {
    /// Create a new type alias from a name and type
    pub fn new(name: Ident, ty: TypeExpr) -> Self {
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

impl Spanned for TypeAlias {
    fn span(&self) -> SourceSpan {
        self.span
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

    /// Get the variants of this enum type, mutably
    pub fn variants_mut(&mut self) -> &mut Vec<Variant> {
        &mut self.variants
    }

    /// Split this definition into its type alias and variant parts
    pub fn into_parts(self) -> (TypeAlias, Vec<Variant>) {
        let Self { span, docs, name, ty, variants } = self;
        let alias = TypeAlias {
            span,
            docs,
            name,
            ty: TypeExpr::Primitive(Span::new(span, ty)),
        };
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
    pub fn new(name: Ident, discriminant: ConstantExpr) -> Self {
        Self {
            span: name.span(),
            docs: None,
            name,
            discriminant,
        }
    }

    /// Override the span for this variant
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Adds documentation to this variant
    pub fn with_docs(mut self, docs: Option<Span<String>>) -> Self {
        self.docs = docs.map(DocString::new);
        self
    }

    /// Used to validate that this variant's discriminant value is an instance of `ty`,
    /// which must be a type valid for use as the underlying representation for an enum, i.e. an
    /// integer type up to 64 bits in size.
    ///
    /// It is expected that the discriminant expression has been folded to an integer value by the
    /// time this is called. If the discriminant has not been fully folded, then an error will be
    /// returned.
    pub fn assert_instance_of(&self, ty: &Type) -> Result<(), crate::SemanticAnalysisError> {
        use crate::{FIELD_MODULUS, SemanticAnalysisError};

        let value = match &self.discriminant {
            ConstantExpr::Int(value) => value.as_int(),
            _ => {
                return Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                    span: self.discriminant.span(),
                    repr: ty.clone(),
                });
            },
        };

        match ty {
            Type::I1 if value > 1 => Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                span: self.discriminant.span(),
                repr: ty.clone(),
            }),
            Type::I1 => Ok(()),
            Type::I8 | Type::U8 if value > u8::MAX as u64 => {
                Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                    span: self.discriminant.span(),
                    repr: ty.clone(),
                })
            },
            Type::I8 | Type::U8 => Ok(()),
            Type::I16 | Type::U16 if value > u16::MAX as u64 => {
                Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                    span: self.discriminant.span(),
                    repr: ty.clone(),
                })
            },
            Type::I16 | Type::U16 => Ok(()),
            Type::I32 | Type::U32 if value > u32::MAX as u64 => {
                Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                    span: self.discriminant.span(),
                    repr: ty.clone(),
                })
            },
            Type::I32 | Type::U32 => Ok(()),
            Type::I64 | Type::U64 if value >= FIELD_MODULUS => {
                Err(SemanticAnalysisError::InvalidEnumDiscriminant {
                    span: self.discriminant.span(),
                    repr: ty.clone(),
                })
            },
            _ => Err(SemanticAnalysisError::InvalidEnumRepr { span: self.span }),
        }
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
