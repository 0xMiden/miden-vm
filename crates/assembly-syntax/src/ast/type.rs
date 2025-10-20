use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};

use miden_debug_types::{SourceSpan, Span, Spanned};
pub use midenc_hir_type as types;
use midenc_hir_type::{AddressSpace, Type, TypeRepr};

use super::{
    ConstantExpr, DocString, GlobalItemIndex, Ident, ItemIndex, LocalSymbolResolutionError, Path,
    PathBuf, SymbolResolution, Visibility,
};

pub trait TypeResolver<E> {
    fn get_type(&self, context: SourceSpan, gid: GlobalItemIndex) -> Result<Type, E>;
    fn get_local_type(&self, context: SourceSpan, id: ItemIndex) -> Result<Option<Type>, E>;
    fn resolve_local_failed(&self, err: LocalSymbolResolutionError) -> E;
    fn resolve_type_ref(&self, ty: Span<&Path>) -> Result<Option<SymbolResolution>, E>;
    fn resolve(&self, ty: &TypeExpr) -> Result<Option<Type>, E> {
        ty.resolve_type(self)
    }
}

// TYPE DECLARATION
// ================================================================================================

/// An abstraction over the different types of type declarations allowed in Miden Assembly
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeDecl {
    /// A named type, i.e. a type alias
    Alias(TypeAlias),
    /// A C-like enumeration type with associated constants
    Enum(EnumType),
}

impl TypeDecl {
    /// Adds documentation to this type alias
    pub fn with_docs(self, docs: Option<Span<String>>) -> Self {
        match self {
            Self::Alias(ty) => Self::Alias(ty.with_docs(docs)),
            Self::Enum(ty) => Self::Enum(ty.with_docs(docs)),
        }
    }

    /// Get the name assigned to this type declaration
    pub fn name(&self) -> &Ident {
        match self {
            Self::Alias(ty) => &ty.name,
            Self::Enum(ty) => &ty.name,
        }
    }

    /// Get the visibility of this type declaration
    pub const fn visibility(&self) -> Visibility {
        match self {
            Self::Alias(ty) => ty.visibility,
            Self::Enum(ty) => ty.visibility,
        }
    }

    /// Get the documentation of this enum type
    pub fn docs(&self) -> Option<Span<&str>> {
        match self {
            Self::Alias(ty) => ty.docs(),
            Self::Enum(ty) => ty.docs(),
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

impl crate::prettier::PrettyPrint for TypeDecl {
    fn render(&self) -> crate::prettier::Document {
        match self {
            Self::Alias(ty) => ty.render(),
            Self::Enum(ty) => ty.render(),
        }
    }
}

// FUNCTION TYPE
// ================================================================================================

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

impl crate::prettier::PrettyPrint for FunctionType {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let singleline_args = self
            .args
            .iter()
            .map(|arg| arg.render())
            .reduce(|acc, arg| acc + const_text(", ") + arg)
            .unwrap_or(Document::Empty);
        let multiline_args = indent(
            4,
            nl() + self
                .args
                .iter()
                .map(|arg| arg.render())
                .reduce(|acc, arg| acc + const_text(",") + nl() + arg)
                .unwrap_or(Document::Empty),
        ) + nl();
        let args = singleline_args | multiline_args;
        let args = const_text("(") + args + const_text(")");

        match self.results.len() {
            0 => args,
            1 => args + const_text(" -> ") + self.results[0].render(),
            _ => {
                let results = self
                    .results
                    .iter()
                    .map(|r| r.render())
                    .reduce(|acc, r| acc + const_text(", ") + r)
                    .unwrap_or(Document::Empty);
                args + const_text(" -> ") + const_text("(") + results + const_text(")")
            },
        }
    }
}

// TYPE EXPRESSION
// ================================================================================================

/// A syntax-level type expression (i.e. primitive type, reference to nominal type, etc.)
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TypeExpr {
    /// A primitive integral type, e.g. `i1`, `u16`
    Primitive(Span<Type>),
    /// A pointer type expression, e.g. `*u8`
    Ptr(PointerType),
    /// An array type expression, e.g. `[u8; 32]`
    Array(ArrayType),
    /// A struct type expression, e.g. `struct { a: u32 }`
    Struct(StructType),
    /// A reference to a type aliased by name, e.g. `Foo`
    Ref(Span<PathBuf>),
}

impl TypeExpr {
    pub fn resolve_type<E, R>(&self, resolver: &R) -> Result<Option<Type>, E>
    where
        R: ?Sized + TypeResolver<E>,
    {
        match self {
            TypeExpr::Ref(path) => {
                let mut current_path: Span<Arc<Path>> = path.clone().map(|path| path.into());
                loop {
                    match resolver.resolve_type_ref(current_path.as_deref())? {
                        Some(SymbolResolution::Local(item)) => {
                            return resolver.get_local_type(current_path.span(), item.into_inner());
                        },
                        Some(SymbolResolution::External(path)) => {
                            current_path = path;
                        },
                        Some(SymbolResolution::Exact { gid, .. }) => {
                            return resolver.get_type(current_path.span(), gid).map(Some);
                        },
                        Some(SymbolResolution::Module { path: module_path, .. }) => {
                            break Err(resolver.resolve_local_failed(
                                LocalSymbolResolutionError::InvalidSymbolType {
                                    expected: "type",
                                    span: path.span(),
                                    actual: module_path.span(),
                                },
                            ));
                        },
                        Some(SymbolResolution::MastRoot(item)) => {
                            break Err(resolver.resolve_local_failed(
                                LocalSymbolResolutionError::InvalidSymbolType {
                                    expected: "type",
                                    span: path.span(),
                                    actual: item.span(),
                                },
                            ));
                        },
                        None => break Ok(None),
                    }
                }
            },
            TypeExpr::Primitive(t) => Ok(Some(t.inner().clone())),
            TypeExpr::Array(t) => Ok(t
                .elem
                .resolve_type(resolver)?
                .map(|elem| types::Type::Array(Arc::new(types::ArrayType::new(elem, t.arity))))),
            TypeExpr::Ptr(ty) => Ok(ty
                .pointee
                .resolve_type(resolver)?
                .map(|pointee| types::Type::Ptr(Arc::new(types::PointerType::new(pointee))))),
            TypeExpr::Struct(t) => {
                let mut fields = Vec::with_capacity(t.fields.len());
                for field in t.fields.iter() {
                    let field_ty = field.ty.resolve_type(resolver)?;
                    if let Some(field_ty) = field_ty {
                        fields.push(field_ty);
                    } else {
                        return Ok(None);
                    }
                }
                Ok(Some(Type::Struct(Arc::new(types::StructType::new(fields)))))
            },
        }
    }
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
            Type::Ptr(t) => Self::Ptr((*t).clone().into()),
            Type::Function(_) => {
                Self::Ptr(PointerType::new(TypeExpr::Primitive(Span::unknown(Type::Felt))))
            },
            Type::List(t) => Self::Ptr(
                PointerType::new((*t).clone().into()).with_address_space(AddressSpace::Byte),
            ),
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

impl crate::prettier::PrettyPrint for TypeExpr {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        match self {
            Self::Primitive(ty) => display(ty),
            Self::Ptr(ty) => ty.render(),
            Self::Array(ty) => ty.render(),
            Self::Struct(ty) => ty.render(),
            Self::Ref(ty) => display(ty),
        }
    }
}

// POINTER TYPE
// ================================================================================================

#[derive(Debug, Clone)]
pub struct PointerType {
    pub span: SourceSpan,
    pub pointee: Box<TypeExpr>,
    addrspace: Option<AddressSpace>,
}

impl From<types::PointerType> for PointerType {
    fn from(ty: types::PointerType) -> Self {
        let types::PointerType { addrspace, pointee } = ty;
        let pointee = Box::new(TypeExpr::from(pointee));
        Self {
            span: SourceSpan::UNKNOWN,
            pointee,
            addrspace: Some(addrspace),
        }
    }
}

impl Eq for PointerType {}

impl PartialEq for PointerType {
    fn eq(&self, other: &Self) -> bool {
        self.address_space() == other.address_space() && self.pointee == other.pointee
    }
}

impl core::hash::Hash for PointerType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.pointee.hash(state);
        self.addrspace.hash(state);
    }
}

impl Spanned for PointerType {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl PointerType {
    pub fn new(pointee: TypeExpr) -> Self {
        Self {
            span: SourceSpan::UNKNOWN,
            pointee: Box::new(pointee),
            addrspace: None,
        }
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }

    /// Override the default address space
    #[inline]
    pub fn with_address_space(mut self, addrspace: AddressSpace) -> Self {
        self.addrspace = Some(addrspace);
        self
    }

    /// Get the address space of this pointer type
    #[inline]
    pub fn address_space(&self) -> AddressSpace {
        self.addrspace.unwrap_or(AddressSpace::Element)
    }
}

impl crate::prettier::PrettyPrint for PointerType {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let doc = const_text("ptr<") + self.pointee.render();
        if let Some(addrspace) = self.addrspace.as_ref() {
            doc + const_text(", ") + text(format!("addrspace({})", addrspace)) + const_text(">")
        } else {
            doc + const_text(">")
        }
    }
}

// ARRAY TYPE
// ================================================================================================

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

impl crate::prettier::PrettyPrint for ArrayType {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        const_text("[")
            + self.elem.render()
            + const_text("; ")
            + display(self.arity)
            + const_text("]")
    }
}

// STRUCT TYPE
// ================================================================================================

#[derive(Debug, Clone)]
pub struct StructType {
    pub span: SourceSpan,
    pub repr: Span<TypeRepr>,
    pub fields: Vec<StructField>,
}

impl Eq for StructType {}

impl PartialEq for StructType {
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr && self.fields == other.fields
    }
}

impl core::hash::Hash for StructType {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.repr.hash(state);
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
            repr: Span::unknown(TypeRepr::Default),
            fields: fields.into_iter().collect(),
        }
    }

    /// Override the default struct representation
    #[inline]
    pub fn with_repr(mut self, repr: Span<TypeRepr>) -> Self {
        self.repr = repr;
        self
    }

    /// Override the default source span
    #[inline]
    pub fn with_span(mut self, span: SourceSpan) -> Self {
        self.span = span;
        self
    }
}

impl crate::prettier::PrettyPrint for StructType {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let repr = match &*self.repr {
            TypeRepr::Default => Document::Empty,
            TypeRepr::BigEndian => const_text("@bigendian "),
            repr @ (TypeRepr::Align(_) | TypeRepr::Packed(_) | TypeRepr::Transparent) => {
                text(format!("@{repr} "))
            },
        };

        let singleline_body = self
            .fields
            .iter()
            .map(|field| field.render())
            .reduce(|acc, field| acc + const_text(", ") + field)
            .unwrap_or(Document::Empty);
        let multiline_body = indent(
            4,
            nl() + self
                .fields
                .iter()
                .map(|field| field.render())
                .reduce(|acc, field| acc + const_text(",") + nl() + field)
                .unwrap_or(Document::Empty),
        ) + nl();
        let body = singleline_body | multiline_body;

        repr + const_text("struct") + const_text(" { ") + body + const_text(" }")
    }
}

// STRUCT FIELD
// ================================================================================================

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

impl crate::prettier::PrettyPrint for StructField {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        display(&self.name) + const_text(": ") + self.ty.render()
    }
}

// TYPE ALIAS
// ================================================================================================

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
    /// The visibility of this type alias
    pub visibility: Visibility,
    /// The name of this type alias
    pub name: Ident,
    /// The concrete underlying type
    pub ty: TypeExpr,
}

impl TypeAlias {
    /// Create a new type alias from a name and type
    pub fn new(visibility: Visibility, name: Ident, ty: TypeExpr) -> Self {
        Self {
            span: name.span(),
            docs: None,
            visibility,
            name,
            ty,
        }
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

    /// Returns the documentation associated with this item.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
    }

    /// Get the name of this type alias
    pub fn name(&self) -> &Ident {
        &self.name
    }

    /// Get the visibility of this type alias
    #[inline]
    pub const fn visibility(&self) -> Visibility {
        self.visibility
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
        let Self { span: _, docs, visibility, name, ty } = self;
        docs.hash(state);
        visibility.hash(state);
        name.hash(state);
        ty.hash(state);
    }
}

impl Spanned for TypeAlias {
    fn span(&self) -> SourceSpan {
        self.span
    }
}

impl crate::prettier::PrettyPrint for TypeAlias {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }

        doc + const_text("type")
            + const_text(" ")
            + display(&self.name)
            + const_text(" = ")
            + self.ty.render()
    }
}

// ENUM TYPE
// ================================================================================================

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
    /// The visibility of this enum type
    visibility: Visibility,
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
    pub fn new(
        visibility: Visibility,
        name: Ident,
        ty: Type,
        variants: impl IntoIterator<Item = Variant>,
    ) -> Self {
        assert!(ty.is_integer(), "only integer types are allowed in enum type definitions");
        Self {
            span: name.span(),
            docs: None,
            visibility,
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

    /// Get the visibility of this enum type
    pub const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// Returns the documentation associated with this item.
    pub fn docs(&self) -> Option<Span<&str>> {
        self.docs.as_ref().map(|docstring| docstring.as_spanned_str())
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
        let Self {
            span,
            docs,
            visibility,
            name,
            ty,
            variants,
        } = self;
        let alias = TypeAlias {
            span,
            docs,
            visibility,
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
        let Self {
            span: _,
            docs,
            visibility,
            name,
            ty,
            variants,
        } = self;
        docs.hash(state);
        visibility.hash(state);
        name.hash(state);
        ty.hash(state);
        variants.hash(state);
    }
}

impl crate::prettier::PrettyPrint for EnumType {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let mut doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        let variants = self
            .variants
            .iter()
            .map(|v| v.render())
            .reduce(|acc, v| acc + const_text(",") + nl() + v)
            .unwrap_or(Document::Empty);

        if self.visibility.is_public() {
            doc += display(self.visibility) + const_text(" ");
        }

        doc + const_text("enum")
            + const_text(" ")
            + display(&self.name)
            + const_text(" : ")
            + self.ty.render()
            + const_text(" {")
            + nl()
            + variants
            + const_text("}")
    }
}

// ENUM VARIANT
// ================================================================================================

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

impl crate::prettier::PrettyPrint for Variant {
    fn render(&self) -> crate::prettier::Document {
        use crate::prettier::*;

        let doc = self
            .docs
            .as_ref()
            .map(|docstring| docstring.render())
            .unwrap_or(Document::Empty);

        doc + display(&self.name) + const_text(" = ") + self.discriminant.render()
    }
}
