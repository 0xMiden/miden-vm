//! Support for recursive struct and enum types, represented as μ-binders.
//!
//! A recursive aggregate is an immutable [RecGroup] of definitions, plus an index selecting one
//! of them. The group is carried by [`Arc`] inside every value that denotes a recursive type, so
//! a recursive [Type] is as self-contained as any other [Type]: no interning table, definition
//! registry, or context object is ever needed to interpret one.
//!
//! The group's definition bodies use [OpenType], which is *not* a [Type], and which may contain
//! [`OpenType::Var`] back-references. Because open bodies are not [Type] values, it is impossible
//! to obtain a [Type] containing an unbound back-reference: "every `Type` is closed" is a property
//! of the type system rather than a convention that validation has to police.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::String,
    sync::Arc,
    vec::Vec,
};
use core::{
    fmt,
    hash::{Hash, Hasher},
    num::NonZeroU16,
};

use smallvec::SmallVec;

use crate::{
    AddressSpace, ArrayType, CallConv, EnumType, FunctionType, PointerType, StructField,
    StructType, Type, TypeRepr, Variant,
};

/// The maximum number of definitions permitted in a single recursive group.
///
/// This is a sanity bound rather than a security bound; adversarial input is constrained by the
/// deserializer's allocation budget. Raising this limit later is backwards-compatible, as the
/// definition count is encoded as a `u16` and the package reader accepts exactly one version.
/// Lowering it would not be, which is why it starts conservative.
pub const MAX_RECURSIVE_GROUP_SIZE: usize = 64;

/// Which kind of aggregate a recursive definition describes.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AggregateKind {
    Struct,
    Enum,
}

impl fmt::Display for AggregateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Struct => f.write_str("struct"),
            Self::Enum => f.write_str("enum"),
        }
    }
}

/// The cached, immutable layout of a recursive definition.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TypeLayout {
    size_in_bytes: u32,
    min_alignment: NonZeroU16,
    is_zst: bool,
}

impl TypeLayout {
    #[inline]
    pub const fn size_in_bytes(&self) -> usize {
        self.size_in_bytes as usize
    }

    #[inline]
    pub const fn min_alignment(&self) -> usize {
        self.min_alignment.get() as usize
    }

    #[inline]
    pub const fn is_zst(&self) -> bool {
        self.is_zst
    }
}

// RECURSIVE TYPE REFERENCE
// ================================================================================================

/// A self-contained reference to one definition of a recursive group.
///
/// This is what makes a recursive [Type] stand alone: the whole group travels with the reference,
/// so layout, unfolding, equality, hashing, and serialization all work without any external
/// context.
#[derive(Debug, Clone)]
pub struct RecTypeRef {
    group: Arc<RecGroup>,
    index: u16,
}

impl RecTypeRef {
    fn def(&self) -> &RecDef {
        &self.group.defs[self.index as usize]
    }

    /// The declared name of the aggregate this reference selects, if it has one.
    ///
    /// This agrees with the name on the unfolded form, so the folded and unfolded views of a
    /// recursive aggregate never disagree about what it is called.
    #[inline]
    pub fn name(&self) -> Option<Arc<str>> {
        match &self.def().body {
            OpenAggregate::Struct(body) => body.name.clone(),
            OpenAggregate::Enum(body) => Some(body.name.clone()),
        }
    }

    /// Whether this reference selects a struct or an enum definition.
    #[inline]
    pub fn kind(&self) -> AggregateKind {
        self.def().kind
    }

    /// The cached layout of the selected definition.
    #[inline]
    pub fn layout(&self) -> TypeLayout {
        self.def().layout
    }

    /// The number of definitions in this reference's group.
    ///
    /// A group larger than one definition is mutually recursive.
    #[inline]
    pub fn group_len(&self) -> usize {
        self.group.defs.len()
    }

    /// The index of the selected definition within its group.
    #[inline]
    #[cfg(feature = "serde")]
    pub(crate) fn index(&self) -> u16 {
        self.index
    }

    /// The group's definitions, in canonical order.
    #[inline]
    #[cfg(feature = "serde")]
    pub(crate) fn defs(&self) -> &[RecDef] {
        &self.group.defs
    }

    /// Unfold this reference one level into the struct it denotes.
    ///
    /// Every child of the result is an ordinary, closed [Type]. Panics if this reference selects
    /// an enum; callers reach this through [`crate::StructRef::get`], which cannot mismatch.
    pub(crate) fn unfold_struct(&self) -> StructType {
        match &self.def().body {
            OpenAggregate::Struct(body) => body.close(&self.group),
            OpenAggregate::Enum(_) => {
                panic!("invalid recursive type reference: expected a struct definition")
            },
        }
    }

    /// Unfold this reference one level into the enum it denotes.
    pub(crate) fn unfold_enum(&self) -> EnumType {
        match &self.def().body {
            OpenAggregate::Enum(body) => body.close(&self.group),
            OpenAggregate::Struct(_) => {
                panic!("invalid recursive type reference: expected an enum definition")
            },
        }
    }

    /// The representation of the selected struct definition, without unfolding it.
    pub(crate) fn struct_repr(&self) -> TypeRepr {
        match &self.def().body {
            OpenAggregate::Struct(body) => body.repr,
            OpenAggregate::Enum(_) => TypeRepr::Default,
        }
    }
}

impl PartialEq for RecTypeRef {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.group == other.group
    }
}

impl Eq for RecTypeRef {}

impl Hash for RecTypeRef {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.index.hash(state);
        self.group.hash(state);
    }
}

// RECURSIVE GROUP
// ================================================================================================

/// An immutable, canonically ordered set of mutually recursive aggregate definitions.
///
/// A group is exactly one strongly connected component of the type reference graph, with its
/// definitions sorted by name. Canonicalization is what makes structural equality a decision
/// procedure: two independently constructed but structurally identical recursive types produce
/// identical groups, and therefore compare and hash equal.
///
/// This is an implementation detail of [RecTypeRef]: a group is reachable only through one, and
/// is never named in the crate's public interface.
#[derive(Debug)]
pub(crate) struct RecGroup {
    defs: Box<[RecDef]>,
    /// Structural hash of `defs`, computed once at construction.
    ///
    /// Comparing recursive types happens on every lookup in a type cache, and a derived
    /// implementation would make each of those cost O(group size). Caching the hash makes
    /// hashing O(1) and gives equality an O(1) rejection path.
    hash: u64,
}

impl RecGroup {
    fn new(defs: Box<[RecDef]>) -> Self {
        let hash = hash_defs(&defs);
        Self { defs, hash }
    }
}

impl PartialEq for RecGroup {
    fn eq(&self, other: &Self) -> bool {
        // Values derived from the same construction share an allocation, which covers the
        // overwhelming majority of comparisons. Otherwise the cached hash rejects unequal groups
        // without walking them.
        core::ptr::eq(self, other) || (self.hash == other.hash && self.defs == other.defs)
    }
}

impl Eq for RecGroup {}

impl Hash for RecGroup {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

/// A single definition within a [RecGroup].
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct RecDef {
    pub(crate) kind: AggregateKind,
    pub(crate) body: OpenAggregate,
    pub(crate) layout: TypeLayout,
}

/// Append an exact encoding of `template` in which references *into the group* are collapsed to a
/// single token, and everything else is written out in full.
///
/// This is a key, not a hash. Two definitions that share a key must be interchangeable, because
/// the initial partition never splits them again on their own content -- only on what they refer
/// to. A hash could collide, and a collision here would merge two types that are not the same,
/// so every part is written with an explicit length or delimiter and nothing is elided.
///
/// References *out of* the group name definitions that are already complete, so they are written
/// as the type they resolve to: two definitions differing only in which of those they use are
/// different types, and two naming different declarations of the same type are not.
fn write_blind_key(
    template: &TypeTemplate,
    in_group: &BTreeSet<Arc<str>>,
    completed: &BTreeMap<Arc<str>, Type>,
    out: &mut String,
) {
    use core::fmt::Write;

    match template {
        TypeTemplate::Type(ty) => {
            let _ = write!(out, "t[{ty:?}]");
        },
        TypeTemplate::Rec(name) if in_group.contains(name) => out.push_str("v[]"),
        TypeTemplate::Rec(name) => match completed.get(name) {
            Some(ty) => {
                let _ = write!(out, "t[{ty:?}]");
            },
            // Unresolvable here means the reference is dangling, which the caller rejects.
            None => {
                let _ = write!(out, "x[{name:?}]");
            },
        },
        TypeTemplate::Ptr(addrspace, pointee) => {
            let _ = write!(out, "p[{addrspace:?}]");
            write_blind_key(pointee, in_group, completed, out);
        },
        TypeTemplate::Array(element, len) => {
            let _ = write!(out, "a[{len}]");
            write_blind_key(element, in_group, completed, out);
        },
        TypeTemplate::List(element) => {
            out.push_str("l[]");
            write_blind_key(element, in_group, completed, out);
        },
        TypeTemplate::Function(ty) => {
            // The list lengths matter: `fn(T)` and `fn() -> T` are otherwise the same tags in
            // the same order.
            let _ = write!(out, "f[{:?},{},{}]", ty.abi, ty.params.len(), ty.results.len());
            for t in ty.params.iter().chain(ty.results.iter()) {
                write_blind_key(t, in_group, completed, out);
            }
        },
        TypeTemplate::Struct(ty) => write_blind_struct_key(ty, in_group, completed, out),
        TypeTemplate::Enum(ty) => write_blind_enum_key(ty, in_group, completed, out),
    }
}

fn write_blind_struct_key(
    ty: &StructTemplate,
    in_group: &BTreeSet<Arc<str>>,
    completed: &BTreeMap<Arc<str>, Type>,
    out: &mut String,
) {
    use core::fmt::Write;

    let _ = write!(out, "s[{:?},{:?},{}]", ty.name, ty.repr, ty.fields.len());
    for field in &ty.fields {
        let _ = write!(out, "n[{:?}]", field.name);
        write_blind_key(&field.ty, in_group, completed, out);
    }
}

fn write_blind_enum_key(
    ty: &EnumTemplate,
    in_group: &BTreeSet<Arc<str>>,
    completed: &BTreeMap<Arc<str>, Type>,
    out: &mut String,
) {
    use core::fmt::Write;

    let _ = write!(out, "e[{:?},{:?},{}]", ty.name, ty.discriminant, ty.variants.len());
    for variant in &ty.variants {
        let _ = write!(out, "w[{:?},{:?}]", variant.name, variant.discriminant_value);
        match variant.value.as_ref() {
            Some(value) => write_blind_key(value, in_group, completed, out),
            None => out.push_str("z[]"),
        }
    }
}

/// A small, dependency-free FNV-1a hasher. Its values never leave the crate.
pub(crate) struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// The key a group's definitions are canonically ordered by.
///
/// Every component is derived from the definition itself rather than from the key it was
/// registered under, so that structurally identical groups order identically.
fn structural_order_key(
    def: &TemplateDef,
    in_group: &BTreeSet<Arc<str>>,
    completed: &BTreeMap<Arc<str>, Type>,
) -> (Option<Arc<str>>, AggregateKind, String) {
    (def.body.declared_name(), def.kind, def.body.blind_key(in_group, completed))
}

fn hash_defs(defs: &[RecDef]) -> u64 {
    let mut hasher = Fnv::new();
    defs.hash(&mut hasher);
    hasher.finish()
}

// OPEN TYPES
// ================================================================================================

/// A definition body which may contain back-references.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum OpenAggregate {
    Struct(OpenStructType),
    Enum(OpenEnumType),
}

/// A type expression that may contain back-references to the enclosing group.
///
/// An `OpenType` uses an open variant only when a [`OpenType::Var`] actually occurs beneath it;
/// anything closed is stored as [`OpenType::Closed`]. Every open body is therefore a thin spine
/// down to its variables, with ordinary [Type] values hanging off it. Closing a body only rewrites
/// that spine, and closed subterms are shared by `Arc` clone rather than rebuilt.
#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum OpenType {
    /// A subterm containing no back-references.
    Closed(Type),
    /// A back-reference to definition `i` of the enclosing group.
    Var(u16),
    Ptr(AddressSpace, Box<OpenType>),
    Array(Box<OpenType>, usize),
    List(Box<OpenType>),
    Function(Box<OpenFunctionType>),
    Struct(Box<OpenStructType>),
    Enum(Box<OpenEnumType>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct OpenStructType {
    pub(crate) name: Option<Arc<str>>,
    pub(crate) repr: TypeRepr,
    pub(crate) size: u32,
    pub(crate) fields: Vec<OpenStructField>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct OpenStructField {
    pub(crate) name: Option<Arc<str>>,
    pub(crate) index: u8,
    pub(crate) align: u16,
    pub(crate) offset: u32,
    pub(crate) ty: OpenType,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct OpenEnumType {
    pub(crate) name: Arc<str>,
    pub(crate) discriminant: Type,
    pub(crate) variants: Vec<OpenVariant>,
    pub(crate) offsets: Vec<u32>,
    pub(crate) size: u32,
    pub(crate) align: u32,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct OpenVariant {
    pub(crate) name: Arc<str>,
    pub(crate) value: Option<OpenType>,
    pub(crate) discriminant_value: Option<u128>,
}

impl OpenType {
    /// Substitute every back-reference with a completed recursive [Type], yielding a closed type.
    fn close(&self, group: &Arc<RecGroup>) -> Type {
        match self {
            Self::Closed(ty) => ty.clone(),
            Self::Var(index) => rec_type(group.clone(), *index),
            Self::Ptr(addrspace, pointee) => Type::Ptr(Arc::new(PointerType {
                addrspace: *addrspace,
                pointee: pointee.close(group),
            })),
            Self::Array(element, len) => {
                Type::Array(Arc::new(ArrayType { ty: element.close(group), len: *len }))
            },
            Self::List(element) => Type::List(Arc::new(element.close(group))),
            Self::Function(ty) => Type::Function(Arc::new(FunctionType {
                abi: ty.abi.clone(),
                params: ty.params.iter().map(|t| t.close(group)).collect(),
                results: ty.results.iter().map(|t| t.close(group)).collect(),
            })),
            Self::Struct(body) => Type::from(body.close(group)),
            Self::Enum(body) => Type::from(body.close(group)),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) struct OpenFunctionType {
    pub(crate) abi: CallConv,
    pub(crate) params: Vec<OpenType>,
    pub(crate) results: Vec<OpenType>,
}

impl OpenStructType {
    /// Rebuild this body as a real [StructType], reusing the stored layout metadata rather than
    /// recomputing it.
    fn close(&self, group: &Arc<RecGroup>) -> StructType {
        StructType::from_raw_parts(
            self.name.clone(),
            self.repr,
            self.size,
            self.fields
                .iter()
                .map(|f| StructField {
                    name: f.name.clone(),
                    index: f.index,
                    align: f.align,
                    offset: f.offset,
                    ty: f.ty.close(group),
                })
                .collect(),
        )
    }
}

impl OpenEnumType {
    fn close(&self, group: &Arc<RecGroup>) -> EnumType {
        EnumType::from_raw_parts(
            self.name.clone(),
            self.discriminant.clone(),
            self.variants
                .iter()
                .map(|v| Variant {
                    name: v.name.clone(),
                    value: v.value.as_ref().map(|t| t.close(group)),
                    discriminant_value: v.discriminant_value,
                })
                .collect(),
            self.offsets.iter().copied().collect(),
            self.size,
            self.align,
        )
    }
}

/// Build the completed [Type] denoting definition `index` of `group`.
fn rec_type(group: Arc<RecGroup>, index: u16) -> Type {
    let reference = RecTypeRef { group, index };
    match reference.kind() {
        AggregateKind::Struct => Type::Struct(crate::StructRef::Rec(reference)),
        AggregateKind::Enum => Type::Enum(crate::EnumRef::Rec(reference)),
    }
}

// TEMPLATES
// ================================================================================================

/// A type expression used while describing a recursive definition to [RecursiveTypeBuilder].
//
// Unlike [OpenType], this is public input: it names its back-references, and carries no layout
// metadata. The builder resolves names to indices and computes layouts.
#[derive(Debug, Clone)]
pub enum TypeTemplate {
    /// An ordinary, already-completed type.
    Type(Type),
    /// A reference to a definition being built, by name.
    Rec(Arc<str>),
    Ptr(AddressSpace, Box<TypeTemplate>),
    Array(Box<TypeTemplate>, usize),
    List(Box<TypeTemplate>),
    Function(Box<FunctionTemplate>),
    Struct(Box<StructTemplate>),
    Enum(Box<EnumTemplate>),
}

impl From<Type> for TypeTemplate {
    fn from(ty: Type) -> Self {
        Self::Type(ty)
    }
}

impl TypeTemplate {
    /// A reference to the definition named `name`.
    pub fn rec(name: impl Into<Arc<str>>) -> Self {
        Self::Rec(name.into())
    }

    /// A byte-addressable pointer to `pointee`.
    pub fn ptr(pointee: impl Into<TypeTemplate>) -> Self {
        Self::Ptr(AddressSpace::Byte, Box::new(pointee.into()))
    }

    /// A pointer to `pointee` in `addrspace`.
    pub fn ptr_in(addrspace: AddressSpace, pointee: impl Into<TypeTemplate>) -> Self {
        Self::Ptr(addrspace, Box::new(pointee.into()))
    }

    /// A fixed-length array of `element`.
    pub fn array(element: impl Into<TypeTemplate>, len: usize) -> Self {
        Self::Array(Box::new(element.into()), len)
    }

    /// A dynamically sized list of `element`.
    pub fn list(element: impl Into<TypeTemplate>) -> Self {
        Self::List(Box::new(element.into()))
    }

    /// A function reference type.
    pub fn function(
        abi: CallConv,
        params: impl IntoIterator<Item = TypeTemplate>,
        results: impl IntoIterator<Item = TypeTemplate>,
    ) -> Self {
        Self::Function(Box::new(FunctionTemplate {
            abi,
            params: params.into_iter().collect(),
            results: results.into_iter().collect(),
        }))
    }

    /// An anonymous struct.
    pub fn struct_type(repr: TypeRepr, fields: impl IntoIterator<Item = FieldTemplate>) -> Self {
        Self::Struct(Box::new(StructTemplate::new(repr, fields)))
    }
}

#[derive(Debug, Clone)]
pub struct FunctionTemplate {
    pub abi: CallConv,
    pub params: Vec<TypeTemplate>,
    pub results: Vec<TypeTemplate>,
}

/// A struct definition described to [RecursiveTypeBuilder].
#[derive(Debug, Clone)]
pub struct StructTemplate {
    pub name: Option<Arc<str>>,
    pub repr: TypeRepr,
    pub fields: Vec<FieldTemplate>,
}

impl StructTemplate {
    /// An anonymous struct.
    pub fn new(repr: TypeRepr, fields: impl IntoIterator<Item = impl Into<FieldTemplate>>) -> Self {
        Self {
            name: None,
            repr,
            fields: fields.into_iter().map(Into::into).collect(),
        }
    }

    /// A struct declared with `name`.
    ///
    /// The name is the aggregate's own, and is independent of the binding key it is defined
    /// under; see [`RecursiveTypeBuilder::define_struct`].
    pub fn named(
        name: impl Into<Arc<str>>,
        repr: TypeRepr,
        fields: impl IntoIterator<Item = impl Into<FieldTemplate>>,
    ) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new(repr, fields)
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldTemplate {
    pub name: Option<Arc<str>>,
    pub ty: TypeTemplate,
}

impl<N: Into<Arc<str>>, T: Into<TypeTemplate>> From<(N, T)> for FieldTemplate {
    fn from((name, ty): (N, T)) -> Self {
        Self { name: Some(name.into()), ty: ty.into() }
    }
}

impl From<TypeTemplate> for FieldTemplate {
    fn from(ty: TypeTemplate) -> Self {
        Self { name: None, ty }
    }
}

/// An enum definition described to [RecursiveTypeBuilder].
#[derive(Debug, Clone)]
pub struct EnumTemplate {
    pub name: Arc<str>,
    pub discriminant: Type,
    pub variants: Vec<VariantTemplate>,
}

impl EnumTemplate {
    pub fn new(
        name: impl Into<Arc<str>>,
        discriminant: Type,
        variants: impl IntoIterator<Item = VariantTemplate>,
    ) -> Self {
        Self {
            name: name.into(),
            discriminant,
            variants: variants.into_iter().collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VariantTemplate {
    pub name: Arc<str>,
    pub value: Option<TypeTemplate>,
    pub discriminant_value: Option<u128>,
}

impl VariantTemplate {
    /// A variant with no payload.
    pub fn c_like(name: impl Into<Arc<str>>, discriminant_value: Option<u128>) -> Self {
        Self {
            name: name.into(),
            value: None,
            discriminant_value,
        }
    }

    /// A variant carrying `value`.
    pub fn new(
        name: impl Into<Arc<str>>,
        value: impl Into<TypeTemplate>,
        discriminant_value: Option<u128>,
    ) -> Self {
        Self {
            name: name.into(),
            value: Some(value.into()),
            discriminant_value,
        }
    }
}

// ERRORS
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecursiveTypeError {
    #[error("invalid recursive type: definition name must not be empty")]
    EmptyName,
    #[error("invalid recursive type: duplicate definition name '{0}'")]
    DuplicateName(Arc<str>),
    #[error("invalid recursive type: reference to undefined type '{0}'")]
    UndefinedReference(Arc<str>),
    #[error(
        "invalid recursive type: '{0}' is recursive without an intervening pointer, list, or \
         function, so it would have infinite size"
    )]
    UnguardedRecursion(Arc<str>),
    #[error(
        "invalid recursive type: group containing '{0}' has {1} definitions, but no more than \
         {MAX_RECURSIVE_GROUP_SIZE} are allowed"
    )]
    GroupTooLarge(Arc<str>, usize),
    #[error("invalid recursive type: {0}")]
    InvalidDefinition(Arc<str>),
}

// BUILDER
// ================================================================================================

/// Builds recursive struct and enum types from a set of named definitions.
///
/// Definitions refer to one another by name. The builder partitions them into strongly connected
/// components, validates that every recursive cycle crosses a layout barrier, canonicalizes each
/// group, computes layouts, and returns the completed [Type] for every definition.
#[derive(Debug, Default)]
pub struct RecursiveTypeBuilder {
    defs: Vec<TemplateDef>,
}

#[derive(Debug)]
struct TemplateDef {
    name: Arc<str>,
    kind: AggregateKind,
    body: AggregateTemplate,
}

#[derive(Debug)]
enum AggregateTemplate {
    Struct(StructTemplate),
    Enum(EnumTemplate),
}

impl RecursiveTypeBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a struct under the binding key `key`.
    ///
    /// The key identifies the definition within the group and is what back-references name; it
    /// does not become the struct's name. Set `template.name` for that.
    pub fn define_struct(
        &mut self,
        key: impl Into<Arc<str>>,
        template: StructTemplate,
    ) -> &mut Self {
        self.defs.push(TemplateDef {
            name: key.into(),
            kind: AggregateKind::Struct,
            body: AggregateTemplate::Struct(template),
        });
        self
    }

    /// Define an enum under the binding key `key`. See [`Self::define_struct`].
    pub fn define_enum(&mut self, key: impl Into<Arc<str>>, template: EnumTemplate) -> &mut Self {
        let name = key.into();
        self.defs.push(TemplateDef {
            name,
            kind: AggregateKind::Enum,
            body: AggregateTemplate::Enum(template),
        });
        self
    }

    /// Validate and materialize every definition, keyed by name.
    pub fn build(&mut self) -> Result<BTreeMap<Arc<str>, Type>, RecursiveTypeError> {
        let defs = core::mem::take(&mut self.defs);
        build_definitions(defs)
    }
}

fn build_definitions(
    defs: Vec<TemplateDef>,
) -> Result<BTreeMap<Arc<str>, Type>, RecursiveTypeError> {
    // Resolve names to indices, rejecting empty and duplicate names.
    let mut index_of = BTreeMap::<Arc<str>, usize>::new();
    for (index, def) in defs.iter().enumerate() {
        if def.name.is_empty() {
            return Err(RecursiveTypeError::EmptyName);
        }
        if index_of.insert(def.name.clone(), index).is_some() {
            return Err(RecursiveTypeError::DuplicateName(def.name.clone()));
        }
    }

    for def in &defs {
        for reference in def.body.references() {
            if !index_of.contains_key(&reference) {
                return Err(RecursiveTypeError::UndefinedReference(reference));
            }
        }
    }

    // Every definition here is part of exactly one group. Self-recursion yields a group of one;
    // mutual recursion yields a group per strongly connected component.
    let groups = strongly_connected_components(&defs, &index_of);

    let mut completed = BTreeMap::<Arc<str>, Type>::new();
    for group in groups {
        build_group(&defs, group, &mut completed)?;
    }

    Ok(completed)
}

/// Partition definitions into strongly connected components, in an order where every component
/// appears after the components it depends on.
fn strongly_connected_components(
    defs: &[TemplateDef],
    index_of: &BTreeMap<Arc<str>, usize>,
) -> Vec<Vec<usize>> {
    // Iterative Tarjan, which yields components in reverse topological order, i.e. dependencies
    // first, which is exactly the order the caller needs.
    #[derive(Clone, Copy)]
    struct State {
        index: usize,
        lowlink: usize,
        on_stack: bool,
    }

    let edges = defs
        .iter()
        .map(|def| {
            def.body
                .references()
                .into_iter()
                .filter_map(|name| index_of.get(&name).copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let mut state = alloc::vec![None::<State>; defs.len()];
    let mut stack = Vec::new();
    let mut components = Vec::new();
    let mut next_index = 0usize;

    for root in 0..defs.len() {
        if state[root].is_some() {
            continue;
        }
        // (node, next edge to visit)
        let mut call_stack = alloc::vec![(root, 0usize)];
        state[root] = Some(State {
            index: next_index,
            lowlink: next_index,
            on_stack: true,
        });
        next_index += 1;
        stack.push(root);

        while let Some((node, edge)) = call_stack.last_mut() {
            let node = *node;
            if *edge < edges[node].len() {
                let successor = edges[node][*edge];
                *edge += 1;
                match state[successor] {
                    None => {
                        state[successor] = Some(State {
                            index: next_index,
                            lowlink: next_index,
                            on_stack: true,
                        });
                        next_index += 1;
                        stack.push(successor);
                        call_stack.push((successor, 0));
                    },
                    Some(successor_state) if successor_state.on_stack => {
                        let node_state = state[node].as_mut().unwrap();
                        node_state.lowlink = node_state.lowlink.min(successor_state.index);
                    },
                    Some(_) => {},
                }
                continue;
            }

            call_stack.pop();
            let node_state = state[node].unwrap();
            if node_state.lowlink == node_state.index {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    state[member].as_mut().unwrap().on_stack = false;
                    component.push(member);
                    if member == node {
                        break;
                    }
                }
                components.push(component);
            }
            if let Some((parent, _)) = call_stack.last() {
                let child_lowlink = node_state.lowlink;
                let parent_state = state[*parent].as_mut().unwrap();
                parent_state.lowlink = parent_state.lowlink.min(child_lowlink);
            }
        }
    }

    components
}

fn build_group(
    defs: &[TemplateDef],
    component: Vec<usize>,
    completed: &mut BTreeMap<Arc<str>, Type>,
) -> Result<(), RecursiveTypeError> {
    let is_recursive = component.len() > 1
        || defs[component[0]].body.references().contains(&defs[component[0]].name);

    if !is_recursive {
        // An ordinary, non-recursive definition. Materialize it directly.
        let def = &defs[component[0]];
        let ty = def.body.close_with(&|name| completed.get(&name).cloned())?;
        completed.insert(def.name.clone(), ty);
        return Ok(());
    }

    // The cap applies to the declarations coming in, since that is the work being bounded;
    // merging below can only reduce the count.
    if component.len() > MAX_RECURSIVE_GROUP_SIZE {
        return Err(RecursiveTypeError::GroupTooLarge(
            defs[component[0]].name.clone(),
            component.len(),
        ));
    }

    // Canonical order must be a function of the group's *structure*, not of the keys it happened
    // to be built under. Keys are collision-free identifiers a frontend supplies to bind
    // back-references -- typically module-qualified paths -- and ordering by them would make the
    // same type declared in two modules order differently, and so compare unequal.
    //
    // Structure alone cannot order definitions that are indistinguishable from one another, so
    // rather than break such ties arbitrarily, indistinguishable definitions are merged: they
    // denote the same type, exactly as two identically named and shaped non-recursive structs
    // already do. What comes back is one definition per equivalence class, canonically ordered.
    let class_of = merge_isomorphic_definitions(defs, &component, completed);
    let class_count = class_of.iter().copied().max().map_or(0, |max| max as usize + 1);

    // Every member of a class resolves to that class's definition, so a reference to any of them
    // is a reference to the one that remains.
    let slot_of = component
        .iter()
        .enumerate()
        .map(|(position, member)| (defs[*member].name.clone(), class_of[position]))
        .collect::<BTreeMap<_, _>>();

    // One representative per class; they are indistinguishable, so which one is immaterial.
    let mut representatives = alloc::vec![None::<usize>; class_count];
    for (position, member) in component.iter().enumerate() {
        representatives[class_of[position] as usize].get_or_insert(*member);
    }
    let original_component = component;
    let component: Vec<usize> = representatives
        .into_iter()
        .map(|member| member.expect("every class has a member"))
        .collect();

    // Guardedness: build the unguarded reference graph over the group and require it to be
    // acyclic. Equivalently, every cycle in the full reference graph must cross a barrier. This
    // is more permissive than requiring every back-reference to sit below a barrier, which is
    // needed for mutual recursion: in `struct A { b: B }` / `struct B { a: *A }`, the `A -> B`
    // edge is unguarded, yet the cycle as a whole is guarded and `A` is finite.
    let unguarded = component
        .iter()
        .map(|member| defs[*member].body.unguarded_references(&slot_of))
        .collect::<Vec<_>>();
    let order = topological_order(&unguarded)
        .ok_or_else(|| RecursiveTypeError::UnguardedRecursion(defs[component[0]].name.clone()))?;

    // Compute each definition's layout in an order where its unguarded dependencies are already
    // known, using a closed probe: substitute guarded references with a zero-sized placeholder
    // (a barrier makes the choice irrelevant) and unguarded ones with an opaque stand-in of the
    // already-computed layout. Running the ordinary eager constructors over that probe yields
    // exactly the right layout, with no duplicated layout rules.
    let mut layouts = alloc::vec![None::<TypeLayout>; component.len()];
    for slot in order {
        let def = &defs[component[slot]];
        let probe = def.body.close_with(&|name| match slot_of.get(&name) {
            Some(other) => Some(probe_stand_in(layouts[*other as usize])),
            None => completed.get(&name).cloned(),
        })?;
        layouts[slot] = Some(layout_of(&probe));
    }

    // Materialize the open bodies, taking layout metadata from each definition's probe.
    let mut rec_defs = Vec::with_capacity(component.len());
    for (slot, member) in component.iter().enumerate() {
        let def = &defs[*member];
        let probe = def.body.close_with(&|name| match slot_of.get(&name) {
            Some(other) => Some(probe_stand_in(layouts[*other as usize])),
            None => completed.get(&name).cloned(),
        })?;
        let body = def.body.open(&probe, &slot_of, completed)?;
        rec_defs.push(RecDef {
            kind: def.kind,
            body,
            layout: layouts[slot].expect("layout computed above"),
        });
    }

    let group = Arc::new(RecGroup::new(rec_defs.into_boxed_slice()));
    for (position, member) in original_component.iter().enumerate() {
        completed.insert(defs[*member].name.clone(), rec_type(group.clone(), class_of[position]));
    }

    Ok(())
}

/// Partition a component's definitions into classes that denote the same type, and return each
/// definition's class.
///
/// Definitions start apart if their declared name, kind, or reference-blind shape differ, and are
/// then repeatedly split whenever they refer to definitions that have themselves been split. What
/// remains in one class at the fixpoint cannot be told apart by any finite unfolding, so those
/// definitions are the same type.
///
/// Class numbering is canonical: at each round the distinct signatures are sorted, and a signature
/// is built from the previous round's numbering, which is canonical by induction. The base case is
/// the structural key, which does not depend on any numbering.
fn merge_isomorphic_definitions(
    defs: &[TemplateDef],
    component: &[usize],
    completed: &BTreeMap<Arc<str>, Type>,
) -> Vec<u16> {
    let position_of = component
        .iter()
        .enumerate()
        .map(|(position, member)| (defs[*member].name.clone(), position))
        .collect::<BTreeMap<_, _>>();

    // References in occurrence order, so that two definitions referring to different classes in
    // different positions are told apart.
    let references = component
        .iter()
        .map(|member| {
            defs[*member]
                .body
                .ordered_references()
                .into_iter()
                .filter_map(|name| position_of.get(&name).copied())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    let in_group = component.iter().map(|member| defs[*member].name.clone()).collect();
    let keys = component
        .iter()
        .map(|member| structural_order_key(&defs[*member], &in_group, completed))
        .collect::<Vec<_>>();
    let mut classes = rank(&keys);

    loop {
        let signatures = (0..component.len())
            .map(|position| {
                (
                    classes[position],
                    references[position].iter().map(|to| classes[*to]).collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();
        let refined = rank(&signatures);
        if refined == classes {
            return classes;
        }
        classes = refined;
    }
}

/// Number `values` by their sorted order, so equal values share a number and the numbering depends
/// only on the values themselves.
fn rank<T: Ord + Clone>(values: &[T]) -> Vec<u16> {
    let mut distinct = values.to_vec();
    distinct.sort();
    distinct.dedup();
    values
        .iter()
        .map(|value| distinct.binary_search(value).expect("value is present") as u16)
        .collect()
}

/// A closed stand-in for a reference to a group member, used when building a probe.
///
/// When the referenced definition's layout is already known, the stand-in reproduces it exactly,
/// so that any enclosing aggregate lays out correctly. When it is not yet known, the reference
/// must be guarded -- the topological order lays out every unguarded dependency first -- and so
/// it sits below a barrier where its layout cannot influence anything, and a zero-sized
/// placeholder is sufficient.
fn probe_stand_in(layout: Option<TypeLayout>) -> Type {
    let Some(layout) = layout else {
        return Type::Never;
    };
    let element = Type::from(ArrayType::new(Type::U8, layout.size_in_bytes()));
    Type::from(StructType::new_with_repr(TypeRepr::Align(layout.min_alignment), [element]))
}

fn layout_of(ty: &Type) -> TypeLayout {
    TypeLayout {
        size_in_bytes: u32::try_from(ty.size_in_bytes())
            .expect("invalid type: size is larger than 2^32 bytes"),
        min_alignment: NonZeroU16::new(
            u16::try_from(ty.min_alignment()).expect("invalid type: alignment is out of range"),
        )
        .expect("invalid type: alignment must be non-zero"),
        is_zst: ty.is_zst(),
    }
}

/// Order the slots so that every slot appears after the slots it unguardedly depends on, or
/// `None` if the unguarded graph has a cycle.
fn topological_order(unguarded: &[BTreeSet<u16>]) -> Option<Vec<usize>> {
    let mut visiting = alloc::vec![false; unguarded.len()];
    let mut visited = alloc::vec![false; unguarded.len()];
    let mut order = Vec::with_capacity(unguarded.len());

    fn visit(
        node: usize,
        unguarded: &[BTreeSet<u16>],
        visiting: &mut [bool],
        visited: &mut [bool],
        order: &mut Vec<usize>,
    ) -> bool {
        if visited[node] {
            return true;
        }
        if visiting[node] {
            return false;
        }
        visiting[node] = true;
        for successor in &unguarded[node] {
            if !visit(*successor as usize, unguarded, visiting, visited, order) {
                return false;
            }
        }
        visiting[node] = false;
        visited[node] = true;
        order.push(node);
        true
    }

    for node in 0..unguarded.len() {
        if !visit(node, unguarded, &mut visiting, &mut visited, &mut order) {
            return None;
        }
    }

    Some(order)
}

// TEMPLATE TRAVERSAL
// ================================================================================================

impl AggregateTemplate {
    /// The name the aggregate was declared with, if any.
    fn declared_name(&self) -> Option<Arc<str>> {
        match self {
            Self::Struct(ty) => ty.name.clone(),
            Self::Enum(ty) => Some(ty.name.clone()),
        }
    }

    /// An exact encoding of this definition's shape, with references into the group collapsed.
    ///
    /// See [`write_blind_key`] for why this is a key rather than a hash.
    fn blind_key(
        &self,
        in_group: &BTreeSet<Arc<str>>,
        completed: &BTreeMap<Arc<str>, Type>,
    ) -> String {
        let mut key = String::new();
        match self {
            Self::Struct(ty) => write_blind_struct_key(ty, in_group, completed, &mut key),
            Self::Enum(ty) => write_blind_enum_key(ty, in_group, completed, &mut key),
        }
        key
    }

    /// Every reference this definition makes, in the order it makes them.
    ///
    /// Occurrence order matters to refinement: two definitions referring to the same classes in
    /// different positions are different types.
    fn ordered_references(&self) -> Vec<Arc<str>> {
        let mut references = Vec::new();
        match self {
            Self::Struct(ty) => {
                for field in &ty.fields {
                    collect_ordered_references(&field.ty, &mut references);
                }
            },
            Self::Enum(ty) => {
                for variant in &ty.variants {
                    if let Some(value) = variant.value.as_ref() {
                        collect_ordered_references(value, &mut references);
                    }
                }
            },
        }
        references
    }

    fn references(&self) -> BTreeSet<Arc<str>> {
        let mut references = BTreeSet::new();
        match self {
            Self::Struct(ty) => {
                for field in &ty.fields {
                    collect_references(&field.ty, &mut references);
                }
            },
            Self::Enum(ty) => {
                for variant in &ty.variants {
                    if let Some(value) = variant.value.as_ref() {
                        collect_references(value, &mut references);
                    }
                }
            },
        }
        references
    }

    /// References to group members which are *not* below a layout barrier.
    fn unguarded_references(&self, slot_of: &BTreeMap<Arc<str>, u16>) -> BTreeSet<u16> {
        let mut references = BTreeSet::new();
        match self {
            Self::Struct(ty) => {
                for field in &ty.fields {
                    collect_unguarded(&field.ty, slot_of, &mut references);
                }
            },
            Self::Enum(ty) => {
                for variant in &ty.variants {
                    if let Some(value) = variant.value.as_ref() {
                        collect_unguarded(value, slot_of, &mut references);
                    }
                }
            },
        }
        references
    }
}

fn collect_ordered_references(template: &TypeTemplate, references: &mut Vec<Arc<str>>) {
    match template {
        TypeTemplate::Type(_) => {},
        TypeTemplate::Rec(name) => references.push(name.clone()),
        TypeTemplate::Ptr(_, inner) | TypeTemplate::Array(inner, _) | TypeTemplate::List(inner) => {
            collect_ordered_references(inner, references)
        },
        TypeTemplate::Function(ty) => {
            for t in ty.params.iter().chain(ty.results.iter()) {
                collect_ordered_references(t, references);
            }
        },
        TypeTemplate::Struct(ty) => {
            for field in &ty.fields {
                collect_ordered_references(&field.ty, references);
            }
        },
        TypeTemplate::Enum(ty) => {
            for variant in &ty.variants {
                if let Some(value) = variant.value.as_ref() {
                    collect_ordered_references(value, references);
                }
            }
        },
    }
}

fn collect_references(template: &TypeTemplate, references: &mut BTreeSet<Arc<str>>) {
    match template {
        TypeTemplate::Type(_) => {},
        TypeTemplate::Rec(name) => {
            references.insert(name.clone());
        },
        TypeTemplate::Ptr(_, inner) | TypeTemplate::Array(inner, _) | TypeTemplate::List(inner) => {
            collect_references(inner, references)
        },
        TypeTemplate::Function(ty) => {
            for t in ty.params.iter().chain(ty.results.iter()) {
                collect_references(t, references);
            }
        },
        TypeTemplate::Struct(ty) => {
            for field in &ty.fields {
                collect_references(&field.ty, references);
            }
        },
        TypeTemplate::Enum(ty) => {
            for variant in &ty.variants {
                if let Some(value) = variant.value.as_ref() {
                    collect_references(value, references);
                }
            }
        },
    }
}

fn collect_unguarded(
    template: &TypeTemplate,
    slot_of: &BTreeMap<Arc<str>, u16>,
    references: &mut BTreeSet<u16>,
) {
    match template {
        // Barriers: their own layout does not depend on what they refer to, so anything beneath
        // one is guarded and cannot contribute to the enclosing definition's size.
        TypeTemplate::Ptr(..) | TypeTemplate::List(_) | TypeTemplate::Function(_) => {},
        TypeTemplate::Type(_) => {},
        TypeTemplate::Rec(name) => {
            if let Some(slot) = slot_of.get(name) {
                references.insert(*slot);
            }
        },
        TypeTemplate::Array(inner, _) => collect_unguarded(inner, slot_of, references),
        TypeTemplate::Struct(ty) => {
            for field in &ty.fields {
                collect_unguarded(&field.ty, slot_of, references);
            }
        },
        TypeTemplate::Enum(ty) => {
            for variant in &ty.variants {
                if let Some(value) = variant.value.as_ref() {
                    collect_unguarded(value, slot_of, references);
                }
            }
        },
    }
}

type Resolve<'a> = dyn Fn(Arc<str>) -> Option<Type> + 'a;

/// Materialize a template as a completed [Type], resolving every back-reference through `resolve`.
///
/// This is for callers which hold a template that mentions definitions built elsewhere -- for
/// example a procedure signature that refers to a recursive type declared alongside it. A
/// reference `resolve` cannot answer is an error: a completed [Type] never contains an unbound
/// back-reference.
pub fn close_template(
    template: &TypeTemplate,
    resolve: impl Fn(&str) -> Option<Type>,
) -> Result<Type, RecursiveTypeError> {
    close_template_inner(template, &|name| resolve(name.as_ref()))
}

impl AggregateTemplate {
    /// Materialize this template as a closed [Type], resolving every reference through `resolve`.
    fn close_with(&self, resolve: &Resolve<'_>) -> Result<Type, RecursiveTypeError> {
        match self {
            Self::Struct(ty) => {
                let mut fields = SmallVec::<[crate::NameAndType; 4]>::new();
                for field in &ty.fields {
                    fields.push(crate::NameAndType {
                        name: field.name.clone(),
                        ty: close_template_inner(&field.ty, resolve)?,
                    });
                }
                Ok(Type::from(StructType::from_parts(ty.name.clone(), ty.repr, fields)))
            },
            Self::Enum(ty) => {
                let mut variants = SmallVec::<[Variant; 4]>::new();
                for variant in &ty.variants {
                    variants.push(Variant {
                        name: variant.name.clone(),
                        value: match variant.value.as_ref() {
                            Some(value) => Some(close_template_inner(value, resolve)?),
                            None => None,
                        },
                        discriminant_value: variant.discriminant_value,
                    });
                }
                EnumType::new(ty.name.clone(), ty.discriminant.clone(), variants)
                    .map(Type::from)
                    .map_err(|err| {
                        RecursiveTypeError::InvalidDefinition(alloc::format!("{err}").into())
                    })
            },
        }
    }
}

fn close_template_inner(
    template: &TypeTemplate,
    resolve: &Resolve<'_>,
) -> Result<Type, RecursiveTypeError> {
    Ok(match template {
        TypeTemplate::Type(ty) => ty.clone(),
        TypeTemplate::Rec(name) => resolve(name.clone())
            .ok_or_else(|| RecursiveTypeError::UndefinedReference(name.clone()))?,
        TypeTemplate::Ptr(addrspace, pointee) => Type::Ptr(Arc::new(PointerType {
            addrspace: *addrspace,
            pointee: close_template_inner(pointee, resolve)?,
        })),
        TypeTemplate::Array(element, len) => {
            Type::from(ArrayType::new(close_template_inner(element, resolve)?, *len))
        },
        TypeTemplate::List(element) => {
            Type::List(Arc::new(close_template_inner(element, resolve)?))
        },
        TypeTemplate::Function(ty) => {
            let mut params = SmallVec::<[Type; 4]>::new();
            for param in &ty.params {
                params.push(close_template_inner(param, resolve)?);
            }
            let mut results = SmallVec::<[Type; 1]>::new();
            for result in &ty.results {
                results.push(close_template_inner(result, resolve)?);
            }
            Type::from(FunctionType { abi: ty.abi.clone(), params, results })
        },
        TypeTemplate::Struct(ty) => {
            let mut fields = SmallVec::<[crate::NameAndType; 4]>::new();
            for field in &ty.fields {
                fields.push(crate::NameAndType {
                    name: field.name.clone(),
                    ty: close_template_inner(&field.ty, resolve)?,
                });
            }
            Type::from(StructType::from_parts(ty.name.clone(), ty.repr, fields))
        },
        TypeTemplate::Enum(ty) => {
            let mut variants = SmallVec::<[Variant; 4]>::new();
            for variant in &ty.variants {
                variants.push(Variant {
                    name: variant.name.clone(),
                    value: match variant.value.as_ref() {
                        Some(value) => Some(close_template_inner(value, resolve)?),
                        None => None,
                    },
                    discriminant_value: variant.discriminant_value,
                });
            }
            EnumType::new(ty.name.clone(), ty.discriminant.clone(), variants)
                .map(Type::from)
                .map_err(|err| {
                    RecursiveTypeError::InvalidDefinition(alloc::format!("{err}").into())
                })?
        },
    })
}

// OPENING: ZIPPING A TEMPLATE AGAINST ITS PROBE
// ================================================================================================

impl AggregateTemplate {
    /// Produce this definition's open body by walking the template and its probe in lockstep.
    ///
    /// The probe supplies layout metadata (sizes, offsets, alignments, discriminant offsets), and
    /// the template supplies the positions of the back-references. Subtrees that mention no group
    /// member are taken wholesale from the probe, where they are already correct.
    fn open(
        &self,
        probe: &Type,
        slot_of: &BTreeMap<Arc<str>, u16>,
        completed: &BTreeMap<Arc<str>, Type>,
    ) -> Result<OpenAggregate, RecursiveTypeError> {
        match (self, probe) {
            (Self::Struct(template), Type::Struct(probe)) => {
                Ok(OpenAggregate::Struct(open_struct(template, &probe.get(), slot_of, completed)?))
            },
            (Self::Enum(template), Type::Enum(probe)) => {
                let probe = probe.get();
                let mut variants = Vec::with_capacity(template.variants.len());
                for (variant, probe_variant) in template.variants.iter().zip(probe.variants()) {
                    variants.push(OpenVariant {
                        name: variant.name.clone(),
                        value: match (variant.value.as_ref(), probe_variant.value.as_ref()) {
                            (Some(value), Some(probe_value)) => {
                                Some(open_type(value, probe_value, slot_of, completed)?)
                            },
                            _ => None,
                        },
                        discriminant_value: probe_variant.discriminant_value,
                    });
                }
                Ok(OpenAggregate::Enum(OpenEnumType {
                    name: template.name.clone(),
                    discriminant: template.discriminant.clone(),
                    variants,
                    offsets: probe.offsets().to_vec(),
                    size: probe.size_in_bytes_raw(),
                    align: probe.align_raw(),
                }))
            },
            _ => Err(RecursiveTypeError::InvalidDefinition(
                "definition kind does not match its computed layout".into(),
            )),
        }
    }
}

fn open_struct(
    template: &StructTemplate,
    probe: &StructType,
    slot_of: &BTreeMap<Arc<str>, u16>,
    completed: &BTreeMap<Arc<str>, Type>,
) -> Result<OpenStructType, RecursiveTypeError> {
    let mut fields = Vec::with_capacity(template.fields.len());
    for (field, probe_field) in template.fields.iter().zip(probe.fields()) {
        fields.push(OpenStructField {
            name: probe_field.name.clone(),
            index: probe_field.index,
            align: probe_field.align,
            offset: probe_field.offset,
            ty: open_type(&field.ty, &probe_field.ty, slot_of, completed)?,
        });
    }
    Ok(OpenStructType {
        name: template.name.clone(),
        repr: template.repr,
        size: probe.size_raw(),
        fields,
    })
}

fn open_type(
    template: &TypeTemplate,
    probe: &Type,
    slot_of: &BTreeMap<Arc<str>, u16>,
    completed: &BTreeMap<Arc<str>, Type>,
) -> Result<OpenType, RecursiveTypeError> {
    if !mentions_group(template, slot_of) {
        // Nothing beneath this point refers to the group, so the probe already holds the exact
        // closed type. Sharing it costs an `Arc` clone rather than a rebuild.
        return Ok(OpenType::Closed(probe.clone()));
    }

    Ok(match (template, probe) {
        (TypeTemplate::Rec(name), _) => {
            OpenType::Var(*slot_of.get(name).expect("checked by mentions_group"))
        },
        (TypeTemplate::Ptr(addrspace, pointee), Type::Ptr(probe)) => OpenType::Ptr(
            *addrspace,
            Box::new(open_type(pointee, probe.pointee(), slot_of, completed)?),
        ),
        (TypeTemplate::Array(element, len), Type::Array(probe)) => OpenType::Array(
            Box::new(open_type(element, probe.element_type(), slot_of, completed)?),
            *len,
        ),
        (TypeTemplate::List(element), Type::List(probe)) => {
            OpenType::List(Box::new(open_type(element, probe, slot_of, completed)?))
        },
        (TypeTemplate::Function(template), Type::Function(probe)) => {
            let mut params = Vec::with_capacity(template.params.len());
            for (param, probe_param) in template.params.iter().zip(probe.params()) {
                params.push(open_type(param, probe_param, slot_of, completed)?);
            }
            let mut results = Vec::with_capacity(template.results.len());
            for (result, probe_result) in template.results.iter().zip(probe.results()) {
                results.push(open_type(result, probe_result, slot_of, completed)?);
            }
            OpenType::Function(Box::new(OpenFunctionType {
                abi: template.abi.clone(),
                params,
                results,
            }))
        },
        (TypeTemplate::Struct(template), Type::Struct(probe)) => {
            OpenType::Struct(Box::new(open_struct(template, &probe.get(), slot_of, completed)?))
        },
        (TypeTemplate::Enum(template), Type::Enum(probe)) => {
            let probe = probe.get();
            let mut variants = Vec::with_capacity(template.variants.len());
            for (variant, probe_variant) in template.variants.iter().zip(probe.variants()) {
                variants.push(OpenVariant {
                    name: variant.name.clone(),
                    value: match (variant.value.as_ref(), probe_variant.value.as_ref()) {
                        (Some(value), Some(probe_value)) => {
                            Some(open_type(value, probe_value, slot_of, completed)?)
                        },
                        _ => None,
                    },
                    discriminant_value: probe_variant.discriminant_value,
                });
            }
            OpenType::Enum(Box::new(OpenEnumType {
                name: template.name.clone(),
                discriminant: template.discriminant.clone(),
                variants,
                offsets: probe.offsets().to_vec(),
                size: probe.size_in_bytes_raw(),
                align: probe.align_raw(),
            }))
        },
        _ => {
            return Err(RecursiveTypeError::InvalidDefinition(
                "type template does not match its computed layout".into(),
            ));
        },
    })
}

/// Whether `template` refers to any member of the group being built.
///
/// A reference to a definition outside the group has already been completed, so it is closed.
fn mentions_group(template: &TypeTemplate, slot_of: &BTreeMap<Arc<str>, u16>) -> bool {
    match template {
        TypeTemplate::Type(_) => false,
        TypeTemplate::Rec(name) => slot_of.contains_key(name),
        TypeTemplate::Ptr(_, inner) | TypeTemplate::Array(inner, _) | TypeTemplate::List(inner) => {
            mentions_group(inner, slot_of)
        },
        TypeTemplate::Function(ty) => {
            ty.params.iter().chain(ty.results.iter()).any(|t| mentions_group(t, slot_of))
        },
        TypeTemplate::Struct(ty) => ty.fields.iter().any(|f| mentions_group(&f.ty, slot_of)),
        TypeTemplate::Enum(ty) => ty
            .variants
            .iter()
            .any(|v| v.value.as_ref().is_some_and(|t| mentions_group(t, slot_of))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_builder() -> RecursiveTypeBuilder {
        // struct Node { value: u32, next: *Node }
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Node",
            StructTemplate::named(
                "Node",
                TypeRepr::Default,
                [
                    ("value", TypeTemplate::from(Type::U32)),
                    ("next", TypeTemplate::ptr(TypeTemplate::rec("Node"))),
                ],
            ),
        );
        builder
    }

    fn build_one(mut builder: RecursiveTypeBuilder, name: &str) -> Type {
        builder
            .build()
            .expect("should build")
            .remove(name)
            .expect("definition should exist")
    }

    #[test]
    fn a_recursive_struct_lowers_the_same_as_an_equivalent_non_recursive_one() {
        // Lowering a recursive aggregate opaquely -- as a name-bearing leaf would have to,
        // having no way to reach the definition -- would give two callers of the same signature
        // different operand-stack layouts. Unfolding is available with no context here, so the
        // recursive form lowers identically to the shape it denotes.
        let node = build_one(node_builder(), "Node");

        let equivalent = Type::from(StructType::named(
            Arc::from("Node"),
            [
                (Arc::from("value"), Type::U32),
                (Arc::from("next"), Type::from(PointerType::new(Type::U32))),
            ],
        ));

        let recursive_parts = node.to_raw_parts().expect("should lower");
        let equivalent_parts = equivalent.to_raw_parts().expect("should lower");

        assert_eq!(recursive_parts.len(), equivalent_parts.len());
        assert_eq!(recursive_parts.len(), 2);
        assert_eq!(recursive_parts[0], Type::U32);
        // The second part is the pointer field in both cases; only its pointee differs.
        assert!(recursive_parts[1].is_pointer());
        assert!(equivalent_parts[1].is_pointer());
    }

    #[test]
    fn splitting_a_recursive_struct_terminates_and_preserves_field_structure() {
        let node = build_one(node_builder(), "Node");

        let (head, tail) = node.split(4);
        assert_eq!(head, Type::U32);
        let tail = tail.expect("the pointer field should remain");
        assert!(tail.is_pointer());
    }

    #[test]
    fn a_recursive_type_prints_without_unfolding_forever() {
        use alloc::string::ToString;

        let node = build_one(node_builder(), "Node");
        let printed = node.to_string();

        assert!(printed.contains("Node"), "expected the name in {printed:?}");
    }

    fn node_under_key(key: &str) -> Type {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            key,
            StructTemplate::named(
                "Node",
                TypeRepr::Default,
                [
                    ("value", TypeTemplate::from(Type::U32)),
                    ("next", TypeTemplate::ptr(TypeTemplate::rec(key))),
                ],
            ),
        );
        build_one(builder, key)
    }

    #[test]
    fn the_binding_key_does_not_affect_identity() {
        // The key binds back-references while a group is being built; it is not part of what the
        // type *is*. Two identical `Node` declarations in different modules are the same type,
        // exactly as they would be if they were not recursive.
        assert_eq!(node_under_key("left::Node"), node_under_key("right::Node"));
    }

    #[test]
    fn a_mutual_group_is_ordered_structurally_not_by_key() {
        // The same pair declared under differently-sorting keys must produce the same type. Here
        // the keys sort opposite to the declared names, so key-based ordering would place the
        // definitions in a different order and make the two groups compare unequal.
        fn build(a_key: &str, b_key: &str) -> Type {
            let mut builder = RecursiveTypeBuilder::new();
            builder
                .define_struct(
                    a_key,
                    StructTemplate::named(
                        "Apple",
                        TypeRepr::Default,
                        [("z", TypeTemplate::ptr(TypeTemplate::rec(b_key)))],
                    ),
                )
                .define_struct(
                    b_key,
                    StructTemplate::named(
                        "Zebra",
                        TypeRepr::Default,
                        [("a", TypeTemplate::ptr(TypeTemplate::rec(a_key)))],
                    ),
                );
            builder.build().expect("should build").remove(a_key).expect("Apple")
        }

        // "z::Apple" > "a::Zebra" by key, but "Apple" < "Zebra" by declared name.
        assert_eq!(build("z::Apple", "a::Zebra"), build("apple", "zebra"));
    }

    #[test]
    fn anonymous_definitions_order_independently_of_declaration_order() {
        // Three anonymous definitions with the same reference-blind shape tie on every component
        // of the ordering key, so a stable sort would leave them in declaration order and make
        // the same group compare unequal depending on how it was written.
        fn build(order: [usize; 3]) -> Type {
            let names = ["a", "b", "c"];
            let mut builder = RecursiveTypeBuilder::new();
            for slot in order {
                let next = names[(slot + 1) % 3];
                builder.define_struct(
                    names[slot],
                    // Anonymous, so the declared name cannot break the tie.
                    StructTemplate::new(
                        TypeRepr::Default,
                        [("next", TypeTemplate::ptr(TypeTemplate::rec(next)))],
                    ),
                );
            }
            builder.build().expect("should build").remove("a").expect("a")
        }

        assert_eq!(build([0, 1, 2]), build([2, 1, 0]));
        assert_eq!(build([0, 1, 2]), build([1, 2, 0]));
    }

    #[test]
    fn definitions_that_denote_the_same_type_are_merged() {
        // Three definitions in a cycle, none distinguishable from the others. They unfold to the
        // same type, so one definition remains and all three references are that type.
        let names = ["a", "b", "c"];
        let mut builder = RecursiveTypeBuilder::new();
        for slot in 0..3 {
            builder.define_struct(
                names[slot],
                StructTemplate::new(
                    TypeRepr::Default,
                    [("next", TypeTemplate::ptr(TypeTemplate::rec(names[(slot + 1) % 3])))],
                ),
            );
        }
        let built = builder.build().expect("should build");

        assert_eq!(built.get("a"), built.get("b"));
        assert_eq!(built.get("a"), built.get("c"));

        let Some(Type::Struct(a)) = built.get("a") else {
            panic!("expected a struct")
        };
        assert_eq!(a.as_recursive().expect("recursive").group_len(), 1);
    }

    #[test]
    fn definitions_sharing_a_name_across_modules_are_one_type() {
        // Two declarations of `A` in different modules, mutually referencing each other. Their
        // keys differ but nothing about the types does, and a non-recursive pair with the same
        // name and fields would already compare equal.
        fn build(order: [usize; 2]) -> BTreeMap<Arc<str>, Type> {
            let keys = ["lib::m1::A", "lib::m2::A"];
            let mut builder = RecursiveTypeBuilder::new();
            for slot in order {
                builder.define_struct(
                    keys[slot],
                    StructTemplate::named(
                        "A",
                        TypeRepr::Default,
                        [("b", TypeTemplate::ptr(TypeTemplate::rec(keys[(slot + 1) % 2])))],
                    ),
                );
            }
            builder.build().expect("should build")
        }

        let forward = build([0, 1]);
        let reversed = build([1, 0]);
        assert_eq!(forward.get("lib::m1::A"), forward.get("lib::m2::A"));
        assert_eq!(forward.get("lib::m1::A"), reversed.get("lib::m1::A"));
    }

    #[test]
    fn definitions_that_differ_are_kept_apart() {
        // Refinement must not over-merge. `p` and `q` are identical in name, kind, and shape, so
        // nothing separates them until what they refer to is taken into account: `p` reaches `m`
        // and `q` reaches `n`, which differ by name. One round of refinement tells them apart.
        let mut builder = RecursiveTypeBuilder::new();
        let mut define = |key: &str, name: &str, to: &str| {
            builder.define_struct(
                key,
                StructTemplate::named(
                    name,
                    TypeRepr::Default,
                    [("f", TypeTemplate::ptr(TypeTemplate::rec(to)))],
                ),
            );
        };
        // One cycle, so all four are a single group: p -> m -> q -> n -> p.
        define("p", "N", "m");
        define("m", "M", "q");
        define("q", "N", "n");
        define("n", "O", "p");
        let built = builder.build().expect("should build");

        assert_ne!(built.get("p"), built.get("q"));
        let Some(Type::Struct(p)) = built.get("p") else {
            panic!("expected a struct")
        };
        assert_eq!(p.as_recursive().expect("recursive").group_len(), 4);
    }

    #[test]
    fn definitions_differing_only_outside_the_group_are_kept_apart() {
        // `p` and `q` share a name and shape and refer to each other, so nothing inside the group
        // separates them. They carry different payloads, which are separate declarations and so
        // outside the group -- that difference still makes them different types.
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "X",
                StructTemplate::named(
                    "X",
                    TypeRepr::Default,
                    [("v", TypeTemplate::from(Type::U8))],
                ),
            )
            .define_struct(
                "Y",
                StructTemplate::named(
                    "Y",
                    TypeRepr::Default,
                    [("v", TypeTemplate::from(Type::U32))],
                ),
            )
            .define_struct(
                "p",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [
                        ("next", TypeTemplate::ptr(TypeTemplate::rec("q"))),
                        ("payload", TypeTemplate::rec("X")),
                    ],
                ),
            )
            .define_struct(
                "q",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [
                        ("next", TypeTemplate::ptr(TypeTemplate::rec("p"))),
                        ("payload", TypeTemplate::rec("Y")),
                    ],
                ),
            );
        let built = builder.build().expect("should build");

        assert_ne!(built.get("p"), built.get("q"));
    }

    #[test]
    fn definitions_differing_in_signature_shape_are_kept_apart() {
        // One takes its reference as a parameter, the other returns it. Same tags in the same
        // order, so a key that omits the list lengths cannot tell them apart.
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "a",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [("f", TypeTemplate::function(CallConv::Fast, [TypeTemplate::rec("b")], []))],
                ),
            )
            .define_struct(
                "b",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [("f", TypeTemplate::function(CallConv::Fast, [], [TypeTemplate::rec("a")]))],
                ),
            );
        let built = builder.build().expect("should build");

        assert_ne!(built.get("a"), built.get("b"));
    }

    #[test]
    fn definitions_naming_equal_external_types_still_merge() {
        // The two payload declarations are different names for the same type, so `p` and `q` are
        // the same type. A key that recorded which declaration was named would keep them apart.
        let mut builder = RecursiveTypeBuilder::new();
        for key in ["X", "Y"] {
            builder.define_struct(
                key,
                StructTemplate::named(
                    "Payload",
                    TypeRepr::Default,
                    [("v", TypeTemplate::from(Type::U8))],
                ),
            );
        }
        builder
            .define_struct(
                "p",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [
                        ("next", TypeTemplate::ptr(TypeTemplate::rec("q"))),
                        ("payload", TypeTemplate::rec("X")),
                    ],
                ),
            )
            .define_struct(
                "q",
                StructTemplate::named(
                    "N",
                    TypeRepr::Default,
                    [
                        ("next", TypeTemplate::ptr(TypeTemplate::rec("p"))),
                        ("payload", TypeTemplate::rec("Y")),
                    ],
                ),
            );
        let built = builder.build().expect("should build");

        assert_eq!(built.get("X"), built.get("Y"));
        assert_eq!(built.get("p"), built.get("q"));
    }

    #[test]
    fn type_size_is_pinned() {
        // `Type` is embedded in every field, variant, and parameter list, so its size is worth
        // guarding. It grew from 16 to 24 bytes when struct and enum payloads became
        // `StructRef`/`EnumRef`: a recursive reference is an `Arc` plus a definition index, so
        // the reference is 16 bytes, which leaves no niche for the outer discriminant.
        //
        // Getting back to 16 would mean a single `Arc<StructRepr>` with the plain/recursive
        // discriminant inside the allocation, which would force `From<Arc<StructType>>` to clone
        // rather than bump a refcount. That is a worse trade than 8 bytes per `Type`.
        use core::mem::size_of;

        assert_eq!(size_of::<Type>(), 24);
        assert_eq!(size_of::<crate::StructRef>(), 16);
        assert_eq!(size_of::<crate::EnumRef>(), 16);
    }

    #[test]
    fn a_recursive_pointee_equals_the_definition_it_points_at() {
        // This is the property that makes a recursive `Type` stand alone: descending through the
        // backedge yields the definition itself, with no resolver and no external context.
        let node = build_one(node_builder(), "Node");

        let Type::Struct(struct_ref) = &node else {
            panic!("expected a struct, got {node:?}");
        };
        let unfolded = struct_ref.get();
        let Type::Ptr(next) = &unfolded.fields()[1].ty else {
            panic!("expected the `next` field to be a pointer");
        };

        assert_eq!(next.pointee(), &node);
    }

    #[test]
    fn the_binding_key_is_distinct_from_the_display_name() {
        // A group's definitions are registered under a key that must be unique within the group,
        // which for a frontend means something like a module-qualified path. That key must not
        // become the aggregate's own name, because `StructType::name` takes part in structural
        // equality: routing an ordinary declaration through the builder would otherwise silently
        // rename it. The key binds references during construction and is then discarded.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "lib::list::Node",
            StructTemplate::named(
                "Node",
                TypeRepr::Default,
                [("next", TypeTemplate::ptr(TypeTemplate::rec("lib::list::Node")))],
            ),
        );
        let node = build_one(builder, "lib::list::Node");

        let Type::Struct(struct_ref) = &node else {
            panic!("expected a struct")
        };

        // The folded and unfolded forms must agree about what the type is called.
        assert_eq!(struct_ref.name().as_deref(), Some("Node"));
        assert_eq!(struct_ref.get().name().as_deref(), Some("Node"));

        let rec = struct_ref.as_recursive().expect("should be recursive");
        assert_eq!(rec.name().as_deref(), Some("Node"));
    }

    #[test]
    fn an_unnamed_aggregate_keeps_its_key_out_of_its_name() {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "lib::anon::Node",
            StructTemplate::new(
                TypeRepr::Default,
                [("next", TypeTemplate::ptr(TypeTemplate::rec("lib::anon::Node")))],
            ),
        );
        let node = build_one(builder, "lib::anon::Node");

        let Type::Struct(struct_ref) = &node else {
            panic!("expected a struct")
        };
        assert_eq!(struct_ref.name(), None);
        assert_eq!(struct_ref.get().name(), None);
    }

    #[test]
    fn unfolding_preserves_field_names_and_offsets() {
        let node = build_one(node_builder(), "Node");
        let Type::Struct(struct_ref) = &node else {
            panic!("expected a struct")
        };
        let unfolded = struct_ref.get();

        assert_eq!(unfolded.name().as_deref(), Some("Node"));
        assert_eq!(unfolded.fields()[0].name.as_deref(), Some("value"));
        assert_eq!(unfolded.fields()[0].offset, 0);
        assert_eq!(unfolded.fields()[1].name.as_deref(), Some("next"));
        assert_eq!(unfolded.fields()[1].offset, 4);
    }

    #[test]
    fn independently_built_recursive_types_are_equal_and_hash_equal() {
        use core::hash::{Hash, Hasher};

        let first = build_one(node_builder(), "Node");
        let second = build_one(node_builder(), "Node");

        assert_eq!(first, second);

        fn hash_of(ty: &Type) -> u64 {
            struct Fnv(u64);
            impl Hasher for Fnv {
                fn finish(&self) -> u64 {
                    self.0
                }

                fn write(&mut self, bytes: &[u8]) {
                    for byte in bytes {
                        self.0 ^= u64::from(*byte);
                        self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
                    }
                }
            }
            let mut hasher = Fnv(0xcbf2_9ce4_8422_2325);
            ty.hash(&mut hasher);
            hasher.finish()
        }

        assert_eq!(hash_of(&first), hash_of(&second));
    }

    #[test]
    fn recursion_through_a_list_barrier() {
        // struct Tree { children: list<Tree> }
        //
        // A list is a fat pointer, so its layout does not depend on its element type.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Tree",
            StructTemplate::named(
                "Tree",
                TypeRepr::Default,
                [("children", TypeTemplate::list(TypeTemplate::rec("Tree")))],
            ),
        );
        let tree = build_one(builder, "Tree");

        assert_eq!(tree.size_in_bytes(), 8);
        assert_eq!(tree.min_alignment(), 4);

        let Type::Struct(tree_ref) = &tree else {
            panic!("expected a struct")
        };
        let body = tree_ref.get();
        let Type::List(element) = &body.fields()[0].ty else {
            panic!("expected a list")
        };
        assert_eq!(element.as_ref(), &tree);
    }

    #[test]
    fn recursion_through_a_function_barrier() {
        // struct Callback { call: fn(Callback) }
        //
        // A function reference is a 4-byte handle regardless of its signature.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Callback",
            StructTemplate::named(
                "Callback",
                TypeRepr::Default,
                [(
                    "call",
                    TypeTemplate::function(CallConv::Fast, [TypeTemplate::rec("Callback")], []),
                )],
            ),
        );
        let callback = build_one(builder, "Callback");

        assert_eq!(callback.size_in_bytes(), 4);

        let Type::Struct(callback_ref) = &callback else {
            panic!("expected a struct")
        };
        let body = callback_ref.get();
        let Type::Function(signature) = &body.fields()[0].ty else {
            panic!("expected a function")
        };
        assert_eq!(&signature.params()[0], &callback);
    }

    #[test]
    fn recursion_nested_arbitrarily_deep_below_a_barrier() {
        // struct Node { next: *struct Option { some: Node, none: () } }
        //
        // This is the `Box<Option<T>>` shape: the back-reference is not the immediate pointee,
        // but sits inside an anonymous aggregate beneath it. A design requiring the reference to
        // be a barrier's direct operand could not express this.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "Node",
            StructTemplate::named(
                "Node",
                TypeRepr::Default,
                [(
                    "next",
                    TypeTemplate::ptr(TypeTemplate::struct_type(
                        TypeRepr::Default,
                        [
                            FieldTemplate::from(("some", TypeTemplate::rec("Node"))),
                            FieldTemplate::from(("none", TypeTemplate::from(Type::U8))),
                        ],
                    )),
                )],
            ),
        );
        let node = build_one(builder, "Node");

        assert_eq!(node.size_in_bytes(), 4);

        let Type::Struct(node_ref) = &node else {
            panic!("expected a struct")
        };
        let body = node_ref.get();
        let Type::Ptr(next) = &body.fields()[0].ty else {
            panic!("expected a pointer")
        };
        let Type::Struct(option_ref) = next.pointee() else {
            panic!("expected a struct")
        };
        let option = option_ref.get();
        assert_eq!(&option.fields()[0].ty, &node);
    }

    #[test]
    fn definitions_differing_only_in_name_or_body_are_unequal() {
        fn build(name: &str, field: Type) -> Type {
            let mut builder = RecursiveTypeBuilder::new();
            builder.define_struct(
                name,
                StructTemplate::named(
                    name,
                    TypeRepr::Default,
                    [
                        ("payload", TypeTemplate::from(field)),
                        ("next", TypeTemplate::ptr(TypeTemplate::rec(name))),
                    ],
                ),
            );
            build_one(builder, name)
        }

        let base = build("Node", Type::U32);
        assert_ne!(build("Other", Type::U32), base, "different name, same body");
        assert_ne!(build("Node", Type::I32), base, "same name, different body");
        assert_eq!(build("Node", Type::U32), base);
    }

    #[test]
    fn mutually_recursive_structs_through_pointers() {
        // struct A { b: *B }   struct B { a: *A }
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "A",
                StructTemplate::new(
                    TypeRepr::Default,
                    [("b", TypeTemplate::ptr(TypeTemplate::rec("B")))],
                ),
            )
            .define_struct(
                "B",
                StructTemplate::new(
                    TypeRepr::Default,
                    [("a", TypeTemplate::ptr(TypeTemplate::rec("A")))],
                ),
            );
        let built = builder.build().expect("mutual recursion should build");

        let a = built.get("A").expect("A").clone();
        let b = built.get("B").expect("B").clone();
        assert_eq!(a.size_in_bytes(), 4);
        assert_eq!(b.size_in_bytes(), 4);

        // Descending A -> b -> B -> a yields A again.
        let Type::Struct(a_ref) = &a else {
            panic!("expected struct")
        };
        let a_body = a_ref.get();
        let Type::Ptr(to_b) = &a_body.fields()[0].ty else {
            panic!("expected pointer")
        };
        assert_eq!(to_b.pointee(), &b);

        let Type::Struct(b_ref) = to_b.pointee() else {
            panic!("expected struct")
        };
        let b_body = b_ref.get();
        let Type::Ptr(to_a) = &b_body.fields()[0].ty else {
            panic!("expected pointer")
        };
        assert_eq!(to_a.pointee(), &a);
    }

    #[test]
    fn a_cycle_is_guarded_even_when_one_edge_is_not() {
        // struct A { b: B }    struct B { a: *A }
        //
        // The `A -> B` edge crosses no barrier, but the cycle as a whole does, so `A` is finite:
        // its size is `B`'s size, which is the size of a pointer. A rule requiring every
        // back-reference to sit below a barrier would wrongly reject this.
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "A",
                StructTemplate::new(TypeRepr::Default, [("b", TypeTemplate::rec("B"))]),
            )
            .define_struct(
                "B",
                StructTemplate::new(
                    TypeRepr::Default,
                    [("a", TypeTemplate::ptr(TypeTemplate::rec("A")))],
                ),
            );
        let built = builder.build().expect("guarded cycle should build");

        assert_eq!(built.get("A").unwrap().size_in_bytes(), 4);
        assert_eq!(built.get("B").unwrap().size_in_bytes(), 4);
    }

    #[test]
    fn definition_order_does_not_affect_the_result() {
        fn build(reversed: bool) -> BTreeMap<Arc<str>, Type> {
            let mut builder = RecursiveTypeBuilder::new();
            let define_a = |builder: &mut RecursiveTypeBuilder| {
                builder.define_struct(
                    "A",
                    StructTemplate::new(
                        TypeRepr::Default,
                        [("b", TypeTemplate::ptr(TypeTemplate::rec("B")))],
                    ),
                );
            };
            let define_b = |builder: &mut RecursiveTypeBuilder| {
                builder.define_struct(
                    "B",
                    StructTemplate::new(
                        TypeRepr::Default,
                        [("a", TypeTemplate::ptr(TypeTemplate::rec("A")))],
                    ),
                );
            };
            if reversed {
                define_b(&mut builder);
                define_a(&mut builder);
            } else {
                define_a(&mut builder);
                define_b(&mut builder);
            }
            builder.build().expect("should build")
        }

        let forward = build(false);
        let reversed = build(true);
        assert_eq!(forward.get("A"), reversed.get("A"));
        assert_eq!(forward.get("B"), reversed.get("B"));
    }

    #[test]
    fn direct_recursion_is_rejected() {
        // struct T { value: T } has infinite size.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "T",
            StructTemplate::new(TypeRepr::Default, [("value", TypeTemplate::rec("T"))]),
        );

        assert_eq!(builder.build(), Err(RecursiveTypeError::UnguardedRecursion("T".into())));
    }

    #[test]
    fn recursion_through_a_fixed_array_alone_is_rejected() {
        // An array is not a barrier: its layout depends on its element type.
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "T",
            StructTemplate::new(
                TypeRepr::Default,
                [("values", TypeTemplate::array(TypeTemplate::rec("T"), 1))],
            ),
        );

        assert_eq!(builder.build(), Err(RecursiveTypeError::UnguardedRecursion("T".into())));
    }

    #[test]
    fn a_wholly_unguarded_mutual_cycle_is_rejected() {
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "A",
                StructTemplate::new(TypeRepr::Default, [("b", TypeTemplate::rec("B"))]),
            )
            .define_struct(
                "B",
                StructTemplate::new(TypeRepr::Default, [("a", TypeTemplate::rec("A"))]),
            );

        assert!(matches!(builder.build(), Err(RecursiveTypeError::UnguardedRecursion(_))));
    }

    #[test]
    fn a_reference_to_an_undefined_type_is_rejected() {
        let mut builder = RecursiveTypeBuilder::new();
        builder.define_struct(
            "T",
            StructTemplate::new(
                TypeRepr::Default,
                [("other", TypeTemplate::ptr(TypeTemplate::rec("Missing")))],
            ),
        );

        assert_eq!(builder.build(), Err(RecursiveTypeError::UndefinedReference("Missing".into())));
    }

    #[test]
    fn duplicate_definition_names_are_rejected() {
        let mut builder = RecursiveTypeBuilder::new();
        builder
            .define_struct(
                "T",
                StructTemplate::new(TypeRepr::Default, [("a", TypeTemplate::from(Type::U8))]),
            )
            .define_struct(
                "T",
                StructTemplate::new(TypeRepr::Default, [("b", TypeTemplate::from(Type::U8))]),
            );

        assert_eq!(builder.build(), Err(RecursiveTypeError::DuplicateName("T".into())));
    }

    #[test]
    fn a_group_larger_than_the_cap_is_rejected() {
        let mut builder = RecursiveTypeBuilder::new();
        let count = MAX_RECURSIVE_GROUP_SIZE + 1;
        for i in 0..count {
            // Each definition points at the next, and the last wraps around, forming one SCC.
            let next = alloc::format!("T{:03}", (i + 1) % count);
            builder.define_struct(
                alloc::format!("T{i:03}"),
                StructTemplate::new(
                    TypeRepr::Default,
                    [("next", TypeTemplate::ptr(TypeTemplate::rec(next)))],
                ),
            );
        }

        assert!(matches!(
            builder.build(),
            Err(RecursiveTypeError::GroupTooLarge(_, n)) if n == count
        ));
    }

    #[test]
    fn a_group_at_the_cap_is_accepted() {
        let mut builder = RecursiveTypeBuilder::new();
        let count = MAX_RECURSIVE_GROUP_SIZE;
        for i in 0..count {
            let next = alloc::format!("T{:03}", (i + 1) % count);
            builder.define_struct(
                alloc::format!("T{i:03}"),
                StructTemplate::new(
                    TypeRepr::Default,
                    [("next", TypeTemplate::ptr(TypeTemplate::rec(next)))],
                ),
            );
        }

        let built = builder.build().expect("a group at the cap should build");
        assert_eq!(built.len(), count);
        assert_eq!(built.get("T000").unwrap().size_in_bytes(), 4);
    }
}
