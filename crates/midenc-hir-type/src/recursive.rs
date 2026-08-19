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

    /// The name of the definition this reference selects.
    #[inline]
    pub fn name(&self) -> &Arc<str> {
        &self.def().name
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
#[derive(Debug)]
pub struct RecGroup {
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
struct RecDef {
    /// Ordering key within the group, and the display name.
    name: Arc<str>,
    kind: AggregateKind,
    body: OpenAggregate,
    layout: TypeLayout,
}

fn hash_defs(defs: &[RecDef]) -> u64 {
    // A small, dependency-free FNV-1a hasher. The cached value only needs to be a stable
    // function of the definitions; it never leaves the crate.
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
    defs.hash(&mut hasher);
    hasher.finish()
}

// OPEN TYPES
// ================================================================================================

/// A definition body which may contain back-references.
#[derive(Debug, PartialEq, Eq, Hash)]
enum OpenAggregate {
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
enum OpenType {
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
struct OpenStructType {
    name: Option<Arc<str>>,
    repr: TypeRepr,
    size: u32,
    fields: Vec<OpenStructField>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct OpenStructField {
    name: Option<Arc<str>>,
    index: u8,
    align: u16,
    offset: u32,
    ty: OpenType,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct OpenEnumType {
    name: Arc<str>,
    discriminant: Type,
    variants: Vec<OpenVariant>,
    offsets: Vec<u32>,
    size: u32,
    align: u32,
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct OpenVariant {
    name: Arc<str>,
    value: Option<OpenType>,
    discriminant_value: Option<u128>,
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
struct OpenFunctionType {
    abi: CallConv,
    params: Vec<OpenType>,
    results: Vec<OpenType>,
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
    pub fn new(repr: TypeRepr, fields: impl IntoIterator<Item = impl Into<FieldTemplate>>) -> Self {
        Self {
            name: None,
            repr,
            fields: fields.into_iter().map(Into::into).collect(),
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

    /// Define a struct named `name`.
    pub fn define_struct(
        &mut self,
        name: impl Into<Arc<str>>,
        mut template: StructTemplate,
    ) -> &mut Self {
        let name = name.into();
        template.name = Some(name.clone());
        self.defs.push(TemplateDef {
            name,
            kind: AggregateKind::Struct,
            body: AggregateTemplate::Struct(template),
        });
        self
    }

    /// Define an enum named `name`.
    pub fn define_enum(&mut self, name: impl Into<Arc<str>>, template: EnumTemplate) -> &mut Self {
        let name = name.into();
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
    mut component: Vec<usize>,
    completed: &mut BTreeMap<Arc<str>, Type>,
) -> Result<(), RecursiveTypeError> {
    // Canonical order: sort by name. Names are distinct, which was checked up front, so this is a
    // total order and a function of the group's structure alone.
    component.sort_by(|a, b| defs[*a].name.cmp(&defs[*b].name));

    let is_recursive = component.len() > 1
        || defs[component[0]].body.references().contains(&defs[component[0]].name);

    if !is_recursive {
        // An ordinary, non-recursive definition. Materialize it directly.
        let def = &defs[component[0]];
        let ty = def.body.close_with(&|name| completed.get(&name).cloned())?;
        completed.insert(def.name.clone(), ty);
        return Ok(());
    }

    if component.len() > MAX_RECURSIVE_GROUP_SIZE {
        return Err(RecursiveTypeError::GroupTooLarge(
            defs[component[0]].name.clone(),
            component.len(),
        ));
    }

    let slot_of = component
        .iter()
        .enumerate()
        .map(|(slot, member)| (defs[*member].name.clone(), slot as u16))
        .collect::<BTreeMap<_, _>>();

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
            name: def.name.clone(),
            kind: def.kind,
            body,
            layout: layouts[slot].expect("layout computed above"),
        });
    }

    let group = Arc::new(RecGroup::new(rec_defs.into_boxed_slice()));
    for slot in 0..component.len() {
        let name = group.defs[slot].name.clone();
        completed.insert(name, rec_type(group.clone(), slot as u16));
    }

    Ok(())
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

impl AggregateTemplate {
    /// Materialize this template as a closed [Type], resolving every reference through `resolve`.
    fn close_with(&self, resolve: &Resolve<'_>) -> Result<Type, RecursiveTypeError> {
        match self {
            Self::Struct(ty) => {
                let mut fields = SmallVec::<[crate::NameAndType; 4]>::new();
                for field in &ty.fields {
                    fields.push(crate::NameAndType {
                        name: field.name.clone(),
                        ty: close_template(&field.ty, resolve)?,
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
                            Some(value) => Some(close_template(value, resolve)?),
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

fn close_template(
    template: &TypeTemplate,
    resolve: &Resolve<'_>,
) -> Result<Type, RecursiveTypeError> {
    Ok(match template {
        TypeTemplate::Type(ty) => ty.clone(),
        TypeTemplate::Rec(name) => resolve(name.clone())
            .ok_or_else(|| RecursiveTypeError::UndefinedReference(name.clone()))?,
        TypeTemplate::Ptr(addrspace, pointee) => Type::Ptr(Arc::new(PointerType {
            addrspace: *addrspace,
            pointee: close_template(pointee, resolve)?,
        })),
        TypeTemplate::Array(element, len) => {
            Type::from(ArrayType::new(close_template(element, resolve)?, *len))
        },
        TypeTemplate::List(element) => Type::List(Arc::new(close_template(element, resolve)?)),
        TypeTemplate::Function(ty) => {
            let mut params = SmallVec::<[Type; 4]>::new();
            for param in &ty.params {
                params.push(close_template(param, resolve)?);
            }
            let mut results = SmallVec::<[Type; 1]>::new();
            for result in &ty.results {
                results.push(close_template(result, resolve)?);
            }
            Type::from(FunctionType { abi: ty.abi.clone(), params, results })
        },
        TypeTemplate::Struct(ty) => {
            let mut fields = SmallVec::<[crate::NameAndType; 4]>::new();
            for field in &ty.fields {
                fields.push(crate::NameAndType {
                    name: field.name.clone(),
                    ty: close_template(&field.ty, resolve)?,
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
                        Some(value) => Some(close_template(value, resolve)?),
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
            StructTemplate::new(
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

        let equivalent = Type::from(StructType::named(Arc::from("Node"), [
            (Arc::from("value"), Type::U32),
            (Arc::from("next"), Type::from(PointerType::new(Type::U32))),
        ]));

        let recursive_parts = node.clone().to_raw_parts().expect("should lower");
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
