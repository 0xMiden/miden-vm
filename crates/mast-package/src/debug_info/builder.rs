use alloc::{boxed::Box, sync::Arc};

use miden_assembly_syntax::Report;
use miden_core::mast::MastNodeId;
use miden_debug_types::{Location, Uri};
use miden_utils_indexing::{Idx, IndexedVecError};

type FxHashMap<K, V> = hashbrown::HashMap<K, V, rustc_hash::FxBuildHasher>;

use super::{
    DebugErrorMessage, DebugInfo, DebugLoc, DebugLocIdx, DebugSourceNodeId, FunctionInfo,
    SourceNode, SourceNodeIdMarker,
    types::{
        DebugFileIdx, DebugFileInfo, DebugFunctionIdx, DebugStringIdx, DebugTypeIdx, DebugTypeInfo,
    },
};
use crate::debug_info::{DebugFieldInfo, DebugPrimitiveType, DebugVariantInfo};

// PACKAGE DEBUG INFO BUILDER
// ================================================================================================

/// This type is used to construct/modify [super::PackageDebugInfo] appended to a Miden package.
///
/// It is a type alias for [`DebugInfoBuilder<MastNodeId, DebugSourceNodeId>`] - see its
/// documentation for more details.
pub type PackageDebugInfoBuilder = DebugInfoBuilder<MastNodeId, DebugSourceNodeId>;

/// This type is used to construct/modify [DebugInfo] during assembly/packaging.
///
/// This type is generic over the index type used for representing execution nodes (unique
/// references into a [`miden_core::mast::MastForest`]) and source occurrances (a unique set of
/// debug information attached to an execution node). This allows us to use the same data structure
/// for representing/constructing debug information during assembly (before execution/source node
/// indices are finalized) and packaging (once execution/source nodes are finalized).
///
/// The [`DebugInfo`] type is heavily reliant on struct-of-arrays layout, with references between
/// different data types using typed indices rather than pointers or owned references. This requires
/// care to construct and maintain correctly, so it provides a largely immutable interface, with
/// responsibility for safely constructing/maintaining it handled by [DebugInfoBuilder].
pub struct DebugInfoBuilder<Exec: Idx, Src: Idx> {
    /// Provides uniquing of values stored in the strings table of the underlying `DebugInfo`
    string_indices: FxHashMap<Arc<str>, DebugStringIdx>,
    /// Provides uniquing of locations stored in the locations table of the underlying `DebugInfo`
    location_indices: FxHashMap<DebugLoc, DebugLocIdx>,
    /// Provides uniquing of locations stored in the locations table of the underlying `DebugInfo`
    type_indices: FxHashMap<DebugTypeInfo, DebugTypeIdx>,
    /// The debug info being built
    debug_info: Box<DebugInfo<Exec, Src>>,
}

// FUNDAMENTAL TRAITS
// ================================================================================================

impl<Exec: Idx, Src: Idx> core::fmt::Debug for DebugInfoBuilder<Exec, Src> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DebugInfoBuilder")
            .field("string_indices", &self.string_indices)
            .field("debug_info", &self.debug_info)
            .finish()
    }
}

impl<Exec: Idx, Src: Idx> Default for DebugInfoBuilder<Exec, Src> {
    fn default() -> Self {
        Self {
            string_indices: Default::default(),
            location_indices: Default::default(),
            type_indices: Default::default(),
            debug_info: Default::default(),
        }
    }
}

impl<Exec: Idx + Clone, Src: Idx + Clone> Clone for DebugInfoBuilder<Exec, Src> {
    fn clone(&self) -> Self {
        Self {
            string_indices: self.string_indices.clone(),
            location_indices: self.location_indices.clone(),
            type_indices: self.type_indices.clone(),
            debug_info: self.debug_info.clone(),
        }
    }
}

// TYPED INDEXING
// ================================================================================================

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugStringIdx> for DebugInfoBuilder<Exec, Src> {
    type Output = Arc<str>;

    fn index(&self, index: DebugStringIdx) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugFileIdx> for DebugInfoBuilder<Exec, Src> {
    type Output = DebugFileInfo;

    fn index(&self, index: DebugFileIdx) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugFunctionIdx> for DebugInfoBuilder<Exec, Src> {
    type Output = FunctionInfo<Src>;

    fn index(&self, index: DebugFunctionIdx) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugLocIdx> for DebugInfoBuilder<Exec, Src> {
    type Output = DebugLoc;

    fn index(&self, index: DebugLocIdx) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: Idx> core::ops::Index<DebugTypeIdx> for DebugInfoBuilder<Exec, Src> {
    type Output = DebugTypeInfo;

    fn index(&self, index: DebugTypeIdx) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: SourceNodeIdMarker> core::ops::Index<Src> for DebugInfoBuilder<Exec, Src> {
    type Output = SourceNode<Exec, Src>;

    fn index(&self, index: Src) -> &Self::Output {
        &self.debug_info[index]
    }
}

impl<Exec: Idx, Src: SourceNodeIdMarker> core::ops::IndexMut<Src> for DebugInfoBuilder<Exec, Src> {
    fn index_mut(&mut self, index: Src) -> &mut Self::Output {
        &mut self.debug_info.nodes[index]
    }
}

// CONSTRUCTION
// ================================================================================================

impl<Exec: Idx, Src: Idx> From<Box<DebugInfo<Exec, Src>>> for DebugInfoBuilder<Exec, Src> {
    fn from(debug_info: Box<DebugInfo<Exec, Src>>) -> Self {
        use hashbrown::hash_map::Entry;

        let mut string_indices = FxHashMap::default();
        for (i, string) in debug_info.strings().iter().enumerate() {
            if let Entry::Vacant(entry) = string_indices.entry(string.clone()) {
                let idx = DebugStringIdx::from(i as u32);
                entry.insert(idx);
            }
        }
        let mut location_indices = FxHashMap::default();
        for (i, loc) in debug_info.locations().iter().enumerate() {
            if let Entry::Vacant(entry) = location_indices.entry(*loc) {
                let idx = DebugLocIdx::from(i as u32);
                entry.insert(idx);
            }
        }
        let mut type_indices = FxHashMap::default();
        for (i, ty) in debug_info.types().iter().enumerate() {
            if let Entry::Vacant(entry) = type_indices.entry(ty.clone()) {
                let idx = DebugTypeIdx::from(i as u32);
                entry.insert(idx);
            }
        }
        Self {
            string_indices,
            location_indices,
            type_indices,
            debug_info,
        }
    }
}

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Finalize construction of the underlying `DebugInfo` and return it
    ///
    /// NOTE: `DebugInfo` is a very large type, so it is heap-allocated and returned via `Box`
    #[inline]
    pub fn build(self) -> Box<DebugInfo<Exec, Src>> {
        self.debug_info
    }
}

// ACCESSORS
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Get a reference to the current state of the `DebugInfo` being built
    pub fn debug_info(&self) -> &DebugInfo<Exec, Src> {
        &self.debug_info
    }

    /// Get a mutable reference to the current state of the `DebugInfo` being built
    pub fn debug_info_mut(&mut self) -> &mut DebugInfo<Exec, Src> {
        &mut self.debug_info
    }
}

// STRINGS
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Gets a string by index.
    pub fn get_string(&self, idx: DebugStringIdx) -> Option<Arc<str>> {
        self.debug_info.strings.get(idx).cloned()
    }

    /// Gets the [DebugStringIdx] for a string, if it is already interned by the builder
    pub fn get_string_index(&self, s: &str) -> Option<DebugStringIdx> {
        self.string_indices.get(s).copied()
    }

    /// Adds a string to the string table and returns its index.
    ///
    /// Strings are uniqued/interned - so adding the same string twice will return the same index
    pub fn add_string(&mut self, s: impl Into<Arc<str>>) -> DebugStringIdx {
        let s = s.into();
        if let Some(exists) = self.string_indices.get(&s).copied() {
            return exists;
        }
        let idx = self.debug_info.strings.push(s.clone()).expect("too many strings");
        self.string_indices.insert(s, idx);
        idx
    }
}

// SOURCE FILES
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Gets the [DebugFileIdx] for a source file whose URI is `uri`, if it is recorded in the
    /// debug info built so far.
    pub fn get_file_index_by_uri(&self, uri: &Uri) -> Option<DebugFileIdx> {
        self.debug_info.get_file_index_by_uri(uri)
    }

    pub fn get_file_index_by_path_index(&self, path_idx: DebugStringIdx) -> Option<DebugFileIdx> {
        self.debug_info
            .files
            .iter()
            .position(|file| file.path_idx == path_idx)
            .map(|pos| DebugFileIdx::from(pos as u32))
    }

    /// Adds a file to the file table under `uri`, with an optional checksum, and returns its index.
    ///
    /// If the same `uri` and `checksum` pair is already recorded, then the previously recorded
    /// index is returned
    pub fn add_file(&mut self, uri: Uri, checksum: Option<[u8; 32]>) -> DebugFileIdx {
        let path_idx = self.add_string(uri);
        self.add_file_info(
            DebugFileInfo::new(path_idx)
                .with_checksum(checksum.unwrap_or(DebugFileInfo::EMPTY_CHECKSUM)),
        )
    }

    /// Adds a file to the file table and returns its index.
    pub fn add_file_info(&mut self, file: DebugFileInfo) -> DebugFileIdx {
        assert!(
            self.debug_info.strings.get(file.path_idx).is_some(),
            "invalid path string index"
        );
        if let Some(idx) = self.debug_info.files.iter().position(|existing| existing == &file) {
            return DebugFileIdx::from(idx as u32);
        }
        self.debug_info.files.push(file).expect("too many files")
    }
}

// LOCATIONS
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Adds `loc` to the set of unique source locations maintained by the builder
    pub fn add_location(&mut self, loc: Location) -> DebugLocIdx {
        let path_idx = self.add_string(loc.uri().clone());
        let file_idx = self
            .get_file_index_by_path_index(path_idx)
            .unwrap_or_else(|| self.add_file_info(DebugFileInfo::new(path_idx)));
        self.add_location_info(DebugLoc { file_idx, start: loc.start, end: loc.end })
    }

    /// Adds a source location whose file is already registered with this builder.
    ///
    /// This form preserves the exact file-table relationship when importing debug information
    /// that may contain multiple records for the same path with different checksums.
    pub fn add_location_info(&mut self, loc: DebugLoc) -> DebugLocIdx {
        use hashbrown::hash_map::Entry;

        assert!(self.debug_info.files.get(loc.file_idx).is_some(), "invalid source file index");

        match self.location_indices.entry(loc) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = self.debug_info.locations.push(loc).expect("too many locations");
                entry.insert(index);
                index
            },
        }
    }
}

// TYPE INFO
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Adds `ty` to the set of unique types maintained by the builder, and returns its index
    pub fn add_type(&mut self, ty: DebugTypeInfo) -> DebugTypeIdx {
        use hashbrown::hash_map::Entry;
        match self.type_indices.entry(ty.clone()) {
            Entry::Occupied(entry) => *entry.get(),
            Entry::Vacant(entry) => {
                let index = self.debug_info.types.push(ty).expect("too many types");
                entry.insert(index);
                index
            },
        }
    }
}

// FUNCTION INFO
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Adds a function to the function table.
    pub fn add_function(&mut self, func: FunctionInfo<Src>) -> DebugFunctionIdx {
        self.debug_info.functions.push(func).expect("too many functions")
    }
}

// ERROR MESSAGES
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Add an error message record keyed by `err_code`.
    ///
    /// Returns `true` if `err_code` was not previously registered, otherwise `false`
    pub fn add_error_message(&mut self, err_code: u64, message: Arc<str>) -> bool {
        if !self.debug_info.error_messages.iter().any(|msg| msg.err_code == err_code) {
            let message = self.add_string(message);
            self.debug_info.error_messages.push(DebugErrorMessage { err_code, message });
            true
        } else {
            false
        }
    }

    /// Add an error message like `add_error_message`, but use a [DebugStringIdx] for the
    /// error message string.
    ///
    /// This function asserts that `message` exists in the debug info strings table, and will panic
    /// if it doesn't
    pub fn add_error_message_with_index(&mut self, err_code: u64, message: DebugStringIdx) {
        assert!(
            self.debug_info.get_string(message).is_some(),
            "invalid string index for message"
        );
        if !self.debug_info.error_messages.iter().any(|msg| msg.err_code == err_code) {
            self.debug_info.error_messages.push(DebugErrorMessage { err_code, message });
        }
    }
}

// SOURCE NODES
// ================================================================================================

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// Add `node` to the set of sources nodes in the debug info source graph
    pub fn add_node(&mut self, node: SourceNode<Exec, Src>) -> Result<Src, IndexedVecError> {
        assert!(node.op_end >= node.op_start);
        assert!(node.children.iter().copied().all(|n| self.debug_info.source_node(n).is_some()));
        self.debug_info.nodes.push(node)
    }

    /// Get a reference to the set of source node indices which correspond to procedure roots
    pub fn roots(&self) -> &[Src] {
        self.debug_info.roots()
    }

    /// Mark `node` as a procedure root
    pub fn add_root(&mut self, node: Src) {
        assert!(self.debug_info.source_node(node).is_some());
        if !self.debug_info.roots.contains(&node) {
            self.debug_info.roots.push(node);
        }
    }
}

impl<Exec: Idx, Src: Idx> DebugInfoBuilder<Exec, Src> {
    /// This visits a type exported or used in a procedure signature, and emits records to the
    /// provided debug types section corresponding to it.
    ///
    /// The declared name and type expression can be optionally provided to give additional useful
    /// context to the debug info type produced, e.g. type name, field names, etc.
    pub fn register_debug_type(
        &mut self,
        declared_name: Option<DebugStringIdx>,
        declared_ty: Option<&miden_assembly_syntax::ast::TypeExpr>,
        ty: &miden_assembly_syntax::ast::types::Type,
    ) -> Result<DebugTypeIdx, Report> {
        use miden_assembly_syntax::ast::{
            TypeExpr,
            types::{StructType, Type},
        };
        Ok(match ty {
            Type::I1 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Bool)),
            Type::I8 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I8)),
            Type::U8 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U8)),
            Type::I16 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I16)),
            Type::U16 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U16)),
            Type::I32 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I32)),
            Type::U32 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32)),
            Type::I64 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I64)),
            Type::U64 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U64)),
            Type::I128 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::I128)),
            Type::U128 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U128)),
            Type::Felt => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt)),
            Type::F64 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::F64)),
            Type::U256 => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U256)),
            Type::Unknown => self.add_type(DebugTypeInfo::Unknown),
            Type::Never => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void)),
            Type::Ptr(ptr) => {
                let pointee_name = declared_ty.and_then(|t| match t {
                    TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                        TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                        _ => None,
                    },
                    _ => None,
                });
                let pointee_name = pointee_name.map(|name| self.add_string(name));
                let pointee_decl = declared_ty.and_then(|t| match t {
                    TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                    _ => None,
                });
                let pointee_type_idx =
                    self.register_debug_type(pointee_name, pointee_decl, ptr.pointee())?;
                self.add_type(DebugTypeInfo::Pointer { pointee_type_idx })
            },
            Type::Array(array) => {
                let element_name = declared_ty.and_then(|t| match t {
                    TypeExpr::Array(array) => match array.elem.as_ref() {
                        TypeExpr::Ref(t) => Some(Arc::from(t.inner().as_str())),
                        _ => None,
                    },
                    _ => None,
                });
                let element_name = element_name.map(|name| self.add_string(name));
                let element_decl = declared_ty.and_then(|t| match t {
                    TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                    _ => None,
                });
                let element_type_idx =
                    self.register_debug_type(element_name, element_decl, array.element_type())?;
                let count = u32::try_from(array.len())
                    .map_err(|_| Report::msg("array type is too large"))?;
                self.add_type(DebugTypeInfo::Array { element_type_idx, count: Some(count) })
            },
            Type::List(ty) => {
                let pointee_name = declared_ty.and_then(|t| match t {
                    TypeExpr::Ptr(p) => match p.pointee.as_ref() {
                        TypeExpr::Ref(p) => Some(Arc::from(p.inner().as_str())),
                        _ => None,
                    },
                    _ => None,
                });
                let pointee_name = pointee_name.map(|name| self.add_string(name));
                let pointee_decl = declared_ty.and_then(|t| match t {
                    TypeExpr::Ptr(p) => Some(p.pointee.as_ref()),
                    _ => None,
                });
                let pointee_ty = self.register_debug_type(pointee_name, pointee_decl, ty)?;
                let usize_ty = self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
                let pointer_ty =
                    self.add_type(DebugTypeInfo::Pointer { pointee_type_idx: pointee_ty });
                let name_idx =
                    declared_name.unwrap_or_else(|| self.add_string(format!("list<{ty}>")));
                let ptr = DebugFieldInfo {
                    name_idx: self.add_string("ptr"),
                    type_idx: pointer_ty,
                    offset: 0,
                };
                let len = DebugFieldInfo {
                    name_idx: self.add_string("len"),
                    type_idx: usize_ty,
                    offset: 4,
                };
                self.add_type(DebugTypeInfo::Struct {
                    name_idx,
                    size: 8,
                    fields: vec![ptr, len],
                })
            },
            Type::Struct(struct_ty) => {
                let declared_field_tys = declared_ty.and_then(|t| match t {
                    TypeExpr::Struct(t) => Some(&t.fields),
                    _ => None,
                });
                let mut fields = vec![];
                for (i, field) in struct_ty.fields().iter().enumerate() {
                    let decl = declared_field_tys.and_then(|fields| fields.get(i));
                    let field_name = decl
                        .map(|decl| decl.name.clone().into_inner())
                        .or_else(|| field.name.clone());
                    let declared_ty = decl.map(|decl| &decl.ty);
                    let field_type_name = declared_type_name(declared_ty);
                    let field_type_name = field_type_name.map(|name| self.add_string(name));
                    let type_idx =
                        self.register_debug_type(field_type_name, declared_ty, &field.ty)?;
                    let name_idx =
                        self.add_string(field_name.unwrap_or_else(|| format!("{i}").into()));
                    fields.push(DebugFieldInfo { name_idx, type_idx, offset: field.offset });
                }
                let struct_name =
                    declared_name.or_else(|| struct_ty.name().map(|name| self.add_string(name)));
                let name_idx = struct_name.unwrap_or_else(|| self.add_string("<anon>"));
                let size = u32::try_from(struct_ty.size()).map_err(|_| {
                    if let Some(declared_name) = struct_name.as_ref() {
                        Report::msg(format!(
                            "invalid struct type '{}': struct is too large",
                            self.get_string(*declared_name).unwrap()
                        ))
                    } else {
                        Report::msg("invalid struct type: struct is too large")
                    }
                })?;
                self.add_type(DebugTypeInfo::Struct { name_idx, size, fields })
            },
            Type::Enum(enum_ty) => {
                let discrim_ty = self.register_debug_type(None, None, enum_ty.discriminant())?;
                let name_idx = self.add_string(enum_ty.name().clone());
                let size = u32::try_from(enum_ty.size_in_bytes()).map_err(|_| {
                    Report::msg(format!(
                        "invalid enum type '{}': enum is too large",
                        enum_ty.name()
                    ))
                })?;
                let variants = enum_ty
                    .variant_offsets()
                    .zip(enum_ty.discriminant_values())
                    .map(|((payload_offset, variant), discriminant)| {
                        let name_idx = self.add_string(variant.name.clone());
                        let type_idx = variant
                            .value
                            .as_ref()
                            .map(|ty| self.register_debug_type(None, None, ty))
                            .transpose()?;
                        let payload_offset = variant.value.as_ref().map(|_| payload_offset);
                        Ok(DebugVariantInfo {
                            name_idx,
                            type_idx,
                            payload_offset,
                            discriminant,
                        })
                    })
                    .collect::<Result<_, Report>>()?;
                self.add_type(DebugTypeInfo::Enum {
                    name_idx,
                    size,
                    discriminant_type_idx: discrim_ty,
                    variants,
                })
            },
            Type::Function(fty) => {
                let return_type_index = match fty.results() {
                    [] => self.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void)),
                    [ty] => self.register_debug_type(None, None, ty)?,
                    types => {
                        let ty = StructType::new(types.iter().cloned());
                        let size = u32::try_from(ty.size()).map_err(|_| {
                        if let Some(declared_name) = declared_name.as_ref() {
                            Report::msg(format!(
                                "invalid signature for '{declared_name}': return type is too big"
                            ))
                        } else {
                            Report::msg("invalid signature: return type is too big")
                        }
                    })?;
                        let mut fields = vec![];
                        for (i, field) in ty.fields().iter().enumerate() {
                            let name_idx = self.add_string(format!("{i}"));
                            let type_idx = self.register_debug_type(None, None, &field.ty)?;
                            fields.push(DebugFieldInfo {
                                name_idx,
                                type_idx,
                                offset: field.offset,
                            });
                        }
                        let name_idx = self.add_string("<anon>");
                        self.add_type(DebugTypeInfo::Struct { name_idx, size, fields })
                    },
                };
                let mut param_type_indices = vec![];
                for param in fty.params() {
                    param_type_indices.push(self.register_debug_type(None, None, param)?);
                }
                self.add_type(DebugTypeInfo::Function {
                    return_type_idx: Some(return_type_index),
                    param_type_indices,
                })
            },
        })
    }
}

fn declared_type_name(
    declared_ty: Option<&miden_assembly_syntax::ast::TypeExpr>,
) -> Option<Arc<str>> {
    use miden_assembly_syntax::ast::TypeExpr;
    match declared_ty? {
        TypeExpr::Ref(path) => Some(Arc::from(path.inner().as_str())),
        TypeExpr::Struct(ty) => ty.name.as_ref().map(|name| name.clone().into_inner()),
        TypeExpr::Primitive(_) | TypeExpr::Ptr(_) | TypeExpr::Array(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use miden_assembly_syntax::ast::types::{
        CallConv, EnumType, FunctionType, StructType, Type, Variant,
    };
    use miden_utils_indexing::Idx;

    use super::*;

    #[test]
    fn registers_c_like_enum_debug_type() {
        let mut builder = PackageDebugInfoBuilder::default();
        let enum_ty = EnumType::new(
            Arc::from("Status"),
            Type::U16,
            [
                Variant::c_like(Arc::from("Ok"), Some(200)),
                Variant::c_like(Arc::from("NotFound"), Some(404)),
            ],
        )
        .unwrap();
        let ty = Type::Enum(Arc::new(enum_ty));

        let type_idx = builder.register_debug_type(None, None, &ty).unwrap();

        let DebugTypeInfo::Enum {
            name_idx,
            size,
            discriminant_type_idx,
            variants,
        } = &builder[type_idx]
        else {
            panic!("expected enum debug type");
        };
        assert_eq!(builder.get_string(*name_idx).as_deref(), Some("Status"));
        assert_eq!(*size, 2);
        assert_eq!(
            &builder[*discriminant_type_idx],
            &DebugTypeInfo::Primitive(DebugPrimitiveType::U16)
        );
        assert_eq!(variants.len(), 2);
        assert_eq!(builder.get_string(variants[0].name_idx).as_deref(), Some("Ok"));
        assert_eq!(variants[0].type_idx, None);
        assert_eq!(variants[0].payload_offset, None);
        assert_eq!(variants[0].discriminant, 200);
        assert_eq!(builder.get_string(variants[1].name_idx).as_deref(), Some("NotFound"));
        assert_eq!(variants[1].type_idx, None);
        assert_eq!(variants[1].payload_offset, None);
        assert_eq!(variants[1].discriminant, 404);
    }

    #[test]
    fn registers_payload_enum_debug_type() {
        let mut builder = PackageDebugInfoBuilder::default();
        let enum_ty = EnumType::new(
            Arc::from("OptionU32"),
            Type::U8,
            [
                Variant::c_like(Arc::from("None"), Some(0)),
                Variant::new(Arc::from("Some"), Type::U32, Some(1)),
            ],
        )
        .unwrap();
        let ty = Type::Enum(Arc::new(enum_ty));

        let type_idx = builder.register_debug_type(None, None, &ty).unwrap();

        let DebugTypeInfo::Enum { variants, .. } = &builder[type_idx] else {
            panic!("expected enum debug type");
        };
        assert_eq!(variants.len(), 2);
        assert_eq!(variants[0].type_idx, None);
        let payload_type_idx = variants[1].type_idx.expect("Some variant should have payload");
        assert_eq!(&builder[payload_type_idx], &DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
        assert_eq!(variants[1].payload_offset, Some(4));
        assert_eq!(variants[1].discriminant, 1);
    }

    #[test]
    fn function_debug_types_preserve_resolved_struct_metadata() {
        let felt_wrapper = Type::Struct(Arc::new(StructType::named(
            "felt-wrapper".into(),
            [(Arc::from("inner"), Type::Felt)],
        )));
        let account_id = Type::Struct(Arc::new(StructType::named(
            "account-id".into(),
            [(Arc::from("prefix"), felt_wrapper.clone()), (Arc::from("suffix"), felt_wrapper)],
        )));
        let function = Type::Function(Arc::new(FunctionType::new(
            CallConv::ComponentModel,
            [account_id.clone()],
            [account_id],
        )));
        let mut builder = PackageDebugInfoBuilder::default();

        let function_name = builder.add_string("take-account-id");
        let function_idx = builder
            .register_debug_type(Some(function_name), None, &function)
            .expect("function type should register");

        let (return_type_idx, param_type_idx) = match &builder[function_idx] {
            DebugTypeInfo::Function {
                return_type_idx: Some(return_type_idx),
                param_type_indices,
            } => {
                assert_eq!(param_type_indices.len(), 1);
                (*return_type_idx, param_type_indices[0])
            },
            other => panic!("expected function debug type, got {other:?}"),
        };

        assert_struct_debug_type(
            &builder,
            param_type_idx,
            "account-id",
            &[("prefix", "felt-wrapper"), ("suffix", "felt-wrapper")],
        );
        assert_struct_debug_type(
            &builder,
            return_type_idx,
            "account-id",
            &[("prefix", "felt-wrapper"), ("suffix", "felt-wrapper")],
        );
    }

    fn assert_struct_debug_type(
        builder: &PackageDebugInfoBuilder,
        type_idx: DebugTypeIdx,
        expected_name: &str,
        expected_fields: &[(&str, &str)],
    ) {
        let DebugTypeInfo::Struct { name_idx, fields, .. } = &builder[type_idx] else {
            panic!("expected struct debug type");
        };

        assert_eq!(builder[*name_idx].as_ref(), expected_name);
        assert_eq!(fields.len(), expected_fields.len());
        for (field, (expected_name, expected_type_name)) in fields.iter().zip(expected_fields) {
            assert_eq!(builder[field.name_idx].as_ref(), *expected_name);

            let DebugTypeInfo::Struct { name_idx, .. } = &builder[field.type_idx] else {
                panic!("expected struct field type");
            };
            assert_eq!(builder[*name_idx].as_ref(), *expected_type_name);
        }
    }

    #[test]
    fn test_debug_info_string_dedup() {
        let mut builder = PackageDebugInfoBuilder::default();

        let idx1 = builder.add_string(Arc::from("test.rs"));
        let idx2 = builder.add_string(Arc::from("main.rs"));
        let idx3 = builder.add_string(Arc::from("test.rs")); // Duplicate

        assert_eq!(idx1.to_usize(), 0);
        assert_eq!(idx2.to_usize(), 1);
        assert_eq!(idx3.to_usize(), 0); // Should return same index
        assert_eq!(builder.string_indices.len(), 2);
        assert_eq!(builder.debug_info.strings.len(), 2);
    }
}
