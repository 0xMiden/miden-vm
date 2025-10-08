use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use miden_core::{
    AdviceMap, Kernel, Word,
    mast::{BasicBlockNodeBuilder, MastForest, MastForestContributor, MastNodeExt, MastNodeId},
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use midenc_hir_type::{FunctionType, Type};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

use crate::ast::{AttributeSet, QualifiedProcedureName};

mod error;
mod module;
mod namespace;
mod path;

pub use module::{ModuleInfo, ProcedureInfo};
pub use semver::{Error as VersionError, Version};

pub use self::{
    error::LibraryError,
    namespace::{LibraryNamespace, LibraryNamespaceError},
    path::{LibraryPath, LibraryPathComponent, PathError},
};

// LIBRARY EXPORT
// ================================================================================================

/// Metadata about a procedure exported by the interface of a [Library]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct LibraryExport {
    /// The id of the MAST root node of the exported procedure
    pub node: MastNodeId,
    /// The fully-qualified name of the exported procedure
    pub name: QualifiedProcedureName,
    /// The type signature of the exported procedure, if known
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature: Option<FunctionType>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub attributes: AttributeSet,
}

impl LibraryExport {
    /// Create a new [LibraryExport] representing the export of `node` with `name`
    pub fn new(node: MastNodeId, name: QualifiedProcedureName) -> Self {
        Self {
            node,
            name,
            signature: None,
            attributes: Default::default(),
        }
    }

    /// Specify the type signature and ABI of this export
    pub fn with_signature(mut self, signature: FunctionType) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Specify the set of attributes attached to this export
    pub fn with_attributes(mut self, attrs: AttributeSet) -> Self {
        self.attributes = attrs;
        self
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for LibraryExport {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::collection::vec as prop_vec;

        // Generate a small set of simple types for params/results to keep strategies fast/stable
        let simple_type = prop_oneof![Just(Type::Felt), Just(Type::U32), Just(Type::U64),];

        // Small vectors of params/results
        let params = prop_vec(simple_type.clone(), 0..=4);
        let results = prop_vec(simple_type, 0..=2);

        // Use Fast ABI for roundtrip coverage
        let abi = Just(midenc_hir_type::CallConv::Fast);

        // Option<FunctionType>
        let signature =
            prop::option::of((abi, params, results).prop_map(|(abi, params_vec, results_vec)| {
                let params = SmallVec::<[Type; 4]>::from_vec(params_vec);
                let results = SmallVec::<[Type; 1]>::from_vec(results_vec);
                FunctionType { abi, params, results }
            }));

        let nid = any::<MastNodeId>();
        let name = any::<QualifiedProcedureName>();
        (nid, name, signature)
            .prop_map(|(nodeid, procname, signature)| LibraryExport {
                node: nodeid,
                name: procname,
                signature,
                attributes: Default::default(),
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

// LIBRARY
// ================================================================================================

/// Represents a library where all modules were compiled into a [`MastForest`].
///
/// A library exports a set of one or more procedures. Currently, all exported procedures belong
/// to the same top-level namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct Library {
    /// The content hash of this library, formed by hashing the roots of all exports in
    /// lexicographical order (by digest, not procedure name)
    digest: Word,
    /// A map between procedure paths and the corresponding procedure metadata in the MAST forest.
    /// Multiple paths can map to the same root, and also, some roots may not be associated with
    /// any paths.
    ///
    /// Note that we use `MastNodeId` as an identifier for procedures instead of MAST root, since 2
    /// different procedures with the same MAST root can be different due to the decorators they
    /// contain. However, note that `MastNodeId` is also not a unique identifier for procedures; if
    /// the procedures have the same MAST root and decorators, they will have the same
    /// `MastNodeId`.
    exports: BTreeMap<QualifiedProcedureName, LibraryExport>,
    /// The MAST forest underlying this library.
    mast_forest: Arc<MastForest>,
}

impl AsRef<Library> for Library {
    #[inline(always)]
    fn as_ref(&self) -> &Library {
        self
    }
}

// ------------------------------------------------------------------------------------------------
/// Constructors
impl Library {
    /// Constructs a new [`Library`] from the provided MAST forest and a set of exports.
    ///
    /// # Errors
    /// Returns an error if the set of exports is empty.
    /// Returns an error if any of the specified exports do not have a corresponding procedure root
    /// in the provided MAST forest.
    pub fn new(
        mast_forest: Arc<MastForest>,
        exports: BTreeMap<QualifiedProcedureName, LibraryExport>,
    ) -> Result<Self, LibraryError> {
        if exports.is_empty() {
            return Err(LibraryError::NoExport);
        }
        for LibraryExport { name, node, .. } in exports.values() {
            if !mast_forest.is_procedure_root(*node) {
                return Err(LibraryError::NoProcedureRootForExport {
                    procedure_path: name.clone(),
                });
            }
        }

        let digest =
            mast_forest.compute_nodes_commitment(exports.values().map(|export| &export.node));

        Ok(Self { digest, exports, mast_forest })
    }

    /// Produces a new library with the existing [`MastForest`] and where all key/values in the
    /// provided advice map are added to the internal advice map.
    pub fn with_advice_map(self, advice_map: AdviceMap) -> Self {
        let mut mast_forest = (*self.mast_forest).clone();
        mast_forest.advice_map_mut().extend(advice_map);
        Self {
            mast_forest: Arc::new(mast_forest),
            ..self
        }
    }
}

// ------------------------------------------------------------------------------------------------
/// Public accessors
impl Library {
    /// Returns the [Word] representing the content hash of this library
    pub fn digest(&self) -> &Word {
        &self.digest
    }

    /// Returns the fully qualified name and metadata of all procedures exported by the library.
    pub fn exports(&self) -> impl Iterator<Item = &LibraryExport> {
        self.exports.values()
    }

    /// Returns the number of exports in this library.
    pub fn num_exports(&self) -> usize {
        self.exports.len()
    }

    /// Returns a MAST node ID associated with the specified exported procedure.
    ///
    /// # Panics
    /// Panics if the specified procedure is not exported from this library.
    pub fn get_export_node_id(&self, proc_name: &QualifiedProcedureName) -> MastNodeId {
        self.exports
            .get(proc_name)
            .expect("procedure not exported from the library")
            .node
    }

    /// Returns true if the specified exported procedure is re-exported from a dependency.
    pub fn is_reexport(&self, proc_name: &QualifiedProcedureName) -> bool {
        self.exports
            .get(proc_name)
            .map(|export| self.mast_forest[export.node].is_external())
            .unwrap_or(false)
    }

    /// Returns a reference to the inner [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Returns the digest of the procedure with the specified name, or `None` if it was not found
    /// in the library or its library path is malformed.
    pub fn get_procedure_root_by_name(
        &self,
        proc_name: impl TryInto<QualifiedProcedureName>,
    ) -> Option<Word> {
        if let Ok(qualified_proc_name) = proc_name.try_into() {
            let export = self.exports.get(&qualified_proc_name);
            export.map(|e| self.mast_forest()[e.node].digest())
        } else {
            None
        }
    }
}

/// Conversions
impl Library {
    /// Returns an iterator over the module infos of the library.
    pub fn module_infos(&self) -> impl Iterator<Item = ModuleInfo> {
        let mut modules_by_path: BTreeMap<LibraryPath, ModuleInfo> = BTreeMap::new();

        for LibraryExport { node, name, signature, attributes } in self.exports.values() {
            modules_by_path
                .entry(name.module.clone())
                .and_modify(|compiled_module| {
                    let proc_digest = self.mast_forest[*node].digest();
                    compiled_module.add_procedure(
                        name.name.clone(),
                        proc_digest,
                        signature.clone().map(Arc::new),
                        attributes.clone(),
                    );
                })
                .or_insert_with(|| {
                    let mut module_info = ModuleInfo::new(name.module.clone());

                    let proc_digest = self.mast_forest[*node].digest();
                    module_info.add_procedure(
                        name.name.clone(),
                        proc_digest,
                        signature.clone().map(Arc::new),
                        attributes.clone(),
                    );

                    module_info
                });
        }

        modules_by_path.into_values()
    }
}

#[cfg(feature = "std")]
impl Library {
    /// File extension for the Assembly Library.
    pub const LIBRARY_EXTENSION: &'static str = "masl";

    /// Write the library to a target file
    ///
    /// NOTE: It is up to the caller to use the correct file extension, but there is no
    /// specific requirement that the extension be set, or the same as
    /// [`Self::LIBRARY_EXTENSION`].
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let path = path.as_ref();

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }

        // NOTE: We catch panics due to i/o errors here due to the fact that the ByteWriter
        // trait does not provide fallible APIs, so WriteAdapter will panic if the underlying
        // writes fail. This needs to be addressed in winterfell at some point
        std::panic::catch_unwind(|| {
            let mut file = std::fs::File::create(path)?;
            self.write_into(&mut file);
            Ok(())
        })
        .map_err(|p| {
            match p.downcast::<std::io::Error>() {
                // SAFETY: It is guaranteed safe to read Box<std::io::Error>
                Ok(err) => unsafe { core::ptr::read(&*err) },
                Err(err) => std::panic::resume_unwind(err),
            }
        })?
    }

    pub fn deserialize_from_file(
        path: impl AsRef<std::path::Path>,
    ) -> Result<Self, DeserializationError> {
        use miden_core::utils::ReadAdapter;

        let path = path.as_ref();
        let mut file = std::fs::File::open(path).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "failed to open file at {}: {err}",
                path.to_string_lossy()
            ))
        })?;
        let mut adapter = ReadAdapter::new(&mut file);

        Self::read_from(&mut adapter)
    }
}

// KERNEL LIBRARY
// ================================================================================================

/// Represents a library containing a Miden VM kernel.
///
/// This differs from the regular [Library] as follows:
/// - All exported procedures must be exported directly from the kernel namespace (i.e., `$kernel`).
/// - There must be at least one exported procedure.
/// - The number of exported procedures cannot exceed [Kernel::MAX_NUM_PROCEDURES] (i.e., 256).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Library"))]
pub struct KernelLibrary {
    #[cfg_attr(feature = "serde", serde(skip))]
    kernel: Kernel,
    #[cfg_attr(feature = "serde", serde(skip))]
    kernel_info: ModuleInfo,
    library: Library,
}

#[cfg(feature = "serde")]
impl serde::Serialize for KernelLibrary {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Library::serialize(&self.library, serializer)
    }
}

impl AsRef<Library> for KernelLibrary {
    #[inline(always)]
    fn as_ref(&self) -> &Library {
        &self.library
    }
}

impl KernelLibrary {
    /// Returns the [Kernel] for this kernel library.
    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    /// Returns a reference to the inner [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        self.library.mast_forest()
    }

    /// Destructures this kernel library into individual parts.
    pub fn into_parts(self) -> (Kernel, ModuleInfo, Arc<MastForest>) {
        (self.kernel, self.kernel_info, self.library.mast_forest)
    }
}

impl TryFrom<Library> for KernelLibrary {
    type Error = LibraryError;

    fn try_from(library: Library) -> Result<Self, Self::Error> {
        let kernel_path = LibraryPath::from(LibraryNamespace::Kernel);
        let mut proc_digests = Vec::with_capacity(library.exports.len());

        let mut kernel_module = ModuleInfo::new(kernel_path.clone());

        for export in library.exports.values() {
            // make sure all procedures are exported only from the kernel root
            if export.name.module != kernel_path {
                return Err(LibraryError::InvalidKernelExport {
                    procedure_path: export.name.clone(),
                });
            }

            let proc_digest = library.mast_forest[export.node].digest();
            proc_digests.push(proc_digest);
            kernel_module.add_procedure(
                export.name.name.clone(),
                proc_digest,
                export.signature.clone().map(Arc::new),
                export.attributes.clone(),
            );
        }

        let kernel = Kernel::new(&proc_digests).map_err(LibraryError::KernelConversion)?;

        Ok(Self {
            kernel,
            kernel_info: kernel_module,
            library,
        })
    }
}

#[cfg(feature = "std")]
impl KernelLibrary {
    /// Write the library to a target file
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        self.library.write_to_file(path)
    }
}

// LIBRARY SERIALIZATION
// ================================================================================================

/// NOTE: Serialization of libraries is likely to be deprecated in a future release
impl Serializable for Library {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { digest: _, exports, mast_forest } = self;

        mast_forest.write_into(target);

        target.write_usize(exports.len());
        for LibraryExport { node, name, signature, attributes: _ } in exports.values() {
            name.module.write_into(target);
            name.name.write_into(target);
            target.write_u32(u32::from(*node));
            if let Some(sig) = signature {
                target.write_bool(true);
                FunctionTypeSerializer(sig).write_into(target);
            } else {
                target.write_bool(false);
            }
        }
    }
}

/// NOTE: Serialization of libraries is likely to be deprecated in a future release
impl Deserializable for Library {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let mast_forest = Arc::new(MastForest::read_from(source)?);

        let num_exports = source.read_usize()?;
        if num_exports == 0 {
            return Err(DeserializationError::InvalidValue(String::from("No exported procedures")));
        };
        let mut exports = BTreeMap::new();
        for _ in 0..num_exports {
            let proc_module = source.read()?;
            let proc_name = source.read()?;
            let proc_name = QualifiedProcedureName::new(proc_module, proc_name);
            let node = MastNodeId::from_u32_safe(source.read_u32()?, &mast_forest)?;
            let signature = if source.read_bool()? {
                Some(FunctionTypeDeserializer::read_from(source)?.0)
            } else {
                None
            };
            let export = LibraryExport {
                node,
                name: proc_name.clone(),
                signature,
                attributes: Default::default(),
            };

            exports.insert(proc_name, export);
        }

        let digest = mast_forest.compute_nodes_commitment(exports.values().map(|e| &e.node));

        Ok(Self { digest, exports, mast_forest })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Library {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        struct LibraryExports<'a>(&'a BTreeMap<QualifiedProcedureName, LibraryExport>);
        impl serde::Serialize for LibraryExports<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::SerializeSeq;
                let mut serializer = serializer.serialize_seq(Some(self.0.len()))?;
                for elem in self.0.values() {
                    serializer.serialize_element(elem)?;
                }
                serializer.end()
            }
        }

        let Self { digest: _, exports, mast_forest } = self;

        let mut serializer = serializer.serialize_struct("Library", 2)?;
        serializer.serialize_field("mast_forest", mast_forest)?;
        serializer.serialize_field("exports", &LibraryExports(exports))?;
        serializer.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Library {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Visitor;

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            MastForest,
            Exports,
        }

        struct LibraryVisitor;

        impl<'de> Visitor<'de> for LibraryVisitor {
            type Value = Library;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct Library")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mast_forest = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let exports: Vec<LibraryExport> = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let exports =
                    exports.into_iter().map(|export| (export.name.clone(), export)).collect();
                Library::new(mast_forest, exports).map_err(serde::de::Error::custom)
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut mast_forest = None;
                let mut exports = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::MastForest => {
                            if mast_forest.is_some() {
                                return Err(serde::de::Error::duplicate_field("mast_forest"));
                            }
                            mast_forest = Some(map.next_value()?);
                        },
                        Field::Exports => {
                            if exports.is_some() {
                                return Err(serde::de::Error::duplicate_field("exports"));
                            }
                            let items: Vec<LibraryExport> = map.next_value()?;
                            exports = Some(
                                items
                                    .into_iter()
                                    .map(|export| (export.name.clone(), export))
                                    .collect(),
                            );
                        },
                    }
                }
                let mast_forest =
                    mast_forest.ok_or_else(|| serde::de::Error::missing_field("mast_forest"))?;
                let exports = exports.ok_or_else(|| serde::de::Error::missing_field("exports"))?;
                Library::new(mast_forest, exports).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_struct("Library", &["mast_forest", "exports"], LibraryVisitor)
    }
}

/// NOTE: Serialization of libraries is likely to be deprecated in a future release
impl Serializable for KernelLibrary {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        let Self { kernel: _, kernel_info: _, library } = self;

        library.write_into(target);
    }
}

/// NOTE: Serialization of libraries is likely to be deprecated in a future release
impl Deserializable for KernelLibrary {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let library = Library::read_from(source)?;

        Self::try_from(library).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "Failed to deserialize kernel library: {err}"
            ))
        })
    }
}

/// A wrapper type for [FunctionType] that provides serialization support via the winter-utils
/// serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
pub struct FunctionTypeSerializer<'a>(pub &'a FunctionType);

impl Serializable for FunctionTypeSerializer<'_> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        target.write_u8(self.0.abi as u8);
        target.write_usize(self.0.params().len());
        target.write_many(self.0.params().iter().map(TypeSerializer));
        target.write_usize(self.0.results().len());
        target.write_many(self.0.results().iter().map(TypeSerializer));
    }
}

/// A wrapper type for [FunctionType] that provides deserialization support via the winter-utils
/// serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
pub struct FunctionTypeDeserializer(pub FunctionType);

impl Deserializable for FunctionTypeDeserializer {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use midenc_hir_type::CallConv;

        let abi = match source.read_u8()? {
            0 => CallConv::Fast,
            1 => CallConv::SystemV,
            2 => CallConv::Wasm,
            3 => CallConv::CanonLift,
            4 => CallConv::CanonLower,
            5 => CallConv::Kernel,
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid CallConv tag: {invalid}"
                )));
            },
        };

        let arity = source.read_usize()?;
        let mut params = SmallVec::<[Type; 4]>::with_capacity(arity);
        for _ in 0..arity {
            let ty = TypeDeserializer::read_from(source)?.0;
            params.push(ty);
        }

        let num_results = source.read_usize()?;
        let mut results = SmallVec::<[Type; 1]>::with_capacity(num_results);
        for _ in 0..num_results {
            let ty = TypeDeserializer::read_from(source)?.0;
            results.push(ty);
        }

        Ok(Self(FunctionType { abi, params, results }))
    }
}

/// A wrapper type for [Type] that provides serialization support via the winter-utils serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
pub struct TypeSerializer<'a>(pub &'a Type);

impl Serializable for TypeSerializer<'_> {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        use midenc_hir_type::{AddressSpace, TypeRepr};

        match self.0 {
            Type::Unknown => target.write_u8(0),
            Type::Never => target.write_u8(1),
            Type::I1 => target.write_u8(2),
            Type::I8 => target.write_u8(3),
            Type::U8 => target.write_u8(4),
            Type::I16 => target.write_u8(5),
            Type::U16 => target.write_u8(6),
            Type::I32 => target.write_u8(7),
            Type::U32 => target.write_u8(8),
            Type::I64 => target.write_u8(9),
            Type::U64 => target.write_u8(10),
            Type::I128 => target.write_u8(11),
            Type::U128 => target.write_u8(12),
            Type::U256 => target.write_u8(13),
            Type::F64 => target.write_u8(14),
            Type::Felt => target.write_u8(15),
            Type::Ptr(ty) => {
                target.write_u8(16);
                match ty.addrspace {
                    AddressSpace::Byte => target.write_u8(0),
                    AddressSpace::Element => target.write_u8(1),
                }
                TypeSerializer(&ty.pointee).write_into(target);
            },
            Type::Struct(ty) => {
                target.write_u8(17);
                match ty.repr() {
                    TypeRepr::Default => target.write_u8(0),
                    TypeRepr::Align(align) => {
                        target.write_u8(1);
                        target.write_u16(align.get());
                    },
                    TypeRepr::Packed(align) => {
                        target.write_u8(2);
                        target.write_u16(align.get());
                    },
                    TypeRepr::Transparent => target.write_u8(3),
                    TypeRepr::BigEndian => target.write_u8(4),
                }
                target.write_u8(ty.len() as u8);
                for field in ty.fields() {
                    TypeSerializer(&field.ty).write_into(target);
                }
            },
            Type::Array(ty) => {
                target.write_u8(18);
                target.write_usize(ty.len);
                TypeSerializer(&ty.ty).write_into(target);
            },
            Type::List(ty) => {
                target.write_u8(19);
                TypeSerializer(ty).write_into(target);
            },
            Type::Function(ty) => {
                target.write_u8(20);
                FunctionTypeSerializer(ty).write_into(target);
            },
        }
    }
}

/// A wrapper type for [Type] that provides deserialization support via the winter-utils serializer.
///
/// This is a temporary implementation to allow type information to be serialized with libraries,
/// but in a future release we'll either rely on the `serde` serialization for these types, or
/// provide the serialization implementation in midenc-hir-type instead
pub struct TypeDeserializer(pub Type);

impl Deserializable for TypeDeserializer {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        use alloc::string::ToString;
        use core::num::NonZeroU16;

        use midenc_hir_type::{AddressSpace, ArrayType, PointerType, StructType, TypeRepr};

        let ty = match source.read_u8()? {
            0 => Type::Unknown,
            1 => Type::Never,
            2 => Type::I1,
            3 => Type::I8,
            4 => Type::U8,
            5 => Type::I16,
            6 => Type::U16,
            7 => Type::I32,
            8 => Type::U32,
            9 => Type::I64,
            10 => Type::U64,
            11 => Type::I128,
            12 => Type::U128,
            13 => Type::U256,
            14 => Type::F64,
            15 => Type::Felt,
            16 => {
                let addrspace = match source.read_u8()? {
                    0 => AddressSpace::Byte,
                    1 => AddressSpace::Element,
                    invalid => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid AddressSpace tag: {invalid}"
                        )));
                    },
                };
                let pointee = TypeDeserializer::read_from(source)?.0;
                Type::Ptr(Arc::new(PointerType { addrspace, pointee }))
            },
            17 => {
                let repr = match source.read_u8()? {
                    0 => TypeRepr::Default,
                    1 => {
                        let align = NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
                            DeserializationError::InvalidValue(
                                "invalid type repr: alignment must be a non-zero value".to_string(),
                            )
                        })?;
                        TypeRepr::Align(align)
                    },
                    2 => {
                        let align = NonZeroU16::new(source.read_u16()?).ok_or_else(|| {
                            DeserializationError::InvalidValue(
                                "invalid type repr: packed alignment must be a non-zero value"
                                    .to_string(),
                            )
                        })?;
                        TypeRepr::Packed(align)
                    },
                    3 => TypeRepr::Transparent,
                    invalid => {
                        return Err(DeserializationError::InvalidValue(format!(
                            "invalid TypeRepr tag: {invalid}"
                        )));
                    },
                };
                let num_fields = source.read_u8()?;
                let mut fields = SmallVec::<[Type; 4]>::with_capacity(num_fields as usize);
                for _ in 0..num_fields {
                    let ty = TypeDeserializer::read_from(source)?.0;
                    fields.push(ty);
                }
                Type::Struct(Arc::new(StructType::new_with_repr(repr, fields)))
            },
            18 => {
                let arity = source.read_usize()?;
                let ty = TypeDeserializer::read_from(source)?.0;
                Type::Array(Arc::new(ArrayType { ty, len: arity }))
            },
            19 => {
                let ty = TypeDeserializer::read_from(source)?.0;
                Type::List(Arc::new(ty))
            },
            20 => Type::Function(Arc::new(FunctionTypeDeserializer::read_from(source)?.0)),
            invalid => {
                return Err(DeserializationError::InvalidValue(format!(
                    "invalid Type tag: {invalid}"
                )));
            },
        };
        Ok(Self(ty))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::prelude::Arbitrary for Library {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::prelude::*;
        prop::collection::btree_map(any::<QualifiedProcedureName>(), any::<LibraryExport>(), 1..5)
            .prop_flat_map(|mut exports| {
                // Create a MastForest with actual nodes for the exports
                let mut mast_forest = MastForest::new();
                let mut nodes = Vec::new();

                // Create a simple node for each export
                for (export_name, export) in exports.iter_mut() {
                    use miden_core::Operation;

                    // Ensure the export name matches the exported procedure, as the Arbitrary
                    // impl will generate different paths for each
                    export.name = export_name.clone();

                    let node_id = BasicBlockNodeBuilder::new(
                        vec![Operation::Add, Operation::Mul],
                        Vec::new(),
                    )
                    .add_to_forest(&mut mast_forest)
                    .unwrap();
                    nodes.push((export.node, node_id));
                }

                (Just(mast_forest), Just(nodes), Just(exports))
            })
            .prop_map(|(mut mast_forest, nodes, exports)| {
                // Replace the export node IDs with the actual node IDs we created
                let mut adjusted_exports = BTreeMap::new();

                for (proc_name, mut export) in exports {
                    // Find the corresponding node we created
                    if let Some(&(_, actual_node_id)) =
                        nodes.iter().find(|(original_id, _)| *original_id == export.node)
                    {
                        export.node = actual_node_id;
                    } else {
                        // If we can't find the node (shouldn't happen), use the first node we
                        // created
                        if let Some(&(_, first_node_id)) = nodes.first() {
                            export.node = first_node_id;
                        } else {
                            // This should never happen since we create nodes for each export
                            panic!("No nodes created for exports");
                        }
                    }

                    adjusted_exports.insert(proc_name, export);
                }

                let mut node_ids = Vec::with_capacity(adjusted_exports.len());
                for export in adjusted_exports.values() {
                    // Add the node to the forest roots if it's not already there
                    mast_forest.make_root(export.node);
                    // Collect the node id for recomputing the digest
                    node_ids.push(export.node);
                }

                // Recompute the digest
                let digest = mast_forest.compute_nodes_commitment(&node_ids);

                let mast_forest = Arc::new(mast_forest);
                Library {
                    digest,
                    exports: adjusted_exports,
                    mast_forest,
                }
            })
            .boxed()
    }

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}
