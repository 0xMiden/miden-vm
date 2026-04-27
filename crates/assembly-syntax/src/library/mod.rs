use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use miden_core::{
    Word,
    advice::AdviceMap,
    mast::{MastForest, MastNodeExt, MastNodeId},
    program::Kernel,
    serde::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};
use midenc_hir_type::{FunctionType, Type};
#[cfg(feature = "arbitrary")]
use proptest::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "arbitrary")]
use crate::ast::QualifiedProcedureName;
#[cfg(feature = "serde")]
use crate::ast::path;
use crate::ast::{AttributeSet, ConstantValue, Ident, Path, PathBuf, ProcedureName};

mod error;
mod module;

pub use module::{ConstantInfo, ItemInfo, ModuleInfo, ProcedureInfo, TypeInfo};
pub use semver::{Error as VersionError, Version};

pub use self::error::LibraryError;

// LIBRARY EXPORT
// ================================================================================================

/// Metadata about a procedure exported by the interface of a [Library]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub enum LibraryExport {
    Procedure(ProcedureExport),
    Constant(ConstantExport),
    Type(TypeExport),
}

impl LibraryExport {
    pub fn path(&self) -> Arc<Path> {
        match self {
            Self::Procedure(export) => export.path.clone(),
            Self::Constant(export) => export.path.clone(),
            Self::Type(export) => export.path.clone(),
        }
    }

    pub fn as_procedure(&self) -> Option<&ProcedureExport> {
        match self {
            Self::Procedure(proc) => Some(proc),
            Self::Constant(_) | Self::Type(_) => None,
        }
    }

    pub fn unwrap_procedure(&self) -> &ProcedureExport {
        match self {
            Self::Procedure(proc) => proc,
            Self::Constant(_) | Self::Type(_) => panic!("expected export to be a procedure"),
        }
    }
}

impl From<ProcedureExport> for LibraryExport {
    fn from(value: ProcedureExport) -> Self {
        Self::Procedure(value)
    }
}

impl From<ConstantExport> for LibraryExport {
    fn from(value: ConstantExport) -> Self {
        Self::Constant(value)
    }
}

impl From<TypeExport> for LibraryExport {
    fn from(value: TypeExport) -> Self {
        Self::Type(value)
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for LibraryExport {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::{arbitrary::any, prop_oneof, strategy::Strategy};

        prop_oneof![
            any::<ProcedureExport>().prop_map(Self::Procedure),
            any::<ConstantExport>().prop_map(Self::Constant),
            any::<TypeExport>().prop_map(Self::Type),
        ]
        .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ProcedureExport {
    /// The id of the MAST root node of the exported procedure
    pub node: MastNodeId,
    /// The fully-qualified path of the exported procedure
    #[cfg_attr(feature = "serde", serde(with = "path"))]
    pub path: Arc<Path>,
    /// The type signature of the exported procedure, if known
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature: Option<FunctionType>,
    #[cfg_attr(feature = "serde", serde(default))]
    pub attributes: AttributeSet,
}

impl ProcedureExport {
    /// Create a new [ProcedureExport] representing the export of `node` with `path`
    pub fn new(node: MastNodeId, path: Arc<Path>) -> Self {
        Self {
            node,
            path,
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
impl Arbitrary for ProcedureExport {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::collection::vec as prop_vec;
        use smallvec::SmallVec;

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
            .prop_map(|(nodeid, procname, signature)| Self {
                node: nodeid,
                path: procname.to_path_buf().into(),
                signature,
                attributes: Default::default(),
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ConstantExport {
    /// The fully-qualified path of the exported constant
    #[cfg_attr(feature = "serde", serde(with = "path"))]
    pub path: Arc<Path>,
    /// The constant-folded AST representing the value of this constant
    pub value: ConstantValue,
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for ConstantExport {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        let path = crate::arbitrary::path::constant_path_random_length(1);
        let value = any::<ConstantValue>();

        (path, value).prop_map(|(path, value)| Self { path, value }).boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct TypeExport {
    /// The fully-qualified path of the exported type declaration
    #[cfg_attr(feature = "serde", serde(with = "path"))]
    pub path: Arc<Path>,
    /// The type bound to `name`
    pub ty: Type,
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for TypeExport {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::{Just, Strategy};
        let path = crate::arbitrary::path::user_defined_type_path_random_length(1);
        let ty = Just(Type::Felt);

        (path, ty).prop_map(|(path, ty)| Self { path, ty }).boxed()
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
    exports: BTreeMap<Arc<Path>, LibraryExport>,
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
        exports: BTreeMap<Arc<Path>, LibraryExport>,
    ) -> Result<Self, LibraryError> {
        if exports.is_empty() {
            return Err(LibraryError::NoExport);
        }

        for export in exports.values() {
            if let LibraryExport::Procedure(ProcedureExport { node, path, .. }) = export
                && !mast_forest.is_procedure_root(*node)
            {
                return Err(LibraryError::NoProcedureRootForExport {
                    procedure_path: path.clone(),
                });
            }
        }

        let digest =
            mast_forest.compute_nodes_commitment(exports.values().filter_map(
                |export| match export {
                    LibraryExport::Procedure(export) => Some(&export.node),
                    LibraryExport::Constant(_) | LibraryExport::Type(_) => None,
                },
            ));

        Ok(Self { digest, exports, mast_forest })
    }

    /// Produces a new library with the existing [`MastForest`] and where all key/values in the
    /// provided advice map are added to the internal advice map.
    pub fn with_advice_map(mut self, advice_map: AdviceMap) -> Self {
        self.extend_advice_map(advice_map);
        self
    }

    /// Extends the advice map of this library
    pub fn extend_advice_map(&mut self, advice_map: AdviceMap) {
        let mast_forest = Arc::make_mut(&mut self.mast_forest);
        mast_forest.advice_map_mut().extend(advice_map);
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
    pub fn get_export_node_id(&self, path: impl AsRef<Path>) -> MastNodeId {
        let path = path.as_ref().to_absolute();
        self.exports
            .get(path.as_ref())
            .expect("procedure not exported from the library")
            .unwrap_procedure()
            .node
    }

    /// Returns true if the specified exported procedure is re-exported from a dependency.
    pub fn is_reexport(&self, path: impl AsRef<Path>) -> bool {
        let path = path.as_ref().to_absolute();
        self.exports
            .get(path.as_ref())
            .and_then(LibraryExport::as_procedure)
            .map(|export| self.mast_forest[export.node].is_external())
            .unwrap_or(false)
    }

    /// Returns a reference to the inner [`MastForest`].
    pub fn mast_forest(&self) -> &Arc<MastForest> {
        &self.mast_forest
    }

    /// Returns the digest of the procedure with the specified name, or `None` if it was not found
    /// in the library or its library path is malformed.
    pub fn get_procedure_root_by_path(&self, path: impl AsRef<Path>) -> Option<Word> {
        let path = path.as_ref().to_absolute();
        let export = self.exports.get(path.as_ref()).and_then(LibraryExport::as_procedure);
        export.map(|e| self.mast_forest()[e.node].digest())
    }
}

/// Conversions
impl Library {
    /// Returns an iterator over the module infos of the library.
    pub fn module_infos(&self) -> impl Iterator<Item = ModuleInfo> {
        let mut modules_by_path: BTreeMap<Arc<Path>, ModuleInfo> = BTreeMap::new();

        for export in self.exports.values() {
            let module_name =
                Arc::from(export.path().parent().unwrap().to_path_buf().into_boxed_path());
            let module = modules_by_path
                .entry(Arc::clone(&module_name))
                .or_insert_with(|| ModuleInfo::new(module_name, None));
            match export {
                LibraryExport::Procedure(ProcedureExport { node, path, signature, attributes }) => {
                    let proc_digest = self.mast_forest[*node].digest();
                    let name = path.last().unwrap();
                    module.add_procedure(
                        ProcedureName::new(name).expect("valid procedure name"),
                        proc_digest,
                        signature.clone().map(Arc::new),
                        attributes.clone(),
                    );
                },
                LibraryExport::Constant(ConstantExport { path, value }) => {
                    let name = Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_constant(name, value.clone());
                },
                LibraryExport::Type(TypeExport { path, ty }) => {
                    let name = Ident::new(path.last().unwrap()).expect("valid identifier");
                    module.add_type(name, ty.clone());
                },
            }
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
        // writes fail. This needs to be addressed upstream at some point
        std::panic::catch_unwind(|| {
            let mut file = std::fs::File::create(path)?;
            self.write_into(&mut file);
            Ok(())
        })
        .map_err(|p| match p.downcast::<std::io::Error>() {
            Ok(err) => *err,
            Err(err) => std::panic::resume_unwind(err),
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
#[cfg_attr(feature = "serde", serde(try_from = "Arc<Library>"))]
pub struct KernelLibrary {
    #[cfg_attr(feature = "serde", serde(skip))]
    kernel: Kernel,
    #[cfg_attr(feature = "serde", serde(skip))]
    kernel_info: ModuleInfo,
    library: Arc<Library>,
}

#[cfg(feature = "serde")]
impl Serialize for KernelLibrary {
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
        (self.kernel, self.kernel_info, self.library.mast_forest().clone())
    }
}

impl TryFrom<Arc<Library>> for KernelLibrary {
    type Error = LibraryError;

    fn try_from(library: Arc<Library>) -> Result<Self, Self::Error> {
        let kernel_path = Arc::from(Path::kernel_path().to_path_buf().into_boxed_path());
        let mut proc_digests = Vec::with_capacity(library.exports.len());

        let mut kernel_module = ModuleInfo::new(Arc::clone(&kernel_path), None);

        for export in library.exports.values() {
            match export {
                LibraryExport::Procedure(export) => {
                    // make sure all procedures are exported only from the kernel root
                    if !export.path.is_in_kernel() {
                        return Err(LibraryError::InvalidKernelExport {
                            procedure_path: export.path.clone(),
                        });
                    }

                    let proc_digest = library.mast_forest[export.node].digest();
                    proc_digests.push(proc_digest);
                    kernel_module.add_procedure(
                        ProcedureName::new(export.path.last().unwrap())
                            .expect("valid procedure name"),
                        proc_digest,
                        export.signature.clone().map(Arc::new),
                        export.attributes.clone(),
                    );
                },
                LibraryExport::Constant(export) => {
                    // Only export constants from the kernel root
                    if export.path.is_in_kernel() {
                        let name =
                            Ident::new(export.path.last().unwrap()).expect("valid identifier");
                        kernel_module.add_constant(name, export.value.clone());
                    }
                },
                LibraryExport::Type(export) => {
                    // Only export types from the kernel root
                    if export.path.is_in_kernel() {
                        let name =
                            Ident::new(export.path.last().unwrap()).expect("valid identifier");
                        kernel_module.add_type(name, export.ty.clone());
                    }
                },
            }
        }

        if proc_digests.is_empty() {
            return Err(LibraryError::NoExport);
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
        for export in exports.values() {
            export.write_into(target);
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
            let tag = source.read_u8()?;
            let path: PathBuf = source.read()?;
            let path = Arc::<Path>::from(path.into_boxed_path());
            let export = match tag {
                0 => {
                    let node = MastNodeId::from_u32_safe(source.read_u32()?, &mast_forest)?;
                    let signature = if source.read_bool()? {
                        Some(FunctionType::read_from(source)?)
                    } else {
                        None
                    };
                    let attributes = AttributeSet::read_from(source)?;
                    LibraryExport::Procedure(ProcedureExport {
                        node,
                        path: path.clone(),
                        signature,
                        attributes,
                    })
                },
                1 => {
                    let value = ConstantValue::read_from(source)?;
                    LibraryExport::Constant(ConstantExport { path: path.clone(), value })
                },
                2 => {
                    let ty = Type::read_from(source)?;
                    LibraryExport::Type(TypeExport { path: path.clone(), ty })
                },
                invalid => {
                    return Err(DeserializationError::InvalidValue(format!(
                        "unknown LibraryExport tag: '{invalid}'"
                    )));
                },
            };
            exports.insert(path, export);
        }

        Self::new(mast_forest, exports)
            .map_err(|err| DeserializationError::InvalidValue(format!("{err}")))
    }
}

#[cfg(feature = "serde")]
impl Serialize for Library {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        struct LibraryExports<'a>(&'a BTreeMap<Arc<Path>, LibraryExport>);
        impl Serialize for LibraryExports<'_> {
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
impl<'de> Deserialize<'de> for Library {
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
                let exports = exports.into_iter().map(|export| (export.path(), export)).collect();
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
                                items.into_iter().map(|export| (export.path(), export)).collect(),
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
        let library = Arc::new(Library::read_from(source)?);

        Self::try_from(library).map_err(|err| {
            DeserializationError::InvalidValue(format!(
                "Failed to deserialize kernel library: {err}"
            ))
        })
    }
}

/// NOTE: Deserialization is handled in the implementation for [Library]
impl Serializable for LibraryExport {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        match self {
            LibraryExport::Procedure(ProcedureExport {
                node,
                path: name,
                signature,
                attributes,
            }) => {
                target.write_u8(0);
                name.write_into(target);
                target.write_u32(u32::from(*node));
                if let Some(sig) = signature {
                    target.write_bool(true);
                    sig.write_into(target);
                } else {
                    target.write_bool(false);
                }
                attributes.write_into(target);
            },
            LibraryExport::Constant(ConstantExport { path: name, value }) => {
                target.write_u8(1);
                name.write_into(target);
                value.write_into(target);
            },
            LibraryExport::Type(TypeExport { path: name, ty }) => {
                target.write_u8(2);
                name.write_into(target);
                ty.write_into(target);
            },
        }
    }
}

#[cfg(feature = "arbitrary")]
impl Arbitrary for Library {
    type Parameters = ();

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        use miden_core::{
            mast::{BasicBlockNodeBuilder, MastForestContributor},
            operations::Operation,
        };
        use proptest::prelude::*;

        prop::collection::vec(any::<LibraryExport>(), 1..5)
            .prop_map(|exports| {
                let mut exports =
                    BTreeMap::from_iter(exports.into_iter().map(|export| (export.path(), export)));
                // Create a MastForest with actual nodes for the exports
                let mut mast_forest = MastForest::new();
                let mut nodes = Vec::new();

                for export in exports.values() {
                    if let LibraryExport::Procedure(export) = export {
                        let node_id = BasicBlockNodeBuilder::new(
                            vec![Operation::Add, Operation::Mul],
                            Vec::new(),
                        )
                        .add_to_forest(&mut mast_forest)
                        .unwrap();
                        nodes.push((export.node, node_id));
                    }
                }

                // Replace the export node IDs with the actual node IDs we created
                let mut procedure_exports = 0;
                for export in exports.values_mut() {
                    match export {
                        LibraryExport::Procedure(export) => {
                            procedure_exports += 1;
                            // Find the corresponding node we created
                            if let Some(&(_, actual_node_id)) =
                                nodes.iter().find(|(original_id, _)| *original_id == export.node)
                            {
                                export.node = actual_node_id;
                            } else {
                                // If we can't find the node (shouldn't happen), use the first node
                                // we created
                                if let Some(&(_, first_node_id)) = nodes.first() {
                                    export.node = first_node_id;
                                } else {
                                    // This should never happen since we create nodes for each
                                    // export
                                    panic!("No nodes created for exports");
                                }
                            }
                        },
                        LibraryExport::Constant(_) | LibraryExport::Type(_) => (),
                    }
                }

                let mut node_ids = Vec::with_capacity(procedure_exports);
                for export in exports.values() {
                    if let LibraryExport::Procedure(export) = export {
                        // Add the node to the forest roots if it's not already there
                        mast_forest.make_root(export.node);
                        // Collect the node id for recomputing the digest
                        node_ids.push(export.node);
                    }
                }

                // Recompute the digest
                let digest = mast_forest.compute_nodes_commitment(&node_ids);

                let mast_forest = Arc::new(mast_forest);
                Library { digest, exports, mast_forest }
            })
            .boxed()
    }

    type Strategy = BoxedStrategy<Self>;
}
