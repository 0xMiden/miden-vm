use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::fmt;

use miden_assembly_syntax::ast::{
    self, AttributeSet, Path,
    types::{FunctionType, Type},
};
#[cfg(all(feature = "arbitrary", test))]
use miden_core::serde::{Deserializable, Serializable};
use miden_core::{Word, mast::MastNodeId, utils::DisplayHex};
#[cfg(any(test, feature = "arbitrary"))]
use proptest::prelude::{Strategy, any};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Dependency, PackageId, debug_info::DebugSourceMastNodeId};

// PACKAGE MANIFEST
// ================================================================================================

/// The manifest of a package, containing the set of package dependencies (libraries or packages)
/// and exported items (procedures, constants, types), if known.
///
/// Exports declared in the package manifest are keyed by their fully-qualified path.
///
/// Dependencies must each specify a unique package identifier, i.e. it is not allowed to have
/// multiple dependencies on the same package identifier, even if they are different versions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(proptest_derive::Arbitrary))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true), serde_test(false))
)]
pub struct PackageManifest {
    /// The set of exports in this package.
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "proptest::collection::vec(any::<PackageExport>(), 1..10).prop_filter_map(\"package exports must have unique paths\", |exports| PackageManifest::new(exports).ok().map(|manifest| manifest.exports))"
        )
    )]
    pub(super) exports: BTreeMap<Arc<Path>, PackageExport>,
    /// The libraries (packages) linked against by this package, which must be provided when
    /// executing the program.
    pub(super) dependencies: Vec<Dependency>,
}

#[derive(Debug, Error)]
pub enum ManifestValidationError {
    #[error("duplicate export path '{0}' in package manifest")]
    DuplicateExport(Arc<Path>),
    #[error("duplicate dependency '{0}' in package manifest")]
    DuplicateDependency(PackageId),
    #[error(
        "package manifest declares export for procedure '{path}', but no procedure root with its digest was found in the MAST"
    )]
    MissingProcedureMast { path: Arc<Path>, digest: Word },
    #[error(
        "invalid procedure export '{path}': the declared node id and digest do not correspond to a procedure root in the MAST"
    )]
    InvalidProcedureExport { path: Arc<Path> },
    #[error("invalid export path '{path}': {error}")]
    InvalidExportPath { path: Arc<Path>, error: ast::PathError },
    #[error("package must contain at least one exported procedure")]
    NoProcedures,
}

impl PackageManifest {
    /// Construct a new [PackageManifest] by providing the set of exports for the corresponding
    /// package.
    pub fn new(
        exports: impl IntoIterator<Item = PackageExport>,
    ) -> Result<Self, ManifestValidationError> {
        let mut manifest = Self {
            exports: Default::default(),
            dependencies: Default::default(),
        };
        let mut has_procedures = false;
        for mut export in exports {
            if export.is_procedure() {
                has_procedures = true;
            }
            normalize_export(&mut export)?;
            manifest.add_export(export)?;
        }

        if !has_procedures {
            return Err(ManifestValidationError::NoProcedures);
        }

        Ok(manifest)
    }

    /// Extend this manifest with the provided dependencies
    pub fn with_dependencies(
        mut self,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Result<Self, ManifestValidationError> {
        for dependency in dependencies {
            self.add_dependency(dependency)?;
        }

        Ok(self)
    }

    /// Add a dependency to the manifest
    pub fn add_dependency(
        &mut self,
        dependency: Dependency,
    ) -> Result<(), ManifestValidationError> {
        if self.dependencies.iter().any(|existing| existing.id() == dependency.id()) {
            return Err(ManifestValidationError::DuplicateDependency(dependency.name));
        }

        self.dependencies.push(dependency);
        Ok(())
    }

    /// Get the number of dependencies of this package
    pub fn num_dependencies(&self) -> usize {
        self.dependencies.len()
    }

    /// Get an iterator over the dependencies of this package
    pub fn dependencies(&self) -> impl Iterator<Item = &Dependency> {
        self.dependencies.iter()
    }

    /// Get the number of items exported from this package
    pub fn num_exports(&self) -> usize {
        self.exports.len()
    }

    /// Get an iterator over the exports in this package
    pub fn exports(&self) -> impl Iterator<Item = &PackageExport> {
        self.exports.values()
    }

    /// Get information about an export by it's qualified name
    pub fn get_export(&self, name: impl AsRef<Path>) -> Option<&PackageExport> {
        self.exports.get(name.as_ref())
    }

    /// Get information about all exported procedures of this package with the given MAST root
    /// digest
    pub fn get_procedures_by_digest(
        &self,
        digest: &Word,
    ) -> impl Iterator<Item = &ProcedureExport> + '_ {
        let digest = *digest;
        self.exports.values().filter_map(move |export| match export {
            PackageExport::Procedure(export) if export.digest == digest => Some(export),
            PackageExport::Procedure(_) => None,
            PackageExport::Constant(_) | PackageExport::Type(_) => None,
        })
    }

    fn add_export(&mut self, export: PackageExport) -> Result<(), ManifestValidationError> {
        let path = export.path();
        if self.exports.insert(path.clone(), export).is_some() {
            return Err(ManifestValidationError::DuplicateExport(path));
        }

        Ok(())
    }
}

/// Represents a named item exported from a package.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub enum PackageExport {
    /// A procedure definition or alias with 'pub' visibility
    Procedure(ProcedureExport) = 1,
    /// A constant definition with 'pub' visibility
    Constant(ConstantExport),
    /// A type declaration with 'pub' visibility
    Type(TypeExport),
}

impl PackageExport {
    /// Get the path of this exported item
    pub fn path(&self) -> Arc<Path> {
        match self {
            Self::Procedure(export) => export.path.clone(),
            Self::Constant(export) => export.path.clone(),
            Self::Type(export) => export.path.clone(),
        }
    }

    /// Get the namespace of the exported item.
    ///
    /// For example, if `Self::path` returns the path `std::foo::NAME`, this returns `std::foo`.
    pub fn namespace(&self) -> &Path {
        match self {
            Self::Procedure(ProcedureExport { path, .. })
            | Self::Constant(ConstantExport { path, .. })
            | Self::Type(TypeExport { path, .. }) => path.parent().unwrap(),
        }
    }

    /// Get the name of the exported item without its namespace.
    ///
    /// For example, if `Self::path` returns the path `std::foo::NAME`, this returns just `NAME`.
    pub fn name(&self) -> &str {
        match self {
            Self::Procedure(ProcedureExport { path, .. })
            | Self::Constant(ConstantExport { path, .. })
            | Self::Type(TypeExport { path, .. }) => path.last().unwrap(),
        }
    }

    /// Returns true if this item is a procedure
    #[inline]
    pub fn is_procedure(&self) -> bool {
        matches!(self, Self::Procedure(_))
    }

    /// Returns true if this item is a constant
    #[inline]
    pub fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }

    /// Returns true if this item is a type declaration
    #[inline]
    pub fn is_type(&self) -> bool {
        matches!(self, Self::Type(_))
    }

    /// Returns true if this item is a procedure
    #[inline]
    pub fn as_procedure(&self) -> Option<&ProcedureExport> {
        match self {
            Self::Procedure(export) => Some(export),
            _ => None,
        }
    }

    /// Returns true if this item is a constant
    #[inline]
    pub fn as_constant(&self) -> Option<&ConstantExport> {
        match self {
            Self::Constant(export) => Some(export),
            _ => None,
        }
    }

    /// Returns true if this item is a type declaration
    #[inline]
    pub fn as_type(&self) -> Option<&TypeExport> {
        match self {
            Self::Type(export) => Some(export),
            _ => None,
        }
    }

    pub(crate) const fn tag(&self) -> u8 {
        // SAFETY: This is safe because we have given this enum a
        // primitive representation with #[repr(u8)], with the first
        // field of the underlying union-of-structs the discriminant
        //
        // See the section on "accessing the numeric value of the discriminant"
        // here: https://doc.rust-lang.org/std/mem/fn.discriminant.html
        unsafe { *(self as *const Self).cast::<u8>() }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl proptest::arbitrary::Arbitrary for PackageExport {
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

    type Strategy = proptest::prelude::BoxedStrategy<Self>;
}

/// A procedure exported by a package, along with its digest, signature, and attributes.
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct ProcedureExport {
    /// The fully-qualified path of the procedure exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(strategy = "miden_assembly_syntax::arbitrary::path::bare_path_random_length(2)")
    )]
    pub path: Arc<Path>,
    /// The id of the MAST root node corresponding to this procedure
    ///
    /// This is used for provenance, i.e. tracing which specific node in the package MAST this
    /// export corresponds to, when multiple exports may have the same digest (conversely, some
    /// procedure roots in the MAST may not be associated with any exports).
    ///
    /// Provenance is important because multiple logically distinct procedures may compile to the
    /// same MAST digest while retaining distinct export identities. The MAST uses executable node
    /// fingerprints to collapse equivalent nodes in the forest. The only way to guarantee that you
    /// will get the precise MAST node that corresponds to the specific procedure you've named is
    /// to use the MAST node, rather than the digest.
    ///
    /// NOTE: While one might get the impression that `MastNodeId` is a unique identifier for each
    /// procedure that gets assembled to the MAST, that isn't actually true. If multiple nodes have
    /// the same executable fingerprint, they may be collapsed into a single node in the MAST and
    /// have the same `MastNodeId`.
    ///
    /// If this field contains `None`, the digest is used to resolve a MAST node.
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "None"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub node: Option<MastNodeId>,
    /// Source/debug occurrence corresponding to this exported procedure, when package debug info
    /// is present.
    ///
    /// This disambiguates exports that collapse to the same executable [`MastNodeId`] but retain
    /// distinct source/debug metadata in the package-owned source occurrence graph.
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "None"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub source_node: Option<DebugSourceMastNodeId>,
    /// The digest of the procedure exported by this package.
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "Word::default()"))]
    pub digest: Word,
    /// The type signature of the exported procedure.
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "None"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature: Option<FunctionType>,
    /// Attributes attached to the exported procedure.
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "AttributeSet::default()"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub attributes: AttributeSet,
}

impl ProcedureExport {
    pub fn new(
        path: Arc<Path>,
        node: Option<MastNodeId>,
        digest: Word,
        signature: Option<FunctionType>,
    ) -> Self {
        Self {
            path,
            node,
            source_node: None,
            digest,
            signature,
            attributes: Default::default(),
        }
    }

    pub fn with_source_node(mut self, source_node: Option<DebugSourceMastNodeId>) -> Self {
        self.source_node = source_node;
        self
    }
}

impl fmt::Debug for ProcedureExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            path,
            node,
            source_node,
            digest,
            signature,
            attributes,
        } = self;
        f.debug_struct("PackageExport")
            .field("path", &format_args!("{path}"))
            .field("node", node)
            .field("source_node", source_node)
            .field("digest", &format_args!("{}", DisplayHex::new(&digest.as_bytes())))
            .field("signature", signature)
            .field("attributes", attributes)
            .finish()
    }
}

/// A constant definition exported by a package
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct ConstantExport {
    /// The fully-qualified path of the constant exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "miden_assembly_syntax::arbitrary::path::constant_path_random_length(1)"
        )
    )]
    pub path: Arc<Path>,
    /// The value of the exported constant
    ///
    /// We export a [ast::ConstantValue] here, rather than raw felts, because it is how a constant
    /// is used that determines its final concrete value, not the declaration itself. However,
    /// [ast::ConstantValue] does represent a concrete value, just one that requires context to
    /// fully evaluate.
    pub value: ast::ConstantValue,
}

impl fmt::Debug for ConstantExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { path, value } = self;
        f.debug_struct("ConstantExport")
            .field("path", &format_args!("{path}"))
            .field("value", value)
            .finish()
    }
}

/// A named type declaration exported by a package
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
    all(feature = "arbitrary", test),
    miden_test_serde_macros::serde_test(binary_serde(true))
)]
pub struct TypeExport {
    /// The fully-qualified path of the type exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        any(test, feature = "arbitrary"),
        proptest(
            strategy = "miden_assembly_syntax::arbitrary::path::user_defined_type_path_random_length(1)"
        )
    )]
    pub path: Arc<Path>,
    /// The type that was declared
    #[cfg_attr(any(test, feature = "arbitrary"), proptest(value = "Type::Felt"))]
    pub ty: Type,
}

impl fmt::Debug for TypeExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { path, ty } = self;
        f.debug_struct("TypeExport")
            .field("path", &format_args!("{path}"))
            .field("ty", ty)
            .finish()
    }
}

fn normalize_export(export: &mut PackageExport) -> Result<(), ManifestValidationError> {
    let canonical_path = canonicalize_export_path(export.path().as_ref())?;
    let leaf = export_raw_leaf(&canonical_path)?;

    match export {
        PackageExport::Procedure(proc) => {
            ast::ProcedureName::new(leaf).map_err(|err| {
                ManifestValidationError::InvalidExportPath {
                    path: proc.path.clone(),
                    error: ast::PathError::InvalidComponent(err),
                }
            })?;
            proc.path = canonical_path;
        },
        PackageExport::Constant(ConstantExport { path, .. })
        | PackageExport::Type(TypeExport { path, .. }) => {
            ast::Ident::new(leaf).map_err(|err| ManifestValidationError::InvalidExportPath {
                path: path.clone(),
                error: ast::PathError::InvalidComponent(err),
            })?;
            *path = canonical_path;
        },
    }

    Ok(())
}

fn canonicalize_export_path(path: &Path) -> Result<Arc<Path>, ManifestValidationError> {
    let canonical =
        path.canonicalize()
            .map_err(|error| ManifestValidationError::InvalidExportPath {
                error,
                path: path.to_path_buf().into(),
            })?;
    Ok(Arc::<Path>::from(canonical.into_boxed_path()))
}

fn export_raw_leaf(path: &Arc<Path>) -> Result<&str, ManifestValidationError> {
    use ast::PathComponent;
    match path.components().next_back() {
        Some(Ok(PathComponent::Normal(leaf))) => Ok(leaf),
        Some(Err(error)) => {
            Err(ManifestValidationError::InvalidExportPath { path: path.clone(), error })
        },
        Some(Ok(PathComponent::Root)) | None => Err(ManifestValidationError::InvalidExportPath {
            path: path.clone(),
            error: ast::PathError::Empty,
        }),
    }
}
