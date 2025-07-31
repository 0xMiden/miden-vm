use alloc::{collections::BTreeMap, vec::Vec};
use core::fmt;

use miden_assembly_syntax::ast::{QualifiedProcedureName, types::FunctionType};
use miden_core::{Word, utils::DisplayHex};

use crate::Dependency;

// PACKAGE MANIFEST
// ================================================================================================

/// The manifest of a package, containing the set of package dependencies (libraries or packages)
/// and exported procedures and their signatures, if known.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct PackageManifest {
    /// The set of exports in this package.
    pub(super) exports: BTreeMap<QualifiedProcedureName, PackageExport>,
    /// The libraries (packages) linked against by this package, which must be provided when
    /// executing the program.
    pub(super) dependencies: Vec<Dependency>,
}

impl PackageManifest {
    pub fn new(exports: impl IntoIterator<Item = PackageExport>) -> Self {
        let exports = exports.into_iter().map(|export| (export.name.clone(), export)).collect();
        Self {
            exports,
            dependencies: Default::default(),
        }
    }

    /// Extend this manifest with the provided dependencies
    pub fn with_dependencies(mut self, dependencies: impl IntoIterator<Item = Dependency>) -> Self {
        self.dependencies.extend(dependencies);
        self
    }

    /// Add a dependency to the manifest
    pub fn add_dependency(&mut self, dependency: Dependency) {
        self.dependencies.push(dependency);
    }

    /// Get the number of dependencies of this package
    pub fn num_dependencies(&self) -> usize {
        self.dependencies.len()
    }

    /// Get an iterator over the dependencies of this package
    pub fn dependencies(&self) -> impl Iterator<Item = &Dependency> {
        self.dependencies.iter()
    }

    /// Get the number of procedures exported from this package
    pub fn num_exports(&self) -> usize {
        self.exports.len()
    }

    /// Get an iterator over the exports in this package
    pub fn exports(&self) -> impl Iterator<Item = &PackageExport> {
        self.exports.values()
    }

    /// Get information about an export by it's qualified name
    pub fn get_export(&self, name: &QualifiedProcedureName) -> Option<&PackageExport> {
        self.exports.get(name)
    }

    /// Get information about all exports of this package with the given MAST root digest
    pub fn get_exports_by_digest(
        &self,
        digest: &Word,
    ) -> impl Iterator<Item = &PackageExport> + '_ {
        let digest = *digest;
        self.exports.values().filter(move |export| export.digest == digest)
    }
}

/// A procedure exported by a package, along with its digest and signature (will be added after
/// MASM type attributes are implemented).
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct PackageExport {
    /// The fully-qualified name of the procedure exported by this package
    pub name: QualifiedProcedureName,
    /// The digest of the procedure exported by this package
    #[cfg_attr(feature = "arbitrary", proptest(value = "Word::default()"))]
    pub digest: Word,
    /// The type signature of the exported procedure
    #[cfg_attr(feature = "arbitrary", proptest(value = "None"))]
    pub signature: Option<FunctionType>,
}

impl fmt::Debug for PackageExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { name, digest, signature } = self;
        f.debug_struct("PackageExport")
            .field("name", &format_args!("{name}"))
            .field("digest", &format_args!("{}", DisplayHex::new(&digest.as_bytes())))
            .field("signature", signature)
            .finish()
    }
}
