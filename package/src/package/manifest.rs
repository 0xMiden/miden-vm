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
    pub exports: BTreeMap<QualifiedProcedureName, PackageExport>,
    /// The libraries (packages) linked against by this package, which must be provided when
    /// executing the program.
    pub dependencies: Vec<Dependency>,
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
