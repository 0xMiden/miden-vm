use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::fmt;

use miden_assembly_syntax::ast::{
    self, AttributeSet, Path,
    types::{FunctionType, Type},
};
use miden_core::{Word, utils::DisplayHex};
#[cfg(feature = "arbitrary")]
use proptest::prelude::{Strategy, any};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::Dependency;

// PACKAGE MANIFEST
// ================================================================================================

/// The manifest of a package, containing the set of package dependencies (libraries or packages)
/// and exported items (procedures, constants, types), if known.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
pub struct PackageManifest {
    /// The set of exports in this package.
    #[cfg_attr(
        feature = "arbitrary",
        proptest(
            strategy = "proptest::collection::vec(any::<PackageExport>(), 1..10).prop_map(|exports| PackageManifest::new(exports).exports)"
        )
    )]
    pub(super) exports: BTreeMap<Arc<Path>, PackageExport>,
    /// The libraries (packages) linked against by this package, which must be provided when
    /// executing the program.
    pub(super) dependencies: Vec<Dependency>,
}

impl PackageManifest {
    pub fn new(exports: impl IntoIterator<Item = PackageExport>) -> Self {
        let exports = exports.into_iter().map(|export| (export.path(), export)).collect();
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
}

/// Represents a named item exported from a package.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
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

#[cfg(feature = "arbitrary")]
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
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ProcedureExport {
    /// The fully-qualified path of the procedure exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        feature = "arbitrary",
        proptest(strategy = "miden_assembly_syntax::arbitrary::path::bare_path_random_length(2)")
    )]
    pub path: Arc<Path>,
    /// The digest of the procedure exported by this package.
    #[cfg_attr(feature = "arbitrary", proptest(value = "Word::default()"))]
    pub digest: Word,
    /// The type signature of the exported procedure.
    #[cfg_attr(feature = "arbitrary", proptest(value = "None"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub signature: Option<FunctionType>,
    /// Attributes attached to the exported procedure.
    #[cfg_attr(feature = "arbitrary", proptest(value = "AttributeSet::default()"))]
    #[cfg_attr(feature = "serde", serde(default))]
    pub attributes: AttributeSet,
}

impl fmt::Debug for ProcedureExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { path, digest, signature, attributes } = self;
        f.debug_struct("PackageExport")
            .field("path", &format_args!("{path}"))
            .field("digest", &format_args!("{}", DisplayHex::new(&digest.as_bytes())))
            .field("signature", signature)
            .field("attributes", attributes)
            .finish()
    }
}

/// A constant definition exported by a package
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct ConstantExport {
    /// The fully-qualified path of the constant exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        feature = "arbitrary",
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
#[cfg_attr(feature = "arbitrary", derive(proptest_derive::Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(all(feature = "arbitrary", test), miden_test_serde_macros::serde_test)]
pub struct TypeExport {
    /// The fully-qualified path of the type exported by this package.
    #[cfg_attr(feature = "serde", serde(with = "miden_assembly_syntax::ast::path"))]
    #[cfg_attr(
        feature = "arbitrary",
        proptest(
            strategy = "miden_assembly_syntax::arbitrary::path::user_defined_type_path_random_length(1)"
        )
    )]
    pub path: Arc<Path>,
    /// The type that was declared
    #[cfg_attr(feature = "arbitrary", proptest(value = "Type::Felt"))]
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
