//! The package post-processing hook of the project assembler.
//!
//! A caller registers a [`PackagePostProcessor`] to transform every package the project
//! assembler builds, for example to attach a package section the assembler knows nothing about.

use super::*;

/// Context given to [`PackagePostProcessor`] implementations.
///
/// The context borrows the [`TargetAssemblyContext`] of the target that produced the package.
/// That context carries the resolved package manifest (`assembly.package`), the manifest and
/// project paths, the target, and the build profile, so a processor can read project
/// configuration such as `[package.metadata.*]` tables.
pub struct PostProcessContext<'a> {
    /// The assembly context of the target that produced the package under post-processing.
    pub assembly: &'a TargetAssemblyContext<'a>,
}

/// A hook that transforms an assembled package before the project assembler freezes it.
///
/// The project assembler runs every registered processor after the source provider's own
/// [`ProjectSourceProvider::post_process_package`] hook, in registration order, and before the
/// package enters the package cache/registry. Processors run only on the packages of the
/// project under assembly, never on source dependencies (see
/// [`ProjectAssembler::with_package_post_processor`]). The assembler registers no processor by
/// default; callers opt in with that method.
///
/// A processor must be generic infrastructure from the assembler's point of view: the assembler
/// knows nothing about what a processor adds to a package. Domain-specific knowledge (for
/// example, custom package sections) belongs in the crate that implements the processor.
pub trait PackagePostProcessor {
    /// Transforms `package` in place.
    ///
    /// # Errors
    /// Returns an error to fail the assembly of the target. The project assembler stops at the
    /// first processor that fails and does not run the remaining processors.
    fn post_process(
        &self,
        package: &mut MastPackage,
        context: &PostProcessContext<'_>,
    ) -> Result<(), Report>;
}
