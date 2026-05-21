mod masm;

use miden_assembly_syntax::debuginfo::SourceManager;
use miden_project::ProjectDependencyGraph;

pub use self::masm::MasmSourceProvider;
use super::*;

/// This struct provides important context about the current target being assembled to
/// implementations of the [ProjectSourceProvider] trait.
pub struct TargetAssemblyContext<'a> {
    /// The package manifest for the target being assembled
    pub package: &'a ProjectPackage,
    /// The resolved/canonicalized package manifest path
    pub manifest_path: &'a std::path::Path,
    /// The resolved/canonicalized path to the directory containing `manifest_path`
    pub project_root: &'a std::path::Path,
    /// The resolved/canonicalized path to the root source file of `target`
    pub resolved_target_root: &'a std::path::Path,
    /// The target being assembled
    pub target: &'a Target,
    /// The build profile selected for this assembly session
    pub profile: &'a Profile,
    /// The dependency graph computed for this assembly session
    pub dependency_graph: &'a ProjectDependencyGraph,
    /// The current source manager
    pub source_manager: Arc<dyn SourceManager>,
    /// The assembler-wide `warnings_as_errors` flag
    pub warnings_as_errors: bool,
}

/// This trait provides source file inputs for a Miden Assembly project, regardless of the source
/// language it was derived from.
///
/// For Miden Assembly source projects this is straightforward, see [MasmSourceProvider].
///
/// For languages other than MASM, which require a compilation step to produce Miden Assembly AST
/// from the source language prior to assembly, this trait provides the necessary hooks so that
/// the project assembler can request compilation of a project in source form on-demand.
/// Implementors are given all available information needed to compile to MASM, and are expected
/// to return requested artifacts to the project assembler.
///
/// Source providers are registered by the file type (i.e. file extension used by the source file)
/// with the assembler when it is created. Only one source provider per-file-type is allowed.
pub trait ProjectSourceProvider {
    /// Returns the file extension this provider should be registered as handling, e.g. `rs`
    fn file_type(&self) -> &'static str;
    /// Called to request the compiled/parsed Miden Assembly AST corresponding to the current target
    /// being assembled.
    fn provide_sources(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceInputs, Report>;
    /// Called to request the source files that are inputs to assembly of the current target, so
    /// that source provenance hash for the target can be computed.
    ///
    /// It is expected that all source files that contribute to the build be included in the set
    /// of source inputs returned, otherwise package identity for the assembled target will be
    /// incomplete, and another instance of the same package may be used from the cache if the
    /// source provenance appears unchanged, even when the artifacts produced would be different.
    ///
    /// For MASM packages, the above is already guaranteed - but for compilation of packages in
    /// other languages, such as Rust, the toolchain invoking the assembler must ensure that all
    /// build inputs are accounted for. Note that you _do not_ need to include the sources of
    /// your Miden dependencies, and non-Miden dependencies can be accounted for by hashing a
    /// dependency lock file if present (e.g. `Cargo.toml`).
    fn provide_source_provenance(
        &self,
        context: &TargetAssemblyContext<'_>,
    ) -> Result<ProjectSourceProvenanceInputs, Report>;
}
