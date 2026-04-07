use alloc::{boxed::Box, sync::Arc, vec::Vec};

#[cfg(any(test, feature = "testing"))]
pub use miden_assembly_syntax::parser;
use miden_assembly_syntax::{
    Library, Parse, ParseOptions, Path, Word,
    ast::{Module, ModuleKind},
    debuginfo::{DefaultSourceManager, SourceManager},
    diagnostics::{
        Report,
        reporting::{ReportHandlerOpts, set_hook},
    },
};
pub use miden_assembly_syntax::{
    assert_diagnostic, assert_diagnostic_lines, parse_module, regex, source_file, testing::Pattern,
};
#[cfg(feature = "testing")]
use miden_assembly_syntax::{ast::Form, debuginfo::SourceFile};
use miden_core::program::Program;
#[cfg(feature = "std")]
use miden_project::TargetType;

use crate::assembler::Assembler;
#[cfg(feature = "std")]
use crate::diagnostics::reporting::set_panic_hook;

/// A [TestContext] provides common functionality for all tests which interact with an [Assembler].
///
/// It is used by constructing it with `TestContext::default()`, which will initialize the
/// diagnostic reporting infrastructure, and construct a default [Assembler] instance for you. You
/// can then optionally customize the context, or start invoking any of its test helpers.
///
/// Some of the assertion macros defined above require a [TestContext], so be aware of that.
pub struct TestContext {
    source_manager: Arc<dyn SourceManager>,
    assembler: Assembler,
    #[cfg(feature = "std")]
    registry: TestRegistry,
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TestContext {
    pub fn new() -> Self {
        #[cfg(feature = "logging")]
        {
            // Enable debug tracing to stderr via the MIDEN_LOG environment variable, if present
            let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
        }

        #[cfg(feature = "std")]
        {
            let result = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
            #[cfg(feature = "std")]
            if result.is_ok() {
                set_panic_hook();
            }
        }

        #[cfg(not(feature = "std"))]
        {
            let _ = set_hook(Box::new(|_| Box::new(ReportHandlerOpts::new().build())));
        }
        let source_manager = Arc::new(DefaultSourceManager::default());
        let assembler = Assembler::new(source_manager.clone()).with_warnings_as_errors(true);
        #[cfg(feature = "std")]
        {
            Self {
                source_manager,
                assembler,
                registry: Default::default(),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            Self { source_manager, assembler }
        }
    }

    #[inline]
    fn assembler(&self) -> Assembler {
        self.assembler.clone()
    }

    #[inline(always)]
    pub fn source_manager(&self) -> Arc<dyn SourceManager> {
        self.source_manager.clone()
    }

    /// Parse the given source file into a vector of top-level [Form]s.
    ///
    /// This does not run semantic analysis, or construct a [Module] from the parsed
    /// forms, and is largely intended for low-level testing of the parser.
    #[cfg(feature = "testing")]
    #[track_caller]
    pub fn parse_forms(&self, source: Arc<SourceFile>) -> Result<Vec<Form>, Report> {
        parser::parse_forms(source.clone()).map_err(|err| Report::new(err).with_source_code(source))
    }

    /// Parse the given source file into an executable [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_program(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..Default::default()
            },
        )
    }

    /// Parse the given source file into a kernel [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_kernel(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::for_kernel()
            },
        )
    }

    /// Parse the given source file into an anonymous library [Module].
    ///
    /// This runs semantic analysis, and the returned module is guaranteed to be syntactically
    /// valid.
    #[track_caller]
    pub fn parse_module(&self, source: impl Parse) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::for_library()
            },
        )
    }

    /// Parse the given source file into a library [Module] with the given fully-qualified path.
    #[track_caller]
    pub fn parse_module_with_path(
        &self,
        path: impl AsRef<Path>,
        source: impl Parse,
    ) -> Result<Box<Module>, Report> {
        source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                warnings_as_errors: self.assembler.warnings_as_errors(),
                ..ParseOptions::new(ModuleKind::Library, path.as_ref().to_absolute())
            },
        )
    }

    /// Add `module` to the [Assembler] constructed by this context, making it available to
    /// other modules.
    #[track_caller]
    pub fn add_module(&mut self, module: impl Parse) -> Result<(), Report> {
        self.assembler.compile_and_statically_link(module).map(|_| ())
    }

    /// Add a module to the [Assembler] constructed by this context, with the fully-qualified
    /// name `path`, by parsing it from the provided source file.
    ///
    /// This will fail if the module cannot be parsed, fails semantic analysis, or conflicts
    /// with a previously added module within the assembler.
    #[track_caller]
    pub fn add_module_from_source(
        &mut self,
        path: impl AsRef<Path>,
        source: impl Parse,
    ) -> Result<(), Report> {
        let module = source.parse_with_options(
            self.source_manager.clone(),
            ParseOptions {
                path: Some(path.as_ref().to_absolute().into_owned().into()),
                ..ParseOptions::for_library()
            },
        )?;
        self.assembler.compile_and_statically_link(module).map(|_| ())
    }

    /// Add the modules of `library` to the [Assembler] constructed by this context.
    #[track_caller]
    pub fn add_library(&mut self, library: impl AsRef<Library>) -> Result<(), Report> {
        self.assembler.link_dynamic_library(library)
    }

    /// Compile a [Program] from `source` using the [Assembler] constructed by this context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the executable
    /// module represented in `source`.
    #[track_caller]
    pub fn assemble(&self, source: impl Parse) -> Result<Program, Report> {
        self.assembler().assemble_program(source)
    }

    /// Compile a [Library] from `modules` using the [Assembler] constructed by this
    /// context.
    ///
    /// NOTE: Any modules added by, e.g. `add_module`, will be available to the library
    #[track_caller]
    pub fn assemble_library(
        &self,
        modules: impl IntoIterator<Item = Box<Module>>,
    ) -> Result<Library, Report> {
        self.assembler().assemble_library(modules)
    }

    /// Compile a module from `source`, with the fully-qualified name `path`, to MAST, returning
    /// the MAST roots of all the exported procedures of that module.
    #[track_caller]
    pub fn assemble_module(
        &self,
        _path: impl AsRef<Path>,
        _module: impl Parse,
    ) -> Result<Vec<Word>, Report> {
        // This API will change after we implement `Assembler::add_library()`
        unimplemented!()
    }
}

#[cfg(feature = "std")]
pub use self::package_features::TestRegistry;

#[cfg(feature = "std")]
mod package_features {
    use std::{
        collections::BTreeMap,
        string::String,
        sync::{Arc, Mutex},
    };

    use miden_mast_package::{Package, PackageId};
    use miden_package_registry::{
        PackageIndex, PackageProvider, PackageRecord, PackageRegistry, PackageStore,
        PackageVersions, Version, VersionRequirement,
    };

    use super::*;
    use crate::ProjectTargetSelector;

    /// A simple in-memory package index/registry
    #[derive(Default)]
    pub struct TestRegistry {
        index: BTreeMap<PackageId, PackageVersions>,
        packages: BTreeMap<(PackageId, Version), Arc<Package>>,
        loads: Mutex<Vec<String>>,
    }

    impl TestRegistry {
        pub fn add_package(&mut self, package: Arc<Package>) -> Version {
            let version =
                miden_package_registry::Version::new(package.version.clone(), package.digest());
            self.publish_package(package).expect("failed to add test package");
            version
        }

        pub fn loaded_packages(&self) -> Vec<String> {
            self.loads.lock().unwrap().clone()
        }

        pub fn clear_loaded_packages(&self) {
            self.loads.lock().unwrap().clear();
        }

        pub fn remove_package(
            &mut self,
            package: &PackageId,
            version: &Version,
        ) -> Option<Arc<Package>> {
            self.packages.remove(&(package.clone(), version.clone()))
        }
    }

    impl PackageRegistry for TestRegistry {
        fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
            self.index.get(package)
        }
    }

    impl PackageIndex for TestRegistry {
        type Error = Report;

        fn register(&mut self, name: PackageId, record: PackageRecord) -> Result<(), Self::Error> {
            use std::collections::btree_map::Entry;

            let semver = record.semantic_version().clone();
            match self.index.entry(name.clone()).or_default().entry(semver.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(record);
                    Ok(())
                },
                Entry::Occupied(_) => Err(Report::msg(format!(
                    "package '{}' version '{}' is already registered",
                    name, semver
                ))),
            }
        }
    }

    impl PackageProvider for TestRegistry {
        fn load_package(
            &self,
            package: &PackageId,
            version: &Version,
        ) -> Result<Arc<Package>, Report> {
            self.loads.lock().unwrap().push(format!("{package}@{version}"));
            self.packages.get(&(package.clone(), version.clone())).cloned().ok_or_else(|| {
                Report::msg(format!("missing test package '{package}' at '{version}'"))
            })
        }
    }

    impl PackageStore for TestRegistry {
        type Error = Report;

        fn publish_package(&mut self, package: Arc<Package>) -> Result<Version, Self::Error> {
            let version =
                miden_package_registry::Version::new(package.version.clone(), package.digest());
            let dependencies = package
                .manifest
                .dependencies()
                .map(|dependency| {
                    let version = Version::new(dependency.version.clone(), dependency.digest);
                    if self.get_exact_version(&dependency.name, &version).is_none() {
                        return Err(Report::msg(format!(
                            "missing dependency '{}' at '{}'",
                            dependency.name, version
                        )));
                    }
                    Ok((dependency.name.clone(), VersionRequirement::Exact(version)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let record = PackageRecord::new(version.clone(), dependencies)
                .with_description(package.description.clone().unwrap_or_default());
            self.register(package.name.clone(), record)?;
            self.packages.insert((package.name.clone(), version.clone()), package);
            Ok(version)
        }
    }

    impl TestContext {
        pub fn registry(&self) -> &TestRegistry {
            &self.registry
        }

        pub fn registry_mut(&mut self) -> &mut TestRegistry {
            &mut self.registry
        }

        pub fn project_assembler_for_path<'a>(
            &'a mut self,
            manifest_path: impl AsRef<std::path::Path>,
        ) -> Result<crate::ProjectAssembler<'a, TestRegistry>, Report> {
            self.assembler().for_project_at_path(manifest_path, &mut self.registry)
        }

        pub fn project_assembler<'a>(
            &'a mut self,
            project: Arc<miden_project::Package>,
        ) -> Result<crate::ProjectAssembler<'a, TestRegistry>, Report> {
            self.assembler().for_project(project, &mut self.registry)
        }

        /// Assembles the library target of the package at `manifest_path`, using `profile`.
        ///
        /// If `profile` is `None`, the `dev` profile will be used.
        ///
        /// This requires that the referenced package define a library target, or an error will be
        /// raised.
        pub fn assemble_library_package(
            &mut self,
            manifest_path: impl AsRef<std::path::Path>,
            profile: Option<&str>,
        ) -> Result<Arc<Package>, Report> {
            let assembler = self.assembler();
            let mut project_assembler =
                assembler.for_project_at_path(manifest_path, &mut self.registry)?;
            project_assembler.assemble(ProjectTargetSelector::Library, profile.unwrap_or("dev"))
        }

        /// Assembles the executable target `name` of the package from `manifest_path`, using
        /// `profile`.
        ///
        /// If `name` is `None`, the default executable target name is selected.
        ///
        /// If `profile` is `None`, the `dev` profile will be used.
        ///
        /// This requires that the referenced package define the given executable target, or an
        /// error will be raised.
        pub fn assemble_executable_package(
            &mut self,
            manifest_path: impl AsRef<std::path::Path>,
            name: Option<&str>,
            profile: Option<&str>,
        ) -> Result<Arc<Package>, Report> {
            let assembler = self.assembler();
            let mut project_assembler =
                assembler.for_project_at_path(manifest_path, &mut self.registry)?;
            project_assembler.assemble(
                ProjectTargetSelector::Executable(name.unwrap_or(Path::EXEC_PATH)),
                profile.unwrap_or("dev"),
            )
        }

        /// Assembles a package named `name` with `version` and `dependencies`, containing a single
        /// export whose path is `export`.
        ///
        /// The exported procedure is defined as follows, given an `export` path of `foo::bar`:
        ///
        /// ```text,ignore
        /// pub proc bar
        ///     add
        /// end
        /// ```
        pub fn assemble_library_package_with_export<'a>(
            &self,
            name: &str,
            version: &str,
            export: &str,
            dependencies: impl IntoIterator<Item = (&'static str, &'a str, TargetType, Word)>,
        ) -> Box<miden_mast_package::Package> {
            use alloc::string::ToString;

            use miden_assembly_syntax::source_file;
            use miden_mast_package::Dependency;

            let export_path = Path::new(export);
            let (export_leaf, export_module) = export_path.split_last().unwrap();
            let source_file = source_file!(self, format!("pub proc {export_leaf} add end"));
            let module = Module::parse(
                export_module,
                ModuleKind::Library,
                source_file,
                self.source_manager(),
            )
            .unwrap();
            let library = self.assemble_library([module]).expect("failed to assemble library");

            Package::from_library(
                name.into(),
                version.parse().unwrap(),
                TargetType::Library,
                Arc::new(library),
                dependencies.into_iter().map(|(name, version, kind, digest)| Dependency {
                    name: name.into(),
                    version: version.parse().unwrap(),
                    kind,
                    digest,
                }),
            )
        }
    }
}
