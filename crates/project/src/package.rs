use alloc::boxed::Box;
#[cfg(feature = "std")]
use std::path::Path;

#[cfg(all(feature = "std", feature = "serde"))]
use miden_assembly_syntax::debuginfo::Spanned;
use miden_mast_package::PackageId;

#[cfg(all(feature = "std", feature = "serde"))]
use crate::ast::{ProjectFileError, WorkspaceFile};
use crate::*;

/// The representation of an individual package in a Miden project
#[derive(Debug)]
pub struct Package {
    /// The file path of the manifest corresponding to this package metadata, if applicable.
    #[cfg(feature = "std")]
    manifest_path: Option<Box<Path>>,
    /// The name of the package
    name: Span<PackageId>,
    /// The semantic version associated with the package
    version: Span<SemVer>,
    /// The optional package description
    description: Option<Arc<str>>,
    /// The set of dependencies required by this package
    dependencies: Vec<Dependency>,
    /// The lint configuration specific to this package.
    ///
    /// By default, this is empty.
    lints: MetadataSet,
    /// The set of custom metadata attached to this package.
    ///
    /// By default, this is empty.
    metadata: MetadataSet,
    /// The library target for this package, if specified.
    lib: Option<Span<Target>>,
    /// The executable targets available for this package.
    bins: Vec<Span<Target>>,
    /// The build profiles configured for this package.
    profiles: Vec<Profile>,
}

/// Constructor
impl Package {
    /// Create a new [Package] named `name` with the given default target.
    ///
    /// The resulting package will have a default version of `0.0.0`, no dependencies, and an
    /// initial set of profiles that consist of the default development and release profiles. The
    /// project will have no other configuration set up - that must be done in subsequent steps.
    pub fn new(name: impl Into<PackageId>, default_target: Target) -> Box<Self> {
        let name = name.into();
        let (lib, bins) = if default_target.is_library() {
            (Some(Span::unknown(default_target)), vec![])
        } else {
            (None, vec![Span::unknown(default_target)])
        };
        let profiles = vec![Profile::default(), Profile::release()];
        Box::new(Self {
            #[cfg(feature = "std")]
            manifest_path: None,
            name: Span::unknown(name),
            version: Span::unknown(SemVer::new(0, 0, 0)),
            description: None,
            dependencies: Default::default(),
            lints: Default::default(),
            metadata: Default::default(),
            lib,
            bins,
            profiles,
        })
    }

    /// Specify a version for this package during initial construction
    pub fn with_version(mut self: Box<Self>, version: SemVer) -> Box<Self> {
        *self.version = version;
        self
    }

    /// Provide the lint configuration for this package during initial construction
    pub fn with_lints(mut self: Box<Self>, lints: MetadataSet) -> Box<Self> {
        self.lints = lints;
        self
    }

    /// Provide the metadata for this package during initial construction
    pub fn with_metadata(mut self: Box<Self>, metadata: MetadataSet) -> Box<Self> {
        self.metadata = metadata;
        self
    }

    /// Add targets to this package during initial construction
    ///
    /// This function will panic if any of the given targets conflict with existing targets or
    /// each other.
    pub fn with_targets(
        mut self: Box<Self>,
        targets: impl IntoIterator<Item = Target>,
    ) -> Box<Self> {
        for target in targets {
            if target.is_library() {
                assert!(self.lib.is_none(), "a package cannot have duplicate library targets");
                self.lib = Some(Span::unknown(target));
            } else {
                if self.bins.iter().any(|t| t.name == target.name) {
                    panic!("duplicate definitions of the same target '{}'", &target.name);
                }
                self.bins.push(Span::unknown(target));
            }
        }
        self
    }

    /// Add a profile to this package during initial construction
    ///
    /// If the given profile matches an existing profile, it will be merged over the top of it.
    pub fn with_profile(mut self: Box<Self>, profile: Profile) -> Box<Self> {
        for existing in self.profiles.iter_mut() {
            if existing.name() == profile.name() {
                existing.merge(&profile);
                return self;
            }
        }

        self.profiles.push(profile);
        self
    }

    /// Add dependencies to this package during initial construction
    ///
    /// This function will panic if any of the given dependencies conflict with existing deps or
    /// each other.
    pub fn with_dependencies(
        mut self: Box<Self>,
        dependencies: impl IntoIterator<Item = Dependency>,
    ) -> Box<Self> {
        for dependency in dependencies {
            if self.dependencies().iter().any(|dep| dep.name() == dependency.name()) {
                panic!("duplicate definitions of dependency '{}'", dependency.name());
            }
            self.dependencies.push(dependency);
        }

        self
    }
}

/// Accessors
impl Package {
    /// Get the name of this package
    pub fn name(&self) -> Span<PackageId> {
        self.name.clone()
    }

    /// Get the semantic version of this package
    pub fn version(&self) -> Span<&SemVer> {
        self.version.as_ref()
    }

    /// Get the description of this package, if specified
    pub fn description(&self) -> Option<Arc<str>> {
        self.description.clone()
    }

    /// Set the description of this package, if specified
    pub fn set_description(&mut self, description: impl Into<Arc<str>>) {
        self.description = Some(description.into());
    }

    /// Get the set of dependencies this package requires
    pub fn dependencies(&self) -> &[Dependency] {
        &self.dependencies
    }

    /// Get the number of dependencies this package requires
    pub fn num_dependencies(&self) -> usize {
        self.dependencies.len()
    }

    /// Get a reference to the linter metadata configured for this package
    pub fn lints(&self) -> &MetadataSet {
        &self.lints
    }

    /// Get a reference to the custom metadata configured for this package
    pub fn metadata(&self) -> &MetadataSet {
        &self.metadata
    }

    /// Get a reference to the build profiles configured for this package
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }

    /// Returns a profile with the specified name, or None if such a profile does not exist in this
    /// package.
    pub fn get_profile(&self, name: &str) -> Option<&Profile> {
        self.profiles().iter().find(|profile| profile.name().as_ref() == name)
    }

    /// Get a reference to the library build target provided by this package
    pub fn library_target(&self) -> Option<&Span<Target>> {
        self.lib.as_ref()
    }

    /// Get a reference to the executable build targets provided by this package
    pub fn executable_targets(&self) -> &[Span<Target>] {
        &self.bins
    }

    /// Get the location of the manifest this package was loaded from, if known/applicable.
    #[cfg(feature = "std")]
    pub fn manifest_path(&self) -> Option<&Path> {
        self.manifest_path.as_deref()
    }
}

/// Parsing
#[cfg(all(feature = "std", feature = "serde"))]
impl Package {
    /// Load a package from `source`, expected to be a standalone package-level `miden-project.toml`
    /// manifest.
    pub fn load(source: Arc<SourceFile>) -> Result<Box<Self>, Report> {
        Self::parse(source, None)
    }

    /// Load a package from `source`, expected to be a package-level `miden-project.toml` manifest
    /// which is presumed to be a member of `workspace` for purposes of configuration inheritance.
    pub fn load_from_workspace(
        source: Arc<SourceFile>,
        workspace: &WorkspaceFile,
    ) -> Result<Box<Self>, Report> {
        Self::parse(source, Some(workspace))
    }

    fn parse(
        source: Arc<SourceFile>,
        workspace: Option<&WorkspaceFile>,
    ) -> Result<Box<Self>, Report> {
        let manifest_path = Path::new(source.uri().path());
        let manifest_path = if manifest_path.try_exists().is_ok_and(|exists| exists) {
            Some(manifest_path.to_path_buf().into_boxed_path())
        } else {
            None
        };

        // Parse the manifest into an AST for further processing
        let package_ast = ast::ProjectFile::parse(source.clone())?;

        // Extract metadata that can be inherited from the workspace manifest (if present)
        let version = package_ast.get_or_inherit_version(source.clone(), workspace)?;
        let description = package_ast.get_or_inherit_description(source.clone(), workspace)?;

        // Compute the set of initial profiles inheritable from the workspace level
        let mut profiles = Vec::default();
        profiles.push(Profile::default());
        profiles.push(Profile::release());
        if let Some(workspace) = workspace {
            for ast in workspace.profiles.iter() {
                let profile = Profile::from_ast(ast, source.clone(), &profiles)?;
                if let Some(prev) = profiles.iter_mut().find(|p| p.name() == ast.name.inner()) {
                    *prev = profile;
                } else {
                    profiles.push(profile);
                }
            }
        }

        // Compute the effective profiles for this project, merging over the top of workspace-level
        // profiles, but raising an error if the same profile is mentioned twice in the current
        // project file.
        let package_profiles_start = profiles.len();
        for ast in package_ast.profiles.iter() {
            let profile = Profile::from_ast(ast, source.clone(), &profiles)?;

            if let Some(prev_index) = profiles.iter().position(|p| p.name() == profile.name()) {
                if prev_index < package_profiles_start {
                    profiles[prev_index].merge(&profile);
                } else {
                    let prev = &profiles[prev_index];
                    return Err(ProjectFileError::DuplicateProfile {
                        name: prev.name().clone(),
                        source_file: source,
                        span: profile.span(),
                        prev: prev.span(),
                    }
                    .into());
                }
            } else {
                profiles.push(profile);
            }
        }

        // Extract project dependencies, using the workspace to resolve workspace-relative
        // dependencies
        let dependencies = package_ast.extract_dependencies(source.clone(), workspace)?;

        // Extract the build targets for this project
        let lib = package_ast.extract_library_target()?;
        let bins = package_ast.extract_executable_targets();

        let mut lints = workspace.map(|ws| ws.workspace.config.lints.clone()).unwrap_or_default();
        lints.extend(package_ast.config.lints.clone());

        let mut metadata =
            workspace.map(|ws| ws.workspace.package.metadata.clone()).unwrap_or_default();
        metadata.extend(package_ast.package.detail.metadata.clone());

        Ok(Box::new(Self {
            manifest_path,
            name: package_ast.package.name.map(Into::into),
            version,
            description,
            dependencies,
            lints,
            metadata,
            profiles,
            lib,
            bins,
        }))
    }
}

#[cfg(feature = "serde")]
impl Package {
    /// Pretty print this [Package] in TOML format.
    ///
    /// The output of this function is not guaranteed to be identical to the way the original
    /// manifest (if one exists) was written, i.e. it may emit keys that are optional or that
    /// contain default or inherited values.
    pub fn to_toml(&self) -> Result<alloc::string::String, Report> {
        let manifest_ast = ast::ProjectFile {
            source_file: None,
            package: ast::PackageTable {
                name: self.name().map(PackageId::into_inner),
                detail: ast::PackageDetail {
                    version: Some(
                        self.version().map(|v| ast::parsing::MaybeInherit::Value(v.clone())),
                    ),
                    description: self
                        .description()
                        .map(ast::parsing::MaybeInherit::Value)
                        .map(Span::unknown),
                    metadata: self.metadata.clone(),
                },
            },
            config: ast::PackageConfig {
                dependencies: self
                    .dependencies()
                    .iter()
                    .map(|dep| {
                        let name = Span::unknown(dep.name().clone());
                        let linkage = if matches!(dep.linkage(), Linkage::Dynamic) {
                            None
                        } else {
                            Some(Span::unknown(dep.linkage()))
                        };
                        let spec = match dep.scheme() {
                            DependencyVersionScheme::Workspace { .. } => ast::DependencySpec {
                                name: name.clone(),
                                version_or_digest: None,
                                workspace: true,
                                path: None,
                                git: None,
                                branch: None,
                                rev: None,
                                linkage,
                            },
                            DependencyVersionScheme::WorkspacePath { path, version } => {
                                ast::DependencySpec {
                                    name: name.clone(),
                                    version_or_digest: version.clone(),
                                    workspace: false,
                                    path: Some(path.clone()),
                                    git: None,
                                    branch: None,
                                    rev: None,
                                    linkage,
                                }
                            },
                            DependencyVersionScheme::Registry(req) => ast::DependencySpec {
                                name: name.clone(),
                                version_or_digest: Some(req.clone()),
                                workspace: false,
                                path: None,
                                git: None,
                                branch: None,
                                rev: None,
                                linkage,
                            },
                            DependencyVersionScheme::Path { path, version } => {
                                ast::DependencySpec {
                                    name: name.clone(),
                                    version_or_digest: version.clone(),
                                    workspace: false,
                                    path: Some(path.clone()),
                                    git: None,
                                    branch: None,
                                    rev: None,
                                    linkage,
                                }
                            },
                            DependencyVersionScheme::Git { repo, revision, version } => {
                                let (branch, rev) = match revision.inner() {
                                    GitRevision::Branch(b) => {
                                        (Some(Span::new(revision.span(), b.clone())), None)
                                    },
                                    GitRevision::Commit(c) => {
                                        (None, Some(Span::new(revision.span(), c.clone())))
                                    },
                                };
                                ast::DependencySpec {
                                    name: name.clone(),
                                    version_or_digest: version.as_ref().map(|spanned| {
                                        VersionRequirement::from(spanned.inner().clone())
                                    }),
                                    workspace: false,
                                    path: None,
                                    git: Some(repo.clone()),
                                    branch,
                                    rev,
                                    linkage,
                                }
                            },
                        };

                        (name, Span::unknown(spec))
                    })
                    .collect(),
                lints: self.lints.clone(),
            },
            lib: self.lib.as_ref().map(|lib| {
                Span::unknown(ast::LibTarget {
                    kind: if matches!(lib.ty, TargetType::Library) {
                        None
                    } else {
                        Some(Span::unknown(lib.ty))
                    },
                    namespace: Some(lib.namespace.as_ref().map(|path| path.as_str().into())),
                    path: lib.path.clone(),
                })
            }),
            bins: self
                .bins
                .iter()
                .map(|bin| {
                    Span::unknown(ast::BinTarget {
                        name: Some(bin.name.clone()),
                        path: bin.path.clone(),
                    })
                })
                .collect(),
            profiles: self
                .profiles()
                .iter()
                .map(|profile| ast::Profile {
                    inherits: None,
                    name: Span::unknown(profile.name().clone()),
                    debug: Some(profile.should_emit_debug_info()),
                    trim_paths: Some(profile.should_trim_paths()),
                    metadata: profile.metadata().clone(),
                })
                .collect(),
        };

        toml::to_string_pretty(&manifest_ast)
            .map_err(|err| Report::msg(format!("failed to pretty print project manifest: {err}")))
    }
}
