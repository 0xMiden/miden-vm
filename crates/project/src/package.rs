use alloc::{
    boxed::Box,
    string::{String, ToString},
};
#[cfg(feature = "std")]
use std::path::Path;

#[cfg(all(feature = "std", feature = "serde"))]
use miden_diagnostics::{DiagnosticCollector, Spanned};
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
                    panic!("duplicate definitions of the same target '{}'", target.name);
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

    /// Returns a profile with the specified name, or an error if such a profile does not exist in
    /// this package.
    pub fn resolve_profile(&self, name: &str) -> Result<&Profile, Report> {
        self.get_profile(name).ok_or_else(|| {
            Report::msg(format!(
                "project '{}' does not define a '{}' build profile",
                self.name().inner(),
                name
            ))
        })
    }

    /// Compute the [PackageId] that will be produced for `target` if derived from this package
    pub fn target_package_name(&self, target: &Target) -> PackageId {
        if target.ty.is_executable() {
            format!("{}:{}", self.name().inner(), target.name.inner()).into()
        } else {
            self.name().inner().clone()
        }
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

    /// Get the location of the manifest this package was loaded from, or return an error if not
    /// available.
    #[cfg(feature = "std")]
    pub fn expect_manifest_path(&self) -> Result<&Path, Report> {
        self.manifest_path().ok_or_else(|| {
            Report::msg(format!("project '{}' is missing its manifest path", self.name().inner()))
        })
    }

    /// Return the package model projection that affects artifact reuse for `target` under
    /// `profile`.
    pub fn build_provenance_projection(&self, target: &Target, profile: &Profile) -> String {
        let Self {
            #[cfg(feature = "std")]
                manifest_path: _,
            name,
            version,
            description: _,
            dependencies: _,
            lints: _,
            metadata: _,
            lib: _,
            bins: _,
            profiles: _,
        } = self;

        let mut projection = String::new();
        projection.push_str("package:name:");
        projection.push_str(name.inner().as_ref());
        projection.push('\n');
        projection.push_str("package:version:");
        projection.push_str(version.inner().to_string().as_str());
        projection.push('\n');
        target.append_build_provenance_projection(&mut projection);
        profile.append_build_provenance_projection(&mut projection);
        projection
    }
}

/// Parsing
#[cfg(all(feature = "std", feature = "serde"))]
impl Package {
    /// Load a package from `source`, expected to be a standalone package-level `miden-project.toml`
    /// manifest.
    pub fn load(
        source_id: SourceId,
        source: &str,
        manifest_path: Option<&Path>,
    ) -> Outcome<Box<Self>> {
        Self::parse(source_id, source, manifest_path, None)
    }

    /// Load a package from `source`, expected to be a package-level `miden-project.toml` manifest
    /// which is presumed to be a member of `workspace` for purposes of configuration inheritance.
    pub(crate) fn load_from_workspace(
        source_id: SourceId,
        source: &str,
        manifest_path: Option<&Path>,
        workspace_source_id: SourceId,
        workspace: &WorkspaceFile,
        workspace_manifest_path: Option<&Path>,
    ) -> Outcome<Box<Self>> {
        Self::parse(
            source_id,
            source,
            manifest_path,
            Some((workspace_source_id, workspace, workspace_manifest_path)),
        )
    }

    fn parse(
        source_id: SourceId,
        source: &str,
        manifest_path: Option<&Path>,
        workspace: Option<(SourceId, &WorkspaceFile, Option<&Path>)>,
    ) -> Outcome<Box<Self>> {
        let mut diagnostics = DiagnosticCollector::new();

        // Parse the manifest into an AST for further processing
        let parsed = ast::ProjectFile::parse(source_id, source);
        let _ = diagnostics.merge(parsed.diagnostics);
        let Ok(package_ast) = parsed.result else {
            return Outcome {
                result: Err(()),
                diagnostics: diagnostics.finish(),
            };
        };

        let errors_before = diagnostics.counts().errors();
        let mut context = ast::parsing::ValidationContext::new(source_id, &mut diagnostics);
        let workspace_ast = workspace.map(|(id, file, _)| (id, file));

        // Extract metadata that can be inherited from the workspace manifest (if present)
        let version = package_ast.get_or_inherit_version(&mut context, workspace_ast);
        let description = package_ast.get_or_inherit_description(&mut context, workspace_ast);

        // Compute the set of initial profiles inheritable from the workspace level
        let mut profiles = Vec::default();
        profiles.push(Profile::default());
        profiles.push(Profile::release());
        if let Some((workspace_source_id, workspace, _)) = workspace {
            for profile_ast in workspace.profiles.iter() {
                let Some(profile) =
                    Profile::from_ast(profile_ast, workspace_source_id, &profiles, &mut context)
                else {
                    continue;
                };
                if let Some(prev) =
                    profiles.iter_mut().find(|p| p.name() == profile_ast.name.get_ref())
                {
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
        for profile_ast in package_ast.profiles.iter() {
            let Some(profile) = Profile::from_ast(profile_ast, source_id, &profiles, &mut context)
            else {
                continue;
            };

            if let Some(prev_index) = profiles.iter().position(|p| p.name() == profile.name()) {
                if prev_index < package_profiles_start {
                    profiles[prev_index].merge(&profile);
                } else {
                    let prev = &profiles[prev_index];
                    let _ = context.add(ProjectFileError::DuplicateProfile {
                        name: prev.name().clone(),
                        span: profile.span(),
                        prev: prev.span(),
                    });
                }
            } else {
                profiles.push(profile);
            }
        }

        // Extract project dependencies, using the workspace to resolve workspace-relative
        // dependencies
        let dependencies = lower_dependencies(&package_ast, source_id, workspace, &mut context);

        // Extract the build targets for this project
        let lib = package_ast.extract_library_target(&mut context);
        let bins = package_ast.extract_executable_targets(&context);

        let mut lints = workspace
            .map(|(id, ws, _)| ast::parsing::lower_metadata_set(id, &ws.workspace.config.lints))
            .unwrap_or_default();
        lints.extend(ast::parsing::lower_metadata_set(source_id, &package_ast.config.lints));

        let mut metadata = workspace
            .map(|(id, ws, _)| ast::parsing::lower_metadata_set(id, &ws.workspace.package.metadata))
            .unwrap_or_default();
        metadata.extend(ast::parsing::lower_metadata_set(
            source_id,
            &package_ast.package.detail.metadata,
        ));

        let result = if context.error_count() == errors_before {
            Ok(Box::new(Self {
                manifest_path: manifest_path.map(|path| path.to_path_buf().into_boxed_path()),
                name: context.lower(package_ast.package.name.clone()).map(Into::into),
                version: version.expect("successful lowering produced a version"),
                description: description.expect("successful lowering produced a description"),
                dependencies,
                lints,
                metadata,
                profiles,
                lib,
                bins,
            }))
        } else {
            Err(())
        };

        Outcome {
            result,
            diagnostics: diagnostics.finish(),
        }
    }
}

#[cfg(all(feature = "std", feature = "serde"))]
fn lower_dependencies(
    package: &ast::ProjectFile,
    source_id: SourceId,
    workspace: Option<(SourceId, &WorkspaceFile, Option<&Path>)>,
    context: &mut ast::parsing::ValidationContext<'_>,
) -> Vec<Dependency> {
    let mut dependencies = Vec::with_capacity(package.config.dependencies.len());
    for dependency in package.config.dependencies.values() {
        let spec = dependency.get_ref();
        let (effective, effective_source_id, workspace_manifest_path) = if spec
            .inherits_workspace_version()
        {
            let Some((workspace_source_id, workspace, workspace_manifest_path)) = workspace else {
                let _ = context.add(ProjectFileError::InvalidPackageDependency {
                    message: "this package is not in a workspace".into(),
                    span: context.span(&spec.name),
                });
                continue;
            };
            let Some((_, effective)) = workspace
                .workspace
                .config
                .dependencies
                .iter()
                .find(|(name, _)| name.get_ref().as_ref() == spec.name.get_ref().as_ref())
            else {
                let _ = context.add(ProjectFileError::InvalidPackageDependency {
                    message: format!("'{}' is not a workspace dependency", spec.name.get_ref()),
                    span: context.span(&spec.name),
                });
                continue;
            };
            (effective.get_ref(), workspace_source_id, workspace_manifest_path)
        } else {
            (spec, source_id, workspace.and_then(|(_, _, path)| path))
        };

        let scheme = match workspace {
            Some((_, workspace, _)) => DependencyVersionScheme::try_from_ast_in_workspace(
                effective,
                effective_source_id,
                workspace,
                workspace_manifest_path,
            ),
            None => DependencyVersionScheme::try_from_ast(effective, effective_source_id),
        };
        let scheme = match scheme {
            Ok(scheme) => scheme,
            Err(error) => {
                let _ = context.add(error);
                continue;
            },
        };

        let linkage = spec
            .linkage
            .as_ref()
            .map(|value| (value, source_id))
            .or_else(|| effective.linkage.as_ref().map(|value| (value, effective_source_id)));
        let linkage = match linkage {
            Some((value, linkage_source_id)) => match value.get_ref().parse::<Linkage>() {
                Ok(linkage) => linkage,
                Err(error) => {
                    let _ = context.add(ProjectFileError::InvalidPackageDependency {
                        message: error.to_string(),
                        span: context.span_in(linkage_source_id, value),
                    });
                    continue;
                },
            },
            None => Linkage::default(),
        };

        dependencies.push(Dependency::new(
            ast::parsing::lower_span(source_id, spec.name.clone()),
            scheme,
            linkage,
        ));
    }
    dependencies
}

#[cfg(feature = "serde")]
impl Package {
    /// Pretty print this [Package] in TOML format.
    ///
    /// The output of this function is not guaranteed to be identical to the way the original
    /// manifest (if one exists) was written, i.e. it may emit keys that are optional or that
    /// contain default or inherited values.
    pub fn to_toml(&self) -> Result<String, Report> {
        fn raw<T>(value: T) -> TomlSpan<T> {
            TomlSpan::new(0..0, value)
        }

        fn raw_metadata(metadata: &Metadata) -> AstMetadata {
            metadata
                .iter()
                .map(|(key, value)| (raw(key.inner().clone()), raw(value.inner().clone())))
                .collect()
        }

        fn raw_metadata_set(metadata: &MetadataSet) -> AstMetadataSet {
            metadata
                .iter()
                .map(|(key, value)| (raw(key.inner().clone()), raw_metadata(value)))
                .collect()
        }

        let manifest_ast = ast::ProjectFile {
            package: ast::PackageTable {
                name: raw(self.name().inner().clone().into_inner()),
                detail: ast::PackageDetail {
                    version: Some(raw(ast::parsing::MaybeInherit::Value(
                        self.version().inner().to_string().into(),
                    ))),
                    description: self.description().map(ast::parsing::MaybeInherit::Value).map(raw),
                    metadata: raw_metadata_set(&self.metadata),
                },
            },
            config: ast::PackageConfig {
                dependencies: self
                    .dependencies()
                    .iter()
                    .map(|dep| {
                        let name = raw(dep.name().clone());
                        let linkage = if matches!(dep.linkage(), Linkage::Dynamic) {
                            None
                        } else {
                            Some(raw(Arc::from(dep.linkage().as_str())))
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
                                    version_or_digest: version
                                        .as_ref()
                                        .map(|version| raw(Arc::from(version.to_string()))),
                                    workspace: false,
                                    path: Some(raw(Arc::from(path.inner().to_string()))),
                                    git: None,
                                    branch: None,
                                    rev: None,
                                    linkage,
                                }
                            },
                            DependencyVersionScheme::Registry(req) => ast::DependencySpec {
                                name: name.clone(),
                                version_or_digest: Some(raw(Arc::from(req.to_string()))),
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
                                    version_or_digest: version
                                        .as_ref()
                                        .map(|version| raw(Arc::from(version.to_string()))),
                                    workspace: false,
                                    path: Some(raw(Arc::from(path.inner().to_string()))),
                                    git: None,
                                    branch: None,
                                    rev: None,
                                    linkage,
                                }
                            },
                            DependencyVersionScheme::Git { repo, revision, version } => {
                                let (branch, rev) = match revision.inner() {
                                    GitRevision::Branch(b) => (Some(raw(b.clone())), None),
                                    GitRevision::Commit(c) => (None, Some(raw(c.clone()))),
                                };
                                ast::DependencySpec {
                                    name: name.clone(),
                                    version_or_digest: version.as_ref().map(|spanned| {
                                        raw(Arc::from(
                                            VersionRequirement::from(spanned.inner().clone())
                                                .to_string(),
                                        ))
                                    }),
                                    workspace: false,
                                    path: None,
                                    git: Some(raw(Arc::from(repo.inner().to_string()))),
                                    branch,
                                    rev,
                                    linkage,
                                }
                            },
                        };

                        (name, raw(spec))
                    })
                    .collect(),
                lints: raw_metadata_set(&self.lints),
            },
            lib: self.lib.as_ref().map(|lib| {
                raw(ast::LibTarget {
                    kind: if matches!(lib.ty, TargetType::Library) {
                        None
                    } else {
                        Some(raw(Arc::from(lib.ty.to_string())))
                    },
                    namespace: Some(raw(Arc::from(lib.namespace.inner().as_str()))),
                    path: raw(Arc::from(lib.path.inner().to_string())),
                })
            }),
            bins: self
                .bins
                .iter()
                .map(|bin| {
                    raw(ast::BinTarget {
                        name: Some(raw(bin.name.inner().clone())),
                        path: raw(Arc::from(bin.path.inner().to_string())),
                    })
                })
                .collect(),
            profiles: self
                .profiles()
                .iter()
                .map(|profile| ast::Profile {
                    inherits: None,
                    name: raw(profile.name().clone()),
                    debug: Some(profile.should_emit_debug_info()),
                    trim_paths: Some(profile.should_trim_paths()),
                    metadata: raw_metadata(profile.metadata()),
                })
                .collect(),
        };

        toml::to_string_pretty(&manifest_ast)
            .map_err(|err| Report::msg(format!("failed to pretty print project manifest: {err}")))
    }
}
