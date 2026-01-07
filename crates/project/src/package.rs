use alloc::format;

use miden_assembly_syntax::debuginfo::Spanned;

use crate::{
    ast::{ProjectFileError, WorkspaceFile, parsing::MaybeInherit},
    *,
};

#[cfg(feature = "std")]
use std::path::Path;

/// The representation of an individual package in a Miden project
#[derive(Debug)]
pub struct Package {
    /// The file path of the manifest corresponding to this package metadata, if applicable.
    #[cfg(feature = "std")]
    manifest_path: Option<Box<Path>>,
    /// The name of the package
    name: Span<Arc<str>>,
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
    /// The build targets available for this package.
    targets: Vec<Span<Target>>,
    /// The build profiles configured for this package.
    profiles: Vec<Profile>,
}

/// Accessors
impl Package {
    /// Get the name of this package
    pub fn name(&self) -> Span<Arc<str>> {
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

    /// Get a reference to the build targets provided by this package
    pub fn targets(&self) -> &[Span<Target>] {
        &self.targets
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
        use core::num::NonZeroU32;
        use miden_assembly_syntax::Path as MasmPath;

        let manifest_path = Path::new(source.uri().path());
        let manifest_path = if manifest_path.try_exists().is_ok_and(|exists| exists) {
            Some(manifest_path.to_path_buf().into_boxed_path())
        } else {
            None
        };

        let package_ast = ast::PackageFile::parse(source.clone())?;

        let Some(version) = package_ast.package.detail.version.as_ref() else {
            let one = NonZeroU32::new(1).unwrap();
            let span = source
                .line_column_to_span(one.into(), one.into())
                .unwrap_or(source.source_span());
            return Err(ProjectFileError::MissingVersion { source_file: source, span }.into());
        };
        let version = match version.inner() {
            MaybeInherit::Value(value) => Span::new(version.span(), value.clone()),
            MaybeInherit::Inherit => match workspace {
                Some(workspace) => {
                    if let Some(version) = workspace.workspace.package.version.as_ref() {
                        version.as_ref().map(|inherit| inherit.unwrap_value().clone())
                    } else {
                        return Err(ProjectFileError::MissingWorkspaceVersion {
                            source_file: source,
                            span: version.span(),
                        }
                        .into());
                    }
                },
                None => {
                    return Err(ProjectFileError::NotAWorkspace {
                        source_file: source,
                        span: version.span(),
                    }
                    .into());
                },
            },
        };

        let description = package_ast.package.detail.description.as_ref();
        let description = match description {
            None => None,
            Some(desc) => match desc.inner() {
                MaybeInherit::Value(value) => Some(value.clone()),
                MaybeInherit::Inherit => match workspace {
                    Some(workspace) => workspace
                        .workspace
                        .package
                        .description
                        .as_ref()
                        .map(|d| d.inner().unwrap_value().clone()),
                    None => {
                        return Err(ProjectFileError::NotAWorkspace {
                            source_file: source,
                            span: desc.span(),
                        }
                        .into());
                    },
                },
            },
        };

        let mut profiles = Vec::default();
        profiles.push(Profile::default());
        profiles.push(Profile::release());
        if let Some(workspace) = workspace {
            for ast in workspace.profiles.iter() {
                let ast::Profile {
                    inherits,
                    name,
                    debug,
                    trim_paths,
                    metadata,
                } = ast;

                let mut profile = match inherits.as_ref() {
                    Some(parent) => {
                        if let Some(parent) = profiles.iter().find(|p| p.name() == parent.inner()) {
                            Profile::inherit(name.clone(), parent)
                        } else {
                            return Err(ProjectFileError::UnknownProfile {
                                name: parent.inner().clone(),
                                source_file: source,
                                span: parent.span(),
                            }
                            .into());
                        }
                    },
                    None => Profile::new(name.clone()),
                };

                if let Some(debug) = *debug {
                    profile.enable_debug_info(debug);
                }

                if let Some(trim_paths) = *trim_paths {
                    profile.enable_trim_paths(trim_paths);
                }

                if !metadata.is_empty() {
                    profile.extend(metadata.iter().map(|(k, v)| (k.clone(), v.clone())));
                }

                profiles.push(profile);
            }
        }

        let package_profiles_start = profiles.len();
        for ast in package_ast.profiles.iter() {
            let ast::Profile {
                inherits,
                name,
                debug,
                trim_paths,
                metadata,
            } = ast;

            let mut profile = match inherits.as_ref() {
                Some(parent) => {
                    if let Some(parent) = profiles.iter().find(|p| p.name() == parent.inner()) {
                        Profile::inherit(name.clone(), parent)
                    } else {
                        return Err(ProjectFileError::UnknownProfile {
                            name: parent.inner().clone(),
                            source_file: source,
                            span: parent.span(),
                        }
                        .into());
                    }
                },
                None => Profile::new(name.clone()),
            };

            if let Some(debug) = *debug {
                profile.enable_debug_info(debug);
            }

            if let Some(trim_paths) = *trim_paths {
                profile.enable_trim_paths(trim_paths);
            }

            if !metadata.is_empty() {
                profile.extend(metadata.iter().map(|(k, v)| (k.clone(), v.clone())));
            }

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

        let mut dependencies = Vec::with_capacity(package_ast.config.dependencies.len());
        for dependency in package_ast.config.dependencies.values() {
            if dependency.inherits_workspace_version() {
                if let Some(workspace) = workspace {
                    match workspace.workspace.config.dependencies.get(&dependency.name) {
                        Some(dep) => {
                            debug_assert!(!dep.inherits_workspace_version());

                            let version = DependencyVersionScheme::try_from_in_workspace(
                                dep.as_ref(),
                                workspace,
                            )?;
                            dependencies.push(Dependency::new(dep.name.clone(), version));
                        },
                        None => {
                            return Err(ProjectFileError::InvalidPackageDependency {
                                source_file: source,
                                label: Label::new(
                                    dependency.span(),
                                    format!("'{}' is not a workspace dependency", &dependency.name),
                                ),
                            }
                            .into());
                        },
                    }
                } else {
                    return Err(ProjectFileError::InvalidPackageDependency {
                        source_file: source,
                        label: Label::new(dependency.span(), "this package is not in a workspace"),
                    }
                    .into());
                }
            } else {
                dependencies.push(Dependency::new(
                    dependency.name.clone(),
                    DependencyVersionScheme::try_from(dependency.as_ref())?,
                ));
            }
        }

        let mut targets = Vec::with_capacity(package_ast.targets.len());
        for target in package_ast.targets.iter() {
            let span = target.span();
            let namespace = target
                .namespace
                .as_ref()
                .map(|ns| Span::new(ns.span(), MasmPath::new(ns.inner()).to_absolute().into()))
                .unwrap_or_else(|| {
                    Span::new(
                        package_ast.package.name.span(),
                        MasmPath::new(package_ast.package.name.inner()).to_absolute().into(),
                    )
                });
            let path =
                Span::new(target.path.as_ref().map(|p| p.span()).unwrap_or(span), target.path());
            targets.push(Span::new(span, Target { ty: target.kind, namespace, path }));
        }

        if targets.is_empty() {
            let name = &package_ast.package.name;
            let span = name.span();
            let target = Target {
                ty: TargetType::Library,
                namespace: Span::new(span, MasmPath::new(name.inner()).to_absolute().into()),
                path: Span::new(span, Uri::new("mod.masm")),
            };
            targets.push(Span::new(span, target));
        }

        Ok(Box::new(Self {
            manifest_path,
            name: package_ast.package.name.clone(),
            version,
            description,
            dependencies,
            lints: workspace.map(|ws| ws.workspace.config.lints.clone()).unwrap_or_default(),
            metadata: workspace.map(|ws| ws.workspace.config.lints.clone()).unwrap_or_default(),
            profiles,
            targets,
        }))
    }
}
