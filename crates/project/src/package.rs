use alloc::{boxed::Box, vec};
#[cfg(feature = "std")]
use std::path::Path;

#[cfg(feature = "std")]
use miden_assembly_syntax::debuginfo::Spanned;

#[cfg(feature = "std")]
use crate::ast::{ProjectFileError, WorkspaceFile};
use crate::*;

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
    pub fn new(name: impl Into<Arc<str>>, default_target: Target) -> Box<Self> {
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

    /// Get a reference to the library build target provided by this package
    pub fn library_target(&self) -> Option<&Span<Target>> {
        self.lib.as_ref()
    }

    /// Get a reference to the executable build targets provided by this package
    pub fn executable_targets(&self) -> &[Span<Target>] {
        &self.bins
    }

    /// Get the total number of build targets for this package
    pub fn num_targets(&self) -> usize {
        self.bins.len() + self.lib.is_some() as usize
    }

    /// Get a reference to one of the build targets in this package, given a [TargetSelector].
    ///
    /// Returns a reference to the target if the selection is matched, and is unambiguous.
    ///
    /// Returns a [TargetSelectionError] if any of the following apply:
    ///
    /// * There are no matching targets
    /// * The selector matched more than a single target
    pub fn get_target(
        &self,
        selector: TargetSelector<'_>,
    ) -> Result<&Target, TargetSelectionError> {
        match selector {
            TargetSelector::Default => self.get_default_target(),
            TargetSelector::Type(ty) if ty.is_library() => match self.lib.as_ref() {
                Some(target) if target.ty == ty => Ok(target.inner()),
                Some(_) | None => Err(TargetSelectionError::TypeNotFound(ty)),
            },
            selector @ TargetSelector::Type(ty) => match self.bins.first() {
                Some(target) if self.bins.len() == 1 => Ok(target.inner()),
                Some(_) => Err(TargetSelectionError::Ambiguous { selector: selector.into_owned() }),
                None => Err(TargetSelectionError::TypeNotFound(ty)),
            },
            selector @ TargetSelector::Name(_) => {
                if let Some(lib_target) = self.lib.as_ref()
                    && selector.matches(lib_target)
                {
                    return Ok(lib_target.inner());
                }
                let mut matches = self.bins.iter().filter(|target| selector.matches(target));
                let selected = matches.next();
                if matches.next().is_some() {
                    Err(TargetSelectionError::Ambiguous { selector: selector.into_owned() })
                } else {
                    selected.map(|target| target.inner()).ok_or_else(|| match selector {
                        TargetSelector::Default => {
                            TargetSelectionError::TypeNotFound(TargetType::Library)
                        },
                        TargetSelector::Type(ty) => TargetSelectionError::TypeNotFound(ty),
                        TargetSelector::Name(name) => {
                            TargetSelectionError::NameNotFound(name.into_owned().into_boxed_str())
                        },
                    })
                }
            },
        }
    }

    /// Returns the default build target for this package, or an error if one cannot be selected.
    ///
    /// Equivalent to calling [`Self::get_target`] with `TargetSelector::Default`.
    pub fn get_default_target(&self) -> Result<&Target, TargetSelectionError> {
        let has_executable_targets = !self.bins.is_empty();
        match self.lib.as_ref() {
            Some(lib_target) if !has_executable_targets => Ok(lib_target.inner()),
            Some(_) => Err(TargetSelectionError::Ambiguous { selector: TargetSelector::Default }),
            None => match self.bins.first() {
                Some(target) if self.bins.len() == 1 => Ok(target.inner()),
                Some(_) => {
                    Err(TargetSelectionError::Ambiguous { selector: TargetSelector::Default })
                },
                None => Err(TargetSelectionError::NoTargets),
            },
        }
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
                profiles.push(Profile::from_ast(ast, source.clone(), &profiles)?);
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
            name: package_ast.package.name.clone(),
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
