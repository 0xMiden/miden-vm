use alloc::{boxed::Box, format, string::String};
use core::{cmp::Reverse, convert::Infallible};

use pubgrub::{Dependencies, DependencyProvider, SelectedDependencies};
use smallvec::SmallVec;

use super::{version_set::VersionSetFilter, *};
use crate::{SemVer, Version};

/// Represents package priorities in the resolver.
///
/// The order of the variants here matters, as the earlier a variant appears, the lower its
/// priority. The resolver will solve for packages with higher priority before those with lower
/// priority, and so it is desirable to prioritize packages with a higher chance of conflict and/or
/// more precise version requirements, as it has a large impact on the performance of the resolver,
/// by eliminating a lot of versions from the tree.
///
/// In general, the goal of this prioritization scheme is to guide the resolver so it can make
/// better selections, and aid in resolving conflicts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackagePriority {
    /// The package has no specific priority, or low priority
    Weak(Reverse<u8>),
    /// The package version range is constrained to a single version, so we want to handle these
    /// packages before other packages, as it will help with version selection for packages with
    /// lower priority.
    Singleton(Reverse<u8>),
    /// The package is constrained to an exact content digest, which is more precise than a single
    /// version constraint, as there may be multiple instances of a package for a given semantic
    /// version with differing digests. Thus we prioritize these before the other types above.
    Digest(Reverse<u8>),
    /// The package is in the same workspace as the root. We prioritize these before specific
    /// versions, as it would be highly unintuitive for dependencies on packages in the workspace
    /// to resolve to versions which are _not_ in the workspace. The purpose of prioritizing this
    /// higher is that it will ensure that when referencing a workspace dependency via path, which
    /// must happen _in_ the workspace itself, that we always choose the version at that path first,
    /// and raise a conflict if other requirements on the same package cannot be unified to that
    /// version.
    Workspace,
    /// The package is the root package, and so we always choose it first
    Root,
}

/// As implied by the name, this is the implementation of the dependency/package resolver.
///
/// The resolver is constructed for a specific root package, along with a reference to the current
/// state of the package index. Once constructed, you then ask the resolver for the dependencies
/// of the given package using [`PackageResolver::resolve`]. It is then up to the caller to take
/// those package and version selections and do something with them, typically fetching the actual
/// package content and using it for program execution or assembly of a new package.
pub struct PackageResolver<'a> {
    index: &'a PackageIndex,
    context: ResolverContext,
}

/// Construction
impl<'a> PackageResolver<'a> {
    /// Create a [PackageResolver] for `package` in `workspace`, using `index`.
    ///
    /// It is assumed that the caller has already:
    ///
    /// 1. Ensured that `index` has been seeded with `package`, along with other members of
    ///    `workspace`, and all versions of all packages known to the system that may be referenced
    ///    as dependencies, directly or transitively.
    /// 2. Verified that `package` is a member of `workspace`. While resolution can still succeed if
    ///    that isn't the case, it may cause unexpected conflicts or selections to occur due to the
    ///    special prioritization given to workspace members.
    pub fn for_package_in_workspace(
        package: &'a crate::Package,
        workspace: &'a crate::Workspace,
        index: &'a PackageIndex,
    ) -> Self {
        Self {
            index,
            context: ResolverContext::Workspace {
                members: SmallVec::from_iter(
                    workspace.members().iter().map(|p| p.name().into_inner().into()),
                ),
                root: package.name().into_inner().into(),
                root_version: package.version().into_inner().clone(),
            },
        }
    }

    /// Create a [PackageResolver] for `package`, using `index`.
    ///
    /// For packages that are members of a workspace, you should prefer
    /// [`Self::for_package_in_workspace`].
    ///
    /// It is assumed that the caller has already:
    ///
    /// 1. Ensured that `index` has been seeded with `package`, along with all versions of all
    ///    packages known to the system that may be referenced as dependencies, directly or
    ///    transitively.
    pub fn for_package(package: &'a crate::Package, index: &'a PackageIndex) -> Self {
        Self {
            index,
            context: ResolverContext::Package {
                root: package.name().into_inner().into(),
                version: package.version().into_inner().clone(),
            },
        }
    }
}

/// Dependency resolution
impl<'a> PackageResolver<'a> {
    pub fn resolve(self) -> Result<SelectedDependencies<Self>, DependencyResolutionError> {
        let (package, version) = match &self.context {
            ResolverContext::Workspace { root, root_version: version, .. }
            | ResolverContext::Package { root, version } => (root, version),
        };
        self.resolve_for(package.clone(), version.clone())
    }

    /// Resolve dependencies for `package` with the given `version`.
    ///
    /// If successful, this returns a map of [PackageId] to [Version] for all dependencies required
    /// by `package`, transitively.
    ///
    /// If unsuccesssful, a [DependencyResolutionError] is returned that indicates why it failed.
    pub fn resolve_for(
        &self,
        package: impl Into<PackageId>,
        version: SemVer,
    ) -> Result<SelectedDependencies<Self>, DependencyResolutionError> {
        let package = package.into();
        let version = Version { version, digest: None };
        pubgrub::resolve(self, package, version).map_err(DependencyResolutionError::from)
    }
}

/// Context used by [PackageResolver] to aid in version selection during resolution.
enum ResolverContext {
    Workspace {
        members: SmallVec<[PackageId; 2]>,
        root: PackageId,
        root_version: SemVer,
    },
    Package {
        root: PackageId,
        version: SemVer,
    },
}

impl ResolverContext {
    /// Attempt to prioritize `package` based on the current resolver context.
    ///
    /// Returns `None` if no specific priority can be determined based solely on the package name
    /// and resolver context.
    pub fn try_prioritize(&self, package: &PackageId) -> Option<PackagePriority> {
        match self {
            Self::Workspace { members, root, .. } => {
                if package == root {
                    Some(PackagePriority::Root)
                } else if members.contains(package) {
                    Some(PackagePriority::Workspace)
                } else {
                    None
                }
            },
            Self::Package { root, .. } => {
                if package == root {
                    Some(PackagePriority::Root)
                } else {
                    None
                }
            },
        }
    }
}

/// This provides the version selection/dependency resolution functionality for [PackageIndex] via
/// [`pubgrub`](https://pubgrub-rs.github.io/pubgrub/pubgrub/).
///
/// We provide a custom implementation, as our versioning scheme must handle a mix of requirements
/// including both semantic versioning schemes as well as requirements on a specific package digest.
impl<'a> DependencyProvider for PackageResolver<'a> {
    /// The type used to identify packages in the provider
    type P = PackageId;
    /// The type used to represent package versions
    type V = Version;
    /// The type used to represent version requirements.
    ///
    /// NOTE: Requirements must be able to process versions of type `V`
    type VS = VersionSet;
    /// The error type used to communicate our own version selection issues, e.g.:
    ///
    /// * The version would require building the package, but builds are disabled.
    /// * The package is not available in the cache, but internet access has been disabled.
    /// * The package uses a legacy format not supported anymore.
    ///
    /// Currently we're using `String` here as a placeholder until we determine a more appropriate
    /// error type.
    type M = String;
    /// The type used to represent prioritize package versions during selection.
    type Priority = PackagePriority;
    /// The error type returned from all functions of this trait that return errors.
    ///
    /// Returning this signals that resolution should fail with this error.
    ///
    /// We're using `Infallible` here currently, as we don't produce any errors that need to be
    /// returned yet, this is likely to change in the near future.
    type Err = Infallible;

    fn prioritize(
        &self,
        package: &Self::P,
        range: &Self::VS,
        _package_conflicts_counts: &pubgrub::PackageResolutionStatistics,
    ) -> Self::Priority {
        if let Some(prio) = self.context.try_prioritize(package) {
            prio
        } else if matches!(range.filter(), VersionSetFilter::Digest(_)) {
            PackagePriority::Digest(Reverse(3))
        } else if range.range().as_singleton().is_some() {
            PackagePriority::Singleton(Reverse(2))
        } else {
            PackagePriority::Weak(Reverse(1))
        }
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        std::dbg!(package, range);
        let Some(versions) = self.index.get(package) else {
            return Ok(None);
        };
        let filter = range.filter();
        let ranges = range.range();
        if ranges.is_empty()
            && let VersionSetFilter::Digest(digests) = filter
        {
            let version = versions
                .keys()
                .rev()
                .find(|v| v.digest.as_ref().is_some_and(|digest| digests.contains(digest)))
                .cloned();

            Ok(version)
        } else if let Some(version) = ranges.as_singleton()
            && let Some((v, _)) = versions.get_key_value(version)
        {
            Ok(Some(v.clone()))
        } else if let Some((start, end)) = ranges.bounding_range() {
            let range = (start.cloned(), end.cloned());
            let version = versions
                .range(range)
                .rev()
                .find_map(|(v, _)| {
                    if filter.matches(v) && ranges.contains(&v.version) {
                        Some(v)
                    } else {
                        None
                    }
                })
                .cloned();
            Ok(version)
        } else {
            let version = versions
                .keys()
                .rev()
                .find(|v| filter.matches(v) && ranges.contains(&v.version))
                .cloned();

            Ok(version)
        }
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<pubgrub::Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        // If `package` has no available versions in the index, indicate that to the caller
        let Some(available) = self.index.get(package) else {
            return Ok(Dependencies::Unavailable(format!(
                "no package named '{package}' found in registry"
            )));
        };

        // If `version` is not in the index, indicate that to the caller
        let Some(deps) = available.get(version) else {
            return Ok(Dependencies::Unavailable(format!(
                "version '{version}' of '{package}' was not found in registry"
            )));
        };

        Ok(Dependencies::Available(
            deps.iter().map(|(name, range)| (name.clone(), range.clone())).collect(),
        ))
    }

    fn should_cancel(&self) -> Result<(), Self::Err> {
        // TODO(pauls): We may wish to introduce a configurable resolution timeout, and return `Err`
        // from this method if resolution exceeds some specified threshold.
        //
        // To do so, we may need to define a new struct that wraps a reference to the index with the
        // timeout configuration, and move the implementation of this trait to that type instead,
        // as there isn't a good place to manage the timeout on PackageIndex itself.
        Ok(())
    }
}

/// The error type raised when [PackageResolver::resolve] fails.
#[derive(thiserror::Error)]
pub enum DependencyResolutionError {
    /// No solution was possible due to conflicts or unsatisified constraints.
    #[error("dependency resolution failed: {}", format_solution_error(.0))]
    NoSolution(Box<pubgrub::DerivationTree<PackageId, VersionSet, String>>),
    /// Resolution could not proceed because one or more dependent packages were unavailable.
    #[error("could not get dependencies for '{package}' version '{version}': {error}")]
    FailedRetreivingDependencies {
        package: PackageId,
        version: Version,
        error: String,
    },
    /// Resolution could not proceed because the resolver was unable to choose an appropriate
    /// version for a given package.
    #[error("could not choose version for {package}: {error}")]
    FailedToChooseVersion { package: PackageId, error: String },
    /// Resolution was cancelled by the implementation of
    /// [`pubgrub::DependencyProvider::should_cancel`] - typically due to timeout or some other
    /// external signal.
    #[error("dependency resolution was cancelled: {reason}")]
    Cancelled { reason: String },
}

impl core::fmt::Debug for DependencyResolutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

fn format_solution_error(tree: &pubgrub::DerivationTree<PackageId, VersionSet, String>) -> String {
    use pubgrub::{DefaultStringReporter, Reporter};

    DefaultStringReporter::report(tree)
}

impl From<pubgrub::DerivationTree<PackageId, VersionSet, String>> for DependencyResolutionError {
    fn from(tree: pubgrub::DerivationTree<PackageId, VersionSet, String>) -> Self {
        Self::NoSolution(Box::new(tree))
    }
}

impl From<pubgrub::PubGrubError<PackageResolver<'_>>> for DependencyResolutionError {
    fn from(error: pubgrub::PubGrubError<PackageResolver<'_>>) -> Self {
        use pubgrub::PubGrubError;

        match error {
            PubGrubError::NoSolution(tree) => Self::from(tree),
            PubGrubError::ErrorRetrievingDependencies { package, version, source: _ } => {
                Self::FailedRetreivingDependencies { package, version, error: String::new() }
            },
            PubGrubError::ErrorChoosingVersion { package, source: _ } => {
                Self::FailedToChooseVersion { package, error: String::new() }
            },
            PubGrubError::ErrorInShouldCancel(_err) => Self::Cancelled { reason: String::new() },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::{Word, crypto::hash::Rpo256};
    use pubgrub::{SelectedDependencies, VersionSet as _};

    use super::*;
    use crate::VersionReq;

    fn select<'a>(packages: &[(&str, &str)]) -> SelectedDependencies<PackageResolver<'a>> {
        packages
            .iter()
            .map(|(name, version)| {
                let name = PackageId::from(*name);
                let version = match version.split_once('@') {
                    Some((v, hex)) => {
                        let version = v.parse::<SemVer>().unwrap();
                        let word = Word::parse(hex).unwrap();
                        Version { version, digest: Some(word.into()) }
                    },
                    None => Version {
                        version: version.parse::<SemVer>().unwrap(),
                        digest: None,
                    },
                };
                (name, version)
            })
            .collect()
    }

    fn assert_selected<'a>(
        resolved: &SelectedDependencies<PackageResolver<'a>>,
        expected: &SelectedDependencies<PackageResolver<'a>>,
    ) {
        use core::cmp::Ordering;

        match resolved.len().cmp(&expected.len()) {
            Ordering::Equal | Ordering::Greater => {
                for (k, v) in resolved.iter() {
                    assert_eq!(
                        expected.get(k),
                        Some(v),
                        "unexpected dependency found in selection"
                    );
                }
            },
            Ordering::Less => {
                for (k, v) in expected.iter() {
                    assert_eq!(resolved.get(k), Some(v), "missing expected dependency '{k}@{v}'");
                }
            },
        }
    }

    /// This test verifies that version requirements for both semantic versions and content digests
    /// can be resolved, and that requirements on specific content digests are resolved correctly.
    #[test]
    fn resolver_resolve_mixed_versioning_schemes() {
        let digest = Rpo256::hash(b"the digest for 'b'");
        let index = PackageIndex::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", VersionSet::from(digest))])]),
            (
                "b",
                vec![
                    (
                        Version::new("1.0.0".parse().unwrap(), digest),
                        vec![
                            ("c", VersionSet::full()),
                            ("d", VersionSet::from("=0.2.1".parse::<VersionReq>().unwrap())),
                        ],
                    ),
                    (
                        "1.0.1".parse().unwrap(),
                        vec![
                            ("c", VersionSet::full()),
                            ("d", VersionSet::from("=0.2.1".parse::<VersionReq>().unwrap())),
                        ],
                    ),
                ],
            ),
            (
                "c",
                vec![("0.2.0".parse().unwrap(), vec![]), ("0.3.0".parse().unwrap(), vec![])],
            ),
            (
                "d",
                vec![
                    ("0.1.0".parse().unwrap(), vec![]),
                    ("0.2.1".parse().unwrap(), vec![]),
                    ("0.2.5".parse().unwrap(), vec![]),
                    ("1.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver {
            index: &index,
            context: ResolverContext::Package {
                root: PackageId::from("a"),
                version: "0.1.0".parse().unwrap(),
            },
        };
        let selected = resolver.resolve().expect("failed to resolve 'a'");
        let b_version = format!("1.0.0@{digest}");
        let expected =
            select(&[("a", "0.1.0"), ("b", b_version.as_str()), ("c", "0.3.0"), ("d", "0.2.1")]);

        assert_selected(&selected, &expected);
    }

    /// In this test:
    ///
    /// * a@0.1.0 depends on b@1.0.0
    /// * b@1.0.0 depends on d@0.2.1
    /// * d@0.2.1 does not exist in the index
    ///
    /// As a result, the requirement on d@0.2.1 by b is unsatisfiable, and b does not permit any of
    /// the other available versions from being selected (it wants _only_ 0.2.1).
    #[test]
    #[should_panic = "Because there is no version of d in >= 0.2.1 and < 0.2.2"]
    fn resolver_resolve_package_not_found() {
        let index = PackageIndex::from_iter([
            (
                "a",
                vec![(
                    "0.1.0".parse().unwrap(),
                    vec![("b", VersionSet::from("=1.0.0".parse::<VersionReq>().unwrap()))],
                )],
            ),
            (
                "b",
                vec![(
                    "1.0.0".parse().unwrap(),
                    vec![
                        ("c", VersionSet::full()),
                        ("d", VersionSet::from("=0.2.1".parse::<VersionReq>().unwrap())),
                    ],
                )],
            ),
            (
                "c",
                vec![("0.2.0".parse().unwrap(), vec![]), ("0.3.0".parse().unwrap(), vec![])],
            ),
            (
                "d",
                vec![
                    ("0.1.0".parse().unwrap(), vec![]),
                    ("0.2.5".parse().unwrap(), vec![]),
                    ("1.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver {
            index: &index,
            context: ResolverContext::Package {
                root: PackageId::from("a"),
                version: "0.1.0".parse().unwrap(),
            },
        };
        let _ = resolver.resolve().unwrap();
    }

    /// In this test:
    ///
    /// * a@0.1.0 depends on b@1.0.0
    /// * b@1.0.0 depends on d@0.2.1 and any version of c
    /// * c@0.2.0 depends on d@0.2.5
    /// * c@0.3.0 depends on any d that matches ^1.0.0
    ///
    /// As a result, there is a conflict in the requirements for b and c; the former has a strict
    /// requirement on 0.2.1, but both versions of c that are available require newer versions of
    /// d than 0.2.1.
    #[test]
    #[should_panic = "because c =0.3.0 depends on d >= 1.0.0 and < 2.0.0, c depends on d >= 0.2.5 and < 0.2.6, or >= 1.0.0 and < 2.0.0"]
    fn resolver_resolve_package_conflict() {
        let index = PackageIndex::from_iter([
            (
                "a",
                vec![(
                    "0.1.0".parse().unwrap(),
                    vec![("b", VersionSet::from("=1.0.0".parse::<VersionReq>().unwrap()))],
                )],
            ),
            (
                "b",
                vec![(
                    "1.0.0".parse().unwrap(),
                    vec![
                        ("c", VersionSet::full()),
                        ("d", VersionSet::from("=0.2.1".parse::<VersionReq>().unwrap())),
                    ],
                )],
            ),
            (
                "c",
                vec![
                    (
                        "0.2.0".parse().unwrap(),
                        vec![("d", VersionSet::from("=0.2.5".parse::<VersionReq>().unwrap()))],
                    ),
                    (
                        "0.3.0".parse().unwrap(),
                        vec![("d", VersionSet::from("^1.0.0".parse::<VersionReq>().unwrap()))],
                    ),
                ],
            ),
            (
                "d",
                vec![
                    ("0.1.0".parse().unwrap(), vec![]),
                    ("0.2.1".parse().unwrap(), vec![]),
                    ("0.2.5".parse().unwrap(), vec![]),
                    ("1.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver {
            index: &index,
            context: ResolverContext::Package {
                root: PackageId::from("a"),
                version: "0.1.0".parse().unwrap(),
            },
        };
        let _ = resolver.resolve().unwrap();
    }

    /// In this test:
    ///
    /// * a@0.1.0 depends on b@1.0.0
    /// * b@1.0.0 depends on d matching ^0.2.1 and any version of c
    /// * c@0.2.0 depends on d matching ^0.2.5
    /// * c@0.3.0 depends on d matching ^1.0.0
    ///
    /// While b@1.0.0 and c have differing requirements on d - c@0.2.0 has a requirement on d that
    /// is compatible with b's requirement on d (according to semantic versioning rules).
    ///
    /// As a result, the resolver is expected to select c@0.2.0 here, as it is the only version
    /// that satisfies all requirements in the dependency tree.
    #[test]
    fn resolver_resolve_compatible_packages() {
        let index = PackageIndex::from_iter([
            (
                "a",
                vec![(
                    "0.1.0".parse().unwrap(),
                    vec![("b", VersionSet::from("=1.0.0".parse::<VersionReq>().unwrap()))],
                )],
            ),
            (
                "b",
                vec![(
                    "1.0.0".parse().unwrap(),
                    vec![
                        ("c", VersionSet::full()),
                        ("d", VersionSet::from("^0.2.1".parse::<VersionReq>().unwrap())),
                    ],
                )],
            ),
            (
                "c",
                vec![
                    (
                        "0.2.0".parse().unwrap(),
                        vec![("d", VersionSet::from("^0.2.5".parse::<VersionReq>().unwrap()))],
                    ),
                    (
                        "0.3.0".parse().unwrap(),
                        vec![("d", VersionSet::from("^1.0.0".parse::<VersionReq>().unwrap()))],
                    ),
                ],
            ),
            (
                "d",
                vec![
                    ("0.1.0".parse().unwrap(), vec![]),
                    ("0.2.1".parse().unwrap(), vec![]),
                    ("0.2.5".parse().unwrap(), vec![]),
                    ("1.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver {
            index: &index,
            context: ResolverContext::Package {
                root: PackageId::from("a"),
                version: "0.1.0".parse().unwrap(),
            },
        };

        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", "1.0.0"), ("c", "0.2.0"), ("d", "0.2.5")]);

        assert_selected(&selected, &expected);
    }
}
