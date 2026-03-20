use alloc::{boxed::Box, format, string::String};
use core::{cmp::Reverse, convert::Infallible};

use pubgrub::{Dependencies, DependencyProvider, SelectedDependencies};
use smallvec::SmallVec;

use super::{version_set::VersionSetFilter, *};
#[cfg(test)]
use crate::InMemoryPackageRegistry;
use crate::{PackageId, PackageRecord, PackageRegistry, SemVer, Version, VersionRequirement};

/// Represents package priorities in the resolver.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackagePriority {
    Weak(Reverse<u8>),
    Singleton(Reverse<u8>),
    Digest(Reverse<u8>),
    Workspace,
    Root,
}

/// A PubGrub-backed resolver that operates on any [`PackageRegistry`] implementation.
pub struct PackageResolver<'a, R: PackageRegistry + ?Sized> {
    index: &'a R,
    context: ResolverContext,
}

impl<'a, R: PackageRegistry + ?Sized> PackageResolver<'a, R> {
    /// Create a resolver for a root package that is not in a workspace.
    pub fn for_package(root: impl Into<PackageId>, version: SemVer, index: &'a R) -> Self {
        Self {
            index,
            context: ResolverContext::Package { root: root.into(), version },
        }
    }

    /// Create a resolver for a root package in a workspace.
    pub fn for_workspace(
        root: impl Into<PackageId>,
        version: SemVer,
        members: impl IntoIterator<Item = impl Into<PackageId>>,
        index: &'a R,
    ) -> Self {
        Self {
            index,
            context: ResolverContext::Workspace {
                members: SmallVec::from_iter(members.into_iter().map(|member| member.into())),
                root: root.into(),
                root_version: version,
            },
        }
    }

    pub fn resolve(self) -> Result<SelectedDependencies<Self>, DependencyResolutionError> {
        let (package, version) = match &self.context {
            ResolverContext::Workspace { root, root_version: version, .. }
            | ResolverContext::Package { root, version } => (root, version),
        };
        self.resolve_for(package.clone(), version.clone())
    }

    /// Resolve dependencies for `package` with the given semantic version.
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
    fn try_prioritize(&self, package: &PackageId) -> Option<PackagePriority> {
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

impl<R: PackageRegistry + ?Sized> DependencyProvider for PackageResolver<'_, R> {
    type P = PackageId;
    type V = Version;
    type VS = VersionSet;
    type M = String;
    type Priority = PackagePriority;
    type Err = Infallible;

    fn prioritize(
        &self,
        package: &Self::P,
        range: &Self::VS,
        _package_conflicts_counts: &pubgrub::PackageResolutionStatistics,
    ) -> Self::Priority {
        if let Some(priority) = self.context.try_prioritize(package) {
            priority
        } else {
            let version_count = self
                .index
                .available_versions(package)
                .map(|versions| {
                    versions
                        .keys()
                        .filter(|version| {
                            <VersionSet as pubgrub::VersionSet>::contains(range, version)
                        })
                        .count()
                })
                .unwrap_or(0)
                .min(u8::MAX as usize) as u8;
            PackagePriority::Weak(Reverse(version_count))
        }
    }

    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        let Some(versions) = self.index.available_versions(package) else {
            return Ok(None);
        };
        let filter = range.filter();
        let ranges = range.range();
        if range.is_digest_only()
            && let VersionSetFilter::Digest(digests) = filter
        {
            let version = versions
                .keys()
                .rev()
                .find(|version| {
                    version.digest.as_ref().is_some_and(|digest| digests.contains(digest))
                })
                .cloned();

            Ok(version)
        } else if let Some((start, end)) = ranges.bounding_range() {
            let range = (start.cloned(), end.cloned());
            let version = versions
                .range(range)
                .rev()
                .find_map(|(version, _)| {
                    if filter.matches(version) && ranges.contains(&version.version) {
                        Some(version)
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
                .find(|version| filter.matches(version) && ranges.contains(&version.version))
                .cloned();

            Ok(version)
        }
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        let Some(available) = self.index.available_versions(package) else {
            return Ok(Dependencies::Unavailable(format!(
                "no package named '{package}' found in registry"
            )));
        };

        let Some(record) = available.get(version) else {
            return Ok(Dependencies::Unavailable(format!(
                "version '{version}' of '{package}' was not found in registry"
            )));
        };

        Ok(Dependencies::Available(self.record_to_version_sets(record)))
    }

    fn should_cancel(&self) -> Result<(), Self::Err> {
        Ok(())
    }
}

impl<R: PackageRegistry + ?Sized> PackageResolver<'_, R> {
    fn record_to_version_sets(
        &self,
        record: &PackageRecord,
    ) -> pubgrub::DependencyConstraints<PackageId, VersionSet> {
        record
            .dependencies()
            .iter()
            .map(|(name, requirement)| {
                let set = match requirement {
                    VersionRequirement::Digest(digest) => self
                        .index
                        .available_versions(name)
                        .map(|versions| {
                            VersionSet::from_available_digest(digest.into_inner(), versions.keys())
                        })
                        .unwrap_or_else(<VersionSet as pubgrub::VersionSet>::empty),
                    _ => VersionSet::from(requirement.clone()),
                };
                (name.clone(), set)
            })
            .collect()
    }
}

#[derive(thiserror::Error)]
pub enum DependencyResolutionError {
    #[error("dependency resolution failed: {}", format_solution_error(.0))]
    NoSolution(Box<pubgrub::DerivationTree<PackageId, VersionSet, String>>),
    #[error("could not get dependencies for '{package}' version '{version}': {error}")]
    FailedRetreivingDependencies {
        package: PackageId,
        version: Version,
        error: String,
    },
    #[error("could not choose version for {package}: {error}")]
    FailedToChooseVersion { package: PackageId, error: String },
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

impl<R: PackageRegistry + ?Sized> From<pubgrub::PubGrubError<PackageResolver<'_, R>>>
    for DependencyResolutionError
{
    fn from(error: pubgrub::PubGrubError<PackageResolver<'_, R>>) -> Self {
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
    use pubgrub::SelectedDependencies;

    use super::*;
    use crate::{VersionReq, VersionRequirement};

    fn any() -> VersionRequirement {
        VersionRequirement::from(VersionReq::STAR.clone())
    }

    fn req(value: &str) -> VersionRequirement {
        let req = value.parse::<VersionReq>().unwrap();
        VersionRequirement::from(req)
    }

    fn digest_requirement(value: Word) -> VersionRequirement {
        VersionRequirement::from(value)
    }

    fn exact_requirement(version: &str, digest: Word) -> VersionRequirement {
        VersionRequirement::Exact(Version::new(version.parse().unwrap(), digest))
    }

    fn select<'a>(
        packages: &[(&str, &str)],
    ) -> SelectedDependencies<PackageResolver<'a, InMemoryPackageRegistry>> {
        packages
            .iter()
            .map(|(name, version)| {
                let name = PackageId::from(*name);
                let version = match version.split_once('@') {
                    Some((version, hex)) => {
                        let version = version.parse::<SemVer>().unwrap();
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
        resolved: &SelectedDependencies<PackageResolver<'a, InMemoryPackageRegistry>>,
        expected: &SelectedDependencies<PackageResolver<'a, InMemoryPackageRegistry>>,
    ) {
        use core::cmp::Ordering;

        match resolved.len().cmp(&expected.len()) {
            Ordering::Equal | Ordering::Greater => {
                for (key, value) in resolved.iter() {
                    assert_eq!(
                        expected.get(key),
                        Some(value),
                        "unexpected dependency found in selection",
                    );
                }
            },
            Ordering::Less => {
                for (key, value) in expected.iter() {
                    assert_eq!(
                        resolved.get(key),
                        Some(value),
                        "missing expected dependency '{key}@{value}'",
                    );
                }
            },
        }
    }

    #[test]
    fn registry_find_latest_version() {
        let index = InMemoryPackageRegistry::from_iter([(
            "foo",
            vec![
                ("0.1.0".parse().unwrap(), vec![]),
                ("0.2.0".parse().unwrap(), vec![]),
                ("0.2.1".parse().unwrap(), vec![]),
            ],
        )]);

        let record = index
            .find_latest(
                &PackageId::from("foo"),
                &VersionRequirement::from("^0.2.0".parse::<VersionReq>().unwrap()),
            )
            .expect("missing matching version");

        assert_eq!(record.semantic_version(), &"0.2.1".parse().unwrap());
    }

    #[test]
    fn registry_find_digest_version() {
        let digest = Rpo256::hash(b"foo");
        let index = InMemoryPackageRegistry::from_iter([(
            "foo",
            vec![(Version::new("1.0.0".parse().unwrap(), digest), vec![])],
        )]);

        let record = index
            .find_latest(&PackageId::from("foo"), &VersionRequirement::from(digest))
            .expect("missing digest match");

        assert_eq!(record.semantic_version(), &"1.0.0".parse().unwrap());
        assert_eq!(record.digest(), Some(&digest));
    }

    #[test]
    fn registry_find_digest_prefers_latest_matching_semver_when_digest_is_reused() {
        let digest = Rpo256::hash(b"foo");
        let index = InMemoryPackageRegistry::from_iter([(
            "foo",
            vec![
                (Version::new("1.0.0".parse().unwrap(), digest), vec![]),
                (Version::new("2.0.0".parse().unwrap(), digest), vec![]),
            ],
        )]);

        let record = index
            .find_latest(&PackageId::from("foo"), &VersionRequirement::from(digest))
            .expect("missing digest match");

        assert_eq!(record.semantic_version(), &"2.0.0".parse().unwrap());
        assert_eq!(record.digest(), Some(&digest));
    }

    #[test]
    fn exact_requirement_uses_hash_separator() {
        let digest = Rpo256::hash(b"foo");
        let requirement = exact_requirement("1.0.0", digest);
        assert_eq!(format!("{requirement}"), format!("1.0.0#{digest}"));
    }

    #[test]
    fn resolver_resolve_mixed_versioning_schemes() {
        let digest = Rpo256::hash(b"the digest for 'b'");
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", digest_requirement(digest))])]),
            (
                "b",
                vec![
                    (
                        Version::new("1.0.0".parse().unwrap(), digest),
                        vec![("c", any()), ("d", req("=0.2.1"))],
                    ),
                    ("1.0.1".parse().unwrap(), vec![("c", any()), ("d", req("=0.2.1"))]),
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

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve 'a'");
        let b_version = format!("1.0.0@{digest}");
        let expected =
            select(&[("a", "0.1.0"), ("b", b_version.as_str()), ("c", "0.3.0"), ("d", "0.2.1")]);

        assert_selected(&selected, &expected);
    }

    #[test]
    #[should_panic = "Because there is no version of d in >= 0.2.1 and < 0.2.2"]
    fn resolver_resolve_package_not_found() {
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", req("=1.0.0"))])]),
            ("b", vec![("1.0.0".parse().unwrap(), vec![("c", any()), ("d", req("=0.2.1"))])]),
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

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let _ = resolver.resolve().unwrap();
    }

    #[test]
    #[should_panic = "because c =0.3.0 depends on d >= 1.0.0 and < 2.0.0, c * depends on d >= 0.2.5 and < 0.2.6, or >= 1.0.0 and < 2.0.0"]
    fn resolver_resolve_package_conflict() {
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", req("=1.0.0"))])]),
            ("b", vec![("1.0.0".parse().unwrap(), vec![("c", any()), ("d", req("=0.2.1"))])]),
            (
                "c",
                vec![
                    ("0.2.0".parse().unwrap(), vec![("d", req("=0.2.5"))]),
                    ("0.3.0".parse().unwrap(), vec![("d", req("^1.0.0"))]),
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

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let _ = resolver.resolve().unwrap();
    }

    #[test]
    fn resolver_resolve_compatible_packages() {
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", req("=1.0.0"))])]),
            ("b", vec![("1.0.0".parse().unwrap(), vec![("c", any()), ("d", req("^0.2.1"))])]),
            (
                "c",
                vec![
                    ("0.2.0".parse().unwrap(), vec![("d", req("^0.2.5"))]),
                    ("0.3.0".parse().unwrap(), vec![("d", req("^1.0.0"))]),
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

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", "1.0.0"), ("c", "0.2.0"), ("d", "0.2.5")]);

        assert_selected(&selected, &expected);
    }

    #[test]
    fn resolver_resolves_transitive_exact_digest_dependencies() {
        let b_digest = Rpo256::hash(b"b");
        let c_digest = Rpo256::hash(b"c");
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", digest_requirement(b_digest))])]),
            (
                "b",
                vec![(
                    Version::new("1.0.0".parse().unwrap(), b_digest),
                    vec![("c", digest_requirement(c_digest))],
                )],
            ),
            ("c", vec![(Version::new("2.0.0".parse().unwrap(), c_digest), vec![])]),
        ]);

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[
            ("a", "0.1.0"),
            ("b", &format!("1.0.0@{b_digest}")),
            ("c", &format!("2.0.0@{c_digest}")),
        ]);

        assert_selected(&selected, &expected);
    }

    #[test]
    fn resolver_resolves_exact_version_requirements() {
        let b_digest = Rpo256::hash(b"b");
        let index = InMemoryPackageRegistry::from_iter([
            (
                "a",
                vec![("0.1.0".parse().unwrap(), vec![("b", exact_requirement("1.0.0", b_digest))])],
            ),
            (
                "b",
                vec![
                    (Version::new("1.0.0".parse().unwrap(), b_digest), vec![]),
                    ("1.0.1".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", &format!("1.0.0@{b_digest}"))]);

        assert_selected(&selected, &expected);
    }

    #[test]
    fn resolver_resolves_semantic_singleton_to_digest_qualified_version() {
        let b_digest = Rpo256::hash(b"b");
        let index = InMemoryPackageRegistry::from_iter([
            ("a", vec![("0.1.0".parse().unwrap(), vec![("b", req("=1.0.0"))])]),
            (
                "b",
                vec![
                    (Version::new("1.0.0".parse().unwrap(), b_digest), vec![]),
                    ("2.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", &format!("1.0.0@{b_digest}"))]);

        assert_selected(&selected, &expected);
    }

    #[test]
    fn resolver_exact_requirement_ignores_newer_versions_with_same_digest() {
        let b_digest = Rpo256::hash(b"b");
        let index = InMemoryPackageRegistry::from_iter([
            (
                "a",
                vec![("0.1.0".parse().unwrap(), vec![("b", exact_requirement("1.0.0", b_digest))])],
            ),
            (
                "b",
                vec![
                    (Version::new("1.0.0".parse().unwrap(), b_digest), vec![]),
                    (Version::new("2.0.0".parse().unwrap(), b_digest), vec![]),
                    ("3.0.0".parse().unwrap(), vec![]),
                ],
            ),
        ]);

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", &format!("1.0.0@{b_digest}"))]);

        assert_selected(&selected, &expected);
    }

    #[test]
    fn resolver_keeps_plain_and_precise_versions_separate() {
        let digest = Rpo256::hash(b"a");
        let mut index = InMemoryPackageRegistry::default();

        let dep_id = PackageId::from("dep");
        index.insert(
            dep_id.clone(),
            "1.0.0".parse::<Version>().unwrap(),
            None::<(PackageId, VersionRequirement)>,
        );
        index.insert(
            dep_id.clone(),
            Version::new("1.0.0".parse().unwrap(), digest),
            None::<(PackageId, VersionRequirement)>,
        );

        let versions = index
            .available_versions(&dep_id)
            .into_iter()
            .flat_map(|versions| versions.keys().map(alloc::string::ToString::to_string))
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(versions.len(), 2, "versions = {versions:?}");
    }

    #[test]
    fn resolver_prefers_compatible_shared_digest_version() {
        let digest = Rpo256::hash(b"shared");
        let index = InMemoryPackageRegistry::from_iter([
            (
                "a",
                vec![(
                    "0.1.0".parse().unwrap(),
                    vec![("b", digest_requirement(digest)), ("c", req("=1.0.0"))],
                )],
            ),
            (
                "b",
                vec![
                    (Version::new("1.0.0".parse().unwrap(), digest), vec![]),
                    (Version::new("2.0.0".parse().unwrap(), digest), vec![]),
                ],
            ),
            ("c", vec![("1.0.0".parse().unwrap(), vec![("b", req("=1.0.0"))])]),
        ]);

        let resolver = PackageResolver::for_package("a", "0.1.0".parse().unwrap(), &index);
        let selected = resolver.resolve().expect("failed to resolve");
        let expected = select(&[("a", "0.1.0"), ("b", &format!("1.0.0@{digest}")), ("c", "1.0.0")]);

        assert_selected(&selected, &expected);
    }
}
