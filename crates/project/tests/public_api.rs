use miden_project::{SemVer, Version, VersionReq, VersionRequirement};

#[test]
fn version_paths_preserve_registry_identities() {
    let semver: SemVer = "1.2.3".parse().unwrap();
    let _: &miden_package_registry::SemVer = &semver;
    let version: Version = semver.into();
    let _: &miden_package_registry::Version = &version;
    let requirement: VersionReq = "^1.2".parse().unwrap();
    let _: &miden_package_registry::VersionReq = &requirement;
    let requirement = VersionRequirement::from(requirement);
    let _: &miden_package_registry::VersionRequirement = &requirement;
    assert!(version.satisfies(&requirement));
}

#[cfg(all(feature = "std", feature = "serde"))]
#[test]
fn dependency_graph_paths_remain_available() {
    let _: Option<miden_project::ProjectDependencyGraph> = None;
    let _: Option<miden_project::ProjectDependencyNode> = None;
    let _: Option<miden_project::ProjectDependencyEdge> = None;
}
