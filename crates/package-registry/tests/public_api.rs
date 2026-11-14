use miden_package_registry::{
    InvalidVersionError, SemVer, SemVerError, Version, VersionReq, VersionRequirement,
};

#[test]
fn version_paths_preserve_semver_and_registry_identities() {
    let semver: SemVer = "1.2.3".parse().unwrap();
    let _: &miden_package_registry::semver::Version = &semver;
    let registry_version = Version::from(semver);
    let requirement: VersionReq = "^1.2".parse().unwrap();
    let _: &miden_package_registry::semver::VersionReq = &requirement;
    assert!(registry_version.satisfies(&VersionRequirement::from(requirement)));

    let error: SemVerError = "invalid".parse::<SemVer>().unwrap_err();
    let _: &miden_package_registry::semver::Error = &error;
    let _ = InvalidVersionError::Version(error);
}
