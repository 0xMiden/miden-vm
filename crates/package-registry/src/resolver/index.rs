use alloc::collections::BTreeMap;

use crate::{
    PackageId, PackageRecord, PackageRegistry, PackageVersions, Version, VersionRequirement,
};

/// An in-memory package registry implementation used for tests, local tooling, and resolver state.
#[derive(Default)]
pub struct InMemoryPackageRegistry {
    packages: BTreeMap<PackageId, PackageVersions>,
}

impl InMemoryPackageRegistry {
    /// Construct a registry from an existing package map.
    pub fn from_packages(packages: BTreeMap<PackageId, PackageVersions>) -> Self {
        Self { packages }
    }

    /// Insert a new entry for `name` and `version`, creating a record from `dependencies`.
    pub fn insert<D, P, V>(&mut self, name: impl Into<PackageId>, version: Version, dependencies: D)
    where
        D: IntoIterator<Item = (P, V)>,
        P: Into<PackageId>,
        V: Into<VersionRequirement>,
    {
        let record_version = version.clone();
        let record = PackageRecord::new(
            record_version,
            dependencies
                .into_iter()
                .map(|(name, requirement)| (name.into(), requirement.into())),
        );
        self.insert_record(name, version, record);
    }

    /// Insert or update the metadata for `name` at `version`.
    pub fn insert_record(
        &mut self,
        name: impl Into<PackageId>,
        version: Version,
        record: PackageRecord,
    ) {
        use alloc::collections::btree_map::Entry;

        let name = name.into();
        match self.packages.entry(name) {
            Entry::Vacant(entry) => {
                let versions = BTreeMap::from_iter([(version, record)]);
                entry.insert(versions);
            },
            Entry::Occupied(mut entry) => {
                let versions = entry.get_mut();
                match versions.entry(version.clone()) {
                    Entry::Vacant(entry) => {
                        entry.insert(record);
                    },
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = record;
                    },
                }
            },
        }
    }

    /// Returns all packages recorded in this registry.
    pub fn packages(&self) -> &BTreeMap<PackageId, PackageVersions> {
        &self.packages
    }
}

impl PackageRegistry for InMemoryPackageRegistry {
    fn available_versions(&self, package: &PackageId) -> Option<&PackageVersions> {
        self.packages.get(package)
    }

    #[inline]
    fn register(&mut self, name: PackageId, version: Version, record: PackageRecord) {
        self.insert_record(name, version, record);
    }
}

impl<'a, V, D> FromIterator<(&'a str, V)> for InMemoryPackageRegistry
where
    D: IntoIterator<Item = (&'a str, VersionRequirement)>,
    V: IntoIterator<Item = (Version, D)>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, V)>,
    {
        let mut index = Self::default();
        for (name, versions) in iter {
            let name = PackageId::from(name);
            for (version, deps) in versions {
                let deps = deps
                    .into_iter()
                    .map(|(name, requirement)| (PackageId::from(name), requirement));
                index.insert(name.clone(), version, deps);
            }
        }
        index
    }
}
