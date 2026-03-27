# miden-package-registry

Shared package registry interfaces, metadata types, and dependency resolution for Miden packages.

This crate provides:

- `PackageRegistry`, the read-oriented trait used by package resolution and project dependency graph construction
- `PackageResolver`, a PubGrub-backed resolver generic over any `PackageRegistry`
- `InMemoryPackageRegistry`, a simple `BTreeMap`-backed implementation for tests and embedding
- shared metadata types such as `PackageId`, `Version`, `VersionRequirement`, and `PackageRecord`

Version resolution currently follows these rules:

- each package semantic version maps to at most one canonical published artifact in the registry
- semantic version requirements select the latest available matching canonical semantic version
- digest requirements match only the exact package digest
- exact `semver#digest` requirements match only that canonical published artifact
- indexed package dependencies are stored as exact resolved requirements from published artifacts

Artifact storage is intentionally out of scope for this crate. Concrete registries are expected to
pair the metadata/index implementation here with their own package storage strategy.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
