# miden-package-registry

Shared package registry interfaces, metadata types, and dependency resolution for Miden packages.

This crate provides:

- `PackageRegistry`, the read-oriented trait used by package resolution and project dependency graph construction
- `PackageResolver`, a PubGrub-backed resolver generic over any `PackageRegistry`
- `InMemoryPackageRegistry`, a simple `BTreeMap`-backed implementation for tests and embedding
- shared metadata types such as `PackageId`, `Version`, `VersionRequirement`, and `PackageRecord`

Version resolution currently follows these rules:

- semantic version requirements select the latest available matching version
- digest requirements match only the exact package digest
- indexed package dependencies are stored as exact resolved requirements from published artifacts

Artifact storage is intentionally out of scope for this crate. Concrete registries are expected to
pair the metadata/index implementation here with their own package storage strategy.
