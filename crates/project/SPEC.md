# Miden Project And Packaging: Post-Hoc Specification

## Scope

This document specifies the current project/versioning/dependency behavior implemented by:

- `miden-project`
- `miden-assembly` / `ProjectAssembler`
- `miden-mast-package`
- `miden-package-registry`
- `miden-package-registry-local`

It is intentionally implementation-first. Where the current behavior appears surprising, incomplete, or inconsistent with older documentation, that is called out explicitly.

## Versioning Model

### Source projects

- A source project is versioned only by the semantic version declared in `miden-project.toml` under `[package].version`.
- Workspace members may inherit a version from `[workspace.package].version`, but the effective version is still a semantic version only.
- A source project does not have an artifact digest until it is assembled.

### Assembled packages

- A `.masp` package preserves the project semantic version as package metadata.
- The assembled package also has a content digest, derived from the package MAST artifact.
- In the package registry and dependency solver, the effective package identity of a published artifact is `name + semver + digest`.
- In assembled package manifests, each runtime dependency records:
  - dependency package name
  - dependency target kind
  - dependency semantic version
  - dependency digest

### Registry version identity

- The registry uses `Version` values of the form `semver` or `semver#digest`.
- Published packages are registered canonically as `semver#digest`.
- `miden-package-registry-local` rejects duplicate registrations for the same package name and semantic version, even if the bytes or digest differ.
- Consequently, a semantic version can map to at most one canonical published artifact in the local registry.

## Dependency Specification

### Accepted manifest forms

Project dependencies in `miden-project.toml` may currently be expressed as:

- a semantic version requirement string, e.g. `dep = "=1.2.3"`
- a digest-only requirement string, e.g. `dep = "0x..."`
- an exact published package requirement string, e.g. `dep = "1.2.3#0x..."`
- a path dependency table, e.g. `dep = { path = "../dep" }`
- a path dependency table with requirement, e.g. `dep = { path = "../dep", version = "^1.2.0" }`
- a git dependency table, e.g. `dep = { git = "...", branch = "main" }`
- a git dependency table with semantic version requirement, e.g. `dep = { git = "...", rev = "deadbeef", version = "^1.2.0" }`
- a workspace-inherited dependency entry, e.g. `dep.workspace = true` or `dep = { workspace = true, linkage = "static" }`

### Registry-hosted dependencies

- A dependency with neither `path` nor `git` is resolved via the configured package registry.
- Registry requirements support:
  - semantic version requirements
  - digest-only requirements
  - exact `semver#digest` requirements
- Registry resolution uses `find_latest`.
- Semantic requirements select the latest matching semantic version.
- Exact `semver#digest` requirements select only that exact published artifact.
- Digest-only requirements select the latest registered package version whose digest matches.
- If multiple semantic versions share the same digest, a plain digest-only lookup still prefers the latest matching registered version.
- When additional semantic constraints on that same dependency are introduced transitively, the dependency solver intersects the digest and semantic constraints and can select a compatible shared-digest version instead of failing resolution.

### Path dependencies

- A `path` dependency may point to:
  - a project directory
  - a workspace root directory
  - a `.masp` artifact
- If `path` points to a project/workspace source tree and no `version` is provided:
  - no additional version validation is performed
  - the dependency uses whatever semantic version is declared in the referenced source manifest
- If `path` points to a project/workspace source tree and `version` is provided:
  - assembly/dependency-graph construction fails unless the referenced source manifest version satisfies the requirement
- If `path` points to a `.masp` artifact and no `version` is provided:
  - the dependency uses whatever semantic version and digest are embedded in that artifact
- If `path` points to a `.masp` artifact and `version` is provided:
  - the requirement is validated against the fully-qualified package version

### Workspace dependencies

- Inside a workspace, any dependency inherited via `workspace = true` is taken from `[workspace.dependencies]`.
- When the inherited dependency path resolves to a member located within the workspace root, it is treated as a workspace-member dependency rather than a generic path dependency.
- Workspace-member dependencies always use the current workspace member source version, not any registry version.
- Package-level linkage may override the linkage defined at the workspace level.
- Workspace-member dependency resolution ignores any registry packages with the same name.

### Git dependencies

- A `git` dependency must specify exactly one of:
  - `branch`
  - `rev`
- `branch` and `rev` together are rejected.
- Digest-only and exact `semver#digest` requirements are rejected for `git` dependencies.
- If no `version` is provided:
  - no additional semantic-version validation is performed
  - the dependency uses whatever semantic version is declared by the checked-out project manifest at the requested revision
- If `version` is provided:
  - dependency resolution fails unless the checked-out project manifest version satisfies the semantic version requirement
- Git dependencies are resolved by cloning/fetching into a cache, checking out the requested revision, and loading `miden-project.toml` from the repository root.

## Assembly And Publication Behavior

### Assembling source dependencies

- Source dependencies resolved from workspace/path/git are assembled before being linked into the dependent package.
- Source dependencies are automatically published to the mutable package store used by `ProjectAssembler`.
- The root package being assembled is not auto-published by `ProjectAssembler`; publication happens only for source dependencies.

### Reuse of already-registered source packages

- Before re-assembling a source dependency, `ProjectAssembler` tries to reuse an already-registered canonical package with the same package name and semantic version.
- Reuse is allowed only if source provenance matches:
  - path/workspace sources use a provenance check derived from the target metadata and the effective manifest/source inputs used for assembly
  - git sources use `repo + resolved commit hash`
- Workspace-manifest changes that do not change a member package’s effective manifest, semantic version, profiles, or dependencies do not prevent reuse of that member package.
- If the registry already contains the same package name and semantic version but different provenance, assembly fails and instructs the caller to bump the semantic version.
- If the registry already contains the same package name and semantic version but the package lacks provenance metadata, assembly also fails and instructs the caller to bump the semantic version.

### Runtime dependency recording

- Dynamically linked dependencies are recorded in the assembled package manifest.
- Statically linked dependencies are not recorded directly, but their own dynamic dependencies are propagated upward.
- Kernel dependencies are always recorded as runtime dependencies, even when linked statically for executable assembly.
- Runtime dependency merging requires exact agreement on dependency name, semantic version, kind, and digest; otherwise assembly fails with a runtime dependency conflict.

### Executable package names

- Library-like targets produce packages named exactly after the project package name.
- Executable targets produce packages named `project:target`.

## Special Cases And Under-Specified Behavior

### Current special cases

- Digest-only requirements are weaker than exact `semver#digest` requirements and stronger than plain semantic requirements, but they are not semver-aware when multiple semantic versions reuse one digest.
- A path dependency pointing at source accepts a digest-only or exact `semver#digest` requirement syntactically, but such a requirement is only satisfiable for a preassembled `.masp` path, not for source-only projects, because source projects do not have digests before assembly.
- Workspace-member dependencies always resolve to the workspace member’s current source version; they do not preserve any explicit semantic requirement from the original path-based workspace dependency declaration once it is normalized to a workspace-member dependency.
- Git dependencies only support repositories whose project manifest is at repository root.
- `assemble_with_sources` omits source-provenance sections and bypasses source-path hashing for the package being assembled from provided modules.
