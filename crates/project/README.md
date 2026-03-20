# miden-project

This crate defines the interfaces for working with `miden-project.toml` files and the corresponding Miden project metadata.

## Terminology

The following document uses some terminology that may be easier to reason about if you understand the specific definitions we're using for those terms in this context:

- *Package*, a single library, program, or component that can be assembled, linked against, and distributed. A package in binary form is considered _assembled_. We also refer to packages as an organizational unit, i.e. before they are assembled, we organize source code into units that correspond to the packages we intend to produce from that source code. Typically the type of package we're referring to will be clear from context, but if we need to distinguish between them, then we use _assembled package_ to refer to the binary form. For an intuition about packages, you can consider a Miden package roughly equivalent to a Rust crate.
- *Project*, refers to the meta-organization of one or more packages into a single unit (i.e. defined by a single `miden-project.toml`). It may also be used as an umbrella term for either a single project, or a _workspace_ (see below).
- *Workspace*, refers to the meta-organization of one or more projects into a single hierarchy, i.e. a project-of-projects. Workspaces are useful when multiple projects would benefit from sharing dependencies and other configuration. This concept is based on Cargo workspaces from Rust.
- *Target*, refers to a specific package artifact that is derivable from a project
- *Version*, refers to the semantic version of a project/package
- *Digest*, refers to the content digest/hash associated with a specific assembled package. Only assembled packages have content digests. When available for a specific package, the content digest becomes an extension of its _version_, and is taken into account during dependency resolution when a specific digest is required by a dependency spec.

## What is a Miden project?

A Miden project, at its most basic, is comprised of two things:

1. A manifest file (i.e. `miden-project.toml`) which describes the project and its dependencies, as well as configuration for tooling in the Miden ecosystem.
2. The source code of the project. This could be any of the following:
  - Miden Assembly
  - Rust, using an installed `cargo-miden`/`midenc` toolchain
  - Any language that can compile to the Miden VM, specifically, are able to produce Miden packages (i.e. `.masp` files).
  - Some combination of the above in one project

The above is the simplest form of project, oriented towards building a single Miden package. However, Miden projects may also be organized into workspaces, similar to how Cargo supports organizing Rust crates into workspaces.

## Versioning model

Miden projects and assembled Miden packages are related, but they are not versioned in exactly the same way:

- A source project is versioned by the semantic version declared in `miden-project.toml` under `[package].version`
- An assembled package preserves that semantic version, but also has a content digest derived from the assembled MAST artifact
- Only assembled packages have digests
- In a package registry, the exact published identity of an assembled package is `name + semver + digest`
- Exact dependency requirements therefore use the `semver#digest` form, e.g. `0.1.0#0x...`

## Workspaces

A Miden workspace is a meta-project that consists of one or more sub-projects that correspond to packages. A workspace is comprised of:

* A workspace-level manifest (i.e. `miden-project.toml`), with workspace-specific syntax, that defines configuration and metadata for the workspace, and is shared amongst members of the workspace.
* One or more subdirectories that contain a Miden project corresponding to a single package. These are the "members" of the workspace.

The benefit of using workspaces is when working with multiple package projects that depend on each other, or which share configuration - as opposed to managing them all independently, which would require much more duplication.

### Defining a workspace

To define a workspace, simply create a new directory, and in that directory,
create a `miden-project.toml` file which contains the following:

```toml
[workspace]
members = []

[workspace.package]
version = "0.1.0"

[workspace.dependencies]
```

This represents an empty workspace for a new project at version `0.1.0`.

The next step is to create subdirectories for each sub-project, and initialize those as called for by the tooling of the language used in that project.

For examples of Miden Assembly and Rust-based projects, see the section below titled [Defining a project](#defining-a-project).

## Defining a project

To define a new project, all you need is a new directory containing the source code of the project (organization of which is language-specific), and in that directory, create a `miden-project.toml` which contains at least the following:

```toml
[package]
name = "foo"
version = "0.1.0" # or whatever semantic version you like
```

This provides the bare minimum metadata needed to construct a basic package. However, in practice you are likely going to want to define [_targets_](#defining-targets), and declare [_dependencies_](#dependency-management).

### Defining targets

A _target_ corresponds to a specific artifact that you want to produce from the project. Most projects will have a single target, but in some cases multiple targets may be useful, particularly for kernels.

Let's add a target to the `miden-project.toml` of the project we created in the previous section:

```toml
[package]
name = "foo"
version = "0.1.0"

# The following target is what would be inferred if no targets were declared
# in this file, also known as the _default target_.
# 
# Only one `[lib]` section can be present per-project.
[lib]
# The type of artifact we're producing
# 
# For `[lib]` the default kind is `library`, but other valid library kinds are:
# 
# * `kernel`
# * `account-component`
# * `note`
# * `tx-script`
kind = "library"
# The relative path to the root module, if the project is written in Miden 
# Assembly. Other languages, such as Rust, will omit this entirely.
path = "mod.masm" 
# The root namespace of modules parsed for this target
namespace = "name"
```

It is also possible to define one or more executable targets from a single
package. Expanding on the example above, lets add two executables that share the same code as the library, but with a different root module:

```toml
[[bin]]
# The `name` field is required when multiple `[[bin]]` targets are present, in
# order to disambiguate them as targets.
name = "primary"
# The `path` field is required, and must specify the path to the module 
# containing the executable entrypoint.
path = "main.masm"

[[bin]]
name = "alternate"
path = "main2.masm"
```

When assembling an executable/bin target, all modules in the same directory as 
`path` are provided to the assembler, _except_ the root modules of other executable targets. This allows the executable targets to build on top of the `[lib]` target easily. If you _don't_ want this behavior, simply ensure that the `[lib]` target and any `[[bin]]` targets locate their sources in separate subdirectories, e.g. `lib/mod.masm` and `primary/main.masm`/`alternate/main.masm` for the example above.

There is a special caveat to be aware of when requesting assembly of an executable target from a project with multiple targets (either a `[lib]` and a `[[bin]]`, multiple `[[bin]]` targets, or both): the name of the package produced for the executable targets must be disambiguated, and so the name of the executable target is appended to the project name. For example, in our example project defined above, assembling the `primary` target would produce a package named `foo:primary`.


### Default target

As noted in the previous section, the `[lib]` target we defined is equivalent to the default target that would have been inferred if no targets had been specified at all, i.e. the default target is a library, whose root module is expected to be `mod.masm`, found in the same directory as the manifest, and whose modules will all belong to the `foo` namespace (individual modules will have their path derived from the directory structure).

To recap, there are two categories of target, _library_ and _executable_, and _library_ targets have multiple flavors/kinds, listed below, and which are specified using `lib.kind`:

* `library`, `lib` - produce a package which exports one or more procedures that can be called from other artifacts, but cannot be executed by the Miden VM without additional setup. Libraries have no implicit dependency on any particular kernel.
* `kernel` - a special library type that provides core functionality in conjunction with an executable program. This is the only artifact type whose exports can be called using `syscall`, and that can be installed as a kernel when instantiating the VM.
* `account-component` - produce a package which is a valid account component in the Miden protocol, and contains all metadata needed to construct that component. This type is only valid in conjunction with the Miden transaction kernel.
* `note` - produce a package which is a valid note script in the Miden protocol, and exports the necessary metadata and procedures to construct and execute the note. This type is only valid in conjunction with the Miden transaction kernel.
* `tx-script` - produce a package which is a valid transaction script in the Miden protocol, and exports the necessary metadata and procedures to construct and execute the script. This type is only valid in conjunction with the Miden transaction kernel.

As noted earlier, you may define multiple targets in a single Miden project - however you must then request a specific target when assembling the project. Additionally, all targets in a project share the same dependency set.

### Dependency management

A key benefit of Miden project manifests is the ability to declare dependencies on Miden packages, and then use those packages in your project, without having to manage the complexity of working with the contents of those packages yourself.

Dependencies are declared in `miden-project.toml` in one of the following forms:

```toml
[dependencies]
# A semantic version constraint
a = "=0.1.0"
# A specific package, given by its content digest
b = "0x......"
# A specific published package version, given by semantic version and digest
c = "0.1.0#0x......"
# A path dependency
d = { path = "../d" }
e = { path = "../d", version = "~> 0.1.0" }
# A git dependency
f = { git = "https://github.com/example/f", branch = "main" }
g = { git = "https://github.com/example/g", rev = "deadbeef" }
h = { git = "https://github.com/example/h", rev = "deadbeef", version = "~> 0.1.0" }
```

#### Linkage

Dependencies are dynamically-linked by default, which means that the assembled
package will have a runtime dependency on the referenced package, and it is
assumed that the dependency will have been loaded into the VM at runtime.

You may also specify that a dependency should be statically-linked, like so:

```toml
[dependencies]
a = { version = "=0.1.0", linkage = "static" }
```

When a dependency is statically-linked, it is as if the dependency was defined
as part of your own package.

NOTE: Kernel dependencies are always statically-linked into executable targets,
and dynamically-linked for library targets, and it is not possible to change
this behavior.

#### Workspace dependencies

Workspace-level shared dependencies are declared under `[workspace.dependencies]`, and inherited by members using `dep.workspace = true` (or the equivalent table form).

When an inherited workspace dependency resolves to a member of the current workspace:

- it resolves to that member's current source project, not to a package registry entry
- the effective dependency version is the version currently declared by that member's manifest
- any explicit semantic requirement carried on the workspace dependency declaration does not override the member's current source version
- member projects may still override the linkage mode locally

#### Semantics

* `a` specifies a semantic version requirement, evaluated against a package registry implementation
* `b` specifies a digest-only requirement, evaluated against a package registry implementation. A plain digest-only lookup selects the latest matching published version; if additional semantic constraints on the same dependency are introduced transitively, the dependency solver intersects those constraints and can select a compatible shared-digest version instead.
* `c` specifies an exact published package version, including both semantic version and digest
* `d` specifies that the package sources (or a package artifact) can be found at the given path. If no `version` is provided, the current version declared by the referenced source/artifact is used as-is.
* `e` is the same as `d`, except it specifies a semantic version requirement that _MUST_ match the package found at `path`
* `f` specifies that the package sources can be found by cloning the `git` repo, and checking out the `main` branch. If no `version` is provided, the current version declared by the checked out sources is used as-is.
* `g` is the same as `f`, except it provides a specific revision in the `git` repo instead
* `h` is the same as `g`, except it specifies a semantic version requirement that _MUST_ match the package found in the cloned repo

In cases where the dependency is resolved to project sources and _not_ an assembled package, the behavior would be to assemble those dependencies first, and then link against them when assembling the current project. This is most useful when linking against packages which are _not_ contracts, or where the contracts are deployed together as a unit.

#### Source dependency reuse and provenance

When a dependency is resolved from workspace/path/git project sources, `ProjectAssembler` assembles that dependency before linking it into the current package, and publishes it into the package store used for the current assembly session.

Before re-assembling such a dependency, `ProjectAssembler` will try to reuse an already-registered package with the same package name and semantic version. Reuse is allowed only when the recorded source provenance matches:

- path/workspace dependencies are compared using the effective manifest/source inputs that affect the assembled package
- git dependencies are compared using the repository URI plus the resolved revision

If a package with the same name and semantic version is already registered with different provenance, or with missing provenance, the assembler will require the semantic version to be bumped before proceeding.

**NOTE:** Currently there is no canonical package registry, so the resolution of the first two forms described above is dependent on the specific tool that is doing the resolution, namely, how it populates the package index for the resolver provided by this crate.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
