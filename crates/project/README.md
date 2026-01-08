# miden-project

This crate defines the interfaces for working with `miden-project.toml` files and the corresponding Miden project metadata.

## Terminology

The following document uses some terminology that may be easier to reason about if you understand the specific definitions we're using for those terms in this context:

- *Package*, a single library, program, or component that can be assembled, linked against, and distributed. A package in binary form is considered _assembled_. We also refer to packages as an organizational unit, i.e. before they are assembled, we organize source code into units that correspond to the packages we intend to produce from that source code. Typically the type of package we're referring to will be clear from context, but if we need to distinguish between them, then we use _assembled package_ to refer to the binary form. For an intuition about packages, you can consider a Miden package roughly equivalent to a Rust crate.
- *Project*, refers to the meta-organization of one or more packages into a single unit. See the definition for _Workspace_ for more details on multi-package projects.
- *Workspace*, refers to a project that contains multiple packages, and can share/inherit dependencies and configuration defined at the workspace level. These work just like Cargo workspaces, if you are familiar with their semantics.
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

[dependencies]
```

This represents an empty workspace for a new project at version `0.1.0`.

The next step is to create subdirectories for each sub-project, and initialize those as called for by the tooling of the language used in that project.

For examples of Miden Assembly and Rust-based projects, see the section below titled [Defining a project](#defining-a-project).

## Defining a project

To define a new project, all you need is a new directory containing the source code of the project (organization of which is language-specific), and in that directory, create a `miden-project.toml` which contains at least the following:

```toml
[package]
name = "name"
version = "0.1.0" # or whatever semantic version you like
```

This provides the bare minimum metadata needed to construct a basic package. However, in practice you are likely going to want to define [_targets_](#defining-targets), and declare [_dependencies_](#dependency-management).

### Defining targets

A _target_ corresponds to a specific artifact that you want to produce from the project. Most projects will have a single target, but in some cases multiple targets may be useful, particularly for kernels.

Let's add a target to the `miden-project.toml` of the project we created in the previous section:

```toml
[package]
name = "name"
version = "0.1.0"

# The following target is what would be inferred if no targets were declared
# in this file, also known as the _default target_.
[[target]]
kind = "lib"       # the type of artifact we're producing
path = "mod.masm"  # the relative path to the root module
namespace = "name" # the root namespace of modules parsed for this target
```

As noted above, we've added a target definition that is equivalent to the default target that is inferred if no targets are explicitly declared: a library, whose root module is expected to be found in `mod.masm`, and whose modules will all belong to the `name` namespace (individual modules will have
their path derived from the directory structure).

There are other types of targets though, currently the available kinds are:

* `library`, `lib` - produce a package which exports one or more procedures that can be called from other artifacts, but cannot be executed by the Miden VM without additional setup. Libraries have no implicit dependency on any particular kernel.
* `executable`, `bin`, or `program` - produce a package which has a single entrypoint, and can be executed by the Miden VM directly. Executables have no dependency on any particular kernel. 
* `account-component` - produce a package which is a valid account component in the Miden protocol, and contains all metadata needed to construct that component. This type is only valid in conjunction with the Miden transaction kernel.
* `note-script` - produce a package which is a valid note script in the Miden protocol, and exports the necessary metadata and procedures to construct and execute the note. This type is only valid in conjunction with the Miden transaction kernel.
* `tx-script` - produce a package which is a valid transaction script in the Miden protocol, and exports the necessary metadata and procedures to construct and execute the script. This type is only valid in conjunction with the Miden transaction kernel.

As noted earlier, you may define multiple targets in a single Miden project - however you must then request a specific target when assembling the project.

### Dependency management

A key benefit of Miden project manifests is the ability to declare dependencies on Miden packages, and then use those packages in your project, without having to manage the complexity of working with the contents of those packages yourself.

Dependencies are declared in `miden-project.toml` in one of the following forms:

```toml
[dependencies]
# A semantic version constraint
a = "=0.1.0"
# A specific package, given by its content digest
b = "0x......"
# A path dependency
c = { path = "../c" }
d = { path = "../c", version = "~> 0.1.0" }
# A git dependency
e = { git = "https://github.com/example/e", branch = "main" }
f = { git = "https://github.com/example/f", rev = "deadbeef" }
g = { git = "https://github.com/example/g", rev = "deadbeef", version = "~> 0.1.0" }
```

#### Semantics

* `a` specifies a semantic version requirement, these would be evaluated against a package registry implementation
* `b` specifies a package digest, essentially this acts as a stricter SemVer requirement of the form `=MAJ.MIN.PATCH`, where what is required is a version that has exactly the given digest. This form is also evaluated against a package registry implementation.
* `c` specifies that the package sources (or a package artifact) can be found at the given path. The version is inferred from the package at that path, but is essentially equivalent to `version = "*"`.
* `d` is the same as `c`, except it specifies a semantic version requirement that _MUST_ match the package found at `path`
* `e` specifies that the package sources can be found by cloning the `git` repo, and checking out the `main` branch.
* `f` is the same as `e`, except it provides a specific revision in the `git` repo instead
* `g` is the same as `f`, except it specifies a semantic version requirement that _MUST_ match the package found in the cloned repo

In cases where the dependency is resolved to project sources and _not_ an assembled package, the behavior would be to assemble those dependencies first, and then link against them when assembling the current project. This is most useful when linking against packages which are _not_ contracts, or where the contracts are deployed together as a unit.

**NOTE:** Currently there is no canonical package registry, so the resolution of the first two forms described above is dependent on the specific tool that is doing the resolution, namely, how it populates the package index for the resolver provided by this crate.

### Build profiles

TODO

### Custom package metadata

TODO

### Lint configuration

TODO
