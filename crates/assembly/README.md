# Miden Assembly

This crate contains Miden assembler.

The purpose of the assembler is to compile/assemble [Miden Assembly (MASM)](https://docs.miden.xyz/miden-vm/user_docs/assembly)
source code into a Miden VM program (represented by `Program` struct). The program
can then be executed on Miden VM [processor](../processor).

## Compiling Miden Assembly

To assemble a program for the Miden VM from some Miden Assembly source code, you first
need to instantiate the assembler, and then call one of its provided assembly methods,
e.g. `assemble_program`.

The `assemble_program` method takes the source code of an executable module as a string, or
file path, and either compiles it to an executable `Package`, or returns an error if the input
is invalid in some way. The error type returned can be pretty-printed to show rich
diagnostics about the source code from which an error is derived, when applicable,
much like the Rust compiler.

### Example

```rust,ignore
use std::path::Path;
use miden_assembly::{
    Assembler,
    debuginfo::{DefaultSourceManager, SourceManager},
};
use std::sync::Arc;

let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());

// Instantiate a default, empty assembler
let assembler = Assembler::new(source_manager.clone());

// Emit an executable package, named `prg` which pushes values 3 and 5 onto the
// stack and adds them
let _ = assembler.assemble_program("prg", "begin push.3 push.5 add end")
    .unwrap();

// Note: assemble_program() consumes the assembler, so create a new one for the
// next program
let assembler2 = Assembler::new(source_manager.clone());

// Emit a program from some source file on disk (requires the `std` feature).
// Standalone source files must declare their module path, e.g. `namespace $exec`.
let _ = assembler2.assemble_program("prg", Path::new("path/to/program.masm"))
    .unwrap();
```

> **Note:** The default assembler provides no kernel or standard libraries, you must
> explicitly add those using the various builder methods of `Assembler`, as
> described in the next section.

## Assembler Options

As noted above, the default assembler is instantiated with nothing in it but
the source code you provide. If you want to support more complex programs, you
will want to either use projects (see `miden-project` for more info), or factor code into libraries and modules, and then link all of them together at once. This can be achieved using a set of builder methods of the `Assembler` struct, e.g. `with_package`, `with_kernel`, etc.

We'll look at a few of these in more detail below. See the module documentation
for the full set of APIs and how to use them.

### Standalone Source Declarations

When source files are assembled through a `miden-project.toml` project, the project manifest provides the root module path and external package requirements. When assembling standalone source files directly through parser or assembler APIs, that information can be written in MASM source.

The canonical order for these top-level declarations is:

```masm
namespace my_package
extern package "miden-core@0.1.0"

pub mod api
mod internal

use miden::core::math::u64

pub proc add64
    exec.u64::wrapping_add
end
```

The `namespace` declaration gives the module its fully-qualified path. It is optional when the caller or project manifest already provides the module path, but if both are present they must agree. It must appear before any item, import, submodule, or external package declaration.

The `extern package "<package-id>"` declaration records an external package dependency for a standalone root module. It is optional when the module is assembled as part of a project, because the manifest supplies the dependency set. When reading a module tree from a root source file, `namespace` and `extern package` declarations belong in that root source file.

The `mod foo` and `pub mod foo` declarations define the direct child modules of the current module. Linked descendants must be declared by their parent modules. A private `mod` child is visible inside the declaring module and its descendants; a `pub mod` child is also visible through public module paths outside that internal scope. Module visibility is separate from item visibility, so public procedures, constants, and types still require `pub` or `pub use`.

Imports are resolved independently. `use path::to::module` and `pub use path::to::item` resolve from the global module tree, whether or not the path has a leading `::`. Descendants of the current module are imported with `use self::child::grandchild`. Import targets may not resolve through another import alias, and modules may not be re-exported with `pub use`; expose modules with `pub mod` instead.

Code references follow the same model: an item path is either absolute, such as `exec.::miden::core::math::u64::wrapping_add`, local, or qualified by an import alias or declared submodule in the current module. Unresolved relative-looking paths are not retried as global paths.

### Libraries/Packages

A Miden package (stored on disk with the `.masp` extension), is a binary artifact that contains assembled code, debug information, useful metadata about the package itself, and optional custom sections that can attach tool-specific data to a package. Packages provide the common unit of distribution and reuse of Miden Assembly code.

Naturally, the first use case that you are likely to encounter when building a Miden program, is the desire to factor out some shared code into a _library_. A library is a package containing reusable modules and functions, typically belonging to a common module path. The [core library](../../crates/lib/core) is an example of this.

To call code in a library from your program entrypoint, you must add the
library to the instance of the assembler you will compile the program with,
using the `with_package` or `link_package` methods, and specify how you want to link against that package - either dynamically (the package must then be provided at runtime) or statically (the package is linked into your own, such that you do not need to provide it separately at runtime).

For example, `miden_core_lib` provides a struct, called `CoreLibrary`, that wraps the deserialized library package containing the core library. It provides some convenience methods to access the raw package, as well as other useful items related to use of the core lib (e.g. event handlers).

To link against the core library, you could do the following:

```rust,ignore
# use miden_assembly::{Assembler, Linkage};
# use miden_assembly::debuginfo::{DefaultSourceManager, SourceManager};
# use miden_core_lib::CoreLibrary;
# use std::sync::Arc;
#
# // Create a source manager
# let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
let assembler = Assembler::new(Arc::clone(&source_manager))
    .with_package(CoreLibrary::default().package(), Linkage::Dynamic)
    .unwrap();
```

The resulting assembler can now compile code that invokes any of the core library procedures by importing them from the module path exported by the library, as shown next:

```masm
use miden::core::math::u64

begin
    push.1.0
    push.2.0
    exec.u64::wrapping_add
end
```

### Program Kernels

A _program kernel_ defines a set of procedures which can be invoked via
`syscall` instructions. Miden programs are always compiled against some kernel,
and by default this kernel is empty, and so no `syscall` instructions are
allowed.

You can provide a kernel in one of two ways: a precompiled kernel package,
or by assembling a kernel module from source, as shown below:

```rust
# use miden_assembly::{
#     Assembler, Path,
#     ast::{Module, ModuleKind},
#     debuginfo::{DefaultSourceManager, SourceManager},
# };
# use std::sync::Arc;
#
# // Create a source manager
# let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());

// First, parse and assemble the kernel library
let mut parser = Module::parser(Some(ModuleKind::Kernel));
let kernel = parser.parse_str(
    Some(Path::KERNEL),
    "pub proc foo add end",
    source_manager.clone(),
).unwrap();

let kernel_lib = Assembler::new(source_manager.clone())
    .assemble_kernel("my-kernel", kernel)
    .unwrap();

// Create assembler with the kernel
let assembler = Assembler::with_kernel(source_manager, kernel_lib.into()).unwrap();
```

Programs compiled by this assembler will be able to make calls to the
`foo` procedure by executing the `syscall` instruction, like so:

```rust
# use miden_assembly::{
#     Assembler, Path,
#     ast::{Module, ModuleKind},
#     debuginfo::{DefaultSourceManager, SourceManager},
# };
# use std::sync::Arc;
#
# // Create a source manager
# let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());
#
# // First, parse and assemble the kernel library
# let mut parser = Module::parser(Some(ModuleKind::Kernel));
# let kernel = parser.parse_str(
#     Some(Path::KERNEL),
#     "pub proc foo add end",
#     source_manager.clone(),
# ).unwrap();
# let kernel_lib = Assembler::new(source_manager.clone())
#     .assemble_kernel("my-kernel", kernel)
#     .unwrap();
#
// Create assembler with the kernel and assemble program
let _program = Assembler::with_kernel(source_manager, kernel_lib.into())
    .unwrap()
    .assemble_program("prg", "
begin
    syscall.foo
end
").unwrap();
```

> **Note:** An unqualified `syscall` target is assumed to be defined in the kernel module.
> This is unlike the `exec` and `call` instructions, which require that callees
> resolve to a local procedure; a procedure reached through an absolute,
> imported, or declared submodule path; or the hash of a MAST root corresponding
> to the compiled procedure.
>
> These options are also available to `syscall`, with the caveat that whatever
> method is used, it _must_ resolve to a procedure in the kernel specified to
> the assembler, or compilation will fail with an error.

## Putting it all together

To help illustrate how all of the topics we discussed above can be combined
together, let's look at one last example:

```rust
use miden_assembly::{
    Assembler, Path,
    ast::{Module, ModuleKind},
    debuginfo::{DefaultSourceManager, SourceManager},
};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Source code of the kernel module
    let kernel = "pub proc foo add end";

    // Create a source manager
    let source_manager: Arc<dyn SourceManager> = Arc::new(DefaultSourceManager::default());

    // First, parse and assemble the kernel library
    let mut parser = Module::parser(Some(ModuleKind::Kernel));
    let kernel = parser.parse_str(Some(Path::KERNEL), kernel, source_manager.clone())?;
    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel("my-kernel", kernel)?;

    // Instantiate the assembler with multiple options at once
    let assembler = Assembler::with_kernel(source_manager, kernel_lib.into()).unwrap();
    // If you wanted to link against the core library, you'd extend the above
    // with: `.with_package(miden_core_lib::CoreLibrary::default().package(), Linkage::Dynamic)?;`

    // Assemble our program
    let _program = assembler.assemble_program("prg", "
begin
    push.1.2
    syscall.foo
end
")?;

    Ok(())
}
```

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
