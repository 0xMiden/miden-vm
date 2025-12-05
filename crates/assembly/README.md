# Miden Assembly

This crate contains Miden assembler.

The purpose of the assembler is to compile/assemble [Miden Assembly (MASM)](https://0xMiden.github.io/miden-vm/user_docs/assembly/main.html)
source code into a Miden VM program (represented by `Program` struct). The program
can then be executed on Miden VM [processor](../processor).

## Compiling Miden Assembly

To assemble a program for the Miden VM from some Miden Assembly source code, you first
need to instantiate the assembler, and then call one of its provided assembly methods,
e.g. `assemble`.

The `assemble` method takes the source code of an executable module as a string, or
file path, and either compiles it to a `Program`, or returns an error if the program
is invalid in some way. The error type returned can be pretty-printed to show rich
diagnostics about the source code from which an error is derived, when applicable,
much like the Rust compiler.

### Example

```rust
use std::path::Path;
use miden_assembly::Assembler;
use miden_assembly_syntax::debuginfo::DefaultSourceManager;
use std::sync::Arc;

// Instantiate a default, empty assembler
let assembler = Assembler::new(Arc::new(DefaultSourceManager::default()));

// Emit a program which pushes values 3 and 5 onto the stack and adds them
let program1 = assembler.assemble_program("begin push.3 push.5 add end")
    .unwrap();

// Note: assemble_program() takes ownership of the assembler, so create a new one for the next program
let assembler2 = Assembler::new(Arc::new(DefaultSourceManager::default()));

// Emit a program from some source code on disk (requires the `std` feature)
let program2 = assembler2.assemble_program(Path::new("../../miden-vm/masm-examples/fib/fib.masm"))
    .unwrap();
```

> **Note:** The default assembler provides no kernel or standard libraries, you must
> explicitly add those using the various builder methods of `Assembler`, as
> described in the next section.

## Assembler Options

As noted above, the default assembler is instantiated with nothing in it but
the source code you provide. If you want to support more complex programs, you
will want to factor code into libraries and modules, and then link all of them
together at once. This can be achieved using a set of builder methods of the
`Assembler` struct, e.g. `with_dynamic_library`, `with_kernel`, etc.

We'll look at a few of these in more detail below. See the module documentation
for the full set of APIs and how to use them.

### Libraries

The first use case that you are likely to encounter is the desire to factor out
some shared code into a _library_. A library is a set of modules which belong
to a common namespace, and which are packaged together. The
[core library](../../libcore) is an example of this.

To call code in this library from your program entrypoint, you must add the
library to the instance of the assembler you will compile the program with,
using the `with_dynamic_library` or `link_dynamic_library` methods.

To be a bit more precise, a library can be anything that implements the `Library`
trait, allowing for some flexibility in how they are managed. The core library
referenced above implements this trait, so if we wanted to make use of the Miden
core library in our own program, we would add it like so:

```rust
# use miden_assembly::Assembler;
# use miden_assembly_syntax::debuginfo::DefaultSourceManager;
# use miden_libcore::CoreLibrary;
# use std::sync::Arc;
#
let assembler = Assembler::new(Arc::new(DefaultSourceManager::default()))
    .with_dynamic_library(&CoreLibrary::default())
    .unwrap();
```

The resulting assembler can now compile code that invokes any of the
core library procedures by importing them from the namespace of
the library, as shown next:

```masm
use std::math::u64

begin
    push.1.0
    push.2.0
    exec.u64::wrapping_add
end
```

A generic container format for libraries, which implements `Library` and
can be used for any set of Miden assembly modules belonging to the same
namespace, is provided by the `MaslLibrary` struct.

A `MaslLibrary` serializes/deserializes to the `.masl` file format, which
is a binary format containing the parsed, but uncompiled, Miden Assembly
code in the form of its abstract syntax tree. You can construct and load
`.masl` files using the `MaslLibrary` interface.

### Program Kernels

A _program kernel_ defines a set of procedures which can be invoked via
`syscall` instructions. Miden programs are always compiled against some kernel,
and by default this kernel is empty, and so no `syscall` instructions are
allowed.

You can provide a kernel in one of two ways: a precompiled `Kernel` struct,
or by compiling a kernel module from source, as shown below:

```rust
# use miden_assembly::Assembler;
# use miden_assembly_syntax::debuginfo::DefaultSourceManager;
# use std::sync::Arc;
#
# // Create a source manager
# let source_manager = Arc::new(DefaultSourceManager::default());

// First, assemble the kernel library
let kernel_lib = Assembler::new(source_manager.clone())
    .assemble_kernel("pub proc foo add end")
    .unwrap();

// Create assembler with the kernel
let assembler = Assembler::with_kernel(source_manager, kernel_lib);
```

Programs compiled by this assembler will be able to make calls to the
`foo` procedure by executing the `syscall` instruction, like so:

```rust
# use miden_assembly::Assembler;
# use miden_assembly_syntax::debuginfo::DefaultSourceManager;
# use std::sync::Arc;
#
# // Create a source manager
# let source_manager = Arc::new(DefaultSourceManager::default());

// First, assemble the kernel library
let kernel_lib = Assembler::new(source_manager.clone())
    .assemble_kernel("pub proc foo add end")
    .unwrap();

// Create assembler with the kernel and assemble program
let program = Assembler::with_kernel(source_manager, kernel_lib)
    .assemble_program("
begin
    syscall.foo
end
").unwrap();
```

> **Note:** An unqualified `syscall` target is assumed to be defined in the kernel module.
> This is unlike the `exec` and `call` instructions, which require that callees
> resolve to a local procedure; a procedure defined in an explicitly imported
> module; or the hash of a MAST root corresponding to the compiled procedure.
>
> These options are also available to `syscall`, with the caveat that whatever
> method is used, it _must_ resolve to a procedure in the kernel specified to
> the assembler, or compilation will fail with an error.

### Debug Mode

The assembler can be instantiated in debug mode. Compiling a program with such an assembler retains source mappings between assembly instructions and VM operations. Thus, when such a program is executed using the `execute_iter()` function of the [processor](../processor), it is possible to correlate each
instruction with the source code that it is derived from. You can do this as
shown below:

```rust
# use miden_assembly::Assembler;
# use miden_assembly_syntax::debuginfo::DefaultSourceManager;
# use std::sync::Arc;
#
// Instantiate the assembler in debug mode
let assembler = Assembler::new(Arc::new(DefaultSourceManager::default()));
```

## Putting it all together

To help illustrate how all of the topics we discussed above can be combined
together, let's look at one last example:

```rust
use miden_assembly::Assembler;
use miden_assembly_syntax::debuginfo::DefaultSourceManager;
use miden_libcore::CoreLibrary;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Source code of the kernel module
    let kernel = "pub proc foo add end";

    // Create a source manager
    let source_manager = Arc::new(DefaultSourceManager::default());

    // First, assemble the kernel library
    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(kernel)?;

    // Instantiate the assembler with multiple options at once
    let assembler = Assembler::with_kernel(source_manager, kernel_lib)
        .with_dynamic_library(&CoreLibrary::default())?;

    // Assemble our program
    let program = assembler.assemble_program("
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
