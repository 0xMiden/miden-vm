---
title: "Code Organization"
sidebar_position: 2
---

## Code organization
A Miden assembly program is just a sequence of instructions each describing a specific directive or an operation. You can use any combination of whitespace characters to separate one instruction from another.

In turn, Miden assembly instructions are just keywords which can be parameterized by zero or more parameters. The notation for specifying parameters is *keyword.param1.param2* - i.e., the parameters are separated by periods. For example, `push.123` instruction denotes a `push` operation which is parameterized by value `123`.

Miden assembly programs are organized into procedures. Procedures, in turn, can be grouped into modules.

### Procedures
A *procedure* can be used to encapsulate a frequently-used sequence of instructions which can later be invoked via a label. A procedure is introduced using the `proc` keyword. Procedure definitions consist of the following parts, in the order they appear:

* Zero or more attributes which modify the procedure definition, or annotate it in some way. These can be user-defined, but there are also built-in attributes that modify the procedure itself. Currently, the only built-in attribute is `@locals(N)`, which specifies the number of procedure locals allocated for the procedure. See the [Attributes](#attributes) section for more on their syntax and semantics.
* An optional visibility modifier, i.e. `pub` if the procedure is to be exported from the containing module.
* The `proc` keyword
* The procedure name/label
* An optional type signature. See the [Types](#types) section for more details.
* The body of the procedure, consisting of one or more instructions, followed by `end`

The following is a complete demonstration of the syntax:

```
@locals(2)
pub proc foo(a: felt, b: felt) -> felt
    add
end
```

A procedure label must start with a letter and can contain any combination of numbers, ASCII letters, and underscores (`_`). Should you need to represent a label with other characters, an extended set is permitted via quoted identifiers, i.e. an identifier surrounded by `".."`. Quoted identifiers additionally allow any alphanumeric letter (ASCII or UTF-8), as well as various common punctuation characters: `!`, `?`, `:`, `.`, `<`, `>`, and `-`. Quoted identifiers are primarily intended for representing symbols/identifiers when compiling higher-level languages to Miden Assembly, but can be used anywhere that normal identifiers are expected.

The number of locals, given by `@locals(N)`, specifies that the procedure requires `N` elements of scratch memory be allocated for use by the VM when it is executed. The default number of locals is 0, so this attribute is not required unless a non-zero number of locals is required. The individual elements of the procedure local memory may be accessed by zero-based index using `loc_load`/`loc_store`, or treated like regular memory by obtaining the address of a specific slot via `locaddr`, and then using any other memory instruction. See [here](./io_operations.md#random-access-memory) for more information on those instructions. A procedure can have at most $2^{16}$ locals, and the total number of locals available to all procedures at runtime is limited to $2^{31} - 1$. Note that the assembler internally always rounds up the number of declared locals to the nearest multiple of 4.

To execute a procedure, the `exec.<label>`, `call.<label>`, and `syscall.<label>` instructions can be used. For example:
```
exec.foo
```
The difference between using each of these instructions is explained in the [next section](./execution_contexts.md#procedure-invocation-semantics).

A procedure may execute any other procedure, however recursion is not currently permitted, due to limitations imposed by the Merkalized Abstract Syntax Tree. Recursion is caught by static analysis of the call graph during assembly, so in general you don't need to think about this, but it is a limitation to be aware of. For example, the following code block defines a program with two procedures:

```
proc bar
    <instructions>
    exec.foo
    <instructions>
end

proc foo
    <instructions>
end

begin
    <instructions>
    exec.bar
    <instructions>
    exec.foo
end
```

#### Dynamic procedure invocation
It is also possible to invoke procedures dynamically - i.e., without specifying target procedure labels at compile time. A procedure can only call itself using dynamic invocation. There are two instructions, `dynexec` and `dyncall`, which can be used to execute dynamically-specified code targets. Both instructions expect the [MAST root](../../design/programs.md) of the target to be stored in memory, and the memory address of the MAST root to be on the top of the stack. The difference between `dynexec` and `dyncall` corresponds to the difference between `exec` and `call`, see the documentation on [procedure invocation semantics](./execution_contexts.md#procedure-invocation-semantics) for more details.


Dynamic code execution in the same context is achieved by setting the top element of the stack to the memory address where the  hash of the dynamic code block is stored, and then executing the `dynexec` or `dyncall` instruction. You can obtain the hash of a procedure in the current program, by name, using the `procref` instruction. See the following example of pairing the two:

```
# Retrieve the hash of `foo`, store it at `ADDR`, and push `ADDR` on top of the stack
procref.foo mem_storew_be.ADDR dropw push.ADDR

# Execute `foo` dynamically
dynexec
```

During assembly, the `procref.foo` instruction is compiled to a `push.HASH`, where `HASH` is the hash of the MAST root of the `foo` procedure.

During execution of the `dynexec` instruction, the VM does the following:

1. Read the top stack element $s_0$, and read the memory word starting at address $s_0$ (the hash of the dynamic target),
2. Shift the stack left by one element,
3. Load the code block referenced by the hash, or trap if no such MAST root is known,
4. Execute the loaded code block.

The `dyncall` instruction is used the same way, with the difference that it involves a context switch to a new context when executing the referenced block, and switching back to the calling context once execution of the callee completes.

### Modules
A *module* consists of one or more items (procedures, constants, types). There are two types of modules: *library modules* and *executable modules* (also called *programs*).

#### Library modules
Library modules contain zero or more private items and one or more exported (public) items. For example, the following module defines one private procedure and one public procedure:
```
proc foo
    <instructions>
end

pub proc bar
    <instructions>
    exec.foo
    <instructions>
end
```

#### Programs
Executable modules are used to define programs. A program contains zero or more private procedures and exactly one public procedure (the program entrypoint, defined with the `begin` keyword). For example, the following module defines one private procedure and the entrypoint:
```
proc foo
    <instructions>
end

begin
    <instructions>
    exec.foo
    <instructions>
end
```
A program cannot contain any exported procedures.

When a program is executed, the execution starts at the first instruction following the `begin` instruction.

#### Importing modules
To reference items in another module, you may either use imports (introduced using the `use` keyword at the top-level scope of a module), or by using the fully-qualified path of the item. This gives you three different ways to reference items, depending on what is most appropriate in a given context. Let's look at all three from the perspective of a concrete example, we want to invoke a public procedure `baz`, which is defined in the namespace `foo::bar`:

1. We can simply use the absolute/fully-qualified path to invoke the procedure, i.e. `exec.::foo::bar::baz`. Absolute paths must be prefixed with `::` to indicate that they are fully-qualified, otherwise the assembler will attempt to resolve them relative to the imports in scope.
2. We can import the `bar` namespace into scope with `use foo::bar`, which allows us to invoke the procedure using a relative path, i.e. `exec.bar::baz`. This approach only requires you to specify the fully-qualified path once to bring a namespace into scope, which reduces visual noise, while retaining a visual cue as to where a symbol reference is defined.
3. We can import the `baz` item directly into scope with `use foo::bar::baz`, allowing us to treat it like a locally-defined item, e.g. `exec.baz`

All three are demonstrated below:

```
use foo::bar
use foo::bar::baz

begin
  exec.::foo::bar::baz # no import, fully-qualified path
  exec.bar::baz # uses the first import, partially-qualified path
  exec.baz # uses the second import, unqualified path
end
```

Let's say we have a local symbol that conflicts with the symbol we're trying to import, we can work around this by renaming the imported symbol to avoid the conflict, as shown below:

```
use foo::bar->bar2
```

This would bring `bar` into scope as `bar2` instead:

```
use foo::bar->bar2

begin
    exec.bar2::baz
end
```

If the assembler cannot resolve external symbol references to a known module or item, assembly will fail. You can register modules with the assembler when instantiating it, either in source form, or precompiled form. See the [miden-assembly docs](https://crates.io/crates/miden-assembly) for details. The assembler will use this information to resolve references to imported items during assembly.

#### Re-exporting items
Items imported into a module, can also be simultaneously re-exported from that module, using the name bound to the symbol when it was imported. For example:
```
use miden::core::math::u64

pub use u64::add
pub use u64::mul->mul64

pub proc foo
    <instructions>
end
```

In the module shown above, not only is the locally-defined procedure `foo` exported, but so are two procedures named `add` and `mul64`, whose implementations are defined in the `miden::core::math::u64` module.

Similar to procedure invocation, you can bypass the explicit import by specifying an absolute path, like so:

```
pub use ::miden::core::math::u64::mul->mul64
```

Additionally, you may re-export a procedure using its MAST root, so long as you specify a name for it, as shown below:

```
pub use 0x0000..0000->mul64
```

Note that when an explicit MAST root is used, either directly, or via an alias like the example above - the assembler assumes that the MAST corresponding to that root will be available at runtime, and so it is up to you to either provide that code to the VM when executing the program, or statically link the code into the assembled program ahead of time using the assembler.

In all of the forms described above, the actual implementation of the re-exported procedure is defined externally. Other modules which reference the re-exported procedure, will have those references resolved to the original procedure during assembly.

You may attach documentation to re-exported items, e.g.:

```
#! Multiply two u64 integers
pub use ::miden::core::math::u64::mul
```

However you cannot attach attributes to re-exported items, i.e. the following is
not supported:

```
@foo
pub use ::miden::core::math::u64::mul
```

### Constants
Miden assembly supports constant declarations. Similar to procedures, constants have private visibility by default, but may be given `pub` visibility to export them for use from other modules. Constants can be used as immediates, rather than literals, with Miden assembly instructions that support immediate operands, avoiding duplicating the same literal expression in many places, as well as naming the value for readers. Many of the instructions in the Miden Assembly instruction set support immediate operands, but check the documentation to confirm that for specific instructions.

A constant's name must start with an upper-case letter and can contain any combination of numbers, upper-case ASCII letters, and underscores (`_`). The number of characters in a constant name cannot exceed 100.

A constant's value must be in a decimal or hexadecimal form and be in the range between $0$ and $2^{64} - 2^{32}$ (both inclusive). Value can be defined by an arithmetic expression using `+`, `-`, `*`, `/`, `//`, `(`, `)` operators and references to the previously defined constants if it uses only decimal numbers. Here `/` is a field division and `//` is an integer division. Note that the arithmetic expression cannot contain spaces.

```
use miden::core::math::u64
use mylib::CONSTANT_1 # constants can be imported like other items

# Constants can be exported like other items
pub const CONSTANT_2 = 200+(CONSTANT_1-50)
const ADDR_1 = 3

pub proc example
    push.CONSTANT_1.CONSTANT_2
    exec.u64::wrapping_add
    mem_store.ADDR_1
end
```

#### Word constants

Along with the regular value constants a _word_ constants could be used. They could be declared as an array of four elements or as a long hex value, and then could be used in the `push` instructions referenced by their name. Notice that a word constant can not be used in a constant expression.

```
const SAMPLE_WORD = [1,2,3,4]
const SAMPLE_HEX_WORD = 0x0200000000000000030000000000000004000000000000000500000000000000

begin
    push.SAMPLE_WORD       # is equivalent to push.1.2.3.4
    push.SAMPLE_HEX_WORD.6 # is equivalent to push.2.3.4.5.6
end
```

#### Constant slices

It is possible to get just some part of a word constant using slice notation. This could be done by specifying a range in square brackets right after the constant's name. Attempt to get slices from constants which don't represent words will result in errors.

```
const SAMPLE_WORD = [5,6,7,8]
const SAMPLE_VALUE = 9

begin
    push.SAMPLE_WORD[1..3]  # is equivalent to push.6.7
    push.SAMPLE_WORD[0]     # is equivalent to push.5

    push.SAMPLE_VALUE[1..3] # returns an error: invalid slice constant
end
```

If a slice with an invalid or empty range is used with a word constant, an error will be returned.

```
const SAMPLE_WORD = [5,6,7,8]

begin
    push.SAMPLE_WORD[10..6] # returns an error: invalid or empty range
    push.SAMPLE_WORD[5..7]  # returns an error: invalid or empty range
    push.SAMPLE_WORD[2..2]  # returns an error: invalid or empty range

end
```

### Types

Miden Assembly supports types for the purpose of specifying the _type signature_ of a procedure. This is used by other tooling in the Miden toolchain to bind against procedures written in Miden Assembly from higher-level languages, e.g. Rust. The type system is low-level and structural, but some conveniences are provided in Miden Assembly to improve ergonomics and aid in the construction of future static analyses.

#### Built-in types

The following types are built-in to Miden Assembly's type system:

* `i1`, a 1-bit integer, or boolean value
* `iN` and `uN`, signed and unsigned N-bit integer types, where N is a power of two. Alignment requirements match that of the C ABI for 32-bit architectures.
* `felt`, a field element. This type has a minimum alignment of 4 bytes when mapping Miden's memory to byte-addressable memory.
* `word`, an array of four `felt`, equivalent to `[felt; 4]`. This type is always aligned to an address divisible by 4 in Miden's memory, i.e. a "word-aligned" address.
* `ptr<T, addrspace(A)>`, a pointer to a value of type `T`, where the address space of the pointer is `A`. Valid values for `A` are `felt` and `byte`. The `felt` address space means that the address corresponds to an element address in Miden's memory. The `byte` address space means that the address is a byte address. Byte addresses are specified as resolving to an element address in Miden's memory by treating every element as a 4-byte chunk. The default address space is `felt`, so the `, addrspace(A)` syntax can be elided for pointer types which use the `felt` address space. Pointers are currently specified to be equivalent in representation to `u32`.
* `[T; N]`, an array of type `T` and size `N`. Minimum alignment is inherited from `T`
* `struct { name: T }`, an aggregate type consisting of one or more named fields. The minimum alignment of the struct type is determined by taking the largest minimum alignment of all the fields.

#### Type aliases

Miden Assembly supports type _aliases_, i.e. types which are aliases of one of the built-in types, but bound to a name. This allows factoring out complex type definitions from their uses, and allows providing more semantically meaningful names for types. These type definitions are introduced using the `type` keyword, as shown below:

```
type Id = u64
```

Similar to procedures and constants, you may import and export types whose declarations are given `pub` visibility:

In `a.masm`:
```
pub type Id = u64
```

In `b.masm`:
```
use a::Id

type Account = struct { id: Id }

pub proc get(id: Id) -> Account
    ...
end
```

#### Enum types

Miden Assembly also provides a special form, `enum`, for defining a type alias and a set of constants which represent the instances/values of the aliased type that are the only instances/values considered valid for the type alias. Let's look at an example:

```
enum Level : u8 {
    DEBUG = 1, # explicit discriminant, default is normally 0
    WARN,
    ERROR,
}

pub proc set_level(level: Level)
    ...
end
```

This is equivalent to the following:

```
type Level = u8

const DEBUG = 1
const WARN = DEBUG + 1
const ERROR = WARN + 1

pub proc set_level(level: Level)
    ...
end
```

Note that nothing currently validates that a `u8` value passed as an instance of `Level` is actually one of those three constants, that is up to you. Instead, the `enum` syntax is intended to provide more semantic information for readers of the code, and to better express the relationship between the type and the constants in question.

#### Type signatures

Procedure type signatures are expressed using familiar function type syntax, e.g.:

```
# A procedure which consumes a single value of type T from the operand stack
# and produces no output
proc foo(t: T)

# A procedure which consumes two values from the operand stack, first a value
# of type T, then a value of type U. Upon return, it pushes a value of type i1
# on the operand stack
proc foo(t: T, u: U) -> i1

# A procedure which consumes nothing from the operand stack, but pushes two
# values on the operand stack upon return, with the value of type i1 on top,
# followed by the value of type T
proc foo() -> (i1, T)
```

Values are expected to be laid out on the operand stack in the order they
appear, with the first to appear being on top of the operand stack. Additionally, a value is expected to be laid out on the operand stack by mapping its byte representation to 1 or more elements by treating each element as 4 bytes (with the exception of `felt`, which is converted 1:1), with the lowest-addressable bytes appearing closest to the top of the operand stack. The size of a value type is rounded up to the nearest element boundary, so a value of type `u8` would require a full element on the operand stack to represent; as would a value of type `struct { a: u8, b: u8, b: u16 }`, as the total size of the struct is 4 bytes. A value of type `[u32; 4]` on the other hand, would require 4 elements on the operand stack, with the element on top of the stack corresponding to the `u32` value at index 0 of the array.

The layout rules described above ensure that callers and callees can agree on how types will be passed and returned by value.

### Comments
Miden assembly allows annotating code with simple comments. There are two types of comments: single-line comments which start with a `#` (pound) character, and documentation comments which start with `#!` characters. For example:
```
#! This is a documentation comment
pub proc foo
    # this is a comment
    push.1
end
```
Documentation comments must precede a procedure declaration. Using them inside a procedure body is an error.
