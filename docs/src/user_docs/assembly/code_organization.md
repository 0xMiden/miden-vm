---
title: "Code Organization"
sidebar_position: 2
---

## Code organization
A Miden assembly program is just a sequence of instructions each describing a specific directive or an operation. You can use any combination of whitespace characters to separate one instruction from another.

In turn, Miden assembly instructions are just keywords which can be parameterized by zero or more parameters. The notation for specifying parameters is *keyword.param1.param2* - i.e., the parameters are separated by periods. For example, `push.123` instruction denotes a `push` operation which is parameterized by value `123`.

Miden assembly programs are organized into procedures. Procedures, in turn, can be grouped into modules.

### Procedures
A *procedure* can be used to encapsulate a frequently-used sequence of instructions which can later be invoked via a label. A procedure must start with a `proc.<label>.<number of locals>` instruction and terminate with an `end` instruction. For example:
```
proc.foo.2
    <instructions>
end
```
A procedure label must start with a letter and can contain any combination of numbers, ASCII letters, and underscores (`_`). Should you need to represent a label with other characters, an extended set is permitted via quoted identifiers, i.e. an identifier surrounded by `".."`. Quoted identifiers additionally allow any alphanumeric letter (ASCII or UTF-8), as well as various common punctuation characters: `!`, `?`, `:`, `.`, `<`, `>`, and `-`. Quoted identifiers are primarily intended for representing symbols/identifiers when compiling higher-level languages to Miden Assembly, but can be used anywhere that normal identifiers are expected.

The number of locals specifies the number of memory-based local field elements a procedure can access (via `loc_load`, `loc_store`, and [other instructions](./io_operations.md#random-access-memory)). If a procedure doesn't need any memory-based locals, this parameter can be omitted or set to `0`. A procedure can have at most $2^{16}$ locals, and the total number of locals available to all procedures at runtime is limited to $2^{30}$. Note that the assembler internally always rounds up the number of declared locals to the nearest multiple of 4.

To execute a procedure, the `exec.<label>`, `call.<label>`, and `syscall.<label>` instructions can be used. For example:
```
exec.foo
```
The difference between using each of these instructions is explained in the [next section](./execution_contexts.md#procedure-invocation-semantics).

A procedure may execute any other procedure, however recursion is not currently permitted, due to limitations imposed by the Merkalized Abstract Syntax Tree. Recursion is caught by static analysis of the call graph during assembly, so in general you don't need to think about this, but it is a limitation to be aware of. For example, the following code block defines a program with two procedures:

```
proc.bar
    <instructions>
    exec.foo
    <instructions>
end

proc.foo
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
procref.foo mem_storew.ADDR dropw push.ADDR

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
A *module* consists of one or more procedures. There are two types of modules: *library modules* and *executable modules* (also called *programs*).

#### Library modules
Library modules contain zero or more internal procedures and one or more exported procedures. For example, the following module defines one internal procedure (defined with `proc` instruction) and one exported procedure (defined with `export` instruction):
```
proc.foo
    <instructions>
end

export.bar
    <instructions>
    exec.foo
    <instructions>
end
```

#### Programs
Executable modules are used to define programs. A program contains zero or more internal procedures (defined with `proc` instruction) and exactly one main procedure (defined with `begin` instruction). For example, the following module defines one internal procedure and a main procedure:
```
proc.foo
    <instructions>
end

begin
    <instructions>
    exec.foo
    <instructions>
end
```
A program cannot contain any exported procedures.

When a program is executed, the execution starts at the first instruction following the `begin` instruction. The main procedure is expected to be the last procedure in the program and can be followed only by comments.

#### Importing modules
To reference items in another module, you must either import the module you wish to use, or specify a fully-qualified path to the item you want to reference.

To import a module, you must use the `use` keyword in the top level scope of the current module, as shown below:

```
use.std::math::u64

begin
  ...
end
```

In this example, the `std::math::u64` module is imported as `u64`, the default "alias" for the imported module. You can specify a different alias like so:

```
use.std::math::u64->bigint
```

This would alias the imported module as `bigint` rather than `u64`. The alias is needed to reference items from the imported module, as shown below:

```
use.std::math::u64

begin
    push.1.0
    push.2.0
    exec.u64::wrapping_add
end
```

You can also bypass imports entirely, and specify an absolute procedure path, which requires prefixing the path with `::`. For example:

```
begin
  push.1.0
  push.2.0
  exec.::std::math::u64::wrapping_add
end
```

In the examples above, we have been referencing the `std::math::u64` module, which is a module in the [Miden Standard Library](../stdlib/index.md). There are a number of useful modules there, that provide a variety of helpful functionality out of the box.

If the assembler does not know about the imported modules, assembly will fail. You can register modules with the assembler when instantiating it, either in source form, or precompiled form. See the [miden-assembly docs](https://crates.io/crates/miden-assembly) for details. The assembler will use this information to resolve references to imported procedures during assembly.

#### Re-exporting procedures
A procedure defined in one module can be re-exported from a different module under the same or a different name. For example:
```
use.std::math::u64

export.u64::add
export.u64::mul->mul64

export.foo
    <instructions>
end
```

In the module shown above, not only is the locally-defined procedure `foo` exported, but so are two procedures named `add` and `mul64`, whose implementations are defined in the `std::math::u64` module.

Similar to procedure invocation, you can bypass the explicit import by specifying an absolute path, like so:

```
export.::std::math::u64::mul->mul64
```

Additionally, you may re-export a procedure using its MAST root, so long as you specify an alias:

```
export.0x0000..0000->mul64
```

In all of the forms described above, the actual implementation of the re-exported procedure is defined externally. Other modules which reference the re-exported procedure, will have those references resolved to the original procedure during assembly.

### Constants
Miden assembly supports constant declarations. These constants are scoped to the module they are defined in and can be used as immediate parameters for Miden assembly instructions. Constants are supported as immediate values for many of the instructions in the Miden Assembly instruction set, see the documentation for specific instructions to determine whether or not it provides a form which accepts immediate operands.

A constant's name must start with an upper-case letter and can contain any combination of numbers, upper-case ASCII letters, and underscores (`_`). The number of characters in a constant name cannot exceed 100.

A constant's value must be in a decimal or hexadecimal form and be in the range between $0$ and $2^{64} - 2^{32}$ (both inclusive). Value can be defined by an arithmetic expression using `+`, `-`, `*`, `/`, `//`, `(`, `)` operators and references to the previously defined constants if it uses only decimal numbers. Here `/` is a field division and `//` is an integer division. Note that the arithmetic expression cannot contain spaces.

```
use.std::math::u64

const.CONSTANT_1=100
const.CONSTANT_2=200+(CONSTANT_1-50)
const.ADDR_1=3

begin
    push.CONSTANT_1.CONSTANT_2
    exec.u64::wrapping_add
    mem_store.ADDR_1
end

```

#### Word constants

Along with the regular value constants a _word_ constants could be used. They could be declared as an array of four elements or as a long hex value, and then could be used in the `push` instructions referenced by their name. Notice that a word constant can not be used in a constant expression.

```
const.SAMPLE_WORD=[1,2,3,4]
const.SAMPLE_HEX_WORD=0x0200000000000000030000000000000004000000000000000500000000000000

begin
    push.SAMPLE_WORD       # is equivalent to push.1.2.3.4
    push.SAMPLE_HEX_WORD.6 # is equivalent to push.2.3.4.5.6
end
```

#### Constant slices

It is possible to get just some part of a word constant using slice notation. This could be done by specifying a range in square brackets right after the constant's name. Attempt to get slices from constants which don't represent words will result in errors. 

```
const.SAMPLE_WORD=[5,6,7,8]
const.SAMPLE_VALUE=9

begin
    push.SAMPLE_WORD[1..3]  # is equivalent to push.6.7
    push.SAMPLE_WORD[0]     # is equivalent to push.5

    push.SAMPLE_VALUE[1..3] # returns an error: invalid slice constant
end
```

If a slice with an invalid or empty range is used with a word constant, an error will be returned.

```
const.SAMPLE_WORD=[5,6,7,8]

begin
    push.SAMPLE_WORD[10..6] # returns an error: invalid or empty range
    push.SAMPLE_WORD[5..7]  # returns an error: invalid or empty range
    push.SAMPLE_WORD[2..2]  # returns an error: invalid or empty range

end
```

### Comments
Miden assembly allows annotating code with simple comments. There are two types of comments: single-line comments which start with a `#` (pound) character, and documentation comments which start with `#!` characters. For example:
```
#! This is a documentation comment
export.foo
    # this is a comment
    push.1
end
```
Documentation comments must precede a procedure declaration. Using them inside a procedure body is an error.
