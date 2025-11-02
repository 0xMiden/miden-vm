---
title: "Miden Debugger"
sidebar_position: 2
---

# Miden Debugger

The Miden debugger is a command-line interface (CLI) application, inspired by [GNU gdb](https://sourceware.org/gdb/), which allows debugging of Miden assembly (MASM) programs. The debugger allows the user to step through the execution of the program, both forward and backward, either per clock cycle tick, or via breakpoints.

The Miden debugger supports the following commands:

| Command | Shortcut | Arguments | Description |
| --- | --- | --- | --- |
| next | n | count? | Steps `count` clock cycles. Will step `1` cycle of `count` is omitted. |
| continue | c | - | Executes the program until completion, failure or a breakpoint. |
| back | b | count? | Backward step `count` clock cycles. Will back-step `1` cycle of `count` is omitted. |
| rewind | r | - | Executes the program backwards until the beginning, failure or a breakpoint. |
| print | p | - | Displays the complete state of the virtual machine. |
| print mem | p m | address? | Displays the memory value at `address`. If `address` is omitted, didisplays all the memory values. |
| print stack | p s | index? | Displays the stack value at `index`. If `index` is omitted, displays all the stack values. |
| clock | c | - | Displays the current clock cycle. |
| quit | q | - | Quits the debugger. |
| help | h | - | Displays the help message. |

In order to start debugging, the user should provide a `MASM` program:

```shell
cargo run --features executable -- debug --assembly miden-vm/masm-examples/nprime/nprime.masm
```

The expected output is:

```
============================================================
Debug program
============================================================
Reading program file `miden-vm/masm-examples/nprime/nprime.masm`
Compiling program... done (16 ms)
Debugging program with hash 11dbbddff27e26e48be3198133df8cbed6c5875d0fb
606c9f037c7893fde4118...
Reading input file `miden-vm/masm-examples/nprime/nprime.inputs`
Welcome! Enter `h` for help.
>>
```

In order to add a breakpoint, the user should insert a `breakpoint` instruction into the MASM file. This will generate a `Noop` operation that will be decorated with the debug break configuration. This is a provisory solution until the source mapping is implemented.

The following example will halt on the third instruction of `foo`:

```
proc.foo
    dup
    dup.2
    breakpoint
    swap
    add.1
end

begin
    exec.foo
end
```
