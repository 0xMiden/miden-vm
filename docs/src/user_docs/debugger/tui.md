---
title: TUI mode
sidebar_position: 3
---

# TUI mode

The default mode renders a full-screen terminal UI with live source,
disassembly, operand stack, call stack, and breakpoint panes. Launch it by
running `miden debug` with a program path:

```bash
miden debug sum.masp
```

When the debugger starts, it stops at cycle 0 so you can set up breakpoints
before the program runs.

## Layout

The home page is split into the following panes:

- **Source code** — current instruction's source line with syntax
  highlighting, when source is available.
- **Disassembly** — the five most recently executed VM instructions plus the
  cycle counter.
- **Stack trace** — call frames, when the program was compiled with frame
  tracing (`trace.240` / `trace.252`).
- **Operand stack** — current contents and depth.
- **Breakpoints** — active breakpoints and how many fired at this instruction.

Switch focus between panes with `h` / `l` (or the arrow keys).

## Keyboard shortcuts

| Key | Action |
| --- | ------ |
| `q` | Quit the debugger |
| `h` | Focus next pane |
| `l` | Focus previous pane |
| `s` | Step one VM cycle |
| `n` | Step to the next instruction |
| `c` | Continue until the next breakpoint or program end |
| `e` | Exit the current call frame (run until return) |
| `d` | Delete the focused item (e.g. a breakpoint when the breakpoints pane has focus) |
| `:` | Open the command prompt (see below) |

In any pane that lists items or shows multiple lines (source, disassembly,
breakpoints, stack trace), `j` / `k` (or up/down arrows) move the cursor.

## Command prompt

Press `:` to open the prompt. The footer shows what you type.

| Command | Aliases | Effect |
| ------- | ------- | ------ |
| `:quit` | `:q` | Exit the debugger |
| `:reload` | `:r`, `:restart` | Reload the program from disk and reset execution (breakpoints kept) |
| `:debug` | | Show the debugger's internal log (its own diagnostic stream) |
| `:next-line` | `:nl`, `:nextline` | Run until the next source line is reached |
| `:break SPEC` | `:b`, `:breakpoint` | Create a breakpoint — see [Breakpoints](#breakpoints) |
| `:read EXPR` | `:r EXPR` | Inspect linear memory — see [Reading memory](#reading-memory) |
| `:vars [all]` | `:variables`, `:locals` | Show source-level variables — see [Inspecting variables](#inspecting-variables) |
| `:where` | `:p`, `:proc` | Print the procedure name at the current instruction (and at the focused frame, if it differs) |

Typing an unknown command leaves the prompt and shows `unknown command` in the
status line.

## Breakpoints

`:break` (alias `:b`, `:breakpoint`) accepts six expression forms:

| Expression | Description |
| ---------- | ----------- |
| `:b FILE[:LINE]` | Break when the current instruction's source location matches `FILE` (a glob, e.g. `fib.masm` or `**/lib/*.masm`) and, when given, exactly the line number. |
| `:b in NAME` | Break when entering a procedure whose fully-qualified name matches the glob `NAME` (e.g. `:b in std::math::*`). |
| `:b for OPCODE` | Break when an instruction with the literal opcode `OPCODE` is about to execute (matched including immediates). |
| `:b next` | Break on the next instruction boundary. One-shot. |
| `:b after N` | Break after `N` more cycles. One-shot. |
| `:b at CYCLE` | Break when the cycle counter reaches `CYCLE`. No-op if `CYCLE` already passed. One-shot. |

`:b finish` is also accepted from the prompt; it's equivalent to the `e`
shortcut and stops when the current call frame returns.

Hit breakpoints are highlighted in the breakpoints pane; the pane's lower
right shows how many breakpoints triggered at the current cycle. One-shot
breakpoints (`next`, `after N`, `at CYCLE`, `finish`) are removed once they
fire.

To find a procedure name to plug into `:b in ...`, use `:where` — it prints
the live procedure as well as the procedure of the focused frame.

## Reading memory

`:read` (alias `:r`) reads linear memory in a chosen format.

```text
:r ADDR [OPTIONS..]
```

`ADDR` is decimal or `0x`-prefixed hex.

| Option | Alias | Values | Default | Description |
| ------ | ----- | ------ | ------- | ----------- |
| `-mode MODE` | `-m` | `words` (`word`, `w`), `bytes` (`byte`, `b`) | `words` | Address mode |
| `-format FORMAT` | `-f` | `decimal` (`d`), `hex` (`x`), `binary` (`bin`, `b`) | `decimal` | Output format for integers |
| `-count N` | `-c` | _integer_ | `1` | Number of units to read |
| `-type TYPE` | `-t` | see below | `word` | Type of value to read (sets default `-format` and unit size) |

### Types

| Type | Meaning |
| ---- | ------- |
| `iN` | Signed integer of `N` bits |
| `uN` | Unsigned integer of `N` bits |
| `felt` | A field element |
| `word` | A Miden word (four field elements) |
| `ptr`, `pointer` | A 32-bit memory address (forces `-format hex`) |

Examples:

```text
:r 0x1000                  # one word in decimal
:r 0x1000 -t felt          # one field element
:r 0x1000 -t u32 -c 4 -f x # four u32 values in hex
```

## Inspecting variables

`:vars` (aliases `:variables`, `:locals`) renders source-level variables
resolved from DWARF info embedded in the program for the selected physical
stack frame. Suspended callers retain their own declarations, captured stack
values, and frame bases; memory reads use the owning invocation's context.
Inline frames do not yet expose separate locals or lexical scopes.

By default the output hides compiler-generated locals (named `local0`,
`local1`, …) so you only see the names that appear in the original source.
Add `all` to include the compiler locals:

```text
:vars       # source-level variables only
:vars all   # also include compiler-generated locals
```

When the program has no DWARF info, `:vars` prints `No debug variables
tracked`. When it has DWARF but every variable is compiler-generated, you'll
see `No source-level variables (use ':vars all' to show compiler locals)`.

After successful termination, variable commands report `Program has terminated; no live
variables`. Final stack outputs remain available, and variables from a failed execution
remain inspectable.

Each variable is rendered as `name=value`. If its storage cannot be read,
the value is shown as `<unavailable>`.

## Tips

- The TUI honours `--color always` / `--color never` if your terminal lies
  about its colour support.
- `MIDENC_TRACE=miden_debug=debug miden debug ...` writes the debugger's own
  log to stderr; combined with `:debug` from the prompt this is the fastest
  way to diagnose unexpected behaviour.
- Breakpoints survive `:reload`; only the program state and cycle counter
  reset.
