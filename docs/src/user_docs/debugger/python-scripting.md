---
title: Python Scripting
sidebar_position: 7
---

# Python scripting

Python scripting is available only when `miden-debug` is built with the
`python` feature:

```bash
cargo build --no-default-features --features "repl,python" --bin miden-debug
```

Python scripts are arbitrary local code. Only run scripts you trust. The
debugger auto-loads `.miden-debug.py` from the debugger working directory when
the file exists; pass `--no-user-python-init` to disable that.

## REPL commands

```text
script <code>                         # execute one Python snippet
script                                # enter Python's interactive console
command script import ./file.py       # import a Python file
command script add NAME -f mod.func   # register a Python-backed command
command script list
command script delete NAME
breakpoint command add ID -f mod.func # register a breakpoint callback
breakpoint command list
breakpoint command delete [ID]
```

`script <expr>` prints the expression value when it is not `None`:

```text
[cycle 0 STOP] > script x = 1
[cycle 0 STOP] > script x + 1
2
```

The embedded module is named `miden_debugger` and provides convenience globals:

```python
import miden_debugger as miden

miden.debugger.get_cycle()
miden.process.stack()
miden.frame.variables()
```

`miden.frame` and breakpoint callback frames inspect the executing invocation.
`miden.thread.frames()` returns snapshots in innermost-first order, and
`miden.thread.selected_frame()` snapshots the frame selected in the debugger.
Each physical frame exposes its own locals, including suspended recursive
callers. These snapshots retain their values after execution resumes. Inline
frames have no separately inspectable locals in this release.

Each variable `Value` exposes its first raw field element through `value`. When ABI type metadata
is available, `display_value` also contains the fully decoded, human-readable value.

## Module initializer

Imported modules may define:

```python
def __miden_init_module(debugger, internal_dict):
    internal_dict["loaded"] = True
```

`internal_dict` persists for the debugger session and is shared with commands
and breakpoint callbacks.

## Custom command callback

```python
def cycle(debugger, command, exe_ctx, result, internal_dict):
    print(debugger.get_cycle(), file=result)
```

Register it from the REPL:

```text
command script import examples/python/cycle.py
command script add py-cycle -f cycle.cycle
py-cycle
```

## Breakpoint callback

Breakpoint callbacks receive `(frame, breakpoint, internal_dict)`.

Return `False` to continue execution without reporting the breakpoint stop.
Return `True`, `None`, or any truthy value to stop normally.

```python
def stop_when_iter_is_5(frame, breakpoint, internal_dict):
    value = frame.variables().get("iter")
    return value is not None and value.value == 5
```

Register it:

```text
b in *entrypoint*
command script import examples/python/watch_var.py
breakpoint command add 0 -f watch_var.stop_when_iter_is_5
c
```
