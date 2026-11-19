---
title: DAP integration
sidebar_position: 5
---

# DAP integration

`miden-debug` also implements the [Debug Adapter Protocol
(DAP)](https://microsoft.github.io/debug-adapter-protocol/). DAP support
shows up in two complementary places:

- **Server side** — the `miden-debug-engine` crate provides a
  `DapExecutor` that implements the VM's `ProgramExecutor` trait. Anything
  that knows how to drive a `ProgramExecutor` (most importantly
  `miden-client exec`) can swap in `DapExecutor` and serve a standard DAP
  session over TCP instead of executing the program directly.
- **Client side** — the `miden-debug` binary can act as a DAP client by
  passing `--dap-connect HOST:PORT`. It connects to the TCP server, drives
  it through the same TUI you'd use locally, and renders the program's
  state from the DAP responses.

The wire format is standard DAP — `Content-Length`-framed JSON over TCP — so
any DAP-compatible IDE (VS Code, Zed, the bundled TUI) can connect to the
same server.

## Architecture

```
┌─────────────────────┐                  ┌──────────────────────┐
│ DAP client          │                  │ miden-client exec     │
│  (TUI / VS Code /   │   TCP, std DAP   │  --start-debug-adapter│
│   Zed)              │ ◄──────────────► │                       │
└─────────────────────┘                  │  ┌─────────────────┐  │
                                         │  │ DapExecutor     │  │
                                         │  │ (miden-debug-   │  │
                                         │  │  engine)        │  │
                                         │  └────────┬────────┘  │
                                         │           ▼           │
                                         │  ┌─────────────────┐  │
                                         │  │ FastProcessor   │  │
                                         │  │ (Miden VM)      │  │
                                         │  └─────────────────┘  │
                                         └───────────────────────┘
```

When the client side asks for a DAP session, `miden-client` builds a
`TransactionExecutor` configured with `DapExecutor` instead of the default
`FastProcessor`. The executor binds a TCP listener on the address you
provide, waits for a DAP client to connect, and from then on every
`continue`, `step`, `setBreakpoints`, and `evaluate` request flows over the
DAP wire — execution only progresses when the client tells it to.

## Server side: starting the DAP server

The supported entry point is `miden-client exec`:

```bash
miden-client exec \
  --script-path /path/to/test.masm \
  --start-debug-adapter 127.0.0.1:4711
```

`miden-client` will:

1. Compile the transaction script (passing the script's path so source
   locations end up referring to the real file on disk).
2. Build a `TransactionExecutor` using `DapExecutor`.
3. Bind a TCP listener at `127.0.0.1:4711` and print
   `DAP server listening on 127.0.0.1:4711. Waiting for client connection...`.
4. Block until exactly one DAP client connects.
5. Hand control over to that client until execution finishes or the client
   disconnects.

Optional flags supported on `miden-client exec`:

- `--inputs FILE` — TOML file with VM advice-map / advice-stack entries.
- `--account ID` — execute the script against a specific account.

See the [miden-client DAP debugging
guide](https://github.com/0xMiden/miden-client/tree/next/docs/external/src/rust-client/debugging.md)
for the full account-bootstrap flow (`init`, `new-wallet`, `sync`).

### Restart flow

The DAP `restart` request is supported with two distinct modes, selected by
the client:

- **Phase 1 — in-process reset.** A bare `restart` request drops back to
  cycle 0 with the *same* compiled program. Fast; useful for re-running
  with a different breakpoint set.
- **Phase 2 — terminate-and-reconnect.** `restart` with a non-empty
  `arguments` payload signals the server to terminate the session, send
  `Terminated { restart: true }`, and let `miden-client` recompile the
  script from disk and re-listen. This drives the *edit-and-continue*
  workflow for IDE clients.

## Client side: `miden debug --dap-connect`

To drive a running server through the standard TUI:

```bash
miden debug --dap-connect 127.0.0.1:4711
```

In this mode `miden-debug` does not load a program from disk; the program
lives on the server. The TUI renders the server's state — operand stack,
memory, call stack, source lines — from DAP responses, and your `:break`,
`:r`, `:vars`, `:next-line` commands turn into DAP requests.

A custom `miden/uiState` event is pushed by the server immediately before
every `stopped` event so the inspector pane can update without an extra
round-trip.

## IDE clients

Request `scopes` with a frame ID from `stackTrace` to inspect that invocation's
locals. `evaluate` accepts the same `frameId`; omitting it selects the executing
physical invocation. Suspended callers and recursive invocations retain separate
locals. Inline frames have no separate locals in this release. Frame IDs and
variable references expire when execution resumes or restarts, so clients must
fetch them again after each stop.

Two first-party IDE extensions speak the same protocol against the same
server:

| IDE | Repo | Adapter type |
| --- | ---- | ------------ |
| VS Code | [`0xMiden/vscode-extension`](https://github.com/0xMiden/vscode-extension) | `miden` (DAP via `vscode.DebugAdapterServer`) |
| Zed | [`0xMiden/zed-extension`](https://github.com/0xMiden/zed-extension) | `miden` (DAP via `zed_extension_api`) |

Both extensions ship two debug-config request kinds:

- `attach` — connect to a `miden-client exec` server you started yourself.
- `launch` — let the editor spawn `miden-client exec
  --start-debug-adapter` and connect to the resulting listener.

Refer to the per-IDE READMEs for `launch.json` / `debug.json` snippets and
backend feature-branch requirements.

## Building with / without DAP

`miden-debug` defaults to building with the `dap` feature on:

```bash
cargo build --bin miden-debug                  # tui + repl + dap + flamegraph
cargo build --bin miden-debug --no-default-features --features tui,repl
                                               # tui + repl, no DAP
```

`--dap-connect` is gated behind both the `dap` and `tui` features because the
remote session is rendered in the TUI; it disappears from `--help` when either
feature is off. The DAP server (`--start-debug-adapter`) only requires `dap`.

On the `miden-client` side, the DAP support is gated by its own `dap`
feature, also enabled by default:

```bash
cargo build -p miden-client-cli                # default (dap enabled)
cargo build -p miden-client-cli --no-default-features
                                               # smaller binary, no DAP
```

`--start-debug-adapter` is the CLI surface; under the hood it lives in the
`execute_program_with_dap` entry on the `Client` API, which any
`miden-client`-based application can call directly.

## Custom DAP events

Beyond the standard DAP set, the server emits two Miden-specific events
that IDE clients can hook:

| Event | Body | When |
| ----- | ---- | ---- |
| `miden/uiState` | `{ cycle, current_stack: [u64], callstack: [{ name, source_path, line, column }] }` | Pushed before every `stopped` event so the IDE inspector can render without extra requests. |
| `evaluate("__miden_ui_state")` | Same payload as above, JSON-encoded | Available as a DAP `evaluate` expression for clients that prefer pull over push. |
| `evaluate("__miden_variables[ all]")` | JSON array of `{ name, value, raw }` | Inspects the requested `frameId`; `value` is formatted text and `raw` is the first field element or `null`. The optional `all` includes compiler locals. |
| `evaluate("__miden_read_memory ...")` | Formatted memory read | Same grammar as the TUI's `:r` — `__miden_read_memory <type> <addr> <fmt> <count>`. |

The TUI client uses these to populate the operand-stack, memory, and call-stack
panes; IDE extensions use them for their inspector views.
