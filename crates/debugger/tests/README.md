# Integration tests

These are tests which require compilation into separate binaries, so as to avoid conflicts related to global state within the debugger (e.g. the global logger).

## Test-specific notes

The following sections document why specific tests are handled here, rather than as plain unit tests.

### Testing the behavior of the `println` trace event

Related to all tests starting with `println_`.

Printed lines are displayed in `DebugLogger`, which is built on `env_logger`. The logger initialized by `env_logger` is global per process. To let each `println` test have its own process-local `DebugLogger`, we create a separate file here for each `println` test. The way integration tests are built and run ensures that this gives each `println` test its own `DebugLogger`. Otherwise multiple tests would concurrently write to the same `DebugLogger`.

`DebugLogger` is feature-gated behind `tui`. To apply that gate to integration tests, add an entry according to the following pattern for each relevant file:

```toml
[[test]]
name = "println_smoke_test"
required-features = ["tui"]
```

## lit / FileCheck tests

End-to-end debugger tests live under `tests/lit/` and are driven by
[`litcheck`](https://crates.io/crates/litcheck). See `tests/lit/README.md`.
