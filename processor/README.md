# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor provides multiple APIs depending on your use case:

### High-level API
`ExecutionRequest::new(&program)` collects inputs, execution options, and source context before
choosing ordinary execution, witness recording, or trace construction. The live machine is
initialized and advice is validated against the final options at `prepare`, `run_sync`, `run`, or
`start`, independently of setter order.

```rust
use miden_processor::{DefaultHost, ExecutionRequest, WitnessOutput};
# fn example(program: &miden_processor::Program) -> Result<(), miden_processor::ExecutionError> {
let WitnessOutput { claim, witness, advice } = ExecutionRequest::new(program)
    .record_witness()
    .run_sync(&mut DefaultHost::default())?;
# Ok(())
# }
```

Ordinary execution uses `.execute().run_sync(...)` or `.execute().run(...).await` and returns
`ExecutionOutput` with the final stack, advice provider, memory, and deferred work. Pass a recorded
witness to the [prover](../prover/) for local or remote proving.

Pass the program as `&Program`, its public inputs as `StackInputs`, and its private inputs as
`AdviceInputs`. The `Host` supplies non-deterministic inputs and receives messages from the VM.
`ExecutionOptions` sets limits such as the maximum allowed number of cycles.

### Execution and sessions

Use `Execution::prepare()` to initialize the machine before a run or session. Benchmarks can use it
to initialize the machine outside the measured section.

Use `.with_source_context(Some(PackageSourceDebugContext::new(&debug_info, source_node)))` on the
request to identify the source occurrence for diagnostics. Source resolution and recorder setup
happen at run or start. Every mode supports `.start()`, which returns an `ExecutionSession`
that owns the machine, continuation, and recorder.

`state()` remains available after halt, failure, or cancellation. Use borrowed `step_sync` and
`step` for individual steps, or `run_until_halt_sync` and `run_until_halt` to drive the remaining
execution and keep the session.

`.run_to_completion_sync(&mut host)` and `.run_to_completion(&mut host).await` return
`CompletedExecution` after successful termination. Its `state()` exposes the halted machine until
`finish()` consumes it and exports the execution output and any recorded artifact. Deferred
precompile witness export happens during `finish()`, so export failures occur after VM completion.
Each stage returns `ExecutionError` on failure. Failed or cancelled sessions cannot resume or
complete.

With the `std` feature, a synchronous `build_trace` run can overlap execution with hasher
trace construction when enabled in `ExecutionOptions`. Execution stays on the calling thread while
Rayon may run the hasher builder on a worker. A caller with no separate Rayon worker uses compact
buffered replay. Async trace building and stepped trace sessions use buffered replay.

## Processor components
The processor is separated into two main components: **execution** and **trace generation**.

### Execution with `FastProcessor`
`FastProcessor` holds the machine state and runs the same engine for all execution modes. Construct
it directly for raw stepping and machine inspection. Ordinary execution uses the no-op tracer.

### Trace generation with `build_trace()`
Select `ExecutionRequest::build_trace(budget)` to return `TraceOutput` with the claim, final advice,
and an `ExecutionTrace` that pairs the VM trace with its optional precompile witness. Use
`vm_trace()` to inspect the VM trace or `into_parts()` to take ownership of both components.
For VM-only trace analysis from a saved witness, extract its `VmWitness` and use
`trace::build_trace(vm_witness, &budget)`.

Use `Prover::trace_budget()` when a configured prover will consume the trace. Standalone callers
can use `miden_vm_stark::memory::default_budget()` or `canonical_budget(limit_bytes)` with the
canonical proof configuration. Processor enforces the supplied model before final allocations and
retains independent row-index and raw-buffer limits. When the `concurrent` feature is enabled,
trace generation is parallelized.

Trace generation produces the four matrices in the Miden proof statement:

* the core trace for the system, decoder, and operand stack;
* the stacked chiplets trace for the hash controller, bitwise, memory, ACE, and kernel ROM;
* the standalone 32-row Eidos compression trace; and
* the fixed And8 lookup trace, whose multiplicities also serve 16-bit range checks.

Typed LogUp relations connect requests and responses across these matrices. The processor collects
range-check and byte-lookup multiplicities while replaying execution and writes them into the fixed
And8 table; there is no separate range-checker execution-trace segment.

A much more in-depth description of Miden VM design is available [here](https://docs.miden.xyz/miden-vm/design).

## Crate features
Miden processor can be compiled with the following features:

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature enables concurrency across parts of execution. The `testing` feature enables APIs used in
tests.

To compile with `no_std`, disable default features via `--no-default-features` flag, in which case only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
