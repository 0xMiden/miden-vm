# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor provides multiple APIs depending on your use case:

### High-level API
`Processor::new(&program)` collects inputs, execution options, and source context before
choosing ordinary execution or witness recording. The live machine is
initialized and advice is validated against the final options at `prepare`, `run_sync`, `run`, or
`start`, independently of setter order.

```rust
use miden_processor::{DefaultHost, Processor, WitnessOutput};
# fn example(program: &miden_processor::Program) -> Result<(), miden_processor::ExecutionError> {
let WitnessOutput { claim, witness, advice } = Processor::new(program)
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

Use `ExecutionPlan::prepare()` to initialize the machine before a run or session. If initial
advice exceeds the configured limits, `ExecutionError::kind()` returns `ProcessorError::Advice`.

Use `.with_source_context(Some(PackageSourceDebugContext::new(&debug_info, source_node)))` on the
request to identify the source occurrence for diagnostics. Both run and start validate the source
context before calling the host. Invalid occurrences surface as `ProcessorError::SourceContext`
through `ExecutionError::kind()`. Every mode supports `.start()`, which returns an
`ExecutionSession` that owns the machine, continuation, and recorder.

`state()` remains available after halt, failure, or cancellation. Use borrowed `step_sync` and
`step` for individual steps, or `run_until_halt_sync` and `run_until_halt` to drive the remaining
execution and keep the session. The failing step or drive returns its original `ExecutionError`.
Another attempt returns `ProcessorError::SessionUnavailable` through `kind()`, with the reason
`PreviouslyFailed` after a failure or `Interrupted` after an interrupted step or drive.

`.run_to_completion_sync(&mut host)` and `.run_to_completion(&mut host).await` return
`HaltedExecution` after successful termination. Its `state()` exposes the halted machine until
`finish()` consumes it and exports the execution output and any recorded artifact. Deferred
precompile witness export happens during `finish()`. Both `finish()` and the combined `run_sync`
and `run` methods report export failures as `ProcessorError::Deferred` through `ExecutionError::kind()`.

On a halted witness recording, `trace_len_upper_bound()` reports the core and chiplet sizes from
the live recorder. The Eidos compression count bounds the distinct requests that replay will keep.

## Processor components
The processor is separated into two main components: **execution** and **trace generation**.

### Execution with `FastProcessor`
`FastProcessor` holds the machine state and runs the same engine for all execution modes. Construct
it directly for raw stepping and machine inspection. Ordinary execution uses the no-op tracer.

### Trace generation with `build_trace()`
The prover consumes the recorded witness and builds the trace after execution. For row-level
inspection or AIR diagnostics, call `witness.into_parts()` to obtain the VM witness and the
optional precompile witness. Then call `vm_witness.build_trace(&budget)`. This method returns
`TraceGenerationError` if replay fails or the trace exceeds its limits.

Use `miden_vm_stark::memory::default_budget()` or `canonical_budget(limit_bytes)` for the
canonical VM proof configuration. The processor checks the model against the padded heights
before final allocations and enforces independent row-index and raw-buffer limits.
With `std`, the builder can replay core fragments and build chiplets in parallel.

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
