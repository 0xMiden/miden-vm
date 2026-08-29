# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor provides multiple APIs depending on your use case:

### High-level API
The `ProgramExecutor` trait provides a pluggable ordinary-execution interface returning
`ExecutionOutput`, with `FastProcessor` as its default implementation:

Pass the program as `&Program`, its public inputs as `StackInputs`, and its private inputs as
`AdviceInputs`. The `Host` supplies non-deterministic inputs and receives messages from the VM.
`ExecutionOptions` sets limits such as the maximum allowed number of cycles.

The async trait method returns `Result<ExecutionOutput, ExecutionError>`, containing the final stack
state, advice provider, memory, and deferred state on success.

### Low-level API
For more control over execution and trace generation, you can use `FastProcessor` directly:

`FastProcessor::execute()` runs a program without trace generation overhead and returns an
`ExecutionOutput` with the final stack state and other execution results.

`FastProcessor::execute_for_proving()` and `FastProcessor::execute_for_proving_sync()` run a
program while collecting the complete post-execution `ExecutionWitness`. Pass the `VmWitness`
from `ExecutionWitness::into_parts()` to `build_trace()` to construct the full `VmTrace`. Trace
building is parallel when the `concurrent` feature is enabled.

With the `std` feature, `FastProcessor::execute_and_build_trace_sync()` preserves the optimized
synchronous path that overlaps execution with hasher trace construction. It returns
`(VmTrace, Option<PrecompileWitness>)`. Execution stays on the calling thread while Rayon may run
the hasher builder on a worker. A caller with no separate Rayon worker uses compact buffered replay
and builds the trace after execution.

## Processor components
The processor is separated into two main components: **execution** and **trace generation**.

### Execution with `FastProcessor`
The `FastProcessor` is designed for fast program execution with minimal overhead. It can operate in two modes:

* **Pure execution** via `FastProcessor::execute()`: Executes a program without generating any trace-related metadata. This mode is optimized for maximum performance when proof generation is not required.
* **Witness-producing execution** via `FastProcessor::execute_for_proving()` /
  `FastProcessor::execute_for_proving_sync()`: Executes a program while collecting the complete
  post-execution `ExecutionWitness`.

### Trace generation with `build_trace()`
After execution with `FastProcessor::execute_for_proving*()`, split the returned
`ExecutionWitness` and pass its `VmWitness` to `build_trace()`. When the `concurrent` feature is
enabled, trace generation is parallelized for improved performance.


The trace consists of several sections:
* The decoder, which tracks instruction decoding and control flow.
* The stack, which records stack state transitions.
* The range-checker, which validates that values fit into 16 bits.
* The chiplets module, which handles complex computations (e.g., hashing) and random access memory.

These sections are connected via two buses:
* The range-checker bus, which links stack and chiplets modules with the range-checker.
* The chiplet bus, which links stack and the decoder with the chiplets module.

A much more in-depth description of Miden VM design is available [here](https://docs.miden.xyz/miden-vm/design).

## Crate features
Miden processor can be compiled with the following features:

The `std` feature is enabled by default and relies on the Rust standard library. The `concurrent`
feature enables concurrency across parts of execution. The `testing` feature enables APIs used in
tests. The `bus-debugger` feature helps debug the buses, but it slows down the processor.

To compile with `no_std`, disable default features via `--no-default-features` flag, in which case only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
