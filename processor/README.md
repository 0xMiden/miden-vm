# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor provides multiple APIs depending on your use case:

### High-level API
The `execute()` function provides a convenient interface that executes a program and generates a complete execution trace:

* `program: &Program` - a reference to a Miden program to be executed.
* `stack_inputs: StackInputs` - a set of public inputs with which to execute the program.
* `advice_inputs: AdviceInputs` - the private inputs used to build the advice provider with which to execute the program.
* `host: &mut impl Host` - an instance of a host which can be used to supply non-deterministic inputs to the VM and receive messages from the VM.
* `options: ExecutionOptions` - a set of options for executing the specified program (e.g., max allowed number of cycles).

The (async) function returns a `Result<ExecutionTrace, ExecutionError>` which will contain the execution trace of the program if the execution was successful, or an error if the execution failed.

### Low-level API
For more control over execution and trace generation, you can use `FastProcessor` directly:

* `FastProcessor::execute()` - Executes a program without any trace generation overhead. Returns `ExecutionOutput` containing the final stack state and other execution results.
* `FastProcessor::execute_for_trace()` - Executes a program while collecting metadata for trace generation. Returns both `ExecutionOutput` and `TraceGenerationContext`.
* `build_trace()` - Takes the `ExecutionOutput` and `TraceGenerationContext` from `execute_for_trace()` and constructs the full execution trace. When the `concurrent` feature is enabled, trace building is parallelized. 

## Processor components
The processor is separated into two main components: **execution** and **trace generation**.

### Execution with `FastProcessor`
The `FastProcessor` is designed for fast program execution with minimal overhead. It can operate in two modes:

* **Pure execution** via `FastProcessor::execute()`: Executes a program without generating any trace-related metadata. This mode is optimized for maximum performance when proof generation is not required.
* **Execution for trace generation** via `FastProcessor::execute_for_trace()`: Executes a program while collecting metadata required for subsequent trace generation. This metadata is encapsulated in a `TraceGenerationContext` that is passed to the `build_trace()` function.

### Trace generation with `build_trace()`
After execution with `FastProcessor::execute_for_trace()`, the `build_trace()` function uses the returned `TraceGenerationContext` to construct the full execution trace. When the `concurrent` feature is enabled, trace generation is parallelized for improved performance.

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

* `std` - enabled by default and relies on the Rust standard library.
* `concurrent` - enables concurrency across certain parts of execution
* `testing` - Enables APIs that can be helpful for testing
* `bus-debugger` - Used to debug our buses. Slows down the processor considerably.

To compile with `no_std`, disable default features via `--no-default-features` flag, in which case only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
