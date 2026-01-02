# Miden processor
This crate contains an implementation of Miden VM processor. The purpose of the processor is to execute a program and to generate a program execution trace. This trace is then used by Miden VM to generate a proof of correct execution of the program.

## Usage
The processor exposes the `execute()` function which takes the following arguments:

* `program: &Program` - a reference to a Miden program to be executed.
* `stack_inputs: StackInputs` - a set of public inputs with which to execute the program.
* `host: Host` - an instance of a `Host` which can be used to supply non-deterministic inputs to the VM and receive messages from the VM.
* `options: ExecutionOptions` - a set of options for executing the specified program (e.g., max allowed number of cycles).

The function returns a `Result<ExecutionTrace, ExecutionError>` which will contain the execution trace of the program if the execution was successful, or an error, if the execution failed. Internally, the VM then passes this execution trace to the prover to generate a proof of a correct execution of the program.

## Processor components
The processor is organized into several components:
* The decoder, which is responsible for decoding instructions and managing control flow.
* The stack, which is responsible for executing instructions against the stack.
* The range-checker, which is responsible for checking whether values can fit into 16 bits.
* The chiplets module, which contains specialized chiplets responsible for handling complex computations (e.g., hashing) as well as random access memory.

These components are connected via two buses:
* The range-checker bus, which links stack and chiplets modules with the range-checker.
* The chiplet bus, which links stack and the decoder with the chiplets module.

A much more in-depth description of Miden VM design is available [here](https://0xMiden.github.io/miden-vm/design/main.html).

## Crate features
Miden processor can be compiled with the following features:

* `std` - enabled by default and relies on the Rust standard library.
* `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
    * Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
