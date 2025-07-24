# Miden VM

This crate aggregates all components of the Miden VM in a single place. Specifically, it re-exports functionality from [processor](../processor/), [prover](../prover/), and [verifier](../verifier/) crates. Additionally, when compiled as an executable, this crate can be used via a [CLI interface](#cli-interface) to execute Miden VM programs and to verify correctness of their execution.

## Basic concepts

An in-depth description of Miden VM is available in the full Miden VM [documentation](https://0xMiden.github.io/miden-vm/). In this section we cover only the basics to make the included examples easier to understand.

### Writing programs

Our goal is to make Miden VM an easy compilation target for high-level languages such as Rust, Move, Sway, and others. We believe it is important to let people write programs in the languages of their choice. However, compilers to help with this have not been developed yet. Thus, for now, the primary way to write programs for Miden VM is to use [Miden assembly](../assembly).

Miden assembler compiles assembly source code in a [program MAST](https://0xMiden.github.io/miden-vm/design/programs.html), which is represented by a `Program` struct. It is possible to construct a `Program` struct manually, but we don't recommend this approach because it is tedious, error-prone, and requires an in-depth understanding of VM internals. All examples throughout these docs use assembly syntax.

#### Program hash

All Miden programs can be reduced to a single 32-byte value, called program hash. Once a `Program` object is constructed, you can access this hash via `Program::hash()` method. This hash value is used by a verifier when they verify program execution. This ensures that the verifier verifies execution of a specific program (e.g. a program which the prover had committed to previously). The methodology for computing program hash is described [here](https://0xMiden.github.io/miden-vm/design/programs.html#program-hash-computation).

### Inputs / outputs

Currently, there are 3 ways to get values onto the stack:

1. You can use `push` instruction to push values onto the stack. These values become a part of the program itself, and, therefore, cannot be changed between program executions. You can think of them as constants.
2. The stack can be initialized to some set of values at the beginning of the program. These inputs are public and must be shared with the verifier for them to verify a proof of the correct execution of a Miden program. At most 16 values could be provided for the stack initialization, attempts to provide more than 16 values will cause an error.
3. The program may request nondeterministic advice inputs from the prover. These inputs are secret inputs. This means that the prover does not need to share them with the verifier. There are three types of advice inputs: (1) a single advice stack which can contain any number of elements; (2) a key-mapped element lists which can be pushed onto the advice stack; (3) a Merkle store, which is used to provide nondeterministic inputs for instructions which work with Merkle trees. There are no restrictions on the number of advice inputs a program can request.

The stack is provided to Miden VM via `StackInputs` struct. These are public inputs of the execution, and should also be provided to the verifier. The secret inputs for the program are provided via the `Host` interface. The default implementation of the host relies on in-memory advice provider (`AdviceProvider`) that can be commonly used for operations that won't require persistence.

Values remaining on the stack after a program is executed can be returned as stack outputs. You can specify exactly how many values (from the top of the stack) should be returned. Notice, that, similar to stack inputs, at most 16 values can be returned via the stack. Attempts to return more than 16 values will cause an error.

Having a small number elements to describe public inputs and outputs of a program may seem limiting, however, just 4 elements are sufficient to represent a root of a Merkle tree or a sequential hash of elements. Both of these can be expanded into an arbitrary number of values by supplying the actual values non-deterministically via the host interface.

## Usage

Miden crate exposes several functions which can be used to execute programs, generate proofs of their correct execution, and verify the generated proofs. How to do this is explained below, but you can also take a look at working examples [here](masm-examples/) and find instructions for running them via CLI [here](#fibonacci-example).

### Executing programs

To execute a program on Miden VM, you can use either `execute()` or `execute_iter()` functions. The `execute()` function takes the following arguments:

- `program: &Program` - a reference to a Miden program to be executed.
- `stack_inputs: StackInputs` - a set of public inputs with which to execute the program.
- `host: Host` - an instance of a `Host` which can be used to supply non-deterministic inputs to the VM and receive messages from the VM.
- `options: ExecutionOptions` - a set of options for executing the specified program (e.g., max allowed number of cycles).

The function returns a `Result<ExecutionTrace, ExecutionError>` which will contain the execution trace of the program if the execution was successful, or an error, if the execution failed. Internally, the VM then passes this execution trace to the prover to generate a proof of a correct execution of the program.

The `execute_iter()` function takes similar arguments (but without the `options`) and returns a `VmStateIterator` . This iterator can be used to iterate over the cycles of the executed program for debug purposes. In fact, when we execute a program using this function, a lot of the debug information is retained and we can get a precise picture of the VM's state at any cycle. Moreover, if the execution results in an error, the `VmStateIterator` can still be used to inspect VM states right up to the cycle at which the error occurred.

For example:

```rust
use std::sync::Arc;
use miden_vm::{assembly::DefaultSourceManager, AdviceInputs, Assembler, execute, execute_iter, DefaultHost, Program, StackInputs};
use miden_processor::ExecutionOptions;

// instantiate the assembler
let mut assembler = Assembler::default();

// compile Miden assembly source code into a program
let program = assembler.assemble_program("begin push.3 push.5 add swap drop end").unwrap();

// use an empty list as initial stack
let stack_inputs = StackInputs::default();

// do not include any initial advice data
let advice_inputs = AdviceInputs::default();

// instantiate a default host (with an empty advice provider)
let mut host = DefaultHost::default();

// instantiate default execution options
let exec_options = ExecutionOptions::default();

// execute the program with no inputs
let trace = execute(&program, stack_inputs.clone(), advice_inputs.clone(), &mut host, exec_options).unwrap();

// now, execute the same program in debug mode and iterate over VM states
for vm_state in execute_iter(
    &program,
    stack_inputs,
    advice_inputs,
    &mut host,
) {
    match vm_state {
        Ok(vm_state) => println!("{:?}", vm_state),
        Err(_) => println!("something went terribly wrong!"),
    }
}
```

### Proving program execution

To execute a program on Miden VM and generate a proof that the program was executed correctly, you can use the `prove()` function. This function takes the following arguments:

- `program: &Program` - a reference to a Miden program to be executed.
- `stack_inputs: StackInputs` - a set of public inputs with which to execute the program.
- `host: Host` - an instance of a `Host` which can be used to supply non-deterministic inputs to the VM and receive messages from the VM.
- `options: ProvingOptions` - config parameters for proof generation. The default options target 96-bit security level.

If the program is executed successfully, the function returns a tuple with 2 elements:

- `outputs: StackOutputs` - the outputs generated by the program.
- `proof: ExecutionProof` - proof of program execution. `ExecutionProof` can be easily serialized and deserialized using `to_bytes()` and `from_bytes()` functions respectively.

#### Proof generation example

Here is a simple example of executing a program which pushes two numbers onto the stack and computes their sum:

```rust
use std::sync::Arc;
use miden_vm::{assembly::DefaultSourceManager, AdviceInputs, Assembler, DefaultHost, ProvingOptions, Program, prove, StackInputs};

// instantiate the assembler
let mut assembler = Assembler::default();

// this is our program, we compile it from assembly code
let program = assembler.assemble_program("begin push.3 push.5 add swap drop end").unwrap();

// let's execute it and generate a STARK proof
let (outputs, proof) = prove(
    &program,
    StackInputs::default(),       // we won't provide any inputs
    AdviceInputs::default(),      // we don't need any initial advice inputs
    &mut DefaultHost::default(),  // we'll be using a default host
    ProvingOptions::default(),    // we'll be using default options
)
.unwrap();

// the output should be 8
assert_eq!(8, outputs.first().unwrap().as_int());
```

### Verifying program execution

To verify program execution, you can use the `verify()` function. The function takes the following parameters:

- `program_info: ProgramInfo` - a structure containing the hash of the program to be verified (represented as a 32-byte digest), and the hashes of the Kernel procedures used to execute the program.
- `stack_inputs: StackInputs` - a list of the values with which the stack was initialized prior to the program's execution..
- `stack_outputs: StackOutputs` - a list of the values returned from the stack after the program completed execution.
- `proof: ExecutionProof` - the proof generated during program execution.

Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one. Thus, their expected order on the stack will be the reverse of the order in which they are provided, and the last value in the `stack_inputs` is expected to be the value at the top of the stack.

Stack outputs are expected to be ordered as if they would be popped off the stack one by one. Thus, the value at the top of the stack is expected to be in the first position of the `stack_outputs`, and the order of the rest of the output elements will also match the order on the stack. This is the reverse of the order of the `stack_inputs`.

The function returns `Result<u32, VerificationError>` which will be `Ok(security_level)` if verification passes, or `Err(VerificationError)` if verification fails, with `VerificationError` describing the reason for the failure.

> If a program with the provided hash is executed against some secret inputs and the provided public inputs, it will produce the provided outputs.

Notice how the verifier needs to know only the hash of the program - not what the actual program was.

#### Proof verification example

Here is a simple example of verifying execution of the program from the previous example:

```rust,ignore
use miden;

let program =   /* value from previous example */;
let proof =     /* value from previous example */;

// let's verify program execution
match miden_vm::verify(program.hash(), StackInputs::default(), &[8], proof) {
    Ok(_) => println!("Execution verified!"),
    Err(msg) => println!("Something went terribly wrong: {}", msg),
}
```

## Fibonacci calculator

Let's write a simple program for Miden VM (using [Miden assembly](../assembly)). Our program will compute the 5-th [Fibonacci number](https://en.wikipedia.org/wiki/Fibonacci_number):

```masm
push.0      // stack state: 0
push.1      // stack state: 1 0
swap        // stack state: 0 1
dup.1       // stack state: 1 0 1
add         // stack state: 1 1
swap        // stack state: 1 1
dup.1       // stack state: 1 1 1
add         // stack state: 2 1
swap        // stack state: 1 2
dup.1       // stack state: 2 1 2
add         // stack state: 3 2
```

Notice that except for the first 2 operations which initialize the stack, the sequence of `swap dup.1 add` operations repeats over and over. In fact, we can repeat these operations an arbitrary number of times to compute an arbitrary Fibonacci number. In Rust, it would look like this:

```rust
use std::sync::Arc;
use miden_vm::{assembly::DefaultSourceManager, AdviceInputs, Assembler, DefaultHost, Program, ProvingOptions, StackInputs};

// set the number of terms to compute
let n = 50;

// instantiate the default assembler and compile the program
let source = format!(
    "
    begin
        repeat.{}
            swap dup.1 add
        end
    end",
    n - 1
);
let mut assembler = Assembler::default();
let program = assembler.assemble_program(&source).unwrap();

// initialize a default host (with an empty advice provider)
let mut host = DefaultHost::default();

// initialize the stack with values 0 and 1
let stack_inputs = StackInputs::try_from_ints([0, 1]).unwrap();

// execute the program
let (outputs, proof) = miden_vm::prove(
    &program,
    stack_inputs,
    AdviceInputs::default(), // without initial advice inputs
    &mut host,
    ProvingOptions::default(), // use default proving options
)
.unwrap();

// fetch the stack outputs, truncating to the first element
let stack = outputs.stack_truncated(1);

// the output should be the 50th Fibonacci number
assert_eq!(12586269025, stack[0].as_int());
```

Above, we used public inputs to initialize the stack rather than using `push` operations. This makes the program a bit simpler, and also allows us to run the program from arbitrary starting points without changing program hash.

## CLI interface

If you want to execute, prove, and verify programs on Miden VM, but don't want to write Rust code, you can use Miden CLI. It also contains a number of useful tools to help analyze and debug programs.

### Compiling Miden VM

First, make sure you have Rust [installed](https://www.rust-lang.org/tools/install). The current version of Miden VM requires Rust version **1.88** or later.

Then, to compile Miden VM into a binary, run the following `make` command:

```shell
make exec
```

This will place `miden-vm` executable in the `./target/optimized` directory.

By default, the executable will be compiled in the multi-threaded mode. If you would like to enable single-threaded proof generation, you can compile Miden VM using the following command:

```shell
make exec-single
```

We also provide a number of `make` commands to simplify building Miden VM for various targets:

```shell
# build an executable for a generic target (concurrent)
make exec

# build an executable for Apple silicon (concurrent+metal)
make exec-metal

# build an executable for targets with AVX2 instructions (concurrent)
make exec-avx2

# build an executable for targets with SVE instructions (concurrent)
make exec-sve

# build an executable with log tree enabled
make exec-info
```

### Running Miden VM

Once the executable has been compiled, you can run Miden VM like so:

```shell
./target/optimized/miden-vm [subcommand] [parameters]
```

Currently, Miden VM can be executed with the following subcommands:

- `run` - this will execute a Miden assembly program and output the result, but will not generate a proof of execution.
- `prove` - this will execute a Miden assembly program, and will also generate a STARK proof of execution.
- `verify` - this will verify a previously generated proof of execution for a given program.
- `compile` - this will compile a Miden assembly program and outputs stats about the compilation process.
- `debug` - this will instantiate a CLI debugger against the specified Miden assembly program and inputs.
- `analyze` - this will run a Miden assembly program against specific inputs and will output stats about its execution.

All of the above subcommands require various parameters to be provided. To get more detailed help on what is needed for a given subcommand, you can run the following:

```shell
./target/optimized/miden-vm [subcommand] --help
```

For example:

```shell
./target/optimized/miden-vm prove --help
```

### Fibonacci example

In the `miden/masm-examples/fib` directory, we provide a very simple Fibonacci calculator example. This example computes the 1000th term of the Fibonacci sequence. You can execute this example on Miden VM like so:

```shell
./target/optimized/miden-vm run miden-vm/masm-examples/fib/fib.masm -n 1
```

This will run the example code to completion and will output the top element remaining on the stack.

## Crate features

Miden VM can be compiled with the following features:

- `std` - enabled by default and relies on the Rust standard library.
- `concurrent` - implies `std` and also enables multi-threaded proof generation.
- `executable` - required for building Miden VM binary as described above. Implies `std`.
- `metal` - enables [Metal](<https://en.wikipedia.org/wiki/Metal_(API)>)-based acceleration of proof generation (for recursive proofs) on supported platforms (e.g., Apple silicon).
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
  - Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation

When compiled with `concurrent` feature enabled, the VM will generate STARK proofs using multiple threads. For benefits of concurrent proof generation check out these [benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. To control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
