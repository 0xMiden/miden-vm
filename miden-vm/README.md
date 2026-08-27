# Miden VM

This crate aggregates all components of the Miden VM in a single place. Specifically, it re-exports
functionality from [processor](../processor/), [prover](../prover/), and [verifier](../verifier/)
crates. Additionally, when compiled as an executable, this crate can be used via a
[CLI interface](#cli-interface) to execute Miden VM programs and to verify correctness of their
execution.

## Basic concepts

An in-depth description of Miden VM is available in the full Miden VM [documentation](https://docs.miden.xyz/miden-vm/). In this section we cover only the basics to make the included examples easier to understand.

### Writing programs

Our goal is to make Miden VM an easy compilation target for high-level languages such as Rust,
Move, Sway, and others. We believe it is important to let people write programs in the languages of
their choice. However, compilers to help with this have not been developed yet. Thus, for now, the
primary way to write programs for Miden VM is to use
[Miden assembly](../crates/assembly/).

Miden assembler compiles assembly source code in a [program MAST](https://docs.miden.xyz/miden-vm/design/programs), which is represented by a `Program` struct. It is possible to construct a `Program` struct manually, but we don't recommend this approach because it is tedious, error-prone, and requires an in-depth understanding of VM internals. All examples throughout these docs use assembly syntax.

#### Program hash

All Miden programs can be reduced to a single 32-byte value, called program hash. Once a `Program` object is constructed, you can access this hash via `Program::hash()` method. This hash value is used by a verifier when they verify program execution. This ensures that the verifier verifies execution of a specific program (e.g. a program which the prover had committed to previously). The methodology for computing program hash is described [here](https://docs.miden.xyz/miden-vm/design/programs#program-hash-computation).

### Inputs / outputs

Currently, there are 3 ways to get values onto the stack:

1. You can use `push` instruction to push values onto the stack. These values become a part of the program itself, and, therefore, cannot be changed between program executions. You can think of them as constants.
2. The stack can be initialized to some set of values at the beginning of the program. These inputs are public and must be shared with the verifier for them to verify a proof of the correct execution of a Miden program. At most 16 values could be provided for the stack initialization, attempts to provide more than 16 values will cause an error.
3. The program may request nondeterministic advice inputs from the prover. These inputs are secret inputs. This means that the prover does not need to share them with the verifier. Advice can come from a stack, a map of element lists, or a Merkle store used by instructions that work with Merkle trees. There are no restrictions on the number of advice inputs a program can request.

The stack is provided to Miden VM via `StackInputs` struct. These are public inputs of the execution, and should also be provided to the verifier. The secret inputs for the program are provided via the `Host` interface. The default implementation of the host relies on in-memory advice provider (`AdviceProvider`) that can be commonly used for operations that won't require persistence.

Values remaining on the stack after a program is executed can be returned as stack outputs. You can specify exactly how many values (from the top of the stack) should be returned. Notice, that, similar to stack inputs, at most 16 values can be returned via the stack. Attempts to return more than 16 values will cause an error.

Having a small number elements to describe public inputs and outputs of a program may seem limiting, however, just 4 elements are sufficient to represent a root of a Merkle tree or a sequential hash of elements. Both of these can be expanded into an arbitrary number of values by supplying the actual values non-deterministically via the host interface.

## Usage

Miden crate exposes types and functions for executing programs, generating proofs of their correct execution, and verifying the generated proofs. How to do this is explained below, but you can also take a look at working examples [here](masm-examples/) and find instructions for running them via CLI [here](#fibonacci-example).

### Executing programs

For ordinary execution, construct `FastProcessor` and call `execute()` or `execute_sync()`.
Generic code can use the `ProgramExecutor` trait, whose default implementation is
`FastProcessor`. These interfaces take the following inputs:

- `program: &Program` is a reference to the Miden program.
- `stack_inputs: StackInputs` contains the public inputs.
- `advice_inputs: AdviceInputs` contains the private inputs used to build the advice provider. Use `AdviceInputs::default()` when no private inputs are needed.
- `host` is a `Host` for `execute()` or a `SyncHost` for `execute_sync()`. It supplies nondeterministic inputs to the VM and receives messages from it.
- `options: ExecutionOptions` controls execution settings such as the maximum cycle count.

Ordinary execution returns a `Result<ExecutionOutput, ExecutionError>` containing the final stack
state and other execution outputs, or an error if execution failed. `ProgramExecutor` represents
this ordinary execution path; it does not capture a proving witness.

An `ExecutionOutput` cannot be converted into an `ExecutionWitness` after execution. The ordinary
path selects `NoopTracer` before the program runs, so it does not retain the replay data needed to
materialize the VM trace. If the execution will be proved, select tracing up front with
`FastProcessor::execute_for_proving()` / `FastProcessor::execute_for_proving_sync()`, then pass the
returned `ExecutionWitness` to `Prover::prove()`. To materialize only the VM trace, split the
witness with `ExecutionWitness::into_parts()` and pass the resulting `VmWitness` to
`trace::build_trace()`.

For example:

```rust
use miden_vm::{
    advice::AdviceInputs,
    Assembler, DefaultHost, ExecutionOptions, FastProcessor, StackInputs
};

// instantiate the assembler
let assembler = Assembler::default();

// compile Miden assembly source code into a program
let program = assembler.assemble_program(
    "prg",
    "begin push.3 push.5 add swap drop end",
).unwrap();

// use an empty list as initial stack
let stack_inputs = StackInputs::default();

// do not include any initial advice data
let advice_inputs = AdviceInputs::default();

// instantiate a default host (with an empty advice provider)
let mut host = DefaultHost::default();

// instantiate default execution options
let exec_options = ExecutionOptions::default();

// execute the program with no inputs
let output = FastProcessor::new_with_options(
    stack_inputs,
    advice_inputs.clone(),
    exec_options,
)
.unwrap()
.execute_sync(&program.unwrap_program(), &mut host)
.unwrap();
```

### Proving program execution

Execute with `FastProcessor` to produce an `ExecutionWitness`, and read its public claim before
proving consumes it. `Prover::prove` proves the VM portion and returns `Complete` when no deferred
work exists, or `Deferred` containing a passive `DeferredStateWire`. Use `Prover::prove_full` to
complete all proof work in the local process.

For delegated precompile proving, transport `proof.to_bytes()`, decode with the registry-free
`ExecutionProof::read_from_bytes`, match `ExecutionProof::Deferred`, and pass its wire to
`precompile_witness_from_wire`. Optionally merge hydrated singleton witnesses, call
`Prover::prove_precompile`, transition each deferred proof with `complete`, and establish validity
with `Verifier::verify`.

`ExecutionOptions` configure execution, while `Prover::with_hash_fn` selects the proof hash
function. The FastProcessor-backed `prove_sync(&Prover, ...)` function executes and fully proves in
one synchronous call while preserving optimized overlapped execution and trace construction.

`prove_sync()` overlaps execution with hasher-chiplet trace construction when a Rayon worker is
available. A caller with no separate Rayon worker uses compact buffered replay, including on
targets such as `wasm32-unknown-unknown`.

#### Proof generation example

Here is a simple example of executing a program which pushes two numbers onto the stack and computes their sum:

```rust
use miden_vm::{
    advice::AdviceInputs,
    field::PrimeField64,
    Assembler, DefaultHost, ExecutionOptions, FastProcessor, Prover, StackInputs,
};

// instantiate the assembler
let assembler = Assembler::default();

// this is our program, we compile it from assembly code
let program = assembler
    .assemble_program("prg", "begin push.3 push.5 add swap drop end")
    .unwrap()
    .unwrap_program();

// execute the program to produce a post-execution witness
let mut host = DefaultHost::default();
let witness = FastProcessor::new_with_options(
    StackInputs::default(),
    AdviceInputs::default(),
    ExecutionOptions::default(),
)
.unwrap()
.execute_for_proving_sync(&program, &mut host)
.unwrap();
let outputs = *witness.claim().stack_outputs();

// this program has no precompile work, so the proof is ready for verification
let proof = Prover::new().prove(witness).unwrap();

// the output should be 8
assert_eq!(8, outputs.first().unwrap().as_canonical_u64());
```

### Verifying program execution

To verify program execution, use `Verifier::new().verify(&claim, &proof)`. The verifier borrows:

- `claim: &ExecutionClaim`. The program information and public stack inputs and outputs.
- `proof: &ExecutionProof`. The deferred or complete execution proof artifacts.

Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one. Thus, their expected order on the stack will be the reverse of the order in which they are provided, and the last value in the `stack_inputs` is expected to be the value at the top of the stack.

Stack outputs are expected to be ordered as if they would be popped off the stack one by one. Thus, the value at the top of the stack is expected to be in the first position of the `stack_outputs`, and the order of the rest of the output elements will also match the order on the stack. This is the reverse of the order of the `stack_inputs`.

The verifier returns `Result<VerificationOutcome, VerificationError>`. A successful deferred outcome
authenticates an outstanding VM root without validating the passive wire; a successful complete
outcome verifies every applicable STARK. Canonical proof decoding is registry-free, while delegated
precompile proving hydrates wire explicitly with `precompile_witness_from_wire`. See the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md) for transport and limit
details.

> If a program with the provided hash is executed against some secret inputs and the provided public inputs, it will produce the provided outputs.

The verifier needs only the program hash. It does not need the program itself.

#### Proof verification example

Here is a simple example of verifying execution of the program from the previous example:

```rust,ignore
use miden_vm::{
    ExecutionClaim, ProgramInfo, StackInputs, StackOutputs, Verifier, field::Felt,
};

let program =   /* value from previous example */;
let proof =     /* value from previous example */;
let expected_outputs = StackOutputs::new(&[Felt::new(8).unwrap()]).unwrap();
let claim = ExecutionClaim::from_program_info(
    ProgramInfo::from(program),
    StackInputs::default(),
    expected_outputs,
);

match Verifier::new().verify(&claim, &proof) {
    Ok(outcome) if outcome.is_complete() => println!("Execution verified and complete!"),
    Ok(outcome) => println!(
        "Execution verified with outstanding root {:?}",
        outcome.outstanding_precompile_root(),
    ),
    Err(err) => eprintln!("Verification failed: {err}"),
}
```

## Fibonacci calculator

Let's write a simple program for Miden VM (using
[Miden assembly](../crates/assembly/)). Our program will compute the 5-th
[Fibonacci number](https://en.wikipedia.org/wiki/Fibonacci_number):

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
use miden_vm::{
    advice::AdviceInputs,
    field::PrimeField64,
    Assembler, DefaultHost, ExecutionOptions, FastProcessor, Prover, StackInputs,
};

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
let assembler = Assembler::default();
let program = assembler
    .assemble_program("prg", &source)
    .unwrap()
    .unwrap_program();

// initialize a default host (with an empty advice provider)
let mut host = DefaultHost::default();

// initialize the stack with values 0 and 1
let stack_inputs = StackInputs::new(&[1_u32.into(), 0_u32.into()]).unwrap();

// execute the program and prove its post-execution witness
let witness = FastProcessor::new_with_options(
    stack_inputs,
    AdviceInputs::default(),
    ExecutionOptions::default(),
)
.unwrap()
.execute_for_proving_sync(&program, &mut host)
.unwrap();
let outputs = *witness.claim().stack_outputs();
let proof = Prover::new().prove(witness).unwrap();

// fetch the stack outputs, truncating to the first element
let stack = outputs.get_num_elements(1);

// the output should be the 50th Fibonacci number
assert_eq!(12586269025, stack[0].as_canonical_u64());
```

Above, we used public inputs to initialize the stack. This keeps the program simpler and lets us run it from arbitrary starting points without changing its hash.

## CLI interface

If you want to execute, prove, and verify programs on Miden VM, but don't want to write Rust code, you can use Miden CLI. It also contains a number of useful tools to help analyze and debug programs.

### Compiling Miden VM

First, make sure you have Rust [installed](https://www.rust-lang.org/tools/install). The current version of Miden VM requires Rust version **1.96** or later.

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

- `run` executes a Miden assembly program and outputs the result without generating a proof.
- `prove` executes a Miden assembly program and generates a STARK proof.
- `verify` verifies a previously generated proof for a given program.
- `compile` compiles a Miden assembly program and reports compilation statistics.
- `debug` starts a CLI debugger for the specified Miden assembly program and inputs.
- `analyze` runs a Miden assembly program against specific inputs and reports execution statistics.

All of the above subcommands require various parameters to be provided. To get more detailed help on what is needed for a given subcommand, you can run the following:

```shell
./target/optimized/miden-vm [subcommand] --help
```

For example:

```shell
./target/optimized/miden-vm prove --help
```

### Fibonacci example

In the `miden-vm/masm-examples/fib` directory, we provide a very simple Fibonacci calculator example. This example computes the 1000th term of the Fibonacci sequence. You can execute this example on Miden VM like so:

```shell
./target/optimized/miden-vm run miden-vm/masm-examples/fib/fib.masm -n 1
```

This will run the example code to completion and will output the top element remaining on the stack.

## Crate features

Miden VM can be compiled with the following features:

- `std` is enabled by default and relies on the Rust standard library.
- `concurrent` implies `std` and enables multithreaded proof generation.
- `executable` is required for building the Miden VM binary as described above. It implies `std`.
- `metal` enables [Metal](<https://en.wikipedia.org/wiki/Metal_(API)>)-based acceleration of proof generation for recursive proofs on supported platforms such as Apple silicon.
- `no_std` does not rely on the Rust standard library and enables compilation to WebAssembly.
  - Only the `wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported.

To compile with `no_std`, disable default features via `--no-default-features` flag.

### Concurrent proof generation

When compiled with `concurrent` feature enabled, the VM will generate STARK proofs using multiple threads. For benefits of concurrent proof generation check out these [benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. To control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
