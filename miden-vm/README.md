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

Execution returns the top 16 stack elements in `StackOutputs`. Use `get_num_elements(n)` to inspect a prefix of these outputs; it returns at most 16 elements.

Having a small number elements to describe public inputs and outputs of a program may seem limiting, however, just 4 elements are sufficient to represent a root of a Merkle tree or a sequential hash of elements. Both of these can be expanded into an arbitrary number of values by supplying the actual values non-deterministically via the host interface.

## Usage

Miden crate exposes types and functions for executing programs, generating proofs of their correct execution, and verifying the generated proofs. How to do this is explained below, but you can also take a look at working examples [here](masm-examples/) and find instructions for running them via CLI [here](#fibonacci-example).

### Executing programs

Create a `Processor` for the program and configure its public stack inputs, private advice,
execution options, and optional package source context. The selected execution validates the advice
against the final options when the machine is initialized. Run it with `run_sync()` for a
`SyncHost` or `run().await` for an asynchronous `Host`.

`execute()` returns an `ExecutionOutput` with the final stack, advice, and memory. Select
`record_witness()` before running if you need the replay data for proving.

```rust
use miden_vm::{Assembler, DefaultHost, Processor};

let program = Assembler::default()
    .assemble_program("prg", "begin push.3 push.5 add swap drop end")
    .unwrap()
    .unwrap_program();
let output = Processor::new(&program)
    .execute()
    .run_sync(&mut DefaultHost::default())
    .unwrap();
```

### Proving program execution

Record a witness, then pass it to `Prover::prove_full` to obtain a `CompleteProof` locally. The
recording also returns the public claim and final advice. To use a
[proving service](../crates/prover-service/README.md), send the serialized witness and retain the
claim and final advice locally. To require a completed proof from the service, decode its bytes
as an `ExecutionProof` and check the precompile status with `CompleteProof::try_from(proof)`.

```rust
use miden_vm::{
    Assembler, DefaultHost, Processor, Prover, Verifier, WitnessOutput, field::PrimeField64,
};

let program = Assembler::default()
    .assemble_program("prg", "begin push.3 push.5 add swap drop end")
    .unwrap()
    .unwrap_program();
let WitnessOutput { claim, witness, .. } = Processor::new(&program)
    .record_witness()
    .run_sync(&mut DefaultHost::default())
    .unwrap();

assert_eq!(8, claim.stack_outputs().first().unwrap().as_canonical_u64());
let proof = Prover::new().prove_full(witness).unwrap();
assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());
```

Use `Prover::prove` to prove the VM portion. The resulting `ExecutionProof` carries a portable
`PrecompileWitness` if any deferred work remains. For delegated precompile proving, transport the
proof with `ExecutionProof::to_bytes` and decode it with `ExecutionProof::read_from_bytes`. Pass the
carried witnesses to `Prover::prove_precompiles`. One batch proof preserves input root order and
repeated roots. Attach it with `ExecutionProof::complete` and verify the completed proof.

`ExecutionOptions::with_execution_precompile_limits` bounds guest-induced deferred work, while
`ExecutionOptions::with_verification_precompile_limits` bounds the final root-reachable witness
exported after execution. `Verifier::with_verification_precompile_limits` and
`Prover::with_verification_precompile_limits` configure the per-singleton policy for transported
witnesses. These logical limits apply separately from the prover's batch-wide peak-memory budget.

Both proving methods build the trace from the recorded witness under the prover's VM memory
budget. For AIR diagnostics, split the witness with `into_parts()` and materialize the VM
component with `vm_witness.build_trace(&budget)`.

#### Stepping a recording

Start a session to inspect the machine as it executes. The recorder stays with the session, so you
can finish recording after stepping and pass that witness to the prover.

```rust,ignore
let mut session = Processor::new(&program).record_witness().start()?;
session.step_sync(&mut host)?;
let clock = session.state().clock();
let finished = session.run_to_completion_sync(&mut host)?;
let WitnessOutput { claim, witness, .. } = finished.finish()?;
let proof = prover.prove_full(witness)?;
```

Use the borrowed `run_until_halt_sync` or `run_until_halt` when you need to inspect the session
after an execution error. A successful halt makes the final state available for inspection before
`finish()` exports the selected output.

### Verifying program execution

To verify program execution, use `Verifier::new().verify(&claim, &proof)`. The verifier borrows:

- `claim: &ExecutionClaim`. The program information and public stack inputs and outputs.
- `proof: &ExecutionProof`. The deferred or complete execution proof artifacts.

`StackInputs` and `StackOutputs` both use top-first ordering: the first supplied element is at the top of the stack, followed by the remaining elements in order. For example, `StackInputs::new(&[1_u32.into(), 0_u32.into()])` starts with `1` above `0`. Constructors pad inputs and outputs shorter than 16 elements with zeros.

The verifier returns `Result<VerificationOutcome, VerificationError>`. A successful deferred outcome
evaluates the carried witness and authenticates its outstanding VM root; a successful
complete outcome verifies every applicable STARK. Canonical proof decoding checks portable graph
encoding and allocation bounds without a registry. Preparation later validates and commits each
graph under the configured per-witness limits. Precompile proving imports the prepared witnesses
directly into a shared Session. See the
[deferred-proof semantics](../docs/src/design/deferred/semantics.md) for transport and limit details.

> If a program with the provided hash is executed against some secret inputs and the provided public inputs, it will produce the provided outputs.

The verifier needs only the program hash. It does not need the program itself.

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
    field::PrimeField64,
    Assembler, DefaultHost, Processor, StackInputs,
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

let output = Processor::new(&program)
    .with_stack_inputs(stack_inputs)
    .execute()
    .run_sync(&mut host)
    .unwrap();

let stack = output.stack.get_num_elements(1);

// the output should be the 50th Fibonacci number
assert_eq!(12586269025, stack[0].as_canonical_u64());
```

Above, we used public inputs to initialize the stack. This keeps the program simpler and lets us run it from arbitrary starting points without changing its hash.

## CLI interface

If you want to execute, prove, and verify programs on Miden VM, but don't want to write Rust code, you can use Miden CLI. It also contains a number of useful tools to help analyze and debug programs.

The CLI limits package (`.masp`) files to 512 MiB, input (`.inputs`) JSON files to
64 MiB, and output (`.outputs`) JSON files to 64 KiB. Files at the limit are accepted;
larger files are rejected before decoding. These readers accept regular files and
symlinks to regular files. Pipes, devices, and directories are rejected.

The CLI writes each proof and output JSON artifact to a temporary file in the
destination directory. It replaces the destination after writing and syncing the
complete artifact, so a write failure leaves the previous file intact. Replacing
a destination symlink replaces the link itself.

New artifacts and replacements belong to the current user and use normal file
creation permissions, including inherited ACLs. The CLI does not copy the previous
file's ownership or access controls.

On Unix, the CLI syncs the destination directory after replacement to persist the
rename. A failure at this final step reports that the new artifact has already
replaced the previous file.

### Compiling Miden VM

First, make sure you have Rust [installed](https://www.rust-lang.org/tools/install). The current version of Miden VM requires Rust version **1.96.1** or later.

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
- `bundle` combines Miden assembly modules into a `.masp` library or kernel package.

All of the above subcommands require various parameters to be provided. To get more detailed help on what is needed for a given subcommand, you can run the following:

```shell
./target/optimized/miden-vm [subcommand] --help
```

For example:

```shell
./target/optimized/miden-vm prove --help
```

### Configuration

Run `miden-vm <command> --help` to see that command's arguments and flags. For reusable
settings, the [CLI settings reference](https://github.com/0xMiden/miden-vm/blob/next/docs/src/usage.md#settings-and-defaults)
lists each key, what it controls, its default, and its accepted values or units. For
example, `proving.hasher` accepts `"eidos"` (the default), `"blake3-256"`, or `"keccak"`.

The CLI reads `miden-vm.toml` from the working directory when present. To use a file
named `ci.toml`, put the settings in that file and pass `--config ci.toml`.

```toml
schema-version = 1

[execution]
max-cycles = 1_000_000

[proving]
hasher = "blake3-256"
```

Repeat `--set KEY=VALUE` to override individual settings for one invocation.

```shell
miden-vm prove program.masm --config ci.toml --set resources.vm-prover-memory=8GiB
```

The executable gets the setting names, types, and descriptions from
[cli-schema.toml](src/cli/cli-schema.toml).

### Fibonacci example

In the `miden-vm/masm-examples/fib` directory, we provide a very simple Fibonacci calculator example. This example computes the 1001st Fibonacci number modulo the VM field. You can execute this example on Miden VM like so:

```shell
./target/optimized/miden-vm run miden-vm/masm-examples/fib/fib.masm --set display.num-outputs=1
```

This will run the example code to completion and will output the top element remaining on the stack.

## Crate features

Miden VM can be compiled with the following features:

- `std` is enabled by default and relies on the Rust standard library.
- `concurrent` implies `std` and enables multithreaded proof generation.
- `executable` is required for building the Miden VM binary as described above. It implies `std`.

For a `no_std` build, disable default features with `--no-default-features`. Only the
`wasm32-unknown-unknown` and `wasm32-wasip1` targets are officially supported for this configuration.

### Concurrent proof generation

When compiled with `concurrent` feature enabled, the VM will generate STARK proofs using multiple threads. For benefits of concurrent proof generation check out these [benchmarks](../README.md#Performance).

Internally, we use [rayon](https://github.com/rayon-rs/rayon) for parallel computations. To control the number of threads used to generate a STARK proof, you can use `RAYON_NUM_THREADS` environment variable.

## License
This project is dual-licensed under the [MIT](http://opensource.org/licenses/MIT) and [Apache 2.0](https://opensource.org/license/apache-2-0) licenses.
