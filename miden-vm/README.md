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

For ordinary execution, create `Processor::new(&program)`, configure its inputs and execution
options, and select `.execute().run(...).await` or `.execute().run_sync(...)`.
These interfaces take the following inputs:

- `program: &Program` is a reference to the Miden program.
- `stack_inputs: StackInputs` contains the public inputs.
- `advice_inputs: AdviceInputs` contains the private inputs used to build the advice provider. Use `AdviceInputs::default()` when no private inputs are needed.
- `host` is a `Host` for `run()` or a `SyncHost` for `run_sync()`. It supplies nondeterministic inputs to the VM and receives messages from it.
- `options: ExecutionOptions` controls execution settings such as the maximum cycle count.

Ordinary execution returns a `Result<ExecutionOutput, ExecutionError>` containing the final stack
state and other execution outputs, or an error if execution failed. Its memory snapshot uses the
`Memory` type reexported by both `miden_vm` and `miden_processor`. Ordinary execution does not
record a proving witness.

An `ExecutionOutput` cannot be converted into an `ExecutionWitness` after execution. The ordinary
path selects `NoopTracer` before the program runs, so it does not retain the replay data needed to
materialize the VM trace. If the execution will be proved, select tracing up front with
`.record_witness().run(...)` / `.record_witness().run_sync(...)`, then pass the returned `witness` to
`Prover::prove()`. You can also execute and prove directly with
`.prove_complete(&prover).run_sync(...)` or select `.prove_deferred(&prover)` to retain
precompile work.
To materialize a VM trace directly, select `.build_trace(budget)`. Its result contains an
`ExecutionTrace` with the VM trace and matching optional precompile witness. A stored
`ExecutionWitness` can materialize both artifacts later with `witness.build_trace(budget)`.

Each `Processor` binds one program and collects inputs, execution options, and optional package
source context before task selection. Advice is validated against the final options when the machine
is initialized. Select `.execute()`, `.record_witness()`,
`.build_trace(budget)`, `.prove_complete(&prover)`, or `.prove_deferred(&prover)` before running or
starting a session.
Create a new builder for each execution; shared `ExecutionOptions` can be cloned explicitly.

`Processor` wraps the processor crate's `ExecutionRequest` and adds complete and deferred proving
tasks. `Execution`, `ExecutionSession`, `CompletedExecution`, `WitnessOutput`, and `TraceOutput`
are the same processor-owned types reexported by this crate. The processor owns initialization,
execution, recording, and session completion. Proving tasks pass the resulting `ExecutionTrace`
to a concrete `&Prover`.

Tasks can also use `.start()` to create a session. The session owns its machine and recorder, so
the program can go out of scope. `state()` returns a processor view while running and after halt,
failure, or a cancelled async step. A `CompletedExecution` permits final inspection before
`.finish()` exports execution outputs, prepares the requested artifact, and performs proving.

For example:

```rust
use miden_vm::{
    advice::AdviceInputs,
    Assembler, DefaultHost, ExecutionOptions, ExecutionOutput, Processor, StackInputs,
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
let program = program.unwrap_program();
let ExecutionOutput { stack, advice, .. } = Processor::new(&program)
    .with_options(exec_options)
    .with_stack_inputs(stack_inputs)
    .with_advice(advice_inputs.clone())
    .execute()
    .run_sync(&mut host)
    .unwrap();
```

### Proving program execution

Select `.prove_complete(&prover)` to execute and prove all work, returning a
`ProvingOutput<CompleteProof>`. Select `.prove_deferred(&prover)` to prove the VM while retaining
any authenticated precompile work in a portable `ExecutionProof`. Both results include the execution claim and final
advice. The complete wrapper can be borrowed with `.as_inner()` or consumed with `.into_inner()`
when an API takes an `ExecutionProof`.

For separate execution and proving, select `.record_witness()` and pass its `witness` field to
`Prover::prove` or `Prover::prove_full`. The former proves the VM portion, returning an empty
precompile status when no deferred work exists or a deferred status carrying one portable
`PrecompileWitness`. The latter completes all proof work locally.

For delegated precompile proving, transport the proof with `ExecutionProof::to_bytes`, then decode
it with `ExecutionProof::read_from_bytes`. Pass the carried witnesses to
`Prover::prove_precompiles(Vec<PrecompileWitness>)`. One batch produces one proof, preserving input
root order and repeated roots. After precompile proving, call `complete` and then `Verifier::verify`.
Completion preserves the compatibility declaration.

`ExecutionOptions::with_execution_precompile_limits` bounds guest-induced deferred work, while
`ExecutionOptions::with_verification_precompile_limits` bounds the final root-reachable witness
exported after execution. `Verifier::with_verification_precompile_limits` and
`Prover::with_verification_precompile_limits` configure the same per-singleton verification policy
for transported witnesses. Preparation applies verification limits before commitment hashing;
native semantic evaluation and Session import do not reapply admission. These logical limits are
distinct from the prover's batch-wide peak-memory budget.

`ExecutionOptions` configure execution, while `Prover::with_hash_fn` selects the proof hash
function. Select `.prove_complete(&prover).run_sync(&mut host)` to execute and fully prove in
one synchronous call. The prover supplies the trace budget before execution starts. Async
`.run(...).await` awaits host callbacks; local proof generation remains synchronous on the calling
thread. To initialize the machine ahead of time, call `.prepare()` on the selected execution before
running or starting it. Advanced APIs under `miden_vm::processor` include `ExecutionRequest` for
execution without the proving facade, `ExecutionTask` for custom task selection, and `FastProcessor`
for direct machine control.

Synchronous trace building overlaps execution with hasher-chiplet trace construction when a Rayon
worker is available. A caller with no separate Rayon worker uses compact buffered replay, including
on targets such as `wasm32-unknown-unknown`.

#### Proof generation example

Here is a simple example of executing a program which pushes two numbers onto the stack and computes their sum:

```rust
use miden_vm::{
    advice::AdviceInputs,
    field::PrimeField64,
    Assembler, DefaultHost, Processor, Prover, ProvingOutput, StackInputs,
};

// instantiate the assembler
let assembler = Assembler::default();

// this is our program, we compile it from assembly code
let program = assembler
    .assemble_program("prg", "begin push.3 push.5 add swap drop end")
    .unwrap()
    .unwrap_program();

// execute and prove the program using the prover's configured trace budget
let mut host = DefaultHost::default();
let prover = Prover::new();
let ProvingOutput { claim, proof, advice } = Processor::new(&program)
    .with_stack_inputs(StackInputs::default())
    .with_advice(AdviceInputs::default())
    .prove_complete(&prover)
    .run_sync(&mut host)
    .unwrap();
let outputs = *claim.stack_outputs();
let proof = proof.into_inner();

// the output should be 8
assert_eq!(8, outputs.first().unwrap().as_canonical_u64());
```

#### Recording a witness for separate proving

The facade returns named outputs with public fields. The witness and final advice can be moved
independently; advice is retained locally rather than serialized into the proving witness.

```rust
use miden_vm::{Processor, Prover, WitnessOutput};
# fn example(program: &miden_vm::Program, host: &mut impl miden_vm::SyncHost, prover: &Prover)
#     -> Result<(), Box<dyn std::error::Error>> {
let WitnessOutput { claim, witness, advice } = Processor::new(program)
    .record_witness()
    .run_sync(host)?;
let proof = prover.prove(witness)?;
miden_vm::Verifier::new().verify(&claim, &proof)?;
# Ok(())
# }
```

`Prover::prove` retains any outstanding precompile work in the proof. Use `Prover::prove_full` to
complete that work locally instead.

To materialize a recorded witness before proving, call `ExecutionWitness::build_trace` with the
prover's trace budget. It returns an `ExecutionTrace` containing the VM trace and its matching optional
precompile witness:

```rust
use miden_vm::{ExecutionWitness, Prover};
# fn example(witness: ExecutionWitness, prover: &Prover) -> Result<(), Box<dyn std::error::Error>> {
let trace = witness.build_trace(prover.trace_budget())?;
let proof = prover.prove_full_trace(trace)?;
# Ok(())
# }
```

#### Running asynchronously

All built-in tasks support `.run(...).await`. Async execution awaits host callbacks; local CPU
proving still runs on the calling thread.

```rust
use miden_vm::{Processor, Prover, ProvingOutput};
# async fn example(program: &miden_vm::Program, host: &mut impl miden_vm::Host, prover: &Prover)
#     -> Result<(), Box<dyn std::error::Error>> {
let ProvingOutput { claim, proof, advice } = Processor::new(program)
    .prove_deferred(prover)
    .run(host)
    .await?;
# Ok(())
# }
```

#### Stepping before completing a proof

A session retains its execution mode and recorded data across steps. Its `run_sync` and async
`run` methods execute the remaining program and return the selected task's output, including
trace construction or proving.

```rust
use miden_vm::{Processor, Prover, ProvingOutput};
# fn example(program: &miden_vm::Program, host: &mut impl miden_vm::SyncHost, prover: &Prover)
#     -> Result<(), Box<dyn std::error::Error>> {
let mut session = Processor::new(program)
    .prove_complete(prover)
    .start()?;
session.step_sync(host)?;
let completed = session.run_to_completion_sync(host)?;
println!("final precompile root: {:?}", completed.state().precompile_root());
let ProvingOutput { claim, proof, advice } = completed.finish()?;
miden_vm::Verifier::new().verify(&claim, proof.as_inner())?;
# Ok(())
# }
```

`run_to_completion_sync` and async `run_to_completion` separate VM completion from artifact
preparation and proving. Inspect the final processor through `CompletedExecution::state()`, then
call `finish()` to export any deferred precompile witness and finalize the task. `finish()` can
report failures from export, artifact preparation, or proving.

Use borrowed `run_until_halt_sync` or async `run_until_halt` to keep the session available for
inspection on success or error. For individual steps, use `step_sync` or async `step`. A failed
or cancelled session remains inspectable. `try_complete` returns
`ControlFlow::Break(CompletedExecution)` after successful termination or
`ControlFlow::Continue(session)` otherwise. Startup and VM driving return `ExecutionError`.
Task finalization can return a task-specific error such as `ProvingRunError`.

#### Inspecting an execution trace before proving

`TraceOutput` carries an `ExecutionTrace` with the materialized VM trace and its matching optional
precompile witness. Borrow those artifacts with `vm_trace()` and `precompile_witness()`, then pass the
execution trace directly to the prover. `ExecutionTrace::try_new` checks the pairing when supplied
with separate artifacts.

```rust
use miden_vm::{Processor, Prover, TraceOutput};
# fn example(program: &miden_vm::Program, host: &mut impl miden_vm::SyncHost, prover: &Prover)
#     -> Result<(), Box<dyn std::error::Error>> {
let budget = prover.trace_budget();
let TraceOutput { claim, trace, .. } = Processor::new(program)
    .build_trace(budget)
    .run_sync(host)?;
println!("Core trace rows: {}", trace.vm_trace().trace_len_summary().core_rows());
let proof = prover.prove_full_trace(trace)?;
miden_vm::Verifier::new().verify(&claim, proof.as_inner())?;
# Ok(())
# }
```

Use `Prover::prove_trace` to leave precompile work deferred. Both trace-proving methods also check
the trace against the selected prover's memory budget.

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

#### Proof verification example

This example proves a small program and verifies that it returns the expected output:

```rust
use miden_vm::{
    Assembler, DefaultHost, ExecutionClaim, Processor, Prover, ProvingOutput, StackInputs,
    StackOutputs, Verifier,
};

let program = Assembler::default()
    .assemble_program("prg", "begin push.3 push.5 add swap drop end")
    .unwrap()
    .unwrap_program();
let prover = Prover::new();
let ProvingOutput { proof, .. } = Processor::new(&program)
    .prove_complete(&prover)
    .run_sync(&mut DefaultHost::default())
    .unwrap();

// Choose the expected claim independently of the prover's returned outputs.
let expected_outputs = StackOutputs::new(&[8_u32.into()]).unwrap();
let claim = ExecutionClaim::from_program_info(
    program.to_info(),
    StackInputs::default(),
    expected_outputs,
);
let outcome = Verifier::new().verify(&claim, proof.as_inner()).unwrap();
assert!(outcome.is_complete());
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
    field::PrimeField64,
    Assembler, DefaultHost, Processor, Prover, ProvingOutput, StackInputs,
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

// execute the program and complete its proof
let prover = Prover::new();
let ProvingOutput { claim, .. } = Processor::new(&program)
    .with_stack_inputs(stack_inputs)
    .prove_complete(&prover)
    .run_sync(&mut host)
    .unwrap();

// fetch the stack outputs, truncating to the first element
let stack = claim.stack_outputs().get_num_elements(1);

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

### Fibonacci example

In the `miden-vm/masm-examples/fib` directory, we provide a very simple Fibonacci calculator example. This example computes the 1001st Fibonacci number modulo the VM field. You can execute this example on Miden VM like so:

```shell
./target/optimized/miden-vm run miden-vm/masm-examples/fib/fib.masm -n 1
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
