---
title: Debugging Programmatically
sidebar_position: 6
---

# Using the debugger programmatically

You may find it useful to debug programs programmatically from Rust. For example, the Miden compiler will compile some code to a package, and then instantiate the debugger to execute code in the package.

Not only does this provide richer output when something goes wrong, but it opens up some useful testing capabilities, such as executing the program up to some breakpoint, asserting something about the state of the VM at that point, and then resuming execution.

## Basic usage

At the most basic level, to use the debugger programmatically, you must instantiate the debug executor, optionally configure it, and then execute a `Program`.

The simplest case is when you have a compiled Miden package (i.e. a `.masp`
file), and you want to run it under the debugger, either printing helpful
diagnostic output on error, or asserting something about the output of the
program. Source compilation is deliberately outside the debugger API; use
`midenc` or `miden build` to produce the package first.

```rust
use std::sync::Arc;
use miden_debug::{Executor, debug_types::DefaultSourceManager, RawFelt};

// Construct a source manager for use in printing diagnostics
let source_manager = Arc::new(DefaultSourceManager::default());

// Load an already compiled executable package
let package = Package::deserialize_from_file_trusted("path/to/program.masp").map(Arc::new).unwrap();

// Construct the debug executor from the package, and specify the initial args
let exec = Executor::for_package(package, [RawFelt::from(1u32)]).expect("invalid package");

// Execute the program
let execution_trace = exec.execute(&program, source_manager);

// Parse expected outputs as Rust values
let output = execution_trace.parse_result::<u32>().expect("expected value of type 'u32'")
assert_eq!(output, 42);
```

If you have more complex inputs to the program, such as advice data, then you can either call specific builder methods on `Executor`, such as `Executor::with_advice_inputs` - or construct the executor with an `ExecutionConfig`, as shown below:

```rust
use miden_debug::{
    Executor, 
    processor::{StackInputs, advice::{AdviceInputs, AdviceStack}},
    RawFelt
};

let exec = Executor::from_config(ExecutionConfig {
    inputs: StackInputs::new(&[RawFelt::from(1u32)]).expect("invalid stack inputs"),
    advice_inputs: AdviceInputs::default()
        .with_advice_stack(AdviceStack::from(vec![RawFelt::from(2u32)])),
    ..Default::default()
});
```

### Dependencies

If your program depends on other packages, you can tell the debug executor how to resolve them like so:

```rust
use miden_core_lib::CoreLibrary;
use miden_protocol::ProtocolLib;
use miden_standards::StandardsLib;

let mut exec = Executor::for_package(program_package, args).unwrap();

// This presumes that `program_package` was assembled against these specific
// versions of the core, protocol, and standards libraries.
let core_lib = Arc::new(CoreLibrary::default().as_ref().clone());
let protocol_lib = Arc::new(ProtocolLib::default().as_ref().clone());
let standards_lib = Arc::new(StandardsLib::default().as_ref().clone());
exec.register_library_dependency(core_lib);
exec.register_library_dependency(protocol_lib);
exec.register_library_dependency(standards_lib);
```

### Event handlers

You can register custom event handlers using `Executor::register_event_handler`, specifying the event and a callback to execute when the event occurs, like so:

```rust
use miden_debug::{
    Executor, 
    events::EventName, 
    processor::{advice::AdviceStack, host::AdviceMutation},
    RawFelt
};

let mut exec = Executor::for_package(program_package, args).unwrap();

exec.register_event_handler(EventName::new("my-event"), |_state| {
    vec![AdviceMutation::extend_advice_stack(AdviceStack::from(vec![RawFelt::from(1u32)]))]
}).expect("invalid event handler");
```

## Controlling execution with breakpoints

As noted in the introduction, one of the more interesting capabilities you get from working with the debugger this way, is the ability to step execution manually either step-by-step, or by setting breakpoints and executing until one of them is hit.

To do so, you need to convert the executor into debug mode, as shown here:

```rust
use miden_debug::{Executor, BreakpointType};

let source_manager = Arc::new(DefaultSourceManager::default());
let program_package = Package::deserialize_from_file_trusted("path/to/program.masp").map(Arc::new).unwrap();
let exec = Executor::for_package(&program_package, args).unwrap();

let program = program_package.unwrap_program();
let mut debug_exec = exec.into_debug(&program, source_manager.clone());

// Step one cycle
let _ = debug_exec.step().expect("step failed");

// Step until execution hits the first op whose source location is associated
// with the given file and line number
let bp = "path/to/file.masm:10".parse::<BreakpointType>().unwrap();
let _ = debug_exec.step_until(bp, None, &source_manager).expect("execution failed");
```

There are a large variety of breakpoint types. You can either construct them
manually using the `BreakpointType` enum, or parse them from a string that contains syntax that is valid in the debugger itself, e.g. `in core::math::u64::overflowing_add` would break when control enters that procedure.

### Extracting information about the current execution state

After stepping execution, you can examine various interesting properties about the state of the program at that point:

```rust
let _ = debug_exec.step().expect("step failed");

// Read a single element from memory at address 1024
let element = debug_exec.read_element(1024);
assert_eq!(element, RawFelt::from(42u32));

// Read a word from memory, starting at address 1024
let word = debug_exec.read_word(1024);
assert_eq!(word, [
    RawFelt::from(42u32),
    RawFelt::from(0u32),
    RawFelt::from(0u32),
    RawFelt::from(0u32),
]);

// Get access to the current state of the operand stack
let stack = debug_exec.stack();
assert!(stack.len() <= 16);
```

We will continue to expand on the set of useful APIs for examining program state in upcoming releases.

## Generating flamegraphs programmatically

The flamegraph support is also exposed as a Rust API, so tests can profile a
program without shelling out to the `miden debug flamegraph` command. Enable the
`flamegraph` feature on `miden-debug`, execute a program with a `DebugExecutor`,
and collect a `FlamegraphProfile` from it:

```rust
use std::sync::Arc;
use miden_debug::{
    Executor,
    debug_types::DefaultSourceManager,
    flamegraph::FlamegraphProfile,
};

let source_manager = Arc::new(DefaultSourceManager::default());
let program_package = Package::deserialize_from_file_trusted("path/to/program.masp").map(Arc::new).unwrap();
let exec = Executor::for_package(&program_package, args).unwrap();

let program = program_package.unwrap_program();
let mut debug_exec = exec.into_debug(&program, source_manager);

let profile = FlamegraphProfile::collect(&mut debug_exec).expect("program execution failed");
assert!(profile.total_cycles() > 0);

profile.write_svg("target/miden-flamegraph.svg").expect("failed to write flamegraph");
```

A recorded transaction can be profiled without its original host by loading its replay snapshot:

```rust
use miden_debug::{ReplaySnapshot, flamegraph::FlamegraphProfile};

let snapshot = ReplaySnapshot::read_from_file("transaction.mdsnap").unwrap();
let profile = FlamegraphProfile::collect_replay(snapshot).unwrap();
profile.write_svg("target/transaction.svg").unwrap();
```

If you are integrating with another executor, you can also build a profile from
already resolved stack names by calling `FlamegraphProfile::record_stack` or
`FlamegraphProfile::record_stack_path`, then write the result as either SVG or
folded stack text.

## Wrapping up

We encourage you to explore the `miden-debug` APIs in more detail, as there are many we have not covered here!

If you find that there are some common boilerplate-like tasks that you think deserve a convenience API in `miden-debug`, don't hesitate to ask!
