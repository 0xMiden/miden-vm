use std::{collections::BTreeSet, path::PathBuf};

use miden_assembly::{Assembler, Library};
use miden_libcore::CoreLibrary;
use miden_processor::{AdviceInputs, ContextId, MemoryAddress};
use miden_vm::{DefaultHost, StackInputs, math::Felt};
use rustyline::{DefaultEditor, error::ReadlineError};

use crate::utils::print_mem_address;

// This work is in continuation to the amazing work done by team `Scribe`
// [here](https://github.com/ControlCplusControlV/Scribe/blob/main/bin/repl/src/repl.rs#L9)
//
// The Miden Read–eval–print loop (REPL) is a Miden shell that allows for quick and easy debugging
// of Miden assembly. To use the repl, simply type "miden-vm repl" after building it with feature
// "executable" (cargo build --release --feature executable) when in the miden home
// crate and the repl will launch. After the REPL gets initialized, you can execute any Miden
// instruction, undo executed instructions, check the state of the stack and memory at a given
// point, and do many other useful things! When the REPL is exited, a `history.txt` file is saved.
// One thing to note is that all the REPL native commands start with an `!` to differentiate them
// from regular assembly instructions.
//
// Miden Instructions
// All Miden instructions mentioned in the
// [Miden Assembly section](https://0xMiden.github.io/miden-vm/user_docs/assembly/main.html)
// are valid.
// One can either input instructions one by one or multiple instructions in one input.
// For example, the below two commands will result in the same output.
// >> push.1
// >> push.2
// >> push.3
//
//  >> push.1 push.2 push.3
//
// In order to execute a control flow operation, one needs to write the entire flow operation in
// a single line with spaces between individual operations.
// Ex.
// ```
// repeat.20
//     pow2
// end
// ```
// should be written as
// `repeat.20 pow2 end`
//
// To execute a control flow operation, one must write the entire statement in a single line with
// spaces between individual operations.
// ```
// >> repeat.20
//       pow2
//    end
// ```
//
// The above example should be written as follows in the REPL tool:
// >> repeat.20 pow2 end
//
// `!stack`
// The `!stack` command prints out the state of the stack at the last executed instruction. Since
// the stack always contains at least 16 elements, 16 or more elements will be printed out (even
// if all of them are zeros).
// >> push.1 push.2 push.3 push.4 push.5
// >> exp
// >> u32wrapping_mul
// >> swap
// >> eq.2
// >> assert
//
// The `!stack` command will print out the following state of the stack:
// ```
// >> !stack
// 3072 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
// ```
//
// `!undo`
// The `!undo` command reverts to the previous state of the stack and memory by dropping off the
// last executed assembly instruction from the program. One could use `!undo` as often as they want
// to restore the state of a stack and memory $n$ instructions ago (provided there are $n$
// instructions in the program). The `!undo` command will result in an error if no remaining
// instructions are left in  the Miden program.
// ```
// >> push.1 push.2 push.3
// >> push.4
// >> !stack
// 4 3 2 1 0 0 0 0 0 0 0 0 0 0 0 0
// >> push.5
// >> !stack
// 5 4 3 2 1 0 0 0 0 0 0 0 0 0 0 0
// >> !undo
// 4 3 2 1 0 0 0 0 0 0 0 0 0 0 0 0
// >> !undo
// 3 2 1 0 0 0 0 0 0 0 0 0 0 0 0 0
// ```
//
//`!program`
// The `!program` command prints out the entire Miden program getting executed. E.g., in the below
// ```
// scenario: >> push.1
// >> push.2
// >> push.3
// >> add
// >> add
// >> !program
// begin
//    push.1
//    push.2
//    push.3
//    add
//    add
// end
// ```
//
// `!help`
// The `!help` command prints out all the available commands in the REPL tool.
//
// `!mem`
// The `!mem` command prints out the contents of all initialized memory locations. For each such
// location, the address, along with its memory values, is printed. Recall that four elements are
// stored at each memory address.
// If the memory has at least one value that has been initialized:
// ```
// >> !mem
// 7: [1, 2, 0, 3]
// 8: [5, 7, 3, 32]
// 9: [9, 10, 2, 0]
// ```
//
// If the memory is not yet been initialized:
// ```
// >> !mem
// The memory has not been initialized yet
// ```
//
// `!mem[addr]`
// The `!mem[addr]` command prints out memory contents at the address specified by `addr`.
// If the `addr` has been initialized:
// ```
// >> !mem[9]
// 9: [9, 10, 2, 0]
// ```
//
// If the `addr` has not been initialized:
// ```
// >> !mem[87]
// Memory at address 87 is empty
// ```

/// Initiates the Miden Repl tool.
pub fn start_repl(library_paths: &Vec<PathBuf>, use_corelib: bool) {
    let mut program_lines: Vec<String> = Vec::new();

    // set of user imported modules
    let mut imported_modules: BTreeSet<String> = BTreeSet::new();

    // load libraries from files
    let mut provided_libraries = Vec::new();
    for path in library_paths {
        let library = Library::deserialize_from_file(path)
            .map_err(|e| format!("Failed to read library: {e}"))
            .unwrap();
        provided_libraries.push(library);
    }
    if use_corelib {
        provided_libraries.push(CoreLibrary::default().into());
    }

    println!("========================== Miden REPL ============================");
    println!();
    // prints out all the available commands in the Miden Repl tool.
    print_instructions();

    // flag to determine if the stack should be printed or not post the execution of the
    // last command.
    let mut should_print_stack = false;

    // state of the entire memory at the latest clock cycle.
    let mut memory: Vec<(MemoryAddress, Felt)> = Vec::new();

    // initializing readline.
    let mut rl = DefaultEditor::new().expect("Readline couldn't be initialized");
    loop {
        let mut program = String::new();
        for module in imported_modules.iter() {
            program.push_str(module);
            program.push('\n');
        }
        program.push_str(&format!(
            "\nbegin\n{}\nend",
            program_lines.iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
        ));

        let result = execute(program.clone(), &provided_libraries);

        if !program_lines.is_empty() {
            match result {
                Ok((mem, stack_state)) => {
                    if should_print_stack {
                        print_stack(stack_state);
                    }
                    memory = mem;
                },
                Err(e) => {
                    println!("Error running program: {e:?}");
                    program_lines.pop();
                },
            }
        } else if should_print_stack {
            println!("{}", str::repeat("0 ", 16));
        }

        match rl.readline(">> ") {
            Ok(line) => {
                if line == "!program" {
                    println!("{program}");
                    should_print_stack = false;
                } else if line == "!help" {
                    // prints out all the available commands in the Miden Repl tool.
                    print_instructions();
                    should_print_stack = false;
                } else if line == "!mem" {
                    should_print_stack = false;
                    if memory.is_empty() {
                        println!("The memory has not been initialized yet");
                        continue;
                    }
                    for &(addr, mem) in &memory {
                        // prints out the address and memory value at that address.
                        print_mem_address(addr, mem);
                    }
                } else if line.len() > 6 && &line[..5] == "!mem[" {
                    // if user wants to see the state of a particular address in a memory, the input
                    // should be at least of length 5.

                    // flag to determine if the memory at an address has been initialized or not
                    let mut mem_at_addr_present = false;

                    // extracts the address from user input.
                    match read_mem_address(&line) {
                        Ok(addr) => {
                            for &(i, memory_value) in &memory {
                                if i == addr {
                                    // prints the address and memory value at that address.
                                    print_mem_address(addr, memory_value);
                                    // sets the flag to true as the address has been initialized.
                                    mem_at_addr_present = true;
                                    break;
                                }
                            }
                            // in case the flag has not been initialized.
                            if !mem_at_addr_present {
                                println!("Memory at address {addr} is empty");
                            }
                        },
                        Err(msg) => println!("{msg}"),
                    }

                    should_print_stack = false;
                } else if line == "!undo" {
                    match program_lines.pop() {
                        Some(last_line) => {
                            println!("Undoing {last_line}");
                            should_print_stack = true;
                        },
                        None => {
                            println!("There's no previously executed command");
                            should_print_stack = false;
                        },
                    };
                } else if line == "!stack" {
                    should_print_stack = true;
                } else if line.starts_with("!use") {
                    handle_use_command(line, &provided_libraries, &mut imported_modules);
                } else {
                    rl.add_history_entry(line.clone()).expect("Failed to add a history entry");
                    program_lines.push(line.clone());
                    should_print_stack = true;
                }
            },
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            },
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            },
            Err(err) => {
                println!("Error: {err:?}");
                break;
            },
        };
    }
    rl.save_history("history.txt")
        .expect("Couldn't dump the program into the history file");
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

/// Compiles and executes a compiled Miden program, returning the stack, memory and any Miden
/// errors. The program is passed in as a String, passed to the Miden Assembler, and then passed
/// into the Miden Processor to be executed.
#[allow(clippy::type_complexity)]
fn execute(
    program: String,
    provided_libraries: &[Library],
) -> Result<(Vec<(MemoryAddress, Felt)>, Vec<Felt>), String> {
    // compile program
    let mut assembler = Assembler::default();

    for library in provided_libraries {
        assembler.link_dynamic_library(library).map_err(|err| format!("{err}"))?;
    }

    let program = assembler.assemble_program(program).map_err(|err| format!("{err}"))?;

    let stack_inputs = StackInputs::default();
    let advice_inputs = AdviceInputs::default();
    let mut host = DefaultHost::default();
    for library in provided_libraries {
        host.load_library(library.mast_forest()).map_err(|err| format!("{err}"))?;
    }

    let state_iter =
        miden_processor::execute_iter(&program, stack_inputs, advice_inputs, &mut host);
    let (system, _, stack, chiplets, err) = state_iter.into_parts();
    if let Some(err) = err {
        return Err(format!("{err}"));
    }

    // loads the memory at the latest clock cycle.
    let mem_state = chiplets.memory.get_state_at(ContextId::root(), system.clk());
    // loads the stack along with the overflow values at the latest clock cycle.
    let stack_state = stack.get_state_at(system.clk());

    Ok((mem_state, stack_state))
}

/// Parses the address in integer form from `!mem[addr]` command, otherwise throws an error.
fn read_mem_address(mem_str: &str) -> Result<MemoryAddress, String> {
    // the first five characters is "!mem[" and the digit character should start from 6th
    // element.
    let remainder = &mem_str[5..];
    let digits_end = remainder
        .char_indices()
        .find_map(|(idx, c)| if c.is_ascii_digit() { None } else { Some(idx) })
        .unwrap_or(remainder.len());

    if &remainder[digits_end..] != "]" {
        return Err("Please enter memory command correctly. It should be !mem[addr]".to_string());
    }

    // convert the parsed digits into integer form.
    let addr: u32 = remainder[..digits_end]
        .parse()
        .expect("The input address couldn't be parsed into an integer");

    Ok(addr.into())
}

/// Parses `!use` command. Adds the provided module to the program imports, or prints the list of
/// all available modules if no module name was provided.
fn handle_use_command(
    line: String,
    provided_libraries: &[Library],
    imported_modules: &mut BTreeSet<String>,
) {
    let tokens: Vec<&str> = line.split_whitespace().collect();

    match tokens.len() {
        1 => {
            println!("Modules available for importing:");
            for lib in provided_libraries {
                lib.module_infos().for_each(|module| println!("{}", module.path()));
            }
        },
        2 => {
            imported_modules.insert(format!("use {}", tokens[1]).to_string());
        },
        _ => println!("malformed instruction '!use': too many parameters provided"),
    }
}

/// Prints out all the available command present in the Miden Repl tool.
fn print_instructions() {
    println!("Available commands:");
    println!();
    println!("!stack: display the complete state of the stack");
    println!("!mem: display the state of the entire memory");
    println!("!mem[i]: display the state of the memory at address i");
    println!("!undo: remove the last instruction");
    println!("!use: display a list of modules available for import");
    println!("!use <full_module_name>: import the specified module");
    println!("!program: display the program");
    println!("!help: print out all the available commands");
    println!();
}

/// Returns the state of the stack along with its overflown part in a string format.
fn print_stack(stack: Vec<Felt>) {
    // converts the stack which is a vector of felt into string and prints it.
    println!("{}", stack.iter().map(|f| format!("{f}")).collect::<Vec<_>>().join(" "),)
}
