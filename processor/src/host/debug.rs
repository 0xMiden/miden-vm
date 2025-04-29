use alloc::vec::Vec;
use std::{print, println};

use miden_air::RowIndex;
use vm_core::{DebugOptions, Felt, PrimeField64};

use super::ProcessState;
use crate::system::ContextId;

// DEBUG HANDLER
// ================================================================================================

/// Prints the info about the VM state specified by the provided options to stdout.
pub fn print_debug_info(process: ProcessState, options: &DebugOptions) {
    let printer = Printer::new(process.clk(), process.ctx(), process.fmp());
    match options {
        DebugOptions::StackAll => {
            printer.print_vm_stack(process, None);
        },
        DebugOptions::StackTop(n) => {
            printer.print_vm_stack(process, Some(*n as usize));
        },
        DebugOptions::MemAll => {
            printer.print_mem_all(process);
        },
        DebugOptions::MemInterval(n, m) => {
            printer.print_mem_interval(process, *n, *m);
        },
        DebugOptions::LocalInterval(n, m, num_locals) => {
            printer.print_local_interval(process, (*n as u32, *m as u32), *num_locals as u32);
        },
    }
}

// HELPER FUNCTIONS
// ================================================================================================

struct Printer {
    clk: RowIndex,
    ctx: ContextId,
    fmp: u32,
}

impl Printer {
    fn new(clk: RowIndex, ctx: ContextId, fmp: u64) -> Self {
        Self { clk, ctx, fmp: fmp as u32 }
    }

    /// Prints the number of stack items specified by `n` if it is provided, otherwise prints
    /// the whole stack.
    fn print_vm_stack(&self, process: ProcessState, n: Option<usize>) {
        let stack = process.get_stack_state();

        // determine how many items to print out
        let num_items = core::cmp::min(stack.len(), n.unwrap_or(stack.len()));

        // print all items except for the last one
        println!("Stack state before step {}:", self.clk);
        for (i, element) in stack.iter().take(num_items - 1).enumerate() {
            println!("├── {i:>2}: {element}");
        }

        // print the last item, and in case the stack has more items, print the total number of
        // un-printed items
        let i = num_items - 1;
        if num_items == stack.len() {
            println!("└── {i:>2}: {}\n", stack[i]);
        } else {
            println!("├── {i:>2}: {}", stack[i]);
            println!("└── ({} more items)\n", stack.len() - num_items);
        }
    }

    /// Prints the whole memory state at the cycle `clk` in context `ctx`.
    fn print_mem_all(&self, process: ProcessState) {
        let mem = process.get_mem_state(self.ctx);
        let element_width = mem
            .iter()
            .map(|(_addr, value)| element_printed_width(Some(*value)))
            .max()
            .unwrap_or(0) as usize;

        println!("Memory state before step {} for the context {}:", self.clk, self.ctx);

        // print the main part of the memory (wihtout the last value)
        for (addr, value) in mem.iter().take(mem.len() - 1) {
            print_mem_address(*addr as u32, Some(*value), false, false, element_width);
        }

        // print the last memory value
        if let Some((addr, value)) = mem.last() {
            print_mem_address(*addr as u32, Some(*value), true, false, element_width);
        }
    }

    /// Prints memory values in the provided addresses interval.
    fn print_mem_interval(&self, process: ProcessState, n: u32, m: u32) {
        let mut mem_interval = Vec::new();
        for addr in n..m + 1 {
            mem_interval.push((addr, process.get_mem_value(self.ctx, addr)));
        }

        if n == m {
            println!(
                "Memory state before step {} for the context {} at address {}:",
                self.clk, self.ctx, n
            )
        } else {
            println!(
                "Memory state before step {} for the context {} in the interval [{}, {}]:",
                self.clk, self.ctx, n, m
            )
        };

        print_interval(mem_interval, false);
    }

    /// Prints locals in provided indexes interval.
    fn print_local_interval(&self, process: ProcessState, interval: (u32, u32), num_locals: u32) {
        let mut local_mem_interval = Vec::new();
        let local_memory_offset = self.fmp - num_locals + 1;

        // in case start index is 0 and end index is 2^16, we should print all available locals.
        let (start, end) = if interval.0 == 0 && interval.1 == u16::MAX as u32 {
            (0, num_locals - 1)
        } else {
            interval
        };
        for index in start..end + 1 {
            local_mem_interval
                .push((index, process.get_mem_value(self.ctx, index + local_memory_offset)))
        }

        if interval.0 == 0 && interval.1 == u16::MAX as u32 {
            println!("State of procedure locals before step {}:", self.clk)
        } else if interval.0 == interval.1 {
            println!("State of procedure local at index {} before step {}:", interval.0, self.clk,)
        } else {
            println!(
                "State of procedure locals [{}, {}] before step {}:",
                interval.0, interval.1, self.clk,
            )
        };

        print_interval(local_mem_interval, true);
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Prints the provided memory interval.
///
/// If `is_local` is true, the output addresses are formatted as decimal values, otherwise as hex
/// strings.
fn print_interval(mem_interval: Vec<(u32, Option<Felt>)>, is_local: bool) {
    let element_width = mem_interval
        .iter()
        .map(|(_addr, value)| element_printed_width(*value))
        .max()
        .unwrap_or(0) as usize;

    // print the main part of the memory (wihtout the last value)
    for (addr, mem_value) in mem_interval.iter().take(mem_interval.len() - 1) {
        print_mem_address(*addr, *mem_value, false, is_local, element_width)
    }

    // print the last memory value
    if let Some((addr, value)) = mem_interval.last() {
        print_mem_address(*addr, *value, true, is_local, element_width);
    }
}

/// Prints single memory value with its address.
///
/// If `is_local` is true, the output address is formatted as decimal value, otherwise as hex
/// string.
fn print_mem_address(
    addr: u32,
    mem_value: Option<Felt>,
    is_last: bool,
    is_local: bool,
    element_width: usize,
) {
    if let Some(value) = mem_value {
        if is_last {
            if is_local {
                print!("└── {addr:>5}: ");
            } else {
                print!("└── {addr:#010x}: ");
            }
            println!("{:>width$}\n", value.as_canonical_u64(), width = element_width);
        } else {
            if is_local {
                print!("├── {addr:>5}: ");
            } else {
                print!("├── {addr:#010x}: ");
            }
            println!("{:>width$}", value.as_canonical_u64(), width = element_width);
        }
    } else if is_last {
        if is_local {
            println!("└── {addr:>5}: EMPTY\n");
        } else {
            println!("└── {addr:#010x}: EMPTY\n");
        }
    } else if is_local {
        println!("├── {addr:>5}: EMPTY");
    } else {
        println!("├── {addr:#010x}: EMPTY");
    }
}

/// Returns the number of digits required to print the provided element.
fn element_printed_width(element: Option<Felt>) -> u32 {
    if let Some(element) = element {
        element.as_canonical_u64().checked_ilog10().unwrap_or(1) + 1
    } else {
        0
    }
}
