use alloc::vec::Vec;
use std::{cmp::min, println, string::ToString};

use vm_core::{DebugOptions, Felt};

use crate::{MemoryAddress, ProcessState};

// DEBUG HANDLER
// ================================================================================================

/// Prints the info about the VM state specified by the provided options to stdout.
pub fn print_debug_info(process: &ProcessState, options: &DebugOptions) {
    match *options {
        DebugOptions::StackAll => {
            print_vm_stack(process, None);
        },
        DebugOptions::StackTop(n) => {
            print_vm_stack(process, Some(n));
        },
        DebugOptions::MemAll => {
            print_mem_all(process);
        },
        DebugOptions::MemInterval(n, m) => {
            print_mem_interval(process, n, m);
        },
        DebugOptions::LocalInterval(n, m, num_locals) => {
            print_local_interval(process, n, m, num_locals as u32);
        },
        DebugOptions::AdvStackTop(n) => {
            print_vm_adv_stack(process, n);
        },
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Prints the number of stack items specified by `n` if it is provided, otherwise prints
/// the whole stack.
fn print_vm_stack(process: &ProcessState, n: Option<u8>) {
    let stack = process.advice_provider().stack();

    // if n is empty, print the entire stack
    let num_items = if let Some(n) = n {
        min(stack.len(), n as usize)
    } else {
        stack.len()
    };

    let stack = &stack[..num_items];

    if let Some((last, front)) = stack.split_last() {
        // print all items except for the last one
        println!("Stack state before step {}:", process.clk());
        for (i, element) in front.iter().enumerate() {
            println!("├── {i:>2}: {element}");
        }

        // print the last item, and in case the stack has more items, print the total number of
        // un-printed items
        let i = num_items - 1;
        println!("└── {i:>2}: {last}\n");
        println!("└── ({} more items)\n", stack.len() - num_items);
    } else {
        println!("Stack empty before step {}.", process.clk());
    }
}

/// Prints length items from the top of the  advice stack. If length is 0 it returns the whole
/// stack.
fn print_vm_adv_stack(process: &ProcessState, n: u16) {
    let stack = process.advice_provider().stack();

    // If n = 0 print the entire stack
    let num_items = if n == 0 {
        stack.len()
    } else {
        min(stack.len(), n as usize)
    };

    let stack = &stack[..num_items];

    if let Some((last, front)) = stack.split_last() {
        // print all items except for the last one
        println!("Advice Stack state before step {}:", process.clk());
        for (i, element) in front.iter().enumerate() {
            println!("├── {i:>2}: {element}");
        }

        let i = num_items - 1;
        println!("└── {i:>2}: {last}\n");
    } else {
        println!("Advice Stack empty before step {}.", process.clk());
    }
}

/// Prints the whole memory state at the cycle `clk` in context `ctx`.
fn print_mem_all(process: &ProcessState) {
    let mem = process.get_mem_state(process.ctx());
    let element_width = mem
        .iter()
        .map(|(_addr, value)| element_printed_width(*value))
        .max()
        .unwrap_or(0);

    println!("Memory state before step {} for the context {}:", process.clk(), process.ctx());

    if let Some(((last_addr, last_value), front)) = mem.split_last() {
        // print the main part of the memory (wihtout the last value)
        for (addr, value) in front.iter() {
            print_mem_address(*addr, Some(*value), false, false, element_width);
        }

        // print the last memory value
        print_mem_address(*last_addr, Some(*last_value), true, false, element_width);
    }
}

/// Prints memory values in the provided addresses interval.
fn print_mem_interval(process: &ProcessState, n: u32, m: u32) {
    let addr_range = n..m + 1;
    let mem_interval: Vec<_> = addr_range
        .map(|addr| (MemoryAddress(addr), process.get_mem_value(process.ctx(), addr)))
        .collect();

    if n == m {
        println!(
            "Memory state before step {} for the context {} at address {}:",
            process.clk(),
            process.ctx(),
            n
        )
    } else {
        println!(
            "Memory state before step {} for the context {} in the interval [{}, {}]:",
            process.clk(),
            process.ctx(),
            n,
            m
        )
    };

    print_interval(mem_interval, false);
}

/// Prints locals in provided indexes interval.
///
/// The interval given is inclusive on *both* ends.
fn print_local_interval(process: &ProcessState, start: u16, end: u16, num_locals: u32) {
    let local_memory_offset = process.fmp() as u32 - num_locals;

    // Account for a case where start is 0 and end is 2^16. In that case we should simply print
    // all available locals.
    let locals_range = if start == 0 && end == u16::MAX {
        0..num_locals - 1
    } else {
        start as u32..end as u32
    };

    let locals: Vec<_> = locals_range
        .map(|local_idx| {
            let addr = local_memory_offset + local_idx;
            let value = process.get_mem_value(process.ctx(), addr);
            (MemoryAddress(local_idx), value)
        })
        .collect();

    if start != end {
        println!("State of procedure locals [{start}, {end}] before step {}:", process.clk());
    } else {
        println!("State of procedure local {start} before step {}:", process.clk());
    }
    print_interval(locals, true);
}

// HELPER FUNCTIONS
// ================================================================================================

/// Prints the provided memory interval.
///
/// If `is_local` is true, the output addresses are formatted as decimal values, otherwise as hex
/// strings.
fn print_interval(mem_interval: Vec<(MemoryAddress, Option<Felt>)>, is_local: bool) {
    let element_width = mem_interval
        .iter()
        .filter_map(|(_addr, value)| value.map(element_printed_width))
        .max()
        .unwrap_or(0);

    if let Some(((last_addr, last_value), front_elements)) = mem_interval.split_last() {
        // print the main part of the memory (wihtout the last value)
        for (addr, mem_value) in front_elements {
            print_mem_address(*addr, *mem_value, false, is_local, element_width)
        }

        // print the last memory value
        print_mem_address(*last_addr, *last_value, true, is_local, element_width);
    }
}

/// Prints single memory value with its address.
///
/// If `is_local` is true, the output address is formatted as decimal value, otherwise as hex
/// string.
fn print_mem_address(
    addr: MemoryAddress,
    mem_value: Option<Felt>,
    is_last: bool,
    is_local: bool,
    element_width: u32,
) {
    let value_string = if let Some(value) = mem_value {
        format!("{:>width$}", value, width = element_width as usize)
    } else {
        "EMPTY".to_string()
    };

    let addr_string = if is_local {
        format!("{addr:>5}")
    } else {
        format!("{addr:#010x}")
    };

    if is_last {
        println!("└── {addr_string}: {value_string}");
    } else {
        println!("├── {addr_string}: {value_string}");
    }
}

/// Returns the number of digits required to print the provided element.
fn element_printed_width(element: Felt) -> u32 {
    element.as_int().checked_ilog10().unwrap_or(1) + 1
}
