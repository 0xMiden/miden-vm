use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::min, fmt};

use miden_core::{DebugOptions, Felt, stack::MIN_STACK_DEPTH};

use crate::{DebugHandler, ExecutionError, MemoryAddress, ProcessState};

// WRITER IMPLEMENTATIONS
// ================================================================================================

/// A wrapper that implements [`fmt::Write`] for `stdout` when the `std` feature is enabled.
#[derive(Default)]
pub struct StdoutWriter;

impl fmt::Write for StdoutWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        #[cfg(feature = "std")]
        std::print!("{}", s);
        Ok(())
    }
}

// DEFAULT DEBUG HANDLER IMPLEMENTATION
// ================================================================================================

/// Default implementation of [`DebugHandler`] that writes debug information to `stdout` when
/// available.
pub struct DefaultDebugHandler<W: fmt::Write + Sync = StdoutWriter> {
    writer: W,
}

impl Default for DefaultDebugHandler<StdoutWriter> {
    fn default() -> Self {
        Self { writer: StdoutWriter }
    }
}

impl<W: fmt::Write + Sync> DefaultDebugHandler<W> {
    /// Creates a new [`DefaultDebugHandler`] with the specified writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Returns a reference to the writer for accessing writer-specific methods.
    pub fn writer(&self) -> &W {
        &self.writer
    }
}

impl<W: fmt::Write + Sync> DebugHandler for DefaultDebugHandler<W> {
    fn on_debug(
        &mut self,
        process: &ProcessState,
        options: &DebugOptions,
    ) -> Result<(), ExecutionError> {
        let _ = match *options {
            DebugOptions::StackAll => self.print_vm_stack(process, None),
            DebugOptions::StackTop(n) => self.print_vm_stack(process, Some(n)),
            DebugOptions::MemAll => self.print_mem_all(process),
            DebugOptions::MemInterval(n, m) => self.print_mem_interval(process, n, m),
            DebugOptions::LocalInterval(n, m, num_locals) => {
                self.print_local_interval(process, n, m, num_locals as u32)
            },
            DebugOptions::AdvStackTop(n) => self.print_vm_adv_stack(process, n),
        };
        Ok(())
    }

    fn on_trace(&mut self, process: &ProcessState, trace_id: u32) -> Result<(), ExecutionError> {
        let _ = writeln!(
            self.writer,
            "Trace with id {} emitted at step {} in context {}",
            trace_id,
            process.clk(),
            process.ctx()
        );
        Ok(())
    }
}

impl<W: fmt::Write + Sync> DefaultDebugHandler<W> {
    /// Writes the number of stack items specified by `n` if it is provided, otherwise writes
    /// the whole stack.
    fn print_vm_stack(&mut self, process: &ProcessState, n: Option<u8>) -> fmt::Result {
        let stack = process.get_stack_state();

        let num_items = n.map(|n| n as usize).unwrap_or(stack.len());

        writeln!(self.writer, "Stack state before step {}:", process.clk())?;

        // Collect all items to print
        let mut all_items = Vec::new();

        // Add actual stack elements
        let num_stack_items = min(num_items, stack.len());
        for (i, element) in stack.iter().enumerate().take(num_stack_items) {
            all_items.push(format!("{i:>2}: {element}"));
        }

        // Add overflow message if needed
        let num_remaining = stack.len() - num_stack_items;
        if num_stack_items > MIN_STACK_DEPTH && num_remaining > 0 {
            all_items.push(format!("({} more items)", num_remaining));
        }

        // Add EMPTY slots if requested
        for i in stack.len()..num_items {
            all_items.push(format!("{i:>2}: EMPTY"));
        }

        // Print all items using the tree method
        print_tree_list(&mut self.writer, all_items)?;

        Ok(())
    }

    /// Writes length items from the top of the advice stack. If length is 0 it writes the whole
    /// stack.
    fn print_vm_adv_stack(&mut self, process: &ProcessState, n: u16) -> fmt::Result {
        let stack = process.advice_provider().stack();

        // If n = 0 print the entire stack
        let num_items = if n == 0 {
            stack.len()
        } else {
            min(stack.len(), n as usize)
        };

        let num_remaining = stack.len() - num_items;

        // get the top `num_items`
        let (_stack_bottom_slice, stack_top_slice) = stack.split_at(num_remaining);

        // Note: `stack` is in reverse order. e.g., `adv_push.1` pushes `stack.last()`.
        if let Some((bottom, top_slice)) = stack_top_slice.split_first() {
            writeln!(self.writer, "Advice Stack state before step {}:", process.clk())?;

            // Collect all items to print
            let mut all_items = Vec::new();

            // Add top elements (reversed)
            for (i, element) in top_slice.iter().rev().enumerate() {
                all_items.push(format!("{i:>2}: {element}"));
            }

            // Add bottom element
            let i = num_items - 1;
            all_items.push(format!("{i:>2}: {bottom}"));

            // Add overflow message if needed
            if num_remaining > 0 {
                all_items.push(format!("({} more items)", num_remaining));
            }

            // Print all items using the tree method
            print_tree_list(&mut self.writer, all_items)?;
        } else {
            writeln!(self.writer, "Advice Stack empty before step {}.", process.clk())?;
        }
        Ok(())
    }

    /// Writes the whole memory state at the cycle `clk` in context `ctx`.
    fn print_mem_all(&mut self, process: &ProcessState) -> fmt::Result {
        let mem = process.get_mem_state(process.ctx());

        writeln!(
            self.writer,
            "Memory state before step {} for the context {}:",
            process.clk(),
            process.ctx()
        )?;

        let mem_interval: Vec<_> = mem.iter().map(|(addr, value)| (*addr, Some(*value))).collect();

        self.print_interval(mem_interval, false)?;
        Ok(())
    }

    /// Writes memory values in the provided addresses interval.
    fn print_mem_interval(&mut self, process: &ProcessState, n: u32, m: u32) -> fmt::Result {
        let addr_range = n..m + 1;
        let mem_interval: Vec<_> = addr_range
            .map(|addr| (MemoryAddress(addr), process.get_mem_value(process.ctx(), addr)))
            .collect();

        if n == m {
            debug_assert_eq!(mem_interval.len(), 1);
            let (addr, value) = mem_interval[0];
            let value_str = if let Some(value) = value {
                value.to_string()
            } else {
                "EMPTY".to_string()
            };
            writeln!(
                self.writer,
                "Memory state before step {} for the context {} at address {addr:#010x}: {value_str}",
                process.clk(),
                process.ctx(),
            )
        } else {
            writeln!(
                self.writer,
                "Memory state before step {} for the context {} in the interval [{}, {}]:",
                process.clk(),
                process.ctx(),
                n,
                m
            )?;
            self.print_interval(mem_interval, false)
        }
    }

    /// Writes locals in provided indexes interval.
    ///
    /// The interval given is inclusive on *both* ends.
    fn print_local_interval(
        &mut self,
        process: &ProcessState,
        start: u16,
        end: u16,
        num_locals: u32,
    ) -> fmt::Result {
        let local_memory_offset = process.fmp() as u32 - num_locals;

        let locals: Vec<_> = (start..=end)
            .map(|local_idx| {
                let addr = local_memory_offset + local_idx as u32;
                let value = process.get_mem_value(process.ctx(), addr);
                (MemoryAddress(local_idx as u32), value)
            })
            .collect();

        if start == end {
            debug_assert_eq!(locals.len(), 1);
            let (addr, value) = locals[0];
            let value_str = if let Some(value) = value {
                value.to_string()
            } else {
                "EMPTY".to_string()
            };

            writeln!(
                self.writer,
                "State of procedure local {addr} before step {}: {value_str}",
                process.clk(),
            )
        } else {
            writeln!(
                self.writer,
                "State of procedure locals [{start}, {end}] before step {}:",
                process.clk()
            )?;
            self.print_interval(locals, true)
        }
    }

    /// Writes the provided memory interval.
    ///
    /// If `is_local` is true, the output addresses are formatted as decimal values, otherwise as
    /// hex strings.
    fn print_interval(
        &mut self,
        mem_interval: Vec<(MemoryAddress, Option<Felt>)>,
        is_local: bool,
    ) -> fmt::Result {
        let element_width = mem_interval
            .iter()
            .filter_map(|(_addr, value)| value.map(element_printed_width))
            .max()
            .unwrap_or(0);

        // Collect formatted items
        let formatted_items: Vec<String> = mem_interval
            .iter()
            .map(|(addr, mem_value)| {
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

                format!("{addr_string}: {value_string}")
            })
            .collect();

        // Print using the tree method
        print_tree_list(&mut self.writer, formatted_items)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Returns the number of digits required to print the provided element.
fn element_printed_width(element: Felt) -> u32 {
    element.as_int().checked_ilog10().unwrap_or(1) + 1
}

/// Prints a list of items with proper tree-style indentation.
/// All items except the last are prefixed with "├── ", and the last item with "└── ".
fn print_tree_list<W: fmt::Write + Sync>(writer: &mut W, items: Vec<String>) -> fmt::Result {
    if let Some((last, front)) = items.split_last() {
        // Print all items except the last with "├── " prefix
        for item in front {
            writeln!(writer, "├── {}", item)?;
        }
        // Print the last item with "└── " prefix
        writeln!(writer, "└── {}", last)?;
    }

    Ok(())
}
