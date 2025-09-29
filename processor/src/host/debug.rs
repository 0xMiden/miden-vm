use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{cmp::min, fmt};

use miden_core::{DebugOptions, stack::MIN_STACK_DEPTH};

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

        let num_items =
            n.map(|n| if n == 0 { stack.len() } else { n as usize }).unwrap_or(stack.len());

        // Determine if we're printing the whole stack or a partial interval
        let is_partial = n.is_some() && n != Some(0) && num_items < stack.len();
        if is_partial {
            writeln!(
                self.writer,
                "Stack state in interval [0, {}] before step {}:",
                num_items - 1,
                process.clk()
            )?;
        } else {
            writeln!(self.writer, "Stack state before step {}:", process.clk())?;
        }

        // Collect stack items for printing
        let mut stack_items = Vec::new();

        // Add actual stack elements
        let num_stack_items = min(num_items, stack.len());
        for (i, element) in stack.iter().enumerate().take(num_stack_items) {
            stack_items.push((i.to_string(), Some(element.to_string())));
        }

        // Add EMPTY slots if requested
        for i in stack.len()..num_items {
            stack_items.push((i.to_string(), None));
        }

        // Calculate remaining overflow items
        let num_remaining = stack.len() - num_stack_items;
        let remaining = if num_stack_items > MIN_STACK_DEPTH && num_remaining > 0 {
            Some(num_remaining)
        } else {
            None
        };

        // Print using the generic interval method
        self.print_interval(stack_items, remaining)?;

        Ok(())
    }

    /// Writes length items from the top of the advice stack. If length is 0 it writes the whole
    /// stack.
    fn print_vm_adv_stack(&mut self, process: &ProcessState, n: u16) -> fmt::Result {
        let stack = process.advice_provider().stack();

        if stack.is_empty() {
            writeln!(self.writer, "Advice Stack empty before step {}.", process.clk())?;
            return Ok(());
        }

        // If n = 0 print the entire stack
        let num_items = if n == 0 {
            stack.len()
        } else {
            min(stack.len(), n as usize)
        };

        let num_remaining = stack.len() - num_items;

        // Determine if we're printing the whole stack or a partial interval
        let is_partial = n != 0 && num_items > 0 && num_items < stack.len();
        if is_partial {
            writeln!(
                self.writer,
                "Advice stack state in interval [0, {}] before step {}:",
                num_items - 1,
                process.clk()
            )?;
        } else {
            writeln!(self.writer, "Advice stack state before step {}:", process.clk())?;
        }

        // Collect advice stack items for printing
        let mut advice_items = Vec::new();

        // Note: `stack` is in reverse order. e.g., `adv_push.1` pushes `stack.last()`.
        // We need to print the top `num_items` from the stack, which are the last `num_items` elements
        // but we want to display them in logical order (index 0 is the top of the stack)

        // Get items from the end of the stack (most recent) going backwards
        let start_idx = num_remaining;
        for (logical_idx, stack_idx) in (start_idx..stack.len()).rev().enumerate() {
            let element = &stack[stack_idx];
            advice_items.push((logical_idx.to_string(), Some(element.to_string())));
        }

        // Calculate remaining items
        let remaining = if num_remaining > 0 { Some(num_remaining) } else { None };

        // Print using the generic interval method
        self.print_interval(advice_items, remaining)?;

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

        let mem_items: Vec<_> = mem
            .iter()
            .map(|(addr, value)| (format!("{addr:#010x}"), Some(value.to_string())))
            .collect();

        self.print_interval(mem_items, None)?;
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
            let mem_items: Vec<_> = mem_interval
                .iter()
                .map(|(addr, value)| {
                    let addr_str = format!("{addr:#010x}");
                    let value_str = value.map(|v| v.to_string());
                    (addr_str, value_str)
                })
                .collect();

            self.print_interval(mem_items, None)
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
            let local_items: Vec<_> = locals
                .iter()
                .map(|(addr, value)| {
                    let addr_str = format!("{}", addr.0);
                    let value_str = value.map(|v| v.to_string());
                    (addr_str, value_str)
                })
                .collect();

            self.print_interval(local_items, None)
        }
    }

    /// Writes a generic interval with proper alignment and optional remaining count.
    ///
    /// Takes a vector of (address_string, optional_value_string) pairs where:
    /// - address_string: The address as a string (not pre-padded)
    /// - optional_value_string: Some(value) or None (prints "EMPTY")
    /// - remaining: Optional count of remaining items to show as "(N remaining elements)"
    fn print_interval(
        &mut self,
        items: Vec<(String, Option<String>)>,
        remaining: Option<usize>,
    ) -> fmt::Result {
        if items.is_empty() && remaining.is_none() {
            return Ok(());
        }

        // Find the maximum address width for proper alignment
        let max_addr_width = items.iter().map(|(addr, _)| addr.len()).max().unwrap_or(0);

        // Collect formatted items
        let mut formatted_items: Vec<String> = items
            .iter()
            .map(|(addr, value_opt)| {
                let value_string = value_opt.as_deref().unwrap_or("EMPTY");
                format!("{addr:>width$}: {value_string}", width = max_addr_width)
            })
            .collect();

        // Add remaining count if specified
        if let Some(count) = remaining {
            formatted_items.push(format!("({} more items)", count));
        }

        // Print using the tree method
        print_tree_list(&mut self.writer, formatted_items)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

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
