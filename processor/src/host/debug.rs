use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, ops::RangeInclusive};

use miden_core::{DebugOptions, FMP_ADDR};

use crate::{DebugHandler, ExecutionError, Felt, ProcessState};

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
            DebugOptions::StackAll => {
                let stack = process.get_stack_state();
                self.print_stack(&stack, None, "Stack", process)
            },
            DebugOptions::StackTop(n) => {
                let stack = process.get_stack_state();
                let count = if n == 0 { None } else { Some(n as usize) };
                self.print_stack(&stack, count, "Stack", process)
            },
            DebugOptions::MemAll => self.print_mem_all(process),
            DebugOptions::MemInterval(n, m) => self.print_mem_interval(process, n..=m),
            DebugOptions::LocalInterval(n, m, num_locals) => {
                self.print_local_interval(process, n..=m, num_locals as u32)
            },
            DebugOptions::AdvStackTop(n) => {
                // Reverse the advice stack so last element becomes index 0
                let stack = process.advice_provider().stack();
                let reversed_stack: Vec<_> = stack.iter().copied().rev().collect();

                let count = if n == 0 { None } else { Some(n as usize) };
                self.print_stack(&reversed_stack, count, "Advice stack", process)
            },
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
    /// Generic stack printing.
    fn print_stack(
        &mut self,
        stack: &[Felt],
        n: Option<usize>,
        stack_type: &str,
        process: &ProcessState,
    ) -> fmt::Result {
        if stack.is_empty() {
            writeln!(self.writer, "{stack_type} empty before step {}.", process.clk())?;
            return Ok(());
        }

        // Determine how many items to show
        let num_items = n.unwrap_or(stack.len());

        // Write header
        let is_partial = num_items < stack.len();
        if is_partial {
            writeln!(
                self.writer,
                "{stack_type} state in interval [0, {}] before step {}:",
                num_items - 1,
                process.clk()
            )?
        } else {
            writeln!(self.writer, "{stack_type} state before step {}:", process.clk())?
        }

        // Build stack items for display
        let mut stack_items = Vec::new();
        for (i, element) in stack.iter().enumerate().take(num_items) {
            stack_items.push((i.to_string(), Some(element.to_string())));
        }
        // Add extra EMPTY slots if requested more than available
        for i in stack.len()..num_items {
            stack_items.push((i.to_string(), None));
        }

        // Calculate remaining items for partial views
        let remaining = if num_items < stack.len() {
            Some(stack.len() - num_items)
        } else {
            None
        };

        self.print_interval(stack_items, remaining)
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
            .into_iter()
            .map(|(addr, value)| (format!("{addr:#010x}"), Some(value.to_string())))
            .collect();

        self.print_interval(mem_items, None)?;
        Ok(())
    }

    /// Writes memory values in the provided addresses interval.
    fn print_mem_interval(
        &mut self,
        process: &ProcessState,
        range: RangeInclusive<u32>,
    ) -> fmt::Result {
        let start = *range.start();
        let end = *range.end();

        if start == end {
            let value = process.get_mem_value(process.ctx(), start);
            let value_str = format_value(value);
            writeln!(
                self.writer,
                "Memory state before step {} for the context {} at address {:#010x}: {value_str}",
                process.clk(),
                process.ctx(),
                start
            )
        } else {
            writeln!(
                self.writer,
                "Memory state before step {} for the context {} in the interval [{}, {}]:",
                process.clk(),
                process.ctx(),
                start,
                end
            )?;
            let mem_items: Vec<_> = range
                .map(|addr| {
                    let value = process.get_mem_value(process.ctx(), addr);
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
        range: RangeInclusive<u16>,
        num_locals: u32,
    ) -> fmt::Result {
        let local_memory_offset = {
            let fmp = process
                .get_mem_value(process.ctx(), FMP_ADDR.as_int() as u32)
                .expect("FMP address is empty");

            fmp.as_int() as u32 - num_locals
        };

        let start = *range.start() as u32;
        let end = *range.end() as u32;

        if start == end {
            let addr = local_memory_offset + start;
            let value = process.get_mem_value(process.ctx(), addr);
            let value_str = format_value(value);

            writeln!(
                self.writer,
                "State of procedure local {start} before step {}: {value_str}",
                process.clk(),
            )
        } else {
            writeln!(
                self.writer,
                "State of procedure locals [{start}, {end}] before step {}:",
                process.clk()
            )?;
            let local_items: Vec<_> = range
                .map(|local_idx| {
                    let addr = local_memory_offset + local_idx as u32;
                    let value = process.get_mem_value(process.ctx(), addr);
                    let addr_str = local_idx.to_string();
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
    /// - remaining: Optional count of remaining items to show as "(N more items)"
    fn print_interval(
        &mut self,
        items: Vec<(String, Option<String>)>,
        remaining: Option<usize>,
    ) -> fmt::Result {
        // Find the maximum address width for proper alignment
        let max_addr_width = items.iter().map(|(addr, _)| addr.len()).max().unwrap_or(0);

        // Collect formatted items
        let mut formatted_items: Vec<String> = items
            .into_iter()
            .map(|(addr, value_opt)| {
                let value_string = format_value(value_opt);
                format!("{addr:>width$}: {value_string}", width = max_addr_width)
            })
            .collect();

        // Add remaining count if specified
        if let Some(count) = remaining {
            formatted_items.push(format!("({count} more items)"));
        }

        // Prints a list of items with proper tree-style indentation.
        // All items except the last are prefixed with "├── ", and the last item with "└── ".
        if let Some((last, front)) = formatted_items.split_last() {
            // Print all items except the last with "├── " prefix
            for item in front {
                writeln!(self.writer, "├── {item}")?;
            }
            // Print the last item with "└── " prefix
            writeln!(self.writer, "└── {last}")?;
        }

        Ok(())
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// Formats a value as a string, using "EMPTY" for None values.
fn format_value<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "EMPTY".to_string())
}
