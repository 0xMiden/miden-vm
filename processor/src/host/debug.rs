use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::{fmt, ops::RangeInclusive};

use miden_core::{FMP_ADDR, Felt, operations::DebugOptions};

use crate::{DebugError, ProcessorState, host::handlers::DebugHandler};

// WRITER IMPLEMENTATIONS
// ================================================================================================

/// A wrapper that implements [`fmt::Write`] for `stdout` when the `std` feature is enabled.
#[derive(Default)]
pub struct StdoutWriter;

impl fmt::Write for StdoutWriter {
    fn write_str(&mut self, _s: &str) -> fmt::Result {
        #[cfg(feature = "std")]
        std::print!("{_s}");
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
        process: &ProcessorState,
        options: &DebugOptions,
    ) -> Result<(), DebugError> {
        match *options {
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
                // .stack() already returns elements from top (index 0) to bottom
                let stack = process.advice_provider().stack();
                let count = if n == 0 { None } else { Some(n as usize) };
                self.print_stack(&stack, count, "Advice stack", process)
            },
        }
        .map_err(DebugError::from)
    }
}

impl<W: fmt::Write + Sync> DefaultDebugHandler<W> {
    /// Generic stack printing.
    fn print_stack(
        &mut self,
        stack: &[Felt],
        n: Option<usize>,
        stack_type: &str,
        process: &ProcessorState,
    ) -> fmt::Result {
        write_stack(&mut self.writer, stack, n, stack_type, process.clock())
    }

    /// Writes the whole memory state at the cycle `clk` in context `ctx`.
    fn print_mem_all(&mut self, process: &ProcessorState) -> fmt::Result {
        let mem = process.get_mem_state(process.ctx());

        writeln!(
            self.writer,
            "Memory state before step {} for the context {}:",
            process.clock(),
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
        process: &ProcessorState,
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
                process.clock(),
                process.ctx(),
                start
            )
        } else {
            writeln!(
                self.writer,
                "Memory state before step {} for the context {} in the interval [{}, {}]:",
                process.clock(),
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
        process: &ProcessorState,
        range: RangeInclusive<u16>,
        num_locals: u32,
    ) -> fmt::Result {
        let local_memory_offset = {
            let fmp = process
                .get_mem_value(process.ctx(), FMP_ADDR.as_canonical_u64() as u32)
                .expect("FMP address is empty");

            fmp.as_canonical_u64() as u32 - num_locals
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
                process.clock(),
            )
        } else {
            writeln!(
                self.writer,
                "State of procedure locals [{start}, {end}] before step {}:",
                process.clock()
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
    fn print_interval(
        &mut self,
        items: Vec<(String, Option<String>)>,
        remaining: Option<usize>,
    ) -> fmt::Result {
        write_interval(&mut self.writer, items, remaining)
    }
}

// SHARED PRINTING HELPERS
// ================================================================================================
//
// These functions implement the VM's tree-style debug formatting independently of any host or
// handler, so that both [`DefaultDebugHandler`] (for `debug.*` decorators) and event-based
// debugging procedures (e.g. `miden::core::debug`) produce identical output.

/// Writes a stack-like list of elements (operand or advice stack) in the VM's debug format.
///
/// `stack` is ordered top-first. `n` is the number of items to show; `None` shows all of them.
/// `label` is the human-readable name of the stack (e.g. `"Stack"` or `"Advice stack"`), and
/// `clk` is the clock cycle reported in the header.
pub fn write_stack<W: fmt::Write>(
    writer: &mut W,
    stack: &[Felt],
    n: Option<usize>,
    label: &str,
    clk: impl fmt::Display,
) -> fmt::Result {
    if stack.is_empty() {
        writeln!(writer, "{label} empty before step {clk}.")?;
        return Ok(());
    }

    // Determine how many items to show
    let num_items = n.unwrap_or(stack.len());

    // Write header
    let is_partial = num_items < stack.len();
    if is_partial {
        writeln!(writer, "{label} state in interval [0, {}] before step {clk}:", num_items - 1)?
    } else {
        writeln!(writer, "{label} state before step {clk}:")?
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

    write_interval(writer, stack_items, remaining)
}

/// Writes a generic interval with proper alignment and optional remaining count.
///
/// Takes a vector of (address_string, optional_value_string) pairs where:
/// - address_string: The address as a string (not pre-padded)
/// - optional_value_string: Some(value) or None (prints "EMPTY")
/// - remaining: Optional count of remaining items to show as "(N more items)"
pub fn write_interval<W: fmt::Write>(
    writer: &mut W,
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
            format!("{addr:>max_addr_width$}: {value_string}")
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
            writeln!(writer, "├── {item}")?;
        }
        // Print the last item with "└── " prefix
        writeln!(writer, "└── {last}")?;
    }

    Ok(())
}

// HELPER FUNCTIONS
// ================================================================================================

/// Formats a value as a string, using "EMPTY" for None values.
pub fn format_value<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "EMPTY".to_string())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{string::String, vec};

    use miden_core::Felt;

    use super::{format_value, write_interval, write_stack};

    #[test]
    fn write_stack_full_uses_tree_style() {
        let mut out = String::new();
        let stack = [Felt::new_unchecked(3), Felt::new_unchecked(2), Felt::new_unchecked(1)];
        write_stack(&mut out, &stack, None, "Stack", 0u32).unwrap();
        assert_eq!(out, "Stack state before step 0:\n├── 0: 3\n├── 1: 2\n└── 2: 1\n");
    }

    #[test]
    fn write_stack_partial_shows_remaining() {
        let mut out = String::new();
        let stack = [Felt::new_unchecked(9), Felt::new_unchecked(8), Felt::new_unchecked(7)];
        write_stack(&mut out, &stack, Some(2), "Stack", 4u32).unwrap();
        assert_eq!(
            out,
            "Stack state in interval [0, 1] before step 4:\n├── 0: 9\n├── 1: 8\n└── (1 more items)\n"
        );
    }

    #[test]
    fn write_interval_marks_empty_slots() {
        let mut out = String::new();
        let items = vec![("0".into(), Some("9".into())), ("1".into(), None)];
        write_interval(&mut out, items, None).unwrap();
        assert_eq!(out, "├── 0: 9\n└── 1: EMPTY\n");
    }

    #[test]
    fn format_value_uses_empty_for_none() {
        assert_eq!(format_value::<&str>(None), "EMPTY");
        assert_eq!(format_value(Some(5)), "5");
    }
}
