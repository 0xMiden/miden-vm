use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use miden_core::Felt;

use crate::{ProcessorState, TraceError, host::handlers::TraceHandler};

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

// DEFAULT TRACE HANDLER IMPLEMENTATION
// ================================================================================================

/// Default trace handler that ignores trace events.
pub struct DefaultTraceHandler<W: fmt::Write + Sync = StdoutWriter> {
    writer: W,
}

impl Default for DefaultTraceHandler<StdoutWriter> {
    fn default() -> Self {
        Self { writer: StdoutWriter }
    }
}

impl<W: fmt::Write + Sync> DefaultTraceHandler<W> {
    /// Creates a new [`DefaultTraceHandler`] with the specified writer.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Returns a reference to the writer for accessing writer-specific methods.
    pub fn writer(&self) -> &W {
        &self.writer
    }
}

impl<W: fmt::Write + Sync> TraceHandler for DefaultTraceHandler<W> {
    fn on_trace(&mut self, _process: &ProcessorState, _trace_id: u32) -> Result<(), TraceError> {
        Ok(())
    }
}

// SHARED PRINTING HELPERS
// ================================================================================================
//
// These functions implement the VM's tree-style debug formatting independently of any host or
// handler, so event-based debugging procedures (e.g. `miden::core::debug`) can reuse it.

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
    if num_items == 0 {
        writeln!(writer, "{label} state in interval [0, 0) before step {clk}:")?;
        return Ok(());
    }

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
    fn write_stack_zero_count_does_not_underflow() {
        let mut out = String::new();
        let stack = [Felt::new_unchecked(9), Felt::new_unchecked(8), Felt::new_unchecked(7)];
        write_stack(&mut out, &stack, Some(0), "Stack", 4u32).unwrap();
        assert_eq!(out, "Stack state in interval [0, 0) before step 4:\n");
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
