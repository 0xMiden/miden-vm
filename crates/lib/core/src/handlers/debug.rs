//! Event handlers backing the `miden::core::debug` print-debugging module.
//!
//! Each `miden::core::debug::print_*` procedure emits a well-known event. This module registers a
//! single [`DebugPrinter`] handler for all of those events; when one fires, the handler reads the
//! requested piece of VM state (operand stack, memory, advice stack, or advice map) and prints it
//! using the VM's tree-style debug formatting (shared with the `debug.*` decorators via
//! [`miden_processor::write_stack`] / [`miden_processor::write_interval`]). Range-based procedures
//! may share events with their full-state variants when the full-state behavior can be represented
//! as an unbounded range.
//!
//! Unlike the `debug.*` decorators, these are ordinary `emit` events: they carry no MAST/decorator
//! cost and print whenever the procedure is executed, regardless of whether the program was
//! assembled in debug mode.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::fmt;

use miden_core::{Felt, Word};
use miden_processor::{
    ProcessorState, StdoutWriter,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventId, EventName},
    write_interval, write_stack,
};
use miden_utils_sync::RwLock;

// EVENT NAMES
// ================================================================================================

/// Prints the entire operand stack (drop-in replacement for the `debug.stack` decorator).
pub const PRINT_STACK_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_stack");
/// Prints memory in the range `[start, end)` of the current context.
pub const PRINT_MEM_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_mem");
/// Prints the value of a single memory cell of the current context.
pub const PRINT_MEM_ADDR_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_mem_addr");
/// Prints the entire memory of the current context.
pub const PRINT_MEM_ALL_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_mem_all");
/// Prints the advice stack in the range `[start, end)`.
pub const PRINT_ADV_STACK_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_adv_stack");
/// Prints the full advice map.
pub const PRINT_ADV_MAP_ALL_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_adv_map_all");
/// Looks up a WORD key in the advice map and prints the associated values.
pub const PRINT_ADV_MAP_ITEM_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_adv_map_item");

/// Returns the default `(EventName, handler)` pairs for print-style debugging.
///
/// The default set prints operand-stack and memory state to stdout. Advice-stack and advice-map
/// printers are excluded because they may expose witness data.
pub fn default_debug_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
    let printer: Arc<dyn EventHandler> = Arc::new(DebugPrinter::default());
    vec![
        (PRINT_STACK_EVENT_NAME, printer.clone()),
        (PRINT_MEM_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ADDR_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, printer),
    ]
}

/// Returns no-op handlers for every `miden::core::debug` print event.
///
/// Privacy-sensitive hosts can use these to replace the default stdout handlers while still
/// allowing programs that emit debug events to execute.
pub fn noop_debug_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
    let handler: Arc<dyn EventHandler> = Arc::new(NoopDebugHandler);
    vec![
        (PRINT_STACK_EVENT_NAME, handler.clone()),
        (PRINT_MEM_EVENT_NAME, handler.clone()),
        (PRINT_MEM_ADDR_EVENT_NAME, handler.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, handler.clone()),
        (PRINT_ADV_STACK_EVENT_NAME, handler.clone()),
        (PRINT_ADV_MAP_ALL_EVENT_NAME, handler.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, handler),
    ]
}

/// Returns the `(EventName, handler)` pairs that back the full `miden::core::debug` module.
///
/// All events share a single [`DebugPrinter`] instance writing to stdout.
pub fn debug_handlers() -> Vec<(EventName, Arc<dyn EventHandler>)> {
    let printer: Arc<dyn EventHandler> = Arc::new(DebugPrinter::default());
    vec![
        (PRINT_STACK_EVENT_NAME, printer.clone()),
        (PRINT_MEM_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ADDR_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, printer.clone()),
        (PRINT_ADV_STACK_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_ALL_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, printer),
    ]
}

// DEBUG PRINTER
// ================================================================================================

/// Handles all `miden::core::debug::print_*` events by printing VM state to its writer.
///
/// The writer is guarded by an [`RwLock`] because [`EventHandler::on_event`] takes `&self`. The
/// default writer prints to stdout (under the `std` feature); a custom writer (e.g. an in-memory
/// buffer) can be supplied via [`DebugPrinter::new`] for testing.
pub struct DebugPrinter<W: fmt::Write + Send + Sync = StdoutWriter> {
    writer: RwLock<W>,
}

impl Default for DebugPrinter<StdoutWriter> {
    fn default() -> Self {
        Self { writer: RwLock::new(StdoutWriter) }
    }
}

impl<W: fmt::Write + Send + Sync> DebugPrinter<W> {
    /// Creates a new [`DebugPrinter`] writing to the provided writer.
    pub fn new(writer: W) -> Self {
        Self { writer: RwLock::new(writer) }
    }
}

impl<W: fmt::Write + Send + Sync + 'static> EventHandler for DebugPrinter<W> {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        // The event id sits at the top of the stack (position 0); the procedure's arguments, if
        // any, are immediately below it.
        let id = EventId::from_felt(process.get_stack_item(0));
        let mut writer = self.writer.write();
        let w: &mut W = &mut writer;

        if id == PRINT_STACK_EVENT_NAME.to_event_id() {
            // Skip position 0 (the event id) so only the user's operand stack is shown. Print the
            // entire stack (no cap) to mirror the `debug.stack` decorator
            // (`DebugOptions::StackAll`).
            let stack = process.get_stack_state();
            let operand_stack = stack.get(1..).unwrap_or(&[]);
            write_stack(w, operand_stack, None, "Stack", process.clock())?;
        } else if id == PRINT_MEM_EVENT_NAME.to_event_id() {
            let range = process.get_mem_addr_range(1, 2)?;
            write_mem_range(w, process, range)?;
        } else if id == PRINT_MEM_ADDR_EVENT_NAME.to_event_id() {
            // Read the address at position 1 as a zero-length range: this validates the u32 bound
            // the same way `print_mem` does (rejecting out-of-bounds addresses) and yields the
            // single address to print.
            let addr = process.get_mem_addr_range(1, 1)?.start;
            write_mem_addr(w, process, addr)?;
        } else if id == PRINT_MEM_ALL_EVENT_NAME.to_event_id() {
            write_mem_all(w, process)?;
        } else if id == PRINT_ADV_STACK_EVENT_NAME.to_event_id() {
            let start = stack_item_as_usize(process, 1);
            let end = stack_item_as_usize(process, 2);
            let adv_stack = process.advice_provider().stack();
            let slice = slice_range(&adv_stack, start, end);
            write_stack(w, slice, None, "Advice stack", process.clock())?;
        } else if id == PRINT_ADV_MAP_ALL_EVENT_NAME.to_event_id() {
            write_adv_map(w, process)?;
        } else if id == PRINT_ADV_MAP_ITEM_EVENT_NAME.to_event_id() {
            write_adv_map_entry(w, process)?;
        }
        // Unknown ids are ignored: the handler is only registered for the events above.

        Ok(Vec::new())
    }
}

struct NoopDebugHandler;

impl EventHandler for NoopDebugHandler {
    fn on_event(&self, _process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        Ok(Vec::new())
    }
}

// HELPERS
// ================================================================================================

/// Reads the element at `pos` on the operand stack as a `usize` (saturating).
fn stack_item_as_usize(process: &ProcessorState, pos: usize) -> usize {
    usize::try_from(process.get_stack_item(pos).as_canonical_u64()).unwrap_or(usize::MAX)
}

/// Returns `slice[start..end]`, clamped to the bounds of `slice` and to `start <= end`.
fn slice_range(slice: &[Felt], start: usize, end: usize) -> &[Felt] {
    let len = slice.len();
    let start = start.min(len);
    let end = end.clamp(start, len);
    &slice[start..end]
}

/// Prints memory in the range `[start, end)` of the current context.
fn write_mem_range<W: fmt::Write>(
    w: &mut W,
    process: &ProcessorState,
    range: core::ops::Range<u32>,
) -> fmt::Result {
    let (ctx, clk) = (process.ctx(), process.clock());
    if range.is_empty() {
        return writeln!(
            w,
            "Memory state before step {clk} for context {ctx}: range [{}, {}) is empty.",
            range.start, range.end
        );
    }
    writeln!(
        w,
        "Memory state before step {clk} for context {ctx} in the range [{}, {}):",
        range.start, range.end
    )?;
    let items: Vec<_> = range
        .map(|addr| {
            let value = process.get_mem_value(ctx, addr).map(|v| v.to_string());
            (format!("{addr:#010x}"), value)
        })
        .collect();
    write_interval(w, items, None)
}

/// Prints the value of the single memory cell at `addr` in the current context.
fn write_mem_addr<W: fmt::Write>(w: &mut W, process: &ProcessorState, addr: u32) -> fmt::Result {
    let (ctx, clk) = (process.ctx(), process.clock());
    match process.get_mem_value(ctx, addr) {
        Some(value) => {
            writeln!(w, "Memory value at {addr:#010x} before step {clk} for context {ctx}: {value}")
        },
        None => writeln!(
            w,
            "Memory at {addr:#010x} before step {clk} for context {ctx} is uninitialized."
        ),
    }
}

/// Prints the full memory of the current context.
fn write_mem_all<W: fmt::Write>(w: &mut W, process: &ProcessorState) -> fmt::Result {
    let (ctx, clk) = (process.ctx(), process.clock());
    writeln!(w, "Memory state before step {clk} for context {ctx}:")?;
    let items: Vec<_> = process
        .get_mem_state(ctx)
        .into_iter()
        .map(|(addr, value)| (format!("{addr:#010x}"), Some(value.to_string())))
        .collect();
    write_interval(w, items, None)
}

/// Prints the full advice map.
fn write_adv_map<W: fmt::Write>(w: &mut W, process: &ProcessorState) -> fmt::Result {
    let clk = process.clock();
    let map = process.advice_provider().map();
    if map.is_empty() {
        return writeln!(w, "Advice map before step {clk}: empty.");
    }

    writeln!(w, "Advice map before step {clk}:")?;
    let items: Vec<_> = map
        .iter()
        .map(|(key, values)| (format_word(key), Some(format_felt_slice(values))))
        .collect();
    write_interval(w, items, None)
}

/// Looks up the WORD key (at stack positions 1..5) in the advice map and prints its values.
fn write_adv_map_entry<W: fmt::Write>(w: &mut W, process: &ProcessorState) -> fmt::Result {
    let key = process.get_stack_word(1);
    let key_str = format_word(&key);
    let clk = process.clock();
    match process.advice_provider().get_mapped_values(&key) {
        Some(values) => {
            writeln!(w, "Advice map entry for key {key_str} before step {clk}:")?;
            let items: Vec<_> = values
                .iter()
                .enumerate()
                .map(|(i, v)| (i.to_string(), Some(v.to_string())))
                .collect();
            write_interval(w, items, None)
        },
        None => writeln!(w, "No advice map entry for key {key_str} before step {clk}."),
    }
}

fn format_word(word: &Word) -> String {
    format!("[{}, {}, {}, {}]", word[0], word[1], word[2], word[3])
}

fn format_felt_slice(values: &[Felt]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&value.to_string());
    }
    out.push(']');
    out
}
