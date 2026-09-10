//! Event handlers backing the `miden::core::debug` print-debugging module.
//!
//! Each `miden::core::debug::print_*` procedure emits a well-known event. This module registers a
//! single [`DebugPrinter`] handler for all of those events; when one fires, the handler reads the
//! requested piece of VM state (operand stack, memory, advice stack, or advice map) and prints it
//! using the VM's tree-style debug formatting via [`miden_processor::write_stack`] /
//! [`miden_processor::write_interval`]. A range-based procedure may share an event with its
//! full-state variant when the full-state behavior can be represented as an unbounded range (e.g.
//! the advice stack); memory uses a dedicated full-state event because `print_mem` enumerates its
//! (capped) range while `print_mem_all` lists only initialized cells.
//!
//! These are ordinary `emit` events: they carry no MAST/decorator cost and print whenever the
//! procedure is executed.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::fmt;

use miden_core::{Felt, Word, events::EventName};
use miden_event_handler::{
    AdviceRecorder, EventContext, EventContextError, EventError, EventHandler, NoopHandler,
};
use miden_processor::{StdoutWriter, event::registration, write_interval, write_stack};
use miden_utils_sync::RwLock;

// EVENT NAMES
// ================================================================================================

/// Prints the entire operand stack.
pub const PRINT_STACK_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_stack");
/// Prints memory in the range `[start, end)` of the current context.
pub const PRINT_MEM_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_mem");
/// Prints the entire memory of the current context.
pub const PRINT_MEM_ALL_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_mem_all");
/// Prints the advice stack in the range `[start, end)`.
pub const PRINT_ADV_STACK_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_adv_stack");
/// Prints the full advice map.
pub const PRINT_ADV_MAP_EVENT_NAME: EventName = EventName::new("miden::core::debug::print_adv_map");
/// Looks up a WORD key in the advice map and prints the associated values.
pub const PRINT_ADV_MAP_ITEM_EVENT_NAME: EventName =
    EventName::new("miden::core::debug::print_adv_map_item");

/// Maximum number of addresses an explicit `print_mem` / `print_mem_addr` range may span.
///
/// Guards against a caller accidentally passing an enormous range. Use `print_mem_all` (which has
/// its own event) to print the entire memory of the current context.
const MAX_PRINT_MEM_RANGE: u64 = 1024;

/// Returns the default `(EventName, handler)` pairs for print-style debugging.
///
/// The default set prints operand-stack and memory state to stdout. Advice-stack and advice-map
/// printers are excluded because they may expose witness data.
pub fn default_debug_event_handlers() -> Vec<(EventName, registration::EventHandler)> {
    let printer: registration::EventHandler = DebugPrinter::default().into();
    vec![
        (PRINT_STACK_EVENT_NAME, printer.clone()),
        (PRINT_MEM_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, printer),
    ]
}

/// Returns no-op handlers for every `miden::core::debug` print event.
///
/// Privacy-sensitive hosts can use these to replace the default stdout handlers while still
/// allowing programs that emit debug events to execute.
pub fn noop_debug_event_handlers() -> Vec<(EventName, registration::EventHandler)> {
    let handler: registration::EventHandler = NoopHandler.into();
    vec![
        (PRINT_STACK_EVENT_NAME, handler.clone()),
        (PRINT_MEM_EVENT_NAME, handler.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, handler.clone()),
        (PRINT_ADV_STACK_EVENT_NAME, handler.clone()),
        (PRINT_ADV_MAP_EVENT_NAME, handler.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, handler),
    ]
}

/// Returns the `(EventName, handler)` pairs that back the full `miden::core::debug` module.
///
/// All events share a single [`DebugPrinter`] instance writing to stdout.
pub fn debug_event_handlers() -> Vec<(EventName, registration::EventHandler)> {
    let printer: registration::EventHandler = DebugPrinter::default().into();
    vec![
        (PRINT_STACK_EVENT_NAME, printer.clone()),
        (PRINT_MEM_EVENT_NAME, printer.clone()),
        (PRINT_MEM_ALL_EVENT_NAME, printer.clone()),
        (PRINT_ADV_STACK_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, printer),
    ]
}

/// Returns the opt-in `(EventName, handler)` pairs for advice-backed debug events.
///
/// [`CoreLibrary::handlers`](crate::CoreLibrary::handlers) registers stack and memory debug
/// handlers by default. This helper returns only the advice-stack and advice-map handlers so hosts
/// can extend the core library handlers without duplicate event registrations.
///
/// All returned events share a single [`DebugPrinter`] instance writing to stdout.
pub fn advice_debug_event_handlers() -> Vec<(EventName, registration::EventHandler)> {
    let printer: registration::EventHandler = DebugPrinter::default().into();
    vec![
        (PRINT_ADV_STACK_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_EVENT_NAME, printer.clone()),
        (PRINT_ADV_MAP_ITEM_EVENT_NAME, printer),
    ]
}

// DEBUG PRINTER
// ================================================================================================

/// Handles all `miden::core::debug::print_*` events by printing VM state to its writer.
///
/// The writer is guarded by an [`RwLock`] because [`EventHandler::handle`] takes `&self`. The
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
    fn handle(
        &self,
        context: EventContext,
        _advice: &mut AdviceRecorder<'_>,
    ) -> Result<(), EventError> {
        let id = context.id();
        let mut writer = self.writer.write();
        let w: &mut W = &mut writer;

        if id == PRINT_STACK_EVENT_NAME.to_event_id() {
            let stack = context.stack_snapshot();
            write_stack(w, &stack, None, "Stack", context.clock())?;
        } else if id == PRINT_MEM_EVENT_NAME.to_event_id() {
            let bounds = read_mem_print_range(context)?;
            // Guard against an accidentally huge explicit range.
            if let Some((first, last)) = bounds {
                let len = u64::from(last - first) + 1;
                if len > MAX_PRINT_MEM_RANGE {
                    return Err(format!(
                        "print_mem range length {len} exceeds maximum of {MAX_PRINT_MEM_RANGE}"
                    )
                    .into());
                }
            }
            write_mem_range(w, context, bounds)?;
        } else if id == PRINT_MEM_ALL_EVENT_NAME.to_event_id() {
            write_mem_all(w, context)?;
        } else if id == PRINT_ADV_STACK_EVENT_NAME.to_event_id() {
            let [start, end] = context
                .read_stack_array(0)
                .map(|felt| usize::try_from(felt.as_canonical_u64()).unwrap_or(usize::MAX));
            let adv_stack: Vec<_> = context.advice_stack().iter().copied().collect();
            let slice = slice_range(&adv_stack, start, end);
            write_stack(w, slice, None, "Advice stack", context.clock())?;
        } else if id == PRINT_ADV_MAP_EVENT_NAME.to_event_id() {
            write_adv_map(w, context)?;
        } else if id == PRINT_ADV_MAP_ITEM_EVENT_NAME.to_event_id() {
            write_adv_map_entry(w, context)?;
        }
        // Unknown ids are ignored: the handler is only registered for the events above.

        Ok(())
    }
}

// HELPERS
// ================================================================================================

/// Returns `slice[start..end]`, clamped to the bounds of `slice` and to `start <= end`.
fn slice_range(slice: &[Felt], start: usize, end: usize) -> &[Felt] {
    let len = slice.len();
    let start = start.min(len);
    let end = end.clamp(start, len);
    &slice[start..end]
}

/// Reads a half-open `[start, end)` memory range off the operand stack and returns it as inclusive
/// `(first, last)` `u32` address bounds, or `None` if the range is empty (`start == end`).
///
/// Memory addresses are `u32`, so both bounds are valid `u32` values. The half-open end may be
/// `2^32` (one past the last address) so the cell at `u32::MAX` stays reachable; it folds into an
/// inclusive end of `u32::MAX`.
fn read_mem_print_range(context: EventContext) -> Result<Option<(u32, u32)>, EventContextError> {
    let [start_addr, end_addr] = context.read_stack_array(0).map(|felt| felt.as_canonical_u64());

    if start_addr > u32::MAX as u64 {
        return Err(EventContextError::AddressOutOfBounds { address: start_addr });
    }
    // The exclusive end may be one past the last valid address (`2^32`).
    if end_addr > u32::MAX as u64 + 1 {
        return Err(EventContextError::AddressOutOfBounds { address: end_addr });
    }
    if start_addr > end_addr {
        return Err(EventContextError::InvalidRange { start: start_addr, end: end_addr });
    }

    if start_addr == end_addr {
        Ok(None)
    } else {
        // Subtract in `u64` before the cast, since `end_addr` may be `2^32`; the result is in
        // `[0, u32::MAX]`.
        Ok(Some((start_addr as u32, (end_addr - 1) as u32)))
    }
}

/// Prints every memory cell in the inclusive `[first, last]` bounds for the current context,
/// showing uninitialized cells as `EMPTY`. `None` denotes an empty range.
///
/// The bounds are inclusive so the cell at `u32::MAX` can be printed without the end overflowing
/// `u32`. The caller is responsible for capping the range length (see [`MAX_PRINT_MEM_RANGE`]).
fn write_mem_range<W: fmt::Write>(
    w: &mut W,
    context: EventContext,
    bounds: Option<(u32, u32)>,
) -> fmt::Result {
    let clk = context.clock();
    let scope = if context.in_root_context() { "root" } else { "non-root" };
    let Some((start, end)) = bounds else {
        return writeln!(w, "Memory state before step {clk} for {scope} context: range is empty.");
    };
    writeln!(
        w,
        "Memory state before step {clk} for {scope} context in the range [{start}, {end}]:",
    )?;
    let items: Vec<_> = (start..=end)
        .map(|addr| {
            let value = context
                .memory_value(u64::from(addr))
                .expect("a u32 memory address is always valid")
                .map(|v| v.to_string());
            (format!("{addr:#010x}"), value)
        })
        .collect();
    write_interval(w, items, None)
}

/// Prints all initialized memory cells of the current context.
fn write_mem_all<W: fmt::Write>(w: &mut W, context: EventContext) -> fmt::Result {
    let clk = context.clock();
    let scope = if context.in_root_context() { "root" } else { "non-root" };
    writeln!(w, "Memory state before step {clk} for {scope} context:")?;
    let items: Vec<_> = context
        .memory_snapshot()
        .into_iter()
        .map(|(addr, value)| (format!("{addr:#010x}"), Some(value.to_string())))
        .collect();
    write_interval(w, items, None)
}

/// Prints the full advice map.
fn write_adv_map<W: fmt::Write>(w: &mut W, context: EventContext) -> fmt::Result {
    let clk = context.clock();
    let map = context.advice_map();
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

/// Looks up the WORD key (at stack positions 0..4) in the advice map and prints its values.
fn write_adv_map_entry<W: fmt::Write>(w: &mut W, context: EventContext) -> fmt::Result {
    let key = context.stack_word(0);
    let key_str = format_word(&key);
    let clk = context.clock();
    match context.advice_map().get(&key).map(AsRef::as_ref) {
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

/// Legacy event-only handler list; use `default_debug_event_handlers` for unified delivery.
#[allow(deprecated)] // Legacy facade.
#[deprecated(note = "use default_debug_event_handlers for unified event and trace delivery")]
pub fn default_debug_handlers()
-> Vec<(EventName, alloc::sync::Arc<dyn miden_processor::event::EventHandler>)> {
    super::legacy_handlers(default_debug_event_handlers())
}

/// Legacy event-only handler list; use `noop_debug_event_handlers` for unified delivery.
#[allow(deprecated)] // Legacy facade.
#[deprecated(note = "use noop_debug_event_handlers for unified event and trace delivery")]
pub fn noop_debug_handlers()
-> Vec<(EventName, alloc::sync::Arc<dyn miden_processor::event::EventHandler>)> {
    super::legacy_handlers(noop_debug_event_handlers())
}

/// Legacy event-only handler list; use `debug_event_handlers` for unified delivery.
#[allow(deprecated)] // Legacy facade.
#[deprecated(note = "use debug_event_handlers for unified event and trace delivery")]
pub fn debug_handlers()
-> Vec<(EventName, alloc::sync::Arc<dyn miden_processor::event::EventHandler>)> {
    super::legacy_handlers(debug_event_handlers())
}

/// Legacy event-only handler list; use `advice_debug_event_handlers` for unified delivery.
#[allow(deprecated)] // Legacy facade.
#[deprecated(note = "use advice_debug_event_handlers for unified event and trace delivery")]
pub fn advice_debug_handlers()
-> Vec<(EventName, alloc::sync::Arc<dyn miden_processor::event::EventHandler>)> {
    super::legacy_handlers(advice_debug_event_handlers())
}

// Preserve DebugPrinter's actual base trait implementation without duplicating its rendering.
#[allow(deprecated)] // Legacy compatibility or independent raw inspection.
impl<W: fmt::Write + Send + Sync + 'static> miden_processor::event::EventHandler
    for DebugPrinter<W>
{
    fn on_event(
        &self,
        process: &miden_processor::ProcessorState<'_>,
    ) -> Result<Vec<miden_processor::advice::AdviceMutation>, EventError> {
        miden_processor::event::invoke_legacy_handler(self, process)
    }
}
