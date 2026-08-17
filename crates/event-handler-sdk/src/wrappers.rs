//! Safe wrappers over the raw host imports.

use miden_event_handler_abi::{RawFelt, RawMerkleNode, RawWord, Status, guest};

/// Decodes a raw status code; an unknown code ends the handler.
fn status(raw: i32) -> Status {
    match Status::from_raw(raw) {
        Some(status) => status,
        None => fail("host returned an unknown status code"),
    }
}

// QUERIES
// ================================================================================================

/// Returns the depth of the operand stack.
pub fn stack_depth() -> u32 {
    unsafe { guest::stack_depth() }
}

/// Returns the operand-stack element at `pos`. Position `0` holds the event ID; positions past
/// the stack depth read as zero.
pub fn stack_get(pos: u32) -> RawFelt {
    RawFelt::new(unsafe { guest::stack_get(pos) })
}

/// Reads the `out.len()` operand-stack elements at positions `start_pos..start_pos + out.len()`,
/// ordered from the top of the stack down. Positions past the stack depth read as zero.
pub fn stack_read(start_pos: u32, out: &mut [RawFelt]) {
    unsafe { guest::stack_read(start_pos, out.as_mut_ptr(), out.len() as u32) }
}

/// Returns the word at operand-stack positions `start_pos..start_pos + 4`.
pub fn stack_get_word(start_pos: u32) -> RawWord {
    let mut out = RawWord::default();
    stack_read(start_pos, &mut out.0);
    out
}

/// Returns the current clock cycle.
pub fn clk() -> u64 {
    unsafe { guest::clk() }
}

/// Returns the current execution context ID.
pub fn ctx() -> u32 {
    unsafe { guest::ctx() }
}

/// Returns the memory element at `addr` of the current context, or `None` when the cell was
/// never written.
pub fn mem_get(addr: u32) -> Option<RawFelt> {
    let mut out = RawFelt::new(0);
    match status(unsafe { guest::mem_get(addr, &mut out) }) {
        Status::Ok => Some(out),
        Status::Uninit => None,
        _ => fail("mem_get failed"),
    }
}

/// Reads the `out.len()` memory elements at addresses `addr..addr + out.len()` of the current
/// context.
///
/// Returns [`Status::OutOfBounds`] when the range goes past the `u32` address space and
/// [`Status::Uninit`] when any cell in the range was never written; `out` is unchanged in both
/// cases. Use [`mem_get`] for a per-cell presence check.
pub fn mem_read(addr: u32, out: &mut [RawFelt]) -> Status {
    let raw = unsafe { guest::mem_read(addr, out.as_mut_ptr(), out.len() as u32) };
    match status(raw) {
        result @ (Status::Ok | Status::Uninit | Status::OutOfBounds) => result,
        _ => fail("mem_read failed"),
    }
}

/// Returns the number of elements on the advice stack.
pub fn adv_stack_len() -> u32 {
    unsafe { guest::adv_stack_len() }
}

/// Reads `out.len()` advice-stack elements starting at `offset` (offset `0` is the top).
///
/// Returns `false` when the range goes past the advice-stack length; `out` is unchanged then.
pub fn adv_stack_read(offset: u32, out: &mut [RawFelt]) -> bool {
    let raw = unsafe { guest::adv_stack_read(offset, out.as_mut_ptr(), out.len() as u32) };
    match status(raw) {
        Status::Ok => true,
        Status::OutOfBounds => false,
        _ => fail("adv_stack_read failed"),
    }
}

/// Returns the length of the advice-map value for `key`, or `None` when the map has no entry.
pub fn adv_map_value_len(key: &RawWord) -> Option<u32> {
    let mut out = 0u32;
    match status(unsafe { guest::adv_map_value_len(key, &mut out) }) {
        Status::Ok => Some(out),
        Status::NotFound => None,
        _ => fail("adv_map_value_len failed"),
    }
}

/// Reads the advice-map value for `key` into `out` and returns the element count, or `None`
/// when the map has no entry.
///
/// Ends the handler when `out` is smaller than the value; size it with [`adv_map_value_len`].
pub fn adv_map_value_read(key: &RawWord, out: &mut [RawFelt]) -> Option<usize> {
    let len = adv_map_value_len(key)?;
    let raw = unsafe { guest::adv_map_value_read(key, out.as_mut_ptr(), out.len() as u32) };
    match status(raw) {
        Status::Ok => Some(len as usize),
        Status::NotFound => None,
        Status::CapacityTooSmall => fail("adv_map_value_read: output buffer is too small"),
        _ => fail("adv_map_value_read failed"),
    }
}

// MUTATIONS
// ================================================================================================

/// Buffers elements to extend the advice stack, ordered from the new top of the stack down.
pub fn adv_stack_extend(vals: &[RawFelt]) {
    unsafe { guest::adv_stack_extend(vals.as_ptr(), vals.len() as u32) }
}

/// Buffers an advice-map insertion of `vals` under `key`.
pub fn adv_map_insert(key: &RawWord, vals: &[RawFelt]) {
    unsafe { guest::adv_map_insert(key, vals.as_ptr(), vals.len() as u32) }
}

/// Buffers inner nodes to extend the Merkle store. Every node must satisfy
/// `value == hash(left, right)`.
pub fn merkle_store_extend(nodes: &[RawMerkleNode]) {
    unsafe { guest::merkle_store_extend(nodes.as_ptr(), nodes.len() as u32) }
}

// FAILURE
// ================================================================================================

/// Records `msg` as the handler's error message and ends the handler.
///
/// The host discards all buffered mutations.
pub fn fail(msg: &str) -> ! {
    unsafe { guest::fail(msg.as_ptr(), msg.len() as u32) }
}
