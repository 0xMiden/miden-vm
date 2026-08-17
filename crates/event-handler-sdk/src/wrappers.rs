//! Safe wrappers over the raw host imports.

use miden_event_handler_abi::{RawFelt, RawMerkleNode, RawWord, Status, guest};

/// Decodes a raw status code; an unknown code ends the handler.
fn status(raw: i32) -> Status {
    match Status::from_raw(raw) {
        Some(status) => status,
        None => fail("host returned an unknown status code"),
    }
}

/// Checks that a host call returned `Status::Ok`; any other status ends the handler.
fn expect_ok(raw: i32, what: &str) {
    if !status(raw).is_ok() {
        fail(what);
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
    let mut out = RawFelt::new(0);
    expect_ok(unsafe { guest::stack_get(pos, &mut out) }, "stack_get failed");
    out
}

/// Returns the word at operand-stack positions `start_pos..start_pos + 4`.
pub fn stack_get_word(start_pos: u32) -> RawWord {
    let mut out = RawWord::default();
    expect_ok(unsafe { guest::stack_get_word(start_pos, &mut out) }, "stack_get_word failed");
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
    expect_ok(
        unsafe { guest::adv_stack_extend(vals.as_ptr(), vals.len() as u32) },
        "adv_stack_extend failed",
    );
}

/// Buffers an advice-map insertion of `vals` under `key`.
pub fn adv_map_insert(key: &RawWord, vals: &[RawFelt]) {
    expect_ok(
        unsafe { guest::adv_map_insert(key, vals.as_ptr(), vals.len() as u32) },
        "adv_map_insert failed",
    );
}

/// Buffers inner nodes to extend the Merkle store. Every node must satisfy
/// `value == hash(left, right)`.
pub fn merkle_store_extend(nodes: &[RawMerkleNode]) {
    expect_ok(
        unsafe { guest::merkle_store_extend(nodes.as_ptr(), nodes.len() as u32) },
        "merkle_store_extend failed",
    );
}

// FAILURE
// ================================================================================================

/// Records `msg` as the handler's error message and ends the handler.
///
/// The host discards all buffered mutations.
pub fn fail(msg: &str) -> ! {
    unsafe { guest::fail(msg.as_ptr(), msg.len() as u32) }
}
