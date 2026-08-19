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

/// Reads the `out.len()` memory elements at addresses `addr..addr + out.len()` of context `ctx`.
///
/// The same contract as [`mem_read`], for an explicit execution context (for example the root
/// context, ID `0`).
pub fn mem_read_ctx(ctx: u32, addr: u32, out: &mut [RawFelt]) -> Status {
    let raw = unsafe { guest::mem_read_ctx(ctx, addr, out.as_mut_ptr(), out.len() as u32) };
    match status(raw) {
        result @ (Status::Ok | Status::Uninit | Status::OutOfBounds) => result,
        _ => fail("mem_read_ctx failed"),
    }
}

/// Returns the Merkle-store node of the tree with root `root` at `depth`/`index`, or `None` when
/// the store has no such tree or no node at this position.
///
/// A `depth` or `index` outside the valid range for a Merkle tree ends the handler.
pub fn merkle_get_node(root: &RawWord, depth: u32, index: u64) -> Option<RawWord> {
    let mut out = RawWord::default();
    match status(unsafe { guest::merkle_get_node(root, depth, index, &mut out) }) {
        Status::Ok => Some(out),
        Status::NotFound => None,
        _ => fail("merkle_get_node failed"),
    }
}

/// Returns `true` when the Merkle store has a path for the node of the tree with root `root` at
/// `depth`/`index`.
///
/// A `depth` or `index` outside the valid range for a Merkle tree ends the handler.
pub fn merkle_has_path(root: &RawWord, depth: u32, index: u64) -> bool {
    unsafe { guest::merkle_has_path(root, depth, index) != 0 }
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

// HASHING
// ================================================================================================

/// Returns the Poseidon2 merge of the two words in `pair`, using `domain`.
///
/// Domain `0` is the plain merge, the digest behind `adv.insert_hdword` advice keys and Merkle
/// inner nodes. A non-canonical `domain` ends the handler.
pub fn poseidon2_merge(pair: &[RawWord; 2], domain: u64) -> RawWord {
    let mut out = RawWord::default();
    unsafe { guest::poseidon2_merge(pair.as_ptr(), domain, &mut out) };
    out
}

/// Returns the Poseidon2 sequential hash of `elems`, using `domain`.
///
/// Domain `0` is the plain hash, the digest behind `adv.insert_hqword` advice keys. A
/// non-canonical `domain` ends the handler.
pub fn poseidon2_hash(elems: &[RawFelt], domain: u64) -> RawWord {
    let mut out = RawWord::default();
    unsafe { guest::poseidon2_hash(elems.as_ptr(), elems.len() as u32, domain, &mut out) };
    out
}

/// Applies the Poseidon2 permutation to the 12-element `state`, in place.
///
/// This matches `adv.insert_hperm` advice keys: the digest is `state[4..8]` afterwards.
pub fn poseidon2_permute(state: &mut [RawFelt; 12]) {
    unsafe { guest::poseidon2_permute(state.as_mut_ptr()) }
}

/// Returns the Keccak-256 digest of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { guest::keccak256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { guest::sha256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the SHA-512 digest of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe { guest::sha512(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the BLAKE3 digest of `data`.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { guest::blake3(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
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
