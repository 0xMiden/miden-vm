//! Safe wrappers over the raw host imports.
//!
//! The wrappers speak [`Felt`], [`Word`] and [`MerkleNode`] — the same types the imports take.
//! There is no conversion layer: the in-memory form of these types *is* the wire encoding, one
//! plain (non-Montgomery) `u64` residue per field element. See the wire-format section of the
//! `miden-event-handler-abi` crate documentation.
//!
//! # Canonicalization
//!
//! The wire encoding needs the *canonical* residue (less than the field modulus), but a guest
//! [`Felt`] may hold a lazy residue after arithmetic: a value in `[p, 2^64)` stands for the value
//! minus `p`. Two rules follow:
//!
//! - Outgoing buffers get canonicalized first. The host traps the handler on a non-canonical
//!   element, so sending a lazy residue would end the handler. The wrappers canonicalize caller
//!   buffers in place, and stage a canonical copy of by-reference values such as keys.
//! - Incoming buffers need no work. Every element the host writes is canonical, and a canonical
//!   `u64` is the plain residue of the value it encodes, so the host writes straight into the
//!   caller's buffer.
//!
//! # Safety contract
//!
//! Every host import is `unsafe` because it takes raw pointers. All call sites below meet the
//! same contract, which the per-site comments only add to:
//!
//! - each pointer comes from a live binding that outlives the call — a caller slice, a caller
//!   reference, or a local of this function — so it is non-null, aligned, and valid to read for
//!   `*const` arguments and to write for `*mut` arguments;
//! - each length or capacity argument is the element count of the buffer its pointer names, so the
//!   host stays inside that buffer;
//! - the host writes only through `*mut` pointers, and keeps no pointer past the call, so no borrow
//!   outlives the call.

use miden_event_handler_abi::{Felt, MerkleNode, Status, Word, guest};

// CANONICALIZATION
// ================================================================================================

/// Rewrites every element of `vals` as its canonical residue.
///
/// This does not change the field values; it only normalizes their representation for the wire.
#[inline]
fn canonicalize(vals: &mut [Felt]) {
    for val in vals.iter_mut() {
        *val = Felt::new_unchecked(val.as_canonical_u64());
    }
}

/// Returns a copy of `word` with every element in canonical residue form.
#[inline]
fn canonical_word(word: &Word) -> Word {
    let mut word = *word;
    canonicalize(&mut word[0..Word::NUM_ELEMENTS]);
    word
}

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
    // SAFETY: the module contract; the call takes no pointer.
    unsafe { guest::stack_depth() }
}

/// Returns the operand-stack element at `pos`. Position `0` holds the event ID; positions past
/// the stack depth read as zero.
pub fn stack_get(pos: u32) -> Felt {
    // SAFETY: the module contract; the call takes no pointer.
    // The host returns a canonical value, which is the plain residue of itself.
    Felt::new_unchecked(unsafe { guest::stack_get(pos) })
}

/// Reads the `out.len()` operand-stack elements at positions `start_pos..start_pos + out.len()`,
/// ordered from the top of the stack down. Positions past the stack depth read as zero.
pub fn stack_read(start_pos: u32, out: &mut [Felt]) {
    let len = out.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `out`.
    unsafe { guest::stack_read(start_pos, out.as_mut_ptr(), len) }
}

/// Returns the word at operand-stack positions `start_pos..start_pos + 4`.
///
/// Element `0` of the word is the element at `start_pos`, the one closest to the top of the
/// stack.
pub fn stack_get_word(start_pos: u32) -> Word {
    let mut out = [Felt::ZERO; Word::NUM_ELEMENTS];
    stack_read(start_pos, &mut out);
    Word::new(out)
}

/// Returns the current clock cycle.
pub fn clk() -> u64 {
    // SAFETY: the module contract; the call takes no pointer.
    unsafe { guest::clk() }
}

/// Returns the current execution context ID.
pub fn ctx() -> u32 {
    // SAFETY: the module contract; the call takes no pointer.
    unsafe { guest::ctx() }
}

/// Returns the memory element at `addr` of the current context, or `None` when the cell was
/// never written.
pub fn mem_get(addr: u32) -> Option<Felt> {
    let mut out = Felt::ZERO;
    // SAFETY: the module contract; the host writes one element into the local `out`.
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
pub fn mem_read(addr: u32, out: &mut [Felt]) -> Status {
    let len = out.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `out`.
    let raw = unsafe { guest::mem_read(addr, out.as_mut_ptr(), len) };
    match status(raw) {
        result @ (Status::Ok | Status::Uninit | Status::OutOfBounds) => result,
        _ => fail("mem_read failed"),
    }
}

/// Reads the `out.len()` memory elements at addresses `addr..addr + out.len()` of context `ctx`.
///
/// The same contract as [`mem_read`], for an explicit execution context (for example the root
/// context, ID `0`).
pub fn mem_read_ctx(ctx: u32, addr: u32, out: &mut [Felt]) -> Status {
    let len = out.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `out`.
    let raw = unsafe { guest::mem_read_ctx(ctx, addr, out.as_mut_ptr(), len) };
    match status(raw) {
        result @ (Status::Ok | Status::Uninit | Status::OutOfBounds) => result,
        _ => fail("mem_read_ctx failed"),
    }
}

/// Returns the Merkle-store node of the tree with root `root` at `depth`/`index`, or `None` when
/// the store has no such tree or no node at this position.
///
/// A `depth` or `index` outside the valid range for a Merkle tree ends the handler.
pub fn merkle_get_node(root: &Word, depth: u32, index: u64) -> Option<Word> {
    let root = canonical_word(root);
    let mut out = Word::empty();
    // SAFETY: the module contract; the host reads the local `root` and writes the local `out`,
    // one word each.
    match status(unsafe { guest::merkle_get_node(&root, depth, index, &mut out) }) {
        Status::Ok => Some(out),
        Status::NotFound => None,
        _ => fail("merkle_get_node failed"),
    }
}

/// Returns `true` when the Merkle store has a path for the node of the tree with root `root` at
/// `depth`/`index`.
///
/// A `depth` or `index` outside the valid range for a Merkle tree ends the handler.
pub fn merkle_has_path(root: &Word, depth: u32, index: u64) -> bool {
    let root = canonical_word(root);
    // SAFETY: the module contract; the host reads one word from the local `root`.
    unsafe { guest::merkle_has_path(&root, depth, index) != 0 }
}

/// Returns the number of elements on the advice stack.
pub fn adv_stack_len() -> u32 {
    // SAFETY: the module contract; the call takes no pointer.
    unsafe { guest::adv_stack_len() }
}

/// Reads `out.len()` advice-stack elements starting at `offset` (offset `0` is the top).
///
/// Returns `false` when the range goes past the advice-stack length; `out` is unchanged then.
pub fn adv_stack_read(offset: u32, out: &mut [Felt]) -> bool {
    let len = out.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `out`.
    let raw = unsafe { guest::adv_stack_read(offset, out.as_mut_ptr(), len) };
    match status(raw) {
        Status::Ok => true,
        Status::OutOfBounds => false,
        _ => fail("adv_stack_read failed"),
    }
}

/// Returns the length of the advice-map value for `key`, or `None` when the map has no entry.
pub fn adv_map_value_len(key: &Word) -> Option<u32> {
    let key = canonical_word(key);
    let mut out = 0u32;
    // SAFETY: the module contract; the host reads one word from the local `key` and writes the
    // local `out`.
    match status(unsafe { guest::adv_map_value_len(&key, &mut out) }) {
        Status::Ok => Some(out),
        Status::NotFound => None,
        _ => fail("adv_map_value_len failed"),
    }
}

/// Reads the advice-map value for `key` into `out` and returns the element count, or `None`
/// when the map has no entry. One host call.
///
/// Ends the handler when `out` is smaller than the value; size it with [`adv_map_value_len`].
pub fn adv_map_value_read(key: &Word, out: &mut [Felt]) -> Option<usize> {
    let key = canonical_word(key);
    let cap = out.len() as u32;
    let mut len = 0u32;
    // SAFETY: the module contract; `cap` is the element count of `out`, the host writes no
    // more than `cap` elements, and the element count goes to the local `len`.
    let raw = unsafe { guest::adv_map_value_read(&key, out.as_mut_ptr(), cap, &mut len) };
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
/// inner nodes.
pub fn poseidon2_merge(pair: &[Word; 2], domain: Felt) -> Word {
    let pair = [canonical_word(&pair[0]), canonical_word(&pair[1])];
    let mut out = Word::empty();
    // SAFETY: the module contract; the host reads the two words the local `pair` holds and
    // writes one word into the local `out`.
    unsafe { guest::poseidon2_merge(pair.as_ptr(), domain.as_canonical_u64(), &mut out) };
    out
}

/// Returns the Poseidon2 sequential hash of `elems`, using `domain`.
///
/// Domain `0` is the plain hash, the digest behind `adv.insert_hqword` advice keys.
///
/// This canonicalizes the elements of `elems` in place; the field values do not change.
pub fn poseidon2_hash(elems: &mut [Felt], domain: Felt) -> Word {
    canonicalize(elems);
    let mut out = Word::empty();
    let len = elems.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `elems`, and the host writes
    // one word into the local `out`.
    unsafe { guest::poseidon2_hash(elems.as_ptr(), len, domain.as_canonical_u64(), &mut out) };
    out
}

/// Applies the Poseidon2 permutation to the 12-element `state`, in place.
///
/// This matches `adv.insert_hperm` advice keys: the digest is `state[4..8]` afterwards.
///
/// This canonicalizes the elements of `state` in place; the field values do not change.
pub fn poseidon2_permute(state: &mut [Felt; 12]) {
    // The host reads the state and writes the permuted state back into the same buffer.
    canonicalize(state);
    // SAFETY: the module contract; the host reads and writes exactly the 12 elements of `state`.
    unsafe { guest::poseidon2_permute(state.as_mut_ptr()) }
}

/// Returns the Keccak-256 digest of `data`.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: the module contract; the length is that of `data`, and `out` holds the 32 bytes of
    // a Keccak-256 digest.
    unsafe { guest::keccak256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: the module contract; the length is that of `data`, and `out` holds the 32 bytes of
    // a SHA-256 digest.
    unsafe { guest::sha256(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the SHA-512 digest of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    // SAFETY: the module contract; the length is that of `data`, and `out` holds the 64 bytes of
    // a SHA-512 digest.
    unsafe { guest::sha512(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

/// Returns the BLAKE3 digest of `data`.
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // SAFETY: the module contract; the length is that of `data`, and `out` holds the 32 bytes of
    // a BLAKE3 digest.
    unsafe { guest::blake3(data.as_ptr(), data.len() as u32, out.as_mut_ptr()) };
    out
}

// MUTATIONS
// ================================================================================================

/// Buffers elements to extend the advice stack, ordered from the new top of the stack down.
///
/// This canonicalizes the elements of `vals` in place; the field values do not change.
pub fn adv_stack_extend(vals: &mut [Felt]) {
    canonicalize(vals);
    let len = vals.len() as u32;
    // SAFETY: the module contract; `len` is the element count of `vals`.
    unsafe { guest::adv_stack_extend(vals.as_ptr(), len) }
}

/// Buffers an advice-map insertion of `vals` under `key`.
///
/// This canonicalizes the elements of `vals` in place; the field values do not change.
pub fn adv_map_insert(key: &Word, vals: &mut [Felt]) {
    canonicalize(vals);
    let key = canonical_word(key);
    let len = vals.len() as u32;
    // SAFETY: the module contract; the host reads one word from the local `key`, and `len` is
    // the element count of `vals`.
    unsafe { guest::adv_map_insert(&key, vals.as_ptr(), len) }
}

/// Buffers inner nodes to extend the Merkle store.
///
/// Each node holds the node digest and its two child digests. Every node must satisfy
/// `value == poseidon2_merge([left, right], 0)`.
///
/// This canonicalizes the elements of `nodes` in place; the field values do not change.
pub fn merkle_store_extend(nodes: &mut [MerkleNode]) {
    for node in nodes.iter_mut() {
        for word in [&mut node.value, &mut node.left, &mut node.right] {
            canonicalize(&mut word[0..Word::NUM_ELEMENTS]);
        }
    }
    let len = nodes.len() as u32;
    // SAFETY: the module contract; `len` is the node count of `nodes`.
    unsafe { guest::merkle_store_extend(nodes.as_ptr(), len) }
}

// FAILURE
// ================================================================================================

/// Records `msg` as the handler's error message and ends the handler.
///
/// The host discards all buffered mutations.
pub fn fail(msg: &str) -> ! {
    // SAFETY: the module contract; the length is the byte length of `msg`. The host always
    // traps, so the call does not return.
    unsafe { guest::fail(msg.as_ptr(), msg.len() as u32) }
}
