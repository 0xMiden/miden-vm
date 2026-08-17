//! ABI contract between the Miden VM host and Wasm-compiled event handlers.
//!
//! A Wasm event handler is a core Wasm module. The host runs it with an interpreter when the VM
//! emits a custom event. The handler does not link any Miden crate. It talks to the host only
//! through the functions it imports from the [`IMPORT_MODULE`] namespace, and through the plain
//! `#[repr(C)]` data types in this crate.
//!
//! # Memory ownership
//!
//! All pointers that cross the host boundary point into the guest's own linear memory. The guest
//! allocates every buffer; the host only reads from and writes into those buffers. The host
//! rejects any pointer range that does not fit into the guest memory.
//!
//! # Handler exports
//!
//! Each handler is an exported function with the signature `() -> ()`. A normal return means
//! success. A trap (including a call to `fail`) means failure; the host then discards every
//! mutation the handler has buffered. The package manifest maps event names to export names.
//!
//! # Failure rules
//!
//! Host functions return a [`Status`] code for conditions a correct handler can meet at run time
//! (a missing advice-map key, an uninitialized memory cell). The host traps the handler for
//! conditions that only a defective or hostile handler can create:
//!
//! - a pointer range outside the guest memory, or one whose `ptr + len` computation overflows;
//! - a field element that is not in canonical form (`>= FIELD_MODULUS`);
//! - a mutation that goes over a host-side size limit;
//! - fuel exhaustion.

#![no_std]

// ABI CONSTANTS
// ================================================================================================

/// The version of this ABI contract.
///
/// The host refuses to load a handler module whose declared ABI version does not match.
pub const ABI_VERSION: u32 = 1;

/// The Wasm import module namespace that provides all host functions.
pub const IMPORT_MODULE: &str = "miden:event/v1";

/// The name of the Wasm custom section that carries handler manifest records.
///
/// The guest SDK macro writes one record per handler into this section. Package build tooling can
/// read the section to construct the package manifest mechanically.
pub const MANIFEST_SECTION_NAME: &str = "miden:event-manifest";

/// The modulus of the Miden field (Goldilocks): `2^64 - 2^32 + 1`.
///
/// A [`RawFelt`] is canonical when its value is less than this modulus.
pub const FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;

/// The number of field elements in a word.
pub const WORD_ELEMENTS: usize = 4;

// RAW FELT
// ================================================================================================

/// A field element in canonical `u64` form.
///
/// The value must be less than [`FIELD_MODULUS`]. The host validates every field element it
/// receives from the guest and traps the handler on a non-canonical value. Every field element
/// the host writes into guest memory is canonical.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RawFelt(pub u64);

impl RawFelt {
    /// Creates a raw field element from a `u64` without a range check.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner `u64` value.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// Returns `true` when the value is less than [`FIELD_MODULUS`].
    pub const fn is_canonical(&self) -> bool {
        self.0 < FIELD_MODULUS
    }
}

impl From<u64> for RawFelt {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

// RAW WORD
// ================================================================================================

/// A word: four field elements.
///
/// When a word comes from the operand stack, the element order is the order of
/// `ProcessorState::get_stack_word`: element `0` of the word is the stack element at the start
/// position (closest to the top of the stack).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RawWord(pub [RawFelt; WORD_ELEMENTS]);

impl RawWord {
    /// Creates a raw word from four `u64` values without a range check.
    pub const fn new(elements: [u64; WORD_ELEMENTS]) -> Self {
        Self([
            RawFelt::new(elements[0]),
            RawFelt::new(elements[1]),
            RawFelt::new(elements[2]),
            RawFelt::new(elements[3]),
        ])
    }

    /// Returns `true` when all four elements are canonical.
    pub const fn is_canonical(&self) -> bool {
        self.0[0].is_canonical()
            && self.0[1].is_canonical()
            && self.0[2].is_canonical()
            && self.0[3].is_canonical()
    }
}

// RAW MERKLE NODE
// ================================================================================================

/// An inner node of a Merkle tree, for `merkle_store_extend`.
///
/// The layout mirrors the host-side `InnerNodeInfo`: the node digest and its two child digests.
/// The host checks `value == hash(left, right)` when it applies the mutation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMerkleNode {
    /// The digest of the node.
    pub value: RawWord,
    /// The digest of the left child.
    pub left: RawWord,
    /// The digest of the right child.
    pub right: RawWord,
}

// STATUS
// ================================================================================================

/// The result code of a host function call.
///
/// Codes other than [`Status::Ok`] report conditions a correct handler can meet at run time.
/// Defect conditions (bad pointers, non-canonical field elements, limit violations) do not get a
/// status code: the host traps the handler instead.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The call succeeded.
    Ok = 0,
    /// A stack or advice-stack range was out of bounds.
    OutOfBounds = 1,
    /// The advice map has no entry for the given key.
    NotFound = 2,
    /// The memory cell was never written. Uninitialized memory is distinct from a zero value.
    Uninit = 3,
    /// The output buffer capacity is smaller than the value length.
    CapacityTooSmall = 4,
}

impl Status {
    /// Decodes a status from the raw `i32` a host function returned.
    ///
    /// Returns `None` for a code this ABI version does not define.
    pub const fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::OutOfBounds),
            2 => Some(Self::NotFound),
            3 => Some(Self::Uninit),
            4 => Some(Self::CapacityTooSmall),
            _ => None,
        }
    }

    /// Returns the raw `i32` code.
    pub const fn as_raw(&self) -> i32 {
        *self as i32
    }

    /// Returns `true` for [`Status::Ok`].
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

// HOST FUNCTION NAMES
// ================================================================================================

/// The names of the host functions in the [`IMPORT_MODULE`] namespace.
///
/// The host registers its functions under these names. The guest extern declarations in the
/// `guest` module (compiled for `wasm32` guests only) use the same names, and their doc
/// comments are the normative description of each function. Keep the two lists identical.
pub mod host_fn {
    /// See `guest::stack_depth`.
    pub const STACK_DEPTH: &str = "stack_depth";
    /// See `guest::stack_get`.
    pub const STACK_GET: &str = "stack_get";
    /// See `guest::stack_get_word`.
    pub const STACK_GET_WORD: &str = "stack_get_word";
    /// See `guest::clk`.
    pub const CLK: &str = "clk";
    /// See `guest::ctx`.
    pub const CTX: &str = "ctx";
    /// See `guest::mem_get`.
    pub const MEM_GET: &str = "mem_get";
    /// See `guest::adv_stack_len`.
    pub const ADV_STACK_LEN: &str = "adv_stack_len";
    /// See `guest::adv_stack_read`.
    pub const ADV_STACK_READ: &str = "adv_stack_read";
    /// See `guest::adv_map_value_len`.
    pub const ADV_MAP_VALUE_LEN: &str = "adv_map_value_len";
    /// See `guest::adv_map_value_read`.
    pub const ADV_MAP_VALUE_READ: &str = "adv_map_value_read";
    /// See `guest::adv_stack_extend`.
    pub const ADV_STACK_EXTEND: &str = "adv_stack_extend";
    /// See `guest::adv_map_insert`.
    pub const ADV_MAP_INSERT: &str = "adv_map_insert";
    /// See `guest::merkle_store_extend`.
    pub const MERKLE_STORE_EXTEND: &str = "merkle_store_extend";
    /// See `guest::fail`.
    pub const FAIL: &str = "fail";
}

// GUEST IMPORT DECLARATIONS
// ================================================================================================

/// Guest-side declarations of the host functions.
///
/// This module compiles only for `wasm32` guests with the `guest` feature on. The doc comments
/// here are the normative description of each host function; the host implementation follows
/// them.
#[cfg(all(feature = "guest", target_arch = "wasm32"))]
pub mod guest {
    use super::{RawFelt, RawMerkleNode, RawWord};

    #[link(wasm_import_module = "miden:event/v1")]
    unsafe extern "C" {
        // QUERIES
        // ----------------------------------------------------------------------------------------

        /// Returns the depth of the operand stack.
        pub fn stack_depth() -> u32;

        /// Writes the operand-stack element at position `pos` to `out`.
        ///
        /// Position `0` is the top of the stack and holds the event ID. Positions past the stack
        /// depth read as zero, the same as for native event handlers. Always returns
        /// `Status::Ok`.
        pub fn stack_get(pos: u32, out: *mut RawFelt) -> i32;

        /// Writes the word at operand-stack positions `start_pos..start_pos + 4` to `out`.
        ///
        /// Element `0` of the word is the stack element at `start_pos` (closest to the top).
        /// Positions past the stack depth read as zero. Always returns `Status::Ok`.
        pub fn stack_get_word(start_pos: u32, out: *mut RawWord) -> i32;

        /// Returns the current clock cycle.
        pub fn clk() -> u64;

        /// Returns the current execution context ID.
        pub fn ctx() -> u32;

        /// Writes the memory element at address `addr` of the current context to `out`.
        ///
        /// Returns `Status::Uninit` when the cell was never written; `out` is not changed in that
        /// case. Uninitialized memory is distinct from a zero value.
        pub fn mem_get(addr: u32, out: *mut RawFelt) -> i32;

        /// Returns the number of elements on the advice stack.
        pub fn adv_stack_len() -> u32;

        /// Writes `count` advice-stack elements starting at `offset` to `out`.
        ///
        /// Offset `0` is the top of the advice stack. Returns `Status::OutOfBounds` when
        /// `offset + count` goes past the advice-stack length; `out` is not changed in that case.
        pub fn adv_stack_read(offset: u32, out: *mut RawFelt, count: u32) -> i32;

        /// Writes the length of the advice-map value for `key` to `out_len`.
        ///
        /// Returns `Status::NotFound` when the map has no entry for `key`; `out_len` is not
        /// changed in that case.
        pub fn adv_map_value_len(key: *const RawWord, out_len: *mut u32) -> i32;

        /// Writes the advice-map value for `key` to `out`.
        ///
        /// `cap` is the element capacity of `out`. Returns `Status::NotFound` when the map has no
        /// entry for `key`, and `Status::CapacityTooSmall` when the value is longer than `cap`;
        /// `out` is not changed in either case. Call `adv_map_value_len` first to size the
        /// buffer.
        pub fn adv_map_value_read(key: *const RawWord, out: *mut RawFelt, cap: u32) -> i32;

        // MUTATIONS
        // ----------------------------------------------------------------------------------------
        //
        // The host buffers mutations. It applies them to the advice provider only after the
        // handler returns without a trap.

        /// Buffers `len` elements to extend the advice stack, ordered from the new top of the
        /// stack down.
        ///
        /// Always returns `Status::Ok`; a size-limit violation traps.
        pub fn adv_stack_extend(vals: *const RawFelt, len: u32) -> i32;

        /// Buffers an advice-map insertion of `len` elements under `key`.
        ///
        /// Inserting a key that exists with a different value makes the handler fail when the
        /// host applies the buffered mutations. Always returns `Status::Ok`; a size-limit
        /// violation traps.
        pub fn adv_map_insert(key: *const RawWord, vals: *const RawFelt, len: u32) -> i32;

        /// Buffers `len` inner nodes to extend the Merkle store.
        ///
        /// Always returns `Status::Ok`; a size-limit violation traps.
        pub fn merkle_store_extend(nodes: *const RawMerkleNode, len: u32) -> i32;

        // FAILURE
        // ----------------------------------------------------------------------------------------

        /// Records `msg` as the handler's error message and traps.
        ///
        /// The host discards all buffered mutations and reports the message together with the
        /// event name and ID.
        pub fn fail(msg_ptr: *const u8, msg_len: u32) -> !;
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_modulus_matches_miden_field() {
        use miden_core::field::PrimeField64;
        assert_eq!(FIELD_MODULUS, miden_core::Felt::ORDER_U64);
        // Cross-check the constant against its arithmetic definition.
        assert_eq!(FIELD_MODULUS as u128, (1u128 << 64) - (1u128 << 32) + 1);
    }

    #[test]
    fn felt_canonical_bounds() {
        assert!(RawFelt::new(0).is_canonical());
        assert!(RawFelt::new(FIELD_MODULUS - 1).is_canonical());
        assert!(!RawFelt::new(FIELD_MODULUS).is_canonical());
        assert!(!RawFelt::new(u64::MAX).is_canonical());

        let good = RawWord::new([1, 2, 3, FIELD_MODULUS - 1]);
        assert!(good.is_canonical());
        let bad = RawWord::new([1, 2, 3, FIELD_MODULUS]);
        assert!(!bad.is_canonical());
    }

    #[test]
    fn status_roundtrip() {
        let all = [
            Status::Ok,
            Status::OutOfBounds,
            Status::NotFound,
            Status::Uninit,
            Status::CapacityTooSmall,
        ];
        for status in all {
            assert_eq!(Status::from_raw(status.as_raw()), Some(status));
        }
        assert_eq!(Status::from_raw(-1), None);
        assert_eq!(Status::from_raw(5), None);
        assert!(Status::Ok.is_ok());
        assert!(!Status::NotFound.is_ok());
    }

    #[test]
    fn repr_c_layouts_are_stable() {
        use core::mem::{align_of, size_of};

        assert_eq!(size_of::<RawFelt>(), 8);
        assert_eq!(align_of::<RawFelt>(), 8);
        assert_eq!(size_of::<RawWord>(), 32);
        assert_eq!(size_of::<RawMerkleNode>(), 96);
    }
}
