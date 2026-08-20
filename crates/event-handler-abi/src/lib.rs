//! ABI contract between the Miden VM host and Wasm-compiled event handlers.
//!
//! A Wasm event handler is a core Wasm module. The host runs it with an interpreter when the VM
//! emits a custom event. The handler talks to the host only through the functions it imports
//! from the [`IMPORT_MODULE`] namespace.
//!
//! # Wire format
//!
//! A field element crosses the wire as its canonical `u64` (less than [`FIELD_MODULUS`]),
//! little-endian in Wasm memory; a word is four of them. The declarations use the off-chain
//! [`Felt`] and [`Word`] types of `miden-field`, whose in-memory representation is exactly this
//! encoding (checked at compile time below). The host validates every element it receives and
//! traps the handler on a non-canonical value; every element the host writes is canonical.
//! Guest-side `Felt` values may hold lazy, non-canonical residues after arithmetic, so guests
//! must canonicalize outgoing buffers — the SDK wrappers do this.
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
/// Version bumps are additive only: a newer version may add host functions, but must not change
/// or remove existing ones. Hosts therefore accept every declared version from `1` up to their
/// own [`ABI_VERSION`]. A breaking change gets a new import namespace (for example
/// `miden:event/v2`) instead of a version bump.
pub const ABI_VERSION: u32 = 1;

/// The Wasm import module namespace that provides all host functions.
pub const IMPORT_MODULE: &str = "miden:event/v1";

/// The name of the Wasm custom section that carries handler manifest records.
///
/// The guest SDK macro writes one record per handler into this section. Package build tooling can
/// read the section to construct the package manifest mechanically.
pub const MANIFEST_SECTION_NAME: &str = "miden:event-manifest";

/// The version byte that leads each record in the [`MANIFEST_SECTION_NAME`] custom section.
///
/// A record is this byte, then the event name and the export name, each as a little-endian `u32`
/// length followed by the bytes.
pub const MANIFEST_RECORD_VERSION: u8 = 1;

/// The modulus of the Miden field (Goldilocks): `2^64 - 2^32 + 1`.
///
/// A wire field element is canonical when its value is less than this modulus.
pub const FIELD_MODULUS: u64 = 0xffff_ffff_0000_0001;

// VALUE TYPES
// ================================================================================================

pub use miden_field::{Felt, word::Word};

/// An inner node of a Merkle tree, for `merkle_store_extend`.
///
/// The layout mirrors the host-side `InnerNodeInfo`: the node digest and its two child digests.
/// The host checks `value == hash(left, right)` when it applies the mutation.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleNode {
    /// The digest of the node.
    pub value: Word,
    /// The digest of the left child.
    pub left: Word,
    /// The digest of the right child.
    pub right: Word,
}

// The extern declarations pass `Felt` and `Word` buffers straight over the wire, so their
// in-memory layout must be the wire encoding: one plain (non-Montgomery) `u64` residue per
// element, little-endian in Wasm memory. This holds for the off-chain `Felt` of `miden-field`,
// whose representation is documented there as load-bearing for this ABI. A build against the
// on-chain (`cfg(miden)`, f32-backed) `Felt` fails here instead of producing wrong bytes.
const _: () = {
    assert!(size_of::<Felt>() == 8, "the ABI needs the off-chain u64-backed Felt");
    assert!(align_of::<Felt>() == 8, "the ABI needs the off-chain u64-backed Felt");
    assert!(size_of::<Word>() == 32, "the ABI needs the off-chain u64-backed Word");
    assert!(size_of::<MerkleNode>() == 96, "MerkleNode must be three packed words");
};

// STATUS
// ================================================================================================

/// The result code of a host function call.
///
/// A host function returns a status only when a non-[`Status::Ok`] outcome is reachable for a
/// correct handler. Calls that cannot fail return their value directly (or nothing). Defect
/// conditions (bad pointers, non-canonical field elements, limit violations) do not get a
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
    /// See `guest::stack_read`.
    pub const STACK_READ: &str = "stack_read";
    /// See `guest::clk`.
    pub const CLK: &str = "clk";
    /// See `guest::ctx`.
    pub const CTX: &str = "ctx";
    /// See `guest::mem_get`.
    pub const MEM_GET: &str = "mem_get";
    /// See `guest::mem_read`.
    pub const MEM_READ: &str = "mem_read";
    /// See `guest::mem_read_ctx`.
    pub const MEM_READ_CTX: &str = "mem_read_ctx";
    /// See `guest::merkle_get_node`.
    pub const MERKLE_GET_NODE: &str = "merkle_get_node";
    /// See `guest::merkle_has_path`.
    pub const MERKLE_HAS_PATH: &str = "merkle_has_path";
    /// See `guest::poseidon2_merge`.
    pub const POSEIDON2_MERGE: &str = "poseidon2_merge";
    /// See `guest::poseidon2_hash`.
    pub const POSEIDON2_HASH: &str = "poseidon2_hash";
    /// See `guest::poseidon2_permute`.
    pub const POSEIDON2_PERMUTE: &str = "poseidon2_permute";
    /// See `guest::keccak256`.
    pub const KECCAK256: &str = "keccak256";
    /// See `guest::sha256`.
    pub const SHA256: &str = "sha256";
    /// See `guest::sha512`.
    pub const SHA512: &str = "sha512";
    /// See `guest::blake3`.
    pub const BLAKE3: &str = "blake3";
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
    use super::{Felt, MerkleNode, Word};

    // The attribute takes only a string literal, so the namespace is repeated here. Keep it in
    // sync with [`IMPORT_MODULE`](super::IMPORT_MODULE).
    #[link(wasm_import_module = "miden:event/v1")]
    unsafe extern "C" {
        // QUERIES
        // ----------------------------------------------------------------------------------------

        /// Returns the depth of the operand stack.
        pub fn stack_depth() -> u32;

        /// Returns the operand-stack element at position `pos` in canonical form.
        ///
        /// Position `0` is the top of the stack and holds the event ID. Positions past the stack
        /// depth read as zero, the same as for native event handlers.
        pub fn stack_get(pos: u32) -> u64;

        /// Writes the `count` operand-stack elements at positions
        /// `start_pos..start_pos + count` to `out`, ordered from the top of the stack down.
        ///
        /// Positions past the stack depth read as zero.
        pub fn stack_read(start_pos: u32, out: *mut Felt, count: u32);

        /// Returns the current clock cycle.
        pub fn clk() -> u64;

        /// Returns the current execution context ID.
        pub fn ctx() -> u32;

        /// Writes the memory element at address `addr` of the current context to `out`.
        ///
        /// Returns `Status::Uninit` when the cell was never written; `out` is not changed in that
        /// case. Uninitialized memory is distinct from a zero value.
        pub fn mem_get(addr: u32, out: *mut Felt) -> i32;

        /// Writes the `count` memory elements at addresses `addr..addr + count` of the current
        /// context to `out`.
        ///
        /// Returns `Status::OutOfBounds` when `addr + count` goes past the `u32` address space,
        /// and `Status::Uninit` when any cell in the range was never written; `out` is not
        /// changed in either case. Use `mem_get` for a per-cell presence check.
        pub fn mem_read(addr: u32, out: *mut Felt, count: u32) -> i32;

        /// Writes the `count` memory elements at addresses `addr..addr + count` of context
        /// `ctx` to `out`.
        ///
        /// The same contract as `mem_read`, for an explicit execution context (for example the
        /// root context, ID `0`). Returns `Status::OutOfBounds` when `addr + count` goes past
        /// the `u32` address space, and `Status::Uninit` when any cell in the range was never
        /// written; `out` is not changed in either case.
        pub fn mem_read_ctx(ctx: u32, addr: u32, out: *mut Felt, count: u32) -> i32;

        /// Writes the Merkle-store node of the tree with root `root` at `depth`/`index` to
        /// `out`.
        ///
        /// `index` is a field element in canonical form, not a plain integer: a value that is
        /// not less than [`crate::FIELD_MODULUS`] traps. `depth` is a plain `u32`, which is
        /// always canonical.
        ///
        /// Returns `Status::NotFound` when the store has no tree with this root or no node at
        /// this position; `out` is not changed in that case. A `depth` or `index` outside the
        /// valid range for a Merkle tree traps.
        pub fn merkle_get_node(root: *const Word, depth: u32, index: u64, out: *mut Word) -> i32;

        /// Returns `1` when the Merkle store has a path for the node of the tree with root
        /// `root` at `depth`/`index`, and `0` when it has not.
        ///
        /// `index` and `depth` follow the rules of `merkle_get_node`: a non-canonical `index`
        /// traps, and so does a `depth` or `index` outside the valid range for a Merkle tree.
        pub fn merkle_has_path(root: *const Word, depth: u32, index: u64) -> i32;

        // HASHING
        // ----------------------------------------------------------------------------------------
        //
        // The host computes VM-native hashes on the guest's behalf, so guests do not carry
        // their own crypto implementations and always agree bit-for-bit with the VM. Poseidon2
        // is the hash behind every advice-map key convention (`adv.insert_hdword` keys are
        // `merge`, `adv.insert_hqword` keys are `hash`, `adv.insert_hperm` keys come from the
        // raw permutation) and behind Merkle nodes and SMT leaves. All `domain` parameters are
        // field elements in canonical form; a non-canonical domain traps.

        /// Writes the Poseidon2 merge of the two words at `pair` to `out`, using `domain`.
        ///
        /// Domain `0` is the plain merge, the digest behind `adv.insert_hdword` advice keys and
        /// Merkle inner nodes. Other domains match `adv.insert_hdword_d` and the SMT leaf
        /// domains.
        pub fn poseidon2_merge(pair: *const Word, domain: u64, out: *mut Word);

        /// Writes the Poseidon2 sequential hash of `count` field elements at `elems` to `out`,
        /// using `domain`.
        ///
        /// Domain `0` is the plain hash, the digest behind `adv.insert_hqword` advice keys and
        /// commitment values. The elements are validated canonical; a non-canonical element
        /// traps.
        pub fn poseidon2_hash(elems: *const Felt, count: u32, domain: u64, out: *mut Word);

        /// Applies the Poseidon2 permutation to the 12-element state at `state`, in place.
        ///
        /// This matches `adv.insert_hperm` advice keys: the digest is `state[4..8]` after the
        /// permutation. The state elements are validated canonical; a non-canonical element
        /// traps.
        pub fn poseidon2_permute(state: *mut Felt);

        /// Writes the Keccak-256 digest (32 bytes) of the `len` bytes at `data` to `out`.
        pub fn keccak256(data: *const u8, len: u32, out: *mut u8);

        /// Writes the SHA-256 digest (32 bytes) of the `len` bytes at `data` to `out`.
        pub fn sha256(data: *const u8, len: u32, out: *mut u8);

        /// Writes the SHA-512 digest (64 bytes) of the `len` bytes at `data` to `out`.
        pub fn sha512(data: *const u8, len: u32, out: *mut u8);

        /// Writes the BLAKE3 digest (32 bytes) of the `len` bytes at `data` to `out`.
        pub fn blake3(data: *const u8, len: u32, out: *mut u8);

        /// Returns the number of elements on the advice stack.
        pub fn adv_stack_len() -> u32;

        /// Writes `count` advice-stack elements starting at `offset` to `out`.
        ///
        /// Offset `0` is the top of the advice stack. Returns `Status::OutOfBounds` when
        /// `offset + count` goes past the advice-stack length; `out` is not changed in that case.
        pub fn adv_stack_read(offset: u32, out: *mut Felt, count: u32) -> i32;

        /// Writes the length of the advice-map value for `key` to `out_len`.
        ///
        /// Returns `Status::NotFound` when the map has no entry for `key`; `out_len` is not
        /// changed in that case.
        pub fn adv_map_value_len(key: *const Word, out_len: *mut u32) -> i32;

        /// Writes the advice-map value for `key` to `out`.
        ///
        /// `cap` is the element capacity of `out`. Returns `Status::NotFound` when the map has no
        /// entry for `key`, and `Status::CapacityTooSmall` when the value is longer than `cap`;
        /// `out` is not changed in either case. Call `adv_map_value_len` first to size the
        /// buffer.
        pub fn adv_map_value_read(key: *const Word, out: *mut Felt, cap: u32) -> i32;

        // MUTATIONS
        // ----------------------------------------------------------------------------------------
        //
        // The host buffers mutations. It applies them to the advice provider only after the
        // handler returns without a trap.

        /// Buffers `len` elements to extend the advice stack, ordered from the new top of the
        /// stack down.
        ///
        /// A size-limit violation traps.
        pub fn adv_stack_extend(vals: *const Felt, len: u32);

        /// Buffers an advice-map insertion of `len` elements under `key`.
        ///
        /// Inserting a key that exists with a different value makes the handler fail when the
        /// host applies the buffered mutations. A size-limit violation traps.
        pub fn adv_map_insert(key: *const Word, vals: *const Felt, len: u32);

        /// Buffers `len` inner nodes to extend the Merkle store.
        ///
        /// A size-limit violation traps.
        pub fn merkle_store_extend(nodes: *const MerkleNode, len: u32);

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
        use miden_core::{Felt as CoreFelt, field::PrimeField64};
        assert_eq!(FIELD_MODULUS, CoreFelt::ORDER_U64);
        // Cross-check the constant against its arithmetic definition.
        assert_eq!(FIELD_MODULUS as u128, (1u128 << 64) - (1u128 << 32) + 1);
    }

    #[test]
    fn wire_encoding_is_the_plain_residue() {
        // A canonical `u64` written by the host must decode to the field value it encodes, and
        // canonicalization of a lazy residue must produce the wire value. This pins the
        // plain-residue representation the pointer-based wire depends on.
        for value in [0u64, 1, FIELD_MODULUS - 1] {
            assert_eq!(Felt::new_unchecked(value).as_canonical_u64(), value);
        }
        // A lazy residue `p + 1` stands for `1` and canonicalizes to it.
        assert_eq!(Felt::new_unchecked(FIELD_MODULUS + 1).as_canonical_u64(), 1);
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
    fn wire_layouts_are_stable() {
        use core::mem::{align_of, size_of};

        assert_eq!(size_of::<Felt>(), 8);
        assert_eq!(align_of::<Felt>(), 8);
        assert_eq!(size_of::<Word>(), 32);
        assert_eq!(size_of::<MerkleNode>(), 96);
    }
}
