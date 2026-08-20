//! The host context and the `miden:event/v1` host functions.
//!
//! Every host function follows the ABI contract in `miden-event-handler-abi`:
//!
//! - run-time conditions a correct handler can meet come back as `Status` codes;
//! - defects (bad pointer ranges, non-canonical field elements, mutation-limit violations) trap the
//!   handler through [`HostTrap`], which discards all buffered mutations.
//!
//! All pointers are offsets into the guest's exported linear memory. Range checks use checked
//! arithmetic; nothing wraps. Output pointers are validated before the host computes the
//! result, so a defect traps even when the call would come back with a status.

use alloc::{format, string::String, vec::Vec};

use miden_crypto::hash::{
    blake::Blake3_256,
    keccak::Keccak256,
    sha2::{Sha256, Sha512},
};
use miden_event_handler_abi::{FIELD_MODULUS, IMPORT_MODULE, Status, host_fn};
use miden_processor::{
    ContextId, Felt, ProcessorState, Word,
    advice::{AdviceError, AdviceMap, AdviceMutation},
    crypto::{hash::Poseidon2, merkle::InnerNodeInfo},
};
use wasmi::{Caller, Engine, Linker, Memory, StoreLimits, StoreLimitsBuilder};

use crate::{
    error::{HostTrap, HostTrapKind},
    module::WasmHandlerLimits,
};

// CONSTANTS
// ================================================================================================

/// The number of bytes of one serialized field element.
const FELT_BYTES: usize = 8;

/// The number of field elements in one serialized Merkle node (three words).
const MERKLE_NODE_FELTS: usize = 12;

/// The number of field elements in the Poseidon2 permutation state.
const POSEIDON2_STATE_FELTS: usize = 12;

/// The maximum number of bytes the host reads from a `fail` message. Longer messages are
/// truncated.
const MAX_FAIL_MSG_BYTES: u32 = 4096;

/// Fuel charged per field element a host call moves between the VM and the guest.
///
/// Calibrated with `benches/handler_call.rs` (Apple M-series, wasmi 1.1): one fuel unit of
/// guest execution costs ~0.8 ns and one host-moved felt costs ~0.7-0.9 ns, so a 1:1 charge
/// makes host-moved data cost the guest about as much fuel as moving it itself would. The
/// instantiation charge in `module.rs` uses the same rate per 8 bytes.
pub(crate) const FUEL_PER_FELT: u64 = 1;

/// Flat fuel charged on entry to every host call, for the guest-to-host transition.
///
/// The transition costs tens of nanoseconds (one fuel unit is ~0.8 ns, see [`FUEL_PER_FELT`]),
/// so without this charge a loop of zero-work host calls would cost the guest only its own
/// `call` instructions while it burns a host transition per iteration.
const HOST_CALL_BASE_FUEL: u64 = 25;

/// Fuel charged per Poseidon2 permutation the host computes for the guest.
///
/// Calibrated with `benches/handler_call.rs` (Apple M-series): one merge measures ~1.5 us,
/// which is ~1900 fuel units at ~0.8 ns per unit.
const FUEL_PER_POSEIDON2_PERM: u64 = 2000;

/// Extra fuel charged per Merkle node for the host-side digest verification hash.
///
/// One node costs one Poseidon2 merge.
const FUEL_PER_MERKLE_NODE: u64 = FUEL_PER_POSEIDON2_PERM;

/// Flat fuel charged per byte-hash call on top of [`HOST_CALL_BASE_FUEL`], for the digest
/// setup and finalization.
const HASH_BASE_FUEL: u64 = 100;

/// Fuel charged per input byte of `keccak256`.
///
/// Measured at ~1.1 ns per byte with `benches/handler_call.rs` (Apple M-series).
const FUEL_PER_KECCAK_BYTE: u64 = 2;

/// Fuel charged per input byte of `sha256`.
///
/// Measured at ~0.5 ns per byte with `benches/handler_call.rs` (Apple M-series).
const FUEL_PER_SHA256_BYTE: u64 = 1;

/// Fuel charged per input byte of `sha512`.
///
/// Measured at ~0.7 ns per byte with `benches/handler_call.rs` (Apple M-series).
const FUEL_PER_SHA512_BYTE: u64 = 1;

/// Fuel charged per input byte of `blake3`.
///
/// Measured at ~0.6 ns per byte with `benches/handler_call.rs` (Apple M-series).
const FUEL_PER_BLAKE3_BYTE: u64 = 1;

// HOST CONTEXT
// ================================================================================================

/// A type-erased pointer to the [`ProcessorState`] borrowed for the duration of one handler
/// call.
///
/// # Safety
///
/// Two facts make the `Send`/`Sync` impls sound:
///
/// 1. The pointer never actually crosses a thread in use. `WasmHandlerModule::call` creates the
///    store, runs the export, and consumes the store on one thread, and host functions dereference
///    the pointer only during that call, while the `&ProcessorState` borrow is alive. The impls
///    exist only to satisfy wasmi's trait bounds (the store-limiter closure and the linker's
///    store-data type parameter), not to enable cross-thread access.
/// 2. Even if a future wasmi internals change moved the store data, `ProcessorState` is `Sync`
///    (checked by a static assertion in the tests), so a shared reference reachable through this
///    pointer is safe to read from any thread.
pub(crate) struct StatePtr(*const ProcessorState<'static>);

// SAFETY: see the type-level comment.
unsafe impl Send for StatePtr {}
// SAFETY: see the type-level comment.
unsafe impl Sync for StatePtr {}

/// The per-call store data: the processor state, the buffered mutations, the mutation budget,
/// the recorded `fail` message, and the resource limits.
pub(crate) struct HostCtx {
    state: StatePtr,
    /// The mutations the handler buffered so far. Returned to the processor only when the
    /// handler returns without a trap.
    pub mutations: Vec<AdviceMutation>,
    /// The number of field elements across all buffered mutations.
    mutation_felts: usize,
    /// The maximum for `mutation_felts`; going over it traps.
    max_mutation_felts: usize,
    /// The message the guest recorded through `fail`, if any.
    pub error_msg: Option<String>,
    /// The wasmi resource limits (linear memory size, instance/table counts).
    pub limits: StoreLimits,
    /// The guest's exported linear memory, resolved once after instantiation. `None` when the
    /// module exports no memory under the name `memory`.
    pub memory: Option<Memory>,
}

impl HostCtx {
    /// Creates the store data for one handler call.
    ///
    /// `state` may be null for the load-time dry-run instantiation, during which no guest code
    /// runs.
    pub fn new(state: *const ProcessorState<'static>, limits: &WasmHandlerLimits) -> Self {
        Self {
            state: StatePtr(state),
            mutations: Vec::new(),
            mutation_felts: 0,
            max_mutation_felts: limits.max_mutation_felts,
            error_msg: None,
            memory: None,
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .memories(1)
                .tables(1)
                // Tables are allocated eagerly at instantiation, before any fuel applies, so
                // the element count needs its own cap.
                .table_elements(limits.max_table_elements)
                .instances(1)
                // A failed grow traps the untrusted handler instead of returning -1.
                .trap_on_grow_failure(true)
                .build(),
        }
    }
}

// HELPERS
// ================================================================================================

/// Creates a wasmi trap with the given defect message.
fn trap(msg: impl Into<String>) -> wasmi::Error {
    wasmi::Error::host(HostTrap {
        msg: msg.into(),
        kind: HostTrapKind::Defect,
    })
}

/// Returns the processor state for the current call.
fn state<'c>(caller: &'c Caller<'_, HostCtx>) -> Result<&'c ProcessorState<'c>, wasmi::Error> {
    let ptr = caller.data().state.0;
    if ptr.is_null() {
        return Err(trap("processor state is not available"));
    }
    // SAFETY: see [`StatePtr`]. The returned borrow cannot outlive `caller`, and `caller` cannot
    // outlive the handler call that keeps the underlying `&ProcessorState` alive.
    Ok(unsafe { &*ptr.cast::<ProcessorState<'c>>() })
}

/// Returns the guest's exported linear memory.
///
/// The handle is resolved once per instantiation, so this is a field read, not an export lookup.
fn memory(caller: &mut Caller<'_, HostCtx>) -> Result<Memory, wasmi::Error> {
    caller
        .data()
        .memory
        .ok_or_else(|| trap("handler module does not export its linear memory as 'memory'"))
}

/// Computes the byte range `[ptr, ptr + count * elem_size)` and checks it against the guest
/// memory length. Overflow and out-of-range pointers trap.
fn byte_range(
    mem_len: usize,
    ptr: u32,
    elem_size: usize,
    count: u32,
) -> Result<core::ops::Range<usize>, wasmi::Error> {
    let len = (count as u64)
        .checked_mul(elem_size as u64)
        .ok_or_else(|| trap("pointer range length overflows"))?;
    let start = ptr as u64;
    let end = start.checked_add(len).ok_or_else(|| trap("pointer range end overflows"))?;
    if end > mem_len as u64 {
        return Err(trap(format!(
            "pointer range [{start}, {end}) is outside the guest memory of {mem_len} bytes"
        )));
    }
    Ok(start as usize..end as usize)
}

/// Reads `count` field elements from guest memory and validates that each one is canonical.
fn read_felts(data: &[u8], ptr: u32, count: u32) -> Result<Vec<Felt>, wasmi::Error> {
    let range = byte_range(data.len(), ptr, FELT_BYTES, count)?;
    let mut out = Vec::with_capacity(count as usize);
    for chunk in data[range].chunks_exact(FELT_BYTES) {
        let raw = u64::from_le_bytes(chunk.try_into().expect("chunk is 8 bytes"));
        if raw >= FIELD_MODULUS {
            return Err(trap(format!("non-canonical field element {raw}")));
        }
        out.push(Felt::new_unchecked(raw));
    }
    Ok(out)
}

/// Converts a `u64` the guest passed by value into a field element; a non-canonical value traps.
fn felt_arg(raw: u64) -> Result<Felt, wasmi::Error> {
    if raw >= FIELD_MODULUS {
        return Err(trap(format!("non-canonical field element {raw}")));
    }
    Ok(Felt::new_unchecked(raw))
}

/// Reads one word (four field elements) from guest memory.
fn read_word(data: &[u8], ptr: u32) -> Result<Word, wasmi::Error> {
    let felts = read_felts(data, ptr, 4)?;
    Ok(Word::new([felts[0], felts[1], felts[2], felts[3]]))
}

/// Writes field elements into guest memory in canonical little-endian form.
fn write_felts(data: &mut [u8], ptr: u32, felts: &[Felt]) -> Result<(), wasmi::Error> {
    let range = byte_range(data.len(), ptr, FELT_BYTES, felts.len() as u32)?;
    for (chunk, felt) in data[range].chunks_exact_mut(FELT_BYTES).zip(felts) {
        chunk.copy_from_slice(&felt.as_canonical_u64().to_le_bytes());
    }
    Ok(())
}

/// Writes one little-endian `u32` into guest memory.
fn write_u32(data: &mut [u8], ptr: u32, value: u32) -> Result<(), wasmi::Error> {
    let range = byte_range(data.len(), ptr, 4, 1)?;
    data[range].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Writes raw bytes into guest memory.
fn write_bytes(data: &mut [u8], ptr: u32, bytes: &[u8]) -> Result<(), wasmi::Error> {
    let range = byte_range(data.len(), ptr, 1, bytes.len() as u32)?;
    data[range].copy_from_slice(bytes);
    Ok(())
}

/// Charges fuel for host-side work; traps when the budget is exhausted.
///
/// wasmi meters guest instructions, but a host call costs the guest only its call overhead.
/// Every host function therefore charges [`HOST_CALL_BASE_FUEL`] for the transition plus the
/// cost of the work it was asked to do (per element moved, per hash computed). Charges land
/// before the work and before validation, so failed probes are not free. The one exception is
/// `fail`, which always ends the call, so a charge would change nothing.
fn charge_fuel(caller: &mut Caller<'_, HostCtx>, cost: u64) -> Result<(), wasmi::Error> {
    let fuel = caller.get_fuel().expect("fuel metering is enabled in the engine config");
    let Some(rest) = fuel.checked_sub(cost) else {
        caller.set_fuel(0).expect("fuel metering is enabled in the engine config");
        return Err(wasmi::Error::host(HostTrap {
            msg: "handler ran out of fuel during a host call".into(),
            kind: HostTrapKind::OutOfFuel,
        }));
    };
    caller.set_fuel(rest).expect("fuel metering is enabled in the engine config");
    Ok(())
}

/// Adds `felts` field elements to the mutation budget; traps when the budget is exceeded.
fn charge_mutation(ctx: &mut HostCtx, felts: usize) -> Result<(), wasmi::Error> {
    ctx.mutation_felts = ctx.mutation_felts.saturating_add(felts);
    if ctx.mutation_felts > ctx.max_mutation_felts {
        return Err(wasmi::Error::host(HostTrap {
            msg: format!(
                "mutation size limit exceeded (at most {} field elements per event)",
                ctx.max_mutation_felts
            ),
            kind: HostTrapKind::MutationLimit,
        }));
    }
    Ok(())
}

/// The `Ok` status as the raw `i32` host functions return.
const OK: i32 = Status::Ok.as_raw();

// QUERIES
// ================================================================================================

/// Returns the depth of the operand stack.
fn stack_depth(mut caller: Caller<'_, HostCtx>) -> Result<u32, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL)?;
    state(&caller).map(ProcessorState::stack_depth)
}

/// Returns the operand-stack element at position `pos` in canonical form.
fn stack_get(mut caller: Caller<'_, HostCtx>, pos: u32) -> Result<u64, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + FUEL_PER_FELT)?;
    Ok(state(&caller)?.get_stack_item(pos as usize).as_canonical_u64())
}

/// Writes the `count` operand-stack elements at positions `start_pos..start_pos + count` to
/// `out`, ordered from the top of the stack down.
fn stack_read(
    mut caller: Caller<'_, HostCtx>,
    start_pos: u32,
    out: u32,
    count: u32,
) -> Result<(), wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + u64::from(count) * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    // Reject a bad output range before collecting, so `count` is bounded by the
    // guest memory size when the collection allocates.
    byte_range(mem.data(&caller).len(), out, FELT_BYTES, count)?;
    let state = state(&caller)?;
    let felts: Vec<Felt> = (0..count as usize)
        .map(|idx| state.get_stack_item((start_pos as usize).saturating_add(idx)))
        .collect();
    write_felts(mem.data_mut(&mut caller), out, &felts)
}

/// Returns the current clock cycle.
fn clk(mut caller: Caller<'_, HostCtx>) -> Result<u64, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL)?;
    state(&caller).map(|state| u64::from(state.clock()))
}

/// Returns the current execution context ID.
fn ctx(mut caller: Caller<'_, HostCtx>) -> Result<u32, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL)?;
    state(&caller).map(|state| u32::from(state.ctx()))
}

/// Writes the memory element at address `addr` of the current context to `out`, or returns
/// [`Status::Uninit`] when the cell was never written.
fn mem_get(mut caller: Caller<'_, HostCtx>, addr: u32, out: u32) -> Result<i32, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    // Output pointers are validated before the lookup, so a defect traps even when the
    // result would be a status.
    byte_range(mem.data(&caller).len(), out, FELT_BYTES, 1)?;
    let state = state(&caller)?;
    match state.get_mem_value(state.ctx(), addr) {
        Some(felt) => {
            write_felts(mem.data_mut(&mut caller), out, &[felt])?;
            Ok(OK)
        },
        None => Ok(Status::Uninit.as_raw()),
    }
}

/// Writes the `count` memory elements at addresses `addr..addr + count` to `out`, reading from
/// `ctx` or, when it is `None`, from the current context. Returns a status when the range is out
/// of bounds or any cell is uninitialized.
///
/// `mem_read` and `mem_read_ctx` are both this function, so the single charge here is the whole
/// fuel charge of one call.
fn mem_read_range(
    caller: &mut Caller<'_, HostCtx>,
    ctx: Option<ContextId>,
    addr: u32,
    out: u32,
    count: u32,
) -> Result<i32, wasmi::Error> {
    charge_fuel(caller, HOST_CALL_BASE_FUEL + u64::from(count) * FUEL_PER_FELT)?;
    let mem = memory(caller)?;
    byte_range(mem.data(&caller).len(), out, FELT_BYTES, count)?;
    if u64::from(addr) + u64::from(count) > u64::from(u32::MAX) + 1 {
        return Ok(Status::OutOfBounds.as_raw());
    }
    let state = state(caller)?;
    let ctx = ctx.unwrap_or_else(|| state.ctx());
    let mut felts = Vec::with_capacity(count as usize);
    for idx in 0..count {
        match state.get_mem_value(ctx, addr + idx) {
            Some(felt) => felts.push(felt),
            // The whole range must be written; use `mem_get` for per-cell checks.
            None => return Ok(Status::Uninit.as_raw()),
        }
    }
    write_felts(mem.data_mut(caller), out, &felts)?;
    Ok(OK)
}

/// Writes the `count` memory elements at addresses `addr..addr + count` of the current context
/// to `out`, or returns a status when the range is out of bounds or any cell is uninitialized.
fn mem_read(
    mut caller: Caller<'_, HostCtx>,
    addr: u32,
    out: u32,
    count: u32,
) -> Result<i32, wasmi::Error> {
    mem_read_range(&mut caller, None, addr, out, count)
}

/// Writes the `count` memory elements at addresses `addr..addr + count` of context `ctx` to
/// `out`, or returns a status when the range is out of bounds or any cell is uninitialized.
fn mem_read_ctx(
    mut caller: Caller<'_, HostCtx>,
    ctx: u32,
    addr: u32,
    out: u32,
    count: u32,
) -> Result<i32, wasmi::Error> {
    mem_read_range(&mut caller, Some(ContextId::from(ctx)), addr, out, count)
}

/// Charges the fuel of one Merkle-store lookup and decodes its arguments. Returns the guest
/// memory with the root word, the depth, and the index.
fn merkle_lookup_args(
    caller: &mut Caller<'_, HostCtx>,
    root: u32,
    depth: u32,
    index: u64,
) -> Result<(Memory, Word, Felt, Felt), wasmi::Error> {
    // The lookup walks one level per depth unit, and moves the root in and the node out.
    charge_fuel(caller, HOST_CALL_BASE_FUEL + u64::from(depth) * FUEL_PER_FELT + 8)?;
    let mem = memory(caller)?;
    let root = read_word(mem.data(&caller), root)?;
    let index = felt_arg(index)?;
    Ok((mem, root, Felt::new_unchecked(u64::from(depth)), index))
}

/// Writes the Merkle-store node of the tree with root `root` at `depth`/`index` to `out`, or
/// returns [`Status::NotFound`] when the store has no such tree or no node at this position.
fn merkle_get_node(
    mut caller: Caller<'_, HostCtx>,
    root: u32,
    depth: u32,
    index: u64,
    out: u32,
) -> Result<i32, wasmi::Error> {
    let (mem, root, depth, index) = merkle_lookup_args(&mut caller, root, depth, index)?;
    // Validate the output pointer before the lookup; see `mem_get`.
    byte_range(mem.data(&caller).len(), out, FELT_BYTES, 4)?;
    let node = state(&caller)?.advice_provider().get_tree_node(root, depth, index);
    match node {
        Ok(node) => {
            write_felts(mem.data_mut(&mut caller), out, node.as_elements())?;
            Ok(OK)
        },
        // A position outside the valid range for a Merkle tree is a defect, not a miss.
        Err(AdviceError::InvalidMerkleTreeNodeIndex { .. }) => {
            Err(trap("invalid merkle node depth/index"))
        },
        Err(AdviceError::MerkleStoreLookupFailed(_)) => Ok(Status::NotFound.as_raw()),
        Err(err) => Err(trap(format!("{err}"))),
    }
}

/// Returns `1` when the Merkle store has a path for the node of the tree with root `root` at
/// `depth`/`index`, and `0` when it has not.
fn merkle_has_path(
    mut caller: Caller<'_, HostCtx>,
    root: u32,
    depth: u32,
    index: u64,
) -> Result<i32, wasmi::Error> {
    let (_mem, root, depth, index) = merkle_lookup_args(&mut caller, root, depth, index)?;
    match state(&caller)?.advice_provider().has_merkle_path(root, depth, index) {
        Ok(has_path) => Ok(i32::from(has_path)),
        Err(AdviceError::InvalidMerkleTreeNodeIndex { .. }) => {
            Err(trap("invalid merkle node depth/index"))
        },
        Err(err) => Err(trap(format!("{err}"))),
    }
}

/// Returns the number of elements on the advice stack.
fn adv_stack_len(mut caller: Caller<'_, HostCtx>) -> Result<u32, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL)?;
    state(&caller).map(|state| state.advice_provider().stack_len() as u32)
}

/// Writes `count` advice-stack elements starting at `offset` to `out`, or returns
/// [`Status::OutOfBounds`] when the range goes past the advice-stack length.
fn adv_stack_read(
    mut caller: Caller<'_, HostCtx>,
    offset: u32,
    out: u32,
    count: u32,
) -> Result<i32, wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + u64::from(count) * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    byte_range(mem.data(&caller).len(), out, FELT_BYTES, count)?;
    let provider = state(&caller)?.advice_provider();
    let start = offset as usize;
    let Some(end) = start.checked_add(count as usize) else {
        return Ok(Status::OutOfBounds.as_raw());
    };
    if end > provider.stack_len() {
        return Ok(Status::OutOfBounds.as_raw());
    }
    let felts: Vec<Felt> =
        provider.stack_iter().skip(start).take(count as usize).copied().collect();
    write_felts(mem.data_mut(&mut caller), out, &felts)?;
    Ok(OK)
}

/// Writes the length of the advice-map value for `key` to `out_len`, or returns
/// [`Status::NotFound`] when the map has no entry for `key`.
fn adv_map_value_len(
    mut caller: Caller<'_, HostCtx>,
    key: u32,
    out_len: u32,
) -> Result<i32, wasmi::Error> {
    // The call reads a key word and performs a map lookup.
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + 4 * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    // Validate the output pointer before the lookup; see `mem_get`.
    byte_range(mem.data(&caller).len(), out_len, 4, 1)?;
    let key = read_word(mem.data(&caller), key)?;
    let Some(len) = state(&caller)?.advice_provider().get_mapped_values(&key).map(<[Felt]>::len)
    else {
        return Ok(Status::NotFound.as_raw());
    };
    let len = u32::try_from(len).map_err(|_| trap("advice-map value length overflows u32"))?;
    write_u32(mem.data_mut(&mut caller), out_len, len)?;
    Ok(OK)
}

/// Writes the advice-map value for `key` to the `cap`-element buffer `out` and its element
/// count to `out_len`, or returns a status when the map has no entry for `key` or the value is
/// longer than `cap`. The count is written on `CapacityTooSmall` too, so one retry with a
/// grown buffer suffices.
fn adv_map_value_read(
    mut caller: Caller<'_, HostCtx>,
    key: u32,
    out: u32,
    cap: u32,
    out_len: u32,
) -> Result<i32, wasmi::Error> {
    // The key read and the map lookup are charged up front, so a probe that comes back
    // `NotFound` or `CapacityTooSmall` still pays for the work it causes. The value copy is
    // charged below, when its size is known.
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + 4 * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    let data_len = mem.data(&caller).len();
    // Validate both output pointers before the lookup; see `mem_get`.
    byte_range(data_len, out, FELT_BYTES, cap)?;
    byte_range(data_len, out_len, 4, 1)?;
    let key = read_word(mem.data(&caller), key)?;
    let Some(len) = state(&caller)?.advice_provider().get_mapped_values(&key).map(<[Felt]>::len)
    else {
        return Ok(Status::NotFound.as_raw());
    };
    let count = u32::try_from(len).map_err(|_| trap("advice-map value length overflows u32"))?;
    write_u32(mem.data_mut(&mut caller), out_len, count)?;
    if len > cap as usize {
        return Ok(Status::CapacityTooSmall.as_raw());
    }
    charge_fuel(&mut caller, len as u64 * FUEL_PER_FELT)?;
    let values = state(&caller)?
        .advice_provider()
        .get_mapped_values(&key)
        .expect("the entry was present above")
        .to_vec();
    write_felts(mem.data_mut(&mut caller), out, &values)?;
    Ok(OK)
}

// HASHING
// ================================================================================================

/// Writes the Poseidon2 merge of the two words at `pair` to `out`, using `domain`.
fn poseidon2_merge(
    mut caller: Caller<'_, HostCtx>,
    pair: u32,
    domain: u64,
    out: u32,
) -> Result<(), wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + FUEL_PER_POSEIDON2_PERM + 12 * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    let felts = read_felts(mem.data(&caller), pair, 8)?;
    let word = |at: usize| Word::new([felts[at], felts[at + 1], felts[at + 2], felts[at + 3]]);
    let pair = [word(0), word(4)];
    // A merge in domain zero is the plain merge: the domain goes into a capacity element that
    // is already zero.
    let digest = Poseidon2::merge_in_domain(&pair, felt_arg(domain)?);
    write_felts(mem.data_mut(&mut caller), out, digest.as_elements())
}

/// Writes the Poseidon2 sequential hash of the `count` field elements at `elems` to `out`, using
/// `domain`.
fn poseidon2_hash(
    mut caller: Caller<'_, HostCtx>,
    elems: u32,
    count: u32,
    domain: u64,
    out: u32,
) -> Result<(), wasmi::Error> {
    // The sponge absorbs eight elements per permutation, and always runs a final one.
    let permutations = u64::from(count) / 8 + 1;
    let fuel = HOST_CALL_BASE_FUEL
        + FUEL_PER_POSEIDON2_PERM * permutations
        + u64::from(count) * FUEL_PER_FELT;
    charge_fuel(&mut caller, fuel)?;
    let mem = memory(&mut caller)?;
    let felts = read_felts(mem.data(&caller), elems, count)?;
    // A hash in domain zero is the plain hash: the domain goes into a capacity element that is
    // already zero, and the empty-input marker fires only for a nonzero domain.
    let digest = Poseidon2::hash_elements_in_domain(&felts, felt_arg(domain)?);
    write_felts(mem.data_mut(&mut caller), out, digest.as_elements())
}

/// Applies the Poseidon2 permutation to the 12-element state at `state_ptr`, in place.
fn poseidon2_permute(mut caller: Caller<'_, HostCtx>, state_ptr: u32) -> Result<(), wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + FUEL_PER_POSEIDON2_PERM + 24 * FUEL_PER_FELT)?;
    let mem = memory(&mut caller)?;
    let felts = read_felts(mem.data(&caller), state_ptr, POSEIDON2_STATE_FELTS as u32)?;
    let mut sponge: [Felt; POSEIDON2_STATE_FELTS] =
        felts.try_into().expect("read_felts returned the requested element count");
    Poseidon2::apply_permutation(&mut sponge);
    write_felts(mem.data_mut(&mut caller), state_ptr, &sponge)
}

/// Hashes the `len` bytes at `data` with `hash` and writes the digest to `out`.
fn hash_bytes<const N: usize>(
    mut caller: Caller<'_, HostCtx>,
    data: u32,
    len: u32,
    out: u32,
    fuel_per_byte: u64,
    hash: impl Fn(&[u8]) -> [u8; N],
) -> Result<(), wasmi::Error> {
    charge_fuel(
        &mut caller,
        HOST_CALL_BASE_FUEL + HASH_BASE_FUEL + u64::from(len) * fuel_per_byte,
    )?;
    let mem = memory(&mut caller)?;
    let range = byte_range(mem.data(&caller).len(), data, 1, len)?;
    let digest = hash(&mem.data(&caller)[range]);
    write_bytes(mem.data_mut(&mut caller), out, &digest)
}

/// Writes the Keccak-256 digest of the `len` bytes at `data` to `out`.
fn keccak256(
    caller: Caller<'_, HostCtx>,
    data: u32,
    len: u32,
    out: u32,
) -> Result<(), wasmi::Error> {
    hash_bytes(caller, data, len, out, FUEL_PER_KECCAK_BYTE, |bytes| {
        *Keccak256::hash(bytes).as_bytes()
    })
}

/// Writes the SHA-256 digest of the `len` bytes at `data` to `out`.
fn sha256(caller: Caller<'_, HostCtx>, data: u32, len: u32, out: u32) -> Result<(), wasmi::Error> {
    hash_bytes(caller, data, len, out, FUEL_PER_SHA256_BYTE, |bytes| {
        *Sha256::hash(bytes).as_bytes()
    })
}

/// Writes the SHA-512 digest of the `len` bytes at `data` to `out`.
fn sha512(caller: Caller<'_, HostCtx>, data: u32, len: u32, out: u32) -> Result<(), wasmi::Error> {
    hash_bytes(caller, data, len, out, FUEL_PER_SHA512_BYTE, |bytes| {
        *Sha512::hash(bytes).as_bytes()
    })
}

/// Writes the BLAKE3 digest of the `len` bytes at `data` to `out`.
fn blake3(caller: Caller<'_, HostCtx>, data: u32, len: u32, out: u32) -> Result<(), wasmi::Error> {
    hash_bytes(caller, data, len, out, FUEL_PER_BLAKE3_BYTE, |bytes| {
        *Blake3_256::hash(bytes).as_bytes()
    })
}

// MUTATIONS
// ================================================================================================

/// Buffers `len` elements to extend the advice stack, ordered from the new top of the stack down.
fn adv_stack_extend(
    mut caller: Caller<'_, HostCtx>,
    vals: u32,
    len: u32,
) -> Result<(), wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + u64::from(len) * FUEL_PER_FELT)?;
    // An empty extension changes nothing; buffering a record for it would let a loop
    // accumulate mutation records without touching the mutation budget.
    if len == 0 {
        return Ok(());
    }
    charge_mutation(caller.data_mut(), len as usize)?;
    let mem = memory(&mut caller)?;
    let felts = read_felts(mem.data(&caller), vals, len)?;
    caller
        .data_mut()
        .mutations
        .push(AdviceMutation::extend_advice_stack_with(felts));
    Ok(())
}

/// Buffers an advice-map insertion of `len` elements under `key`.
fn adv_map_insert(
    mut caller: Caller<'_, HostCtx>,
    key: u32,
    vals: u32,
    len: u32,
) -> Result<(), wasmi::Error> {
    charge_fuel(&mut caller, HOST_CALL_BASE_FUEL + (u64::from(len) + 4) * FUEL_PER_FELT)?;
    charge_mutation(caller.data_mut(), (len as usize).saturating_add(4))?;
    let mem = memory(&mut caller)?;
    let key = read_word(mem.data(&caller), key)?;
    let values = read_felts(mem.data(&caller), vals, len)?;
    let mut map = AdviceMap::default();
    map.insert(key, values);
    caller.data_mut().mutations.push(AdviceMutation::extend_map(map));
    Ok(())
}

/// Buffers `len` inner nodes to extend the Merkle store.
fn merkle_store_extend(
    mut caller: Caller<'_, HostCtx>,
    nodes: u32,
    len: u32,
) -> Result<(), wasmi::Error> {
    let felt_count = (len as usize).saturating_mul(MERKLE_NODE_FELTS);
    // Charge for the data moved and for the per-node digest verification hash.
    let fuel = HOST_CALL_BASE_FUEL
        + (felt_count as u64).saturating_mul(FUEL_PER_FELT)
        + u64::from(len).saturating_mul(FUEL_PER_MERKLE_NODE);
    charge_fuel(&mut caller, fuel)?;
    // An empty extension changes nothing; see `adv_stack_extend`.
    if len == 0 {
        return Ok(());
    }
    charge_mutation(caller.data_mut(), felt_count)?;
    // The fuel and mutation charges above trap long before the count can leave the `u32` range,
    // so this conversion cannot fail; it must not wrap if a limit ever grows.
    let felt_count = u32::try_from(felt_count).map_err(|_| trap("merkle node count overflows"))?;
    let mem = memory(&mut caller)?;
    let felts = read_felts(mem.data(&caller), nodes, felt_count)?;
    let nodes: Vec<InnerNodeInfo> = felts
        .chunks_exact(MERKLE_NODE_FELTS)
        .map(|chunk| {
            let word =
                |at: usize| Word::new([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]]);
            InnerNodeInfo {
                value: word(0),
                left: word(4),
                right: word(8),
            }
        })
        .collect();
    // The Merkle store does not verify digests on extension, so reject inconsistent
    // nodes from the untrusted guest here.
    for node in &nodes {
        if Poseidon2::merge(&[node.left, node.right]) != node.value {
            return Err(trap("merkle node digest does not match hash(left, right)"));
        }
    }
    caller.data_mut().mutations.push(AdviceMutation::extend_merkle_store(nodes));
    Ok(())
}

// FAILURE
// ================================================================================================

/// Records the guest message as the handler's error message and traps.
///
/// This call charges no fuel: it always ends the call, so it cannot amplify work.
fn fail(mut caller: Caller<'_, HostCtx>, msg_ptr: u32, msg_len: u32) -> Result<(), wasmi::Error> {
    let mem = memory(&mut caller)?;
    let len = msg_len.min(MAX_FAIL_MSG_BYTES);
    let range = byte_range(mem.data(&caller).len(), msg_ptr, 1, len)?;
    let msg = String::from_utf8_lossy(&mem.data(&caller)[range]).into_owned();
    caller.data_mut().error_msg = Some(msg);
    Err(trap("handler failed"))
}

// LINKER
// ================================================================================================

/// Defines the given host functions in the linker under the [`IMPORT_MODULE`] namespace.
macro_rules! register {
    ($linker:ident, $($name:path => $func:path),+ $(,)?) => {
        $(
            $linker
                .func_wrap(IMPORT_MODULE, $name, $func)
                .expect("no duplicate host function definitions");
        )+
    };
}

/// Builds the linker that provides the full `miden:event/v1` host function set.
///
/// # Panics
/// Panics on a duplicate definition, which would be a bug in this crate.
pub(crate) fn build_linker(engine: &Engine) -> Linker<HostCtx> {
    let mut linker = Linker::new(engine);

    register!(linker,
        // queries
        host_fn::STACK_DEPTH => stack_depth,
        host_fn::STACK_GET => stack_get,
        host_fn::STACK_READ => stack_read,
        host_fn::CLK => clk,
        host_fn::CTX => ctx,
        host_fn::MEM_GET => mem_get,
        host_fn::MEM_READ => mem_read,
        host_fn::MEM_READ_CTX => mem_read_ctx,
        host_fn::MERKLE_GET_NODE => merkle_get_node,
        host_fn::MERKLE_HAS_PATH => merkle_has_path,
        // hashing
        host_fn::POSEIDON2_MERGE => poseidon2_merge,
        host_fn::POSEIDON2_HASH => poseidon2_hash,
        host_fn::POSEIDON2_PERMUTE => poseidon2_permute,
        host_fn::KECCAK256 => keccak256,
        host_fn::SHA256 => sha256,
        host_fn::SHA512 => sha512,
        host_fn::BLAKE3 => blake3,
        // advice-provider queries
        host_fn::ADV_STACK_LEN => adv_stack_len,
        host_fn::ADV_STACK_READ => adv_stack_read,
        host_fn::ADV_MAP_VALUE_LEN => adv_map_value_len,
        host_fn::ADV_MAP_VALUE_READ => adv_map_value_read,
        // mutations
        host_fn::ADV_STACK_EXTEND => adv_stack_extend,
        host_fn::ADV_MAP_INSERT => adv_map_insert,
        host_fn::MERKLE_STORE_EXTEND => merkle_store_extend,
        // failure
        host_fn::FAIL => fail,
    );

    linker
}
