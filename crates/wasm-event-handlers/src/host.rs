//! The host context and the `miden:event/v1` host functions.
//!
//! Every host function follows the ABI contract in `miden-event-handler-abi`:
//!
//! - run-time conditions a correct handler can meet come back as `Status` codes;
//! - defects (bad pointer ranges, non-canonical field elements, mutation-limit violations) trap the
//!   handler through [`HostTrap`], which discards all buffered mutations.
//!
//! All pointers are offsets into the guest's exported linear memory. Range checks use checked
//! arithmetic; nothing wraps.

use alloc::{format, string::String, vec::Vec};

use miden_event_handler_abi::{FIELD_MODULUS, IMPORT_MODULE, Status, host_fn};
use miden_processor::{
    Felt, ProcessorState, Word,
    advice::{AdviceMap, AdviceMutation},
    crypto::{hash::Poseidon2, merkle::InnerNodeInfo},
};
use wasmi::{Caller, Engine, Linker, Memory, StoreLimits, StoreLimitsBuilder};

use crate::{error::HostTrap, module::WasmHandlerLimits};

// CONSTANTS
// ================================================================================================

/// The number of bytes of one serialized field element.
const FELT_BYTES: usize = 8;

/// The number of field elements in one serialized Merkle node (three words).
const MERKLE_NODE_FELTS: usize = 12;

/// The maximum number of bytes the host reads from a `fail` message. Longer messages are
/// truncated.
const MAX_FAIL_MSG_BYTES: u32 = 4096;

/// Fuel charged per field element a host call moves between the VM and the guest.
const FUEL_PER_FELT: u64 = 1;

/// Extra fuel charged per Merkle node for the host-side digest verification hash.
const FUEL_PER_MERKLE_NODE: u64 = 200;

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
///    store, runs the export, and consumes the store on one thread, and host functions
///    dereference the pointer only during that call, while the `&ProcessorState` borrow is
///    alive. The impls exist only to satisfy wasmi's trait bounds (the store-limiter closure
///    and the linker's store-data type parameter), not to enable cross-thread access.
/// 2. Even if a future wasmi internals change moved the store data, `ProcessorState` is `Sync`
///    (checked by a static assertion in the tests), so a shared reference reachable through
///    this pointer is safe to read from any thread.
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
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .memories(1)
                .tables(1)
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
    wasmi::Error::host(HostTrap(msg.into()))
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
fn memory(caller: &mut Caller<'_, HostCtx>) -> Result<Memory, wasmi::Error> {
    caller
        .get_export("memory")
        .and_then(wasmi::Extern::into_memory)
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

/// Charges fuel for host-side work; traps when the budget is exhausted.
///
/// wasmi meters guest instructions, but a host call costs the guest only its call overhead.
/// Without this charge, a small loop of host calls could make the host move data far out of
/// proportion to the guest's fuel budget. Charging per element moved (and per hash computed)
/// keeps the fuel budget a bound on the total work a handler causes. The charge applies to the
/// requested size, before validation, so failed probes are not free.
fn charge_fuel(caller: &mut Caller<'_, HostCtx>, cost: u64) -> Result<(), wasmi::Error> {
    let fuel = caller.get_fuel().expect("fuel metering is enabled in the engine config");
    let Some(rest) = fuel.checked_sub(cost) else {
        caller.set_fuel(0).expect("fuel metering is enabled in the engine config");
        return Err(trap("handler ran out of fuel during a host call"));
    };
    caller.set_fuel(rest).expect("fuel metering is enabled in the engine config");
    Ok(())
}

/// Adds `felts` field elements to the mutation budget; traps when the budget is exceeded.
fn charge_mutation(ctx: &mut HostCtx, felts: usize) -> Result<(), wasmi::Error> {
    ctx.mutation_felts = ctx.mutation_felts.saturating_add(felts);
    if ctx.mutation_felts > ctx.max_mutation_felts {
        return Err(trap(format!(
            "mutation size limit exceeded (at most {} field elements per event)",
            ctx.max_mutation_felts
        )));
    }
    Ok(())
}

/// The `Ok` status as the raw `i32` host functions return.
const OK: i32 = Status::Ok.as_raw();

// LINKER
// ================================================================================================

/// Builds the linker that provides the full `miden:event/v1` host function set.
///
/// # Panics
/// Panics on a duplicate definition, which would be a bug in this crate.
pub(crate) fn build_linker(engine: &Engine) -> Linker<HostCtx> {
    let mut linker = Linker::new(engine);

    // QUERIES
    // --------------------------------------------------------------------------------------------

    linker
        .func_wrap(IMPORT_MODULE, host_fn::STACK_DEPTH, |caller: Caller<'_, HostCtx>| {
            state(&caller).map(ProcessorState::stack_depth)
        })
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::STACK_GET,
            |caller: Caller<'_, HostCtx>, pos: u32| -> Result<u64, wasmi::Error> {
                Ok(state(&caller)?.get_stack_item(pos as usize).as_canonical_u64())
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::STACK_READ,
            |mut caller: Caller<'_, HostCtx>, start_pos: u32, out: u32, count: u32| {
                charge_fuel(&mut caller, u64::from(count) * FUEL_PER_FELT)?;
                let mem = memory(&mut caller)?;
                // Reject a bad output range before collecting, so `count` is bounded by the
                // guest memory size when the collection allocates.
                byte_range(mem.data(&caller).len(), out, FELT_BYTES, count)?;
                let state = state(&caller)?;
                let felts: Vec<Felt> = (0..count as usize)
                    .map(|idx| state.get_stack_item((start_pos as usize).saturating_add(idx)))
                    .collect();
                write_felts(mem.data_mut(&mut caller), out, &felts)
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(IMPORT_MODULE, host_fn::CLK, |caller: Caller<'_, HostCtx>| {
            state(&caller).map(|state| u64::from(state.clock()))
        })
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(IMPORT_MODULE, host_fn::CTX, |caller: Caller<'_, HostCtx>| {
            state(&caller).map(|state| u32::from(state.ctx()))
        })
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::MEM_GET,
            |mut caller: Caller<'_, HostCtx>, addr: u32, out: u32| {
                let state = state(&caller)?;
                let value = state.get_mem_value(state.ctx(), addr);
                match value {
                    Some(felt) => {
                        let mem = memory(&mut caller)?;
                        write_felts(mem.data_mut(&mut caller), out, &[felt])?;
                        Ok(OK)
                    },
                    None => Ok(Status::Uninit.as_raw()),
                }
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::MEM_READ,
            |mut caller: Caller<'_, HostCtx>, addr: u32, out: u32, count: u32| {
                charge_fuel(&mut caller, u64::from(count) * FUEL_PER_FELT)?;
                let mem = memory(&mut caller)?;
                byte_range(mem.data(&caller).len(), out, FELT_BYTES, count)?;
                if u64::from(addr) + u64::from(count) > u64::from(u32::MAX) + 1 {
                    return Ok(Status::OutOfBounds.as_raw());
                }
                let state = state(&caller)?;
                let ctx = state.ctx();
                let mut felts = Vec::with_capacity(count as usize);
                for idx in 0..count {
                    match state.get_mem_value(ctx, addr + idx) {
                        Some(felt) => felts.push(felt),
                        // The whole range must be written; use `mem_get` for per-cell checks.
                        None => return Ok(Status::Uninit.as_raw()),
                    }
                }
                write_felts(mem.data_mut(&mut caller), out, &felts)?;
                Ok(OK)
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(IMPORT_MODULE, host_fn::ADV_STACK_LEN, |caller: Caller<'_, HostCtx>| {
            state(&caller).map(|state| state.advice_provider().stack_len() as u32)
        })
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::ADV_STACK_READ,
            |mut caller: Caller<'_, HostCtx>, offset: u32, out: u32, count: u32| {
                charge_fuel(&mut caller, u64::from(count) * FUEL_PER_FELT)?;
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
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::ADV_MAP_VALUE_LEN,
            |mut caller: Caller<'_, HostCtx>, key: u32, out_len: u32| {
                let mem = memory(&mut caller)?;
                let key = read_word(mem.data(&caller), key)?;
                let Some(len) = state(&caller)?
                    .advice_provider()
                    .get_mapped_values(&key)
                    .map(|values| values.len() as u32)
                else {
                    return Ok(Status::NotFound.as_raw());
                };
                write_u32(mem.data_mut(&mut caller), out_len, len)?;
                Ok(OK)
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::ADV_MAP_VALUE_READ,
            |mut caller: Caller<'_, HostCtx>, key: u32, out: u32, cap: u32| {
                let mem = memory(&mut caller)?;
                let key = read_word(mem.data(&caller), key)?;
                let Some(len) =
                    state(&caller)?.advice_provider().get_mapped_values(&key).map(<[Felt]>::len)
                else {
                    return Ok(Status::NotFound.as_raw());
                };
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
            },
        )
        .expect("no duplicate host function definitions");

    // MUTATIONS
    // --------------------------------------------------------------------------------------------

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::ADV_STACK_EXTEND,
            |mut caller: Caller<'_, HostCtx>, vals: u32, len: u32| {
                charge_fuel(&mut caller, u64::from(len) * FUEL_PER_FELT)?;
                charge_mutation(caller.data_mut(), len as usize)?;
                let mem = memory(&mut caller)?;
                let felts = read_felts(mem.data(&caller), vals, len)?;
                caller
                    .data_mut()
                    .mutations
                    .push(AdviceMutation::extend_advice_stack_with(felts));
                Ok(())
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::ADV_MAP_INSERT,
            |mut caller: Caller<'_, HostCtx>, key: u32, vals: u32, len: u32| {
                charge_fuel(&mut caller, (u64::from(len) + 4) * FUEL_PER_FELT)?;
                charge_mutation(caller.data_mut(), (len as usize).saturating_add(4))?;
                let mem = memory(&mut caller)?;
                let key = read_word(mem.data(&caller), key)?;
                let values = read_felts(mem.data(&caller), vals, len)?;
                let mut map = AdviceMap::default();
                map.insert(key, values);
                caller.data_mut().mutations.push(AdviceMutation::extend_map(map));
                Ok(())
            },
        )
        .expect("no duplicate host function definitions");

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::MERKLE_STORE_EXTEND,
            |mut caller: Caller<'_, HostCtx>, nodes: u32, len: u32| {
                let felt_count = (len as usize).saturating_mul(MERKLE_NODE_FELTS);
                // Charge for the data moved and for the per-node digest verification hash.
                let fuel = (felt_count as u64).saturating_mul(FUEL_PER_FELT)
                    + u64::from(len).saturating_mul(FUEL_PER_MERKLE_NODE);
                charge_fuel(&mut caller, fuel)?;
                charge_mutation(caller.data_mut(), felt_count)?;
                let mem = memory(&mut caller)?;
                let felts = read_felts(mem.data(&caller), nodes, felt_count as u32)?;
                let nodes: Vec<InnerNodeInfo> = felts
                    .chunks_exact(MERKLE_NODE_FELTS)
                    .map(|chunk| {
                        let word = |at: usize| {
                            Word::new([chunk[at], chunk[at + 1], chunk[at + 2], chunk[at + 3]])
                        };
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
            },
        )
        .expect("no duplicate host function definitions");

    // FAILURE
    // --------------------------------------------------------------------------------------------

    linker
        .func_wrap(
            IMPORT_MODULE,
            host_fn::FAIL,
            |mut caller: Caller<'_, HostCtx>,
             msg_ptr: u32,
             msg_len: u32|
             -> Result<(), wasmi::Error> {
                let mem = memory(&mut caller)?;
                let len = msg_len.min(MAX_FAIL_MSG_BYTES);
                let range = byte_range(mem.data(&caller).len(), msg_ptr, 1, len)?;
                let msg = String::from_utf8_lossy(&mem.data(&caller)[range]).into_owned();
                caller.data_mut().error_msg = Some(msg);
                Err(trap("handler failed"))
            },
        )
        .expect("no duplicate host function definitions");

    linker
}
