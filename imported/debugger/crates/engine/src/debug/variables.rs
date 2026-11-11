use alloc::{
    collections::BTreeMap,
    rc::Rc,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::cell::RefCell;

use miden_assembly_syntax::ast::{
    DebugFrameBase, DebugLocationExpression, DebugLocationExpressionOp, DebugVarInfo,
    DebugVarLocation, types::Type,
};
use miden_core::Felt;
use miden_processor::{ContextId, FastProcessor, trace::RowIndex};

use super::InvocationId;

type DebugVarEvents = Rc<RefCell<BTreeMap<RowIndex, Vec<DebugVarInfo>>>>;
type CapturedDebugValues = Rc<RefCell<BTreeMap<(RowIndex, Arc<str>), Vec<Felt>>>>;

/// A snapshot of a debug variable at a specific clock cycle.
#[derive(Debug, Clone)]
pub struct DebugVarSnapshot {
    /// The clock cycle when this variable info was recorded.
    pub clk: RowIndex,
    /// The debug variable information.
    pub info: DebugVarInfo,
}

/// A variable resolved in its owning invocation's retained execution context.
#[derive(Debug, Clone)]
pub struct ResolvedDebugVariable {
    pub raw: Option<Felt>,
    pub value: String,
    pub type_name: String,
}

#[derive(Default)]
struct InvocationVariables {
    variables: BTreeMap<String, DebugVarSnapshot>,
    captured: BTreeMap<String, Vec<Felt>>,
    /// Locations with frame-base anchors refreshed while active and retained while suspended.
    locations: BTreeMap<String, DebugVarLocation>,
    context: ContextId,
    fmp: Option<u32>,
}

impl InvocationVariables {
    fn refresh_storage(&mut self, processor: &FastProcessor) {
        let read_memory = |address: u32| {
            processor.memory().read_element(self.context, Felt::from_u32(address)).ok()
        };
        self.fmp = read_memory(miden_core::FMP_ADDR.as_canonical_u64() as u32)
            .and_then(|value| u32::try_from(value.as_canonical_u64()).ok());
        let read_local =
            |offset: i16| read_memory(self.fmp?.checked_add_signed(i32::from(offset))?);
        self.locations = self
            .variables
            .iter()
            .map(|(name, variable)| {
                (
                    name.clone(),
                    anchor_frame_bases(variable.info.value_location(), &read_memory, &read_local)
                        .unwrap_or(DebugVarLocation::Unavailable),
                )
            })
            .collect();
    }
}

/// Tracks debug variable snapshots, mapping variable names to their most recent location info.
pub struct DebugVarTracker {
    invocations: BTreeMap<InvocationId, InvocationVariables>,
    current_invocation: Option<InvocationId>,
    invocation_mode: bool,
    /// All debug variable events recorded during execution, keyed by clock cycle.
    events: DebugVarEvents,
    /// Canonical values frozen at transient debug decorators.
    captured_values: CapturedDebugValues,
    /// Current view of variables - maps variable name to most recent info.
    current_vars: BTreeMap<String, DebugVarSnapshot>,
    /// Canonical values captured for currently visible transient variables.
    current_captured_values: BTreeMap<String, Vec<Felt>>,
    /// The clock cycle up to which we've processed events.
    processed_up_to: RowIndex,
}

impl DebugVarTracker {
    /// Create a new tracker using the given shared event store.
    pub fn new(events: DebugVarEvents) -> Self {
        Self {
            invocations: BTreeMap::new(),
            current_invocation: None,
            invocation_mode: false,
            events,
            captured_values: Rc::new(Default::default()),
            current_vars: BTreeMap::new(),
            current_captured_values: BTreeMap::new(),
            processed_up_to: RowIndex::from(0),
        }
    }

    pub fn current_invocation(&self) -> Option<InvocationId> {
        self.current_invocation
    }

    pub fn has_invocation(&self, invocation: InvocationId) -> bool {
        self.invocations.contains_key(&invocation)
    }

    pub fn variables_for(
        &self,
        invocation: InvocationId,
    ) -> impl Iterator<Item = &DebugVarSnapshot> {
        self.invocations
            .get(&invocation)
            .into_iter()
            .flat_map(|frame| frame.variables.values())
    }

    /// Observe the operation's owner and declarations before executing it. Only observed active
    /// invocations acquire variable state; recovered ancestors do not inherit a callee's locals.
    pub fn observe_execution(
        &mut self,
        live_ids: impl IntoIterator<Item = InvocationId>,
        current: Option<InvocationId>,
        processor: &FastProcessor,
        clk: RowIndex,
        mut infos: Vec<DebugVarInfo>,
    ) {
        // An external CALL can switch memory contexts before its source forest is entered.
        // The retained caller identity still appears during that transition, but it must not
        // acquire the callee's memory context or declarations. An invocation's context is fixed.
        let current = current.filter(|id| {
            self.invocations
                .get(id)
                .is_none_or(|frame| frame.context == processor.state().ctx())
        });
        // The previous operation may have changed a frame base immediately before an exec
        // boundary. Refresh the departing owner before capturing the new owner's declarations.
        // CALL/return context switches already suspend the old context without modifying it.
        if self.current_invocation != current
            && let Some(previous) = self.current_invocation
            && let Some(frame) = self.invocations.get_mut(&previous)
            && frame.context == processor.state().ctx()
        {
            frame.refresh_storage(processor);
        }
        self.invocation_mode = true;
        self.current_invocation = current;
        let live_ids = live_ids.into_iter().collect::<alloc::collections::BTreeSet<_>>();
        self.invocations.retain(|id, _| live_ids.contains(id));
        let Some(current) = current else { return };
        let state = processor.state();
        let context = state.ctx();
        let stack = state.get_stack_state();
        let frame = self.invocations.entry(current).or_default();
        frame.context = context;
        let kills = infos.iter().map(is_debug_var_kill).collect::<Vec<_>>();
        let captured = snapshot_transient_debug_values(&mut infos, &stack);
        for (info, is_kill) in infos.into_iter().zip(kills) {
            let name = info.name().to_string();
            if is_kill {
                frame.variables.remove(&name);
                frame.captured.remove(&name);
                frame.locations.remove(&name);
            } else {
                match captured.get(info.name()) {
                    Some(values) => {
                        frame.captured.insert(name.clone(), values.clone());
                    }
                    None => {
                        frame.captured.remove(&name);
                    }
                }
                frame.variables.insert(name, DebugVarSnapshot { clk, info });
            }
        }
        frame.refresh_storage(processor);
    }

    /// Read live storage using the selected invocation's context and retained frame bases.
    pub fn resolve(
        &self,
        invocation: InvocationId,
        name: &str,
        processor: &FastProcessor,
    ) -> Option<ResolvedDebugVariable> {
        let frame = self.invocations.get(&invocation)?;
        let variable = frame.variables.get(name)?;
        let read_memory = |address: u32| {
            processor.memory().read_element(frame.context, Felt::from_u32(address)).ok()
        };
        let active =
            self.current_invocation == Some(invocation) && processor.state().ctx() == frame.context;
        let fmp = if active {
            read_memory(miden_core::FMP_ADDR.as_canonical_u64() as u32)
                .and_then(|value| u32::try_from(value.as_canonical_u64()).ok())
        } else {
            frame.fmp
        };
        let read_local = |offset: i16| read_memory(fmp?.checked_add_signed(i32::from(offset))?);
        let location = if active {
            anchor_frame_bases(variable.info.value_location(), &read_memory, &read_local)
                .unwrap_or(DebugVarLocation::Unavailable)
        } else {
            frame.locations.get(name)?.clone()
        };
        let captured = frame.captured.get(name);
        let raw = captured
            .and_then(|values| values.first().copied())
            .or_else(|| resolve_variable_value(&location, &[], read_memory, read_local));
        let type_name =
            variable.info.ty().map(ToString::to_string).unwrap_or_else(|| "Felt".into());
        let typed = variable.info.ty().and_then(|ty| {
            super::format_value(ty, |count| {
                captured.filter(|values| values.len() == count).cloned().or_else(|| {
                    resolve_typed_variable_values(
                        &location,
                        ty,
                        count,
                        &[],
                        read_memory,
                        read_local,
                    )
                })
            })
        });
        let value = typed
            .or_else(|| raw.map(|value| value.as_canonical_u64().to_string()))
            .unwrap_or_else(|| "<unavailable>".into());
        Some(ResolvedDebugVariable {
            raw,
            value,
            type_name,
        })
    }

    /// Record debug variable events at the given clock cycle.
    pub fn record_events(&self, clk: RowIndex, infos: Vec<DebugVarInfo>) {
        if !infos.is_empty() {
            self.events.borrow_mut().entry(clk).or_default().extend(infos);
        }
    }

    /// Record debug variable events after freezing transient stack-backed values.
    pub fn record_events_with_stack(
        &self,
        clk: RowIndex,
        mut infos: Vec<DebugVarInfo>,
        stack: &[Felt],
    ) {
        let names = infos.iter().map(|info| info.name().clone()).collect::<Vec<_>>();
        let captured_values = snapshot_transient_debug_values(&mut infos, stack);
        {
            let mut stored_values = self.captured_values.borrow_mut();
            for name in names {
                stored_values.remove(&(clk, name));
            }
            stored_values
                .extend(captured_values.into_iter().map(|(name, values)| ((clk, name), values)));
        }
        self.record_events(clk, infos);
    }

    /// Process all events up to and including `clk`, updating current variable state.
    pub fn update_to_cycle(&mut self, clk: RowIndex) {
        let events = self.events.borrow();
        let captured_values = self.captured_values.borrow();

        // Process events from processed_up_to to clk
        for (event_clk, var_infos) in events.range(self.processed_up_to..=clk) {
            for info in var_infos {
                if is_debug_var_kill(info) {
                    self.current_vars.remove(info.name().as_ref());
                    self.current_captured_values.remove(info.name().as_ref());
                    continue;
                }
                let snapshot = DebugVarSnapshot {
                    clk: *event_clk,
                    info: info.clone(),
                };
                let name = info.name().to_string();
                match captured_values.get(&(*event_clk, info.name().clone())) {
                    Some(values) => {
                        self.current_captured_values.insert(name.clone(), values.clone());
                    }
                    None => {
                        self.current_captured_values.remove(&name);
                    }
                }
                self.current_vars.insert(name, snapshot);
            }
        }

        self.processed_up_to = clk;
    }

    /// Reset the tracker to the beginning of execution.
    pub fn reset(&mut self) {
        self.invocations.clear();
        self.current_invocation = None;
        self.current_vars.clear();
        self.current_captured_values.clear();
        self.processed_up_to = RowIndex::from(0);
    }

    fn active_variables(&self) -> Option<&BTreeMap<String, DebugVarSnapshot>> {
        if self.invocation_mode {
            Some(&self.invocations.get(&self.current_invocation?)?.variables)
        } else {
            Some(&self.current_vars)
        }
    }

    /// Get all currently visible variables.
    pub fn current_variables(&self) -> impl Iterator<Item = &DebugVarSnapshot> {
        self.active_variables().into_iter().flat_map(|variables| variables.values())
    }

    /// Get a specific variable by name.
    pub fn get_variable(&self, name: &str) -> Option<&DebugVarSnapshot> {
        self.active_variables()?.get(name)
    }

    /// Returns canonical values captured at the variable's latest debug decorator.
    pub fn captured_values(&self, name: &str) -> Option<&[Felt]> {
        if self.invocation_mode {
            self.invocations
                .get(&self.current_invocation?)?
                .captured
                .get(name)
                .map(Vec::as_slice)
        } else {
            self.current_captured_values.get(name).map(Vec::as_slice)
        }
    }

    /// Get the number of tracked variables.
    pub fn variable_count(&self) -> usize {
        self.active_variables().map_or(0, BTreeMap::len)
    }

    /// Check if there are any tracked variables.
    pub fn has_variables(&self) -> bool {
        self.variable_count() != 0
    }
}

/// Only frame-base operands are anchored. Ordinary memory reads remain live, including pointers
/// read by general location expressions. The original declaration is retained for the next refresh.
fn anchor_frame_bases(
    location: &DebugVarLocation,
    read_memory: &impl Fn(u32) -> Option<Felt>,
    read_local: &impl Fn(i16) -> Option<Felt>,
) -> Option<DebugVarLocation> {
    let operations = match location {
        DebugVarLocation::ResolvedFrameBase { base, byte_offset } => vec![
            DebugLocationExpressionOp::ConstU64(resolve_frame_base_address(
                *base,
                *byte_offset,
                read_memory,
                read_local,
            )?),
            DebugLocationExpressionOp::DerefBytes,
        ],
        DebugVarLocation::Expression(expression) => expression
            .operations()
            .iter()
            .map(|operation| match operation {
                DebugLocationExpressionOp::FrameBaseAddress { base, byte_offset } => {
                    Some(DebugLocationExpressionOp::ConstU64(resolve_frame_base_address(
                        *base,
                        *byte_offset,
                        read_memory,
                        read_local,
                    )?))
                }
                operation => Some(*operation),
            })
            .collect::<Option<Vec<_>>>()?,
        location => return Some(location.clone()),
    };
    Some(DebugVarLocation::Expression(DebugLocationExpression::new(operations).ok()?))
}

/// Snapshot transient debug locations at the decorator point.
///
/// Stack locations are only meaningful at the debug decorator itself. Keeping them live and
/// resolving them against a later VM stack can report unrelated values. Memory, local, and
/// frame-base declarations describe live storage and must be resolved against the current VM state
/// when the user inspects variables.
pub fn snapshot_transient_debug_values(
    infos: &mut [DebugVarInfo],
    stack: &[Felt],
) -> BTreeMap<Arc<str>, Vec<Felt>> {
    let mut captured_values = BTreeMap::new();

    for info in infos {
        captured_values.remove(info.name().as_ref());
        match info.value_location() {
            DebugVarLocation::Stack(position) => {
                let count = info.ty().and_then(super::abi_types::value_felt_count).unwrap_or(1);
                let start = *position as usize;
                let values = start
                    .checked_add(count)
                    .and_then(|end| stack.get(start..end))
                    .map(<[Felt]>::to_vec);
                let location = values
                    .as_ref()
                    .and_then(|values| values.first().copied())
                    .or_else(|| (count == 0).then(|| Felt::from_u32(0)))
                    .map(DebugVarLocation::Const)
                    .unwrap_or(DebugVarLocation::Unavailable);
                if let Some(values) = values {
                    captured_values.insert(info.name().clone(), values);
                }
                info.set_value_location(location);
            }
            DebugVarLocation::Expression(expression) => {
                let operations = expression
                    .operations()
                    .iter()
                    .map(|operation| match operation {
                        DebugLocationExpressionOp::ReadStack(position) => stack
                            .get(*position as usize)
                            .map(|value| {
                                DebugLocationExpressionOp::ConstU64(value.as_canonical_u64())
                            })
                            .ok_or(()),
                        operation => Ok(*operation),
                    })
                    .collect::<Result<Vec<_>, _>>();
                let location = operations
                    .and_then(|ops| DebugLocationExpression::new(ops).map_err(|_| ()))
                    .map(DebugVarLocation::Expression)
                    .unwrap_or(DebugVarLocation::Unavailable);
                info.set_value_location(location);
            }
            _ => {}
        }
    }

    captured_values
}

fn is_debug_var_kill(info: &DebugVarInfo) -> bool {
    matches!(info.value_location(), DebugVarLocation::Unavailable)
}

/// Resolve a debug variable's value given its location and the current VM state.
pub fn resolve_variable_value(
    location: &DebugVarLocation,
    stack: &[Felt],
    get_memory: impl Fn(u32) -> Option<Felt>,
    get_local: impl Fn(i16) -> Option<Felt>,
) -> Option<Felt> {
    resolve_variable_values(location, 1, stack, get_memory, get_local)?.pop()
}

/// Resolve one or more consecutive felts for a debug variable.
pub fn resolve_variable_values(
    location: &DebugVarLocation,
    count: usize,
    stack: &[Felt],
    get_memory: impl Fn(u32) -> Option<Felt>,
    get_local: impl Fn(i16) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    if count == 0 {
        return Some(Vec::new());
    }

    match location {
        DebugVarLocation::Stack(pos) => {
            let start = *pos as usize;
            let end = start.checked_add(count)?;
            Some(stack.get(start..end)?.to_vec())
        }
        DebugVarLocation::Memory(addr) => resolve_consecutive_memory(*addr, count, &get_memory),
        DebugVarLocation::Const(felt) => (count == 1).then_some(vec![*felt]),
        DebugVarLocation::Local(offset) => {
            let mut values = Vec::with_capacity(count);
            for index in 0..count {
                let index = i16::try_from(index).ok()?;
                values.push(get_local(offset.checked_add(index)?)?);
            }
            Some(values)
        }
        DebugVarLocation::ResolvedFrameBase { base, byte_offset } => {
            resolve_frame_base_values(*base, *byte_offset, count, &get_memory, &get_local)
        }
        DebugVarLocation::Expression(expression) => {
            match resolve_expression(expression.operations(), stack, &get_memory, &get_local)? {
                ResolvedExpression::Scalar(value) => {
                    (count == 1).then(|| integer_to_felt(value)).flatten().map(|value| vec![value])
                }
                ResolvedExpression::ByteAddress(address) => {
                    let element_address = u32::try_from(address / 4).ok()?;
                    resolve_consecutive_memory(element_address, count, &get_memory)
                }
            }
        }
        DebugVarLocation::Unavailable => None,
    }
}

/// Resolve a typed debug variable into the canonical ABI felts consumed by the typed decoder.
///
/// Simple Miden locations already contain canonical stack values. Frame-base locations and a
/// terminal [`DebugLocationExpressionOp::DerefBytes`] instead identify packed Rust memory, which
/// must be read at byte granularity and lifted according to `ty` before it can be decoded.
pub fn resolve_typed_variable_values(
    location: &DebugVarLocation,
    ty: &Type,
    count: usize,
    stack: &[Felt],
    get_memory: impl Fn(u32) -> Option<Felt>,
    get_local: impl Fn(i16) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    match location {
        DebugVarLocation::ResolvedFrameBase { base, byte_offset } => {
            let byte_address =
                resolve_frame_base_address(*base, *byte_offset, &get_memory, &get_local)?;
            resolve_typed_memory_value(ty, byte_address, count, &get_memory)
        }
        DebugVarLocation::Expression(expression) => {
            match resolve_expression(expression.operations(), stack, &get_memory, &get_local)? {
                ResolvedExpression::ByteAddress(byte_address) => {
                    resolve_typed_memory_value(ty, byte_address, count, &get_memory)
                }
                ResolvedExpression::Scalar(value) => {
                    (count == 1).then(|| integer_to_felt(value)).flatten().map(|value| vec![value])
                }
            }
        }
        _ => resolve_variable_values(location, count, stack, get_memory, get_local),
    }
}

fn resolve_consecutive_memory(
    start_addr: u32,
    count: usize,
    get_memory: &impl Fn(u32) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    let mut values = Vec::with_capacity(count);
    for index in 0..count {
        let addr = start_addr.checked_add(u32::try_from(index).ok()?)?;
        values.push(get_memory(addr)?);
    }
    Some(values)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResolvedExpression {
    Scalar(i128),
    ByteAddress(u64),
}

fn resolve_expression(
    ops: &[DebugLocationExpressionOp],
    stack: &[Felt],
    get_memory: &impl Fn(u32) -> Option<Felt>,
    get_local: &impl Fn(i16) -> Option<Felt>,
) -> Option<ResolvedExpression> {
    let mut values = Vec::<i128>::new();

    for (index, op) in ops.iter().enumerate() {
        match op {
            DebugLocationExpressionOp::ReadStack(index) => {
                values.push(i128::from(stack.get(*index as usize)?.as_canonical_u64()));
            }
            DebugLocationExpressionOp::ReadMemory(index) => {
                values.push(i128::from(get_memory(*index)?.as_canonical_u64()));
            }
            DebugLocationExpressionOp::ReadLocal(index) => {
                values.push(i128::from(get_local(*index)?.as_canonical_u64()));
            }
            DebugLocationExpressionOp::ConstU64(value) => {
                values.push(i128::from(*value));
            }
            DebugLocationExpressionOp::ConstI64(value) => {
                values.push(i128::from(*value));
            }
            DebugLocationExpressionOp::AddUnsigned(value) => {
                let lhs = values.pop()?;
                values.push(lhs.checked_add(i128::from(*value))?);
            }
            DebugLocationExpressionOp::Add => {
                let rhs = values.pop()?;
                let lhs = values.pop()?;
                values.push(lhs.checked_add(rhs)?);
            }
            DebugLocationExpressionOp::Sub => {
                let rhs = values.pop()?;
                let lhs = values.pop()?;
                values.push(lhs.checked_sub(rhs)?);
            }
            DebugLocationExpressionOp::DerefBytes => {
                let byte_address = u64::try_from(values.pop()?).ok()?;
                if index + 1 == ops.len() {
                    return Some(ResolvedExpression::ByteAddress(byte_address));
                }
                let element_address = u32::try_from(byte_address / 4).ok()?;
                values.push(i128::from(get_memory(element_address)?.as_canonical_u64()));
            }
            DebugLocationExpressionOp::FrameBaseAddress { base, byte_offset } => {
                values.push(i128::from(resolve_frame_base_address(
                    *base,
                    *byte_offset,
                    get_memory,
                    get_local,
                )?));
            }
        }
    }

    values.pop().map(ResolvedExpression::Scalar)
}

fn resolve_frame_base_values(
    base: DebugFrameBase,
    byte_offset: i64,
    count: usize,
    get_memory: &impl Fn(u32) -> Option<Felt>,
    get_local: &impl Fn(i16) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    let byte_address = resolve_frame_base_address(base, byte_offset, get_memory, get_local)?;
    resolve_byte_address_values(byte_address, count, get_memory)
}

fn resolve_frame_base_address(
    base: DebugFrameBase,
    byte_offset: i64,
    get_memory: &impl Fn(u32) -> Option<Felt>,
    get_local: &impl Fn(i16) -> Option<Felt>,
) -> Option<u64> {
    let base = match base {
        DebugFrameBase::Local(offset) => get_local(offset)?,
        DebugFrameBase::Memory(address) => get_memory(address)?,
    };
    base.as_canonical_u64().checked_add_signed(byte_offset)
}

fn resolve_byte_address_values(
    byte_address: u64,
    count: usize,
    get_memory: &impl Fn(u32) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    if !byte_address.is_multiple_of(4) {
        return None;
    }
    let element_address = u32::try_from(byte_address / 4).ok()?;
    resolve_consecutive_memory(element_address, count, get_memory)
}

fn integer_to_felt(value: i128) -> Option<Felt> {
    Felt::new(u64::try_from(value).ok()?).ok()
}

fn read_memory_bytes(
    byte_address: u64,
    size: usize,
    get_memory: &impl Fn(u32) -> Option<Felt>,
) -> Option<Vec<u8>> {
    if size == 0 {
        return Some(Vec::new());
    }

    let element_address = u32::try_from(byte_address / 4).ok()?;
    let byte_offset = usize::try_from(byte_address % 4).ok()?;
    let end = byte_offset.checked_add(size)?;
    let element_count = end.div_ceil(4);
    let mut bytes = Vec::with_capacity(element_count.checked_mul(4)?);

    for index in 0..element_count {
        let address = element_address.checked_add(u32::try_from(index).ok()?)?;
        let value = get_memory(address)?.as_canonical_u64() as u32;
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    Some(bytes.get(byte_offset..end)?.to_vec())
}

fn resolve_typed_memory_value(
    ty: &Type,
    byte_address: u64,
    expected_count: usize,
    get_memory: &impl Fn(u32) -> Option<Felt>,
) -> Option<Vec<Felt>> {
    let mut values = Vec::with_capacity(expected_count);
    append_typed_memory_value(ty, byte_address, get_memory, &mut values)?;
    (values.len() == expected_count).then_some(values)
}

fn append_typed_memory_value(
    ty: &Type,
    byte_address: u64,
    get_memory: &impl Fn(u32) -> Option<Felt>,
    values: &mut Vec<Felt>,
) -> Option<()> {
    match ty {
        Type::Felt => {
            if !byte_address.is_multiple_of(4) {
                return None;
            }
            values.push(get_memory(u32::try_from(byte_address / 4).ok()?)?);
        }
        Type::I1 => {
            let byte = *read_memory_bytes(byte_address, 1, get_memory)?.first()?;
            values.push(Felt::from_u32(u32::from(byte & 1)));
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 | Type::I128 => {
            let value = read_unsigned_integer(ty, byte_address, get_memory)?;
            let bit_width = u32::try_from(ty.size_in_bits()).ok()?;
            let shift = 128_u32.checked_sub(bit_width)?;
            let signed = ((value << shift) as i128) >> shift;
            let slot_bits = u32::try_from(ty.size_in_felts().checked_mul(32)?).ok()?;
            let canonical = (signed as u128) & low_bits_mask(slot_bits);
            append_u128_limbs(canonical, ty.size_in_felts(), values);
        }
        Type::U8 | Type::U16 | Type::U32 | Type::U64 | Type::U128 | Type::F64 => {
            let value = read_unsigned_integer(ty, byte_address, get_memory)?;
            append_u128_limbs(value, ty.size_in_felts(), values);
        }
        Type::Struct(struct_ty) => {
            for field in struct_ty.get().fields() {
                let field_address = byte_address.checked_add(u64::from(field.offset))?;
                append_typed_memory_value(&field.ty, field_address, get_memory, values)?;
            }
        }
        Type::Array(array_ty) => {
            let element_size = array_ty.ty.size_in_bytes();
            let alignment = array_ty.ty.min_alignment();
            let stride = align_up(element_size, alignment)?;
            for index in 0..array_ty.len {
                let offset = index.checked_mul(stride)?;
                let element_address = byte_address.checked_add(u64::try_from(offset).ok()?)?;
                append_typed_memory_value(&array_ty.ty, element_address, get_memory, values)?;
            }
        }
        Type::U256
        | Type::List(_)
        | Type::Ptr(_)
        | Type::Function(_)
        | Type::Enum(_)
        | Type::Unknown
        | Type::Never
        | Type::Variadic => return None,
    }

    Some(())
}

fn read_unsigned_integer(
    ty: &Type,
    byte_address: u64,
    get_memory: &impl Fn(u32) -> Option<Felt>,
) -> Option<u128> {
    let bytes = read_memory_bytes(byte_address, ty.size_in_bytes(), get_memory)?;
    let mut value = 0_u128;
    for (index, byte) in bytes.into_iter().enumerate() {
        value |= u128::from(byte) << index.checked_mul(8)?;
    }
    Some(value)
}

fn append_u128_limbs(value: u128, count: usize, values: &mut Vec<Felt>) {
    values.extend((0..count).map(|index| Felt::from_u32((value >> (index * 32)) as u32)));
}

fn low_bits_mask(bits: u32) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1_u128 << bits) - 1
    }
}

fn align_up(size: usize, alignment: usize) -> Option<usize> {
    if size == 0 {
        return Some(0);
    }
    size.checked_add(alignment.checked_sub(1)?)?
        .checked_div(alignment)?
        .checked_mul(alignment)
}

#[cfg(test)]
mod tests;
