//! Intraprocedural type inference and mismatch checking.

use std::collections::HashMap;

use super::{
    domain::{TypeFact, VarKey},
    summary::{TypeSummary, TypeSummaryMap},
};
use crate::{
    ir::{BinOp, Constant, Expr, Stmt, UnOp, Var},
    symbol::path::SymbolPath,
};

/// Maximum number of fixed-point iterations for local type inference.
const MAX_TYPE_PASSES: usize = 128;

/// Upper bound (exclusive) of the valid Miden VM memory address range.
///
/// Memory addresses must be in `[0, 2^32)`. Operations like `mem_load`
/// and `mem_store` trap at runtime if the address is `>= 2^32`.
const MAX_MEMORY_ADDRESS: u64 = 1u64 << 32;

/// Abstract memory address identity for type tracking.
///
/// Two memory operations target the same logical address when they share
/// the same `MemAddressKey`. This is necessary because the lifter creates
/// distinct SSA variables for each address operand, even when they refer
/// to the same constant or `locaddr` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum MemAddressKey {
    /// Constant address known to be in the valid memory range `[0, 2^32)`.
    ///
    /// Stored as `u32` to enforce the range invariant at the type level.
    /// Created from `Constant::Felt(n)` assignments where `n < 2^32`.
    Constant(u32),
    /// Local-mapped address (from `locaddr.N`).
    LocalAddr(u16),
    /// Local-mapped address offset by a known constant (from `locaddr.N + k`).
    ///
    /// Only created for `Add` operations (not `Sub`), because field `sub`
    /// computes `(a - b) mod p` which can wrap to addresses outside the
    /// procedure's local frame.
    ///
    /// The absolute address is not known at analysis time, but two operations
    /// sharing the same `(local_index, offset)` target the same location.
    LocalAddrOffset(u16, u32),
}

/// Provenance of a variable in the output summary.
///
/// Used to determine whether a return variable is an unmodified copy of
/// a procedure input, enabling type narrowing based on the input's
/// backward-propagated requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Variable traces back to the procedure input at the given index.
    ///
    /// The index corresponds to the stack position (0 = deepest input,
    /// matching the convention used by `input_var_key`).
    Input(usize),
    /// Variable was produced by a computation (arithmetic, call result,
    /// memory load, etc.) or by merging incompatible origins.
    Computed,
}

/// Analyze a single procedure body and infer its [TypeSummary].
pub(crate) fn analyze_proc_types(
    input_count: usize,
    output_count: usize,
    stmts: &[Stmt],
    callee_summaries: &TypeSummaryMap,
) -> TypeSummary {
    let mut analyzer = ProcTypeAnalyzer::new(input_count, output_count, callee_summaries);
    analyzer.analyze(stmts)
}

/// Internal fixed-point analyzer for one procedure.
struct ProcTypeAnalyzer<'a> {
    /// Number of stack inputs.
    input_count: usize,
    /// Number of stack outputs.
    output_count: usize,
    /// Previously inferred summaries for callees.
    callee_summaries: &'a TypeSummaryMap,
    /// Inferred type guarantees for variables.
    inferred: HashMap<VarKey, TypeFact>,
    /// Inferred requirements for variables.
    required: HashMap<VarKey, TypeFact>,
    /// Inferred types for local variable slots.
    ///
    /// Updated on `LocalStore`/`LocalStoreW` and read on `LocalLoad`.
    /// The fixed-point loop ensures convergence when stored types change
    /// across iterations.
    local_types: HashMap<u16, TypeFact>,
    /// Maps SSA variables to their abstract memory address identity.
    ///
    /// Populated during inference when a variable is defined as a constant
    /// (`Assign { expr: Constant(Felt(n)) }`) or a `locaddr.N` intrinsic
    /// result. Also propagated through variable copies
    /// (`Assign { expr: Var(src) }`).
    var_address_keys: HashMap<VarKey, MemAddressKey>,
    /// Inferred types for memory locations, keyed by abstract address.
    mem_types: HashMap<MemAddressKey, TypeFact>,
    /// Requirements propagated backward to local variable slots.
    local_requirements: HashMap<u16, TypeFact>,
    /// Requirements propagated backward to memory locations.
    mem_requirements: HashMap<MemAddressKey, TypeFact>,
    /// Input-backed provenance for SSA variables.
    ///
    /// This is computed once from the lifted body and callee passthrough maps.
    /// It lets selector typing distinguish real input-backed values from
    /// computed values that only happen to inherit a downstream requirement.
    origins: HashMap<VarKey, Origin>,
    /// Direct expression definitions for SSA assignments.
    ///
    /// This supports small sound structural refinements such as preserving the
    /// `u32` result of bit-count operations through known-safe constant offsets.
    expr_defs: HashMap<VarKey, Expr>,
}

impl<'a> ProcTypeAnalyzer<'a> {
    /// Construct a new analyzer.
    fn new(input_count: usize, output_count: usize, callee_summaries: &'a TypeSummaryMap) -> Self {
        Self {
            input_count,
            output_count,
            callee_summaries,
            inferred: HashMap::new(),
            required: HashMap::new(),
            local_types: HashMap::new(),
            var_address_keys: HashMap::new(),
            mem_types: HashMap::new(),
            local_requirements: HashMap::new(),
            mem_requirements: HashMap::new(),
            origins: HashMap::new(),
            expr_defs: HashMap::new(),
        }
    }

    /// Run fixed-point inference and mismatch checks.
    fn analyze(&mut self, stmts: &[Stmt]) -> TypeSummary {
        self.origins = self.compute_origins(stmts);
        self.expr_defs = Self::collect_expr_defs(stmts);

        for _ in 0..MAX_TYPE_PASSES {
            let prev_inferred = self.inferred.clone();
            let prev_required = self.required.clone();
            let prev_local_types = self.local_types.clone();
            let prev_mem_types = self.mem_types.clone();
            let prev_local_req = self.local_requirements.clone();
            let prev_mem_req = self.mem_requirements.clone();
            let prev_addr_keys = self.var_address_keys.clone();

            // Return values are intentionally discarded: convergence is
            // detected by comparing full state snapshots (below), not by
            // per-call `changed` flags, which can oscillate within a pass.
            let _ = self.infer_types_in_block(stmts, true);
            let _ = self.seed_requirements_in_block(stmts, true);
            let _ = self.propagate_requirements_in_block(stmts);

            if self.inferred == prev_inferred
                && self.required == prev_required
                && self.local_types == prev_local_types
                && self.mem_types == prev_mem_types
                && self.local_requirements == prev_local_req
                && self.mem_requirements == prev_mem_req
                && self.var_address_keys == prev_addr_keys
            {
                break;
            }
        }

        self.build_summary(stmts)
    }

    /// Collect direct assignment expressions keyed by destination SSA variable.
    fn collect_expr_defs(stmts: &[Stmt]) -> HashMap<VarKey, Expr> {
        let mut defs = HashMap::new();
        Self::collect_expr_defs_in_block(stmts, &mut defs);
        defs
    }

    /// Collect direct assignment expressions in a structured statement block.
    fn collect_expr_defs_in_block(stmts: &[Stmt], defs: &mut HashMap<VarKey, Expr>) {
        for stmt in stmts {
            match stmt {
                Stmt::Assign { dest, expr, .. } => {
                    defs.insert(VarKey::from_var(dest), expr.clone());
                },
                Stmt::If { then_body, else_body, .. } => {
                    Self::collect_expr_defs_in_block(then_body, defs);
                    Self::collect_expr_defs_in_block(else_body, defs);
                },
                Stmt::Repeat { body, .. } | Stmt::While { body, .. } => {
                    Self::collect_expr_defs_in_block(body, defs);
                },
                _ => {},
            }
        }
    }

    /// Build the final procedure summary from inferred state.
    fn build_summary(&self, stmts: &[Stmt]) -> TypeSummary {
        let mut inputs = Vec::with_capacity(self.input_count);
        for index in (0..self.input_count).rev() {
            let key = Self::input_var_key(index);
            let req = self.required.get(&key).copied().unwrap_or(TypeFact::Felt);
            inputs.push(req.to_requirement());
        }

        let mut outputs = Vec::with_capacity(self.output_count);
        let mut output_input_map = Vec::with_capacity(self.output_count);
        let return_values = Self::find_return_values(stmts);
        for index in (0..self.output_count).rev() {
            let (ty, origin_input) = return_values
                .and_then(|values| values.get(index))
                .map(|var| {
                    let inferred = self.inferred_type_for_var(var);
                    let key = VarKey::from_var(var);
                    if let Some(Origin::Input(input_idx)) = self.origins.get(&key) {
                        let input_key = Self::input_var_key(*input_idx);
                        let input_req =
                            self.required.get(&input_key).copied().unwrap_or(TypeFact::Felt);
                        (inferred.glb(input_req), Some(*input_idx))
                    } else {
                        (inferred, None)
                    }
                })
                .unwrap_or((TypeFact::Felt, None));
            outputs.push(ty.to_inferred_type());
            output_input_map.push(origin_input);
        }

        TypeSummary::new_with_map(inputs, outputs, output_input_map)
    }

    /// Find the top-level return statement values.
    fn find_return_values(stmts: &[Stmt]) -> Option<&[Var]> {
        for stmt in stmts {
            if let Stmt::Return { values, .. } = stmt {
                return Some(values);
            }
        }
        None
    }

    /// Compute the origin of each variable in the procedure body.
    ///
    /// This is a post-hoc structural analysis run after the fixed-point
    /// converges. It determines which variables are unmodified copies of
    /// procedure inputs, tracing through variable copies (`Assign { expr:
    /// Var(_) }`), ternary selects, if-phi merges, and loop-phi merges.
    ///
    /// A variable has `Origin::Input(i)` only if every path from the input
    /// to the variable consists exclusively of copy operations and phi/ternary
    /// nodes where all incoming edges agree on the same input index.
    ///
    /// The analysis iterates to a fixed point to handle nested loops: an
    /// inner loop phi may optimistically inherit `Input(i)` from an outer
    /// loop phi that is later demoted to `Computed`. Fixed-point iteration
    /// ensures such stale origins are corrected.
    fn compute_origins(&self, stmts: &[Stmt]) -> HashMap<VarKey, Origin> {
        let mut origins: HashMap<VarKey, Origin> = HashMap::new();

        // Seed input variables.
        for index in 0..self.input_count {
            let key = Self::input_var_key(index);
            origins.insert(key, Origin::Input(index));
        }

        // Iterate to a fixed point. Each pass may demote origins from
        // Input to Computed (monotonic — never the reverse), so
        // convergence is guaranteed in at most N passes where N is the
        // number of variables.
        loop {
            let prev = origins.clone();
            self.propagate_origins_in_block(stmts, &mut origins);
            if origins == prev {
                break;
            }
        }

        origins
    }

    /// Propagate origins through a statement block.
    fn propagate_origins_in_block(&self, stmts: &[Stmt], origins: &mut HashMap<VarKey, Origin>) {
        for stmt in stmts {
            self.propagate_origins_in_stmt(stmt, origins);
        }
    }

    /// Look up the origin for a variable expression, or `Computed` if not a variable.
    fn origin_of_expr(expr: &Expr, origins: &HashMap<VarKey, Origin>) -> Origin {
        match expr {
            Expr::Var(var) => {
                origins.get(&VarKey::from_var(var)).copied().unwrap_or(Origin::Computed)
            },
            _ => Origin::Computed,
        }
    }

    /// Merge two origins: both must agree on the same `Input(i)`, otherwise `Computed`.
    fn merge_origins(a: Origin, b: Origin) -> Origin {
        match (a, b) {
            (Origin::Input(i), Origin::Input(j)) if i == j => Origin::Input(i),
            _ => Origin::Computed,
        }
    }

    /// Propagate origins through a single statement.
    fn propagate_origins_in_stmt(&self, stmt: &Stmt, origins: &mut HashMap<VarKey, Origin>) {
        match stmt {
            Stmt::Assign { dest, expr, .. } => {
                let origin = match expr {
                    // Variable copy: propagate the source's origin.
                    Expr::Var(src) => {
                        origins.get(&VarKey::from_var(src)).copied().unwrap_or(Origin::Computed)
                    },
                    // Ternary select (cdrop/cswap): both branches must agree.
                    Expr::Ternary { then_expr, else_expr, .. } => {
                        let then_origin = Self::origin_of_expr(then_expr, origins);
                        let else_origin = Self::origin_of_expr(else_expr, origins);
                        Self::merge_origins(then_origin, else_origin)
                    },
                    // Any other expression: the value is computed.
                    _ => Origin::Computed,
                };
                origins.insert(VarKey::from_var(dest), origin);
            },
            Stmt::If { then_body, else_body, phis, .. } => {
                self.propagate_origins_in_block(then_body, origins);
                self.propagate_origins_in_block(else_body, origins);
                for phi in phis {
                    let then_origin = origins
                        .get(&VarKey::from_var(&phi.then_var))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let else_origin = origins
                        .get(&VarKey::from_var(&phi.else_var))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let merged = Self::merge_origins(then_origin, else_origin);
                    origins.insert(VarKey::from_var(&phi.dest), merged);
                }
            },
            Stmt::While { body, phis, .. } => {
                // Seed loop-phi dests from their init values.
                for phi in phis {
                    let init_origin = origins
                        .get(&VarKey::from_var(&phi.init))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    // Only narrow (Input→Computed), never widen.
                    let current =
                        origins.get(&VarKey::from_var(&phi.dest)).copied().unwrap_or(init_origin);
                    let updated = Self::merge_origins(current, init_origin);
                    origins.insert(VarKey::from_var(&phi.dest), updated);
                }
                self.propagate_origins_in_block(body, origins);
                // Verify step agrees with dest; demote if not.
                for phi in phis {
                    let dest_origin = origins
                        .get(&VarKey::from_var(&phi.dest))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let step_origin = origins
                        .get(&VarKey::from_var(&phi.step))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let merged = Self::merge_origins(dest_origin, step_origin);
                    origins.insert(VarKey::from_var(&phi.dest), merged);
                }
            },
            Stmt::Repeat { body, phis, loop_count, .. } => {
                for phi in phis {
                    let init_origin = origins
                        .get(&VarKey::from_var(&phi.init))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    if *loop_count == 0 {
                        origins.insert(VarKey::from_var(&phi.dest), init_origin);
                    } else {
                        let current = origins
                            .get(&VarKey::from_var(&phi.dest))
                            .copied()
                            .unwrap_or(init_origin);
                        let updated = Self::merge_origins(current, init_origin);
                        origins.insert(VarKey::from_var(&phi.dest), updated);
                    }
                }
                if *loop_count == 0 {
                    return;
                }
                self.propagate_origins_in_block(body, origins);
                for phi in phis {
                    let dest_origin = origins
                        .get(&VarKey::from_var(&phi.dest))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let step_origin = origins
                        .get(&VarKey::from_var(&phi.step))
                        .copied()
                        .unwrap_or(Origin::Computed);
                    let merged = Self::merge_origins(dest_origin, step_origin);
                    origins.insert(VarKey::from_var(&phi.dest), merged);
                }
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                let callee_map = self.summary_for_target(&call.target).map(|s| &s.output_input_map);
                for (idx, result) in call.results.iter().enumerate() {
                    let origin = if let Some(Some(input_idx)) = callee_map.and_then(|m| m.get(idx))
                    {
                        // Callee output traces to callee input — inherit
                        // the origin of the corresponding caller argument.
                        // Origin::Input uses 0=deepest, args uses 0=topmost.
                        call.args
                            .len()
                            .checked_sub(1 + *input_idx)
                            .and_then(|i| call.args.get(i))
                            .and_then(|arg| origins.get(&VarKey::from_var(arg)).copied())
                            .unwrap_or(Origin::Computed)
                    } else {
                        Origin::Computed
                    };
                    origins.insert(VarKey::from_var(result), origin);
                }
            },
            Stmt::DynCall { results, .. } => {
                for result in results {
                    origins.insert(VarKey::from_var(result), Origin::Computed);
                }
            },
            Stmt::Intrinsic { intrinsic, .. } => {
                for result in &intrinsic.results {
                    origins.insert(VarKey::from_var(result), Origin::Computed);
                }
            },
            Stmt::MemLoad { load, .. } => {
                for output in &load.outputs {
                    origins.insert(VarKey::from_var(output), Origin::Computed);
                }
            },
            Stmt::LocalLoad { load, .. } => {
                for output in &load.outputs {
                    origins.insert(VarKey::from_var(output), Origin::Computed);
                }
            },
            Stmt::AdvLoad { load, .. } => {
                for output in &load.outputs {
                    origins.insert(VarKey::from_var(output), Origin::Computed);
                }
            },
            // Statements that don't define new variables.
            Stmt::MemStore { .. }
            | Stmt::AdvStore { .. }
            | Stmt::LocalStore { .. }
            | Stmt::LocalStoreW { .. }
            | Stmt::Return { .. } => {},
        }
    }

    /// Build the canonical key for an input variable by stack index.
    fn input_var_key(index: usize) -> VarKey {
        let var = Var::new((index as u64).into(), index);
        VarKey::from_var(&var)
    }

    /// Infer type guarantees in a statement block.
    fn infer_types_in_block(&mut self, stmts: &[Stmt], allow_proof_narrowing: bool) -> bool {
        let mut changed = false;
        for stmt in stmts {
            changed |= self.infer_types_in_stmt(stmt, allow_proof_narrowing);
        }
        changed
    }

    /// Infer type guarantees for one statement.
    fn infer_types_in_stmt(&mut self, stmt: &Stmt, allow_proof_narrowing: bool) -> bool {
        match stmt {
            Stmt::Assign { dest, expr, .. } => {
                let changed = self.set_inferred_type_for_var(dest, self.infer_expr_type(expr));
                // Track abstract address keys for memory type tracking.
                match expr {
                    Expr::Constant(Constant::Felt(n)) if *n < MAX_MEMORY_ADDRESS => {
                        self.var_address_keys
                            .insert(VarKey::from_var(dest), MemAddressKey::Constant(*n as u32));
                    },
                    Expr::Var(src) => {
                        if let Some(key) =
                            self.var_address_keys.get(&VarKey::from_var(src)).copied()
                        {
                            self.var_address_keys.insert(VarKey::from_var(dest), key);
                        }
                    },
                    Expr::Binary(BinOp::Add, lhs, rhs) => {
                        // Propagate MemAddressKey through locaddr + constant offset.
                        // Try both operand orderings since addition is commutative.
                        // Sub is excluded: field sub computes (a - b) mod p, which
                        // wraps to addresses outside the procedure's local frame.
                        //
                        // Uses `or` (eager) instead of `or_else` (lazy) because
                        // a closure capturing `&self` conflicts with the outer
                        // `&mut self` borrow.
                        let key = self
                            .resolve_addr_offset_key(lhs, rhs)
                            .or(self.resolve_addr_offset_key(rhs, lhs));
                        if let Some(key) = key {
                            self.var_address_keys.insert(VarKey::from_var(dest), key);
                        }
                    },
                    _ => {},
                }
                changed
            },
            Stmt::MemLoad { load, .. } => {
                let stored_ty = load
                    .address
                    .first()
                    .and_then(|v| self.mem_address_key_for_var(v))
                    .and_then(|key| self.mem_types.get(&key).copied())
                    .unwrap_or(TypeFact::Felt);
                let mut changed = false;
                for output in &load.outputs {
                    changed |= self.set_inferred_type_for_var(output, stored_ty);
                }
                changed
            },
            Stmt::LocalLoad { load, .. } => {
                let stored_ty =
                    self.local_types.get(&load.index).copied().unwrap_or(TypeFact::Felt);
                let mut changed = false;
                for output in &load.outputs {
                    changed |= self.set_inferred_type_for_var(output, stored_ty);
                }
                changed
            },
            Stmt::AdvLoad { load, .. } => {
                let mut changed = false;
                for output in &load.outputs {
                    changed |= self.set_inferred_type_for_var(output, TypeFact::Felt);
                }
                changed
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                self.assign_call_result_types(&call.target, &call.args, &call.results)
            },
            Stmt::DynCall { results, .. } => {
                let mut changed = false;
                for result in results {
                    changed |= self.set_inferred_type_for_var(result, TypeFact::Felt);
                }
                changed
            },
            Stmt::Intrinsic { intrinsic, .. } => {
                let output_count = intrinsic.results.len();
                let mut changed = false;
                for (idx, result) in intrinsic.results.iter().enumerate() {
                    let result_ty = self.intrinsic_output_type(
                        &intrinsic.name,
                        idx,
                        output_count,
                        &intrinsic.args,
                    );
                    changed |= self.set_inferred_type_for_var(result, result_ty);
                }
                if allow_proof_narrowing && Self::intrinsic_asserts_u32_args(&intrinsic.name) {
                    for arg in &intrinsic.args {
                        changed |= self.set_inferred_type_for_var(arg, TypeFact::U32);
                    }
                }
                if allow_proof_narrowing
                    && let Some(common_fact) = self.assert_eq_common_fact(intrinsic)
                {
                    for arg in &intrinsic.args {
                        changed |= self.set_inferred_type_for_var(arg, common_fact);
                    }
                }
                // Track locaddr results for memory address key mapping.
                if let Some(index_str) = intrinsic.name.strip_prefix("locaddr.")
                    && let Ok(index) = index_str.parse::<u16>()
                {
                    for result in &intrinsic.results {
                        self.var_address_keys
                            .insert(VarKey::from_var(result), MemAddressKey::LocalAddr(index));
                    }
                }
                changed
            },
            Stmt::If { then_body, else_body, phis, .. } => {
                let mut changed = false;
                changed |= self.infer_types_in_block(then_body, false);
                changed |= self.infer_types_in_block(else_body, false);
                for phi in phis {
                    let then_ty = self.inferred_phi_source_type(&phi.then_var);
                    let else_ty = self.inferred_phi_source_type(&phi.else_var);
                    changed |= self.set_inferred_type_for_var(&phi.dest, then_ty.join(else_ty));
                    self.propagate_phi_address_key(&phi.dest, &phi.then_var, &phi.else_var);
                }
                changed
            },
            Stmt::While { body, phis, .. } => {
                let mut changed = false;
                changed |= self.infer_types_in_block(body, false);
                for phi in phis {
                    let init_ty = self.inferred_type_for_var(&phi.init);
                    let step_ty = self.inferred_type_for_var(&phi.step);
                    changed |= self.set_inferred_type_for_var(&phi.dest, init_ty.join(step_ty));
                    self.propagate_phi_address_key(&phi.dest, &phi.init, &phi.step);
                }
                changed
            },
            Stmt::Repeat { body, phis, loop_count, .. } => {
                let mut changed = false;
                let executes_body = *loop_count > 0;
                if executes_body {
                    changed |= self.infer_types_in_block(body, allow_proof_narrowing);
                }
                for phi in phis {
                    let init_ty = self.inferred_type_for_var(&phi.init);
                    if executes_body {
                        let step_ty = self.inferred_type_for_var(&phi.step);
                        changed |= self.set_inferred_type_for_var(&phi.dest, init_ty.join(step_ty));
                        self.propagate_phi_address_key(&phi.dest, &phi.init, &phi.step);
                    } else {
                        changed |= self.set_inferred_type_for_var(&phi.dest, init_ty);
                        if let Some(key) = self.mem_address_key_for_var(&phi.init) {
                            self.var_address_keys.insert(VarKey::from_var(&phi.dest), key);
                        }
                    }
                }
                changed
            },
            Stmt::LocalStore { store, .. } => {
                self.record_local_store_type(store.index, &store.values)
            },
            Stmt::LocalStoreW { store, .. } => {
                self.record_local_store_type(store.index, &store.values)
            },
            Stmt::MemStore { store, .. } => {
                let mut changed = false;
                if let Some(addr_key) =
                    store.address.first().and_then(|v| self.mem_address_key_for_var(v))
                {
                    let stored_ty = store
                        .values
                        .iter()
                        .map(|v| self.inferred_type_for_var(v))
                        .reduce(TypeFact::glb)
                        .unwrap_or(TypeFact::Felt);
                    let current = self.mem_types.get(&addr_key).copied();
                    let updated = match current {
                        Some(existing) => existing.join(stored_ty),
                        None => stored_ty,
                    };
                    if current != Some(updated) {
                        self.mem_types.insert(addr_key, updated);
                        changed = true;
                    }
                }
                changed
            },
            Stmt::AdvStore { .. } | Stmt::Return { .. } => false,
        }
    }

    /// Assign types to call results from a known callee summary.
    ///
    /// For outputs that trace back to a callee input (`output_input_map`),
    /// the result type is resolved from the caller's argument type rather
    /// than the callee's fixed output type. This eliminates false positives
    /// for passthrough procedures that only permute their inputs.
    fn assign_call_result_types(&mut self, target: &str, args: &[Var], results: &[Var]) -> bool {
        let mut changed = false;
        let Some(summary) = self.summary_for_target(target).cloned() else {
            return false;
        };
        for (idx, result) in results.iter().enumerate() {
            let ty = if summary.is_opaque() {
                TypeFact::Felt
            } else if let Some(Some(input_idx)) = summary.output_input_map.get(idx) {
                // Passthrough output: resolve type from the caller's argument.
                // Origin::Input uses 0=deepest, but args uses 0=topmost (inverted).
                args.len()
                    .checked_sub(1 + *input_idx)
                    .and_then(|i| args.get(i))
                    .map(|arg| self.inferred_type_for_var(arg))
                    .unwrap_or(TypeFact::Felt)
            } else {
                summary
                    .outputs
                    .get(idx)
                    .map(|t| TypeFact::from_inferred_type(*t))
                    .unwrap_or(TypeFact::Felt)
            };
            changed |= self.set_inferred_type_for_var(result, ty);
        }
        changed
    }

    /// Infer result type for an intrinsic output at a given position.
    ///
    /// Position 0 is the first pushed result (deepest on stack for multi-output
    /// intrinsics). The last position is the topmost result on the stack.
    fn intrinsic_output_type(
        &self,
        name: &str,
        output_index: usize,
        output_count: usize,
        args: &[Var],
    ) -> TypeFact {
        let base = Self::intrinsic_base_name(name);
        match base {
            // Multi-output intrinsics with Bool carry/borrow flag as last output.
            "u32overflowing_add" | "u32overflowing_sub" | "u32overflowing_add3" => {
                if output_index == output_count - 1 {
                    TypeFact::Bool
                } else {
                    TypeFact::U32
                }
            },
            // `u32widening_add` leaves the low limb on top of the stack and the
            // carry underneath it.
            "u32widening_add" => {
                if output_index == output_count - 1 {
                    TypeFact::U32
                } else {
                    TypeFact::Bool
                }
            },
            // `u32widening_add3` also leaves the low limb on top. When the
            // carry input is already known Bool, the carry output stays Bool.
            "u32widening_add3" => {
                if output_index == output_count - 1 {
                    TypeFact::U32
                } else if args.iter().any(|arg| self.inferred_type_for_var(arg) == TypeFact::Bool) {
                    TypeFact::Bool
                } else {
                    TypeFact::U32
                }
            },
            // Multi-output intrinsics where all outputs are U32.
            "u32widening_mul" | "u32widening_madd" | "u32divmod" | "u32split" | "u32mod"
            | "u32wrapping_add3" | "u32wrapping_madd" => TypeFact::U32,
            // Word test leaves a boolean on top of the stack.
            "u32testw" => TypeFact::Bool,
            // Other u32 intrinsics and sdepth: all outputs U32.
            _ if base.starts_with("u32") || name == "sdepth" => TypeFact::U32,
            // locaddr: U32. Note: uses `name` (not `base`) because
            // `intrinsic_base_name` strips at the first dot, turning
            // `locaddr.0` into `locaddr`. The match on `base` above
            // intentionally falls through to these wildcard arms for dotted
            // intrinsics.
            _ if name.starts_with("locaddr.") => TypeFact::U32,
            // is_odd: Bool.
            "is_odd" => TypeFact::Bool,
            // All other intrinsics (crypto, extension field, mem_stream,
            // adv_pipe, etc.): Felt.
            _ => TypeFact::Felt,
        }
    }

    /// Return intrinsic base name without suffixes such as `.err=*` or immediates.
    fn intrinsic_base_name(name: &str) -> &str {
        name.split_once('.').map_or(name, |(base, _)| base)
    }

    /// Return true if intrinsic arguments require a caller-side u32 precondition.
    fn intrinsic_requires_u32_precondition(name: &str) -> bool {
        let base = Self::intrinsic_base_name(name);
        if !name.starts_with("u32") {
            return false;
        }

        !matches!(
            base,
            "u32assert" | "u32assert2" | "u32assertw" | "u32split" | "u32cast" | "u32testw"
        )
    }

    /// Return true if this intrinsic asserts that all arguments are valid u32 values.
    fn intrinsic_asserts_u32_args(name: &str) -> bool {
        matches!(Self::intrinsic_base_name(name), "u32assert" | "u32assert2" | "u32assertw")
    }

    /// Infer type for an expression.
    fn infer_expr_type(&self, expr: &Expr) -> TypeFact {
        match expr {
            Expr::True | Expr::False => TypeFact::Bool,
            Expr::Var(var) => self.inferred_type_for_var(var),
            Expr::Constant(constant) => self.infer_constant_type(constant),
            Expr::Unary(op, inner) => self.infer_unary_expr_type(*op, inner),
            Expr::Binary(op, lhs, rhs) => self.infer_binary_expr_type(*op, lhs, rhs),
            Expr::EqW { .. } => TypeFact::Bool,
            Expr::Ternary { then_expr, else_expr, .. } => {
                let then_ty = self.infer_expr_type(then_expr);
                let else_ty = self.infer_expr_type(else_expr);
                let selector_floor = self
                    .selector_input_lower_bound(then_expr)
                    .join(self.selector_input_lower_bound(else_expr));
                then_ty.join(else_ty).glb(selector_floor)
            },
        }
    }

    /// Read a control-flow merge source type, preserving input-backed requirements.
    ///
    /// This keeps branch merges precise when one arm returns an unchanged
    /// input-backed value and the other arm computes a value with the same
    /// proven `U32`/`Bool` requirement.
    fn inferred_phi_source_type(&self, var: &Var) -> TypeFact {
        let inferred = self.inferred_type_for_var(var);
        if let Some(Origin::Input(input_idx)) = self.origins.get(&VarKey::from_var(var)) {
            let input_req = self
                .required
                .get(&Self::input_var_key(*input_idx))
                .copied()
                .unwrap_or(TypeFact::Felt);
            inferred.glb(input_req)
        } else {
            inferred
        }
    }

    /// Return the shared lower bound guaranteed by an input-backed selector arm.
    ///
    /// Only input-backed values may inherit requirements as proven facts. A
    /// computed value with a downstream obligation must stay broad until some
    /// validating instruction proves that obligation.
    fn selector_input_lower_bound(&self, expr: &Expr) -> TypeFact {
        match expr {
            Expr::Var(var)
                if matches!(self.origins.get(&VarKey::from_var(var)), Some(Origin::Input(_))) =>
            {
                self.requirement_for_var(var)
            },
            Expr::Ternary { then_expr, else_expr, .. } => self
                .selector_input_lower_bound(then_expr)
                .join(self.selector_input_lower_bound(else_expr)),
            Expr::True
            | Expr::False
            | Expr::Var(_)
            | Expr::Constant(_)
            | Expr::Unary(..)
            | Expr::Binary(..)
            | Expr::EqW { .. } => TypeFact::Felt,
        }
    }

    /// Infer type for a constant expression.
    ///
    /// `Felt(0)` and `Felt(1)` are inferred as `Bool` since they are the
    /// most precise type for these values. Constants in the u32 range are
    /// inferred as `U32`. The chain lattice ensures they widen correctly
    /// in arithmetic or felt contexts.
    fn infer_constant_type(&self, constant: &Constant) -> TypeFact {
        match constant {
            Constant::Felt(0 | 1) => TypeFact::Bool,
            Constant::Felt(n) if *n < MAX_MEMORY_ADDRESS => TypeFact::U32,
            Constant::Felt(_) | Constant::Defined(_) => TypeFact::Felt,
            Constant::Word(_) => TypeFact::Felt,
        }
    }

    /// Infer type for a unary expression.
    fn infer_unary_expr_type(&self, op: UnOp, _inner: &Expr) -> TypeFact {
        match op {
            UnOp::Not => TypeFact::Bool,
            UnOp::U32Test => TypeFact::Bool,
            UnOp::U32Cast
            | UnOp::U32Not
            | UnOp::U32Clz
            | UnOp::U32Ctz
            | UnOp::U32Clo
            | UnOp::U32Cto => TypeFact::U32,
            UnOp::Neg | UnOp::Inv | UnOp::Pow2 => TypeFact::Felt,
        }
    }

    /// Infer type for a binary expression.
    fn infer_binary_expr_type(&self, op: BinOp, lhs: &Expr, rhs: &Expr) -> TypeFact {
        match op {
            BinOp::Eq
            | BinOp::Neq
            | BinOp::Lt
            | BinOp::Lte
            | BinOp::Gt
            | BinOp::Gte
            | BinOp::And
            | BinOp::Or
            | BinOp::Xor
            | BinOp::U32Lt
            | BinOp::U32Lte
            | BinOp::U32Gt
            | BinOp::U32Gte => TypeFact::Bool,
            BinOp::U32And
            | BinOp::U32Or
            | BinOp::U32Xor
            | BinOp::U32Shl
            | BinOp::U32Shr
            | BinOp::U32Rotr
            | BinOp::U32WrappingAdd
            | BinOp::U32WrappingSub
            | BinOp::U32WrappingMul => TypeFact::U32,
            BinOp::Add if self.is_u32_count_offset_expr(lhs, rhs) => TypeFact::U32,
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::U32Exp => TypeFact::Felt,
        }
    }

    /// Return true when an addition preserves a `u32` bit-count result plus a safe constant.
    fn is_u32_count_offset_expr(&self, lhs: &Expr, rhs: &Expr) -> bool {
        self.count_offset_operands(lhs, rhs)
            .or_else(|| self.count_offset_operands(rhs, lhs))
            .is_some()
    }

    /// Match `count_expr + constant` where the count expression comes from a `u32` count op.
    fn count_offset_operands(&self, count_expr: &Expr, other: &Expr) -> Option<()> {
        let offset = match other {
            Expr::Constant(Constant::Felt(value)) => *value,
            _ => return None,
        };
        if offset > (u32::MAX as u64).saturating_sub(32) {
            return None;
        }
        self.is_direct_u32_count_expr(count_expr).then_some(())
    }

    /// Return true when the expression is a `u32` count result, following local copy chains.
    fn is_direct_u32_count_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Unary(UnOp::U32Clz | UnOp::U32Ctz | UnOp::U32Clo | UnOp::U32Cto, _) => true,
            Expr::Var(var) => self
                .expr_defs
                .get(&VarKey::from_var(var))
                .is_some_and(|def| self.is_direct_u32_count_expr(def)),
            _ => false,
        }
    }

    /// Read inferred type for a variable.
    fn inferred_type_for_var(&self, var: &Var) -> TypeFact {
        self.inferred.get(&VarKey::from_var(var)).copied().unwrap_or(TypeFact::Felt)
    }

    /// Resolve the abstract memory address key for a variable, if known.
    fn mem_address_key_for_var(&self, var: &Var) -> Option<MemAddressKey> {
        self.var_address_keys.get(&VarKey::from_var(var)).copied()
    }

    /// Propagate a `MemAddressKey` through a phi node when both incoming
    /// values share the same key. If the keys disagree or either is absent,
    /// no key is assigned (conservative).
    fn propagate_phi_address_key(&mut self, dest: &Var, lhs: &Var, rhs: &Var) {
        let lhs_key = self.mem_address_key_for_var(lhs);
        let rhs_key = self.mem_address_key_for_var(rhs);
        if let (Some(lk), Some(rk)) = (lhs_key, rhs_key)
            && lk == rk
        {
            self.var_address_keys.insert(VarKey::from_var(dest), lk);
        }
    }

    /// Resolve a `MemAddressKey` for an address-plus-offset expression.
    ///
    /// Returns `Some(LocalAddrOffset(index, offset))` when `base_expr`
    /// resolves to a `LocalAddr` or `LocalAddrOffset` key and `offset_expr`
    /// is a constant in `[0, 2^32)`. Returns `None` if the accumulated
    /// offset overflows `u32` or the base is not a local address.
    fn resolve_addr_offset_key(
        &self,
        base_expr: &Expr,
        offset_expr: &Expr,
    ) -> Option<MemAddressKey> {
        let base_key = match base_expr {
            Expr::Var(v) => self.mem_address_key_for_var(v)?,
            _ => return None,
        };
        let offset: u32 = match offset_expr {
            Expr::Constant(Constant::Felt(n)) if *n < MAX_MEMORY_ADDRESS => *n as u32,
            Expr::Var(v) => match self.mem_address_key_for_var(v)? {
                MemAddressKey::Constant(n) => n,
                _ => return None,
            },
            _ => return None,
        };
        match base_key {
            MemAddressKey::LocalAddr(index) => Some(MemAddressKey::LocalAddrOffset(index, offset)),
            MemAddressKey::LocalAddrOffset(index, base_offset) => {
                let total = base_offset.checked_add(offset)?;
                Some(MemAddressKey::LocalAddrOffset(index, total))
            },
            MemAddressKey::Constant(_) => None,
        }
    }

    /// Record the inferred type for a local variable slot from stored values.
    ///
    /// Combines the types of all stored values via [`TypeFact::glb`] and
    /// joins with the existing slot type. Returns `true` if the type changed.
    fn record_local_store_type(&mut self, index: u16, values: &[Var]) -> bool {
        let stored_ty = values
            .iter()
            .map(|v| self.inferred_type_for_var(v))
            .reduce(TypeFact::glb)
            .unwrap_or(TypeFact::Felt);
        let current = self.local_types.get(&index).copied();
        let updated = match current {
            Some(existing) => existing.join(stored_ty),
            None => stored_ty,
        };
        if current != Some(updated) {
            self.local_types.insert(index, updated);
            true
        } else {
            false
        }
    }

    /// Propagate a local slot's accumulated requirement to stored values.
    ///
    /// Looks up the requirement for `index` in [`local_requirements`] and
    /// applies it to each stored value. Returns `true` if any requirement
    /// changed.
    fn propagate_local_store_requirement(&mut self, index: u16, values: &[Var]) -> bool {
        let req = self.local_requirements.get(&index).copied().unwrap_or(TypeFact::Felt);
        if req == TypeFact::Felt {
            return false;
        }
        let mut changed = false;
        for value in values {
            changed |= self.apply_requirement_to_var(value, req);
        }
        changed
    }

    /// Update inferred type for a variable.
    fn set_inferred_type_for_var(&mut self, var: &Var, new_type: TypeFact) -> bool {
        let key = VarKey::from_var(var);
        let current = self.inferred.get(&key).copied().unwrap_or(TypeFact::Felt);
        let updated = current.glb(new_type);
        if updated != current {
            self.inferred.insert(key, updated);
            true
        } else {
            false
        }
    }

    /// Return the common proven fact established by a scalar equality assertion.
    ///
    /// When `assert_eq(lhs, rhs)` succeeds, both operands must satisfy the
    /// greatest lower bound of their already-proven facts.
    fn assert_eq_common_fact(&self, intrinsic: &crate::ir::Intrinsic) -> Option<TypeFact> {
        if Self::intrinsic_base_name(&intrinsic.name) != "assert_eq" || intrinsic.args.len() != 2 {
            return None;
        }

        let lhs = self.inferred_type_for_var(&intrinsic.args[0]);
        let rhs = self.inferred_type_for_var(&intrinsic.args[1]);
        let common = lhs.glb(rhs);
        (common != TypeFact::Felt).then_some(common)
    }

    /// Seed type requirements from direct statement semantics.
    fn seed_requirements_in_block(&mut self, stmts: &[Stmt], allow_proof_narrowing: bool) -> bool {
        let mut changed = false;
        for stmt in stmts {
            changed |= self.seed_requirements_in_stmt(stmt, allow_proof_narrowing);
        }
        changed
    }

    /// Seed type requirements from one statement.
    fn seed_requirements_in_stmt(&mut self, stmt: &Stmt, allow_proof_narrowing: bool) -> bool {
        match stmt {
            Stmt::Assign { expr, .. } => self.seed_requirements_in_expr(expr),
            Stmt::MemLoad { load, .. } => {
                let mut changed = false;
                for address in &load.address {
                    if self.mem_address_key_for_var(address).is_some() {
                        continue;
                    }
                    changed |= self.apply_requirement_to_var(address, TypeFact::U32);
                }
                changed
            },
            Stmt::MemStore { store, .. } => {
                let mut changed = false;
                for address in &store.address {
                    if self.mem_address_key_for_var(address).is_some() {
                        continue;
                    }
                    changed |= self.apply_requirement_to_var(address, TypeFact::U32);
                }
                changed
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                self.seed_call_arg_requirements(&call.target, &call.args)
            },
            Stmt::Intrinsic { intrinsic, .. } => {
                self.seed_intrinsic_arg_requirements(intrinsic, allow_proof_narrowing)
            },
            Stmt::If { cond, then_body, else_body, .. } => {
                let mut changed = self.require_bool_expr(cond);
                changed |= self.seed_requirements_in_block(then_body, false);
                changed |= self.seed_requirements_in_block(else_body, false);
                changed
            },
            Stmt::While { cond, body, .. } => {
                let mut changed = self.require_bool_expr(cond);
                changed |= self.seed_requirements_in_block(body, false);
                changed
            },
            Stmt::Repeat { body, loop_count, .. } => {
                if *loop_count == 0 {
                    false
                } else {
                    self.seed_requirements_in_block(body, allow_proof_narrowing)
                }
            },
            Stmt::AdvLoad { .. }
            | Stmt::AdvStore { .. }
            | Stmt::LocalLoad { .. }
            | Stmt::LocalStore { .. }
            | Stmt::LocalStoreW { .. }
            | Stmt::DynCall { .. }
            | Stmt::Return { .. } => false,
        }
    }

    /// Seed requirements from a call argument list.
    fn seed_call_arg_requirements(&mut self, target: &str, args: &[Var]) -> bool {
        let Some(summary) = self.summary_for_target(target).cloned() else {
            return false;
        };
        if summary.is_opaque() {
            return false;
        }
        let mut changed = false;
        for (arg, expected) in args.iter().zip(summary.inputs.iter().copied()) {
            changed |= self.apply_requirement_to_var(arg, TypeFact::from_requirement(expected));
        }
        changed
    }

    /// Seed requirements for intrinsic arguments.
    fn seed_intrinsic_arg_requirements(
        &mut self,
        intrinsic: &crate::ir::Intrinsic,
        allow_proof_narrowing: bool,
    ) -> bool {
        let mut changed = false;

        // Blanket u32 precondition for u32 arithmetic intrinsics.
        if Self::intrinsic_requires_u32_precondition(&intrinsic.name) {
            for arg in &intrinsic.args {
                changed |= self.require_u32_var_if_not_guaranteed(arg);
            }
        }

        // Per-intrinsic positional requirements.
        let base = Self::intrinsic_base_name(&intrinsic.name);
        match base {
            // mtree_get: [d, i, R, ...] — depth (arg 0) and index (arg 1) are U32.
            "mtree_get" => {
                for arg in intrinsic.args.iter().take(2) {
                    changed |= self.require_u32_var_if_not_guaranteed(arg);
                }
            },
            // mtree_set: [d, i, R, V', ...] — depth (arg 0) and index (arg 1) are U32.
            "mtree_set" => {
                for arg in intrinsic.args.iter().take(2) {
                    changed |= self.require_u32_var_if_not_guaranteed(arg);
                }
            },
            // mtree_verify: [V, d, i, R, ...] — depth (arg 4) and index (arg 5) are U32.
            "mtree_verify" => {
                for arg in intrinsic.args.iter().skip(4).take(2) {
                    changed |= self.require_u32_var_if_not_guaranteed(arg);
                }
            },
            // mem_stream / adv_pipe: address is the last argument.
            "mem_stream" | "adv_pipe" => {
                if let Some(addr) = intrinsic.args.last() {
                    changed |= self.require_u32_var_if_not_guaranteed(addr);
                }
            },
            _ => {},
        }

        if allow_proof_narrowing && let Some(common_fact) = self.assert_eq_common_fact(intrinsic) {
            for arg in &intrinsic.args {
                changed |= self.apply_requirement_to_var(arg, common_fact);
            }
        }

        changed
    }

    /// Seed requirements from expression semantics.
    fn seed_requirements_in_expr(&mut self, expr: &Expr) -> bool {
        match expr {
            Expr::True | Expr::False | Expr::Var(_) | Expr::Constant(_) => false,
            Expr::Unary(op, inner) => {
                let mut changed = self.seed_requirements_in_expr(inner);
                match op {
                    UnOp::Not => changed |= self.require_bool_expr(inner),
                    UnOp::U32Cast | UnOp::U32Test => {},
                    UnOp::Pow2 => {
                        changed |= self.require_u32_expr_if_not_guaranteed(inner);
                    },
                    UnOp::U32Not | UnOp::U32Clz | UnOp::U32Ctz | UnOp::U32Clo | UnOp::U32Cto => {
                        changed |= self.require_u32_expr_if_not_guaranteed(inner);
                    },
                    UnOp::Neg | UnOp::Inv => {
                        changed |= self.require_felt_expr(inner);
                    },
                }
                changed
            },
            Expr::Binary(op, lhs, rhs) => {
                let mut changed = self.seed_requirements_in_expr(lhs);
                changed |= self.seed_requirements_in_expr(rhs);
                match op {
                    BinOp::U32And
                    | BinOp::U32Or
                    | BinOp::U32Xor
                    | BinOp::U32Shl
                    | BinOp::U32Shr
                    | BinOp::U32Rotr
                    | BinOp::U32Lt
                    | BinOp::U32Lte
                    | BinOp::U32Gt
                    | BinOp::U32Gte
                    | BinOp::U32WrappingAdd
                    | BinOp::U32WrappingSub
                    | BinOp::U32WrappingMul => {
                        changed |= self.require_u32_expr_if_not_guaranteed(lhs);
                        changed |= self.require_u32_expr_if_not_guaranteed(rhs);
                    },
                    BinOp::U32Exp => {
                        changed |= self.require_felt_expr(lhs);
                        changed |= self.require_u32_expr_if_not_guaranteed(rhs);
                    },
                    BinOp::And | BinOp::Or | BinOp::Xor => {
                        changed |= self.require_bool_expr(lhs);
                        changed |= self.require_bool_expr(rhs);
                    },
                    BinOp::Add
                    | BinOp::Sub
                    | BinOp::Mul
                    | BinOp::Div
                    | BinOp::Eq
                    | BinOp::Neq
                    | BinOp::Lt
                    | BinOp::Lte
                    | BinOp::Gt
                    | BinOp::Gte => {
                        changed |= self.require_felt_expr(lhs);
                        changed |= self.require_felt_expr(rhs);
                    },
                }
                changed
            },
            Expr::EqW { lhs, rhs } => {
                let mut changed = false;
                for var in lhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                for var in rhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                changed
            },
            Expr::Ternary { cond, then_expr, else_expr } => {
                let mut changed = self.require_bool_expr(cond);
                changed |= self.seed_requirements_in_expr(then_expr);
                changed |= self.seed_requirements_in_expr(else_expr);
                changed
            },
        }
    }

    /// Propagate requirements through copy-like dataflow.
    fn propagate_requirements_in_block(&mut self, stmts: &[Stmt]) -> bool {
        let mut changed = false;
        for stmt in stmts {
            changed |= self.propagate_requirements_in_stmt(stmt);
        }
        changed
    }

    /// Propagate requirements through one statement.
    fn propagate_requirements_in_stmt(&mut self, stmt: &Stmt) -> bool {
        match stmt {
            Stmt::Assign { dest, expr, .. } => {
                let req = self.requirement_for_var(dest);
                if req == TypeFact::Felt {
                    return false;
                }
                self.apply_requirement_to_expr(expr, req)
            },
            Stmt::If { then_body, else_body, phis, .. } => {
                let mut changed = false;
                changed |= self.propagate_requirements_in_block(then_body);
                changed |= self.propagate_requirements_in_block(else_body);
                for phi in phis {
                    let req = self.requirement_for_var(&phi.dest);
                    if req == TypeFact::Felt {
                        continue;
                    }
                    changed |= self.apply_requirement_to_var(&phi.then_var, req);
                    changed |= self.apply_requirement_to_var(&phi.else_var, req);
                }
                changed
            },
            Stmt::While { body, phis, .. } => {
                let mut changed = false;
                changed |= self.propagate_requirements_in_block(body);
                for phi in phis {
                    let req = self.requirement_for_var(&phi.dest);
                    if req == TypeFact::Felt {
                        continue;
                    }
                    changed |= self.apply_requirement_to_var(&phi.init, req);
                    changed |= self.apply_requirement_to_var(&phi.step, req);
                }
                changed
            },
            Stmt::Repeat { body, phis, loop_count, .. } => {
                let mut changed = false;
                if *loop_count > 0 {
                    changed |= self.propagate_requirements_in_block(body);
                }
                for phi in phis {
                    let req = self.requirement_for_var(&phi.dest);
                    if req == TypeFact::Felt {
                        continue;
                    }
                    changed |= self.apply_requirement_to_var(&phi.init, req);
                    if *loop_count > 0 {
                        changed |= self.apply_requirement_to_var(&phi.step, req);
                    }
                }
                changed
            },
            Stmt::LocalLoad { load, .. } => {
                let mut changed = false;
                for output in &load.outputs {
                    let req = self.requirement_for_var(output);
                    if req == TypeFact::Felt {
                        continue;
                    }
                    let current =
                        self.local_requirements.get(&load.index).copied().unwrap_or(TypeFact::Felt);
                    let updated = current.glb(req);
                    if updated != current {
                        self.local_requirements.insert(load.index, updated);
                        changed = true;
                    }
                }
                changed
            },
            Stmt::LocalStore { store, .. } => {
                self.propagate_local_store_requirement(store.index, &store.values)
            },
            Stmt::LocalStoreW { store, .. } => {
                self.propagate_local_store_requirement(store.index, &store.values)
            },
            Stmt::MemLoad { load, .. } => {
                let mut changed = false;
                if let Some(addr_key) =
                    load.address.first().and_then(|v| self.mem_address_key_for_var(v))
                {
                    for output in &load.outputs {
                        let req = self.requirement_for_var(output);
                        if req == TypeFact::Felt {
                            continue;
                        }
                        let current =
                            self.mem_requirements.get(&addr_key).copied().unwrap_or(TypeFact::Felt);
                        let updated = current.glb(req);
                        if updated != current {
                            self.mem_requirements.insert(addr_key, updated);
                            changed = true;
                        }
                    }
                }
                changed
            },
            Stmt::MemStore { store, .. } => {
                let mut changed = false;
                if let Some(addr_key) =
                    store.address.first().and_then(|v| self.mem_address_key_for_var(v))
                {
                    let req =
                        self.mem_requirements.get(&addr_key).copied().unwrap_or(TypeFact::Felt);
                    if req != TypeFact::Felt {
                        for value in &store.values {
                            changed |= self.apply_requirement_to_var(value, req);
                        }
                    }
                }
                changed
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                let mut changed = false;
                if let Some(summary) = self.summary_for_target(&call.target).cloned() {
                    for (idx, result) in call.results.iter().enumerate() {
                        let req = self.requirement_for_var(result);
                        if req == TypeFact::Felt {
                            continue;
                        }
                        if let Some(Some(input_idx)) = summary.output_input_map.get(idx)
                            && let Some(arg) = call
                                .args
                                .len()
                                .checked_sub(1 + *input_idx)
                                .and_then(|i| call.args.get(i))
                        {
                            changed |= self.apply_requirement_to_var(arg, req);
                        }
                    }
                }
                changed
            },
            Stmt::AdvLoad { .. }
            | Stmt::AdvStore { .. }
            | Stmt::DynCall { .. }
            | Stmt::Intrinsic { .. }
            | Stmt::Return { .. } => false,
        }
    }

    /// Apply a requirement to an expression from a required destination.
    fn apply_requirement_to_expr(&mut self, expr: &Expr, req: TypeFact) -> bool {
        match expr {
            Expr::Var(var) => self.apply_requirement_to_var(var, req),
            Expr::Ternary { cond, then_expr, else_expr } => {
                let mut changed = self.require_bool_expr(cond);
                changed |= self.apply_requirement_to_expr(then_expr, req);
                changed |= self.apply_requirement_to_expr(else_expr, req);
                changed
            },
            Expr::EqW { .. } => false,
            Expr::True | Expr::False | Expr::Constant(_) | Expr::Binary(..) | Expr::Unary(..) => {
                false
            },
        }
    }

    /// Read the current requirement for a variable.
    fn requirement_for_var(&self, var: &Var) -> TypeFact {
        self.required.get(&VarKey::from_var(var)).copied().unwrap_or(TypeFact::Felt)
    }

    /// Apply a requirement to a variable.
    fn apply_requirement_to_var(&mut self, var: &Var, req: TypeFact) -> bool {
        if req == TypeFact::Felt {
            return false;
        }
        let key = VarKey::from_var(var);
        let current = self.required.get(&key).copied().unwrap_or(TypeFact::Felt);
        let updated = current.glb(req);
        if updated != current {
            self.required.insert(key, updated);
            true
        } else {
            false
        }
    }

    /// Require a variable to be u32 only if it is not already guaranteed u32.
    fn require_u32_var_if_not_guaranteed(&mut self, var: &Var) -> bool {
        let actual = self.inferred_type_for_var(var);
        if actual.satisfies(TypeFact::U32) {
            false
        } else {
            self.apply_requirement_to_var(var, TypeFact::U32)
        }
    }

    /// Require that an expression is boolean.
    fn require_bool_expr(&mut self, expr: &Expr) -> bool {
        match expr {
            Expr::Var(var) => self.apply_requirement_to_var(var, TypeFact::Bool),
            Expr::Unary(UnOp::Not, inner) => self.require_bool_expr(inner),
            Expr::Binary(BinOp::And | BinOp::Or, lhs, rhs) => {
                self.require_bool_expr(lhs) | self.require_bool_expr(rhs)
            },
            Expr::Ternary { cond, then_expr, else_expr } => {
                self.require_bool_expr(cond)
                    | self.require_bool_expr(then_expr)
                    | self.require_bool_expr(else_expr)
            },
            Expr::EqW { lhs, rhs } => {
                let mut changed = false;
                for var in lhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                for var in rhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                changed
            },
            Expr::True | Expr::False | Expr::Constant(_) | Expr::Binary(..) | Expr::Unary(..) => {
                false
            },
        }
    }

    /// Require that an expression is U32.
    fn require_u32_expr(&mut self, expr: &Expr) -> bool {
        match expr {
            Expr::Var(var) => self.apply_requirement_to_var(var, TypeFact::U32),
            Expr::Ternary { cond, then_expr, else_expr } => {
                self.require_bool_expr(cond)
                    | self.require_u32_expr(then_expr)
                    | self.require_u32_expr(else_expr)
            },
            Expr::EqW { .. } => false,
            Expr::True | Expr::False | Expr::Constant(_) | Expr::Binary(..) | Expr::Unary(..) => {
                false
            },
        }
    }

    /// Require an expression to be u32 only if it is not already guaranteed u32.
    fn require_u32_expr_if_not_guaranteed(&mut self, expr: &Expr) -> bool {
        let actual = self.infer_expr_type(expr);
        if actual.satisfies(TypeFact::U32) {
            false
        } else {
            self.require_u32_expr(expr)
        }
    }

    /// Require that an expression is Felt-compatible.
    fn require_felt_expr(&mut self, expr: &Expr) -> bool {
        match expr {
            Expr::Var(var) => self.apply_requirement_to_var(var, TypeFact::Felt),
            Expr::Ternary { cond, then_expr, else_expr } => {
                self.require_bool_expr(cond)
                    | self.require_felt_expr(then_expr)
                    | self.require_felt_expr(else_expr)
            },
            Expr::EqW { lhs, rhs } => {
                let mut changed = false;
                for var in lhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                for var in rhs.iter() {
                    changed |= self.apply_requirement_to_var(var, TypeFact::Felt);
                }
                changed
            },
            Expr::True | Expr::False | Expr::Constant(_) | Expr::Binary(..) | Expr::Unary(..) => {
                false
            },
        }
    }

    /// Look up a callee summary by target string.
    fn summary_for_target(&self, target: &str) -> Option<&TypeSummary> {
        let key = SymbolPath::new(target.to_string());
        self.callee_summaries.get(&key)
    }
}
