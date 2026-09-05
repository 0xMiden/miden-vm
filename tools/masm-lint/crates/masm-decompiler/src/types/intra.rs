//! Intraprocedural type inference and mismatch checking.

use std::{collections::HashMap, hash::Hash};

use tracing::{debug, trace};

use super::{
    calls,
    domain::{TypeFact, VarKey},
    expr_defs::ExprDefs,
    intrinsics,
    locals::LocalState,
    memory::{MAX_MEMORY_ADDRESS, MemAddressKey, MemoryState},
    origin::{self, Origin},
    summary::{TypeSummary, TypeSummaryMap},
    summary_builder,
};
use crate::{
    abstract_interp::{FixpointConfig, FixpointOutcome, JoinSemiLattice, iterate_to_fixpoint},
    ir::{BinOp, Constant, Expr, Stmt, UnOp, Var},
    semantics::intrinsic_asserts_u32_args,
    symbol::path::SymbolPath,
};

/// Maximum number of fixed-point iterations for local type inference.
const MAX_TYPE_PASSES: usize = 128;

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

/// Converging state for intraprocedural type inference.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ProcTypeState {
    /// Inferred type guarantees for variables.
    inferred: HashMap<VarKey, TypeFact>,
    /// Inferred requirements for variables.
    required: HashMap<VarKey, TypeFact>,
    /// Local slot types and requirements.
    locals: LocalState,
    /// Memory address identities, memory types, and memory requirements.
    memory: MemoryState,
}

impl JoinSemiLattice for ProcTypeState {
    fn join_assign(&mut self, other: &Self) -> bool {
        let mut changed = false;
        changed |= merge_type_fact_map(&mut self.inferred, &other.inferred, TypeFact::glb);
        changed |= merge_type_fact_map(&mut self.required, &other.required, TypeFact::glb);
        changed |= self.locals.join_assign(&other.locals);
        changed |= self.memory.join_assign(&other.memory);
        changed
    }
}

fn merge_type_fact_map<K>(
    target: &mut HashMap<K, TypeFact>,
    source: &HashMap<K, TypeFact>,
    merge: impl Fn(TypeFact, TypeFact) -> TypeFact,
) -> bool
where
    K: Clone + Eq + Hash,
{
    let mut changed = false;
    for (key, source_fact) in source {
        let updated = target
            .get(key)
            .copied()
            .map_or(*source_fact, |target_fact| merge(target_fact, *source_fact));
        if target.get(key).copied() != Some(updated) {
            target.insert(key.clone(), updated);
            changed = true;
        }
    }
    changed
}

/// Internal fixed-point analyzer for one procedure.
struct ProcTypeAnalyzer<'a> {
    /// Number of stack inputs.
    input_count: usize,
    /// Number of stack outputs.
    output_count: usize,
    /// Previously inferred summaries for callees.
    callee_summaries: &'a TypeSummaryMap,
    /// Converging type inference state.
    state: ProcTypeState,
    /// Input-backed provenance for SSA variables.
    ///
    /// This is computed once from the lifted body and callee passthrough maps.
    /// It lets selector typing distinguish real input-backed values from
    /// computed values that only happen to inherit a downstream requirement.
    origins: HashMap<VarKey, Origin>,
    /// Direct expression definitions for SSA assignments.
    expr_defs: ExprDefs,
}

impl<'a> ProcTypeAnalyzer<'a> {
    /// Construct a new analyzer.
    fn new(input_count: usize, output_count: usize, callee_summaries: &'a TypeSummaryMap) -> Self {
        Self {
            input_count,
            output_count,
            callee_summaries,
            state: ProcTypeState::default(),
            origins: HashMap::new(),
            expr_defs: ExprDefs::default(),
        }
    }

    /// Run fixed-point inference and mismatch checks.
    fn analyze(&mut self, stmts: &[Stmt]) -> TypeSummary {
        self.origins = origin::compute_origins(stmts, self.input_count, self.callee_summaries);
        self.expr_defs = ExprDefs::collect(stmts);

        let result = iterate_to_fixpoint(
            self.state.clone(),
            FixpointConfig::new(MAX_TYPE_PASSES),
            |state| {
                self.state = state.clone();
                self.run_type_pass(stmts);
                self.state.clone()
            },
        );

        match result.outcome() {
            FixpointOutcome::Converged => {
                trace!(
                    analysis = "type_inference",
                    iterations = result.iterations(),
                    "type inference converged"
                );
            },
            FixpointOutcome::ReachedIterationLimitAfterChange
            | FixpointOutcome::ReachedIterationLimit => {
                debug!(
                    analysis = "type_inference",
                    iterations = result.iterations(),
                    max_iterations = MAX_TYPE_PASSES,
                    outcome = ?result.outcome(),
                    "type inference reached iteration cutoff"
                );
            },
        }
        self.state = result.into_state();

        summary_builder::build_summary(
            self.input_count,
            self.output_count,
            stmts,
            &self.state.inferred,
            &self.state.required,
            &self.origins,
        )
    }

    /// Run one complete type-inference transfer pass.
    fn run_type_pass(&mut self, stmts: &[Stmt]) {
        // Return values are intentionally discarded: convergence is detected
        // by joining full state snapshots in the shared fixpoint engine, not
        // by per-call `changed` flags, which can oscillate within a pass.
        let _ = self.infer_types_in_block(stmts, true);
        let _ = self.seed_requirements_in_block(stmts, true);
        let _ = self.propagate_requirements_in_block(stmts);
    }

    /// Build the canonical key for an input variable by stack index.
    fn input_var_key(index: usize) -> VarKey {
        origin::input_var_key(index)
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
                self.state.memory.track_assignment_address_key(dest, expr);
                changed
            },
            Stmt::MemLoad { load, .. } => {
                let stored_ty = load
                    .address
                    .first()
                    .and_then(|v| self.mem_address_key_for_var(v))
                    .and_then(|key| self.state.memory.type_for_address(key))
                    .unwrap_or(TypeFact::Felt);
                let mut changed = false;
                for output in &load.outputs {
                    changed |= self.set_inferred_type_for_var(output, stored_ty);
                }
                changed
            },
            Stmt::LocalLoad { load, .. } => {
                let stored_ty = self.state.locals.type_for_slot(load.index);
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
                let output_types = intrinsics::output_types(
                    &intrinsic.name,
                    output_count,
                    &intrinsic.args,
                    |arg| self.inferred_type_for_var(arg),
                );
                for (result, result_ty) in intrinsic.results.iter().zip(output_types) {
                    changed |= self.set_inferred_type_for_var(result, result_ty);
                }
                if allow_proof_narrowing && intrinsic_asserts_u32_args(&intrinsic.name) {
                    for arg in &intrinsic.args {
                        changed |= self.set_inferred_type_for_var(arg, TypeFact::U32);
                    }
                }
                if allow_proof_narrowing
                    && let Some(common_fact) =
                        intrinsics::assert_eq_common_fact(&intrinsic.name, &intrinsic.args, |arg| {
                            self.inferred_type_for_var(arg)
                        })
                {
                    for arg in &intrinsic.args {
                        changed |= self.set_inferred_type_for_var(arg, common_fact);
                    }
                }
                self.state.memory.track_locaddr_results(&intrinsic.name, &intrinsic.results);
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
                        self.state.memory.copy_address_key(&phi.dest, &phi.init);
                    }
                }
                changed
            },
            Stmt::LocalStore { store, .. } => {
                let stored_ty = LocalState::stored_values_type(&store.values, |v| {
                    self.inferred_type_for_var(v)
                });
                self.state.locals.record_store_type(store.index, stored_ty)
            },
            Stmt::LocalStoreW { store, .. } => {
                let stored_ty = LocalState::stored_values_type(&store.values, |v| {
                    self.inferred_type_for_var(v)
                });
                self.state.locals.record_store_type(store.index, stored_ty)
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
                    changed |= self.state.memory.record_store_type(addr_key, stored_ty);
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
        let result_types = calls::result_types(&summary, args, results.len(), |arg| {
            self.inferred_type_for_var(arg)
        });
        for (result, ty) in results.iter().zip(result_types) {
            changed |= self.set_inferred_type_for_var(result, ty);
        }
        changed
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
                .state
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
        self.expr_defs.is_u32_count_expr(count_expr).then_some(())
    }

    /// Read inferred type for a variable.
    fn inferred_type_for_var(&self, var: &Var) -> TypeFact {
        self.state
            .inferred
            .get(&VarKey::from_var(var))
            .copied()
            .unwrap_or(TypeFact::Felt)
    }

    /// Resolve the abstract memory address key for a variable, if known.
    fn mem_address_key_for_var(&self, var: &Var) -> Option<MemAddressKey> {
        self.state.memory.address_key_for_var(var)
    }

    /// Propagate a `MemAddressKey` through a phi node when both incoming
    /// values share the same key. If the keys disagree or either is absent,
    /// no key is assigned (conservative).
    fn propagate_phi_address_key(&mut self, dest: &Var, lhs: &Var, rhs: &Var) {
        self.state.memory.propagate_phi_address_key(dest, lhs, rhs);
    }

    /// Update inferred type for a variable.
    fn set_inferred_type_for_var(&mut self, var: &Var, new_type: TypeFact) -> bool {
        let key = VarKey::from_var(var);
        let current = self.state.inferred.get(&key).copied().unwrap_or(TypeFact::Felt);
        let updated = current.glb(new_type);
        if updated != current {
            self.state.inferred.insert(key, updated);
            true
        } else {
            false
        }
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
        let mut changed = false;
        for (arg, req) in calls::arg_requirements(&summary, args) {
            changed |= self.apply_requirement_to_var(arg, req);
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
        let requirements = intrinsics::arg_requirements(
            &intrinsic.name,
            &intrinsic.args,
            intrinsic.results.len(),
            allow_proof_narrowing,
            |arg| self.inferred_type_for_var(arg),
        );
        for (arg, requirement) in requirements {
            changed |= self.apply_requirement_to_var(arg, requirement);
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
                let requirements: Vec<_> =
                    load.outputs.iter().map(|output| self.requirement_for_var(output)).collect();
                self.state.locals.require_slot_from_outputs(load.index, requirements)
            },
            Stmt::LocalStore { store, .. } => {
                self.propagate_local_store_value_requirements(store.index, &store.values)
            },
            Stmt::LocalStoreW { store, .. } => {
                self.propagate_local_store_value_requirements(store.index, &store.values)
            },
            Stmt::MemLoad { load, .. } => {
                if let Some(addr_key) =
                    load.address.first().and_then(|v| self.mem_address_key_for_var(v))
                {
                    let requirements: Vec<_> = load
                        .outputs
                        .iter()
                        .map(|output| self.requirement_for_var(output))
                        .collect();
                    self.state.memory.require_address_from_outputs(addr_key, requirements)
                } else {
                    false
                }
            },
            Stmt::MemStore { store, .. } => {
                if let Some(addr_key) =
                    store.address.first().and_then(|v| self.mem_address_key_for_var(v))
                {
                    self.propagate_memory_store_value_requirements(addr_key, &store.values)
                } else {
                    false
                }
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                let mut changed = false;
                if let Some(summary) = self.summary_for_target(&call.target).cloned() {
                    let requirements = calls::passthrough_result_requirements(
                        &summary,
                        &call.args,
                        &call.results,
                        |result| self.requirement_for_var(result),
                    );
                    for (arg, req) in requirements {
                        changed |= self.apply_requirement_to_var(arg, req);
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
        self.state
            .required
            .get(&VarKey::from_var(var))
            .copied()
            .unwrap_or(TypeFact::Felt)
    }

    /// Apply a requirement to a variable.
    fn apply_requirement_to_var(&mut self, var: &Var, req: TypeFact) -> bool {
        if req == TypeFact::Felt {
            return false;
        }
        let key = VarKey::from_var(var);
        let current = self.state.required.get(&key).copied().unwrap_or(TypeFact::Felt);
        let updated = current.glb(req);
        if updated != current {
            self.state.required.insert(key, updated);
            true
        } else {
            false
        }
    }

    /// Propagate local slot requirements to values stored in the slot.
    fn propagate_local_store_value_requirements(&mut self, index: u16, values: &[Var]) -> bool {
        let requirements: Vec<_> =
            self.state.locals.store_value_requirements(index, values).collect();
        let mut changed = false;
        for (value, req) in requirements {
            changed |= self.apply_requirement_to_var(value, req);
        }
        changed
    }

    /// Propagate memory address requirements to values stored at the address.
    fn propagate_memory_store_value_requirements(
        &mut self,
        addr_key: MemAddressKey,
        values: &[Var],
    ) -> bool {
        let requirements: Vec<_> =
            self.state.memory.store_value_requirements(addr_key, values).collect();
        let mut changed = false;
        for (value, req) in requirements {
            changed |= self.apply_requirement_to_var(value, req);
        }
        changed
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ir::{IndexExpr, ValueId},
        types::domain::VarBaseKey,
    };

    fn key(id: u64) -> VarKey {
        VarKey {
            base: VarBaseKey::Value(ValueId::from(id)),
            subscript: IndexExpr::Const(0),
        }
    }

    fn var(id: u64) -> Var {
        Var::new(ValueId::from(id), 0)
    }

    #[test]
    fn proc_type_state_join_merges_scalar_maps() {
        let mut left = ProcTypeState::default();
        let mut right = ProcTypeState::default();
        left.inferred.insert(key(1), TypeFact::Felt);
        right.inferred.insert(key(1), TypeFact::U32);
        left.required.insert(key(2), TypeFact::Felt);
        right.required.insert(key(2), TypeFact::U32);

        assert!(left.join_assign(&right));

        assert_eq!(left.inferred.get(&key(1)), Some(&TypeFact::U32));
        assert_eq!(left.required.get(&key(2)), Some(&TypeFact::U32));
    }

    #[test]
    fn proc_type_state_join_merges_local_state() {
        let mut left = ProcTypeState::default();
        let mut right = ProcTypeState::default();
        left.locals.record_store_type(0, TypeFact::Bool);
        right.locals.record_store_type(0, TypeFact::Felt);
        right.locals.require_slot(1, TypeFact::U32);

        assert!(left.join_assign(&right));

        assert_eq!(left.locals.type_for_slot(0), TypeFact::Felt);
        assert_eq!(left.locals.requirement_for_slot(1), TypeFact::U32);
    }

    #[test]
    fn proc_type_state_join_merges_memory_state() {
        let mut left = ProcTypeState::default();
        let mut right = ProcTypeState::default();
        let address = MemAddressKey::LocalAddr(0);
        left.memory.record_store_type(address, TypeFact::Bool);
        right.memory.record_store_type(address, TypeFact::Felt);
        right.memory.require_address(address, TypeFact::U32);

        assert!(left.join_assign(&right));

        assert_eq!(left.memory.type_for_address(address), Some(TypeFact::Felt));
        assert_eq!(left.memory.requirement_for_address(address), TypeFact::U32);
    }

    #[test]
    fn proc_type_state_join_drops_conflicting_memory_address_identities() {
        let mut left = ProcTypeState::default();
        let mut right = ProcTypeState::default();
        let value = var(1);
        left.memory.set_var_address_key(&value, MemAddressKey::LocalAddr(0));
        right.memory.set_var_address_key(&value, MemAddressKey::LocalAddr(1));

        assert!(left.join_assign(&right));
        assert_eq!(left.memory.address_key_for_var(&value), None);

        let mut later = ProcTypeState::default();
        later.memory.set_var_address_key(&value, MemAddressKey::LocalAddr(1));

        assert!(!left.join_assign(&later));
        assert_eq!(left.memory.address_key_for_var(&value), None);
    }
}
