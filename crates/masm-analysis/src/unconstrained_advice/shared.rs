//! Shared state and transfer helpers for unconstrained-advice analyses.

use std::collections::{HashMap, HashSet};

use masm_decompiler::{BinOp, Expr, Intrinsic, LocalAccessKind, LoopPhi, Stmt, UnOp, Var, VarKey};
pub(super) use masm_decompiler::{
    INTRINSIC_ADV_PIPE, INTRINSIC_ADV_PUSH, INTRINSIC_ADV_PUSHW, INTRINSIC_MEM_STREAM,
    intrinsic_base_name, intrinsic_memory_address_arg_index, intrinsic_merkle_root_arg_range,
    intrinsic_nonzero_arg_index, intrinsic_positional_u32_arg_range,
    intrinsic_requires_u32_precondition,
};

use super::{domain::AdviceFact, u32_domain::U32Validity};
use crate::abstract_interp::{FixpointConfig, JoinSemiLattice, iterate_to_fixpoint};

/// Maximum number of loop-approximation passes.
pub(super) const MAX_LOOP_PASSES: usize = 32;

/// Exact witness that a boolean value was computed as `x == 0`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EqZeroWitness {
    /// Alias identity of the value compared against zero.
    pub(super) value_identity: VarKey,
}

/// Shared flow environment at a program point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct Env {
    vars: HashMap<VarKey, AdviceFact>,
    locals: HashMap<u32, AdviceFact>,
    u32_validity: HashMap<VarKey, U32Validity>,
    local_u32_validity: HashMap<u32, U32Validity>,
    u32_valid_identities: HashSet<VarKey>,
    aliases: HashMap<VarKey, VarKey>,
    local_aliases: HashMap<u32, VarKey>,
    zero_tests: HashMap<VarKey, EqZeroWitness>,
    local_zero_tests: HashMap<u32, EqZeroWitness>,
    nonzero_identities: HashSet<VarKey>,
}

impl Env {
    /// Read the current fact for a variable.
    pub(super) fn fact_for_var(&self, var: &Var) -> AdviceFact {
        self.vars
            .get(&VarKey::from_var(var))
            .cloned()
            .unwrap_or_else(AdviceFact::bottom)
    }

    /// Set the current fact for a variable.
    pub(super) fn set_var_fact(&mut self, var: &Var, fact: AdviceFact) {
        self.vars.insert(VarKey::from_var(var), fact);
    }

    /// Read the current `u32` validity fact for a variable.
    pub(super) fn u32_validity_for_var(&self, var: &Var) -> U32Validity {
        let key = VarKey::from_var(var);
        let direct = self.u32_validity.get(&key).copied().unwrap_or(U32Validity::Unknown);
        if direct.is_proven() {
            return direct;
        }

        let identity = self.identity_for_var(var);
        if self.u32_valid_identities.contains(&identity) {
            U32Validity::ProvenU32
        } else {
            U32Validity::Unknown
        }
    }

    /// Set the current `u32` validity fact for a variable.
    pub(super) fn set_var_u32_validity(&mut self, var: &Var, validity: U32Validity) {
        let key = VarKey::from_var(var);
        if validity.is_proven() {
            self.u32_validity.insert(key.clone(), validity);
        } else {
            self.u32_validity.remove(&key);
        }
        let identity = self.identity_for_var(var);
        self.refresh_u32_identity_cache(&identity);
    }

    /// Return the alias identity for a variable.
    pub(super) fn identity_for_var(&self, var: &Var) -> VarKey {
        let key = VarKey::from_var(var);
        self.aliases.get(&key).cloned().unwrap_or(key)
    }

    /// Return the alias identity for a local slot, if known.
    pub(super) fn identity_for_local(&self, slot: u32) -> Option<VarKey> {
        self.local_aliases.get(&slot).cloned()
    }

    /// Set the alias identity for a variable.
    pub(super) fn set_var_identity(&mut self, var: &Var, identity: VarKey) {
        let key = VarKey::from_var(var);
        let old_identity = self.identity_for_var(var);
        if identity == key {
            self.aliases.remove(&key);
        } else {
            self.aliases.insert(key, identity);
        }
        self.refresh_u32_identity_cache(&old_identity);
        self.refresh_u32_identity_cache(&self.identity_for_var(var));
    }

    /// Clear any alias identity for a variable.
    pub(super) fn clear_var_identity(&mut self, var: &Var) {
        let old_identity = self.identity_for_var(var);
        self.aliases.remove(&VarKey::from_var(var));
        self.refresh_u32_identity_cache(&old_identity);
        self.refresh_u32_identity_cache(&self.identity_for_var(var));
    }

    /// Set the alias identity for a local slot.
    pub(super) fn set_local_identity(&mut self, slot: u32, identity: Option<VarKey>) {
        let old_identity = self.identity_for_local(slot);
        match identity {
            Some(identity) => {
                self.local_aliases.insert(slot, identity);
            },
            None => {
                self.local_aliases.remove(&slot);
            },
        }
        if let Some(identity) = old_identity {
            self.refresh_u32_identity_cache(&identity);
        }
        if let Some(identity) = self.identity_for_local(slot) {
            self.refresh_u32_identity_cache(&identity);
        }
    }

    /// Return the zero-test witness for a variable, if any.
    pub(super) fn zero_test_for_var(&self, var: &Var) -> Option<EqZeroWitness> {
        self.zero_tests.get(&VarKey::from_var(var)).cloned()
    }

    /// Return the zero-test witness for a local slot, if any.
    pub(super) fn zero_test_for_local(&self, slot: u32) -> Option<EqZeroWitness> {
        self.local_zero_tests.get(&slot).cloned()
    }

    /// Set the zero-test witness for a variable.
    pub(super) fn set_var_zero_test(&mut self, var: &Var, witness: Option<EqZeroWitness>) {
        match witness {
            Some(witness) => {
                self.zero_tests.insert(VarKey::from_var(var), witness);
            },
            None => {
                self.zero_tests.remove(&VarKey::from_var(var));
            },
        }
    }

    /// Set the zero-test witness for a local slot.
    pub(super) fn set_local_zero_test(&mut self, slot: u32, witness: Option<EqZeroWitness>) {
        match witness {
            Some(witness) => {
                self.local_zero_tests.insert(slot, witness);
            },
            None => {
                self.local_zero_tests.remove(&slot);
            },
        }
    }

    /// Return true if the variable is proven non-zero on the current path.
    pub(super) fn is_var_nonzero(&self, var: &Var) -> bool {
        self.nonzero_identities.contains(&self.identity_for_var(var))
    }

    /// Mark the given alias identity as non-zero on the current path.
    pub(super) fn mark_identity_nonzero(&mut self, identity: VarKey) {
        self.nonzero_identities.insert(identity);
    }

    /// Clear all best-effort metadata for a variable definition.
    pub(super) fn clear_var_metadata(&mut self, var: &Var) {
        self.clear_var_identity(var);
        self.set_var_zero_test(var, None);
    }

    /// Mark a variable as range-checked from this point onward.
    pub(super) fn sanitize_var(&mut self, var: &Var) {
        let identity = self.identity_for_var(var);
        self.set_identity_u32_validity(&identity, U32Validity::ProvenU32);
    }

    /// Read the current fact for a local slot.
    pub(super) fn fact_for_local(&self, slot: u32) -> AdviceFact {
        self.locals.get(&slot).cloned().unwrap_or_else(AdviceFact::bottom)
    }

    /// Read the current `u32` validity fact for a local slot.
    pub(super) fn u32_validity_for_local(&self, slot: u32) -> U32Validity {
        let direct = self.local_u32_validity.get(&slot).copied().unwrap_or(U32Validity::Unknown);
        if direct.is_proven() {
            return direct;
        }

        self.identity_for_local(slot)
            .filter(|identity| self.u32_valid_identities.contains(identity))
            .map(|_| U32Validity::ProvenU32)
            .unwrap_or(U32Validity::Unknown)
    }

    /// Set the current fact for a local slot.
    pub(super) fn set_local_fact(&mut self, slot: u32, fact: AdviceFact) {
        self.locals.insert(slot, fact);
    }

    /// Set the current `u32` validity fact for a local slot.
    pub(super) fn set_local_u32_validity(&mut self, slot: u32, validity: U32Validity) {
        if validity.is_proven() {
            self.local_u32_validity.insert(slot, validity);
        } else {
            self.local_u32_validity.remove(&slot);
        }
        if let Some(identity) = self.identity_for_local(slot) {
            self.refresh_u32_identity_cache(&identity);
        }
    }

    /// Join two environments conservatively.
    pub(super) fn join(&self, other: &Self) -> Self {
        let mut joined = self.clone();
        for (key, fact) in &other.vars {
            let current = joined.vars.get(key).cloned().unwrap_or_else(AdviceFact::bottom);
            joined.vars.insert(key.clone(), current.join(fact));
        }
        for (slot, fact) in &other.locals {
            let current = joined.locals.get(slot).cloned().unwrap_or_else(AdviceFact::bottom);
            joined.locals.insert(*slot, current.join(fact));
        }
        joined.u32_validity = join_u32_validity_maps(&self.u32_validity, &other.u32_validity);
        joined.local_u32_validity =
            join_u32_validity_maps(&self.local_u32_validity, &other.local_u32_validity);
        joined.aliases = agreeing_entries(&self.aliases, &other.aliases);
        joined.local_aliases = agreeing_entries(&self.local_aliases, &other.local_aliases);
        joined.zero_tests = agreeing_entries(&self.zero_tests, &other.zero_tests);
        joined.local_zero_tests = agreeing_entries(&self.local_zero_tests, &other.local_zero_tests);
        joined.nonzero_identities = self
            .nonzero_identities
            .intersection(&other.nonzero_identities)
            .cloned()
            .collect();
        joined.rebuild_u32_identity_cache();
        joined
    }

    /// Set one alias identity to the requested `u32` validity fact.
    fn set_identity_u32_validity(&mut self, identity: &VarKey, validity: U32Validity) {
        if validity.is_proven() {
            self.u32_validity.insert(identity.clone(), validity);
        } else {
            self.u32_validity.remove(identity);
        }
        for key in self
            .aliases
            .iter()
            .filter_map(|(key, alias)| (alias == identity).then_some(key.clone()))
        {
            if validity.is_proven() {
                self.u32_validity.insert(key, validity);
            } else {
                self.u32_validity.remove(&key);
            }
        }
        for (slot, alias) in self.local_aliases.clone() {
            if alias == *identity {
                if validity.is_proven() {
                    self.local_u32_validity.insert(slot, validity);
                } else {
                    self.local_u32_validity.remove(&slot);
                }
            }
        }
        if validity.is_proven() {
            self.u32_valid_identities.insert(identity.clone());
        } else {
            self.u32_valid_identities.remove(identity);
        }
    }

    /// Refresh the cached `u32` proof bit for one alias identity.
    fn refresh_u32_identity_cache(&mut self, identity: &VarKey) {
        let has_proven_var = self
            .u32_validity
            .keys()
            .any(|key| self.aliases.get(key).cloned().unwrap_or_else(|| key.clone()) == *identity);
        let has_proven_local = self
            .local_u32_validity
            .keys()
            .any(|slot| self.local_aliases.get(slot).cloned() == Some(identity.clone()));
        if has_proven_var || has_proven_local {
            self.u32_valid_identities.insert(identity.clone());
        } else {
            self.u32_valid_identities.remove(identity);
        }
    }

    /// Rebuild the alias-identity proof cache from place-level validity facts.
    fn rebuild_u32_identity_cache(&mut self) {
        self.u32_valid_identities.clear();
        let identities = self
            .u32_validity
            .keys()
            .map(|key| self.aliases.get(key).cloned().unwrap_or_else(|| key.clone()))
            .chain(
                self.local_u32_validity
                    .keys()
                    .filter_map(|slot| self.local_aliases.get(slot).cloned()),
            )
            .collect::<Vec<_>>();
        for identity in identities {
            self.refresh_u32_identity_cache(&identity);
        }
    }
}

impl JoinSemiLattice for Env {
    fn join_assign(&mut self, other: &Self) -> bool {
        let joined = self.join(other);
        let changed = *self != joined;
        *self = joined;
        changed
    }
}

/// Retain only entries that are present in both maps with the same value.
fn agreeing_entries<K, V>(lhs: &HashMap<K, V>, rhs: &HashMap<K, V>) -> HashMap<K, V>
where
    K: Clone + Eq + std::hash::Hash,
    V: Clone + Eq,
{
    lhs.iter()
        .filter_map(|(key, value)| {
            rhs.get(key)
                .filter(|other| *other == value)
                .map(|_| (key.clone(), value.clone()))
        })
        .collect()
}

/// Join two sparse `u32` validity maps, treating absent entries as unknown.
fn join_u32_validity_maps<K>(
    lhs: &HashMap<K, U32Validity>,
    rhs: &HashMap<K, U32Validity>,
) -> HashMap<K, U32Validity>
where
    K: Clone + Eq + std::hash::Hash,
{
    lhs.keys()
        .chain(rhs.keys())
        .collect::<HashSet<_>>()
        .into_iter()
        .filter_map(|key| {
            let merged = lhs
                .get(key)
                .copied()
                .unwrap_or(U32Validity::Unknown)
                .join(rhs.get(key).copied().unwrap_or(U32Validity::Unknown));
            merged.is_proven().then_some((key.clone(), merged))
        })
        .collect()
}

/// Seed input variables using the same numbering scheme as the lifting pass.
pub(super) fn seed_input_env(input_count: usize) -> Env {
    let mut env = Env::default();
    for depth in 0..input_count {
        let input_position = input_count - 1 - depth;
        let var = Var::new((depth as u64).into(), depth);
        env.set_var_fact(&var, AdviceFact::from_input(input_position));
    }
    env
}

/// Preserve alias and zero-test metadata across a fresh assignment.
pub(super) fn assign_expr_metadata(dest: &Var, expr: &Expr, env: &mut Env) {
    if let Some(identity) = expr_identity(expr, env) {
        env.set_var_identity(dest, identity);
    } else {
        env.clear_var_identity(dest);
    }
    env.set_var_zero_test(dest, eq_zero_witness_for_expr(expr, env));
    env.set_var_u32_validity(dest, expr_u32_validity(expr, env));
}

/// Preserve metadata across a phi only when both sides agree on the fact being preserved.
pub(super) fn assign_phi_metadata(
    dest: &Var,
    lhs_var: &Var,
    lhs_env: &Env,
    rhs_var: &Var,
    rhs_env: &Env,
    env: &mut Env,
) {
    let lhs_identity = lhs_env.identity_for_var(lhs_var);
    let rhs_identity = rhs_env.identity_for_var(rhs_var);
    if lhs_identity == rhs_identity {
        env.set_var_identity(dest, lhs_identity);
    } else {
        env.clear_var_identity(dest);
    }

    let lhs_witness = lhs_env.zero_test_for_var(lhs_var);
    let rhs_witness = rhs_env.zero_test_for_var(rhs_var);
    if lhs_witness.is_some() && lhs_witness == rhs_witness {
        env.set_var_zero_test(dest, lhs_witness);
    } else {
        env.set_var_zero_test(dest, None);
    }

    env.set_var_u32_validity(
        dest,
        lhs_env
            .u32_validity_for_var(lhs_var)
            .join(rhs_env.u32_validity_for_var(rhs_var)),
    );
}

/// Join one loop-body evaluation back into the current abstract loop state.
pub(super) fn join_loop_head_env(
    loop_env: &Env,
    entry_env: &Env,
    body_env: &Env,
    phis: &[LoopPhi],
) -> Env {
    let mut next_env = loop_env.join(body_env);
    for phi in phis {
        let merged = entry_env.fact_for_var(&phi.init).join(&body_env.fact_for_var(&phi.step));
        next_env.set_var_fact(&phi.dest, merged);
        assign_phi_metadata(&phi.dest, &phi.init, entry_env, &phi.step, body_env, &mut next_env);
    }

    next_env
}

/// Loop-head state used while iterating to a stable environment.
#[derive(Clone)]
struct LoopHeadState<'a> {
    env: Env,
    entry_env: &'a Env,
    phis: &'a [LoopPhi],
}

impl<'a> LoopHeadState<'a> {
    /// Build the initial loop-head state from the loop entry environment.
    fn at_loop_head(entry_env: &'a Env, phis: &'a [LoopPhi]) -> Self {
        Self { env: entry_env.clone(), entry_env, phis }
    }

    /// Build the candidate state produced by one loop-body evaluation.
    fn from_body_env(body_env: Env, entry_env: &'a Env, phis: &'a [LoopPhi]) -> Self {
        Self { env: body_env, entry_env, phis }
    }

    /// Return a clone of the stabilized loop-head environment.
    fn env(&self) -> Env {
        self.env.clone()
    }
}

impl JoinSemiLattice for LoopHeadState<'_> {
    fn join_assign(&mut self, other: &Self) -> bool {
        let next_env = join_loop_head_env(&self.env, self.entry_env, &other.env, self.phis);
        let changed = self.env != next_env;
        self.env = next_env;
        changed
    }
}

/// Iterate a loop body to a stable loop-head environment.
pub(super) fn stabilized_loop_head_env(
    entry_env: &Env,
    phis: &[LoopPhi],
    mut eval_body: impl FnMut(Env) -> Env,
) -> Env {
    iterate_to_fixpoint(
        LoopHeadState::at_loop_head(entry_env, phis),
        FixpointConfig::new(MAX_LOOP_PASSES),
        |loop_env| {
            let body_env = eval_body(loop_env.env());
            LoopHeadState::from_body_env(body_env, entry_env, phis)
        },
    )
    .into_state()
    .env()
}

/// Refine branch environments using an exact `eq.0` witness when available.
pub(super) fn refine_if_envs(cond: &Expr, env: &Env) -> (Env, Env) {
    let then_env = env.clone();
    let mut else_env = env.clone();
    if let Some(witness) = eq_zero_witness_for_expr(cond, env) {
        else_env.mark_identity_nonzero(witness.value_identity);
    }
    (then_env, else_env)
}

/// Refine the environment after `assertz` proves an `eq.0` witness is zero.
pub(super) fn refine_nonzero_from_intrinsic(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic_base_name(&intrinsic.name) != "assertz" {
        return;
    }
    let Some(arg) = intrinsic.args.first() else {
        return;
    };
    let Some(witness) = env.zero_test_for_var(arg) else {
        return;
    };
    env.mark_identity_nonzero(witness.value_identity);
}

/// Return the exact alias identity of an expression, when it is a simple copy.
pub(super) fn expr_identity(expr: &Expr, env: &Env) -> Option<VarKey> {
    match expr {
        Expr::Var(var) => Some(env.identity_for_var(var)),
        _ => None,
    }
}

/// Return the exact `eq.0` witness carried by an expression, if any.
pub(super) fn eq_zero_witness_for_expr(expr: &Expr, env: &Env) -> Option<EqZeroWitness> {
    match expr {
        Expr::Var(var) => env.zero_test_for_var(var),
        Expr::Binary(BinOp::Eq, lhs, rhs) => {
            zero_comparison_var(lhs, rhs).map(|var| EqZeroWitness {
                value_identity: env.identity_for_var(var),
            })
        },
        _ => None,
    }
}

/// Traverse an expression and join sink facts produced at each expression node.
pub(super) fn collect_expr_sink_fact(
    expr: &Expr,
    env: &Env,
    sink_fact: &impl Fn(&Expr, &Env) -> AdviceFact,
) -> AdviceFact {
    let nested = match expr {
        Expr::Var(_) | Expr::True | Expr::False | Expr::Constant(_) | Expr::EqW { .. } => {
            AdviceFact::bottom()
        },
        Expr::Ternary { cond, then_expr, else_expr } => {
            collect_expr_sink_fact(cond, env, sink_fact)
                .join(&collect_expr_sink_fact(then_expr, env, sink_fact))
                .join(&collect_expr_sink_fact(else_expr, env, sink_fact))
        },
        Expr::Unary(_, inner) => collect_expr_sink_fact(inner, env, sink_fact),
        Expr::Binary(_, lhs, rhs) => collect_expr_sink_fact(lhs, env, sink_fact)
            .join(&collect_expr_sink_fact(rhs, env, sink_fact)),
    };

    nested.join(&sink_fact(expr, env))
}

/// Return true when the expression is proven non-zero by the best-effort refinement.
pub(super) fn expr_is_proven_nonzero(expr: &Expr, env: &Env) -> bool {
    match expr {
        Expr::Constant(constant) => !constant.is_zero(),
        Expr::Var(var) => env.is_var_nonzero(var),
        _ => false,
    }
}

/// Compute the provenance fact for an expression result.
pub(super) fn expr_output_fact(expr: &Expr, env: &Env) -> AdviceFact {
    match expr {
        Expr::Var(var) => env.fact_for_var(var),
        Expr::Ternary { then_expr, else_expr, .. } => {
            expr_output_fact(then_expr, env).join(&expr_output_fact(else_expr, env))
        },
        Expr::Unary(op, inner) => match op {
            UnOp::Neg | UnOp::Inv | UnOp::Pow2 => expr_output_fact(inner, env),
            UnOp::Not
            | UnOp::U32Cast
            | UnOp::U32Test
            | UnOp::U32Not
            | UnOp::U32Clz
            | UnOp::U32Ctz
            | UnOp::U32Clo
            | UnOp::U32Cto => AdviceFact::bottom(),
        },
        Expr::Binary(op, lhs, rhs) => match op {
            BinOp::Add | BinOp::Sub | BinOp::Mul | BinOp::Div => {
                expr_output_fact(lhs, env).join(&expr_output_fact(rhs, env))
            },
            BinOp::And
            | BinOp::Or
            | BinOp::Xor
            | BinOp::Eq
            | BinOp::Neq
            | BinOp::Lt
            | BinOp::Lte
            | BinOp::Gt
            | BinOp::Gte
            | BinOp::U32And
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
            | BinOp::U32WrappingMul
            | BinOp::U32Exp => AdviceFact::bottom(),
        },
        Expr::EqW { .. } | Expr::True | Expr::False | Expr::Constant(_) => AdviceFact::bottom(),
    }
}

/// Compute the `u32` validity of an expression result.
pub(super) fn expr_u32_validity(expr: &Expr, env: &Env) -> U32Validity {
    match expr {
        Expr::Var(var) => env.u32_validity_for_var(var),
        Expr::Ternary { then_expr, else_expr, .. } => {
            expr_u32_validity(then_expr, env).join(expr_u32_validity(else_expr, env))
        },
        Expr::Unary(op, _) => match op {
            UnOp::U32Cast
            | UnOp::U32Test
            | UnOp::U32Not
            | UnOp::U32Clz
            | UnOp::U32Ctz
            | UnOp::U32Clo
            | UnOp::U32Cto => U32Validity::ProvenU32,
            UnOp::Neg | UnOp::Inv | UnOp::Pow2 | UnOp::Not => U32Validity::Unknown,
        },
        Expr::Binary(op, ..) => match op {
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
            | BinOp::U32WrappingMul => U32Validity::ProvenU32,
            BinOp::U32Exp
            | BinOp::Add
            | BinOp::Sub
            | BinOp::Mul
            | BinOp::Div
            | BinOp::And
            | BinOp::Or
            | BinOp::Xor
            | BinOp::Eq
            | BinOp::Neq
            | BinOp::Lt
            | BinOp::Lte
            | BinOp::Gt
            | BinOp::Gte => U32Validity::Unknown,
        },
        Expr::EqW { .. } | Expr::True | Expr::False | Expr::Constant(_) => U32Validity::Unknown,
    }
}

/// Apply the common provenance transfer semantics of one intrinsic statement.
pub(super) fn apply_intrinsic_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if matches!(intrinsic_base_name(&intrinsic.name), INTRINSIC_ADV_PUSH | INTRINSIC_ADV_PUSHW) {
        for result in &intrinsic.results {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    match intrinsic_base_name(&intrinsic.name) {
        "u32assert" | "u32assert2" | "u32assertw" => {
            for arg in &intrinsic.args {
                env.sanitize_var(arg);
            }
        },
        "u32split" => {
            for (index, result) in intrinsic.results.iter().enumerate() {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                if index == intrinsic.results.len().saturating_sub(1) {
                    env.set_var_u32_validity(result, U32Validity::ProvenU32);
                }
            }
        },
        "is_odd" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        "u32testw" => {
            if let Some((flag, preserved)) = intrinsic.results.split_first() {
                env.set_var_fact(flag, AdviceFact::bottom());
                env.clear_var_metadata(flag);
                env.set_var_u32_validity(flag, U32Validity::ProvenU32);
                for (result, arg) in preserved.iter().zip(intrinsic.args.iter()) {
                    env.set_var_fact(result, env.fact_for_var(arg));
                    env.set_var_u32_validity(result, env.u32_validity_for_var(arg));
                    env.set_var_identity(result, env.identity_for_var(arg));
                    env.set_var_zero_test(result, env.zero_test_for_var(arg));
                }
            }
        },
        INTRINSIC_ADV_PIPE => {
            apply_adv_pipe_effect(span, intrinsic, env);
        },
        INTRINSIC_MEM_STREAM => {
            apply_mem_stream_effect(intrinsic, env);
        },
        "sdepth" => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        name if name.starts_with("locaddr") => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
            }
        },
        _ if intrinsic_requires_u32_precondition(&intrinsic.name) => {
            for result in &intrinsic.results {
                env.set_var_fact(result, AdviceFact::bottom());
                env.clear_var_metadata(result);
                env.set_var_u32_validity(result, U32Validity::ProvenU32);
            }
        },
        _ => {
            let joined =
                AdviceFact::join_all(intrinsic.args.iter().map(|arg| env.fact_for_var(arg)));
            for result in &intrinsic.results {
                env.set_var_fact(result, joined.clone());
                env.clear_var_metadata(result);
            }
        },
    }
}

/// Store a scalar local and preserve exact alias metadata when possible.
pub(super) fn apply_local_store(values: &[Var], index: u32, env: &mut Env) {
    let fact = AdviceFact::join_all(values.iter().map(|var| env.fact_for_var(var)));
    env.set_local_fact(index, fact);
    let validity = single_var(values)
        .map(|var| env.u32_validity_for_var(var))
        .unwrap_or(U32Validity::Unknown);
    env.set_local_u32_validity(index, validity);
    let identity = single_var(values).map(|var| env.identity_for_var(var));
    let witness = single_var(values).and_then(|var| env.zero_test_for_var(var));
    env.set_local_identity(index, identity);
    env.set_local_zero_test(index, witness);
}

/// Store a local word slot-by-slot.
pub(super) fn apply_local_store_word(
    kind: LocalAccessKind,
    values: &[Var],
    index: u32,
    env: &mut Env,
) {
    for (offset, value) in values.iter().enumerate() {
        let slot = match kind {
            // Canonical slot order follows ascending local-memory addresses.
            LocalAccessKind::WordBe => index + (values.len().saturating_sub(1) - offset) as u32,
            LocalAccessKind::WordLe => index + offset as u32,
            LocalAccessKind::Element => index,
        };
        env.set_local_fact(slot, env.fact_for_var(value));
        env.set_local_u32_validity(slot, env.u32_validity_for_var(value));
        env.set_local_identity(slot, None);
        env.set_local_zero_test(slot, None);
    }
}

/// Load a scalar local and restore exact alias metadata when available.
pub(super) fn apply_local_load_scalar(outputs: &[Var], index: u32, env: &mut Env) {
    let fact = env.fact_for_local(index);
    let identity = env.identity_for_local(index);
    let witness = env.zero_test_for_local(index);
    for output in outputs {
        env.set_var_fact(output, fact.clone());
        env.set_var_u32_validity(output, env.u32_validity_for_local(index));
        if let Some(identity) = identity.clone() {
            env.set_var_identity(output, identity);
        } else {
            env.clear_var_identity(output);
        }
        env.set_var_zero_test(output, witness.clone());
    }
}

/// Load a local word slot-by-slot, preserving stack order.
pub(super) fn apply_local_load_word(
    kind: LocalAccessKind,
    outputs: &[Var],
    index: u32,
    env: &mut Env,
) {
    for (offset, output) in outputs.iter().enumerate() {
        let slot = match kind {
            LocalAccessKind::WordBe => index + offset as u32,
            LocalAccessKind::WordLe => index + (outputs.len().saturating_sub(1) - offset) as u32,
            LocalAccessKind::Element => index,
        };
        env.set_var_fact(output, env.fact_for_local(slot));
        env.set_var_u32_validity(output, env.u32_validity_for_local(slot));
        env.clear_var_metadata(output);
    }
}

/// Return the variable compared against zero in an `eq.0`-shaped expression.
pub(super) fn zero_comparison_var<'a>(lhs: &'a Expr, rhs: &'a Expr) -> Option<&'a Var> {
    match (lhs, rhs) {
        (Expr::Var(var), Expr::Constant(constant)) if constant.is_zero() => Some(var),
        (Expr::Constant(constant), Expr::Var(var)) if constant.is_zero() => Some(var),
        _ => None,
    }
}

/// Return the statement span for a structured statement.
pub(super) fn stmt_span(stmt: &Stmt) -> miden_debug_types::SourceSpan {
    match stmt {
        Stmt::Assign { span, .. }
        | Stmt::MemLoad { span, .. }
        | Stmt::MemStore { span, .. }
        | Stmt::AdvLoad { span, .. }
        | Stmt::AdvStore { span, .. }
        | Stmt::LocalLoad { span, .. }
        | Stmt::LocalStore { span, .. }
        | Stmt::LocalStoreW { span, .. }
        | Stmt::Call { span, .. }
        | Stmt::Exec { span, .. }
        | Stmt::SysCall { span, .. }
        | Stmt::DynCall { span, .. }
        | Stmt::Intrinsic { span, .. }
        | Stmt::Repeat { span, .. }
        | Stmt::If { span, .. }
        | Stmt::While { span, .. }
        | Stmt::Return { span, .. } => *span,
    }
}

/// Return the sole variable in the slice, if there is exactly one.
pub(super) fn single_var(vars: &[Var]) -> Option<&Var> {
    match vars {
        [var] => Some(var),
        _ => None,
    }
}

/// Apply the custom transfer semantics of `mem_stream`.
fn apply_mem_stream_effect(intrinsic: &Intrinsic, env: &mut Env) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        let address = &intrinsic.args[12];
        env.set_var_fact(&intrinsic.results[0], env.fact_for_var(address));
        env.set_var_u32_validity(&intrinsic.results[0], U32Validity::Unknown);
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::bottom());
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::bottom());
        env.clear_var_metadata(result);
    }
}

/// Apply the custom transfer semantics of `adv_pipe`.
fn apply_adv_pipe_effect(
    span: miden_debug_types::SourceSpan,
    intrinsic: &Intrinsic,
    env: &mut Env,
) {
    if intrinsic.args.len() == 13 && intrinsic.results.len() == 13 {
        env.set_var_fact(&intrinsic.results[0], AdviceFact::bottom());
        env.clear_var_metadata(&intrinsic.results[0]);

        for (offset, result) in intrinsic.results[1..5].iter().enumerate() {
            let preserved_input = &intrinsic.args[11 - offset];
            env.set_var_fact(result, env.fact_for_var(preserved_input));
            env.set_var_u32_validity(result, env.u32_validity_for_var(preserved_input));
            env.set_var_identity(result, env.identity_for_var(preserved_input));
            env.set_var_zero_test(result, env.zero_test_for_var(preserved_input));
        }

        for result in &intrinsic.results[5..] {
            env.set_var_fact(result, AdviceFact::from_source(span));
            env.clear_var_metadata(result);
        }
        return;
    }

    for result in &intrinsic.results {
        env.set_var_fact(result, AdviceFact::from_source(span));
        env.clear_var_metadata(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(depth: usize) -> Var {
        Var::new((depth as u64).into(), depth)
    }

    #[test]
    fn join_requires_var_u32_validity_on_both_sides() {
        let value = var(0);
        let mut proven = Env::default();
        proven.set_var_u32_validity(&value, U32Validity::ProvenU32);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_var(&value), U32Validity::ProvenU32);
    }

    #[test]
    fn join_preserves_sanitized_identity_u32_validity_when_both_sides_prove_it() {
        let value = var(0);
        let mut proven = Env::default();
        proven.sanitize_var(&value);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_var(&value), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_var(&value), U32Validity::ProvenU32);
    }

    #[test]
    fn join_requires_local_u32_validity_on_both_sides() {
        let mut proven = Env::default();
        proven.set_local_u32_validity(7, U32Validity::ProvenU32);

        assert_eq!(proven.join(&Env::default()).u32_validity_for_local(7), U32Validity::Unknown);
        assert_eq!(Env::default().join(&proven).u32_validity_for_local(7), U32Validity::Unknown);
        assert_eq!(proven.join(&proven).u32_validity_for_local(7), U32Validity::ProvenU32);
    }
}
