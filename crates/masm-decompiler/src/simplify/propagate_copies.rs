//! Copy propagation for structured code.
//!
//! This pass replaces uses of variables that are pure copies of other variables.
//! It is conservative across structured control-flow: copies are propagated
//! within straight-line segments and inside each branch/loop body, but not
//! across `if`, `repeat`, or `while` boundaries.

use std::collections::{HashMap, HashSet};

use crate::ir::{Expr, IndexExpr, Stmt, ValueId, Var, VarBase};

/// Base identity for a variable in copy propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VarBaseKey {
    /// Concrete SSA value identifier.
    Value(ValueId),
    /// Loop-entry snapshot identity (by loop depth).
    LoopInput(usize),
}

/// Identity key for a variable in copy propagation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarKey {
    /// Base identity.
    base: VarBaseKey,
    /// Subscript identifying a concrete SSA version.
    subscript: IndexExpr,
}

impl VarKey {
    /// Build a key from a variable reference.
    fn from_var(var: &Var) -> Self {
        let base = match &var.base {
            VarBase::Value(id) => VarBaseKey::Value(*id),
            VarBase::LoopInput { loop_depth } => VarBaseKey::LoopInput(*loop_depth),
        };
        Self { base, subscript: var.subscript.clone() }
    }

    /// Return true if the variable is indexed by a loop variable.
    fn is_loop_indexed(&self) -> bool {
        !matches!(self.subscript, IndexExpr::Const(_))
    }
}

/// State for copy propagation within a straight-line segment.
#[derive(Debug, Clone, Default)]
struct CopyState {
    /// Map from destination variable to its source variable.
    copies: HashMap<VarKey, Var>,
}

impl CopyState {
    /// Create an empty copy state.
    fn new() -> Self {
        Self::default()
    }

    /// Remove all known copies.
    fn clear(&mut self) {
        self.copies.clear();
    }

    /// Return true if a variable is eligible for copy propagation.
    fn is_eligible(&self, var: &Var) -> bool {
        let key = VarKey::from_var(var);
        !matches!(key.base, VarBaseKey::LoopInput(_)) && !key.is_loop_indexed()
    }

    /// Insert a copy mapping, storing the resolved source.
    fn insert(&mut self, dest: &Var, src: Var) {
        let dest_key = VarKey::from_var(dest);
        let src_key = VarKey::from_var(&src);
        if dest_key != src_key {
            self.copies.insert(dest_key, src);
        }
    }

    /// Remove any mappings that define or depend on the given variable.
    fn kill_var(&mut self, var: &Var) {
        let key = VarKey::from_var(var);
        self.copies.remove(&key);
        let mut to_remove = Vec::new();
        for (dest, src) in &self.copies {
            if VarKey::from_var(src) == key {
                to_remove.push(dest.clone());
            }
        }
        for dest in to_remove {
            self.copies.remove(&dest);
        }
    }

    /// Remove mappings for a list of variables.
    fn kill_vars(&mut self, vars: &[Var]) {
        for var in vars {
            self.kill_var(var);
        }
    }

    /// Resolve a variable through the copy map to its ultimate source.
    fn resolve_var(&self, var: &Var) -> Var {
        if !self.is_eligible(var) {
            return var.clone();
        }

        let mut current = var.clone();
        let mut visited: HashSet<VarKey> = HashSet::new();
        loop {
            let key = VarKey::from_var(&current);
            if !visited.insert(key.clone()) {
                break;
            }
            let Some(next) = self.copies.get(&key) else {
                break;
            };
            if !self.is_eligible(next) {
                break;
            }
            let next_key = VarKey::from_var(next);
            if next_key == key {
                break;
            }
            current = next.clone();
        }
        current
    }
}

/// Propagate copy assignments into var-only use sites.
pub fn propagate_copies(code: &mut [Stmt]) {
    let mut state = CopyState::new();
    propagate_block(code, &mut state);
}

/// Propagate copies within a block of statements.
fn propagate_block(stmts: &mut [Stmt], state: &mut CopyState) -> bool {
    let mut changed = false;
    for stmt in stmts.iter_mut() {
        match stmt {
            Stmt::Assign { dest, expr, .. } => {
                changed |= rewrite_expr(expr, state);
                state.kill_var(dest);
                if let Expr::Var(src) = expr
                    && state.is_eligible(dest)
                    && state.is_eligible(src)
                {
                    let resolved = state.resolve_var(src);
                    state.insert(dest, resolved);
                }
            },

            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                changed |= rewrite_vars(&mut call.args, state);
                state.kill_vars(&call.results);
            },

            Stmt::DynCall { args, results, .. } => {
                changed |= rewrite_vars(args, state);
                state.kill_vars(results);
            },

            Stmt::Intrinsic { intrinsic: intr, .. } => {
                changed |= rewrite_vars(&mut intr.args, state);
                state.kill_vars(&intr.results);
            },

            Stmt::MemLoad { load, .. } => {
                changed |= rewrite_vars(&mut load.address, state);
                state.kill_vars(&load.outputs);
            },

            Stmt::MemStore { store, .. } => {
                changed |= rewrite_vars(&mut store.address, state);
                changed |= rewrite_vars(&mut store.values, state);
            },

            Stmt::AdvLoad { load, .. } => {
                state.kill_vars(&load.outputs);
            },

            Stmt::AdvStore { store, .. } => {
                changed |= rewrite_vars(&mut store.values, state);
            },

            Stmt::LocalLoad { load, .. } => {
                state.kill_vars(&load.outputs);
            },

            Stmt::LocalStore { store, .. } => {
                changed |= rewrite_vars(&mut store.values, state);
            },

            Stmt::LocalStoreW { store, .. } => {
                changed |= rewrite_vars(&mut store.values, state);
            },

            Stmt::Return { values, .. } => {
                changed |= rewrite_vars(values, state);
            },

            Stmt::If { cond, then_body, else_body, .. } => {
                changed |= rewrite_expr(cond, state);
                let mut then_state = state.clone();
                let mut else_state = state.clone();
                changed |= propagate_block(then_body, &mut then_state);
                changed |= propagate_block(else_body, &mut else_state);
                state.clear();
            },

            Stmt::Repeat { body, .. } => {
                let mut body_state = state.clone();
                changed |= propagate_block(body, &mut body_state);
                state.clear();
            },

            Stmt::While { cond, body, phis, .. } => {
                // Do not rewrite loop-carried while conditions from pre-loop copies.
                let loop_carried = while_loop_carried_keys(phis);
                if !expr_uses_any_key(cond, &loop_carried) {
                    changed |= rewrite_expr(cond, state);
                }
                let mut body_state = state.clone();
                changed |= propagate_block(body, &mut body_state);
                state.clear();
            },
        }
    }
    changed
}

/// Rewrite variables in a list using the copy state.
fn rewrite_vars(vars: &mut Vec<Var>, state: &CopyState) -> bool {
    let mut changed = false;
    for var in vars {
        let resolved = state.resolve_var(var);
        if resolved != *var {
            *var = resolved;
            changed = true;
        }
    }
    changed
}

/// Rewrite variables inside an expression using the copy state.
fn rewrite_expr(expr: &mut Expr, state: &CopyState) -> bool {
    match expr {
        Expr::Var(var) => {
            let resolved = state.resolve_var(var);
            if resolved != *var {
                *var = resolved;
                true
            } else {
                false
            }
        },
        Expr::Binary(_, left, right) => {
            let left_changed = rewrite_expr(left, state);
            let right_changed = rewrite_expr(right, state);
            left_changed || right_changed
        },
        Expr::Unary(_, inner) => rewrite_expr(inner, state),
        Expr::Ternary { cond, then_expr, else_expr } => {
            let cond_changed = rewrite_expr(cond, state);
            let then_changed = rewrite_expr(then_expr, state);
            let else_changed = rewrite_expr(else_expr, state);
            cond_changed || then_changed || else_changed
        },
        Expr::EqW { lhs, rhs } => {
            let mut changed = false;
            for var in lhs.iter_mut() {
                let resolved = state.resolve_var(var);
                if resolved != *var {
                    *var = resolved;
                    changed = true;
                }
            }
            for var in rhs.iter_mut() {
                let resolved = state.resolve_var(var);
                if resolved != *var {
                    *var = resolved;
                    changed = true;
                }
            }
            changed
        },
        Expr::Constant(_) | Expr::True | Expr::False => false,
    }
}

/// Collect while loop-carried identities from loop phis.
fn while_loop_carried_keys(phis: &[crate::ir::LoopPhi]) -> HashSet<VarKey> {
    let mut keys = HashSet::new();
    for phi in phis {
        keys.insert(VarKey::from_var(&phi.init));
        keys.insert(VarKey::from_var(&phi.dest));
        keys.insert(VarKey::from_var(&phi.step));
    }
    keys
}

/// Return true if the expression uses any variable in `keys`.
fn expr_uses_any_key(expr: &Expr, keys: &HashSet<VarKey>) -> bool {
    match expr {
        Expr::Var(var) => keys.contains(&VarKey::from_var(var)),
        Expr::Binary(_, lhs, rhs) => expr_uses_any_key(lhs, keys) || expr_uses_any_key(rhs, keys),
        Expr::Unary(_, inner) => expr_uses_any_key(inner, keys),
        Expr::Ternary { cond, then_expr, else_expr } => {
            expr_uses_any_key(cond, keys)
                || expr_uses_any_key(then_expr, keys)
                || expr_uses_any_key(else_expr, keys)
        },
        Expr::EqW { lhs, rhs } => {
            lhs.iter().chain(rhs.iter()).any(|var| keys.contains(&VarKey::from_var(var)))
        },
        Expr::Constant(_) | Expr::True | Expr::False => false,
    }
}
