//! Input-backed provenance analysis for type summaries.

use std::collections::HashMap;

use super::{domain::VarKey, summary::TypeSummaryMap};
use crate::{
    ir::{Expr, Stmt, Var},
    symbol::path::SymbolPath,
};

/// Provenance of a variable in the output summary.
///
/// Used to determine whether a return variable is an unmodified copy of
/// a procedure input, enabling type narrowing based on the input's
/// backward-propagated requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// Variable traces back to the procedure input at the given index.
    ///
    /// The index corresponds to the stack position (0 = deepest input),
    /// matching the convention used by `input_var_key`.
    Input(usize),
    /// Variable was produced by a computation (arithmetic, call result,
    /// memory load, etc.) or by merging incompatible origins.
    Computed,
}

/// Compute the origin of each variable in the procedure body.
///
/// This is a post-hoc structural analysis run after the fixed-point type
/// inference converges. It determines which variables are unmodified copies of
/// procedure inputs, tracing through variable copies (`Assign { expr: Var(_) }`),
/// ternary selects, if-phi merges, loop-phi merges, and callee passthrough maps.
///
/// A variable has `Origin::Input(i)` only if every path from the input to the
/// variable consists exclusively of copy operations and phi/ternary nodes where
/// all incoming edges agree on the same input index.
pub(super) fn compute_origins(
    stmts: &[Stmt],
    input_count: usize,
    callee_summaries: &TypeSummaryMap,
) -> HashMap<VarKey, Origin> {
    let mut analyzer = OriginAnalyzer { input_count, callee_summaries };
    analyzer.compute(stmts)
}

struct OriginAnalyzer<'a> {
    input_count: usize,
    callee_summaries: &'a TypeSummaryMap,
}

impl OriginAnalyzer<'_> {
    fn compute(&mut self, stmts: &[Stmt]) -> HashMap<VarKey, Origin> {
        let mut origins: HashMap<VarKey, Origin> = HashMap::new();

        // Seed input variables.
        for index in 0..self.input_count {
            let key = input_var_key(index);
            origins.insert(key, Origin::Input(index));
        }

        // Iterate to a fixed point. Each pass may demote origins from
        // Input to Computed (monotonic: never the reverse), so convergence
        // is guaranteed in at most N passes where N is the number of variables.
        loop {
            let prev = origins.clone();
            self.propagate_origins_in_block(stmts, &mut origins);
            if origins == prev {
                break;
            }
        }

        origins
    }

    fn propagate_origins_in_block(&self, stmts: &[Stmt], origins: &mut HashMap<VarKey, Origin>) {
        for stmt in stmts {
            self.propagate_origins_in_stmt(stmt, origins);
        }
    }

    fn propagate_origins_in_stmt(&self, stmt: &Stmt, origins: &mut HashMap<VarKey, Origin>) {
        match stmt {
            Stmt::Assign { dest, expr, .. } => {
                let origin = match expr {
                    // Variable copy: propagate the source's origin.
                    Expr::Var(src) => origin_of_var(src, origins),
                    // Ternary select (cdrop/cswap): both branches must agree.
                    Expr::Ternary { then_expr, else_expr, .. } => {
                        let then_origin = origin_of_expr(then_expr, origins);
                        let else_origin = origin_of_expr(else_expr, origins);
                        merge_origins(then_origin, else_origin)
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
                    let then_origin = origin_of_var(&phi.then_var, origins);
                    let else_origin = origin_of_var(&phi.else_var, origins);
                    origins.insert(
                        VarKey::from_var(&phi.dest),
                        merge_origins(then_origin, else_origin),
                    );
                }
            },
            Stmt::While { body, phis, .. } => {
                // Seed loop-phi dests from their init values.
                for phi in phis {
                    let init_origin = origin_of_var(&phi.init, origins);
                    // Only narrow (Input -> Computed), never widen.
                    let current =
                        origins.get(&VarKey::from_var(&phi.dest)).copied().unwrap_or(init_origin);
                    let updated = merge_origins(current, init_origin);
                    origins.insert(VarKey::from_var(&phi.dest), updated);
                }
                self.propagate_origins_in_block(body, origins);
                // Verify step agrees with dest; demote if not.
                for phi in phis {
                    let dest_origin = origin_of_var(&phi.dest, origins);
                    let step_origin = origin_of_var(&phi.step, origins);
                    origins.insert(
                        VarKey::from_var(&phi.dest),
                        merge_origins(dest_origin, step_origin),
                    );
                }
            },
            Stmt::Repeat { body, phis, loop_count, .. } => {
                for phi in phis {
                    let init_origin = origin_of_var(&phi.init, origins);
                    if *loop_count == 0 {
                        origins.insert(VarKey::from_var(&phi.dest), init_origin);
                    } else {
                        let current = origins
                            .get(&VarKey::from_var(&phi.dest))
                            .copied()
                            .unwrap_or(init_origin);
                        let updated = merge_origins(current, init_origin);
                        origins.insert(VarKey::from_var(&phi.dest), updated);
                    }
                }
                if *loop_count == 0 {
                    return;
                }
                self.propagate_origins_in_block(body, origins);
                for phi in phis {
                    let dest_origin = origin_of_var(&phi.dest, origins);
                    let step_origin = origin_of_var(&phi.step, origins);
                    origins.insert(
                        VarKey::from_var(&phi.dest),
                        merge_origins(dest_origin, step_origin),
                    );
                }
            },
            Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
                let callee_map = self.summary_for_target(&call.target).map(|s| &s.output_input_map);
                for (idx, result) in call.results.iter().enumerate() {
                    let origin = if let Some(Some(input_idx)) = callee_map.and_then(|m| m.get(idx))
                    {
                        // Callee output traces to callee input; inherit the
                        // origin of the corresponding caller argument.
                        // Origin::Input uses 0=deepest, args uses 0=topmost.
                        call.args
                            .len()
                            .checked_sub(1 + *input_idx)
                            .and_then(|i| call.args.get(i))
                            .map(|arg| origin_of_var(arg, origins))
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

    fn summary_for_target(&self, target: &str) -> Option<&super::summary::TypeSummary> {
        let key = SymbolPath::new(target.to_string());
        self.callee_summaries.get(&key)
    }
}

/// Build the canonical key for an input variable by stack index.
pub(super) fn input_var_key(index: usize) -> VarKey {
    let var = Var::new((index as u64).into(), index);
    VarKey::from_var(&var)
}

fn origin_of_expr(expr: &Expr, origins: &HashMap<VarKey, Origin>) -> Origin {
    match expr {
        Expr::Var(var) => origin_of_var(var, origins),
        _ => Origin::Computed,
    }
}

fn origin_of_var(var: &Var, origins: &HashMap<VarKey, Origin>) -> Origin {
    origins.get(&VarKey::from_var(var)).copied().unwrap_or(Origin::Computed)
}

fn merge_origins(a: Origin, b: Origin) -> Origin {
    match (a, b) {
        (Origin::Input(i), Origin::Input(j)) if i == j => Origin::Input(i),
        _ => Origin::Computed,
    }
}
