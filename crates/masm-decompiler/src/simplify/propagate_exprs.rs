//! Expression propagation for structured code.
//!
//! This module performs expression propagation on structured code (after flattening).
//! Unlike CFG-based propagation, this version correctly handles loop boundaries by
//! never propagating expressions into loops that might modify variables used by
//! the expression.
//!
//! # Safety Invariant
//!
//! An expression `e` can be propagated from definition `d` to use `u` only if:
//! 1. The use is in an `Assign` statement (expressions can be substituted)
//! 2. The variable is used exactly once in the target expression
//! 3. No intervening statement redefines variables used by `e`
//! 4. The use is NOT inside a loop that defines any variable used by `e`

use std::collections::HashSet;

use crate::ir::{Expr, IfPhi, IndexExpr, LoopPhi, Stmt, ValueId, Var, VarBase};

/// Maximum number of propagation passes to avoid infinite loops.
const MAX_PROPAGATION_PASSES: usize = 100;

/// Maximum expression complexity for propagation (prevents blowup).
const MAX_EXPR_COMPLEXITY: usize = 4;

/// Maximum combined complexity of expression + use site.
const MAX_COMBINED_COMPLEXITY: usize = 7;

/// Base identity for propagation keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VarBaseKey {
    /// Concrete SSA value identifier.
    Value(ValueId),
    /// Loop-entry snapshot identity (by loop depth).
    LoopInput(usize),
}

/// Identity key for a variable in propagation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VarKey {
    base: VarBaseKey,
    subscript: IndexExpr,
}

/// Helper trait for extracting phi destinations.
trait PhiDest {
    /// Return the destination variable for this phi node.
    fn dest(&self) -> &Var;
}

impl PhiDest for IfPhi {
    /// Return the destination variable for an if-phi.
    fn dest(&self) -> &Var {
        &self.dest
    }
}

impl PhiDest for LoopPhi {
    /// Return the destination variable for a loop-phi.
    fn dest(&self) -> &Var {
        &self.dest
    }
}

/// Collect all phi destination variables as propagation keys.
fn collect_defined_vars_in_phis<T: PhiDest>(phis: &[T]) -> HashSet<VarKey> {
    phis.iter().map(|phi| VarKey::from_var(phi.dest())).collect()
}

impl VarKey {
    /// Build a propagation identity key from a variable reference.
    fn from_var(var: &Var) -> Self {
        let base = match &var.base {
            VarBase::Value(id) => VarBaseKey::Value(*id),
            VarBase::LoopInput { loop_depth } => VarBaseKey::LoopInput(*loop_depth),
        };
        Self { base, subscript: var.subscript.clone() }
    }

    /// Return true if this key is indexed by a loop variable.
    fn is_loop_indexed(&self) -> bool {
        !matches!(self.subscript, IndexExpr::Const(_))
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Propagate expressions in structured code.
///
/// This replaces variable uses with their defining expressions where safe,
/// respecting loop boundaries to ensure semantic correctness.
pub fn propagate_expressions(code: &mut [Stmt]) {
    for _ in 0..MAX_PROPAGATION_PASSES {
        if !propagate_one_pass(code) {
            break;
        }
    }
}

// ============================================================================
// Single Propagation Pass
// ============================================================================

/// Perform one pass of expression propagation.
/// Returns true if any propagation was performed.
fn propagate_one_pass(code: &mut [Stmt]) -> bool {
    // Process definitions in order, trying to propagate each one.
    // This handles cases where a variable is defined multiple times -
    // we try to propagate each definition to its uses before the next redefinition.
    for def_idx in 0..code.len() {
        let (var_key, def_expr) = match &code[def_idx] {
            Stmt::Assign { dest, expr, .. } => (VarKey::from_var(dest), expr.clone()),
            _ => continue,
        };

        let props = ExprProperties::compute(&def_expr);
        if props.complexity > MAX_EXPR_COMPLEXITY {
            continue;
        }

        // Don't propagate loop-indexed or loop-input variables.
        if matches!(var_key.base, VarBaseKey::LoopInput(_)) || var_key.is_loop_indexed() {
            continue;
        }

        // Don't propagate expressions that contain the variable being defined.
        // Such expressions read the OLD value of the variable (e.g., v_0 = v_0 + 1),
        // and propagating them would be incorrect - the use sites expect the NEW value.
        let used_vars: HashSet<VarKey> = expr_uses_vars(&def_expr).into_iter().collect();
        if used_vars.contains(&var_key) {
            continue;
        }

        // Find uses of this variable that can be propagated.
        if let Some(use_info) = find_propagatable_use(code, &var_key, def_idx, &def_expr, props) {
            // Perform the substitution.
            substitute_at_path(code, &use_info.path, &var_key, &def_expr);
            return true;
        }
    }

    false
}

/// Information about a use site that can receive propagation.
struct UseInfo {
    /// Path to the statement containing the use.
    path: Vec<usize>,
}

/// Find a use of `var_key` that can be safely propagated.
fn find_propagatable_use(
    code: &[Stmt],
    var_key: &VarKey,
    def_idx: usize,
    def_expr: &Expr,
    props: ExprProperties,
) -> Option<UseInfo> {
    let used_vars: HashSet<VarKey> = expr_uses_vars(def_expr).into_iter().collect();

    // Search for uses after the definition.
    for (idx, stmt) in code.iter().enumerate().skip(def_idx + 1) {
        // Check if this statement uses the variable and can receive propagation.
        if let Some(path) = can_propagate_into(stmt, var_key, &used_vars, props, vec![idx]) {
            return Some(UseInfo { path });
        }

        // Check if this statement kills propagation (redefines used vars,
        // redefines the variable being propagated, or is a barrier).
        if is_propagation_barrier(stmt, var_key, &used_vars) {
            return None;
        }
    }

    None
}

/// Check if propagation can proceed into this statement.
/// Returns the path to the use site if propagation is valid.
fn can_propagate_into(
    stmt: &Stmt,
    var_key: &VarKey,
    used_vars: &HashSet<VarKey>,
    props: ExprProperties,
    current_path: Vec<usize>,
) -> Option<Vec<usize>> {
    match stmt {
        Stmt::Assign { dest, expr, .. } => {
            // Can propagate if:
            // 1. This assignment uses the variable
            // 2. The variable appears exactly once
            // 3. Combined complexity is acceptable
            let occurrences = count_var_in_expr(expr, var_key);
            if occurrences == 1 {
                let use_complexity = expr_complexity(expr);
                if props.complexity + use_complexity <= MAX_COMBINED_COMPLEXITY {
                    return Some(current_path);
                }
            }

            // Can't propagate into this assignment, but check if it's a barrier.
            if used_vars.contains(&VarKey::from_var(dest)) {
                return None; // Variable redefined, stop searching.
            }
            None
        },

        Stmt::If { cond, then_body, else_body, phis, .. } => {
            // Can propagate into condition if variable is used there.
            let cond_uses = count_var_in_expr(cond, var_key);
            if cond_uses == 1 {
                let use_complexity = expr_complexity(cond);
                if props.complexity + use_complexity <= MAX_COMBINED_COMPLEXITY {
                    return Some(current_path);
                }
            }

            // Check branches - but only if neither branch defines variables we need.
            let then_defs = collect_defined_vars_in_block(then_body);
            let else_defs = collect_defined_vars_in_block(else_body);
            let phi_defs = collect_defined_vars_in_phis(phis);

            // If either branch defines a variable we use, we can't propagate past this If.
            if then_defs.intersection(used_vars).next().is_some()
                || else_defs.intersection(used_vars).next().is_some()
                || phi_defs.intersection(used_vars).next().is_some()
            {
                return None;
            }

            // Search in then branch.
            for (i, inner) in then_body.iter().enumerate() {
                let mut path = current_path.clone();
                path.push(i);
                if let Some(result) =
                    can_propagate_into_if_branch(inner, var_key, used_vars, props, path, true)
                {
                    return Some(result);
                }
            }

            // Search in else branch.
            for (i, inner) in else_body.iter().enumerate() {
                let mut path = current_path.clone();
                path.push(i);
                if let Some(result) =
                    can_propagate_into_if_branch(inner, var_key, used_vars, props, path, false)
                {
                    return Some(result);
                }
            }

            None
        },

        Stmt::Repeat { body, phis, .. } => {
            // CRITICAL: Never propagate into a repeat loop if the loop body
            // defines any variable used by the expression being propagated.
            let loop_defs = collect_defined_vars_in_block(body);
            let phi_defs = collect_defined_vars_in_phis(phis);
            if loop_defs.intersection(used_vars).next().is_some() {
                return None; // Unsafe to propagate.
            }
            if phi_defs.intersection(used_vars).next().is_some() {
                return None;
            }

            // Also don't propagate if the variable we're propagating is used inside,
            // as the loop might be modifying stack positions semantically.
            // Conservative: don't propagate into repeat loops at all.
            // This is safe and matches the expected behavior.
            None
        },

        Stmt::While { cond, body, phis, .. } => {
            // Similar to Repeat - don't propagate into while loops.
            let loop_defs = collect_defined_vars_in_block(body);
            let phi_defs = collect_defined_vars_in_phis(phis);
            let loop_carried = while_loop_carried_keys(phis);
            if loop_defs.intersection(used_vars).next().is_some() {
                return None;
            }
            if phi_defs.intersection(used_vars).next().is_some() {
                return None;
            }

            // Can propagate into condition only if it does not use loop-carried identities.
            let cond_uses_loop_carried =
                expr_uses_vars(cond).into_iter().any(|var| loop_carried.contains(&var));
            let cond_uses = count_var_in_expr(cond, var_key);
            if !cond_uses_loop_carried
                && cond_uses == 1
                && loop_defs.intersection(used_vars).next().is_none()
            {
                let use_complexity = expr_complexity(cond);
                if props.complexity + use_complexity <= MAX_COMBINED_COMPLEXITY {
                    return Some(current_path);
                }
            }

            None
        },

        // These statements can't receive expression propagation.
        Stmt::Return { .. }
        | Stmt::MemLoad { .. }
        | Stmt::MemStore { .. }
        | Stmt::AdvLoad { .. }
        | Stmt::AdvStore { .. }
        | Stmt::LocalLoad { .. }
        | Stmt::LocalStore { .. }
        | Stmt::LocalStoreW { .. }
        | Stmt::Call { .. }
        | Stmt::Exec { .. }
        | Stmt::SysCall { .. }
        | Stmt::DynCall { .. }
        | Stmt::Intrinsic { .. } => None,
    }
}

/// Helper for propagating into if branches (marks which branch we're in).
fn can_propagate_into_if_branch(
    stmt: &Stmt,
    var_key: &VarKey,
    used_vars: &HashSet<VarKey>,
    props: ExprProperties,
    current_path: Vec<usize>,
    _is_then: bool,
) -> Option<Vec<usize>> {
    can_propagate_into(stmt, var_key, used_vars, props, current_path)
}

/// Check if a statement is a barrier that prevents further propagation.
///
/// A statement is a barrier if it:
/// - Redefines the variable being propagated (`var_key`)
/// - Redefines any variable used by the expression being propagated (`used_vars`)
/// - Has side effects that could affect propagation
fn is_propagation_barrier(stmt: &Stmt, var_index: &VarKey, used_vars: &HashSet<VarKey>) -> bool {
    match stmt {
        Stmt::Assign { dest, .. } => {
            // Barrier if it redefines the propagated variable or any used variable.
            let dest_key = VarKey::from_var(dest);
            dest_key == *var_index || used_vars.contains(&dest_key)
        },

        Stmt::Repeat { body, phis, .. } | Stmt::While { body, phis, .. } => {
            // A loop is a barrier if it defines the propagated variable or any used variable.
            let loop_defs = collect_defined_vars_in_block(body);
            let phi_defs = collect_defined_vars_in_phis(phis);
            loop_defs.contains(var_index)
                || loop_defs.intersection(used_vars).next().is_some()
                || phi_defs.contains(var_index)
                || phi_defs.intersection(used_vars).next().is_some()
        },

        Stmt::If { then_body, else_body, phis, .. } => {
            // An if is a barrier if either branch defines the propagated variable
            // or any variable we're using.
            let then_defs = collect_defined_vars_in_block(then_body);
            let else_defs = collect_defined_vars_in_block(else_body);
            let phi_defs = collect_defined_vars_in_phis(phis);
            then_defs.contains(var_index)
                || else_defs.contains(var_index)
                || phi_defs.contains(var_index)
                || then_defs.intersection(used_vars).next().is_some()
                || else_defs.intersection(used_vars).next().is_some()
                || phi_defs.intersection(used_vars).next().is_some()
        },

        // Side-effecting statements are barriers.
        Stmt::MemLoad { .. }
        | Stmt::MemStore { .. }
        | Stmt::AdvLoad { .. }
        | Stmt::AdvStore { .. }
        | Stmt::LocalLoad { .. }
        | Stmt::LocalStore { .. }
        | Stmt::LocalStoreW { .. }
        | Stmt::Call { .. }
        | Stmt::Exec { .. }
        | Stmt::SysCall { .. }
        | Stmt::DynCall { .. }
        | Stmt::Intrinsic { .. } => true,

        _ => false,
    }
}

// ============================================================================
// Substitution
// ============================================================================

/// Substitute variable `var_key` with `expr` at the given path.
fn substitute_at_path(code: &mut [Stmt], path: &[usize], var_key: &VarKey, expr: &Expr) {
    if path.is_empty() {
        return;
    }

    let idx = path[0];
    if path.len() == 1 {
        // This is the target statement.
        substitute_in_stmt(&mut code[idx], var_key, expr);
    } else {
        // Navigate into nested structure.
        match &mut code[idx] {
            Stmt::If { cond, then_body, else_body, .. } => {
                // For If, we need to determine which branch to descend into.
                // The path encoding here is simplified - we just try both.
                if path.len() > 1 {
                    let inner_path = &path[1..];
                    // Try then branch first.
                    if inner_path[0] < then_body.len() {
                        substitute_at_path(then_body, inner_path, var_key, expr);
                    } else {
                        // Adjust index for else branch.
                        let adjusted_idx = inner_path[0] - then_body.len();
                        if adjusted_idx < else_body.len() {
                            let mut adjusted_path = inner_path.to_vec();
                            adjusted_path[0] = adjusted_idx;
                            substitute_at_path(else_body, &adjusted_path, var_key, expr);
                        }
                    }
                }
                // Also substitute in condition if it contains the variable.
                substitute_in_expr(cond, var_key, expr);
            },
            Stmt::Repeat { body, .. } | Stmt::While { body, .. } => {
                substitute_at_path(body, &path[1..], var_key, expr);
            },
            _ => {
                // Direct statement - substitute in it.
                substitute_in_stmt(&mut code[idx], var_key, expr);
            },
        }
    }
}

/// Substitute variable in a statement.
fn substitute_in_stmt(stmt: &mut Stmt, var_key: &VarKey, with: &Expr) {
    match stmt {
        Stmt::Assign { expr, .. } => {
            substitute_in_expr(expr, var_key, with);
        },
        Stmt::If { cond, .. } => {
            substitute_in_expr(cond, var_key, with);
        },
        Stmt::While { cond, .. } => {
            substitute_in_expr(cond, var_key, with);
        },
        _ => {},
    }
}

/// Substitute variable in an expression.
fn substitute_in_expr(expr: &mut Expr, var_key: &VarKey, with: &Expr) {
    match expr {
        Expr::Var(v) if VarKey::from_var(v) == *var_key => {
            *expr = with.clone();
        },
        Expr::Var(_) => {},
        Expr::Binary(_, a, b) => {
            substitute_in_expr(a, var_key, with);
            substitute_in_expr(b, var_key, with);
        },
        Expr::Unary(_, a) => {
            substitute_in_expr(a, var_key, with);
        },
        Expr::Ternary { cond, then_expr, else_expr } => {
            substitute_in_expr(cond, var_key, with);
            substitute_in_expr(then_expr, var_key, with);
            substitute_in_expr(else_expr, var_key, with);
        },
        Expr::EqW { lhs, rhs } => {
            for var in lhs.iter_mut() {
                if VarKey::from_var(var) == *var_key
                    && let Expr::Var(replacement) = with
                {
                    *var = replacement.clone();
                }
            }
            for var in rhs.iter_mut() {
                if VarKey::from_var(var) == *var_key
                    && let Expr::Var(replacement) = with
                {
                    *var = replacement.clone();
                }
            }
        },
        Expr::True | Expr::False | Expr::Constant(_) => {},
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Collect all variables defined in a block of statements.
fn collect_defined_vars_in_block(stmts: &[Stmt]) -> HashSet<VarKey> {
    let mut defs = HashSet::new();
    for stmt in stmts {
        collect_defined_vars(stmt, &mut defs);
    }
    defs
}

/// Recursively collect all variables defined by a statement.
fn collect_defined_vars(stmt: &Stmt, defs: &mut HashSet<VarKey>) {
    match stmt {
        Stmt::Assign { dest, .. } => {
            defs.insert(VarKey::from_var(dest));
        },
        Stmt::If { then_body, else_body, phis, .. } => {
            for s in then_body {
                collect_defined_vars(s, defs);
            }
            for s in else_body {
                collect_defined_vars(s, defs);
            }
            for phi in phis {
                defs.insert(VarKey::from_var(&phi.dest));
            }
        },
        Stmt::Repeat { body, phis, .. } | Stmt::While { body, phis, .. } => {
            for s in body {
                collect_defined_vars(s, defs);
            }
            for phi in phis {
                defs.insert(VarKey::from_var(&phi.dest));
            }
        },
        Stmt::MemLoad { load, .. } => {
            for v in &load.outputs {
                defs.insert(VarKey::from_var(v));
            }
        },
        Stmt::AdvLoad { load, .. } => {
            for v in &load.outputs {
                defs.insert(VarKey::from_var(v));
            }
        },
        Stmt::LocalLoad { load, .. } => {
            for v in &load.outputs {
                defs.insert(VarKey::from_var(v));
            }
        },
        Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
            for v in &call.results {
                defs.insert(VarKey::from_var(v));
            }
        },
        Stmt::DynCall { results, .. } => {
            for v in results {
                defs.insert(VarKey::from_var(v));
            }
        },
        Stmt::Intrinsic { intrinsic: intr, .. } => {
            for v in &intr.results {
                defs.insert(VarKey::from_var(v));
            }
        },
        _ => {},
    }
}

/// Collect loop-carried variable identities for a while loop.
fn while_loop_carried_keys(phis: &[LoopPhi]) -> HashSet<VarKey> {
    let mut keys = HashSet::new();
    for phi in phis {
        keys.insert(VarKey::from_var(&phi.init));
        keys.insert(VarKey::from_var(&phi.dest));
        keys.insert(VarKey::from_var(&phi.step));
    }
    keys
}

/// Get all variables used by an expression.
fn expr_uses_vars(expr: &Expr) -> Vec<VarKey> {
    let mut vars = Vec::new();
    collect_expr_vars(expr, &mut vars);
    vars
}

fn collect_expr_vars(expr: &Expr, vars: &mut Vec<VarKey>) {
    match expr {
        Expr::Var(v) => vars.push(VarKey::from_var(v)),
        Expr::Binary(_, a, b) => {
            collect_expr_vars(a, vars);
            collect_expr_vars(b, vars);
        },
        Expr::Unary(_, a) => collect_expr_vars(a, vars),
        Expr::Ternary { cond, then_expr, else_expr } => {
            collect_expr_vars(cond, vars);
            collect_expr_vars(then_expr, vars);
            collect_expr_vars(else_expr, vars);
        },
        Expr::EqW { lhs, rhs } => {
            for var in lhs.iter() {
                vars.push(VarKey::from_var(var));
            }
            for var in rhs.iter() {
                vars.push(VarKey::from_var(var));
            }
        },
        Expr::True | Expr::False | Expr::Constant(_) => {},
    }
}

/// Count occurrences of a variable in an expression.
fn count_var_in_expr(expr: &Expr, var_key: &VarKey) -> usize {
    match expr {
        Expr::Var(v) if VarKey::from_var(v) == *var_key => 1,
        Expr::Var(_) => 0,
        Expr::Binary(_, a, b) => count_var_in_expr(a, var_key) + count_var_in_expr(b, var_key),
        Expr::Unary(_, a) => count_var_in_expr(a, var_key),
        Expr::Ternary { cond, then_expr, else_expr } => {
            count_var_in_expr(cond, var_key)
                + count_var_in_expr(then_expr, var_key)
                + count_var_in_expr(else_expr, var_key)
        },
        Expr::EqW { lhs, rhs } => {
            let lhs_count = lhs.iter().filter(|var| VarKey::from_var(var) == *var_key).count();
            let rhs_count = rhs.iter().filter(|var| VarKey::from_var(var) == *var_key).count();
            lhs_count + rhs_count
        },
        Expr::True | Expr::False | Expr::Constant(_) => 0,
    }
}

/// Compute expression complexity.
fn expr_complexity(expr: &Expr) -> usize {
    match expr {
        Expr::True | Expr::False | Expr::Var(_) | Expr::Constant(_) => 1,
        Expr::Unary(_, a) => 1 + expr_complexity(a),
        Expr::Binary(_, a, b) => 1 + expr_complexity(a) + expr_complexity(b),
        Expr::EqW { .. } => 9,
        Expr::Ternary { cond, then_expr, else_expr } => {
            1 + expr_complexity(cond) + expr_complexity(then_expr) + expr_complexity(else_expr)
        },
    }
}

/// Properties of an expression that affect propagation decisions.
#[derive(Debug, Clone, Copy)]
struct ExprProperties {
    complexity: usize,
}

impl ExprProperties {
    fn compute(expr: &Expr) -> Self {
        Self { complexity: expr_complexity(expr) }
    }
}

// ============================================================================
// Tests
// ============================================================================
