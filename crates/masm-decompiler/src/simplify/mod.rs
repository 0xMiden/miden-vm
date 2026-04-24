//! IR simplification passes.
//!
//! This module implements statement and expression simplification
//! passes for structured code. These passes remove trivial statements
//! such as self-assignments and empty branches, and perform constant
//! folding on expressions.
//!
//! The main API is the `simplify_statements` function, which applies a series
//! of simplification passes to a vector of statements. Each simplification
//! returns a `SimplifyResult` that tracks whether any changes were made during
//! simplification.

pub mod eliminate;
pub mod propagate_copies;
pub mod propagate_exprs;
pub mod shorten_call_targets;
pub mod used_vars;

pub use eliminate::eliminate_dead_code;
pub use propagate_copies::propagate_copies;
pub use propagate_exprs::propagate_expressions;
pub use shorten_call_targets::shorten_call_targets;

use crate::ir::{
    AdvLoad, AdvStore, BinOp, Call, Constant, Expr, IndexExpr, LocalLoad, LocalStore, LocalStoreW,
    MemLoad, MemStore, Stmt, UnOp, Var,
};

const MAX_SIMPLIFY_PASSES: usize = 100;

pub fn simplify_statements(code: &mut Vec<Stmt>) {
    for _ in 0..MAX_SIMPLIFY_PASSES {
        let result = code.clone().simplify();
        if !result.changed {
            break;
        }
        *code = result.value;
    }
}

/// Result of a simplification pass, tracking whether changes were made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplifyResult<T> {
    /// The simplified value.
    pub value: T,
    /// Whether any simplification was applied.
    pub changed: bool,
}

impl<T> SimplifyResult<T> {
    /// Create a result indicating no change occurred.
    pub fn unchanged(value: T) -> Self {
        Self { value, changed: false }
    }

    /// Create a result indicating a change occurred.
    pub fn changed(value: T) -> Self {
        Self { value, changed: true }
    }

    /// Create a result with an explicit changed flag.
    pub fn new(value: T, changed: bool) -> Self {
        Self { value, changed }
    }

    /// Map the inner value while preserving the changed flag.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> SimplifyResult<U> {
        SimplifyResult {
            value: f(self.value),
            changed: self.changed,
        }
    }
}

impl<T> std::ops::Deref for SimplifyResult<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> std::ops::DerefMut for SimplifyResult<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

/// Trait for types that can be simplified.
pub trait Simplify: Sized {
    /// The output type after simplification.
    type Output;

    /// Simplify this value, returning the result and whether any changes were made.
    fn simplify(self) -> SimplifyResult<Self::Output>;
}

impl Simplify for Vec<Stmt> {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let mut changed = false;
        let mut result = Vec::new();
        for item in self {
            let simplified = item.simplify();
            changed = changed || simplified.changed;
            result.extend(simplified.value);
        }
        SimplifyResult::new(result, changed)
    }
}

impl Simplify for Vec<Var> {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let mut changed = false;
        let mut result = Vec::with_capacity(self.len());
        for item in self {
            let simplified = item.simplify();
            changed = changed || simplified.changed;
            result.push(simplified.value);
        }
        SimplifyResult::new(result, changed)
    }
}

impl Simplify for Stmt {
    type Output = Vec<Stmt>;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        match self {
            Stmt::If { span, cond, then_body, else_body, phis } => {
                let cond_result = cond.simplify();
                let then_result = then_body.simplify();
                let else_result = else_body.simplify();
                let mut changed = cond_result.changed || then_result.changed || else_result.changed;

                let mut cond = cond_result.value;
                let mut then_body = then_result.value;
                let mut else_body = else_result.value;

                // Remove empty if-statements.
                if then_body.is_empty() && else_body.is_empty() {
                    return SimplifyResult::changed(Vec::new());
                }
                // Replace `if (cond) {} else { stmts }` with `if (!cond) { stmts}`.
                if then_body.is_empty() {
                    invert_cond(&mut cond);
                    std::mem::swap(&mut then_body, &mut else_body);
                    changed = true;
                }
                // Inline branches with constant true condition.
                if cond.maybe_boolean() == Some(true) {
                    return SimplifyResult::changed(then_body);
                }
                // Inline branches with constant false condition.
                if cond.maybe_boolean() == Some(false) {
                    return SimplifyResult::changed(else_body);
                }
                SimplifyResult::new(
                    vec![Stmt::If { span, cond, then_body, else_body, phis }],
                    changed,
                )
            },
            Stmt::Repeat { span, loop_var, loop_count, body, phis } => {
                let body_result = body.simplify();
                let changed = body_result.changed;
                let body = body_result.value;

                // Remove trivial loops.
                if loop_count == 0 || body.is_empty() {
                    return SimplifyResult::changed(Vec::new());
                }
                SimplifyResult::new(
                    vec![Stmt::Repeat { span, loop_var, loop_count, body, phis }],
                    changed,
                )
            },
            // Remove self-assignments.
            Stmt::Assign { span, dest, expr } => {
                let dest_result = dest.simplify();
                let expr_result = expr.simplify();
                let changed = dest_result.changed || expr_result.changed;

                let dest = dest_result.value;
                let expr = expr_result.value;

                if let Expr::Var(source) = &expr
                    && &dest == source
                {
                    return SimplifyResult::changed(Vec::new());
                }
                SimplifyResult::new(vec![Stmt::Assign { span, dest, expr }], changed)
            },
            // Simplify load and store arguments.
            Stmt::MemLoad { span, load } => {
                load.simplify().map(|l| vec![Stmt::MemLoad { span, load: l }])
            },
            Stmt::MemStore { span, store } => {
                store.simplify().map(|s| vec![Stmt::MemStore { span, store: s }])
            },
            Stmt::AdvLoad { span, load } => {
                load.simplify().map(|l| vec![Stmt::AdvLoad { span, load: l }])
            },
            Stmt::AdvStore { span, store } => {
                store.simplify().map(|s| vec![Stmt::AdvStore { span, store: s }])
            },
            Stmt::LocalLoad { span, load } => {
                load.simplify().map(|l| vec![Stmt::LocalLoad { span, load: l }])
            },
            Stmt::LocalStore { span, store } => {
                store.simplify().map(|s| vec![Stmt::LocalStore { span, store: s }])
            },
            Stmt::LocalStoreW { span, store } => {
                store.simplify().map(|s| vec![Stmt::LocalStoreW { span, store: s }])
            },
            // Calls.
            Stmt::Call { span, call } => {
                call.simplify().map(|c| vec![Stmt::Call { span, call: c }])
            },
            Stmt::Exec { span, call } => {
                call.simplify().map(|c| vec![Stmt::Exec { span, call: c }])
            },
            Stmt::SysCall { span, call } => {
                call.simplify().map(|c| vec![Stmt::SysCall { span, call: c }])
            },
            Stmt::DynCall { span, args, results } => {
                let args_result = args.simplify();
                let results_result = results.simplify();
                let changed = args_result.changed || results_result.changed;
                SimplifyResult::new(
                    vec![Stmt::DynCall {
                        span,
                        args: args_result.value,
                        results: results_result.value,
                    }],
                    changed,
                )
            },
            _ => SimplifyResult::unchanged(vec![self]),
        }
    }
}

impl Simplify for AdvLoad {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        self.outputs.simplify().map(|outputs| AdvLoad { outputs })
    }
}

impl Simplify for AdvStore {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        self.values.simplify().map(|values| AdvStore { values })
    }
}

impl Simplify for LocalLoad {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        self.outputs.simplify().map(|outputs| LocalLoad {
            kind: self.kind,
            index: self.index,
            outputs,
        })
    }
}

impl Simplify for LocalStore {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        self.values.simplify().map(|values| LocalStore { index: self.index, values })
    }
}

impl Simplify for LocalStoreW {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        self.values.simplify().map(|values| LocalStoreW {
            kind: self.kind,
            index: self.index,
            values,
        })
    }
}

impl Simplify for MemLoad {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let address_result = self.address.simplify();
        let outputs_result = self.outputs.simplify();
        SimplifyResult::new(
            MemLoad {
                kind: self.kind,
                address: address_result.value,
                outputs: outputs_result.value,
            },
            address_result.changed || outputs_result.changed,
        )
    }
}

impl Simplify for MemStore {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let address_result = self.address.simplify();
        let values_result = self.values.simplify();
        SimplifyResult::new(
            MemStore {
                kind: self.kind,
                address: address_result.value,
                values: values_result.value,
            },
            address_result.changed || values_result.changed,
        )
    }
}

impl Simplify for Call {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let args_result = self.args.simplify();
        let results_result = self.results.simplify();
        SimplifyResult::new(
            Call {
                target: self.target,
                args: args_result.value,
                results: results_result.value,
            },
            args_result.changed || results_result.changed,
        )
    }
}

impl Simplify for Expr {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        match self {
            // Simplify variable subscripts.
            Expr::Var(v) => v.simplify().map(Expr::Var),
            // Fold constant expressions.
            Expr::Unary(op, expr) => {
                let expr_result = expr.simplify();
                let expr = expr_result.value;
                match (op, &expr) {
                    (UnOp::Not, Expr::Constant(c)) => match c.maybe_boolean() {
                        Some(true) => SimplifyResult::changed(Expr::False),
                        Some(false) => SimplifyResult::changed(Expr::True),
                        None => SimplifyResult::new(
                            Expr::Unary(op, Box::new(expr)),
                            expr_result.changed,
                        ),
                    },
                    (UnOp::Neg, Expr::Constant(Constant::Felt(felt))) => {
                        SimplifyResult::changed(Expr::Constant(Constant::Felt(felt.wrapping_neg())))
                    },
                    _ => SimplifyResult::new(Expr::Unary(op, Box::new(expr)), expr_result.changed),
                }
            },
            // Simplify addition and multiplication of constants.
            Expr::Binary(op, left, right) => {
                let left_result = left.simplify();
                let right_result = right.simplify();
                let child_changed = left_result.changed || right_result.changed;
                let left = left_result.value;
                let right = right_result.value;

                match (op, &left, &right) {
                    // Constant folding for addition.
                    (
                        BinOp::Add,
                        Expr::Constant(Constant::Felt(a)),
                        Expr::Constant(Constant::Felt(b)),
                    ) => SimplifyResult::changed(Expr::Constant(Constant::Felt(a + b))),
                    // Constant folding for multiplication.
                    (
                        BinOp::Mul,
                        Expr::Constant(Constant::Felt(a)),
                        Expr::Constant(Constant::Felt(b)),
                    ) => SimplifyResult::changed(Expr::Constant(Constant::Felt(a * b))),
                    // 0 + x = x + 0 = x
                    (BinOp::Add, Expr::Constant(c), r) if c.is_zero() => {
                        SimplifyResult::changed(r.clone())
                    },
                    (BinOp::Add, l, Expr::Constant(c)) if c.is_zero() => {
                        SimplifyResult::changed(l.clone())
                    },
                    // 1 * x = x * 1 = x
                    (BinOp::Mul, Expr::Constant(c), r) if c.is_one() => {
                        SimplifyResult::changed(r.clone())
                    },
                    (BinOp::Mul, l, Expr::Constant(c)) if c.is_one() => {
                        SimplifyResult::changed(l.clone())
                    },
                    // 0 * x = x * 0 = 0
                    (BinOp::Mul, Expr::Constant(c), _) if c.is_zero() && c.as_felt().is_some() => {
                        SimplifyResult::changed(Expr::Constant(Constant::Felt(0)))
                    },
                    (BinOp::Mul, Expr::Constant(c), _) if c.is_zero() && c.as_word().is_some() => {
                        SimplifyResult::changed(Expr::Constant(Constant::Word([0; 4])))
                    },
                    (BinOp::Mul, _, Expr::Constant(c)) if c.is_zero() && c.as_felt().is_some() => {
                        SimplifyResult::changed(Expr::Constant(Constant::Felt(0)))
                    },
                    (BinOp::Mul, _, Expr::Constant(c)) if c.is_zero() && c.as_word().is_some() => {
                        SimplifyResult::changed(Expr::Constant(Constant::Word([0; 4])))
                    },
                    _ => SimplifyResult::new(
                        Expr::Binary(op, Box::new(left), Box::new(right)),
                        child_changed,
                    ),
                }
            },
            Expr::Ternary { cond, then_expr, else_expr } => {
                let cond_result = cond.simplify();
                let then_result = then_expr.simplify();
                let else_result = else_expr.simplify();
                let changed = cond_result.changed || then_result.changed || else_result.changed;
                let cond = cond_result.value;
                let then_expr = then_result.value;
                let else_expr = else_result.value;

                if let Some(value) = cond.maybe_boolean() {
                    let chosen = if value { then_expr } else { else_expr };
                    return SimplifyResult::new(chosen, true);
                }

                if then_expr == else_expr {
                    return SimplifyResult::new(then_expr, true);
                }

                SimplifyResult::new(
                    Expr::Ternary {
                        cond: Box::new(cond),
                        then_expr: Box::new(then_expr),
                        else_expr: Box::new(else_expr),
                    },
                    changed,
                )
            },
            Expr::EqW { lhs, rhs } => {
                let [lhs0, lhs1, lhs2, lhs3] = *lhs;
                let [rhs0, rhs1, rhs2, rhs3] = *rhs;

                let lhs0 = lhs0.simplify();
                let lhs1 = lhs1.simplify();
                let lhs2 = lhs2.simplify();
                let lhs3 = lhs3.simplify();
                let rhs0 = rhs0.simplify();
                let rhs1 = rhs1.simplify();
                let rhs2 = rhs2.simplify();
                let rhs3 = rhs3.simplify();

                let changed = lhs0.changed
                    || lhs1.changed
                    || lhs2.changed
                    || lhs3.changed
                    || rhs0.changed
                    || rhs1.changed
                    || rhs2.changed
                    || rhs3.changed;

                SimplifyResult::new(
                    Expr::EqW {
                        lhs: Box::new([lhs0.value, lhs1.value, lhs2.value, lhs3.value]),
                        rhs: Box::new([rhs0.value, rhs1.value, rhs2.value, rhs3.value]),
                    },
                    changed,
                )
            },
            _ => SimplifyResult::unchanged(self),
        }
    }
}

impl Simplify for Var {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        let simplified = self.subscript.clone().simplify();
        if simplified.changed {
            SimplifyResult::changed(self.with_subscript(simplified.value))
        } else {
            SimplifyResult::unchanged(self)
        }
    }
}

impl Simplify for IndexExpr {
    type Output = Self;

    fn simplify(self) -> SimplifyResult<Self::Output> {
        match self {
            IndexExpr::Add(left, right) => {
                let left_result = left.simplify();
                let right_result = right.simplify();
                let changed = left_result.changed || right_result.changed;
                let left = left_result.value;
                let right = right_result.value;

                match (&left, &right) {
                    // Fold addition.
                    (IndexExpr::Const(a), IndexExpr::Const(b)) => {
                        SimplifyResult::changed(IndexExpr::Const(a + b))
                    },
                    // Simplify addition with 0.
                    (IndexExpr::Const(0), expr) => SimplifyResult::changed(expr.clone()),
                    (expr, IndexExpr::Const(0)) => SimplifyResult::changed(expr.clone()),
                    _ => SimplifyResult::new(
                        IndexExpr::Add(Box::new(left), Box::new(right)),
                        changed,
                    ),
                }
            },
            IndexExpr::Mul(left, right) => {
                let left_result = left.simplify();
                let right_result = right.simplify();
                let changed = left_result.changed || right_result.changed;
                let left = left_result.value;
                let right = right_result.value;

                match (&left, &right) {
                    // Fold multiplication.
                    (IndexExpr::Const(a), IndexExpr::Const(b)) => {
                        SimplifyResult::changed(IndexExpr::Const(a * b))
                    },
                    // Simplify multiplication with 0 and 1.
                    (IndexExpr::Const(1), expr) => SimplifyResult::changed(expr.clone()),
                    (expr, IndexExpr::Const(1)) => SimplifyResult::changed(expr.clone()),
                    (IndexExpr::Const(0), _) => SimplifyResult::changed(IndexExpr::Const(0)),
                    (_, IndexExpr::Const(0)) => SimplifyResult::changed(IndexExpr::Const(0)),
                    _ => SimplifyResult::new(
                        IndexExpr::Mul(Box::new(left), Box::new(right)),
                        changed,
                    ),
                }
            },
            _ => SimplifyResult::unchanged(self),
        }
    }
}

trait MaybeBoolean {
    fn maybe_boolean(&self) -> Option<bool>;
}

impl MaybeBoolean for Expr {
    fn maybe_boolean(&self) -> Option<bool> {
        match self {
            Expr::True => Some(true),
            Expr::False => Some(false),
            Expr::Constant(c) => c.maybe_boolean(),
            Expr::Unary(UnOp::Not, inner) => inner.maybe_boolean().map(|b| !b),
            Expr::Binary(BinOp::And, a, b) => match (a.maybe_boolean(), b.maybe_boolean()) {
                (Some(true), Some(true)) => Some(true),
                (Some(false), _) | (_, Some(false)) => Some(false),
                _ => None,
            },
            Expr::Binary(BinOp::Or, a, b) => match (a.maybe_boolean(), b.maybe_boolean()) {
                (Some(false), Some(false)) => Some(false),
                (Some(true), _) | (_, Some(true)) => Some(true),
                _ => None,
            },
            Expr::Ternary { cond, then_expr, else_expr } => match cond.maybe_boolean() {
                Some(true) => then_expr.maybe_boolean(),
                Some(false) => else_expr.maybe_boolean(),
                None => None,
            },
            _ => None,
        }
    }
}

impl MaybeBoolean for Constant {
    fn maybe_boolean(&self) -> Option<bool> {
        match self {
            Constant::Felt(felt) => Some(*felt != 0),
            Constant::Word(word) => Some(word.iter().any(|w| *w != 0)),
            Constant::Defined(_) => None,
        }
    }
}

fn invert_cond(cond: &mut Expr) {
    match cond {
        Expr::Unary(UnOp::Not, inner) => {
            *cond = (*inner.as_ref()).clone();
        },
        _ => {
            *cond = Expr::Unary(UnOp::Not, Box::new(cond.clone()));
        },
    }
}
