//! Expression facts and traversal for unconstrained-advice analyses.

use masm_decompiler::{BinOp, Expr, UnOp, Var, VarKey};

use super::{
    domain::AdviceFact,
    env::{Env, EqZeroWitness},
    u32_domain::U32Validity,
};

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

/// Refine branch environments using an exact `eq.0` witness when available.
pub(super) fn refine_if_envs(cond: &Expr, env: &Env) -> (Env, Env) {
    let then_env = env.clone();
    let mut else_env = env.clone();
    if let Some(witness) = eq_zero_witness_for_expr(cond, env) {
        else_env.mark_identity_nonzero(witness.value_identity);
    }
    (then_env, else_env)
}

/// Return the exact alias identity of an expression, when it is a simple copy.
fn expr_identity(expr: &Expr, env: &Env) -> Option<VarKey> {
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

/// Return the variable compared against zero in an `eq.0`-shaped expression.
fn zero_comparison_var<'a>(lhs: &'a Expr, rhs: &'a Expr) -> Option<&'a Var> {
    match (lhs, rhs) {
        (Expr::Var(var), Expr::Constant(constant)) if constant.is_zero() => Some(var),
        (Expr::Constant(constant), Expr::Var(var)) if constant.is_zero() => Some(var),
        _ => None,
    }
}
