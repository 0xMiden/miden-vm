//! Direct SSA expression definitions used by local type refinements.

use std::collections::HashMap;

use super::domain::VarKey;
use crate::ir::{Expr, Stmt, UnOp};

/// Direct expression definitions keyed by destination SSA variable.
///
/// This supports small sound structural refinements such as preserving the
/// `u32` result of bit-count operations through known-safe constant offsets.
#[derive(Debug, Default, Clone)]
pub(super) struct ExprDefs {
    defs: HashMap<VarKey, Expr>,
}

impl ExprDefs {
    /// Collect direct assignment expressions from a structured statement block.
    pub(super) fn collect(stmts: &[Stmt]) -> Self {
        let mut expr_defs = Self::default();
        expr_defs.collect_in_block(stmts);
        expr_defs
    }

    /// Return true when the expression is a `u32` count result, following local copy chains.
    pub(super) fn is_u32_count_expr(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Unary(UnOp::U32Clz | UnOp::U32Ctz | UnOp::U32Clo | UnOp::U32Cto, _) => true,
            Expr::Var(var) => self
                .defs
                .get(&VarKey::from_var(var))
                .is_some_and(|def| self.is_u32_count_expr(def)),
            _ => false,
        }
    }

    fn collect_in_block(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            match stmt {
                Stmt::Assign { dest, expr, .. } => {
                    self.defs.insert(VarKey::from_var(dest), expr.clone());
                },
                Stmt::If { then_body, else_body, .. } => {
                    self.collect_in_block(then_body);
                    self.collect_in_block(else_body);
                },
                Stmt::Repeat { body, .. } | Stmt::While { body, .. } => {
                    self.collect_in_block(body);
                },
                _ => {},
            }
        }
    }
}
