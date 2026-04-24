//! Dead code elimination for structured code.
//!
//! This module eliminates dead assignments from structured code using the
//! forward liveness analysis in `used_vars`.
//!
//! ## Algorithm
//!
//! 1. Run forward liveness analysis to identify dead statement paths
//! 2. Collect indices of dead `Assign` statements
//! 3. Remove statements at those indices (in reverse order to preserve indices)
//! 4. Iterate until a fixed point is reached (eliminating dead code may create new dead code when
//!    uses are removed)

use std::collections::HashSet;

use log::trace;

use super::used_vars::{PathSegment, StmtPath, analyze_liveness};
use crate::ir::Stmt;

const MAX_ELIMINATION_PASSES: usize = 100;

/// Eliminate dead code from structured statements.
///
/// This pass removes assignments whose results are never used.
/// It iterates until a fixed point is reached (no more eliminations possible).
pub fn eliminate_dead_code(stmts: &mut Vec<Stmt>) {
    for pass in 0..MAX_ELIMINATION_PASSES {
        let result = analyze_liveness(stmts);

        if result.dead_paths.is_empty() {
            trace!("DCE converged after {pass} passes");
            break;
        }

        trace!("DCE pass {pass}: {} dead paths identified", result.dead_paths.len());

        // Collect and remove dead statements.
        let changed = eliminate_at_paths(stmts, &result.dead_paths, &mut Vec::new());
        if !changed {
            break;
        }
    }
}

/// Eliminate statements at the specified paths.
///
/// Only `Assign` statements are eliminated; other statements have side effects.
/// Returns true if any statements were eliminated.
fn eliminate_at_paths(
    stmts: &mut Vec<Stmt>,
    dead_paths: &HashSet<StmtPath>,
    current_path: &mut StmtPath,
) -> bool {
    // Collect indices of statements to remove at this level.
    let mut indices_to_remove: Vec<usize> = Vec::new();
    let mut changed = false;

    for (i, stmt) in stmts.iter_mut().enumerate() {
        current_path.push(PathSegment::Index(i));

        match stmt {
            Stmt::Assign { .. } if dead_paths.contains(current_path) => {
                trace!("eliminating dead assignment at {current_path:?}");
                indices_to_remove.push(i);
                changed = true;
            },

            Stmt::Repeat { body, .. } => {
                current_path.push(PathSegment::Repeat);
                changed |= eliminate_at_paths(body, dead_paths, current_path);
                current_path.pop();
            },

            Stmt::If { then_body, else_body, .. } => {
                current_path.push(PathSegment::Then);
                changed |= eliminate_at_paths(then_body, dead_paths, current_path);
                current_path.pop();

                current_path.push(PathSegment::Else);
                changed |= eliminate_at_paths(else_body, dead_paths, current_path);
                current_path.pop();
            },

            Stmt::While { body, .. } => {
                current_path.push(PathSegment::While);
                changed |= eliminate_at_paths(body, dead_paths, current_path);
                current_path.pop();
            },

            // Other statements are not eliminated (side effects or not definitions).
            _ => {},
        }

        current_path.pop();
    }

    // Remove collected indices in reverse order to preserve earlier indices.
    for i in indices_to_remove.into_iter().rev() {
        stmts.remove(i);
    }

    changed
}
