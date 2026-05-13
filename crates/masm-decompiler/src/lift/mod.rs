//! Direct AST-to-IR lifting.
//!
//! This module transforms MASM AST directly into structured IR statements,
//! without an intermediate CFG representation. The approach mirrors signature
//! inference: recursive AST traversal with symbolic stack tracking.

mod inst;
mod repeat;
mod stack;

use std::collections::{HashMap, HashSet, VecDeque};

use log::trace;
use miden_assembly_syntax::{
    ast::{Block, Instruction, Op, Procedure},
    debuginfo::{SourceSpan, Spanned},
};
use repeat::{SlotStack, TaggedSlotStack, simulate_block_slots, simulate_block_tags};
use stack::{SlotId, StackEntry, SymbolicStack};

use crate::{
    ir::{Expr, IfPhi, IndexExpr, LoopPhi, LoopVar, Stmt, ValueId, Var, VarBase},
    signature::{ProcSignature, SignatureMap},
    symbol::{path::SymbolPath, resolution::SymbolResolver},
};

/// Errors that can occur during lifting.
#[derive(Debug)]
pub enum LiftingError {
    /// Unsupported instruction encountered.
    UnsupportedInstruction {
        /// Source span of the unsupported instruction.
        span: SourceSpan,
        /// The instruction which could not be lifted.
        instruction: Instruction,
    },
    /// Call target could not be resolved to a concrete procedure path.
    UnresolvedCallTarget {
        /// Source span of the call instruction.
        span: SourceSpan,
        /// The unresolved call target as written in source.
        target: String,
        /// Optional resolver error details.
        reason: Option<String>,
    },
    /// Call target was resolved, but no inferred signature entry exists.
    MissingSignature {
        /// Source span of the call instruction.
        span: SourceSpan,
        /// Fully-qualified callee path.
        callee: SymbolPath,
    },
    /// Call target was resolved, but signature inference produced `Unknown`.
    UnknownSignature {
        /// Source span of the call instruction.
        span: SourceSpan,
        /// Fully-qualified callee path.
        callee: SymbolPath,
    },
    /// Control-flow construct tried to consume a condition from an empty stack.
    MissingControlFlowCondition {
        /// Source span of the originating control-flow operation.
        span: SourceSpan,
        /// The MASM construct that required the condition.
        construct: &'static str,
        /// Required stack depth to evaluate the condition.
        required_depth: usize,
        /// Actual symbolic stack depth at the point of failure.
        actual_depth: usize,
    },
    /// Instruction or stack operation required more inputs than lifting had available.
    InsufficientStackDepth {
        /// Source span of the originating operation.
        span: SourceSpan,
        /// The operation that required the missing inputs.
        operation: String,
        /// Required stack depth to execute the operation.
        required_depth: usize,
        /// Actual symbolic stack depth at the point of failure.
        actual_depth: usize,
    },
    /// Unbalanced if-statement (branches have different stack effects).
    UnbalancedIf {
        /// Source span of the originating if operation.
        span: SourceSpan,
    },
    /// Non-neutral while loop.
    NonNeutralWhile {
        /// Source span of the originating while operation.
        span: SourceSpan,
    },
    /// If-statement branches produced incompatible variable subscripts.
    IncompatibleIfMerge {
        /// Source span of the originating if operation.
        span: SourceSpan,
    },
    /// Repeat loop pattern cannot be represented with linear subscripts.
    UnsupportedRepeatPattern {
        /// Source span of the originating repeat operation.
        span: SourceSpan,
        /// Description of the unsupported pattern.
        reason: String,
    },
}

impl std::fmt::Display for LiftingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiftingError::UnsupportedInstruction { instruction, .. } => {
                write!(f, "unsupported instruction `{instruction}` found")
            },
            LiftingError::UnresolvedCallTarget { target, reason, .. } => {
                if let Some(reason) = reason {
                    write!(f, "failed to resolve call target `{target}`: {reason}")
                } else {
                    write!(f, "failed to resolve call target `{target}`")
                }
            },
            LiftingError::MissingSignature { callee, .. } => {
                write!(f, "missing inferred signature for call target `{callee}`")
            },
            LiftingError::UnknownSignature { callee, .. } => {
                write!(f, "call target `{callee}` has unknown inferred signature")
            },
            LiftingError::MissingControlFlowCondition {
                construct,
                required_depth,
                actual_depth,
                ..
            } => write!(
                f,
                "`{construct}` requires stack depth {required_depth}, but lifting only has depth {actual_depth}"
            ),
            LiftingError::InsufficientStackDepth {
                operation,
                required_depth,
                actual_depth,
                ..
            } => write!(
                f,
                "`{operation}` requires stack depth {required_depth}, but lifting only has depth {actual_depth}"
            ),
            LiftingError::UnbalancedIf { .. } => write!(f, "unbalanced if-statement"),
            LiftingError::NonNeutralWhile { .. } => write!(f, "non-neutral while loop"),
            LiftingError::IncompatibleIfMerge { .. } => {
                write!(f, "if-statement branches produced incompatible subscripts")
            },
            LiftingError::UnsupportedRepeatPattern { reason, .. } => {
                write!(f, "unsupported repeat loop pattern: {reason}")
            },
        }
    }
}

impl std::error::Error for LiftingError {}

/// Result type for lifting operations.
pub type LiftingResult<T> = Result<T, LiftingError>;

/// Context for tracking loop nesting during lifting.
#[derive(Debug, Clone, Default)]
struct LoopContext {
    /// Stack of (loop_var, entry_depth) for each enclosing loop.
    loops: Vec<(LoopVar, usize)>,
}

impl LoopContext {
    /// Create a new empty loop context.
    fn new() -> Self {
        Self { loops: Vec::new() }
    }

    /// Enter a new loop with the given loop variable and entry stack depth.
    fn enter(&mut self, loop_var: LoopVar, entry_depth: usize) {
        self.loops.push((loop_var, entry_depth));
    }

    /// Exit the current loop.
    fn exit(&mut self) {
        self.loops.pop();
    }

    /// Get the current loop nesting depth (number of enclosing loops).
    fn depth(&self) -> usize {
        self.loops.len()
    }
}

/// Lift a procedure AST to structured IR statements.
///
/// This is the main entry point for the lifting pass. It initializes the
/// symbolic stack with input variables based on the procedure signature,
/// processes the procedure body, and appends a return statement.
pub fn lift_proc(
    proc: &Procedure,
    proc_path: &SymbolPath,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    let mut stack = SymbolicStack::new();
    let mut loop_ctx = LoopContext::new();

    // Initialize stack with input variables from signature.
    if let Some(ProcSignature::Known { inputs, public_inputs, .. }) = sigs.get(proc_path) {
        if public_inputs < inputs {
            for hidden_depth in *public_inputs..*inputs {
                stack.push_fresh_with_value_id((hidden_depth as u64).into(), hidden_depth);
            }
            for display_depth in 0..*public_inputs {
                stack.push_fresh_with_value_id((display_depth as u64).into(), display_depth);
            }
        } else {
            stack.ensure_depth(*inputs);
        }
    }

    let mut stmts = lift_block(proc.body(), &mut stack, &mut loop_ctx, resolver, sigs)?;

    // Add return statement with outputs.
    if let Some(ProcSignature::Known { outputs, .. }) = sigs.get(proc_path) {
        let return_vars = stack.top_n_checked(*outputs, SourceSpan::UNKNOWN, "return")?;
        stmts.push(Stmt::Return {
            span: SourceSpan::UNKNOWN,
            values: return_vars,
        });
    }

    Ok(stmts)
}

/// Lift a block of operations to statements.
fn lift_block(
    block: &Block,
    stack: &mut SymbolicStack,
    loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    let mut stmts = Vec::new();
    for op in block.iter() {
        let op_stmts = lift_op(op, op.span(), stack, loop_ctx, resolver, sigs)?;
        stmts.extend(op_stmts);
    }
    Ok(stmts)
}

/// Lift a single operation to statements.
fn lift_op(
    op: &Op,
    op_span: SourceSpan,
    stack: &mut SymbolicStack,
    loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    match op {
        Op::Inst(inst) => inst::lift_inst(inst.inner(), op_span, stack, loop_ctx, resolver, sigs),
        Op::If { then_blk, else_blk, .. } => {
            lift_if(op_span, then_blk, else_blk, stack, loop_ctx, resolver, sigs)
        },
        Op::Repeat { count, body, .. } => lift_repeat(
            op_span,
            count.expect_value() as usize,
            body,
            stack,
            loop_ctx,
            resolver,
            sigs,
        ),
        Op::While { body, .. } => lift_while(op_span, body, stack, loop_ctx, resolver, sigs),
    }
}

/// Lift an if-else construct.
///
/// Both branches must have the same stack effect.
fn lift_if(
    op_span: SourceSpan,
    then_block: &Block,
    else_block: &Block,
    stack: &mut SymbolicStack,
    loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    // Pop condition from stack.
    if stack.is_empty() {
        return Err(LiftingError::MissingControlFlowCondition {
            span: op_span,
            construct: "if.true",
            required_depth: 1,
            actual_depth: 0,
        });
    }
    let cond_var = stack.pop();
    let cond = Expr::Var(cond_var);

    // Process both branches with cloned stacks.
    let mut then_stack = stack.clone();
    let mut else_stack = stack.clone();

    let then_body = lift_block(then_block, &mut then_stack, loop_ctx, resolver, sigs)?;
    let else_body = lift_block(else_block, &mut else_stack, loop_ctx, resolver, sigs)?;

    // Verify balanced stack effects.
    if then_stack.len() != else_stack.len() {
        return Err(LiftingError::UnbalancedIf { span: op_span });
    }

    // Merge branch stacks with Phi nodes where needed.
    let mut phis = Vec::new();
    let mut merged = Vec::with_capacity(then_stack.len());
    let then_entries = then_stack.to_entries();
    let else_entries = else_stack.to_entries();

    for (then_entry, else_entry) in then_entries.iter().zip(else_entries.iter()) {
        let then_var = &then_entry.var;
        let else_var = &else_entry.var;
        if !if_merge_subscripts_compatible(&then_var.subscript, &else_var.subscript) {
            return Err(LiftingError::IncompatibleIfMerge { span: op_span });
        }
        if then_var.base == else_var.base && then_var.subscript == else_var.subscript {
            merged.push(then_var.clone());
            continue;
        }

        let dest = stack.fresh_like(then_var);
        phis.push(IfPhi {
            dest: dest.clone(),
            then_var: then_var.clone(),
            else_var: else_var.clone(),
        });
        merged.push(dest);
    }

    stack.set_stack(merged);

    Ok(vec![Stmt::If {
        span: op_span,
        cond,
        then_body,
        else_body,
        phis,
    }])
}

/// Return true when branch-exit subscripts can be represented by an `IfPhi`.
///
/// Straight-line branches can legitimately produce different constant
/// subscripts after local stack reshaping, but loop-indexed subscripts must
/// still agree exactly to avoid fabricating an unrepresentable merged index.
fn if_merge_subscripts_compatible(lhs: &IndexExpr, rhs: &IndexExpr) -> bool {
    matches!((lhs, rhs), (IndexExpr::Const(_), IndexExpr::Const(_))) || lhs == rhs
}

/// Lift a repeat loop construct.
///
/// For repeat loops, we process the body once to get the template statements,
/// then compute appropriate subscripts for variables that escape the loop.
fn lift_repeat(
    op_span: SourceSpan,
    count: usize,
    body: &Block,
    stack: &mut SymbolicStack,
    loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    let entry_depth = stack.len();
    let entry_entries = stack.to_entries();

    // Create loop variable using current nesting depth.
    // The depth uniquely identifies this loop within its scope and maps
    // directly to loop counter names (0 → i, 1 → j, etc.).
    let loop_var = LoopVar { loop_depth: loop_ctx.depth() };

    // Enter loop context.
    loop_ctx.enter(loop_var, entry_depth);

    // Process body once to get template and determine stack effect.
    let body_stmts = lift_block(body, stack, loop_ctx, resolver, sigs)?;

    // Exit loop context.
    loop_ctx.exit();

    let exit_depth = stack.len();
    let exit_entries = stack.to_entries();
    let (mut repeat_phis, loop_carried_dests, loop_carried_ids) =
        collect_repeat_phis_by_slot(&entry_entries, &exit_entries, stack);

    // Compute net effect per iteration.
    let delta = exit_depth as isize - entry_depth as isize;
    let loop_depth = loop_var.loop_depth;
    let value_slots = stack.value_slots();
    let exit2_slots = if count > 1 {
        Some(simulate_repeat_slots(body, &exit_entries, resolver, sigs)?)
    } else {
        None
    };
    let slot_indices = compute_slot_indices(
        op_span,
        &entry_entries,
        &exit_entries,
        exit2_slots.as_deref(),
        count,
    )?;
    let produced_value_ids =
        collect_produced_value_ids(&entry_entries, &exit_entries, &body_stmts, &value_slots);
    let produced_stride = if delta > 0 { delta as i64 } else { 0 };
    let mut body_stmts = transform_loop_subscripts(
        body_stmts,
        loop_depth,
        &slot_indices,
        &value_slots,
        &loop_carried_ids,
        &produced_value_ids,
        produced_stride,
    );
    repeat_phis = repeat_phis
        .into_iter()
        .map(|phi| {
            transform_loop_phi_subscripts(
                phi,
                loop_depth,
                &slot_indices,
                &value_slots,
                &loop_carried_ids,
                &produced_value_ids,
                produced_stride,
            )
        })
        .collect();
    let loop_input_ids = collect_loop_input_ids(&entry_entries, &slot_indices, &loop_carried_ids);
    if !loop_input_ids.is_empty() {
        body_stmts = transform_loop_input_bases(body_stmts, &loop_input_ids, loop_depth);
        repeat_phis = repeat_phis
            .into_iter()
            .map(|phi| LoopPhi {
                dest: transform_var_loop_input(phi.dest, &loop_input_ids, loop_depth),
                init: transform_var_loop_input(phi.init, &loop_input_ids, loop_depth),
                step: transform_var_loop_input(phi.step, &loop_input_ids, loop_depth),
            })
            .collect();
    }

    let produced_slots = collect_produced_slot_ids(&entry_entries, &exit_entries);
    update_stack_after_repeat(
        op_span,
        count,
        body,
        stack,
        &exit_entries,
        &loop_carried_dests,
        &produced_slots,
        resolver,
        sigs,
    )?;

    Ok(vec![Stmt::Repeat {
        span: op_span,
        loop_var,
        loop_count: count,
        body: body_stmts,
        phis: repeat_phis,
    }])
}

/// Add two index expressions, simplifying trivial cases.
///
/// This is used to combine subscript contributions from nested loops.
fn add_index_exprs(a: IndexExpr, b: IndexExpr) -> IndexExpr {
    match (&a, &b) {
        // Identity: 0 + x = x, x + 0 = x
        (IndexExpr::Const(0), _) => b,
        (_, IndexExpr::Const(0)) => a,
        // Constant folding
        (IndexExpr::Const(x), IndexExpr::Const(y)) => IndexExpr::Const(x + y),
        // General case
        _ => IndexExpr::Add(Box::new(a), Box::new(b)),
    }
}

/// Build a loop-term expression `coeff * loop_var`.
fn loop_term(loop_var_id: usize, coeff: i64) -> IndexExpr {
    match coeff {
        0 => IndexExpr::Const(0),
        1 => IndexExpr::LoopVar(loop_var_id),
        _ => IndexExpr::Mul(
            Box::new(IndexExpr::Const(coeff)),
            Box::new(IndexExpr::LoopVar(loop_var_id)),
        ),
    }
}

/// Per-slot index parameters used for loop subscript rewriting.
#[derive(Debug, Clone, Copy)]
struct SlotIndex {
    /// Linear shift applied per iteration.
    #[allow(dead_code)]
    delta: i64,
    /// Change in relative depth from the top of the stack per iteration.
    access_delta: i64,
}

/// Transform loop subscripts using slot provenance.
fn transform_loop_subscripts(
    stmts: Vec<Stmt>,
    loop_var_id: usize,
    slot_indices: &HashMap<SlotId, SlotIndex>,
    value_slots: &HashMap<ValueId, SlotId>,
    loop_carried_value_ids: &HashSet<ValueId>,
    produced_value_ids: &HashSet<ValueId>,
    produced_stride: i64,
) -> Vec<Stmt> {
    stmts
        .into_iter()
        .map(|stmt| {
            transform_stmt_loop_subscripts(
                stmt,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )
        })
        .collect()
}

/// Rewrite a single statement using slot-based subscript adjustments.
fn transform_stmt_loop_subscripts(
    stmt: Stmt,
    loop_var_id: usize,
    slot_indices: &HashMap<SlotId, SlotIndex>,
    value_slots: &HashMap<ValueId, SlotId>,
    loop_carried_value_ids: &HashSet<ValueId>,
    produced_value_ids: &HashSet<ValueId>,
    produced_stride: i64,
) -> Stmt {
    match stmt {
        Stmt::Assign { span, dest, expr } => Stmt::Assign {
            span,
            dest: transform_var_loop_subscripts(
                dest,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            expr: transform_expr_loop_subscripts(
                expr,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
        },
        Stmt::Repeat { span, loop_var, loop_count, body, phis } => Stmt::Repeat {
            span,
            loop_var,
            loop_count,
            body: transform_loop_subscripts(
                body,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            phis: phis
                .into_iter()
                .map(|phi| {
                    transform_loop_phi_subscripts(
                        phi,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    )
                })
                .collect(),
        },
        Stmt::If { span, cond, then_body, else_body, phis } => Stmt::If {
            span,
            cond: transform_expr_loop_subscripts(
                cond,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            then_body: transform_loop_subscripts(
                then_body,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            else_body: transform_loop_subscripts(
                else_body,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            phis: phis
                .into_iter()
                .map(|phi| IfPhi {
                    dest: transform_var_loop_subscripts(
                        phi.dest,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    ),
                    then_var: transform_var_loop_subscripts(
                        phi.then_var,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    ),
                    else_var: transform_var_loop_subscripts(
                        phi.else_var,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    ),
                })
                .collect(),
        },
        Stmt::While { span, cond, body, phis } => Stmt::While {
            span,
            cond: transform_expr_loop_subscripts(
                cond,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            body: transform_loop_subscripts(
                body,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            ),
            phis: phis
                .into_iter()
                .map(|phi| {
                    transform_loop_phi_subscripts(
                        phi,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    )
                })
                .collect(),
        },
        Stmt::Return { span, values } => Stmt::Return {
            span,
            values: values
                .into_iter()
                .map(|v| {
                    transform_var_loop_subscripts(
                        v,
                        loop_var_id,
                        slot_indices,
                        value_slots,
                        loop_carried_value_ids,
                        produced_value_ids,
                        produced_stride,
                    )
                })
                .collect(),
        },
        other => other,
    }
}

/// Rewrite a loop phi node using slot-based subscript adjustments.
fn transform_loop_phi_subscripts(
    phi: LoopPhi,
    loop_var_id: usize,
    slot_indices: &HashMap<SlotId, SlotIndex>,
    value_slots: &HashMap<ValueId, SlotId>,
    loop_carried_value_ids: &HashSet<ValueId>,
    produced_value_ids: &HashSet<ValueId>,
    produced_stride: i64,
) -> LoopPhi {
    LoopPhi {
        dest: transform_var_loop_subscripts(
            phi.dest,
            loop_var_id,
            slot_indices,
            value_slots,
            loop_carried_value_ids,
            produced_value_ids,
            produced_stride,
        ),
        init: transform_var_loop_subscripts(
            phi.init,
            loop_var_id,
            slot_indices,
            value_slots,
            loop_carried_value_ids,
            produced_value_ids,
            produced_stride,
        ),
        step: transform_var_loop_subscripts(
            phi.step,
            loop_var_id,
            slot_indices,
            value_slots,
            loop_carried_value_ids,
            produced_value_ids,
            produced_stride,
        ),
    }
}

/// Rewrite a variable subscript using the slot index mapping.
fn transform_var_loop_subscripts(
    var: Var,
    loop_var_id: usize,
    slot_indices: &HashMap<SlotId, SlotIndex>,
    value_slots: &HashMap<ValueId, SlotId>,
    loop_carried_value_ids: &HashSet<ValueId>,
    produced_value_ids: &HashSet<ValueId>,
    produced_stride: i64,
) -> Var {
    let value_id = match var.base.value_id() {
        Some(id) => id,
        None => return var,
    };
    if loop_carried_value_ids.contains(&value_id) {
        return var;
    }
    let slot_id = value_slots.get(&value_id).copied();
    let slot_delta = slot_id
        .and_then(|slot_id| slot_indices.get(&slot_id))
        .map(|index| index.access_delta)
        .unwrap_or(0);
    let loop_delta = if produced_value_ids.contains(&value_id) {
        produced_stride
    } else {
        slot_delta
    };
    if loop_delta == 0 {
        return var;
    }

    let loop_adjustment = loop_term(loop_var_id, loop_delta);
    let new_subscript = add_index_exprs(var.subscript.clone(), loop_adjustment);
    var.with_subscript(new_subscript)
}

/// Rewrite expression variables using the slot index mapping.
fn transform_expr_loop_subscripts(
    expr: Expr,
    loop_var_id: usize,
    slot_indices: &HashMap<SlotId, SlotIndex>,
    value_slots: &HashMap<ValueId, SlotId>,
    loop_carried_value_ids: &HashSet<ValueId>,
    produced_value_ids: &HashSet<ValueId>,
    produced_stride: i64,
) -> Expr {
    match expr {
        Expr::Var(v) => Expr::Var(transform_var_loop_subscripts(
            v,
            loop_var_id,
            slot_indices,
            value_slots,
            loop_carried_value_ids,
            produced_value_ids,
            produced_stride,
        )),
        Expr::Binary(op, lhs, rhs) => Expr::Binary(
            op,
            Box::new(transform_expr_loop_subscripts(
                *lhs,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
            Box::new(transform_expr_loop_subscripts(
                *rhs,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
        ),
        Expr::Unary(op, inner) => Expr::Unary(
            op,
            Box::new(transform_expr_loop_subscripts(
                *inner,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
        ),
        Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
            cond: Box::new(transform_expr_loop_subscripts(
                *cond,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
            then_expr: Box::new(transform_expr_loop_subscripts(
                *then_expr,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
            else_expr: Box::new(transform_expr_loop_subscripts(
                *else_expr,
                loop_var_id,
                slot_indices,
                value_slots,
                loop_carried_value_ids,
                produced_value_ids,
                produced_stride,
            )),
        },
        Expr::EqW { lhs, rhs } => Expr::EqW {
            lhs: Box::new((*lhs).map(|var| {
                transform_var_loop_subscripts(
                    var,
                    loop_var_id,
                    slot_indices,
                    value_slots,
                    loop_carried_value_ids,
                    produced_value_ids,
                    produced_stride,
                )
            })),
            rhs: Box::new((*rhs).map(|var| {
                transform_var_loop_subscripts(
                    var,
                    loop_var_id,
                    slot_indices,
                    value_slots,
                    loop_carried_value_ids,
                    produced_value_ids,
                    produced_stride,
                )
            })),
        },
        other => other,
    }
}

/// Adjust the constant term of an index expression while preserving loop terms.
#[allow(dead_code)]
fn adjust_subscript_base(expr: IndexExpr, new_base: i64) -> IndexExpr {
    let current = constant_term(&expr);
    let delta = new_base - current;
    add_index_exprs(expr, IndexExpr::Const(delta))
}

/// Extract the constant term from a linear index expression.
#[allow(dead_code)]
fn constant_term(expr: &IndexExpr) -> i64 {
    match expr {
        IndexExpr::Const(value) => *value,
        IndexExpr::LoopVar(_) => 0,
        IndexExpr::Add(lhs, rhs) => constant_term(lhs) + constant_term(rhs),
        IndexExpr::Mul(lhs, rhs) => match (&**lhs, &**rhs) {
            (IndexExpr::Const(a), IndexExpr::Const(b)) => a * b,
            _ => 0,
        },
    }
}

/// Identify entry values that must be treated as loop inputs.
fn collect_loop_input_ids(
    entry_entries: &[StackEntry],
    slot_indices: &HashMap<SlotId, SlotIndex>,
    loop_carried_value_ids: &HashSet<ValueId>,
) -> HashSet<ValueId> {
    entry_entries
        .iter()
        .filter_map(|entry| {
            let value_id = entry.var.base.value_id()?;
            if loop_carried_value_ids.contains(&value_id) {
                return None;
            }
            let access_delta =
                slot_indices.get(&entry.slot_id).map(|index| index.access_delta).unwrap_or(0);
            (access_delta != 0).then_some(value_id)
        })
        .collect()
}

/// Build repeat-loop phis by matching entry and exit slot identities.
fn collect_repeat_phis_by_slot(
    entry_entries: &[StackEntry],
    exit_entries: &[StackEntry],
    stack: &mut SymbolicStack,
) -> (Vec<LoopPhi>, HashMap<SlotId, Var>, HashSet<ValueId>) {
    let mut entry_map = HashMap::new();
    for entry in entry_entries {
        entry_map.insert(entry.slot_id, entry.var.clone());
    }
    let mut phis = Vec::new();
    let mut loop_carried_dests = HashMap::new();
    let mut loop_carried_ids = HashSet::new();
    for exit in exit_entries {
        if let Some(init) = entry_map.get(&exit.slot_id)
            && init.base != exit.var.base
        {
            let dest = stack.fresh_like(init);
            stack.register_value_slot_for_var(&dest, exit.slot_id);
            phis.push(LoopPhi {
                dest: dest.clone(),
                init: init.clone(),
                step: exit.var.clone(),
            });
            loop_carried_dests.insert(exit.slot_id, dest);
            if let Some(id) = init.base.value_id() {
                loop_carried_ids.insert(id);
            }
            if let Some(id) = exit.var.base.value_id() {
                loop_carried_ids.insert(id);
            }
        }
    }
    for dest in loop_carried_dests.values() {
        if let Some(id) = dest.base.value_id() {
            loop_carried_ids.insert(id);
        }
    }
    (phis, loop_carried_dests, loop_carried_ids)
}

/// Identify values defined in the loop body that correspond to produced slots.
fn collect_produced_value_ids(
    entry_entries: &[StackEntry],
    exit_entries: &[StackEntry],
    body_stmts: &[Stmt],
    value_slots: &HashMap<ValueId, SlotId>,
) -> HashSet<ValueId> {
    let entry_slots: HashSet<SlotId> = entry_entries.iter().map(|entry| entry.slot_id).collect();
    let exit_slots: HashSet<SlotId> = exit_entries.iter().map(|entry| entry.slot_id).collect();
    let produced_slots: HashSet<SlotId> = exit_slots.difference(&entry_slots).copied().collect();

    let defined_ids = collect_defined_value_ids(body_stmts);
    defined_ids
        .into_iter()
        .filter(|id| {
            value_slots
                .get(id)
                .map(|slot_id| produced_slots.contains(slot_id))
                .unwrap_or(false)
        })
        .collect()
}

/// Identify slots that are newly produced by a repeat-loop iteration.
fn collect_produced_slot_ids(
    entry_entries: &[StackEntry],
    exit_entries: &[StackEntry],
) -> HashSet<SlotId> {
    let entry_slots: HashSet<SlotId> = entry_entries.iter().map(|entry| entry.slot_id).collect();
    let exit_slots: HashSet<SlotId> = exit_entries.iter().map(|entry| entry.slot_id).collect();
    exit_slots.difference(&entry_slots).copied().collect()
}

/// Collect value identifiers defined within a statement list.
fn collect_defined_value_ids(stmts: &[Stmt]) -> HashSet<ValueId> {
    let mut defined = HashSet::new();
    for stmt in stmts {
        collect_defined_value_ids_stmt(stmt, &mut defined);
    }
    defined
}

/// Collect value identifiers defined in a single statement.
fn collect_defined_value_ids_stmt(stmt: &Stmt, defined: &mut HashSet<ValueId>) {
    match stmt {
        Stmt::Assign { dest, .. } => record_defined_id(dest, defined),
        Stmt::MemLoad { load, .. } => {
            for v in &load.outputs {
                record_defined_id(v, defined);
            }
        },
        Stmt::AdvLoad { load, .. } => {
            for v in &load.outputs {
                record_defined_id(v, defined);
            }
        },
        Stmt::LocalLoad { load, .. } => {
            for v in &load.outputs {
                record_defined_id(v, defined);
            }
        },
        Stmt::Call { call, .. } | Stmt::Exec { call, .. } | Stmt::SysCall { call, .. } => {
            for v in &call.results {
                record_defined_id(v, defined);
            }
        },
        Stmt::DynCall { results, .. } => {
            for v in results {
                record_defined_id(v, defined);
            }
        },
        Stmt::Intrinsic { intrinsic, .. } => {
            for v in &intrinsic.results {
                record_defined_id(v, defined);
            }
        },
        Stmt::Repeat { body, phis, .. } => {
            for phi in phis {
                record_defined_id(&phi.dest, defined);
            }
            for stmt in body {
                collect_defined_value_ids_stmt(stmt, defined);
            }
        },
        Stmt::If { then_body, else_body, phis, .. } => {
            for phi in phis {
                record_defined_id(&phi.dest, defined);
            }
            for stmt in then_body {
                collect_defined_value_ids_stmt(stmt, defined);
            }
            for stmt in else_body {
                collect_defined_value_ids_stmt(stmt, defined);
            }
        },
        Stmt::While { body, phis, .. } => {
            for phi in phis {
                record_defined_id(&phi.dest, defined);
            }
            for stmt in body {
                collect_defined_value_ids_stmt(stmt, defined);
            }
        },
        Stmt::MemStore { .. }
        | Stmt::AdvStore { .. }
        | Stmt::LocalStore { .. }
        | Stmt::LocalStoreW { .. }
        | Stmt::Return { .. } => {},
    }
}

/// Record a value identifier from a variable definition.
fn record_defined_id(var: &Var, defined: &mut HashSet<ValueId>) {
    if let Some(id) = var.base.value_id() {
        defined.insert(id);
    }
}

/// Compute slot indices for loop subscripts, validating linear movement.
fn compute_slot_indices(
    op_span: SourceSpan,
    entry_entries: &[StackEntry],
    exit_entries: &[StackEntry],
    exit2_slots: Option<&[SlotId]>,
    loop_count: usize,
) -> LiftingResult<HashMap<SlotId, SlotIndex>> {
    let entry_pos = slot_positions(entry_entries);
    let exit_pos = slot_positions(exit_entries);
    let exit2_pos = exit2_slots.map(slot_positions_from_ids);

    let entry_slots: HashSet<SlotId> = entry_entries.iter().map(|entry| entry.slot_id).collect();
    let exit_slots: HashSet<SlotId> = exit_entries.iter().map(|entry| entry.slot_id).collect();
    let consumed_stride =
        entry_slots.iter().filter(|slot| !exit_slots.contains(slot)).count() as i64;

    let mut slot_indices = HashMap::new();
    for entry in entry_entries {
        if let Some(exit_idx) = exit_pos.get(&entry.slot_id) {
            let delta = if let Some(exit2_pos) = &exit2_pos {
                if let Some(next) = exit2_pos.get(&entry.slot_id) {
                    let base = *entry_pos.get(&entry.slot_id).expect("entry slot");
                    let delta1 = *exit_idx - base;
                    let delta2 = *next - *exit_idx;
                    if loop_count > 1 && delta1 != delta2 {
                        return Err(LiftingError::UnsupportedRepeatPattern {
                            span: op_span,
                            reason: "repeat loop permutes stack positions across iterations"
                                .to_string(),
                        });
                    }
                    let access_delta =
                        (exit_entries.len() as i64 - entry_entries.len() as i64) - delta1;
                    slot_indices.insert(entry.slot_id, SlotIndex { delta: delta1, access_delta });
                    continue;
                } else {
                    -consumed_stride
                }
            } else {
                -consumed_stride
            };
            slot_indices.insert(entry.slot_id, SlotIndex { delta, access_delta: delta });
        } else {
            let delta = -consumed_stride;
            slot_indices.insert(entry.slot_id, SlotIndex { delta, access_delta: delta });
        }
    }

    for exit in exit_entries {
        if entry_slots.contains(&exit.slot_id) {
            continue;
        }
        let delta = if let Some(exit2_pos) = &exit2_pos {
            if let Some(next) = exit2_pos.get(&exit.slot_id) {
                let base = *exit_pos.get(&exit.slot_id).expect("exit slot");
                *next - base
            } else if loop_count > 1 {
                return Err(LiftingError::UnsupportedRepeatPattern {
                    span: op_span,
                    reason: "repeat loop does not reach a steady stack layout".to_string(),
                });
            } else {
                0
            }
        } else {
            0
        };
        slot_indices.insert(exit.slot_id, SlotIndex { delta, access_delta: delta });
    }

    Ok(slot_indices)
}

/// Map slot identifiers to their stack positions.
fn slot_positions(entries: &[StackEntry]) -> HashMap<SlotId, i64> {
    entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| (entry.slot_id, idx as i64))
        .collect()
}

/// Map slot identifiers to positions from an ordered list.
fn slot_positions_from_ids(ids: &[SlotId]) -> HashMap<SlotId, i64> {
    ids.iter().enumerate().map(|(idx, slot_id)| (*slot_id, idx as i64)).collect()
}

/// Simulate the stack slot layout after one repeat-loop iteration.
fn simulate_repeat_slots(
    body: &Block,
    entry_entries: &[StackEntry],
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<SlotId>> {
    let entry_slots = entry_entries.iter().map(|entry| entry.slot_id).collect::<Vec<_>>();
    simulate_repeat_slots_from_ids(body, &entry_slots, resolver, sigs)
}

/// Simulate the stack slot layout after one iteration using slot identifiers.
fn simulate_repeat_slots_from_ids(
    body: &Block,
    entry_slots: &[SlotId],
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<SlotId>> {
    let mut stack = SlotStack::new(entry_slots);
    simulate_block_slots(body, &mut stack, resolver, sigs)?;
    Ok(stack.into_slots())
}

/// Update the stack after a repeat loop using slot-based simulation.
#[allow(clippy::too_many_arguments)]
fn update_stack_after_repeat(
    op_span: SourceSpan,
    count: usize,
    body: &Block,
    stack: &mut SymbolicStack,
    exit_entries: &[StackEntry],
    loop_carried_dests: &HashMap<SlotId, Var>,
    produced_slots: &HashSet<SlotId>,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<()> {
    if count <= 1 {
        return Ok(());
    }

    let loop_carried_slots: HashSet<SlotId> = loop_carried_dests.keys().copied().collect();
    let exit_slots = exit_entries.iter().map(|entry| entry.slot_id.as_u64()).collect::<Vec<_>>();
    let mut carried = loop_carried_slots.iter().map(|slot| slot.as_u64()).collect::<Vec<_>>();
    let mut produced = produced_slots.iter().map(|slot| slot.as_u64()).collect::<Vec<_>>();
    carried.sort_unstable();
    produced.sort_unstable();
    trace!(
        "starting repeat tag simulation: count={count}, exit_slots={exit_slots:?}, loop_carried={carried:?}, produced={produced:?}"
    );

    let mut fresh_slots = HashSet::new();
    let mut slot_vars: HashMap<SlotId, Var> = exit_entries
        .iter()
        .map(|entry| {
            let var = if produced_slots.contains(&entry.slot_id) {
                let fresh = stack.fresh_var(0);
                fresh_slots.insert(entry.slot_id);
                fresh
            } else {
                loop_carried_dests
                    .get(&entry.slot_id)
                    .cloned()
                    .unwrap_or_else(|| entry.var.clone())
            };
            (entry.slot_id, var)
        })
        .collect();

    let mut tagged_stack = TaggedSlotStack::new(
        &exit_entries.iter().map(|entry| entry.slot_id).collect::<Vec<_>>(),
        &loop_carried_slots,
    );
    let mut known_slots: HashSet<SlotId> = slot_vars.keys().copied().collect();

    for iter in 1..count {
        trace!(
            "state snapshot before repeat tag simulation iteration {}: {}",
            iter,
            tagged_stack.state_snapshot()
        );
        simulate_block_tags(body, &mut tagged_stack, resolver, sigs)?;
        trace!(
            "state snapshot after repeat tag simulation iteration {}: {}",
            iter,
            tagged_stack.state_snapshot()
        );
        for slot_id in tagged_stack.slots() {
            if !known_slots.contains(slot_id) {
                let var = stack.fresh_var(0);
                slot_vars.insert(*slot_id, var);
                known_slots.insert(*slot_id);
                fresh_slots.insert(*slot_id);
            }
        }
    }

    let mut final_entries = VecDeque::with_capacity(tagged_stack.slots().len());
    for (idx, slot_id) in tagged_stack.slots().iter().enumerate() {
        let tag_set = tagged_stack.tags_for(*slot_id);
        if tag_set.len() > 1 {
            return Err(LiftingError::UnsupportedRepeatPattern {
                span: op_span,
                reason: "repeat loop merges multiple loop-carried values".to_string(),
            });
        }
        let var = if let Some(tag) = tag_set.iter().next() {
            loop_carried_dests.get(tag).cloned().ok_or_else(|| {
                LiftingError::UnsupportedRepeatPattern {
                    span: op_span,
                    reason: "repeat loop produced unknown loop-carried value".to_string(),
                }
            })?
        } else {
            slot_vars.get(slot_id).cloned().expect("slot variable must exist")
        };
        if fresh_slots.contains(slot_id) {
            let adjusted_var = Var {
                base: var.base.clone(),
                stack_depth: idx,
                subscript: IndexExpr::Const(idx as i64),
            };
            final_entries.push_back(StackEntry::new(adjusted_var, *slot_id));
        } else {
            final_entries.push_back(StackEntry::new(var, *slot_id));
        }
    }

    trace!(
        "final state snapshot after repeat tag simulation: {}",
        tagged_stack.state_snapshot()
    );

    stack.set_entries(final_entries);
    Ok(())
}
/// Rewrite entry-stack references inside consuming loops to use loop-input bases.
fn transform_loop_input_bases(
    stmts: Vec<Stmt>,
    entry_value_ids: &HashSet<ValueId>,
    loop_depth: usize,
) -> Vec<Stmt> {
    stmts
        .into_iter()
        .map(|stmt| transform_stmt_loop_input(stmt, entry_value_ids, loop_depth))
        .collect()
}

/// Rewrite variables inside a statement to use loop-input bases when needed.
fn transform_stmt_loop_input(
    stmt: Stmt,
    entry_value_ids: &HashSet<ValueId>,
    loop_depth: usize,
) -> Stmt {
    match stmt {
        Stmt::Assign { span, dest, expr } => {
            let dest = transform_var_loop_input(dest, entry_value_ids, loop_depth);
            let expr = transform_expr_loop_input(expr, entry_value_ids, loop_depth);
            Stmt::Assign { span, dest, expr }
        },
        Stmt::Repeat { span, loop_var, loop_count, body, phis } => Stmt::Repeat {
            span,
            loop_var,
            loop_count,
            body: transform_loop_input_bases(body, entry_value_ids, loop_depth),
            phis: phis
                .into_iter()
                .map(|phi| LoopPhi {
                    dest: transform_var_loop_input(phi.dest, entry_value_ids, loop_depth),
                    init: transform_var_loop_input(phi.init, entry_value_ids, loop_depth),
                    step: transform_var_loop_input(phi.step, entry_value_ids, loop_depth),
                })
                .collect(),
        },
        Stmt::If { span, cond, then_body, else_body, phis } => Stmt::If {
            span,
            cond: transform_expr_loop_input(cond, entry_value_ids, loop_depth),
            then_body: transform_loop_input_bases(then_body, entry_value_ids, loop_depth),
            else_body: transform_loop_input_bases(else_body, entry_value_ids, loop_depth),
            phis: phis
                .into_iter()
                .map(|phi| IfPhi {
                    dest: transform_var_loop_input(phi.dest, entry_value_ids, loop_depth),
                    then_var: transform_var_loop_input(phi.then_var, entry_value_ids, loop_depth),
                    else_var: transform_var_loop_input(phi.else_var, entry_value_ids, loop_depth),
                })
                .collect(),
        },
        Stmt::While { span, cond, body, phis } => Stmt::While {
            span,
            cond: transform_expr_loop_input(cond, entry_value_ids, loop_depth),
            body: transform_loop_input_bases(body, entry_value_ids, loop_depth),
            phis: phis
                .into_iter()
                .map(|phi| LoopPhi {
                    dest: transform_var_loop_input(phi.dest, entry_value_ids, loop_depth),
                    init: transform_var_loop_input(phi.init, entry_value_ids, loop_depth),
                    step: transform_var_loop_input(phi.step, entry_value_ids, loop_depth),
                })
                .collect(),
        },
        Stmt::Return { span, values } => Stmt::Return {
            span,
            values: values
                .into_iter()
                .map(|v| transform_var_loop_input(v, entry_value_ids, loop_depth))
                .collect(),
        },
        other => other,
    }
}

/// Rewrite a single variable to use a loop-input base when it refers to entry values.
fn transform_var_loop_input(
    var: Var,
    entry_value_ids: &HashSet<ValueId>,
    loop_depth: usize,
) -> Var {
    match var.base {
        VarBase::Value(id) if entry_value_ids.contains(&id) => {
            var.with_base(VarBase::LoopInput { loop_depth })
        },
        _ => var,
    }
}

/// Rewrite variables in an expression to use loop-input bases when needed.
fn transform_expr_loop_input(
    expr: Expr,
    entry_value_ids: &HashSet<ValueId>,
    loop_depth: usize,
) -> Expr {
    match expr {
        Expr::Var(v) => Expr::Var(transform_var_loop_input(v, entry_value_ids, loop_depth)),
        Expr::Binary(op, lhs, rhs) => Expr::Binary(
            op,
            Box::new(transform_expr_loop_input(*lhs, entry_value_ids, loop_depth)),
            Box::new(transform_expr_loop_input(*rhs, entry_value_ids, loop_depth)),
        ),
        Expr::Unary(op, inner) => Expr::Unary(
            op,
            Box::new(transform_expr_loop_input(*inner, entry_value_ids, loop_depth)),
        ),
        Expr::Ternary { cond, then_expr, else_expr } => Expr::Ternary {
            cond: Box::new(transform_expr_loop_input(*cond, entry_value_ids, loop_depth)),
            then_expr: Box::new(transform_expr_loop_input(*then_expr, entry_value_ids, loop_depth)),
            else_expr: Box::new(transform_expr_loop_input(*else_expr, entry_value_ids, loop_depth)),
        },
        Expr::EqW { lhs, rhs } => Expr::EqW {
            lhs: Box::new(
                (*lhs).map(|var| transform_var_loop_input(var, entry_value_ids, loop_depth)),
            ),
            rhs: Box::new(
                (*rhs).map(|var| transform_var_loop_input(var, entry_value_ids, loop_depth)),
            ),
        },
        other => other,
    }
}

/// Lift a while loop construct.
///
/// We only support stack-neutral while loops.
fn lift_while(
    op_span: SourceSpan,
    body: &Block,
    stack: &mut SymbolicStack,
    loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    // Pop initial condition.
    if stack.is_empty() {
        return Err(LiftingError::MissingControlFlowCondition {
            span: op_span,
            construct: "while.true",
            required_depth: 1,
            actual_depth: 0,
        });
    }
    let cond_var = stack.pop();
    let cond = Expr::Var(cond_var.clone());

    let entry_depth = stack.len();
    let entry_vars = stack.to_vec();

    // Create phi vars for the loop header and use them as the body stack.
    let mut phi_vars = Vec::with_capacity(entry_vars.len());
    for var in &entry_vars {
        phi_vars.push(stack.fresh_like(var));
    }

    let mut body_stack = stack.clone();
    body_stack.set_stack(phi_vars.clone());
    let body_stmts = lift_block(body, &mut body_stack, loop_ctx, resolver, sigs)?;

    // The body should end with pushing a condition value.
    if body_stack.is_empty() {
        return Err(LiftingError::NonNeutralWhile { span: op_span });
    }
    // Pop the continuation condition and model it as a loop-carried phi.
    let cond_step = body_stack.pop();

    // Verify that the loop body is stack-neutral.
    if body_stack.len() != entry_depth {
        return Err(LiftingError::NonNeutralWhile { span: op_span });
    }

    let step_vars = body_stack.to_vec();
    let cond_dest = stack.fresh_like(&cond_var);
    let mut phis = Vec::with_capacity(phi_vars.len() + 1);
    phis.push(LoopPhi {
        dest: cond_dest,
        init: cond_var,
        step: cond_step,
    });
    for ((dest, init), step) in phi_vars.iter().cloned().zip(entry_vars).zip(step_vars) {
        phis.push(LoopPhi { dest, init, step });
    }

    // Update outer stack to the phi destinations.
    stack.set_stack(phi_vars);

    Ok(vec![Stmt::While {
        span: op_span,
        cond,
        body: body_stmts,
        phis,
    }])
}
