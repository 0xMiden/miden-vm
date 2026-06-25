//! Instruction-level lifting from MASM to IR statements.

use miden_assembly_syntax::{
    ast::{ImmFelt, ImmU8, ImmU32, Immediate, Instruction, InvocationTarget},
    debuginfo::SourceSpan,
    parser::PushValue,
};

use super::{LiftingError, LiftingResult, LoopContext, resolved_immediate, stack::SymbolicStack};
use crate::{
    ir::{
        AdvLoad, BinOp, Call, Constant, Expr, Intrinsic, LocalAccessKind, LocalLoad, LocalStore,
        LocalStoreW, MemAccessKind, MemLoad, MemStore, Stmt, UnOp, Var,
    },
    semantics::{
        INTRINSIC_ADV_PIPE, INTRINSIC_ADV_PUSH, INTRINSIC_ADV_PUSHW, INTRINSIC_MEM_STREAM,
        INTRINSIC_MTREE_GET, INTRINSIC_MTREE_MERGE, INTRINSIC_MTREE_SET, INTRINSIC_MTREE_VERIFY,
        StackFamily, StackFamilyMovement, stack_family,
    },
    signature::{SignatureMap, StackEffect},
    symbol::{path::SymbolPath, resolution::SymbolResolver},
};

/// Lift a single instruction into one or more IR statements.
pub(super) fn lift_inst(
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
    _loop_ctx: &mut LoopContext,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<Vec<Stmt>> {
    // Try each instruction category in turn.
    if let Some(stmts) = lift_call_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_u32_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_arith_inst(inst, span, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_stack_inst(inst, span, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_mem_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_local_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_adv_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_intrinsic_inst(inst, span, resolver, sigs, stack)? {
        return Ok(stmts);
    }
    if let Some(stmts) = lift_push_inst(inst, span, stack)? {
        return Ok(stmts);
    }
    Err(LiftingError::UnsupportedInstruction { span, instruction: inst.clone() })
}

/// Lift call-like instructions (`exec`, `call`, `syscall`).
fn lift_call_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let stmts = match inst {
        Instruction::Exec(t) => {
            vec![lift_call_like(t, span, resolver, sigs, stack, |call| Stmt::Exec {
                span,
                call,
            })?]
        },
        Instruction::Call(t) => {
            vec![lift_call_like(t, span, resolver, sigs, stack, |call| Stmt::Call {
                span,
                call,
            })?]
        },
        Instruction::SysCall(t) => {
            vec![lift_call_like(t, span, resolver, sigs, stack, |call| Stmt::SysCall {
                span,
                call,
            })?]
        },
        Instruction::DynExec | Instruction::DynCall => {
            return Err(LiftingError::UnsupportedInstruction { span, instruction: inst.clone() });
        },
        _ => return Ok(None),
    };
    Ok(Some(stmts))
}

/// Lift arithmetic and comparison instructions.
fn lift_arith_inst(
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let stmt = match inst {
        Instruction::Add => lift_binop(inst, span, BinOp::Add, stack)?,
        Instruction::AddImm(imm) => lift_binop_imm(inst, span, BinOp::Add, imm, stack)?,
        Instruction::Sub => lift_binop(inst, span, BinOp::Sub, stack)?,
        Instruction::SubImm(imm) => lift_binop_imm(inst, span, BinOp::Sub, imm, stack)?,
        Instruction::Mul => lift_binop(inst, span, BinOp::Mul, stack)?,
        Instruction::MulImm(imm) => lift_binop_imm(inst, span, BinOp::Mul, imm, stack)?,
        Instruction::Div => lift_binop(inst, span, BinOp::Div, stack)?,
        Instruction::DivImm(imm) => lift_binop_imm(inst, span, BinOp::Div, imm, stack)?,
        Instruction::And => lift_binop(inst, span, BinOp::And, stack)?,
        Instruction::Or => lift_binop(inst, span, BinOp::Or, stack)?,
        Instruction::Xor => lift_binop(inst, span, BinOp::Xor, stack)?,
        Instruction::Eq => lift_binop(inst, span, BinOp::Eq, stack)?,
        Instruction::EqImm(imm) => lift_binop_imm(inst, span, BinOp::Eq, imm, stack)?,
        Instruction::Eqw => lift_eqw(span, inst.to_string(), stack)?,
        Instruction::Neq => lift_binop(inst, span, BinOp::Neq, stack)?,
        Instruction::NeqImm(imm) => lift_binop_imm(inst, span, BinOp::Neq, imm, stack)?,
        Instruction::Lt => lift_binop(inst, span, BinOp::Lt, stack)?,
        Instruction::Lte => lift_binop(inst, span, BinOp::Lte, stack)?,
        Instruction::Gt => lift_binop(inst, span, BinOp::Gt, stack)?,
        Instruction::Gte => lift_binop(inst, span, BinOp::Gte, stack)?,
        Instruction::Not => lift_unop(inst, span, UnOp::Not, stack)?,
        Instruction::Neg => lift_unop(inst, span, UnOp::Neg, stack)?,
        Instruction::Inv => lift_unop(inst, span, UnOp::Inv, stack)?,
        Instruction::Pow2 => lift_unop(inst, span, UnOp::Pow2, stack)?,
        Instruction::ExpBitLength(32) => lift_binop(inst, span, BinOp::U32Exp, stack)?,
        Instruction::Incr => lift_incr(inst, span, stack)?,
        _ => return Ok(None),
    };
    Ok(Some(vec![stmt]))
}

/// Lift u32 instructions.
fn lift_u32_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let stmt = match inst {
        Instruction::U32And => lift_binop(inst, span, BinOp::U32And, stack)?,
        Instruction::U32Or => lift_binop(inst, span, BinOp::U32Or, stack)?,
        Instruction::U32Xor => lift_binop(inst, span, BinOp::U32Xor, stack)?,
        Instruction::U32Shl => lift_binop(inst, span, BinOp::U32Shl, stack)?,
        Instruction::U32Shr => lift_binop(inst, span, BinOp::U32Shr, stack)?,
        Instruction::U32Rotr => lift_binop(inst, span, BinOp::U32Rotr, stack)?,
        Instruction::U32ShlImm(imm) => lift_binop_u8_imm(inst, span, BinOp::U32Shl, imm, stack)?,
        Instruction::U32ShrImm(imm) => lift_binop_u8_imm(inst, span, BinOp::U32Shr, imm, stack)?,
        Instruction::U32RotrImm(imm) => lift_binop_u8_imm(inst, span, BinOp::U32Rotr, imm, stack)?,
        Instruction::U32Rotl => {
            return lift_u32_intrinsic(inst, span, "u32rotl", resolver, sigs, stack);
        },
        Instruction::U32RotlImm(imm) => {
            return lift_u32_intrinsic_u8_imm(inst, span, "u32rotl", imm, resolver, sigs, stack);
        },
        Instruction::U32Lt => lift_binop(inst, span, BinOp::U32Lt, stack)?,
        Instruction::U32Lte => lift_binop(inst, span, BinOp::U32Lte, stack)?,
        Instruction::U32Gt => lift_binop(inst, span, BinOp::U32Gt, stack)?,
        Instruction::U32Gte => lift_binop(inst, span, BinOp::U32Gte, stack)?,
        Instruction::U32Min => {
            return lift_u32_intrinsic(inst, span, "u32min", resolver, sigs, stack);
        },
        Instruction::U32Max => {
            return lift_u32_intrinsic(inst, span, "u32max", resolver, sigs, stack);
        },
        Instruction::U32WrappingAdd => lift_binop(inst, span, BinOp::U32WrappingAdd, stack)?,
        Instruction::U32WrappingSub => lift_binop(inst, span, BinOp::U32WrappingSub, stack)?,
        Instruction::U32WrappingMul => lift_binop(inst, span, BinOp::U32WrappingMul, stack)?,
        Instruction::U32WrappingAddImm(imm) => {
            lift_binop_u32_imm(inst, span, BinOp::U32WrappingAdd, imm, stack)?
        },
        Instruction::U32WrappingSubImm(imm) => {
            lift_binop_u32_imm(inst, span, BinOp::U32WrappingSub, imm, stack)?
        },
        Instruction::U32WrappingMulImm(imm) => {
            lift_binop_u32_imm(inst, span, BinOp::U32WrappingMul, imm, stack)?
        },
        Instruction::U32Cast => lift_unop(inst, span, UnOp::U32Cast, stack)?,
        Instruction::U32Test => {
            return Ok(Some(vec![lift_non_consuming_unop(inst, span, UnOp::U32Test, stack)?]));
        },
        Instruction::U32TestW => {
            return Ok(Some(vec![lift_u32_testw(span, stack)?]));
        },
        Instruction::U32Not => lift_unop(inst, span, UnOp::U32Not, stack)?,
        Instruction::U32Clz => lift_unop(inst, span, UnOp::U32Clz, stack)?,
        Instruction::U32Ctz => lift_unop(inst, span, UnOp::U32Ctz, stack)?,
        Instruction::U32Clo => lift_unop(inst, span, UnOp::U32Clo, stack)?,
        Instruction::U32Cto => lift_unop(inst, span, UnOp::U32Cto, stack)?,
        Instruction::U32Popcnt => {
            return lift_u32_intrinsic(inst, span, "u32popcnt", resolver, sigs, stack);
        },
        Instruction::U32WideningAdd => {
            return lift_u32_intrinsic(inst, span, "u32widening_add", resolver, sigs, stack);
        },
        Instruction::U32WideningAddImm(imm) => {
            return lift_u32_intrinsic_imm(
                inst,
                span,
                "u32widening_add",
                imm,
                resolver,
                sigs,
                stack,
            );
        },
        Instruction::U32OverflowingAdd => {
            return lift_u32_intrinsic(inst, span, "u32overflowing_add", resolver, sigs, stack);
        },
        Instruction::U32OverflowingAddImm(imm) => {
            return lift_u32_intrinsic_imm(
                inst,
                span,
                "u32overflowing_add",
                imm,
                resolver,
                sigs,
                stack,
            );
        },
        Instruction::U32OverflowingAdd3 => {
            return lift_u32_intrinsic(inst, span, "u32overflowing_add3", resolver, sigs, stack);
        },
        Instruction::U32WideningAdd3 => {
            return lift_u32_intrinsic(inst, span, "u32widening_add3", resolver, sigs, stack);
        },
        Instruction::U32WrappingAdd3 => {
            return lift_u32_intrinsic(inst, span, "u32wrapping_add3", resolver, sigs, stack);
        },
        Instruction::U32OverflowingSub => {
            return lift_u32_intrinsic(inst, span, "u32overflowing_sub", resolver, sigs, stack);
        },
        Instruction::U32OverflowingSubImm(imm) => {
            return lift_u32_intrinsic_imm(
                inst,
                span,
                "u32overflowing_sub",
                imm,
                resolver,
                sigs,
                stack,
            );
        },
        Instruction::U32WideningMul => {
            return lift_u32_intrinsic(inst, span, "u32widening_mul", resolver, sigs, stack);
        },
        Instruction::U32WideningMulImm(imm) => {
            return lift_u32_intrinsic_imm(
                inst,
                span,
                "u32widening_mul",
                imm,
                resolver,
                sigs,
                stack,
            );
        },
        Instruction::U32WideningMadd => {
            return lift_u32_intrinsic(inst, span, "u32widening_madd", resolver, sigs, stack);
        },
        Instruction::U32WrappingMadd => {
            return lift_u32_intrinsic(inst, span, "u32wrapping_madd", resolver, sigs, stack);
        },
        Instruction::U32DivMod => {
            return lift_u32_intrinsic(inst, span, "u32divmod", resolver, sigs, stack);
        },
        Instruction::U32DivModImm(imm) => {
            return lift_u32_intrinsic_imm(inst, span, "u32divmod", imm, resolver, sigs, stack);
        },
        Instruction::U32Div => {
            return lift_u32_intrinsic(inst, span, "u32div", resolver, sigs, stack);
        },
        Instruction::U32DivImm(imm) => {
            return lift_u32_intrinsic_imm(inst, span, "u32div", imm, resolver, sigs, stack);
        },
        Instruction::U32Mod => {
            return lift_u32_intrinsic(inst, span, "u32mod", resolver, sigs, stack);
        },
        Instruction::U32ModImm(imm) => {
            return lift_u32_intrinsic_imm(inst, span, "u32mod", imm, resolver, sigs, stack);
        },
        Instruction::U32Split => {
            return Ok(Some(vec![lift_u32split(span, inst.to_string(), stack)?]));
        },
        Instruction::U32Assert => {
            return Ok(Some(vec![lift_u32_assert(span, "u32assert", stack)?]));
        },
        Instruction::U32AssertWithError(err) => {
            return Ok(Some(vec![lift_u32_assert(span, &format!("u32assert.{err}"), stack)?]));
        },
        Instruction::U32Assert2 => {
            return Ok(Some(vec![lift_u32_assert2(span, "u32assert2", stack)?]));
        },
        Instruction::U32Assert2WithError(err) => {
            return Ok(Some(vec![lift_u32_assert2(span, &format!("u32assert2.{err}"), stack)?]));
        },
        Instruction::U32AssertW => {
            return Ok(Some(vec![lift_u32_assertw(span, "u32assertw", stack)?]));
        },
        Instruction::U32AssertWWithError(err) => {
            return Ok(Some(vec![lift_u32_assertw(span, &format!("u32assertw.{err}"), stack)?]));
        },
        _ => return Ok(None),
    };
    Ok(Some(vec![stmt]))
}

/// Lift stack manipulation instructions.
fn lift_stack_inst(
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    if let Some(family) = stack_family(inst) {
        return lift_stack_family_inst(family, inst, span, stack).map(Some);
    }

    match inst {
        Instruction::Drop => {
            stack.require_depth(1, span, inst.to_string())?;
            stack.pop();
            Ok(Some(Vec::new()))
        },
        Instruction::DropW => {
            stack.require_depth(4, span, inst.to_string())?;
            for _ in 0..4 {
                stack.pop();
            }
            Ok(Some(Vec::new()))
        },
        Instruction::PadW => Ok(Some(lift_padw(span, stack))),
        Instruction::CDrop => Ok(Some(vec![lift_cdrop(span, inst.to_string(), stack)?])),
        Instruction::CDropW => Ok(Some(lift_cdropw(span, inst.to_string(), stack)?)),
        Instruction::CSwap => Ok(Some(lift_cswap(span, inst.to_string(), stack)?)),
        Instruction::CSwapW => Ok(Some(lift_cswapw(span, inst.to_string(), stack)?)),
        Instruction::Reversew => {
            stack.reversew(span, inst.to_string())?;
            Ok(Some(Vec::new()))
        },
        Instruction::Nop => Ok(Some(Vec::new())),
        _ => Ok(None),
    }
}

fn lift_stack_family_inst(
    family: StackFamily,
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
) -> LiftingResult<Vec<Stmt>> {
    match family.movement() {
        StackFamilyMovement::Dup { index, width: 1 } => lift_dup(span, index, stack),
        StackFamilyMovement::Dup { index, width: 4 } => lift_dupw(span, index, stack),
        StackFamilyMovement::Swap { index, width: 1 } => {
            stack.swap(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::Swap { index, width: 4 } => {
            stack.swapw(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::SwapDoubleWord => {
            stack.swapdw(span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::MovUp { index, width: 1 } => {
            stack.movup(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::MovUp { index, width: 4 } => {
            stack.movupw(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::MovDown { index, width: 1 } => {
            stack.movdn(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::MovDown { index, width: 4 } => {
            stack.movdnw(index, span, inst.to_string())?;
            Ok(Vec::new())
        },
        StackFamilyMovement::Dup { width, .. }
        | StackFamilyMovement::Swap { width, .. }
        | StackFamilyMovement::MovUp { width, .. }
        | StackFamilyMovement::MovDown { width, .. } => {
            unreachable!("unsupported stack movement width {width}")
        },
    }
}

fn lift_u32_intrinsic(
    inst: &Instruction,
    span: SourceSpan,
    name: &str,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let effect = effect_for_inst(inst, span, resolver, sigs)?;
    let (args, results) = stack.apply_checked(
        effect.pops(),
        effect.pushes(),
        effect.required_depth(),
        span,
        inst.to_string(),
    )?;
    Ok(Some(vec![Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic { name: name.to_string(), args, results },
    }]))
}

/// Lift a u32 intrinsic instruction with a u32 immediate suffix.
fn lift_u32_intrinsic_imm(
    inst: &Instruction,
    span: SourceSpan,
    name: &str,
    imm: &ImmU32,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let effect = effect_for_inst(inst, span, resolver, sigs)?;
    let (args, results) = stack.apply_checked(
        effect.pops(),
        effect.pushes(),
        effect.required_depth(),
        span,
        inst.to_string(),
    )?;
    Ok(Some(vec![Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: format!("{name}.{imm}"),
            args,
            results,
        },
    }]))
}

/// Lift a u32 intrinsic instruction with a u8 immediate suffix.
fn lift_u32_intrinsic_u8_imm(
    inst: &Instruction,
    span: SourceSpan,
    name: &str,
    imm: &ImmU8,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let effect = effect_for_inst(inst, span, resolver, sigs)?;
    let (args, results) = stack.apply_checked(
        effect.pops(),
        effect.pushes(),
        effect.required_depth(),
        span,
        inst.to_string(),
    )?;
    Ok(Some(vec![Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: format!("{name}.{imm}"),
            args,
            results,
        },
    }]))
}

/// Lift `u32assert` and `u32assert.err=*` as no-stack-change intrinsics.
fn lift_u32_assert(span: SourceSpan, name: &str, stack: &mut SymbolicStack) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, name)?;
    let a = stack.peek(0).cloned().expect("u32assert stack");
    Ok(Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: name.to_string(),
            args: vec![a],
            results: Vec::new(),
        },
    })
}

/// Lift `u32assert2` and `u32assert2.err=*` as no-stack-change intrinsics.
fn lift_u32_assert2(
    span: SourceSpan,
    name: &str,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(2, span, name)?;
    let b = stack.peek(0).cloned().expect("u32assert2 stack");
    let a = stack.peek(1).cloned().expect("u32assert2 stack");
    Ok(Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: name.to_string(),
            args: vec![b, a],
            results: Vec::new(),
        },
    })
}

/// Lift `u32assertw` and `u32assertw.err=*` as no-stack-change intrinsics.
fn lift_u32_assertw(
    span: SourceSpan,
    name: &str,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    let args = stack.top_n_checked(4, span, name)?;
    Ok(Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: name.to_string(),
            args,
            results: Vec::new(),
        },
    })
}

/// Lift `u32testw` as a non-consuming word test with one Bool result.
fn lift_u32_testw(span: SourceSpan, stack: &mut SymbolicStack) -> LiftingResult<Stmt> {
    let args = stack.top_n_checked(4, span, "u32testw")?;
    let dest = stack.push_fresh();
    Ok(Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: "u32testw".to_string(),
            args,
            results: vec![dest],
        },
    })
}

/// Lift memory load/store instructions.
fn lift_mem_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    match inst {
        Instruction::MemLoad => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::MemLoad {
                span,
                load: MemLoad {
                    kind: MemAccessKind::Element,
                    address: popped,
                    outputs: pushed,
                },
            }]))
        },
        Instruction::MemLoadImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemLoad {
                    span,
                    load: MemLoad {
                        kind: MemAccessKind::Element,
                        address: vec![addr_var],
                        outputs: pushed,
                    },
                },
            ]))
        },
        Instruction::MemLoadWBe => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let address = popped[0].clone();
            Ok(Some(vec![Stmt::MemLoad {
                span,
                load: MemLoad {
                    kind: MemAccessKind::WordBe,
                    address: vec![address],
                    outputs: pushed,
                },
            }]))
        },
        Instruction::MemLoadWBeImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemLoad {
                    span,
                    load: MemLoad {
                        kind: MemAccessKind::WordBe,
                        address: vec![addr_var],
                        outputs: pushed,
                    },
                },
            ]))
        },
        Instruction::MemLoadWLe => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let address = popped[0].clone();
            Ok(Some(vec![Stmt::MemLoad {
                span,
                load: MemLoad {
                    kind: MemAccessKind::WordLe,
                    address: vec![address],
                    outputs: pushed,
                },
            }]))
        },
        Instruction::MemLoadWLeImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemLoad {
                    span,
                    load: MemLoad {
                        kind: MemAccessKind::WordLe,
                        address: vec![addr_var],
                        outputs: pushed,
                    },
                },
            ]))
        },
        Instruction::MemStore => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (mut popped, _) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let address = popped.remove(0);
            Ok(Some(vec![Stmt::MemStore {
                span,
                store: MemStore {
                    kind: MemAccessKind::Element,
                    address: vec![address],
                    values: popped,
                },
            }]))
        },
        Instruction::MemStoreImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, _) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemStore {
                    span,
                    store: MemStore {
                        kind: MemAccessKind::Element,
                        address: vec![addr_var],
                        values: popped,
                    },
                },
            ]))
        },
        Instruction::MemStoreWBe => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, _) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let address = popped[0].clone();
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            Ok(Some(vec![Stmt::MemStore {
                span,
                store: MemStore {
                    kind: MemAccessKind::WordBe,
                    address: vec![address],
                    values,
                },
            }]))
        },
        Instruction::MemStoreWBeImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (..) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemStore {
                    span,
                    store: MemStore {
                        kind: MemAccessKind::WordBe,
                        address: vec![addr_var],
                        values,
                    },
                },
            ]))
        },
        Instruction::MemStoreWLe => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, _) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let address = popped[0].clone();
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            Ok(Some(vec![Stmt::MemStore {
                span,
                store: MemStore {
                    kind: MemAccessKind::WordLe,
                    address: vec![address],
                    values,
                },
            }]))
        },
        Instruction::MemStoreWLeImm(imm) => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (..) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            let (addr_var, assign) = assign_from_u32_immediate(span, imm, stack);
            Ok(Some(vec![
                assign,
                Stmt::MemStore {
                    span,
                    store: MemStore {
                        kind: MemAccessKind::WordLe,
                        address: vec![addr_var],
                        values,
                    },
                },
            ]))
        },
        _ => Ok(None),
    }
}

/// Lift local-variable load/store instructions.
fn lift_local_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    match inst {
        Instruction::LocLoad(idx) => {
            let index = resolved_immediate(idx, span)?;
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::LocalLoad {
                span,
                load: LocalLoad {
                    kind: LocalAccessKind::Element,
                    index,
                    outputs: pushed,
                },
            }]))
        },
        Instruction::LocLoadWBe(idx) => {
            let index = resolved_immediate(idx, span)?;
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::LocalLoad {
                span,
                load: LocalLoad {
                    kind: LocalAccessKind::WordBe,
                    index,
                    outputs: pushed,
                },
            }]))
        },
        Instruction::LocLoadWLe(idx) => {
            let index = resolved_immediate(idx, span)?;
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::LocalLoad {
                span,
                load: LocalLoad {
                    kind: LocalAccessKind::WordLe,
                    index,
                    outputs: pushed,
                },
            }]))
        },
        Instruction::LocStore(idx) => {
            let index = resolved_immediate(idx, span)?;
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (popped, _) = stack.apply_checked(
                effect.pops(),
                0,
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::LocalStore {
                span,
                store: LocalStore { index, values: popped },
            }]))
        },
        Instruction::LocStoreWBe(idx) => {
            let index = resolved_immediate(idx, span)?;
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            Ok(Some(vec![Stmt::LocalStoreW {
                span,
                store: LocalStoreW {
                    kind: LocalAccessKind::WordBe,
                    index,
                    values,
                },
            }]))
        },
        Instruction::LocStoreWLe(idx) => {
            let index = resolved_immediate(idx, span)?;
            let values = stack.top_n_checked(4, span, inst.to_string())?;
            Ok(Some(vec![Stmt::LocalStoreW {
                span,
                store: LocalStoreW {
                    kind: LocalAccessKind::WordLe,
                    index,
                    values,
                },
            }]))
        },
        _ => Ok(None),
    }
}

/// Lift advice provider instructions.
fn lift_adv_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    match inst {
        Instruction::AdvLoadW => {
            let effect = effect_for_inst(inst, span, resolver, sigs)?;
            let (_, pushed) = stack.apply_checked(
                effect.pops(),
                effect.pushes(),
                effect.required_depth(),
                span,
                inst.to_string(),
            )?;
            Ok(Some(vec![Stmt::AdvLoad { span, load: AdvLoad { outputs: pushed } }]))
        },
        Instruction::AdvPush => {
            let (_, pushed) = stack.apply_checked(0, 1, 0, span, inst.to_string())?;
            Ok(Some(vec![Stmt::Intrinsic {
                span,
                intrinsic: Intrinsic {
                    name: INTRINSIC_ADV_PUSH.to_string(),
                    args: Vec::new(),
                    results: pushed,
                },
            }]))
        },
        Instruction::AdvPushW => {
            let (_, pushed) = stack.apply_checked(0, 4, 0, span, inst.to_string())?;
            Ok(Some(vec![Stmt::Intrinsic {
                span,
                intrinsic: Intrinsic {
                    name: INTRINSIC_ADV_PUSHW.to_string(),
                    args: Vec::new(),
                    results: pushed,
                },
            }]))
        },
        _ => Ok(None),
    }
}

/// Lift intrinsic-style instructions.
fn lift_intrinsic_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    let name = match inst {
        Instruction::Assert => "assert".to_string(),
        Instruction::AssertWithError(err) => format!("assert.{err}"),
        Instruction::AssertEq => "assert_eq".to_string(),
        Instruction::AssertEqWithError(err) => format!("assert_eq.{err}"),
        Instruction::AssertEqw => "assert_eqw".to_string(),
        Instruction::AssertEqwWithError(err) => format!("assert_eqw.{err}"),
        Instruction::Assertz => "assertz".to_string(),
        Instruction::AssertzWithError(err) => format!("assertz.{err}"),
        Instruction::IsOdd => "is_odd".to_string(),
        Instruction::Ext2Add => "ext2add".to_string(),
        Instruction::Ext2Sub => "ext2sub".to_string(),
        Instruction::Ext2Mul => "ext2mul".to_string(),
        Instruction::Ext2Div => "ext2div".to_string(),
        Instruction::Ext2Neg => "ext2neg".to_string(),
        Instruction::Ext2Inv => "ext2inv".to_string(),
        Instruction::MemStream => INTRINSIC_MEM_STREAM.to_string(),
        Instruction::AdvPipe => INTRINSIC_ADV_PIPE.to_string(),
        Instruction::Hash => "hash".to_string(),
        Instruction::HMerge => "hmerge".to_string(),
        Instruction::HPerm => "hperm".to_string(),
        Instruction::MTreeGet => INTRINSIC_MTREE_GET.to_string(),
        Instruction::MTreeSet => INTRINSIC_MTREE_SET.to_string(),
        Instruction::MTreeMerge => INTRINSIC_MTREE_MERGE.to_string(),
        Instruction::MTreeVerify => INTRINSIC_MTREE_VERIFY.to_string(),
        Instruction::MTreeVerifyWithError(err) => format!("{INTRINSIC_MTREE_VERIFY}.{err}"),
        Instruction::EvalCircuit => "eval_circuit".to_string(),
        Instruction::HornerBase => "horner_eval_base".to_string(),
        Instruction::HornerExt => "horner_eval_ext".to_string(),
        Instruction::Emit => "emit".to_string(),
        Instruction::EmitImm(imm) => format!("emit.{imm}"),
        Instruction::Sdepth => "sdepth".to_string(),
        _ => return Ok(None),
    };
    let effect = effect_for_inst(inst, span, resolver, sigs)?;
    // Use required_depth for intrinsic args so that passthrough inputs
    // (read but not consumed) are visible in the decompiled output.
    let args = stack.top_n_checked(effect.required_depth(), span, name.as_str())?;
    let (_, results) = stack.apply_checked(
        effect.pops(),
        effect.pushes(),
        effect.required_depth(),
        span,
        name.clone(),
    )?;
    Ok(Some(vec![Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic { name, args, results },
    }]))
}

/// Lift push immediates into assignments.
fn lift_push_inst(
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
) -> LiftingResult<Option<Vec<Stmt>>> {
    match inst {
        Instruction::Push(imm) => match imm {
            Immediate::Value(spanned) => match spanned.inner() {
                PushValue::Word(word) => {
                    let mut stmts = Vec::with_capacity(4);
                    // Push elements in reverse so that word[0] ends up on top,
                    // matching the Miden VM semantics for `push.[a, b, c, d]`.
                    for i in (0..4).rev() {
                        let dest = stack.push_fresh();
                        let expr = Expr::Constant(Constant::Felt(word.0[i].as_canonical_u64()));
                        stmts.push(Stmt::Assign { span, dest, expr });
                    }
                    Ok(Some(stmts))
                },
                PushValue::Int(_) => {
                    let dest = stack.push_fresh();
                    let expr: Expr = imm.into();
                    Ok(Some(vec![Stmt::Assign { span, dest, expr }]))
                },
            },
            Immediate::Constant(_) => {
                let dest = stack.push_fresh();
                let expr: Expr = imm.into();
                Ok(Some(vec![Stmt::Assign { span, dest, expr }]))
            },
        },
        Instruction::PushSlice(imm, range) => match imm {
            Immediate::Value(spanned) => {
                Ok(Some(lift_push_word_slice(span, &spanned.inner().0, range.clone(), stack)))
            },
            Immediate::Constant(id) => Err(LiftingError::UnsupportedInstruction {
                span,
                instruction: Instruction::PushSlice(Immediate::Constant(id.clone()), range.clone()),
            }),
        },
        Instruction::PushFeltList(values) => {
            let mut stmts = Vec::with_capacity(values.len());
            // Push in reverse so that values[0] ends up on top, matching
            // the convention used for `push.[a, b, c, d]`.
            for felt in values.iter().rev() {
                let dest = stack.push_fresh();
                let expr = Expr::Constant(Constant::Felt(felt.as_canonical_u64()));
                stmts.push(Stmt::Assign { span, dest, expr });
            }
            Ok(Some(stmts))
        },
        Instruction::Locaddr(index) => {
            let index = resolved_immediate(index, span)?;
            let (_, pushed) = stack.apply_checked(0, 1, 0, span, "locaddr")?;
            Ok(Some(vec![Stmt::Intrinsic {
                span,
                intrinsic: Intrinsic {
                    name: format!("locaddr.{index}"),
                    args: Vec::new(),
                    results: pushed,
                },
            }]))
        },
        _ => Ok(None),
    }
}

/// Push a sub-range of a word's felt elements onto the symbolic stack.
///
/// Elements are pushed in reverse order so that `word[range.start]` ends up
/// on top, matching the Miden VM convention for `push.[a, b, c, d]`.
fn lift_push_word_slice(
    span: SourceSpan,
    word: &[miden_assembly_syntax::Felt; 4],
    range: std::ops::Range<usize>,
    stack: &mut SymbolicStack,
) -> Vec<Stmt> {
    let mut stmts = Vec::with_capacity(range.len());
    for i in range.rev() {
        let dest = stack.push_fresh();
        let expr = Expr::Constant(Constant::Felt(word[i].as_canonical_u64()));
        stmts.push(Stmt::Assign { span, dest, expr });
    }
    stmts
}

// Helper functions

/// Compute the stack effect for an instruction, resolving call signatures when needed.
pub(super) fn effect_for_inst(
    inst: &Instruction,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<StackEffect> {
    match inst {
        Instruction::Exec(t) | Instruction::Call(t) | Instruction::SysCall(t) => {
            call_effect(t, span, resolver, sigs)
        },
        _ => {
            let effect = StackEffect::from(inst);
            match effect {
                StackEffect::Known { .. } => Ok(effect),
                StackEffect::Unknown => {
                    Err(LiftingError::UnsupportedInstruction { span, instruction: inst.clone() })
                },
            }
        },
    }
}

fn lift_call_like<F>(
    target: &InvocationTarget,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
    stack: &mut SymbolicStack,
    ctor: F,
) -> LiftingResult<Stmt>
where
    F: Fn(Call) -> Stmt,
{
    let (name, effect) = resolve_call_target_and_effect(target, span, resolver, sigs)?;
    // Use required_depth for call args so that passthrough inputs
    // (read but not consumed) are visible in the decompiled output.
    let args = stack.top_n_checked(effect.required_depth(), span, target.to_string())?;
    let (_, results) = stack.apply_checked(
        effect.pops(),
        effect.pushes(),
        effect.required_depth(),
        span,
        target.to_string(),
    )?;
    Ok(ctor(Call { target: name.to_string(), args, results }))
}

fn lift_binop(
    inst: &Instruction,
    span: SourceSpan,
    op: BinOp,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(2, span, inst.to_string())?;
    let b = stack.pop_entry();
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Binary(op, Box::new(Expr::Var(a.var)), Box::new(Expr::Var(b.var))),
    })
}

fn lift_binop_imm(
    inst: &Instruction,
    span: SourceSpan,
    op: BinOp,
    imm: &ImmFelt,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    let rhs: Expr = imm.into();
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Binary(op, Box::new(Expr::Var(a.var)), Box::new(rhs)),
    })
}

fn lift_unop(
    inst: &Instruction,
    span: SourceSpan,
    op: UnOp,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Unary(op, Box::new(Expr::Var(a.var))),
    })
}

fn lift_non_consuming_unop(
    inst: &Instruction,
    span: SourceSpan,
    op: UnOp,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.peek(0).cloned().expect("non-consuming unary stack");
    let dest = stack.push_fresh();
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Unary(op, Box::new(Expr::Var(a))),
    })
}

fn lift_incr(
    inst: &Instruction,
    span: SourceSpan,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Binary(
            BinOp::Add,
            Box::new(Expr::Var(a.var)),
            Box::new(Expr::Constant(Constant::Felt(1))),
        ),
    })
}

fn lift_binop_u32_imm(
    inst: &Instruction,
    span: SourceSpan,
    op: BinOp,
    imm: &ImmU32,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    let rhs: Expr = imm.into();
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Binary(op, Box::new(Expr::Var(a.var)), Box::new(rhs)),
    })
}

fn lift_binop_u8_imm(
    inst: &Instruction,
    span: SourceSpan,
    op: BinOp,
    imm: &ImmU8,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, inst.to_string())?;
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    let rhs: Expr = imm.into();
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Binary(op, Box::new(Expr::Var(a.var)), Box::new(rhs)),
    })
}

/// Lift the `cdrop` instruction into a ternary expression assignment.
/// Lift the `cdrop` instruction into a ternary expression assignment.
fn lift_cdrop(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(3, span, operation)?;
    let cond = stack.pop_entry();
    let b = stack.pop_entry();
    let a = stack.pop_entry();
    let dest = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::Ternary {
            cond: Box::new(Expr::Var(cond.var)),
            then_expr: Box::new(Expr::Var(b.var)),
            else_expr: Box::new(Expr::Var(a.var)),
        },
    })
}

/// Lift the `eqw` instruction into a word-equality assignment.
fn lift_eqw(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(8, span, operation)?;
    let lhs = [
        stack.peek(0).cloned().expect("eqw stack"),
        stack.peek(1).cloned().expect("eqw stack"),
        stack.peek(2).cloned().expect("eqw stack"),
        stack.peek(3).cloned().expect("eqw stack"),
    ];
    let rhs = [
        stack.peek(4).cloned().expect("eqw stack"),
        stack.peek(5).cloned().expect("eqw stack"),
        stack.peek(6).cloned().expect("eqw stack"),
        stack.peek(7).cloned().expect("eqw stack"),
    ];
    let dest = stack.push_fresh();
    Ok(Stmt::Assign {
        span,
        dest,
        expr: Expr::EqW { lhs: Box::new(lhs), rhs: Box::new(rhs) },
    })
}

/// Lift the `cswap` instruction into two ternary expression assignments.
fn lift_cswap(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Vec<Stmt>> {
    stack.require_depth(3, span, operation)?;
    let cond = stack.pop_entry();
    let b = stack.pop_entry();
    let a = stack.pop_entry();

    let d = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    let e = stack.push_fresh_with_slot_like(b.slot_id, &b.var);

    let first = Stmt::Assign {
        span,
        dest: d,
        expr: Expr::Ternary {
            cond: Box::new(Expr::Var(cond.var.clone())),
            then_expr: Box::new(Expr::Var(b.var.clone())),
            else_expr: Box::new(Expr::Var(a.var.clone())),
        },
    };
    let second = Stmt::Assign {
        span,
        dest: e,
        expr: Expr::Ternary {
            cond: Box::new(Expr::Var(cond.var)),
            then_expr: Box::new(Expr::Var(a.var)),
            else_expr: Box::new(Expr::Var(b.var)),
        },
    };
    Ok(vec![first, second])
}

/// Lift the `cdropw` instruction into four ternary expression assignments.
///
/// Stack: `[A3, A2, A1, A0, B3, B2, B1, B0, C, ...]` (C on top).
/// If `C = 1`: result is word B; if `C = 0`: result is word A.
fn lift_cdropw(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Vec<Stmt>> {
    stack.require_depth(9, span, operation)?;
    let cond = stack.pop_entry();

    let mut b = Vec::with_capacity(4);
    for _ in 0..4 {
        b.push(stack.pop_entry());
    }

    let mut a = Vec::with_capacity(4);
    for _ in 0..4 {
        a.push(stack.pop_entry());
    }

    let mut stmts = Vec::with_capacity(4);
    for i in 0..4 {
        let dest = stack.push_fresh_with_slot_like(a[i].slot_id, &a[i].var);
        stmts.push(Stmt::Assign {
            span,
            dest,
            expr: Expr::Ternary {
                cond: Box::new(Expr::Var(cond.var.clone())),
                then_expr: Box::new(Expr::Var(b[i].var.clone())),
                else_expr: Box::new(Expr::Var(a[i].var.clone())),
            },
        });
    }
    Ok(stmts)
}

/// Lift the `cswapw` instruction into eight ternary expression assignments.
///
/// Stack: `[A3, A2, A1, A0, B3, B2, B1, B0, C, ...]` (C on top).
/// If `C != 0`: words are swapped (result is `[B, A]`);
/// if `C = 0`: words are unchanged (result is `[A, B]`).
fn lift_cswapw(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Vec<Stmt>> {
    stack.require_depth(9, span, operation)?;
    let cond = stack.pop_entry();

    let mut b = Vec::with_capacity(4);
    for _ in 0..4 {
        b.push(stack.pop_entry());
    }

    let mut a = Vec::with_capacity(4);
    for _ in 0..4 {
        a.push(stack.pop_entry());
    }

    let mut stmts = Vec::with_capacity(8);
    // First word: when swapped this is B, when not swapped this is A.
    for i in 0..4 {
        let dest = stack.push_fresh_with_slot_like(a[i].slot_id, &a[i].var);
        stmts.push(Stmt::Assign {
            span,
            dest,
            expr: Expr::Ternary {
                cond: Box::new(Expr::Var(cond.var.clone())),
                then_expr: Box::new(Expr::Var(b[i].var.clone())),
                else_expr: Box::new(Expr::Var(a[i].var.clone())),
            },
        });
    }
    // Second word: when swapped this is A, when not swapped this is B.
    for i in 0..4 {
        let dest = stack.push_fresh_with_slot_like(b[i].slot_id, &b[i].var);
        stmts.push(Stmt::Assign {
            span,
            dest,
            expr: Expr::Ternary {
                cond: Box::new(Expr::Var(cond.var.clone())),
                then_expr: Box::new(Expr::Var(a[i].var.clone())),
                else_expr: Box::new(Expr::Var(b[i].var.clone())),
            },
        });
    }
    Ok(stmts)
}

/// Lift the `u32split` instruction into an intrinsic assignment.
fn lift_u32split(
    span: SourceSpan,
    operation: impl Into<String>,
    stack: &mut SymbolicStack,
) -> LiftingResult<Stmt> {
    stack.require_depth(1, span, operation)?;
    let a = stack.pop_entry();
    let lo = stack.push_fresh_with_slot_like(a.slot_id, &a.var);
    let hi = stack.push_fresh();
    Ok(Stmt::Intrinsic {
        span,
        intrinsic: Intrinsic {
            name: "u32split".to_string(),
            args: vec![a.var],
            results: vec![lo, hi],
        },
    })
}

fn lift_padw(span: SourceSpan, stack: &mut SymbolicStack) -> Vec<Stmt> {
    let mut stmts = Vec::with_capacity(4);
    for _ in 0..4 {
        let dest = stack.push_fresh();
        stmts.push(Stmt::Assign {
            span,
            dest,
            expr: Expr::Constant(Constant::Felt(0)),
        });
    }
    stmts
}

fn lift_dup(span: SourceSpan, idx: usize, stack: &mut SymbolicStack) -> LiftingResult<Vec<Stmt>> {
    let required_depth = idx + 1;
    stack.require_depth(required_depth, span, format!("dup.{idx}"))?;
    let src = stack.peek(idx).cloned().unwrap();
    let dest = stack.push_fresh();
    Ok(vec![Stmt::Assign { span, dest, expr: Expr::Var(src) }])
}

fn lift_dupw(span: SourceSpan, idx: usize, stack: &mut SymbolicStack) -> LiftingResult<Vec<Stmt>> {
    let required_depth = (idx + 1) * 4;
    stack.require_depth(required_depth, span, format!("dupw.{idx}"))?;
    let offset = idx * 4;
    let mut stmts = Vec::with_capacity(4);
    // Peek the word (4 elements starting at offset from top).
    let mut word = Vec::with_capacity(4);
    for i in 0..4 {
        if let Some(v) = stack.peek(offset + 3 - i) {
            word.push(v.clone());
        }
    }
    for src in word {
        let dest = stack.push_fresh();
        stmts.push(Stmt::Assign { span, dest, expr: Expr::Var(src) });
    }
    Ok(stmts)
}

fn assign_from_u32_immediate(
    span: SourceSpan,
    imm: &ImmU32,
    stack: &mut SymbolicStack,
) -> (Var, Stmt) {
    let depth = stack.len();
    let dest = stack.fresh_var(depth);
    // Note: we don't push this to the stack - it's just a temporary for the address.
    let expr: Expr = imm.into();
    (dest.clone(), Stmt::Assign { span, dest, expr })
}

fn call_effect(
    target: &InvocationTarget,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<StackEffect> {
    let (_, effect) = resolve_call_target_and_effect(target, span, resolver, sigs)?;
    Ok(effect)
}

/// Resolve a call target and compute its stack effect from the inferred signature map.
fn resolve_call_target_and_effect(
    target: &InvocationTarget,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
    sigs: &SignatureMap,
) -> LiftingResult<(SymbolPath, StackEffect)> {
    let callee = resolve_call_target(target, span, resolver)?;
    let signature = sigs
        .get(&callee)
        .ok_or_else(|| LiftingError::MissingSignature { span, callee: callee.clone() })?;
    let effect: StackEffect = signature.into();
    match effect {
        StackEffect::Known { .. } => Ok((callee, effect)),
        StackEffect::Unknown => Err(LiftingError::UnknownSignature { span, callee }),
    }
}

/// Resolve a call target to a concrete procedure path.
fn resolve_call_target(
    target: &InvocationTarget,
    span: SourceSpan,
    resolver: &SymbolResolver<'_>,
) -> LiftingResult<SymbolPath> {
    match resolver.resolve_target(target) {
        Ok(Some(callee)) => Ok(callee),
        Ok(None) => Err(LiftingError::UnresolvedCallTarget {
            span,
            target: format!("{target}"),
            reason: None,
        }),
        Err(err) => Err(LiftingError::UnresolvedCallTarget {
            span,
            target: format!("{target}"),
            reason: Some(err.to_string()),
        }),
    }
}

// Extension trait for StackEffect to get individual fields.
trait StackEffectExt {
    fn pops(&self) -> usize;
    fn pushes(&self) -> usize;
    fn required_depth(&self) -> usize;
}

impl StackEffectExt for StackEffect {
    fn pops(&self) -> usize {
        match self {
            StackEffect::Known { pops, .. } => *pops,
            StackEffect::Unknown => 0,
        }
    }

    fn pushes(&self) -> usize {
        match self {
            StackEffect::Known { pushes, .. } => *pushes,
            StackEffect::Unknown => 0,
        }
    }

    fn required_depth(&self) -> usize {
        match self {
            StackEffect::Known { required_depth, .. } => *required_depth,
            StackEffect::Unknown => 0,
        }
    }
}
