use alloc::vec::Vec;

use miden_assembly_syntax::{
    ast::{ImmU16, Instruction},
    debuginfo::{Span, Spanned},
    diagnostics::{RelatedLabel, Report},
    parser::{IntValue, PushValue},
};
use miden_core::{Decorator, Felt, Operation, WORD_SIZE, ZERO, mast::MastNodeId};

use crate::{
    Assembler, ProcedureContext, ast::InvokeKind, basic_block_builder::BasicBlockBuilder,
    push_value_ops,
};

mod adv_ops;
mod crypto_ops;
mod debug;
mod env_ops;
mod ext2_ops;
mod field_ops;
mod mem_ops;
mod procedures;
mod u32_ops;

use self::u32_ops::U32OpMode::*;

/// Instruction Compilation
impl Assembler {
    pub(super) fn compile_instruction(
        &self,
        instruction: &Span<Instruction>,
        block_builder: &mut BasicBlockBuilder,
        proc_ctx: &mut ProcedureContext,
    ) -> Result<Option<MastNodeId>, Report> {
        // Determine whether this instruction can create a new node
        let can_create_node = matches!(
            instruction.inner(),
            Instruction::Call(_)
                | Instruction::SysCall(_)
                | Instruction::DynExec
                | Instruction::DynCall
        );

        // Always collect decorators into a single Vec; it will remain empty if not needed.
        let mut decorators = Vec::new();

        if self.in_debug_mode() {
            // if the assembler is in debug mode, start tracking the instruction about to be
            // executed; this will allow us to map the instruction to the sequence of
            // operations which were executed as a part of this instruction.
            block_builder.track_instruction(instruction, proc_ctx)?;

            // New node is being created, so we are done building the current block. We then want to
            // add the assembly operation to the new node - for example call, dyncall, if/else
            // statements, loops, etc. However, `exec` instructions are compiled away and not
            // added to the trace, so we should ignore them. Theoretically, we
            // could probably add them anyways, but it currently breaks the
            // `VmStateIterator`.
            if can_create_node
                && !matches!(instruction.inner(), Instruction::Exec(_))
                && let Some(asm_op_id) = block_builder.set_instruction_cycle_count()
            {
                // Set the cycle count for this assembly op to 1
                let assembly_op = &mut block_builder.mast_forest_builder_mut()[asm_op_id];
                match assembly_op {
                    Decorator::AsmOp(op) => op.set_num_cycles(1),
                    _ => panic!("expected AsmOp decorator"),
                }
                decorators.push(asm_op_id);
            }
        }

        // Compile the instruction, passing the decorators (which may be empty).
        let opt_new_node_id =
            self.compile_instruction_impl(instruction, block_builder, proc_ctx, decorators)?;

        // If we're in debug mode but didn't create a node, set the cycle count after compilation.
        if self.in_debug_mode() && !can_create_node {
            let _ = block_builder.set_instruction_cycle_count();
        }

        Ok(opt_new_node_id)
    }

    fn compile_instruction_impl(
        &self,
        instruction: &Span<Instruction>,
        block_builder: &mut BasicBlockBuilder,
        proc_ctx: &mut ProcedureContext,
        before_enter: Vec<miden_core::mast::DecoratorId>,
    ) -> Result<Option<MastNodeId>, Report> {
        use Operation::*;

        let span = instruction.span();
        match &**instruction {
            Instruction::Nop => block_builder.push_op(Noop),
            Instruction::Assert => block_builder.push_op(Assert(ZERO)),
            Instruction::AssertWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_op(Assert(error_code))
            },
            Instruction::AssertEq => block_builder.push_ops([Eq, Assert(ZERO)]),
            Instruction::AssertEqWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_ops([Eq, Assert(error_code)])
            },
            Instruction::AssertEqw => field_ops::assertw(block_builder, ZERO),
            Instruction::AssertEqwWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                field_ops::assertw(block_builder, error_code)
            },
            Instruction::Assertz => block_builder.push_ops([Eqz, Assert(ZERO)]),
            Instruction::AssertzWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_ops([Eqz, Assert(error_code)])
            },

            Instruction::Add => block_builder.push_op(Add),
            Instruction::AddImm(imm) => field_ops::add_imm(block_builder, imm.expect_value()),
            Instruction::Sub => block_builder.push_ops([Neg, Add]),
            Instruction::SubImm(imm) => field_ops::sub_imm(block_builder, imm.expect_value()),
            Instruction::Mul => block_builder.push_op(Mul),
            Instruction::MulImm(imm) => field_ops::mul_imm(block_builder, imm.expect_value()),
            Instruction::Div => block_builder.push_ops([Inv, Mul]),
            Instruction::DivImm(imm) => {
                field_ops::div_imm(block_builder, proc_ctx, imm.expect_spanned_value())?;
            },
            Instruction::Neg => block_builder.push_op(Neg),
            Instruction::Inv => block_builder.push_op(Inv),
            Instruction::Incr => block_builder.push_op(Incr),

            Instruction::Pow2 => field_ops::pow2(block_builder),
            Instruction::Exp => field_ops::exp(block_builder, proc_ctx, 64_u8, span)?,

            Instruction::ExpImm(pow) => {
                field_ops::exp_imm(block_builder, proc_ctx, pow.expect_value(), pow.span())?
            },
            Instruction::ExpBitLength(num_pow_bits) => {
                field_ops::exp(block_builder, proc_ctx, *num_pow_bits, span)?
            },
            Instruction::ILog2 => field_ops::ilog2(block_builder),

            Instruction::Not => block_builder.push_op(Not),
            Instruction::And => block_builder.push_op(And),
            Instruction::Or => block_builder.push_op(Or),
            Instruction::Xor => block_builder.push_ops([Dup0, Dup2, Or, MovDn2, And, Not, And]),

            Instruction::Eq => block_builder.push_op(Eq),
            Instruction::EqImm(imm) => field_ops::eq_imm(block_builder, imm.expect_value()),
            Instruction::Eqw => field_ops::eqw(block_builder),
            Instruction::Neq => block_builder.push_ops([Eq, Not]),
            Instruction::NeqImm(imm) => field_ops::neq_imm(block_builder, imm.expect_value()),
            Instruction::Lt => field_ops::lt(block_builder),
            Instruction::Lte => field_ops::lte(block_builder),
            Instruction::Gt => field_ops::gt(block_builder),
            Instruction::Gte => field_ops::gte(block_builder),
            Instruction::IsOdd => field_ops::is_odd(block_builder),

            // ----- ext2 instructions ------------------------------------------------------------
            Instruction::Ext2Add => ext2_ops::ext2_add(block_builder),
            Instruction::Ext2Sub => ext2_ops::ext2_sub(block_builder),
            Instruction::Ext2Mul => ext2_ops::ext2_mul(block_builder),
            Instruction::Ext2Div => ext2_ops::ext2_div(block_builder),
            Instruction::Ext2Neg => ext2_ops::ext2_neg(block_builder),
            Instruction::Ext2Inv => ext2_ops::ext2_inv(block_builder)?,

            // ----- u32 manipulation -------------------------------------------------------------
            Instruction::U32Test => block_builder.push_ops([Dup0, U32split, Swap, Drop, Eqz]),
            Instruction::U32TestW => u32_ops::u32testw(block_builder),
            Instruction::U32Assert => block_builder.push_ops([Pad, U32assert2(ZERO), Drop]),
            Instruction::U32AssertWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_ops([Pad, U32assert2(error_code), Drop])
            },
            Instruction::U32Assert2 => block_builder.push_op(U32assert2(ZERO)),
            Instruction::U32Assert2WithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_op(U32assert2(error_code))
            },
            Instruction::U32AssertW => u32_ops::u32assertw(block_builder, ZERO),
            Instruction::U32AssertWWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                u32_ops::u32assertw(block_builder, error_code)
            },

            Instruction::U32Cast => block_builder.push_ops([U32split, Drop]),
            Instruction::U32Split => block_builder.push_op(U32split),

            Instruction::U32OverflowingAdd => u32_ops::u32add(block_builder, Overflowing, None),
            Instruction::U32OverflowingAddImm(v) => {
                u32_ops::u32add(block_builder, Overflowing, Some(v.expect_value()))
            },
            Instruction::U32WrappingAdd => u32_ops::u32add(block_builder, Wrapping, None),
            Instruction::U32WrappingAddImm(v) => {
                u32_ops::u32add(block_builder, Wrapping, Some(v.expect_value()))
            },
            Instruction::U32OverflowingAdd3 => block_builder.push_op(U32add3),
            Instruction::U32WrappingAdd3 => block_builder.push_ops([U32add3, Drop]),

            Instruction::U32OverflowingSub => u32_ops::u32sub(block_builder, Overflowing, None),
            Instruction::U32OverflowingSubImm(v) => {
                u32_ops::u32sub(block_builder, Overflowing, Some(v.expect_value()))
            },
            Instruction::U32WrappingSub => u32_ops::u32sub(block_builder, Wrapping, None),
            Instruction::U32WrappingSubImm(v) => {
                u32_ops::u32sub(block_builder, Wrapping, Some(v.expect_value()))
            },

            Instruction::U32OverflowingMul => u32_ops::u32mul(block_builder, Overflowing, None),
            Instruction::U32OverflowingMulImm(v) => {
                u32_ops::u32mul(block_builder, Overflowing, Some(v.expect_value()))
            },
            Instruction::U32WrappingMul => u32_ops::u32mul(block_builder, Wrapping, None),
            Instruction::U32WrappingMulImm(v) => {
                u32_ops::u32mul(block_builder, Wrapping, Some(v.expect_value()))
            },
            Instruction::U32OverflowingMadd => block_builder.push_op(U32madd),
            Instruction::U32WrappingMadd => block_builder.push_ops([U32madd, Drop]),

            Instruction::U32Div => u32_ops::u32div(block_builder, proc_ctx, None)?,
            Instruction::U32DivImm(v) => {
                u32_ops::u32div(block_builder, proc_ctx, Some(v.expect_spanned_value()))?
            },
            Instruction::U32Mod => u32_ops::u32mod(block_builder, proc_ctx, None)?,
            Instruction::U32ModImm(v) => {
                u32_ops::u32mod(block_builder, proc_ctx, Some(v.expect_spanned_value()))?
            },
            Instruction::U32DivMod => u32_ops::u32divmod(block_builder, proc_ctx, None)?,
            Instruction::U32DivModImm(v) => {
                u32_ops::u32divmod(block_builder, proc_ctx, Some(v.expect_spanned_value()))?
            },
            Instruction::U32And => block_builder.push_op(U32and),
            Instruction::U32Or => block_builder.push_ops([Dup1, Dup1, U32and, Neg, Add, Add]),
            Instruction::U32Xor => block_builder.push_op(U32xor),
            Instruction::U32Not => u32_ops::u32not(block_builder),
            Instruction::U32Shl => u32_ops::u32shl(block_builder, proc_ctx, None, span)?,
            Instruction::U32ShlImm(v) => {
                u32_ops::u32shl(block_builder, proc_ctx, Some(v.expect_value()), span)?
            },
            Instruction::U32Shr => u32_ops::u32shr(block_builder, proc_ctx, None, span)?,
            Instruction::U32ShrImm(v) => {
                u32_ops::u32shr(block_builder, proc_ctx, Some(v.expect_value()), v.span())?
            },
            Instruction::U32Rotl => u32_ops::u32rotl(block_builder, proc_ctx, None, span)?,
            Instruction::U32RotlImm(v) => {
                u32_ops::u32rotl(block_builder, proc_ctx, Some(v.expect_value()), v.span())?
            },
            Instruction::U32Rotr => u32_ops::u32rotr(block_builder, proc_ctx, None, span)?,
            Instruction::U32RotrImm(v) => {
                u32_ops::u32rotr(block_builder, proc_ctx, Some(v.expect_value()), v.span())?
            },
            Instruction::U32Popcnt => u32_ops::u32popcnt(block_builder),
            Instruction::U32Clz => u32_ops::u32clz(block_builder),
            Instruction::U32Ctz => u32_ops::u32ctz(block_builder),
            Instruction::U32Clo => u32_ops::u32clo(block_builder),
            Instruction::U32Cto => u32_ops::u32cto(block_builder),
            Instruction::U32Lt => u32_ops::u32lt(block_builder),
            Instruction::U32Lte => u32_ops::u32lte(block_builder),
            Instruction::U32Gt => u32_ops::u32gt(block_builder),
            Instruction::U32Gte => u32_ops::u32gte(block_builder),
            Instruction::U32Min => u32_ops::u32min(block_builder),
            Instruction::U32Max => u32_ops::u32max(block_builder),

            // ----- stack manipulation -----------------------------------------------------------
            Instruction::Drop => block_builder.push_op(Drop),
            Instruction::DropW => block_builder.push_ops([Drop; 4]),
            Instruction::PadW => block_builder.push_ops([Pad; 4]),
            Instruction::Dup0 => block_builder.push_op(Dup0),
            Instruction::Dup1 => block_builder.push_op(Dup1),
            Instruction::Dup2 => block_builder.push_op(Dup2),
            Instruction::Dup3 => block_builder.push_op(Dup3),
            Instruction::Dup4 => block_builder.push_op(Dup4),
            Instruction::Dup5 => block_builder.push_op(Dup5),
            Instruction::Dup6 => block_builder.push_op(Dup6),
            Instruction::Dup7 => block_builder.push_op(Dup7),
            Instruction::Dup8 => block_builder.push_ops([Pad, Dup9, Add]),
            Instruction::Dup9 => block_builder.push_op(Dup9),
            Instruction::Dup10 => block_builder.push_ops([Pad, Dup11, Add]),
            Instruction::Dup11 => block_builder.push_op(Dup11),
            Instruction::Dup12 => block_builder.push_ops([Pad, Dup13, Add]),
            Instruction::Dup13 => block_builder.push_op(Dup13),
            Instruction::Dup14 => block_builder.push_ops([Pad, Dup15, Add]),
            Instruction::Dup15 => block_builder.push_op(Dup15),
            Instruction::DupW0 => block_builder.push_ops([Dup3; 4]),
            Instruction::DupW1 => block_builder.push_ops([Dup7; 4]),
            Instruction::DupW2 => block_builder.push_ops([Dup11; 4]),
            Instruction::DupW3 => block_builder.push_ops([Dup15; 4]),
            Instruction::Swap1 => block_builder.push_op(Swap),
            Instruction::Swap2 => block_builder.push_ops([Swap, MovUp2]),
            Instruction::Swap3 => block_builder.push_ops([MovDn2, MovUp3]),
            Instruction::Swap4 => block_builder.push_ops([MovDn3, MovUp4]),
            Instruction::Swap5 => block_builder.push_ops([MovDn4, MovUp5]),
            Instruction::Swap6 => block_builder.push_ops([MovDn5, MovUp6]),
            Instruction::Swap7 => block_builder.push_ops([MovDn6, MovUp7]),
            Instruction::Swap8 => block_builder.push_ops([MovDn7, MovUp8]),
            Instruction::Swap9 => block_builder.push_ops([MovDn8, SwapDW, Swap, SwapDW, MovUp8]),
            Instruction::Swap10 => {
                block_builder.push_ops([MovDn8, SwapDW, Swap, MovUp2, SwapDW, MovUp8])
            },
            Instruction::Swap11 => {
                block_builder.push_ops([MovDn8, SwapDW, MovDn2, MovUp3, SwapDW, MovUp8])
            },
            Instruction::Swap12 => {
                block_builder.push_ops([MovDn8, SwapDW, MovDn3, MovUp4, SwapDW, MovUp8])
            },
            Instruction::Swap13 => {
                block_builder.push_ops([MovDn8, SwapDW, MovDn4, MovUp5, SwapDW, MovUp8])
            },
            Instruction::Swap14 => {
                block_builder.push_ops([MovDn8, SwapDW, MovDn5, MovUp6, SwapDW, MovUp8])
            },
            Instruction::Swap15 => {
                block_builder.push_ops([MovDn8, SwapDW, MovDn6, MovUp7, SwapDW, MovUp8])
            },
            Instruction::SwapW1 => block_builder.push_op(SwapW),
            Instruction::SwapW2 => block_builder.push_op(SwapW2),
            Instruction::SwapW3 => block_builder.push_op(SwapW3),
            Instruction::SwapDw => block_builder.push_op(SwapDW),
            Instruction::MovUp2 => block_builder.push_op(MovUp2),
            Instruction::MovUp3 => block_builder.push_op(MovUp3),
            Instruction::MovUp4 => block_builder.push_op(MovUp4),
            Instruction::MovUp5 => block_builder.push_op(MovUp5),
            Instruction::MovUp6 => block_builder.push_op(MovUp6),
            Instruction::MovUp7 => block_builder.push_op(MovUp7),
            Instruction::MovUp8 => block_builder.push_op(MovUp8),
            Instruction::MovUp9 => block_builder.push_ops([SwapDW, Swap, SwapDW, MovUp8]),
            Instruction::MovUp10 => block_builder.push_ops([SwapDW, MovUp2, SwapDW, MovUp8]),
            Instruction::MovUp11 => block_builder.push_ops([SwapDW, MovUp3, SwapDW, MovUp8]),
            Instruction::MovUp12 => block_builder.push_ops([SwapDW, MovUp4, SwapDW, MovUp8]),
            Instruction::MovUp13 => block_builder.push_ops([SwapDW, MovUp5, SwapDW, MovUp8]),
            Instruction::MovUp14 => block_builder.push_ops([SwapDW, MovUp6, SwapDW, MovUp8]),
            Instruction::MovUp15 => block_builder.push_ops([SwapDW, MovUp7, SwapDW, MovUp8]),
            Instruction::MovUpW2 => block_builder.push_ops([SwapW, SwapW2]),
            Instruction::MovUpW3 => block_builder.push_ops([SwapW, SwapW2, SwapW3]),
            Instruction::MovDn2 => block_builder.push_op(MovDn2),
            Instruction::MovDn3 => block_builder.push_op(MovDn3),
            Instruction::MovDn4 => block_builder.push_op(MovDn4),
            Instruction::MovDn5 => block_builder.push_op(MovDn5),
            Instruction::MovDn6 => block_builder.push_op(MovDn6),
            Instruction::MovDn7 => block_builder.push_op(MovDn7),
            Instruction::MovDn8 => block_builder.push_op(MovDn8),
            Instruction::MovDn9 => block_builder.push_ops([MovDn8, SwapDW, Swap, SwapDW]),
            Instruction::MovDn10 => block_builder.push_ops([MovDn8, SwapDW, MovDn2, SwapDW]),
            Instruction::MovDn11 => block_builder.push_ops([MovDn8, SwapDW, MovDn3, SwapDW]),
            Instruction::MovDn12 => block_builder.push_ops([MovDn8, SwapDW, MovDn4, SwapDW]),
            Instruction::MovDn13 => block_builder.push_ops([MovDn8, SwapDW, MovDn5, SwapDW]),
            Instruction::MovDn14 => block_builder.push_ops([MovDn8, SwapDW, MovDn6, SwapDW]),
            Instruction::MovDn15 => block_builder.push_ops([MovDn8, SwapDW, MovDn7, SwapDW]),
            Instruction::MovDnW2 => block_builder.push_ops([SwapW2, SwapW]),
            Instruction::MovDnW3 => block_builder.push_ops([SwapW3, SwapW2, SwapW]),
            Instruction::Reversew => push_reversew(block_builder),
            Instruction::Reversedw => {
                push_reversew(block_builder);
                block_builder.push_op(SwapW);
                push_reversew(block_builder);
            },

            Instruction::CSwap => block_builder.push_op(CSwap),
            Instruction::CSwapW => block_builder.push_op(CSwapW),
            Instruction::CDrop => block_builder.push_ops([CSwap, Drop]),
            Instruction::CDropW => block_builder.push_ops([CSwapW, Drop, Drop, Drop, Drop]),

            // ----- input / output instructions --------------------------------------------------
            Instruction::Push(imm) => match (*imm).expect_value() {
                PushValue::Int(value) => match value {
                    IntValue::U8(v) => env_ops::push_one(v, block_builder),
                    IntValue::U16(v) => env_ops::push_one(v, block_builder),
                    IntValue::U32(v) => env_ops::push_one(v, block_builder),
                    IntValue::Felt(v) => env_ops::push_one(v, block_builder),
                },
                PushValue::Word(v) => env_ops::push_many(&v.0, block_builder),
            },
            Instruction::PushSlice(imm, range) => {
                env_ops::push_word_slice(imm, range, block_builder)?
            },
            Instruction::PushFeltList(imms) => env_ops::push_many(imms, block_builder),
            Instruction::Sdepth => block_builder.push_op(SDepth),
            Instruction::Caller => env_ops::caller(block_builder),
            Instruction::Clk => block_builder.push_op(Clk),
            Instruction::AdvPipe => block_builder.push_op(Pipe),
            Instruction::AdvPush(n) => {
                adv_ops::adv_push(block_builder, proc_ctx, n.expect_value(), n.span())?
            },
            Instruction::AdvLoadW => block_builder.push_op(AdvPopW),

            Instruction::MemStream => block_builder.push_op(MStream),
            Instruction::Locaddr(v) => {
                env_ops::locaddr(block_builder, v.expect_value(), proc_ctx, span)?
            },
            Instruction::MemLoad => {
                mem_ops::mem_read(block_builder, proc_ctx, None, false, true, span)?
            },
            Instruction::MemLoadImm(v) => mem_ops::mem_read(
                block_builder,
                proc_ctx,
                Some(v.expect_value()),
                false,
                true,
                span,
            )?,
            Instruction::MemLoadWBe => {
                mem_ops::mem_read(block_builder, proc_ctx, None, false, false, span)?
            },
            Instruction::MemLoadWLe => {
                mem_ops::mem_read(block_builder, proc_ctx, None, false, false, span)?;
                push_reversew(block_builder);
            },
            Instruction::MemLoadWBeImm(v) => mem_ops::mem_read(
                block_builder,
                proc_ctx,
                Some(v.expect_value()),
                false,
                false,
                span,
            )?,
            Instruction::MemLoadWLeImm(v) => {
                mem_ops::mem_read(
                    block_builder,
                    proc_ctx,
                    Some(v.expect_value()),
                    false,
                    false,
                    span,
                )?;
                push_reversew(block_builder);
            },
            Instruction::LocLoad(v) => mem_ops::mem_read(
                block_builder,
                proc_ctx,
                Some(v.expect_value() as u32),
                true,
                true,
                span,
            )?,
            Instruction::LocLoadWBe(v) => {
                let local_addr = validate_local_word_alignment(v, proc_ctx)?;
                mem_ops::mem_read(
                    block_builder,
                    proc_ctx,
                    Some(local_addr),
                    true,
                    false,
                    instruction.span(),
                )?
            },
            Instruction::LocLoadWLe(v) => {
                let local_addr = validate_local_word_alignment(v, proc_ctx)?;
                mem_ops::mem_read(
                    block_builder,
                    proc_ctx,
                    Some(local_addr),
                    true,
                    false,
                    instruction.span(),
                )?;
                push_reversew(block_builder)
            },
            Instruction::MemStore => block_builder.push_ops([MStore, Drop]),
            Instruction::MemStoreImm(v) => mem_ops::mem_write_imm(
                block_builder,
                proc_ctx,
                v.expect_value(),
                false,
                true,
                span,
            )?,
            Instruction::MemStoreWBe => block_builder.push_ops([MStoreW]),
            Instruction::MemStoreWLe => {
                block_builder.push_op(MovDn4);
                push_reversew(block_builder);
                block_builder.push_op(MovUp4);
                block_builder.push_op(MStoreW);
                push_reversew(block_builder);
            },
            Instruction::MemStoreWBeImm(v) => mem_ops::mem_write_imm(
                block_builder,
                proc_ctx,
                v.expect_value(),
                false,
                false,
                span,
            )?,
            Instruction::MemStoreWLeImm(v) => {
                push_reversew(block_builder);
                mem_ops::mem_write_imm(
                    block_builder,
                    proc_ctx,
                    v.expect_value(),
                    false,
                    false,
                    span,
                )?;
                push_reversew(block_builder);
            },
            Instruction::LocStore(v) => mem_ops::mem_write_imm(
                block_builder,
                proc_ctx,
                v.expect_value() as u32,
                true,
                true,
                span,
            )?,
            Instruction::LocStoreWBe(v) => {
                let local_addr = validate_local_word_alignment(v, proc_ctx)?;
                mem_ops::mem_write_imm(block_builder, proc_ctx, local_addr, true, false, span)?
            },
            Instruction::LocStoreWLe(v) => {
                let local_addr = validate_local_word_alignment(v, proc_ctx)?;
                push_reversew(block_builder);
                mem_ops::mem_write_imm(block_builder, proc_ctx, local_addr, true, false, span)?;
                push_reversew(block_builder)
            },
            Instruction::SysEvent(system_event) => {
                block_builder.push_system_event(system_event.into())
            },

            // ----- cryptographic instructions ---------------------------------------------------
            Instruction::Hash => crypto_ops::hash(block_builder),
            Instruction::HPerm => block_builder.push_op(HPerm),
            Instruction::HMerge => crypto_ops::hmerge(block_builder),
            Instruction::MTreeGet => crypto_ops::mtree_get(block_builder),
            Instruction::MTreeSet => crypto_ops::mtree_set(block_builder)?,
            Instruction::MTreeMerge => crypto_ops::mtree_merge(block_builder),
            Instruction::MTreeVerify => block_builder.push_op(MpVerify(ZERO)),
            Instruction::MTreeVerifyWithError(err_msg) => {
                let error_code = block_builder.register_error(err_msg.expect_string());
                block_builder.push_op(MpVerify(error_code))
            },

            // ----- STARK proof verification -----------------------------------------------------
            Instruction::FriExt2Fold4 => block_builder.push_op(FriE2F4),
            Instruction::HornerBase => block_builder.push_op(HornerBase),
            Instruction::HornerExt => block_builder.push_op(HornerExt),
            Instruction::EvalCircuit => block_builder.push_op(EvalCircuit),
            Instruction::LogPrecompile => block_builder.push_op(LogPrecompile),

            // ----- exec/call instructions -------------------------------------------------------
            Instruction::Exec(callee) => {
                return self
                    .invoke(
                        InvokeKind::Exec,
                        callee,
                        proc_ctx.id(),
                        block_builder.mast_forest_builder_mut(),
                        before_enter,
                    )
                    .map(Into::into);
            },
            Instruction::Call(callee) => {
                return self
                    .invoke(
                        InvokeKind::Call,
                        callee,
                        proc_ctx.id(),
                        block_builder.mast_forest_builder_mut(),
                        before_enter,
                    )
                    .map(Into::into);
            },
            Instruction::SysCall(callee) => {
                return self
                    .invoke(
                        InvokeKind::SysCall,
                        callee,
                        proc_ctx.id(),
                        block_builder.mast_forest_builder_mut(),
                        before_enter,
                    )
                    .map(Into::into);
            },
            Instruction::DynExec => {
                return self.dynexec(block_builder.mast_forest_builder_mut(), before_enter);
            },
            Instruction::DynCall => {
                return self.dyncall(block_builder.mast_forest_builder_mut(), before_enter);
            },
            Instruction::ProcRef(callee) => self.procref(callee, proc_ctx.id(), block_builder)?,

            // ----- debug decorators -------------------------------------------------------------
            Instruction::Breakpoint => {
                if self.in_debug_mode() {
                    block_builder.push_op(Noop);
                    block_builder.track_instruction(instruction, proc_ctx)?;
                }
            },

            Instruction::Debug(options) => {
                if self.in_debug_mode() {
                    block_builder.push_decorator(Decorator::Debug(debug::compile_options(
                        options, proc_ctx,
                    )?))?;
                }
            },

            // ----- emit instruction -------------------------------------------------------------
            // emit: reads event ID from top of stack and execute the corresponding handler.
            Instruction::Emit => {
                block_builder.push_ops([Operation::Emit]);
            },
            // emit.<id>: expands to `push.<id>, emit, drop` sequence leaving the stack unchanged.
            Instruction::EmitImm(event_id) => {
                let event_id_value = event_id.expect_value();
                block_builder.push_ops([
                    Operation::Push(event_id_value),
                    Operation::Emit,
                    Operation::Drop,
                ]);
            },

            // ----- trace instruction ------------------------------------------------------------
            Instruction::Trace(trace_id) => {
                block_builder.push_decorator(Decorator::Trace(trace_id.expect_value()))?;
            },
        }

        Ok(None)
    }
}

// HELPER FUNCTIONS
// ================================================================================================

/// This is a helper function that appends a PUSH operation to the span block which puts the
/// provided u32 value onto the stack.
///
/// When the value is 0, PUSH operation is replaced with PAD. When the value is 1, PUSH operation
/// is replaced with PAD INCR because in most cases this will be more efficient than doing a PUSH.
fn push_u32_value(span_builder: &mut BasicBlockBuilder, value: u32) {
    use Operation::*;

    if value == 0 {
        span_builder.push_op(Pad);
    } else if value == 1 {
        span_builder.push_op(Pad);
        span_builder.push_op(Incr);
    } else {
        span_builder.push_op(Push(Felt::from(value)));
    }
}

/// This is a helper function that appends a PUSH operation to the span block which puts the
/// provided field element onto the stack.
///
/// When the value is 0, PUSH operation is replaced with PAD. When the value is 1, PUSH operation
/// is replaced with PAD INCR because in most cases this will be more efficient than doing a PUSH.
fn push_felt(span_builder: &mut BasicBlockBuilder, value: Felt) {
    span_builder.push_ops(push_value_ops(value));
}

/// Helper function that appends operations to reverse the order of the top 4 elements
/// on the stack, used for little-endian memory instructions.
///
/// The instruction takes 3 cycles to execute and transforms the stack as follows:
/// [a, b, c, d, ...] -> [d, c, b, a, ...].
fn push_reversew(block_builder: &mut BasicBlockBuilder) {
    use Operation::*;

    block_builder.push_ops([MovDn3, Swap, MovUp2]);
}

/// Helper function that validates a local word address is properly word-aligned.
///
/// Returns the validated address as u32 or an error if the address is not a multiple of 4.
fn validate_local_word_alignment(
    local_addr: &ImmU16,
    proc_ctx: &ProcedureContext,
) -> Result<u32, Report> {
    let addr = local_addr.expect_value();
    if !addr.is_multiple_of(WORD_SIZE as u16) {
        return Err(RelatedLabel::error("invalid local word index")
            .with_help("the index to a local word must be a multiple of 4")
            .with_labeled_span(local_addr.span(), "this index is not word-aligned")
            .with_source_file(proc_ctx.source_manager().get(proc_ctx.span().source_id()).ok())
            .into());
    }
    Ok(addr as u32)
}
