use crate::{
    DisplayHex,
    ast::{Immediate, Instruction, InvocationTarget},
    prettier::{Document, PrettyPrint},
};

impl PrettyPrint for Instruction {
    fn render(&self) -> Document {
        use crate::prettier::*;

        match self {
            Self::Nop => const_text("nop"),
            Self::Assert => const_text("assert"),
            Self::AssertWithError(err_code) => flatten(
                const_text("assert.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::AssertEq => const_text("assert_eq"),
            Self::AssertEqWithError(err_code) => flatten(
                const_text("assert_eq.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::AssertEqw => const_text("assert_eqw"),
            Self::AssertEqwWithError(err_code) => flatten(
                const_text("assert_eqw.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::Assertz => const_text("assertz"),
            Self::AssertzWithError(err_code) => flatten(
                const_text("assertz.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::Add => const_text("add"),
            Self::AddImm(value) => inst_with_felt_imm("add", value),
            Self::Sub => const_text("sub"),
            Self::SubImm(value) => inst_with_felt_imm("sub", value),
            Self::Mul => const_text("mul"),
            Self::MulImm(value) => inst_with_felt_imm("mul", value),
            Self::Div => const_text("div"),
            Self::DivImm(value) => inst_with_felt_imm("div", value),
            Self::Neg => const_text("neg"),
            Self::ILog2 => const_text("ilog2"),
            Self::Inv => const_text("inv"),
            Self::Incr => const_text("add.1"),
            Self::Pow2 => const_text("pow2"),
            Self::Exp => const_text("exp"),
            Self::ExpImm(value) => inst_with_felt_imm("exp", value),
            Self::ExpBitLength(value) => text(format!("exp.u{value}")),
            Self::Not => const_text("not"),
            Self::And => const_text("and"),
            Self::Or => const_text("or"),
            Self::Xor => const_text("xor"),
            Self::Eq => const_text("eq"),
            Self::EqImm(value) => inst_with_felt_imm("eq", value),
            Self::Neq => const_text("neq"),
            Self::NeqImm(value) => inst_with_felt_imm("neq", value),
            Self::Eqw => const_text("eqw"),
            Self::Lt => const_text("lt"),
            Self::Lte => const_text("lte"),
            Self::Gt => const_text("gt"),
            Self::Gte => const_text("gte"),
            Self::IsOdd => const_text("is_odd"),

            // ----- ext2 operations --------------------------------------------------------------
            Self::Ext2Add => const_text("ext2add"),
            Self::Ext2Sub => const_text("ext2sub"),
            Self::Ext2Mul => const_text("ext2mul"),
            Self::Ext2Div => const_text("ext2div"),
            Self::Ext2Neg => const_text("ext2neg"),
            Self::Ext2Inv => const_text("ext2inv"),

            // ----- u32 manipulation -------------------------------------------------------------
            Self::U32Test => const_text("u32test"),
            Self::U32TestW => const_text("u32testw"),
            Self::U32Assert => const_text("u32assert"),
            Self::U32AssertWithError(err_code) => flatten(
                const_text("u32assert.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::U32Assert2 => const_text("u32assert2"),
            Self::U32Assert2WithError(err_code) => flatten(
                const_text("u32assert2.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::U32AssertW => const_text("u32assertw"),
            Self::U32AssertWWithError(err_code) => flatten(
                const_text("u32assertw.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),
            Self::U32Split => const_text("u32split"),
            Self::U32Cast => const_text("u32cast"),
            Self::U32WrappingAdd => const_text("u32wrapping_add"),
            Self::U32WrappingAddImm(value) => inst_with_imm("u32wrapping_add", value),
            Self::U32OverflowingAdd => const_text("u32overflowing_add"),
            Self::U32OverflowingAddImm(value) => inst_with_imm("u32overflowing_add", value),
            Self::U32OverflowingAdd3 => const_text("u32overflowing_add3"),
            Self::U32WrappingAdd3 => const_text("u32wrapping_add3"),
            Self::U32WrappingSub => const_text("u32wrapping_sub"),
            Self::U32WrappingSubImm(value) => inst_with_imm("u32wrapping_sub", value),
            Self::U32OverflowingSub => const_text("u32overflowing_sub"),
            Self::U32OverflowingSubImm(value) => inst_with_imm("u32overflowing_sub", value),
            Self::U32WrappingMul => const_text("u32wrapping_mul"),
            Self::U32WrappingMulImm(value) => inst_with_imm("u32wrapping_mul", value),
            Self::U32OverflowingMul => const_text("u32overflowing_mul"),
            Self::U32OverflowingMulImm(value) => inst_with_imm("u32overflowing_mul", value),
            Self::U32OverflowingMadd => const_text("u32overflowing_madd"),
            Self::U32WrappingMadd => const_text("u32wrapping_madd"),
            Self::U32Div => const_text("u32div"),
            Self::U32DivImm(value) => inst_with_imm("u32div", value),
            Self::U32Mod => const_text("u32mod"),
            Self::U32ModImm(value) => inst_with_imm("u32mod", value),
            Self::U32DivMod => const_text("u32divmod"),
            Self::U32DivModImm(value) => inst_with_imm("u32divmod", value),
            Self::U32And => const_text("u32and"),
            Self::U32Or => const_text("u32or"),
            Self::U32Xor => const_text("u32xor"),
            Self::U32Not => const_text("u32not"),
            Self::U32Shr => const_text("u32shr"),
            Self::U32ShrImm(value) => inst_with_imm("u32shr", value),
            Self::U32Shl => const_text("u32shl"),
            Self::U32ShlImm(value) => inst_with_imm("u32shl", value),
            Self::U32Rotr => const_text("u32rotr"),
            Self::U32RotrImm(value) => inst_with_imm("u32rotr", value),
            Self::U32Rotl => const_text("u32rotl"),
            Self::U32RotlImm(value) => inst_with_imm("u32rotl", value),
            Self::U32Popcnt => const_text("u32popcnt"),
            Self::U32Clz => const_text("u32clz"),
            Self::U32Ctz => const_text("u32ctz"),
            Self::U32Clo => const_text("u32clo"),
            Self::U32Cto => const_text("u32cto"),
            Self::U32Lt => const_text("u32lt"),
            Self::U32Lte => const_text("u32lte"),
            Self::U32Gt => const_text("u32gt"),
            Self::U32Gte => const_text("u32gte"),
            Self::U32Min => const_text("u32min"),
            Self::U32Max => const_text("u32max"),

            // ----- stack manipulation -----------------------------------------------------------
            Self::Drop => const_text("drop"),
            Self::DropW => const_text("dropw"),
            Self::PadW => const_text("padw"),
            Self::Dup0 => const_text("dup.0"),
            Self::Dup1 => const_text("dup.1"),
            Self::Dup2 => const_text("dup.2"),
            Self::Dup3 => const_text("dup.3"),
            Self::Dup4 => const_text("dup.4"),
            Self::Dup5 => const_text("dup.5"),
            Self::Dup6 => const_text("dup.6"),
            Self::Dup7 => const_text("dup.7"),
            Self::Dup8 => const_text("dup.8"),
            Self::Dup9 => const_text("dup.9"),
            Self::Dup10 => const_text("dup.10"),
            Self::Dup11 => const_text("dup.11"),
            Self::Dup12 => const_text("dup.12"),
            Self::Dup13 => const_text("dup.13"),
            Self::Dup14 => const_text("dup.14"),
            Self::Dup15 => const_text("dup.15"),
            Self::DupW0 => const_text("dupw.0"),
            Self::DupW1 => const_text("dupw.1"),
            Self::DupW2 => const_text("dupw.2"),
            Self::DupW3 => const_text("dupw.3"),
            Self::Swap1 => const_text("swap.1"),
            Self::Swap2 => const_text("swap.2"),
            Self::Swap3 => const_text("swap.3"),
            Self::Swap4 => const_text("swap.4"),
            Self::Swap5 => const_text("swap.5"),
            Self::Swap6 => const_text("swap.6"),
            Self::Swap7 => const_text("swap.7"),
            Self::Swap8 => const_text("swap.8"),
            Self::Swap9 => const_text("swap.9"),
            Self::Swap10 => const_text("swap.10"),
            Self::Swap11 => const_text("swap.11"),
            Self::Swap12 => const_text("swap.12"),
            Self::Swap13 => const_text("swap.13"),
            Self::Swap14 => const_text("swap.14"),
            Self::Swap15 => const_text("swap.15"),
            Self::SwapW1 => const_text("swapw.1"),
            Self::SwapW2 => const_text("swapw.2"),
            Self::SwapW3 => const_text("swapw.3"),
            Self::SwapDw => const_text("swapdw"),
            Self::MovUp2 => const_text("movup.2"),
            Self::MovUp3 => const_text("movup.3"),
            Self::MovUp4 => const_text("movup.4"),
            Self::MovUp5 => const_text("movup.5"),
            Self::MovUp6 => const_text("movup.6"),
            Self::MovUp7 => const_text("movup.7"),
            Self::MovUp8 => const_text("movup.8"),
            Self::MovUp9 => const_text("movup.9"),
            Self::MovUp10 => const_text("movup.10"),
            Self::MovUp11 => const_text("movup.11"),
            Self::MovUp12 => const_text("movup.12"),
            Self::MovUp13 => const_text("movup.13"),
            Self::MovUp14 => const_text("movup.14"),
            Self::MovUp15 => const_text("movup.15"),
            Self::MovUpW2 => const_text("movupw.2"),
            Self::MovUpW3 => const_text("movupw.3"),
            Self::MovDn2 => const_text("movdn.2"),
            Self::MovDn3 => const_text("movdn.3"),
            Self::MovDn4 => const_text("movdn.4"),
            Self::MovDn5 => const_text("movdn.5"),
            Self::MovDn6 => const_text("movdn.6"),
            Self::MovDn7 => const_text("movdn.7"),
            Self::MovDn8 => const_text("movdn.8"),
            Self::MovDn9 => const_text("movdn.9"),
            Self::MovDn10 => const_text("movdn.10"),
            Self::MovDn11 => const_text("movdn.11"),
            Self::MovDn12 => const_text("movdn.12"),
            Self::MovDn13 => const_text("movdn.13"),
            Self::MovDn14 => const_text("movdn.14"),
            Self::MovDn15 => const_text("movdn.15"),
            Self::MovDnW2 => const_text("movdnw.2"),
            Self::MovDnW3 => const_text("movdnw.3"),
            Self::CSwap => const_text("cswap"),
            Self::CSwapW => const_text("cswapw"),
            Self::CDrop => const_text("cdrop"),
            Self::CDropW => const_text("cdropw"),

            // ----- input / output operations ----------------------------------------------------
            Self::Push(value) => inst_with_imm("push", value),
            Self::PushSlice(value, range) => flatten(
                const_text("push.")
                    + value.render()
                    + const_text("[")
                    + display(range.start)
                    + const_text("..")
                    + display(range.end)
                    + const_text("]"),
            ),
            Self::PushFeltList(values) => inst_with_pretty_felt_params("push", values),
            Self::Locaddr(value) => inst_with_imm("locaddr", value),
            Self::Sdepth => const_text("sdepth"),
            Self::Caller => const_text("caller"),
            Self::Clk => const_text("clk"),

            Self::MemLoad => const_text("mem_load"),
            Self::MemLoadImm(value) => inst_with_imm("mem_load", value),
            Self::MemLoadW => const_text("mem_loadw"),
            Self::MemLoadWImm(value) => inst_with_imm("mem_loadw", value),
            Self::LocLoad(value) => inst_with_imm("loc_load", value),
            Self::LocLoadW(value) => inst_with_imm("loc_loadw", value),

            Self::MemStore => const_text("mem_store"),
            Self::MemStoreImm(value) => inst_with_imm("mem_store", value),
            Self::LocStore(value) => inst_with_imm("loc_store", value),
            Self::MemStoreW => const_text("mem_storew"),
            Self::MemStoreWImm(value) => inst_with_imm("mem_storew", value),
            Self::LocStoreW(value) => inst_with_imm("loc_storew", value),

            Self::MemStream => const_text("mem_stream"),
            Self::AdvPipe => const_text("adv_pipe"),

            Self::AdvPush(value) => inst_with_imm("adv_push", value),
            Self::AdvLoadW => const_text("adv_loadw"),

            Self::SysEvent(sys_event) => inst_with_imm("adv", sys_event),

            // ----- cryptographic operations -----------------------------------------------------
            Self::Hash => const_text("hash"),
            Self::HMerge => const_text("hmerge"),
            Self::HPerm => const_text("hperm"),
            Self::MTreeGet => const_text("mtree_get"),
            Self::MTreeSet => const_text("mtree_set"),
            Self::MTreeMerge => const_text("mtree_merge"),
            Self::MTreeVerify => const_text("mtree_verify"),
            Self::MTreeVerifyWithError(err_code) => flatten(
                const_text("mtree_verify.err") + const_text("=") + text(format!("\"{err_code}\"")),
            ),

            // ----- STARK proof verification -----------------------------------------------------
            Self::FriExt2Fold4 => const_text("fri_ext2fold4"),
            Self::HornerBase => const_text("horner_eval_base"),
            Self::HornerExt => const_text("horner_eval_ext"),
            Self::EvalCircuit => const_text("eval_circuit"),

            // ----- exec / call ------------------------------------------------------------------
            Self::Exec(InvocationTarget::MastRoot(root)) => flatten(
                const_text("exec")
                    + const_text(".")
                    + text(format!("{:#x}", DisplayHex(root.as_bytes().as_slice()))),
            ),
            Self::Exec(InvocationTarget::ProcedureName(name)) => {
                flatten(const_text("exec") + const_text(".") + text(name))
            },
            Self::Exec(InvocationTarget::ProcedurePath { name, module }) => {
                const_text("exec") + const_text(".") + text(format!("{module}::{name}"))
            },
            Self::Exec(InvocationTarget::AbsoluteProcedurePath { name, path }) => {
                const_text("exec") + const_text(".") + text(format!("::{path}::{name}"))
            },
            Self::Call(InvocationTarget::MastRoot(root)) => {
                const_text("call")
                    + const_text(".")
                    + text(format!("{:#x}", DisplayHex(root.as_bytes().as_slice())))
            },
            Self::Call(InvocationTarget::ProcedureName(name)) => {
                flatten(const_text("call") + const_text(".") + text(name))
            },
            Self::Call(InvocationTarget::ProcedurePath { name, module }) => {
                const_text("call") + const_text(".") + text(format!("{module}::{name}"))
            },
            Self::Call(InvocationTarget::AbsoluteProcedurePath { name, path }) => {
                const_text("call") + const_text(".") + text(format!("::{path}::{name}"))
            },
            Self::SysCall(InvocationTarget::MastRoot(root)) => {
                const_text("syscall")
                    + const_text(".")
                    + text(format!("{:#x}", DisplayHex(root.as_bytes().as_slice())))
            },
            Self::SysCall(InvocationTarget::ProcedureName(name)) => {
                flatten(const_text("syscall") + const_text(".") + text(format!("{name}")))
            },
            Self::SysCall(InvocationTarget::ProcedurePath { name, module }) => {
                const_text("syscall") + const_text(".") + text(format!("{module}::{name}"))
            },
            Self::SysCall(InvocationTarget::AbsoluteProcedurePath { name, path }) => {
                const_text("syscall") + const_text(".") + text(format!("::{path}::{name}"))
            },
            Self::DynExec => const_text("dynexec"),
            Self::DynCall => const_text("dyncall"),
            Self::ProcRef(InvocationTarget::MastRoot(_)) => {
                panic!("invalid procref instruction: expected name not MAST root")
            },
            Self::ProcRef(InvocationTarget::ProcedureName(name)) => {
                flatten(const_text("procref") + const_text(".") + text(name))
            },
            Self::ProcRef(InvocationTarget::ProcedurePath { name, module }) => {
                flatten(const_text("procref") + const_text(".") + text(format!("{module}::{name}")))
            },
            Self::ProcRef(InvocationTarget::AbsoluteProcedurePath { name, path }) => {
                flatten(const_text("procref") + const_text(".") + text(format!("::{path}::{name}")))
            },

            // ----- debug decorators -------------------------------------------------------------
            Self::Breakpoint => const_text("breakpoint"),
            Self::Debug(options) => inst_with_imm("debug", options),

            // ----- event decorators -------------------------------------------------------------
            Self::Emit => const_text("emit"),
            Self::EmitImm(value) => inst_with_felt_imm("emit", value),
            Self::Trace(value) => inst_with_imm("trace", value),
        }
    }
}

fn inst_with_imm(name: &'static str, imm: &dyn PrettyPrint) -> Document {
    use crate::prettier::*;

    let imm = imm.render();

    flatten(const_text(name) + const_text(".") + imm)
}

fn inst_with_felt_imm(name: &'static str, imm: &Immediate<crate::Felt>) -> Document {
    use crate::prettier::*;

    let value = match imm {
        Immediate::Value(value) => display(*value),
        Immediate::Constant(name) => text(name),
    };

    flatten(const_text(name) + const_text(".") + value)
}

fn inst_with_pretty_felt_params(inst: &'static str, params: &[crate::Felt]) -> Document {
    use crate::prettier::*;

    let single_line = text(inst)
        + const_text(".")
        + params
            .iter()
            .copied()
            .map(display)
            .reduce(|acc, doc| acc + const_text(".") + doc)
            .unwrap_or_default();

    let multi_line = params
        .iter()
        .copied()
        .map(|v| text(inst) + const_text(".") + display(v))
        .reduce(|acc, doc| acc + nl() + doc)
        .unwrap_or_default();
    single_line | multi_line
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::crypto::hash::Rpo256;
    use miden_debug_types::Span;

    use crate::{Felt, ast::*};

    #[test]
    fn test_instruction_display() {
        let instruction = format!("{}", Instruction::Assert);
        assert_eq!("assert", instruction);

        let instruction = format!("{}", Instruction::Add);
        assert_eq!("add", instruction);

        let instruction = format!("{}", Instruction::AddImm(Felt::new(5).into()));
        assert_eq!("add.5", instruction);

        let instruction = format!("{}", Instruction::ExpBitLength(32));
        assert_eq!("exp.u32", instruction);

        let instruction = format!(
            "{}",
            Instruction::PushFeltList(vec![Felt::new(3), Felt::new(4), Felt::new(8), Felt::new(9)])
        );
        assert_eq!("push.3.4.8.9", instruction);
        let instruction = format!(
            "{}",
            Instruction::Push(Immediate::Value(miden_debug_types::Span::unknown(
                crate::parser::IntValue::U8(3)
            )))
        );
        assert_eq!("push.3", instruction);

        let digest = Rpo256::hash(b"std::math::u64::add");
        let target = InvocationTarget::MastRoot(Span::unknown(digest));
        let instruction = format!("{}", Instruction::Exec(target));
        assert_eq!(
            "exec.0x90b3926941061b28638b6cc0bbdb3bcb335e834dc9ab8044250875055202d2fe",
            instruction
        );
    }
}
