use alloc::{string::String, vec::Vec};

use miden_assembly_syntax_cst::{
    SyntaxKind,
    ast::{AstNode, Instruction as CstInstruction},
};
use miden_debug_types::{SourceSpan, Span};

use super::context::LoweringContext;
use crate::ast::{self, DebugOptions, Immediate, Instruction, SystemEventNode};

pub(super) fn try_lower_instruction(
    context: &LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Option<Vec<ast::Op>> {
    let text = compact_instruction_text(instruction)?;
    let span = context.parse().span_for_node(instruction.syntax());
    let inst = lower_primitive_instruction(span, text.as_str())?;
    Some(vec![ast::Op::Inst(Span::new(span, inst))])
}

fn compact_instruction_text(instruction: &CstInstruction) -> Option<String> {
    let mut text = String::new();
    for token in instruction
        .syntax()
        .children_with_tokens()
        .filter_map(|element| element.into_token())
    {
        if token.kind().is_trivia() {
            continue;
        }

        match token.kind() {
            SyntaxKind::Ident | SyntaxKind::Dot => text.push_str(token.text()),
            _ => return None,
        }
    }

    (!text.is_empty()).then_some(text)
}

fn lower_primitive_instruction(span: SourceSpan, text: &str) -> Option<Instruction> {
    let instruction = match text {
        "add" => Instruction::Add,
        "adv.insert_hdword" => Instruction::SysEvent(SystemEventNode::InsertHdword),
        "adv.insert_hdword_d" => Instruction::SysEvent(SystemEventNode::InsertHdwordWithDomain),
        "adv.insert_hperm" => Instruction::SysEvent(SystemEventNode::InsertHperm),
        "adv.insert_hqword" => Instruction::SysEvent(SystemEventNode::InsertHqword),
        "adv.insert_mem" => Instruction::SysEvent(SystemEventNode::InsertMem),
        "adv.has_mapkey" => Instruction::SysEvent(SystemEventNode::HasMapKey),
        "adv.push_mapval" => Instruction::SysEvent(SystemEventNode::PushMapVal),
        "adv.push_mapval_count" => Instruction::SysEvent(SystemEventNode::PushMapValCount),
        "adv.push_mapvaln" => Instruction::SysEvent(SystemEventNode::PushMapValN0),
        "adv.push_mtnode" => Instruction::SysEvent(SystemEventNode::PushMtNode),
        "adv_loadw" => Instruction::AdvLoadW,
        "adv_pipe" => Instruction::AdvPipe,
        "and" => Instruction::And,
        "assert" => Instruction::Assert,
        "assert_eq" => Instruction::AssertEq,
        "assert_eqw" => Instruction::AssertEqw,
        "assertz" => Instruction::Assertz,
        "caller" => Instruction::Caller,
        "cdrop" => Instruction::CDrop,
        "cdropw" => Instruction::CDropW,
        "clk" => Instruction::Clk,
        "crypto_stream" => Instruction::CryptoStream,
        "cswap" => Instruction::CSwap,
        "cswapw" => Instruction::CSwapW,
        "debug.adv_stack" => {
            Instruction::Debug(DebugOptions::AdvStackTop(zero_u16_immediate(span)))
        },
        "debug.local" => Instruction::Debug(DebugOptions::LocalAll),
        "debug.mem" => Instruction::Debug(DebugOptions::MemAll),
        "debug.stack" => Instruction::Debug(DebugOptions::StackAll),
        "div" => Instruction::Div,
        "drop" => Instruction::Drop,
        "dropw" => Instruction::DropW,
        "dup" => Instruction::Dup0,
        "dupw" => Instruction::DupW0,
        "dyncall" => Instruction::DynCall,
        "dynexec" => Instruction::DynExec,
        "emit" => Instruction::Emit,
        "eq" => Instruction::Eq,
        "eqw" => Instruction::Eqw,
        "eval_circuit" => Instruction::EvalCircuit,
        "exp" => Instruction::Exp,
        "ext2add" => Instruction::Ext2Add,
        "ext2div" => Instruction::Ext2Div,
        "ext2inv" => Instruction::Ext2Inv,
        "ext2mul" => Instruction::Ext2Mul,
        "ext2neg" => Instruction::Ext2Neg,
        "ext2sub" => Instruction::Ext2Sub,
        "fri_ext2fold4" => Instruction::FriExt2Fold4,
        "gt" => Instruction::Gt,
        "gte" => Instruction::Gte,
        "hash" => Instruction::Hash,
        "hmerge" => Instruction::HMerge,
        "hperm" => Instruction::HPerm,
        "horner_eval_base" => Instruction::HornerBase,
        "horner_eval_ext" => Instruction::HornerExt,
        "ilog2" => Instruction::ILog2,
        "inv" => Instruction::Inv,
        "is_odd" => Instruction::IsOdd,
        "log_precompile" => Instruction::LogPrecompile,
        "lt" => Instruction::Lt,
        "lte" => Instruction::Lte,
        "mem_load" => Instruction::MemLoad,
        "mem_loadw_be" => Instruction::MemLoadWBe,
        "mem_loadw_le" => Instruction::MemLoadWLe,
        "mem_store" => Instruction::MemStore,
        "mem_storew_be" => Instruction::MemStoreWBe,
        "mem_storew_le" => Instruction::MemStoreWLe,
        "mem_stream" => Instruction::MemStream,
        "mtree_get" => Instruction::MTreeGet,
        "mtree_merge" => Instruction::MTreeMerge,
        "mtree_set" => Instruction::MTreeSet,
        "mtree_verify" => Instruction::MTreeVerify,
        "mul" => Instruction::Mul,
        "neg" => Instruction::Neg,
        "neq" => Instruction::Neq,
        "nop" => Instruction::Nop,
        "not" => Instruction::Not,
        "or" => Instruction::Or,
        "padw" => Instruction::PadW,
        "pow2" => Instruction::Pow2,
        "reversew" => Instruction::Reversew,
        "reversedw" => Instruction::Reversedw,
        "sdepth" => Instruction::Sdepth,
        "sub" => Instruction::Sub,
        "swap" => Instruction::Swap1,
        "swapdw" => Instruction::SwapDw,
        "swapw" => Instruction::SwapW1,
        "u32and" => Instruction::U32And,
        "u32assert" => Instruction::U32Assert,
        "u32assert2" => Instruction::U32Assert2,
        "u32assertw" => Instruction::U32AssertW,
        "u32cast" => Instruction::U32Cast,
        "u32clo" => Instruction::U32Clo,
        "u32clz" => Instruction::U32Clz,
        "u32cto" => Instruction::U32Cto,
        "u32ctz" => Instruction::U32Ctz,
        "u32div" => Instruction::U32Div,
        "u32divmod" => Instruction::U32DivMod,
        "u32gt" => Instruction::U32Gt,
        "u32gte" => Instruction::U32Gte,
        "u32lt" => Instruction::U32Lt,
        "u32lte" => Instruction::U32Lte,
        "u32max" => Instruction::U32Max,
        "u32min" => Instruction::U32Min,
        "u32mod" => Instruction::U32Mod,
        "u32not" => Instruction::U32Not,
        "u32or" => Instruction::U32Or,
        "u32overflowing_add" => Instruction::U32OverflowingAdd,
        "u32overflowing_add3" => Instruction::U32OverflowingAdd3,
        "u32overflowing_sub" => Instruction::U32OverflowingSub,
        "u32popcnt" => Instruction::U32Popcnt,
        "u32rotl" => Instruction::U32Rotl,
        "u32rotr" => Instruction::U32Rotr,
        "u32shl" => Instruction::U32Shl,
        "u32shr" => Instruction::U32Shr,
        "u32split" => Instruction::U32Split,
        "u32test" => Instruction::U32Test,
        "u32testw" => Instruction::U32TestW,
        "u32widening_add" => Instruction::U32WideningAdd,
        "u32widening_add3" => Instruction::U32WideningAdd3,
        "u32widening_madd" => Instruction::U32WideningMadd,
        "u32widening_mul" => Instruction::U32WideningMul,
        "u32wrapping_add" => Instruction::U32WrappingAdd,
        "u32wrapping_add3" => Instruction::U32WrappingAdd3,
        "u32wrapping_madd" => Instruction::U32WrappingMadd,
        "u32wrapping_mul" => Instruction::U32WrappingMul,
        "u32wrapping_sub" => Instruction::U32WrappingSub,
        "u32xor" => Instruction::U32Xor,
        "xor" => Instruction::Xor,
        _ => return None,
    };

    Some(instruction)
}

fn zero_u16_immediate(span: SourceSpan) -> ast::ImmU16 {
    Immediate::Value(Span::new(span, 0u16))
}
