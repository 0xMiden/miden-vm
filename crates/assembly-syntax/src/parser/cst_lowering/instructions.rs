use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax_cst::{
    SyntaxKind, SyntaxToken,
    ast::{AstNode, Instruction as CstInstruction},
};
use miden_core::events::EventId;
use miden_debug_types::{SourceSpan, Span};

use super::{
    context::LoweringContext,
    fragments::{ParsedNumeric, lower_u32_immediate_token, parse_decimal_u64, parse_numeric_token},
};
use crate::{
    Felt, Word,
    ast::{self, DebugOptions, Immediate, Instruction, SystemEventNode},
    parser::{LiteralErrorKind, ParsingError, PushValue},
};

pub(super) fn try_lower_instruction(
    context: &mut LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let span = context.parse().span_for_node(instruction.syntax());
    if let Some(compact) = CompactInstruction::parse(instruction) {
        if let Some(error) = deprecated_instruction_error(span, &compact) {
            return Err(error);
        }

        if let Some(inst) = lower_primitive_instruction(compact.text.as_str()) {
            return Ok(Some(vec![inst_op(span, inst)]));
        }

        if let Some(ops) = lower_immediate_instruction(context, span, &compact)? {
            return Ok(Some(ops));
        }
    }

    lower_extended_instruction(context, instruction)
}

struct CompactInstruction {
    text: String,
    segments: Vec<SyntaxToken>,
}

impl CompactInstruction {
    fn parse(instruction: &CstInstruction) -> Option<Self> {
        let mut text = String::new();
        let mut segments = Vec::new();
        for token in instruction
            .syntax()
            .children_with_tokens()
            .filter_map(|element| element.into_token())
        {
            if token.kind().is_trivia() {
                continue;
            }

            match token.kind() {
                SyntaxKind::Ident | SyntaxKind::Number | SyntaxKind::Dot => {
                    text.push_str(token.text());
                    if token.kind() != SyntaxKind::Dot {
                        segments.push(token);
                    }
                },
                _ => return None,
            }
        }

        (!text.is_empty()).then_some(Self { text, segments })
    }

    fn texts(&self) -> Vec<&str> {
        self.segments.iter().map(|token| token.text()).collect()
    }

    fn token(&self, index: usize) -> &SyntaxToken {
        &self.segments[index]
    }
}

fn lower_immediate_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    compact: &CompactInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let texts = compact.texts();
    match texts.as_slice() {
        ["eq", _] => lower_eq_like(context, span, compact.token(1), Instruction::EqImm),
        ["neq", _] => lower_eq_like(context, span, compact.token(1), Instruction::NeqImm),
        ["lt", _] => lower_int_compare(context, span, compact.token(1), Instruction::Lt),
        ["lte", _] => lower_int_compare(context, span, compact.token(1), Instruction::Lte),
        ["gt", _] => lower_int_compare(context, span, compact.token(1), Instruction::Gt),
        ["gte", _] => lower_int_compare(context, span, compact.token(1), Instruction::Gte),
        ["add", _] => lower_foldable_felt(context, span, compact.token(1), FeltFoldKind::Add),
        ["sub", _] => lower_foldable_felt(context, span, compact.token(1), FeltFoldKind::Sub),
        ["mul", _] => lower_foldable_felt(context, span, compact.token(1), FeltFoldKind::Mul),
        ["div", _] => lower_foldable_felt(context, span, compact.token(1), FeltFoldKind::Div),
        ["exp", _] => lower_exp_family(context, span, compact.token(1)),
        ["mem_load", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemLoadImm)
        },
        ["mem_loadw_be", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemLoadWBeImm)
        },
        ["mem_loadw_le", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemLoadWLeImm)
        },
        ["mem_store", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemStoreImm)
        },
        ["mem_storew_be", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemStoreWBeImm)
        },
        ["mem_storew_le", _] => {
            lower_u32_instruction(context, span, compact.token(1), Instruction::MemStoreWLeImm)
        },
        ["locaddr", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::Locaddr)
        },
        ["loc_load", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocLoad)
        },
        ["loc_loadw_be", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocLoadWBe)
        },
        ["loc_loadw_le", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocLoadWLe)
        },
        ["loc_store", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocStore)
        },
        ["loc_storew_be", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocStoreWBe)
        },
        ["loc_storew_le", _] => {
            lower_u16_instruction(context, span, compact.token(1), Instruction::LocStoreWLe)
        },
        ["adv_push", _] => lower_adv_push(span, compact.token(1)),
        ["dup", _] => lower_dup(span, compact.token(1)),
        ["dupw", _] => lower_dupw(span, compact.token(1)),
        ["swap", _] => lower_swap(span, compact.token(1)),
        ["swapw", _] => lower_swapw(span, compact.token(1)),
        ["movdn", _] => lower_movdn(span, compact.token(1)),
        ["movdnw", _] => lower_movdnw(span, compact.token(1)),
        ["movup", _] => lower_movup(span, compact.token(1)),
        ["movupw", _] => lower_movupw(span, compact.token(1)),
        ["u32div", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Div),
        ["u32divmod", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::DivMod)
        },
        ["u32mod", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Mod),
        ["u32and", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::And),
        ["u32or", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Or),
        ["u32xor", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Xor),
        ["u32not", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Not),
        ["u32wrapping_add", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::WrappingAdd)
        },
        ["u32wrapping_sub", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::WrappingSub)
        },
        ["u32wrapping_mul", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::WrappingMul)
        },
        ["u32overflowing_add", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::OverflowingAdd)
        },
        ["u32widening_add", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::WideningAdd)
        },
        ["u32overflowing_sub", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::OverflowingSub)
        },
        ["u32widening_mul", _] => {
            lower_foldable_u32(context, span, compact.token(1), U32FoldKind::WideningMul)
        },
        ["u32shl", _] => lower_shift_u32(context, span, compact.token(1), Instruction::U32ShlImm),
        ["u32shr", _] => lower_shift_u32(context, span, compact.token(1), Instruction::U32ShrImm),
        ["u32rotl", _] => lower_shift_u32(context, span, compact.token(1), Instruction::U32RotlImm),
        ["u32rotr", _] => lower_shift_u32(context, span, compact.token(1), Instruction::U32RotrImm),
        ["u32lt", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Lt),
        ["u32lte", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Lte),
        ["u32gt", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Gt),
        ["u32gte", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Gte),
        ["u32min", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Min),
        ["u32max", _] => lower_foldable_u32(context, span, compact.token(1), U32FoldKind::Max),
        ["adv", "push_mapvaln", _] => lower_push_mapvaln(span, compact.token(2)),
        _ => Ok(None),
    }
}

fn lower_primitive_instruction(text: &str) -> Option<Instruction> {
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
        "debug.adv_stack" => Instruction::Debug(DebugOptions::AdvStackTop(0u16.into())),
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

fn deprecated_instruction_error(
    span: SourceSpan,
    compact: &CompactInstruction,
) -> Option<ParsingError> {
    let instruction = compact.texts().first().copied()?;
    let replacement = match instruction {
        "mem_loadw" => "mem_loadw_be",
        "mem_storew" => "mem_storew_be",
        "loc_loadw" => "loc_loadw_be",
        "loc_storew" => "loc_storew_be",
        _ => return None,
    };

    Some(ParsingError::DeprecatedInstruction {
        span,
        instruction: instruction.to_string(),
        replacement: replacement.to_string(),
    })
}

fn lower_extended_instruction(
    context: &mut LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let tokens = significant_tokens(instruction);
    let Some(first) = tokens.first() else {
        return Ok(None);
    };
    if first.kind() != SyntaxKind::Ident {
        return Ok(None);
    }

    let span = context.parse().span_for_node(instruction.syntax());
    match first.text() {
        "push" => lower_push_instruction(context, span, &tokens),
        "exec" => lower_invocation_instruction(context, span, &tokens, Instruction::Exec),
        "call" => lower_invocation_instruction(context, span, &tokens, Instruction::Call),
        "syscall" => lower_invocation_instruction(context, span, &tokens, Instruction::SysCall),
        "procref" => lower_invocation_instruction(context, span, &tokens, Instruction::ProcRef),
        "debug" => lower_debug_instruction(context, span, &tokens),
        "emit" => lower_emit_instruction(context, span, &tokens),
        "trace" => lower_trace_instruction(context, span, &tokens),
        "assert" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "assert",
            Instruction::AssertWithError,
        ),
        "assertz" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "assertz",
            Instruction::AssertzWithError,
        ),
        "assert_eq" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "assert_eq",
            Instruction::AssertEqWithError,
        ),
        "assert_eqw" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "assert_eqw",
            Instruction::AssertEqwWithError,
        ),
        "u32assert" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "u32assert",
            Instruction::U32AssertWithError,
        ),
        "u32assert2" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "u32assert2",
            Instruction::U32Assert2WithError,
        ),
        "u32assertw" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "u32assertw",
            Instruction::U32AssertWWithError,
        ),
        "mtree_verify" => lower_error_code_instruction(
            context,
            span,
            &tokens,
            "mtree_verify",
            Instruction::MTreeVerifyWithError,
        ),
        _ => Ok(None),
    }
}

fn lower_push_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if !matches!(tokens, [push, dot, ..] if push.kind() == SyntaxKind::Ident
        && push.text() == "push"
        && dot.kind() == SyntaxKind::Dot)
    {
        return Ok(None);
    }

    let rest = &tokens[2..];
    if rest.is_empty() {
        return Ok(None);
    }

    if let Some((imm, consumed, imm_span)) = lower_word_immediate(context, rest)? {
        if consumed == rest.len() {
            let push = match imm {
                Immediate::Constant(name) => Immediate::Constant(name),
                Immediate::Value(value) => Immediate::Value(value.map(PushValue::Word)),
            };
            return Ok(Some(vec![inst_op(instruction_span, Instruction::Push(push))]));
        }

        if rest.get(consumed).is_some_and(|token| token.kind() == SyntaxKind::LBracket)
            && let Some((range, used)) = parse_push_slice_range(context, rest, consumed)?
            && consumed + used == rest.len()
        {
            return Ok(Some(vec![inst_op(
                instruction_span,
                Instruction::PushSlice(imm.with_span(imm_span), range),
            )]));
        }
    }

    lower_push_list(context, instruction_span, rest)
}

fn lower_invocation_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
    build: fn(ast::InvocationTarget) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if tokens.len() < 3 || tokens[1].kind() != SyntaxKind::Dot {
        return Ok(None);
    }

    let target = lower_invocation_target(context, &tokens[2..])?;
    Ok(Some(vec![inst_op(instruction_span, build(target))]))
}

fn lower_debug_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if tokens.len() < 3
        || tokens[0].kind() != SyntaxKind::Ident
        || tokens[0].text() != "debug"
        || tokens[1].kind() != SyntaxKind::Dot
        || tokens[2].kind() != SyntaxKind::Ident
    {
        return Ok(None);
    }

    let option = match tokens[2].text() {
        "stack" => match &tokens[3..] {
            [] => return Ok(None),
            [dot, value] if dot.kind() == SyntaxKind::Dot => {
                let imm = lower_u8_immediate(context, value)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(value),
                        message: "expected a u8 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::StackTop(imm)
            },
            _ => return Ok(None),
        },
        "mem" => match &tokens[3..] {
            [] => return Ok(None),
            [dot, value] if dot.kind() == SyntaxKind::Dot => {
                let imm = lower_u32_immediate(context, value)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(value),
                        message: "expected a u32 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::MemInterval(imm.clone(), imm)
            },
            [dot1, first, dot2, second]
                if dot1.kind() == SyntaxKind::Dot && dot2.kind() == SyntaxKind::Dot =>
            {
                let first = lower_u32_immediate(context, first)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(first),
                        message: "expected a u32 literal or constant reference".to_string(),
                    }
                })?;
                let second = lower_u32_immediate(context, second)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(second),
                        message: "expected a u32 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::MemInterval(first, second)
            },
            _ => return Ok(None),
        },
        "local" => match &tokens[3..] {
            [] => return Ok(None),
            [dot, value] if dot.kind() == SyntaxKind::Dot => {
                let imm = lower_u16_immediate(context, value)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(value),
                        message: "expected a u16 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::LocalRangeFrom(imm)
            },
            [dot1, first, dot2, second]
                if dot1.kind() == SyntaxKind::Dot && dot2.kind() == SyntaxKind::Dot =>
            {
                let first = lower_u16_immediate(context, first)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(first),
                        message: "expected a u16 literal or constant reference".to_string(),
                    }
                })?;
                let second = lower_u16_immediate(context, second)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(second),
                        message: "expected a u16 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::LocalInterval(first, second)
            },
            _ => return Ok(None),
        },
        "adv_stack" => match &tokens[3..] {
            [] => return Ok(None),
            [dot, value] if dot.kind() == SyntaxKind::Dot => {
                let imm = lower_u16_immediate(context, value)?.ok_or_else(|| {
                    ParsingError::InvalidSyntax {
                        span: context.parse().span_for_token(value),
                        message: "expected a u16 literal or constant reference".to_string(),
                    }
                })?;
                DebugOptions::AdvStackTop(imm)
            },
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };

    Ok(Some(vec![inst_op(instruction_span, Instruction::Debug(option))]))
}

fn lower_emit_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if tokens.len() < 3
        || tokens[0].kind() != SyntaxKind::Ident
        || tokens[0].text() != "emit"
        || tokens[1].kind() != SyntaxKind::Dot
    {
        return Ok(None);
    }

    match &tokens[2..] {
        [name] if name.kind() == SyntaxKind::Ident && name.text() != "event" => {
            let name = context.lower_constant_ident_token(name)?;
            Ok(Some(vec![inst_op(
                instruction_span,
                Instruction::EmitImm(Immediate::Constant(name)),
            )]))
        },
        [event, lparen, string, rparen]
            if event.kind() == SyntaxKind::Ident
                && event.text() == "event"
                && lparen.kind() == SyntaxKind::LParen
                && matches!(string.kind(), SyntaxKind::QuotedString | SyntaxKind::QuotedIdent)
                && rparen.kind() == SyntaxKind::RParen =>
        {
            let value = unquote_string_token(string, context.parse().span_for_token(string))?;
            let event_id = EventId::from_name(value.as_ref()).as_felt();
            Ok(Some(vec![inst_op(
                instruction_span,
                Instruction::EmitImm(Immediate::Value(Span::new(instruction_span, event_id))),
            )]))
        },
        _ => Ok(None),
    }
}

fn lower_trace_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if !matches!(tokens, [trace, dot, _value] if trace.kind() == SyntaxKind::Ident
        && trace.text() == "trace"
        && dot.kind() == SyntaxKind::Dot)
    {
        return Ok(None);
    }

    let value =
        lower_u32_immediate(context, &tokens[2])?.ok_or_else(|| ParsingError::InvalidSyntax {
            span: context.parse().span_for_token(&tokens[2]),
            message: "expected a u32 literal or constant reference".to_string(),
        })?;
    Ok(Some(vec![inst_op(instruction_span, Instruction::Trace(value))]))
}

fn lower_error_code_instruction(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
    keyword: &str,
    build: fn(ast::ErrorMsg) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if !matches!(
        tokens,
        [kw, dot, err, eq, _]
            if kw.kind() == SyntaxKind::Ident
                && kw.text() == keyword
                && dot.kind() == SyntaxKind::Dot
                && err.kind() == SyntaxKind::Ident
                && err.text() == "err"
                && eq.kind() == SyntaxKind::Equal
    ) {
        return Ok(None);
    }

    let value = lower_error_msg(context, &tokens[4])?;
    Ok(Some(vec![inst_op(instruction_span, build(value))]))
}

fn lower_invocation_target(
    context: &mut LoweringContext<'_>,
    tokens: &[SyntaxToken],
) -> Result<ast::InvocationTarget, ParsingError> {
    let span = span_for_tokens(context, tokens);
    if tokens.len() == 1 && tokens[0].kind() == SyntaxKind::Number {
        return match parse_numeric_token(span, tokens[0].text())? {
            ParsedNumeric::Word(value) => {
                Ok(ast::InvocationTarget::MastRoot(Span::new(span, Word::from(value.0))))
            },
            ParsedNumeric::Int(_)
                if tokens[0].text().starts_with("0x") || tokens[0].text().starts_with("0X") =>
            {
                Err(ParsingError::InvalidMastRoot { span })
            },
            ParsedNumeric::Int(_) => Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a procedure name, path, or MAST root digest".to_string(),
            }),
        };
    }

    if !tokens.iter().all(|token| {
        matches!(
            token.kind(),
            SyntaxKind::Ident
                | SyntaxKind::QuotedIdent
                | SyntaxKind::SpecialIdent
                | SyntaxKind::ColonColon
        )
    }) {
        return Err(ParsingError::InvalidSyntax {
            span,
            message: "expected a procedure name, path, or MAST root digest".to_string(),
        });
    }

    let raw = tokens.iter().map(SyntaxToken::text).collect::<String>();
    let path = context.lower_raw_path(span, &raw)?;
    if let Some(name) = path.as_ident() {
        Ok(ast::InvocationTarget::Symbol(name.with_span(span)))
    } else {
        Ok(ast::InvocationTarget::Path(path))
    }
}

fn lower_push_list(
    context: &mut LoweringContext<'_>,
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let mut ops = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        let imm_span = context.parse().span_for_token(token);
        let imm = match token.kind() {
            SyntaxKind::Ident => Immediate::Constant(context.lower_constant_ident_token(token)?),
            SyntaxKind::Number => match parse_numeric_token(imm_span, token.text())? {
                ParsedNumeric::Int(value) => Immediate::Value(Span::new(imm_span, value)),
                ParsedNumeric::Word(_) => return Ok(None),
            },
            _ => return Ok(None),
        };

        let span = if ops.is_empty() {
            SourceSpan::new(instruction_span.source_id(), instruction_span.start()..imm_span.end())
        } else {
            imm_span
        };
        ops.push(inst_op(span, Instruction::Push(imm.map(PushValue::Int))));

        index += 1;
        if index == tokens.len() {
            break;
        }
        if tokens[index].kind() != SyntaxKind::Dot {
            return Ok(None);
        }
        index += 1;
    }

    if ops.len() > 16 {
        return Err(ParsingError::PushOverflow { span: instruction_span, count: ops.len() });
    }
    Ok(Some(ops))
}

fn lower_word_immediate(
    context: &mut LoweringContext<'_>,
    tokens: &[SyntaxToken],
) -> Result<Option<(Immediate<crate::parser::WordValue>, usize, SourceSpan)>, ParsingError> {
    let Some(first) = tokens.first() else {
        return Ok(None);
    };

    match first.kind() {
        SyntaxKind::Ident => {
            let ident = context.lower_constant_ident_token(first)?;
            Ok(Some((Immediate::Constant(ident), 1, context.parse().span_for_token(first))))
        },
        SyntaxKind::Number => {
            let span = context.parse().span_for_token(first);
            match parse_numeric_token(span, first.text())? {
                ParsedNumeric::Word(word) => {
                    Ok(Some((Immediate::Value(Span::new(span, word)), 1, span)))
                },
                ParsedNumeric::Int(_) => Ok(None),
            }
        },
        SyntaxKind::LBracket => lower_word_literal(context, tokens).map(|option| {
            option.map(|(value, consumed, span)| {
                (Immediate::Value(Span::new(span, value)), consumed, span)
            })
        }),
        _ => Ok(None),
    }
}

fn lower_word_literal(
    context: &mut LoweringContext<'_>,
    tokens: &[SyntaxToken],
) -> Result<Option<(crate::parser::WordValue, usize, SourceSpan)>, ParsingError> {
    if tokens.first().is_none_or(|token| token.kind() != SyntaxKind::LBracket) {
        return Ok(None);
    }
    if tokens.len() < 9 {
        return Ok(None);
    }

    let mut index = 1usize;
    let mut elements = [Felt::ZERO; 4];
    for (position, element) in elements.iter_mut().enumerate() {
        let Some(token) = tokens.get(index) else {
            return Ok(None);
        };
        if token.kind() != SyntaxKind::Number {
            return Ok(None);
        }
        let span = context.parse().span_for_token(token);
        match parse_numeric_token(span, token.text())? {
            ParsedNumeric::Int(value) => *element = Felt::new(value.as_int()),
            ParsedNumeric::Word(_) => {
                return Err(ParsingError::InvalidSyntax {
                    span,
                    message: "expected a felt-sized integer literal".to_string(),
                });
            },
        }
        index += 1;
        if position < 3 {
            if tokens.get(index).is_none_or(|token| token.kind() != SyntaxKind::Comma) {
                return Ok(None);
            }
            index += 1;
        }
    }

    let Some(rbracket) = tokens.get(index) else {
        return Ok(None);
    };
    if rbracket.kind() != SyntaxKind::RBracket {
        return Ok(None);
    }
    let span = join_spans(
        context.parse().span_for_token(&tokens[0]),
        context.parse().span_for_token(rbracket),
    );
    Ok(Some((crate::parser::WordValue(elements), index + 1, span)))
}

fn parse_push_slice_range(
    context: &LoweringContext<'_>,
    tokens: &[SyntaxToken],
    start: usize,
) -> Result<Option<(core::ops::Range<usize>, usize)>, ParsingError> {
    if tokens.get(start).is_none_or(|token| token.kind() != SyntaxKind::LBracket) {
        return Ok(None);
    }

    let Some(first) = tokens.get(start + 1) else {
        return Ok(None);
    };
    let Some(begin) = parse_decimal_u64(first.text()) else {
        return Ok(None);
    };
    let begin = usize::try_from(begin).ok().unwrap_or(usize::MAX);

    match (tokens.get(start + 2), tokens.get(start + 3), tokens.get(start + 4)) {
        (Some(rbracket), _, _) if rbracket.kind() == SyntaxKind::RBracket => {
            let end = begin.checked_add(1).ok_or(ParsingError::ImmediateOutOfRange {
                span: join_spans(
                    context.parse().span_for_token(&tokens[start]),
                    context.parse().span_for_token(rbracket),
                ),
                range: 0..usize::MAX,
            })?;
            Ok(Some((core::ops::Range { start: begin, end }, 3)))
        },
        (Some(dotdot), Some(end), Some(rbracket))
            if dotdot.kind() == SyntaxKind::DotDot && rbracket.kind() == SyntaxKind::RBracket =>
        {
            let Some(end) = parse_decimal_u64(end.text()) else {
                return Ok(None);
            };
            let end = usize::try_from(end).ok().unwrap_or(usize::MAX);
            Ok(Some((core::ops::Range { start: begin, end }, 5)))
        },
        _ => Ok(None),
    }
}

fn lower_error_msg(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<ast::ErrorMsg, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::QuotedString | SyntaxKind::QuotedIdent => {
            let value = unquote_string_token(token, span)?;
            Ok(Immediate::Value(Span::new(span, value)))
        },
        SyntaxKind::Ident => Ok(Immediate::Constant(context.lower_constant_ident_token(token)?)),
        _ => Err(ParsingError::InvalidSyntax {
            span,
            message: "expected a quoted string or constant reference".to_string(),
        }),
    }
}

fn lower_u8_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<ast::ImmU8>, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(Some(Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            let Some(value) = parse_decimal_u64(token.text()) else {
                return Ok(None);
            };
            let value = u8::try_from(value).map_err(|_| ParsingError::ImmediateOutOfRange {
                span,
                range: 0..(u8::MAX as usize + 1),
            })?;
            Ok(Some(Immediate::Value(Span::new(span, value))))
        },
        _ => Ok(None),
    }
}

fn significant_tokens(instruction: &CstInstruction) -> Vec<SyntaxToken> {
    instruction
        .syntax()
        .children_with_tokens()
        .filter_map(|element| element.into_token())
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

fn span_for_tokens(context: &LoweringContext<'_>, tokens: &[SyntaxToken]) -> SourceSpan {
    let first = tokens.first().expect("instruction operands should be non-empty");
    let last = tokens.last().expect("non-empty tokens");
    join_spans(context.parse().span_for_token(first), context.parse().span_for_token(last))
}

fn unquote_string_token(token: &SyntaxToken, span: SourceSpan) -> Result<Arc<str>, ParsingError> {
    token
        .text()
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .map(Arc::<str>::from)
        .ok_or(ParsingError::InvalidSyntax {
            span,
            message: "expected a quoted string".to_string(),
        })
}

fn join_spans(start: SourceSpan, end: SourceSpan) -> SourceSpan {
    SourceSpan::new(start.source_id(), start.start()..end.end())
}

enum FeltFoldKind {
    Add,
    Sub,
    Mul,
    Div,
}

enum U32FoldKind {
    Div,
    DivMod,
    Mod,
    And,
    Or,
    Xor,
    Not,
    WrappingAdd,
    WrappingSub,
    WrappingMul,
    OverflowingAdd,
    WideningAdd,
    OverflowingSub,
    WideningMul,
    Lt,
    Lte,
    Gt,
    Gte,
    Min,
    Max,
}

fn lower_eq_like(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    build: fn(ast::ImmFelt) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_felt_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, build(imm))]))
}

fn lower_int_compare(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    instruction: Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_int_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![push_int_op(span, imm), inst_op(span, instruction)]))
}

fn lower_foldable_felt(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    kind: FeltFoldKind,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_felt_immediate(context, token)? else {
        return Ok(None);
    };

    let ops = match kind {
        FeltFoldKind::Add => {
            if imm == Felt::ZERO {
                Vec::new()
            } else if imm == Felt::ONE {
                vec![inst_op(span, Instruction::Incr)]
            } else {
                vec![inst_op(span, Instruction::AddImm(imm))]
            }
        },
        FeltFoldKind::Sub => {
            if imm == Felt::ZERO {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::SubImm(imm))]
            }
        },
        FeltFoldKind::Mul => {
            if imm == Felt::ZERO {
                vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
            } else if imm == Felt::ONE {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::MulImm(imm))]
            }
        },
        FeltFoldKind::Div => {
            if imm == Felt::ZERO {
                return Err(ParsingError::DivisionByZero { span });
            }
            if imm == Felt::ONE {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::DivImm(imm))]
            }
        },
    };

    Ok(Some(ops))
}

fn lower_exp_family(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if token.kind() == SyntaxKind::Ident
        && let Some(bits) = token.text().strip_prefix('u')
        && let Some(bits) = parse_decimal_u64(bits)
    {
        let bits = u8::try_from(bits).expect("parsed decimal bit-size should fit in u8");
        if bits < 64 {
            return Ok(Some(vec![inst_op(span, Instruction::ExpBitLength(bits))]));
        }

        return Err(ParsingError::InvalidLiteral {
            span: context.parse().span_for_token(token),
            kind: LiteralErrorKind::InvalidBitSize,
        });
    }

    let Some(imm) = lower_felt_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, Instruction::ExpImm(imm))]))
}

fn lower_u32_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    build: fn(ast::ImmU32) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_u32_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, build(imm))]))
}

fn lower_u16_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    build: fn(ast::ImmU16) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_u16_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, build(imm))]))
}

fn lower_shift_u32(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    build: fn(ast::ImmU8) -> Instruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_shift32_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, build(imm))]))
}

fn lower_foldable_u32(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    kind: U32FoldKind,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_u32_immediate(context, token)? else {
        return Ok(None);
    };

    let ops = match kind {
        U32FoldKind::Div => {
            if imm == 0 {
                return Err(ParsingError::DivisionByZero { span });
            }
            if imm == 1 {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::U32DivImm(imm))]
            }
        },
        U32FoldKind::DivMod => {
            if imm == 0 {
                return Err(ParsingError::DivisionByZero { span });
            }
            vec![inst_op(span, Instruction::U32DivModImm(imm))]
        },
        U32FoldKind::Mod => {
            if imm == 0 {
                return Err(ParsingError::DivisionByZero { span });
            }
            vec![inst_op(span, Instruction::U32ModImm(imm))]
        },
        U32FoldKind::And => {
            if imm == 0 {
                vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
            } else {
                vec![push_u32_op(span, imm), inst_op(span, Instruction::U32And)]
            }
        },
        U32FoldKind::Or => {
            if imm == 0 {
                Vec::new()
            } else {
                vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Or)]
            }
        },
        U32FoldKind::Xor => {
            if imm == 0 {
                Vec::new()
            } else {
                vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Xor)]
            }
        },
        U32FoldKind::Not => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Not)],
        U32FoldKind::WrappingAdd => {
            if imm == 0 {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::U32WrappingAddImm(imm))]
            }
        },
        U32FoldKind::WrappingSub => {
            if imm == 0 {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::U32WrappingSubImm(imm))]
            }
        },
        U32FoldKind::WrappingMul => {
            if imm == 0 {
                vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
            } else if imm == 1 {
                Vec::new()
            } else {
                vec![inst_op(span, Instruction::U32WrappingMulImm(imm))]
            }
        },
        U32FoldKind::OverflowingAdd => vec![inst_op(span, Instruction::U32OverflowingAddImm(imm))],
        U32FoldKind::WideningAdd => vec![inst_op(span, Instruction::U32WideningAddImm(imm))],
        U32FoldKind::OverflowingSub => vec![inst_op(span, Instruction::U32OverflowingSubImm(imm))],
        U32FoldKind::WideningMul => vec![inst_op(span, Instruction::U32WideningMulImm(imm))],
        U32FoldKind::Lt => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Lt)],
        U32FoldKind::Lte => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Lte)],
        U32FoldKind::Gt => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Gt)],
        U32FoldKind::Gte => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Gte)],
        U32FoldKind::Min => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Min)],
        U32FoldKind::Max => vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Max)],
    };

    Ok(Some(ops))
}

fn lower_adv_push(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    if index == 0 || index > 16 {
        return Err(ParsingError::ImmediateOutOfRange { span, range: 1..17 });
    }

    Ok(Some(vec![inst_op(
        span,
        Instruction::AdvPush(Immediate::Value(Span::new(span, index))),
    )]))
}

fn lower_dup(span: SourceSpan, token: &SyntaxToken) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        0 => Instruction::Dup0,
        1 => Instruction::Dup1,
        2 => Instruction::Dup2,
        3 => Instruction::Dup3,
        4 => Instruction::Dup4,
        5 => Instruction::Dup5,
        6 => Instruction::Dup6,
        7 => Instruction::Dup7,
        8 => Instruction::Dup8,
        9 => Instruction::Dup9,
        10 => Instruction::Dup10,
        11 => Instruction::Dup11,
        12 => Instruction::Dup12,
        13 => Instruction::Dup13,
        14 => Instruction::Dup14,
        15 => Instruction::Dup15,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 0..16 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_dupw(span: SourceSpan, token: &SyntaxToken) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        0 => Instruction::DupW0,
        1 => Instruction::DupW1,
        2 => Instruction::DupW2,
        3 => Instruction::DupW3,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 0..4 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_swap(span: SourceSpan, token: &SyntaxToken) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        1 => Instruction::Swap1,
        2 => Instruction::Swap2,
        3 => Instruction::Swap3,
        4 => Instruction::Swap4,
        5 => Instruction::Swap5,
        6 => Instruction::Swap6,
        7 => Instruction::Swap7,
        8 => Instruction::Swap8,
        9 => Instruction::Swap9,
        10 => Instruction::Swap10,
        11 => Instruction::Swap11,
        12 => Instruction::Swap12,
        13 => Instruction::Swap13,
        14 => Instruction::Swap14,
        15 => Instruction::Swap15,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 1..16 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_swapw(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        1 => Instruction::SwapW1,
        2 => Instruction::SwapW2,
        3 => Instruction::SwapW3,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 1..4 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_movdn(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        2 => Instruction::MovDn2,
        3 => Instruction::MovDn3,
        4 => Instruction::MovDn4,
        5 => Instruction::MovDn5,
        6 => Instruction::MovDn6,
        7 => Instruction::MovDn7,
        8 => Instruction::MovDn8,
        9 => Instruction::MovDn9,
        10 => Instruction::MovDn10,
        11 => Instruction::MovDn11,
        12 => Instruction::MovDn12,
        13 => Instruction::MovDn13,
        14 => Instruction::MovDn14,
        15 => Instruction::MovDn15,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 2..16 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_movdnw(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        2 => Instruction::MovDnW2,
        3 => Instruction::MovDnW3,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 2..4 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_movup(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        2 => Instruction::MovUp2,
        3 => Instruction::MovUp3,
        4 => Instruction::MovUp4,
        5 => Instruction::MovUp5,
        6 => Instruction::MovUp6,
        7 => Instruction::MovUp7,
        8 => Instruction::MovUp8,
        9 => Instruction::MovUp9,
        10 => Instruction::MovUp10,
        11 => Instruction::MovUp11,
        12 => Instruction::MovUp12,
        13 => Instruction::MovUp13,
        14 => Instruction::MovUp14,
        15 => Instruction::MovUp15,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 2..16 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_movupw(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(index) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let instruction = match index {
        2 => Instruction::MovUpW2,
        3 => Instruction::MovUpW3,
        _ => {
            return Err(ParsingError::ImmediateOutOfRange { span, range: 2..4 });
        },
    };
    Ok(Some(vec![inst_op(span, instruction)]))
}

fn lower_push_mapvaln(
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(padding) = lower_decimal_u8_literal(token)? else {
        return Ok(None);
    };
    let event = match padding {
        0 => SystemEventNode::PushMapValN0,
        4 => SystemEventNode::PushMapValN4,
        8 => SystemEventNode::PushMapValN8,
        _ => return Err(ParsingError::InvalidPadValue { span, padding }),
    };
    Ok(Some(vec![inst_op(span, Instruction::SysEvent(event))]))
}

fn lower_felt_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<ast::ImmFelt>, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(Some(ast::Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            if token.text().starts_with("0b") || token.text().starts_with("0B") {
                return Ok(None);
            }

            match parse_numeric_token(span, token.text())? {
                ParsedNumeric::Int(value) => {
                    Ok(Some(ast::Immediate::Value(Span::new(span, Felt::new(value.as_int())))))
                },
                ParsedNumeric::Word(_) => Ok(None),
            }
        },
        _ => Ok(None),
    }
}

fn lower_int_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<Immediate<crate::parser::IntValue>>, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(Some(ast::Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            if token.text().starts_with("0b") || token.text().starts_with("0B") {
                return Ok(None);
            }

            match parse_numeric_token(span, token.text())? {
                ParsedNumeric::Int(value) => {
                    Ok(Some(ast::Immediate::Value(Span::new(span, value))))
                },
                ParsedNumeric::Word(_) => Ok(None),
            }
        },
        _ => Ok(None),
    }
}

fn lower_u32_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<ast::ImmU32>, ParsingError> {
    match token.kind() {
        SyntaxKind::Ident | SyntaxKind::Number => {
            lower_u32_immediate_token(context, token).map(Some)
        },
        _ => Ok(None),
    }
}

fn lower_u16_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<ast::ImmU16>, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(Some(ast::Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            let Some(value) = lower_decimal_u64_literal(token)? else {
                return Ok(None);
            };
            let Ok(value) = u16::try_from(value) else {
                return Err(ParsingError::ImmediateOutOfRange {
                    span,
                    range: 0..(u16::MAX as usize + 1),
                });
            };
            Ok(Some(ast::Immediate::Value(Span::new(span, value))))
        },
        _ => Ok(None),
    }
}

fn lower_shift32_immediate(
    context: &mut LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<Option<ast::ImmU8>, ParsingError> {
    let span = context.parse().span_for_token(token);
    match token.kind() {
        SyntaxKind::Ident => {
            Ok(Some(ast::Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            let Some(value) = lower_decimal_u64_literal(token)? else {
                return Ok(None);
            };
            let Ok(value) = u8::try_from(value) else {
                return Err(ParsingError::ImmediateOutOfRange { span, range: 0..32 });
            };
            if value > 31 {
                return Err(ParsingError::ImmediateOutOfRange { span, range: 0..32 });
            }
            Ok(Some(ast::Immediate::Value(Span::new(span, value))))
        },
        _ => Ok(None),
    }
}

fn lower_decimal_u8_literal(token: &SyntaxToken) -> Result<Option<u8>, ParsingError> {
    let Some(value) = lower_decimal_u64_literal(token)? else {
        return Ok(None);
    };
    Ok(u8::try_from(value).ok())
}

fn lower_decimal_u64_literal(token: &SyntaxToken) -> Result<Option<u64>, ParsingError> {
    if token.kind() != SyntaxKind::Number {
        return Ok(None);
    }
    Ok(parse_decimal_u64(token.text()))
}

fn inst_op(span: SourceSpan, instruction: Instruction) -> ast::Op {
    ast::Op::Inst(Span::new(span, instruction))
}

fn push_int_op(span: SourceSpan, imm: Immediate<crate::parser::IntValue>) -> ast::Op {
    inst_op(span, Instruction::Push(imm.map(PushValue::from)))
}

fn push_u32_op(span: SourceSpan, imm: ast::ImmU32) -> ast::Op {
    let push = match imm {
        Immediate::Constant(name) => Immediate::Constant(name),
        Immediate::Value(value) => Immediate::Value(value.map(|value| PushValue::from(value))),
    };
    inst_op(span, Instruction::Push(push))
}

fn push_zero_op(span: SourceSpan) -> ast::Op {
    inst_op(span, Instruction::Push(Immediate::Value(Span::new(span, PushValue::from(0u8)))))
}
