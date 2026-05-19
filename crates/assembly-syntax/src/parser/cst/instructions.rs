use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax_cst::{
    SyntaxKind, SyntaxToken,
    ast::{AstNode, Instruction as CstInstruction},
    rowan,
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

/// Attempts to lower a CST instruction node into one or more AST ops.
///
/// Lowering first tries compact single-line spellings (`dup.3`, `exp.u32`, etc.), then falls back
/// to extended operand forms (`push`, `exec`, `debug`, `emit`, ...). `None` means the direct
/// lowerer does not recognize the spelling and callers should report it as malformed.
pub(super) fn try_lower_instruction(
    context: &mut LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let span = context.parse().span_for_node(instruction.syntax());
    if let Some(compact) = CompactInstruction::parse(instruction) {
        if let Some(error) = deprecated_instruction_error(span, &compact) {
            return Err(error);
        }

        if let Some(inst) = lower_primitive_instruction(compact.spelling()) {
            return Ok(Some(vec![inst_op(span, inst)]));
        }

        if let Some(ops) = lower_immediate_instruction(context, span, &compact)? {
            return Ok(Some(ops));
        }

        if let Some(error) = unexpected_primitive_suffix_error(context, instruction, &compact) {
            return Err(error);
        }
    }

    lower_extended_instruction(context, instruction)
}

/// Compact instruction view used for spellings that can be interpreted as a trivia-free
/// `ident(.segment)*` token sequence.
struct CompactInstruction {
    spelling: String,
    segments: Vec<SyntaxToken>,
}

impl CompactInstruction {
    /// Parses `instruction` as a compact `ident(.segment)*` spelling if possible.
    fn parse(instruction: &CstInstruction) -> Option<Self> {
        let mut text = String::new();
        let mut segments = Vec::new();
        for token in instruction
            .syntax()
            .children_with_tokens()
            .filter_map(rowan::NodeOrToken::into_token)
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

        (!text.is_empty()).then_some(Self { spelling: text, segments })
    }

    /// Returns the full compact spelling.
    fn spelling(&self) -> &str {
        self.spelling.as_str()
    }

    /// Returns the number of non-dot compact segments.
    fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the `index`th non-dot segment text.
    fn segment_text(&self, index: usize) -> Option<&str> {
        self.segments.get(index).map(rowan::SyntaxToken::text)
    }

    /// Returns the `index`th non-dot segment token.
    fn token(&self, index: usize) -> &SyntaxToken {
        &self.segments[index]
    }

    /// Returns true if the leading segments match `prefix`.
    fn starts_with_segments(&self, prefix: &[&str]) -> bool {
        self.segments.len() >= prefix.len()
            && prefix.iter().enumerate().all(|(index, segment)| {
                self.segment_text(index).is_some_and(|text| text == *segment)
            })
    }

    /// Returns the final segment token when `prefix` matches every preceding segment.
    fn suffix_after_prefix(&self, prefix: &[&str]) -> Option<&SyntaxToken> {
        (self.segment_count() == prefix.len() + 1 && self.starts_with_segments(prefix))
            .then(|| self.token(prefix.len()))
    }

    /// Returns the first segment for compact diagnostics.
    fn first_segment_text(&self) -> Option<&str> {
        self.segment_text(0)
    }

    /// Returns the first segment when the compact spelling has exactly one suffix.
    fn single_suffix_base(&self) -> Option<&str> {
        (self.segment_count() == 2).then(|| self.segment_text(0)).flatten()
    }
}

/// Lowers compact spellings that carry exactly one immediate-like segment.
fn lower_immediate_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    compact: &CompactInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    for spec in COMPACT_SUFFIX_SPECS {
        if let Some(token) = compact.suffix_after_prefix(spec.prefix) {
            return lower_compact_suffix_instruction(context, span, token, spec.kind);
        }
    }
    Ok(None)
}

/// Restores the legacy “unexpected `.`” diagnostic for primitive opcodes that do not accept
/// suffixes, e.g. `neg.1` or `inv.1`.
fn unexpected_primitive_suffix_error(
    context: &LoweringContext<'_>,
    instruction: &CstInstruction,
    compact: &CompactInstruction,
) -> Option<ParsingError> {
    let name = compact.single_suffix_base()?;
    if lower_primitive_instruction(name).is_none() || accepts_single_suffix(name) {
        return None;
    }

    let dot = instruction
        .syntax()
        .children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .find(|token| token.kind() == SyntaxKind::Dot)?;
    Some(ParsingError::UnrecognizedToken {
        span: context.parse().span_for_token(&dot),
        token: dot.text().to_string(),
        expected: expected_block_operation_tokens(),
    })
}

/// Returns true when `name.<suffix>` may be a valid spelling handled by direct lowering.
fn accepts_single_suffix(name: &str) -> bool {
    COMPACT_SUFFIX_SPECS
        .iter()
        .any(|spec| spec.prefix.len() == 1 && spec.prefix[0] == name)
        || matches!(name, "debug" | "emit" | "trace")
}

/// Returns the compact legacy expected-token set for block-local syntax errors.
fn expected_block_operation_tokens() -> Vec<String> {
    vec![
        r#"primitive opcode (e.g. "add")"#.to_string(),
        r#""end""#.to_string(),
        r#"control flow opcode (e.g. "if.true")"#.to_string(),
    ]
}

/// Returns the fixed primitive instruction for suffix-free spellings.
fn lower_primitive_instruction(text: &str) -> Option<Instruction> {
    PRIMITIVE_SPECS
        .iter()
        .find(|spec| spec.spelling == text)
        .map(|spec| (spec.build)())
        .or_else(|| stack_default_instruction(text))
}

struct PrimitiveSpec {
    spelling: &'static str,
    build: fn() -> Instruction,
}

static PRIMITIVE_SPECS: &[PrimitiveSpec] = &[
    PrimitiveSpec {
        spelling: "adv.insert_hdword",
        build: || Instruction::SysEvent(SystemEventNode::InsertHdword),
    },
    PrimitiveSpec {
        spelling: "adv.insert_hdword_d",
        build: || Instruction::SysEvent(SystemEventNode::InsertHdwordWithDomain),
    },
    PrimitiveSpec {
        spelling: "adv.insert_hperm",
        build: || Instruction::SysEvent(SystemEventNode::InsertHperm),
    },
    PrimitiveSpec {
        spelling: "adv.insert_hqword",
        build: || Instruction::SysEvent(SystemEventNode::InsertHqword),
    },
    PrimitiveSpec {
        spelling: "adv.insert_mem",
        build: || Instruction::SysEvent(SystemEventNode::InsertMem),
    },
    PrimitiveSpec {
        spelling: "adv.has_mapkey",
        build: || Instruction::SysEvent(SystemEventNode::HasMapKey),
    },
    PrimitiveSpec {
        spelling: "adv.push_mapval",
        build: || Instruction::SysEvent(SystemEventNode::PushMapVal),
    },
    PrimitiveSpec {
        spelling: "adv.push_mapval_count",
        build: || Instruction::SysEvent(SystemEventNode::PushMapValCount),
    },
    PrimitiveSpec {
        spelling: "adv.push_mapvaln",
        build: || Instruction::SysEvent(SystemEventNode::PushMapValN0),
    },
    PrimitiveSpec {
        spelling: "adv.push_mtnode",
        build: || Instruction::SysEvent(SystemEventNode::PushMtNode),
    },
    PrimitiveSpec {
        spelling: "adv.register_deferred",
        build: || Instruction::SysEvent(SystemEventNode::DeferredRegister),
    },
    PrimitiveSpec {
        spelling: "adv.register_deferred_chunk",
        build: || Instruction::SysEvent(SystemEventNode::DeferredRegisterChunk),
    },
    PrimitiveSpec {
        spelling: "adv.evaluate_deferred",
        build: || Instruction::SysEvent(SystemEventNode::DeferredEvaluate),
    },
    PrimitiveSpec {
        spelling: "debug.adv_stack",
        build: || Instruction::Debug(DebugOptions::AdvStackTop(0u16.into())),
    },
    PrimitiveSpec {
        spelling: "debug.local",
        build: || Instruction::Debug(DebugOptions::LocalAll),
    },
    PrimitiveSpec {
        spelling: "debug.mem",
        build: || Instruction::Debug(DebugOptions::MemAll),
    },
    PrimitiveSpec {
        spelling: "debug.stack",
        build: || Instruction::Debug(DebugOptions::StackAll),
    },
    PrimitiveSpec {
        spelling: "add",
        build: || Instruction::Add,
    },
    PrimitiveSpec {
        spelling: "and",
        build: || Instruction::And,
    },
    PrimitiveSpec {
        spelling: "assert",
        build: || Instruction::Assert,
    },
    PrimitiveSpec {
        spelling: "assert_eq",
        build: || Instruction::AssertEq,
    },
    PrimitiveSpec {
        spelling: "assert_eqw",
        build: || Instruction::AssertEqw,
    },
    PrimitiveSpec {
        spelling: "assertz",
        build: || Instruction::Assertz,
    },
    PrimitiveSpec {
        spelling: "div",
        build: || Instruction::Div,
    },
    PrimitiveSpec {
        spelling: "eq",
        build: || Instruction::Eq,
    },
    PrimitiveSpec {
        spelling: "eqw",
        build: || Instruction::Eqw,
    },
    PrimitiveSpec {
        spelling: "exp",
        build: || Instruction::Exp,
    },
    PrimitiveSpec {
        spelling: "gt",
        build: || Instruction::Gt,
    },
    PrimitiveSpec {
        spelling: "gte",
        build: || Instruction::Gte,
    },
    PrimitiveSpec {
        spelling: "inv",
        build: || Instruction::Inv,
    },
    PrimitiveSpec {
        spelling: "lt",
        build: || Instruction::Lt,
    },
    PrimitiveSpec {
        spelling: "lte",
        build: || Instruction::Lte,
    },
    PrimitiveSpec {
        spelling: "mul",
        build: || Instruction::Mul,
    },
    PrimitiveSpec {
        spelling: "neg",
        build: || Instruction::Neg,
    },
    PrimitiveSpec {
        spelling: "neq",
        build: || Instruction::Neq,
    },
    PrimitiveSpec {
        spelling: "not",
        build: || Instruction::Not,
    },
    PrimitiveSpec {
        spelling: "or",
        build: || Instruction::Or,
    },
    PrimitiveSpec {
        spelling: "sub",
        build: || Instruction::Sub,
    },
    PrimitiveSpec {
        spelling: "xor",
        build: || Instruction::Xor,
    },
    PrimitiveSpec {
        spelling: "adv_push",
        build: || Instruction::AdvPush,
    },
    PrimitiveSpec {
        spelling: "adv_pushw",
        build: || Instruction::AdvPushW,
    },
    PrimitiveSpec {
        spelling: "caller",
        build: || Instruction::Caller,
    },
    PrimitiveSpec {
        spelling: "cdrop",
        build: || Instruction::CDrop,
    },
    PrimitiveSpec {
        spelling: "cdropw",
        build: || Instruction::CDropW,
    },
    PrimitiveSpec {
        spelling: "cswap",
        build: || Instruction::CSwap,
    },
    PrimitiveSpec {
        spelling: "cswapw",
        build: || Instruction::CSwapW,
    },
    PrimitiveSpec {
        spelling: "drop",
        build: || Instruction::Drop,
    },
    PrimitiveSpec {
        spelling: "dropw",
        build: || Instruction::DropW,
    },
    PrimitiveSpec {
        spelling: "padw",
        build: || Instruction::PadW,
    },
    PrimitiveSpec {
        spelling: "sdepth",
        build: || Instruction::Sdepth,
    },
    PrimitiveSpec {
        spelling: "swapdw",
        build: || Instruction::SwapDw,
    },
    PrimitiveSpec {
        spelling: "adv_loadw",
        build: || Instruction::AdvLoadW,
    },
    PrimitiveSpec {
        spelling: "adv_pipe",
        build: || Instruction::AdvPipe,
    },
    PrimitiveSpec {
        spelling: "clk",
        build: || Instruction::Clk,
    },
    PrimitiveSpec {
        spelling: "crypto_stream",
        build: || Instruction::CryptoStream,
    },
    PrimitiveSpec {
        spelling: "dyncall",
        build: || Instruction::DynCall,
    },
    PrimitiveSpec {
        spelling: "dynexec",
        build: || Instruction::DynExec,
    },
    PrimitiveSpec {
        spelling: "emit",
        build: || Instruction::Emit,
    },
    PrimitiveSpec {
        spelling: "eval_circuit",
        build: || Instruction::EvalCircuit,
    },
    PrimitiveSpec {
        spelling: "ext2add",
        build: || Instruction::Ext2Add,
    },
    PrimitiveSpec {
        spelling: "ext2div",
        build: || Instruction::Ext2Div,
    },
    PrimitiveSpec {
        spelling: "ext2inv",
        build: || Instruction::Ext2Inv,
    },
    PrimitiveSpec {
        spelling: "ext2mul",
        build: || Instruction::Ext2Mul,
    },
    PrimitiveSpec {
        spelling: "ext2neg",
        build: || Instruction::Ext2Neg,
    },
    PrimitiveSpec {
        spelling: "ext2sub",
        build: || Instruction::Ext2Sub,
    },
    PrimitiveSpec {
        spelling: "fri_ext2fold4",
        build: || Instruction::FriExt2Fold4,
    },
    PrimitiveSpec {
        spelling: "hash",
        build: || Instruction::Hash,
    },
    PrimitiveSpec {
        spelling: "hmerge",
        build: || Instruction::HMerge,
    },
    PrimitiveSpec {
        spelling: "hperm",
        build: || Instruction::HPerm,
    },
    PrimitiveSpec {
        spelling: "horner_eval_base",
        build: || Instruction::HornerBase,
    },
    PrimitiveSpec {
        spelling: "horner_eval_ext",
        build: || Instruction::HornerExt,
    },
    PrimitiveSpec {
        spelling: "ilog2",
        build: || Instruction::ILog2,
    },
    PrimitiveSpec {
        spelling: "is_odd",
        build: || Instruction::IsOdd,
    },
    PrimitiveSpec {
        spelling: "log_precompile",
        build: || Instruction::LogPrecompile,
    },
    PrimitiveSpec {
        spelling: "nop",
        build: || Instruction::Nop,
    },
    PrimitiveSpec {
        spelling: "pow2",
        build: || Instruction::Pow2,
    },
    PrimitiveSpec {
        spelling: "reversew",
        build: || Instruction::Reversew,
    },
    PrimitiveSpec {
        spelling: "reversedw",
        build: || Instruction::Reversedw,
    },
    PrimitiveSpec {
        spelling: "mem_load",
        build: || Instruction::MemLoad,
    },
    PrimitiveSpec {
        spelling: "mem_loadw_be",
        build: || Instruction::MemLoadWBe,
    },
    PrimitiveSpec {
        spelling: "mem_loadw_le",
        build: || Instruction::MemLoadWLe,
    },
    PrimitiveSpec {
        spelling: "mem_store",
        build: || Instruction::MemStore,
    },
    PrimitiveSpec {
        spelling: "mem_storew_be",
        build: || Instruction::MemStoreWBe,
    },
    PrimitiveSpec {
        spelling: "mem_storew_le",
        build: || Instruction::MemStoreWLe,
    },
    PrimitiveSpec {
        spelling: "mem_stream",
        build: || Instruction::MemStream,
    },
    PrimitiveSpec {
        spelling: "mtree_get",
        build: || Instruction::MTreeGet,
    },
    PrimitiveSpec {
        spelling: "mtree_merge",
        build: || Instruction::MTreeMerge,
    },
    PrimitiveSpec {
        spelling: "mtree_set",
        build: || Instruction::MTreeSet,
    },
    PrimitiveSpec {
        spelling: "mtree_verify",
        build: || Instruction::MTreeVerify,
    },
    PrimitiveSpec {
        spelling: "u32and",
        build: || Instruction::U32And,
    },
    PrimitiveSpec {
        spelling: "u32assert",
        build: || Instruction::U32Assert,
    },
    PrimitiveSpec {
        spelling: "u32assert2",
        build: || Instruction::U32Assert2,
    },
    PrimitiveSpec {
        spelling: "u32assertw",
        build: || Instruction::U32AssertW,
    },
    PrimitiveSpec {
        spelling: "u32cast",
        build: || Instruction::U32Cast,
    },
    PrimitiveSpec {
        spelling: "u32clo",
        build: || Instruction::U32Clo,
    },
    PrimitiveSpec {
        spelling: "u32clz",
        build: || Instruction::U32Clz,
    },
    PrimitiveSpec {
        spelling: "u32cto",
        build: || Instruction::U32Cto,
    },
    PrimitiveSpec {
        spelling: "u32ctz",
        build: || Instruction::U32Ctz,
    },
    PrimitiveSpec {
        spelling: "u32div",
        build: || Instruction::U32Div,
    },
    PrimitiveSpec {
        spelling: "u32divmod",
        build: || Instruction::U32DivMod,
    },
    PrimitiveSpec {
        spelling: "u32gt",
        build: || Instruction::U32Gt,
    },
    PrimitiveSpec {
        spelling: "u32gte",
        build: || Instruction::U32Gte,
    },
    PrimitiveSpec {
        spelling: "u32lt",
        build: || Instruction::U32Lt,
    },
    PrimitiveSpec {
        spelling: "u32lte",
        build: || Instruction::U32Lte,
    },
    PrimitiveSpec {
        spelling: "u32max",
        build: || Instruction::U32Max,
    },
    PrimitiveSpec {
        spelling: "u32min",
        build: || Instruction::U32Min,
    },
    PrimitiveSpec {
        spelling: "u32mod",
        build: || Instruction::U32Mod,
    },
    PrimitiveSpec {
        spelling: "u32not",
        build: || Instruction::U32Not,
    },
    PrimitiveSpec {
        spelling: "u32or",
        build: || Instruction::U32Or,
    },
    PrimitiveSpec {
        spelling: "u32overflowing_add",
        build: || Instruction::U32OverflowingAdd,
    },
    PrimitiveSpec {
        spelling: "u32overflowing_add3",
        build: || Instruction::U32OverflowingAdd3,
    },
    PrimitiveSpec {
        spelling: "u32overflowing_sub",
        build: || Instruction::U32OverflowingSub,
    },
    PrimitiveSpec {
        spelling: "u32popcnt",
        build: || Instruction::U32Popcnt,
    },
    PrimitiveSpec {
        spelling: "u32rotl",
        build: || Instruction::U32Rotl,
    },
    PrimitiveSpec {
        spelling: "u32rotr",
        build: || Instruction::U32Rotr,
    },
    PrimitiveSpec {
        spelling: "u32shl",
        build: || Instruction::U32Shl,
    },
    PrimitiveSpec {
        spelling: "u32shr",
        build: || Instruction::U32Shr,
    },
    PrimitiveSpec {
        spelling: "u32split",
        build: || Instruction::U32Split,
    },
    PrimitiveSpec {
        spelling: "u32test",
        build: || Instruction::U32Test,
    },
    PrimitiveSpec {
        spelling: "u32testw",
        build: || Instruction::U32TestW,
    },
    PrimitiveSpec {
        spelling: "u32widening_add",
        build: || Instruction::U32WideningAdd,
    },
    PrimitiveSpec {
        spelling: "u32widening_add3",
        build: || Instruction::U32WideningAdd3,
    },
    PrimitiveSpec {
        spelling: "u32widening_madd",
        build: || Instruction::U32WideningMadd,
    },
    PrimitiveSpec {
        spelling: "u32widening_mul",
        build: || Instruction::U32WideningMul,
    },
    PrimitiveSpec {
        spelling: "u32wrapping_add",
        build: || Instruction::U32WrappingAdd,
    },
    PrimitiveSpec {
        spelling: "u32wrapping_add3",
        build: || Instruction::U32WrappingAdd3,
    },
    PrimitiveSpec {
        spelling: "u32wrapping_madd",
        build: || Instruction::U32WrappingMadd,
    },
    PrimitiveSpec {
        spelling: "u32wrapping_mul",
        build: || Instruction::U32WrappingMul,
    },
    PrimitiveSpec {
        spelling: "u32wrapping_sub",
        build: || Instruction::U32WrappingSub,
    },
    PrimitiveSpec {
        spelling: "u32xor",
        build: || Instruction::U32Xor,
    },
];

struct DeprecatedAliasSpec {
    spelling: &'static str,
    replacement: &'static str,
}

static DEPRECATED_ALIAS_SPECS: &[DeprecatedAliasSpec] = &[
    DeprecatedAliasSpec {
        spelling: "mem_loadw",
        replacement: "mem_loadw_be",
    },
    DeprecatedAliasSpec {
        spelling: "mem_storew",
        replacement: "mem_storew_be",
    },
    DeprecatedAliasSpec {
        spelling: "loc_loadw",
        replacement: "loc_loadw_be",
    },
    DeprecatedAliasSpec {
        spelling: "loc_storew",
        replacement: "loc_storew_be",
    },
];

#[derive(Clone, Copy)]
struct CompactSuffixSpec {
    prefix: &'static [&'static str],
    kind: CompactSuffixKind,
}

#[derive(Clone, Copy)]
enum CompactSuffixKind {
    /// A comparison instruction with felt immediate, e.g. `eq.1` or `lt.42`
    Comparison(fn(ast::ImmFelt) -> Instruction),
    /// A possibly-foldable felt arithmetic instruction with felt immediate
    Felt(fn(ast::ImmFelt, SourceSpan) -> Result<Vec<ast::Op>, ParsingError>),
    /// An instruction with u32 immediate
    U32(fn(ast::ImmU32) -> Instruction),
    /// A instruction with u32 immediate with parse-time folder
    U32WithFolder(fn(ast::ImmU32, SourceSpan) -> Result<Vec<ast::Op>, ParsingError>),
    U16(fn(ast::ImmU16) -> Instruction),
    Stack(&'static StackIndexSpec),
    ShiftU32(fn(ast::ImmU8) -> Instruction),
    Exp,
    PushMapValN,
}

static COMPACT_SUFFIX_SPECS: &[CompactSuffixSpec] = &[
    CompactSuffixSpec {
        prefix: &["eq"],
        kind: CompactSuffixKind::Comparison(Instruction::EqImm),
    },
    CompactSuffixSpec {
        prefix: &["neq"],
        kind: CompactSuffixKind::Comparison(Instruction::NeqImm),
    },
    CompactSuffixSpec {
        prefix: &["lt"],
        kind: CompactSuffixKind::Comparison(Instruction::LtImm),
    },
    CompactSuffixSpec {
        prefix: &["lte"],
        kind: CompactSuffixKind::Comparison(Instruction::LteImm),
    },
    CompactSuffixSpec {
        prefix: &["gt"],
        kind: CompactSuffixKind::Comparison(Instruction::GtImm),
    },
    CompactSuffixSpec {
        prefix: &["gte"],
        kind: CompactSuffixKind::Comparison(Instruction::GteImm),
    },
    CompactSuffixSpec {
        prefix: &["add"],
        kind: CompactSuffixKind::Felt(super::folders::fold_add),
    },
    CompactSuffixSpec {
        prefix: &["sub"],
        kind: CompactSuffixKind::Felt(super::folders::fold_sub),
    },
    CompactSuffixSpec {
        prefix: &["mul"],
        kind: CompactSuffixKind::Felt(super::folders::fold_mul),
    },
    CompactSuffixSpec {
        prefix: &["div"],
        kind: CompactSuffixKind::Felt(super::folders::fold_div),
    },
    CompactSuffixSpec {
        prefix: &["exp"],
        kind: CompactSuffixKind::Exp,
    },
    CompactSuffixSpec {
        prefix: &["mem_load"],
        kind: CompactSuffixKind::U32(Instruction::MemLoadImm),
    },
    CompactSuffixSpec {
        prefix: &["mem_loadw_be"],
        kind: CompactSuffixKind::U32(Instruction::MemLoadWBeImm),
    },
    CompactSuffixSpec {
        prefix: &["mem_loadw_le"],
        kind: CompactSuffixKind::U32(Instruction::MemLoadWLeImm),
    },
    CompactSuffixSpec {
        prefix: &["mem_store"],
        kind: CompactSuffixKind::U32(Instruction::MemStoreImm),
    },
    CompactSuffixSpec {
        prefix: &["mem_storew_be"],
        kind: CompactSuffixKind::U32(Instruction::MemStoreWBeImm),
    },
    CompactSuffixSpec {
        prefix: &["mem_storew_le"],
        kind: CompactSuffixKind::U32(Instruction::MemStoreWLeImm),
    },
    CompactSuffixSpec {
        prefix: &["locaddr"],
        kind: CompactSuffixKind::U16(Instruction::Locaddr),
    },
    CompactSuffixSpec {
        prefix: &["loc_load"],
        kind: CompactSuffixKind::U16(Instruction::LocLoad),
    },
    CompactSuffixSpec {
        prefix: &["loc_loadw_be"],
        kind: CompactSuffixKind::U16(Instruction::LocLoadWBe),
    },
    CompactSuffixSpec {
        prefix: &["loc_loadw_le"],
        kind: CompactSuffixKind::U16(Instruction::LocLoadWLe),
    },
    CompactSuffixSpec {
        prefix: &["loc_store"],
        kind: CompactSuffixKind::U16(Instruction::LocStore),
    },
    CompactSuffixSpec {
        prefix: &["loc_storew_be"],
        kind: CompactSuffixKind::U16(Instruction::LocStoreWBe),
    },
    CompactSuffixSpec {
        prefix: &["loc_storew_le"],
        kind: CompactSuffixKind::U16(Instruction::LocStoreWLe),
    },
    CompactSuffixSpec {
        prefix: &["dup"],
        kind: CompactSuffixKind::Stack(&STACK_DUP_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["dupw"],
        kind: CompactSuffixKind::Stack(&STACK_DUPW_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["swap"],
        kind: CompactSuffixKind::Stack(&STACK_SWAP_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["swapw"],
        kind: CompactSuffixKind::Stack(&STACK_SWAPW_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["movdn"],
        kind: CompactSuffixKind::Stack(&STACK_MOVDN_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["movdnw"],
        kind: CompactSuffixKind::Stack(&STACK_MOVDNW_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["movup"],
        kind: CompactSuffixKind::Stack(&STACK_MOVUP_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["movupw"],
        kind: CompactSuffixKind::Stack(&STACK_MOVUPW_SPEC),
    },
    CompactSuffixSpec {
        prefix: &["u32div"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32div),
    },
    CompactSuffixSpec {
        prefix: &["u32divmod"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32divmod),
    },
    CompactSuffixSpec {
        prefix: &["u32mod"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32mod),
    },
    CompactSuffixSpec {
        prefix: &["u32and"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32and),
    },
    CompactSuffixSpec {
        prefix: &["u32or"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32or),
    },
    CompactSuffixSpec {
        prefix: &["u32xor"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32xor),
    },
    CompactSuffixSpec {
        prefix: &["u32not"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32not),
    },
    CompactSuffixSpec {
        prefix: &["u32wrapping_add"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32wrapping_add),
    },
    CompactSuffixSpec {
        prefix: &["u32wrapping_sub"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32wrapping_sub),
    },
    CompactSuffixSpec {
        prefix: &["u32wrapping_mul"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32wrapping_mul),
    },
    CompactSuffixSpec {
        prefix: &["u32overflowing_add"],
        kind: CompactSuffixKind::U32(Instruction::U32OverflowingAddImm),
    },
    CompactSuffixSpec {
        prefix: &["u32widening_add"],
        kind: CompactSuffixKind::U32(Instruction::U32WideningAddImm),
    },
    CompactSuffixSpec {
        prefix: &["u32overflowing_sub"],
        kind: CompactSuffixKind::U32(Instruction::U32OverflowingSubImm),
    },
    CompactSuffixSpec {
        prefix: &["u32widening_mul"],
        kind: CompactSuffixKind::U32(Instruction::U32WideningMulImm),
    },
    CompactSuffixSpec {
        prefix: &["u32lt"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32lt),
    },
    CompactSuffixSpec {
        prefix: &["u32lte"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32lte),
    },
    CompactSuffixSpec {
        prefix: &["u32gt"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32gt),
    },
    CompactSuffixSpec {
        prefix: &["u32gte"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32gte),
    },
    CompactSuffixSpec {
        prefix: &["u32min"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32min),
    },
    CompactSuffixSpec {
        prefix: &["u32max"],
        kind: CompactSuffixKind::U32WithFolder(super::folders::fold_u32max),
    },
    CompactSuffixSpec {
        prefix: &["u32shl"],
        kind: CompactSuffixKind::ShiftU32(Instruction::U32ShlImm),
    },
    CompactSuffixSpec {
        prefix: &["u32shr"],
        kind: CompactSuffixKind::ShiftU32(Instruction::U32ShrImm),
    },
    CompactSuffixSpec {
        prefix: &["u32rotl"],
        kind: CompactSuffixKind::ShiftU32(Instruction::U32RotlImm),
    },
    CompactSuffixSpec {
        prefix: &["u32rotr"],
        kind: CompactSuffixKind::ShiftU32(Instruction::U32RotrImm),
    },
    CompactSuffixSpec {
        prefix: &["adv", "push_mapvaln"],
        kind: CompactSuffixKind::PushMapValN,
    },
];

struct StackIndexSpec {
    spelling: &'static str,
    default: Option<u8>,
    min: u8,
    end: u8,
    ops: &'static [(u8, Instruction)],
}

impl StackIndexSpec {
    fn instruction(&self, index: u8) -> Option<Instruction> {
        self.ops
            .iter()
            .find_map(|(op_index, instruction)| (*op_index == index).then(|| instruction.clone()))
    }

    fn range(&self) -> core::ops::Range<usize> {
        self.min as usize..self.end as usize
    }
}

static STACK_DUP_OPS: &[(u8, Instruction)] = &[
    (0, Instruction::Dup0),
    (1, Instruction::Dup1),
    (2, Instruction::Dup2),
    (3, Instruction::Dup3),
    (4, Instruction::Dup4),
    (5, Instruction::Dup5),
    (6, Instruction::Dup6),
    (7, Instruction::Dup7),
    (8, Instruction::Dup8),
    (9, Instruction::Dup9),
    (10, Instruction::Dup10),
    (11, Instruction::Dup11),
    (12, Instruction::Dup12),
    (13, Instruction::Dup13),
    (14, Instruction::Dup14),
    (15, Instruction::Dup15),
];

static STACK_DUPW_OPS: &[(u8, Instruction)] = &[
    (0, Instruction::DupW0),
    (1, Instruction::DupW1),
    (2, Instruction::DupW2),
    (3, Instruction::DupW3),
];

static STACK_SWAP_OPS: &[(u8, Instruction)] = &[
    (1, Instruction::Swap1),
    (2, Instruction::Swap2),
    (3, Instruction::Swap3),
    (4, Instruction::Swap4),
    (5, Instruction::Swap5),
    (6, Instruction::Swap6),
    (7, Instruction::Swap7),
    (8, Instruction::Swap8),
    (9, Instruction::Swap9),
    (10, Instruction::Swap10),
    (11, Instruction::Swap11),
    (12, Instruction::Swap12),
    (13, Instruction::Swap13),
    (14, Instruction::Swap14),
    (15, Instruction::Swap15),
];

static STACK_SWAPW_OPS: &[(u8, Instruction)] =
    &[(1, Instruction::SwapW1), (2, Instruction::SwapW2), (3, Instruction::SwapW3)];

static STACK_MOVDN_OPS: &[(u8, Instruction)] = &[
    (2, Instruction::MovDn2),
    (3, Instruction::MovDn3),
    (4, Instruction::MovDn4),
    (5, Instruction::MovDn5),
    (6, Instruction::MovDn6),
    (7, Instruction::MovDn7),
    (8, Instruction::MovDn8),
    (9, Instruction::MovDn9),
    (10, Instruction::MovDn10),
    (11, Instruction::MovDn11),
    (12, Instruction::MovDn12),
    (13, Instruction::MovDn13),
    (14, Instruction::MovDn14),
    (15, Instruction::MovDn15),
];

static STACK_MOVDNW_OPS: &[(u8, Instruction)] =
    &[(2, Instruction::MovDnW2), (3, Instruction::MovDnW3)];

static STACK_MOVUP_OPS: &[(u8, Instruction)] = &[
    (2, Instruction::MovUp2),
    (3, Instruction::MovUp3),
    (4, Instruction::MovUp4),
    (5, Instruction::MovUp5),
    (6, Instruction::MovUp6),
    (7, Instruction::MovUp7),
    (8, Instruction::MovUp8),
    (9, Instruction::MovUp9),
    (10, Instruction::MovUp10),
    (11, Instruction::MovUp11),
    (12, Instruction::MovUp12),
    (13, Instruction::MovUp13),
    (14, Instruction::MovUp14),
    (15, Instruction::MovUp15),
];

static STACK_MOVUPW_OPS: &[(u8, Instruction)] =
    &[(2, Instruction::MovUpW2), (3, Instruction::MovUpW3)];

static STACK_DUP_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "dup",
    default: Some(0),
    min: 0,
    end: 16,
    ops: STACK_DUP_OPS,
};
static STACK_DUPW_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "dupw",
    default: Some(0),
    min: 0,
    end: 4,
    ops: STACK_DUPW_OPS,
};
static STACK_SWAP_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "swap",
    default: Some(1),
    min: 1,
    end: 16,
    ops: STACK_SWAP_OPS,
};
static STACK_SWAPW_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "swapw",
    default: Some(1),
    min: 1,
    end: 4,
    ops: STACK_SWAPW_OPS,
};
static STACK_MOVDN_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "movdn",
    default: None,
    min: 2,
    end: 16,
    ops: STACK_MOVDN_OPS,
};
static STACK_MOVDNW_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "movdnw",
    default: None,
    min: 2,
    end: 4,
    ops: STACK_MOVDNW_OPS,
};
static STACK_MOVUP_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "movup",
    default: None,
    min: 2,
    end: 16,
    ops: STACK_MOVUP_OPS,
};
static STACK_MOVUPW_SPEC: StackIndexSpec = StackIndexSpec {
    spelling: "movupw",
    default: None,
    min: 2,
    end: 4,
    ops: STACK_MOVUPW_OPS,
};

static STACK_INDEX_SPECS: &[&StackIndexSpec] = &[
    &STACK_DUP_SPEC,
    &STACK_DUPW_SPEC,
    &STACK_SWAP_SPEC,
    &STACK_SWAPW_SPEC,
    &STACK_MOVDN_SPEC,
    &STACK_MOVDNW_SPEC,
    &STACK_MOVUP_SPEC,
    &STACK_MOVUPW_SPEC,
];

fn stack_default_instruction(text: &str) -> Option<Instruction> {
    let spec = STACK_INDEX_SPECS.iter().copied().find(|spec| spec.spelling == text)?;
    spec.default.and_then(|index| spec.instruction(index))
}

fn lower_compact_suffix_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    kind: CompactSuffixKind,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    match kind {
        CompactSuffixKind::Comparison(build) => lower_felt_comparison(context, span, token, build),
        CompactSuffixKind::Felt(folder) => lower_felt_instruction(context, span, token, folder),
        CompactSuffixKind::U32(build) => lower_u32_instruction(context, span, token, build),
        CompactSuffixKind::U32WithFolder(folder) => {
            lower_foldable_u32_instruction(context, span, token, folder)
        },
        CompactSuffixKind::U16(build) => lower_u16_instruction(context, span, token, build),
        CompactSuffixKind::Stack(spec) => lower_stack_index_instruction(context, span, token, spec),
        CompactSuffixKind::ShiftU32(build) => lower_shift_u32(context, span, token, build),
        CompactSuffixKind::Exp => lower_exp_family(context, span, token),
        CompactSuffixKind::PushMapValN => lower_push_mapvaln(context, span, token),
    }
}

fn lower_stack_index_instruction(
    context: &LoweringContext<'_>,
    instruction_span: SourceSpan,
    token: &SyntaxToken,
    spec: &StackIndexSpec,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let immediate_span = context.parse().span_for_token(token);
    let Some(index) = lower_decimal_u8_literal(token) else {
        return Ok(None);
    };
    let Some(instruction) = spec.instruction(index) else {
        return Err(ParsingError::ImmediateOutOfRange {
            span: immediate_span,
            range: spec.range(),
        });
    };
    Ok(Some(vec![inst_op(instruction_span, instruction)]))
}

fn deprecated_instruction_error(
    span: SourceSpan,
    compact: &CompactInstruction,
) -> Option<ParsingError> {
    let instruction = compact.first_segment_text()?;
    let spec = DEPRECATED_ALIAS_SPECS.iter().find(|spec| spec.spelling == instruction)?;

    Some(ParsingError::DeprecatedInstruction {
        span,
        instruction: instruction.to_string(),
        replacement: spec.replacement.to_string(),
    })
}

/// Lowers the instruction spellings that are not representable as compact primitives/immediates.
///
/// These forms generally have richer operand structure, such as invocation targets, push lists,
/// event names, or debug operand tuples.
fn lower_extended_instruction(
    context: &mut LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let tokens = instruction.significant_tokens().collect::<Vec<_>>();
    let Some(first) = tokens.first() else {
        return Ok(None);
    };
    if first.kind() != SyntaxKind::Ident {
        return Ok(None);
    }

    let span = context.parse().span_for_node(instruction.syntax());
    let Some(spec) = EXTENDED_INSTRUCTION_SPECS.iter().find(|spec| spec.keyword == first.text())
    else {
        return Ok(None);
    };

    match spec.kind {
        ExtendedInstructionKind::Push => lower_push_instruction(context, span, &tokens),
        ExtendedInstructionKind::Invocation(build) => {
            lower_invocation_instruction(context, span, &tokens, build)
        },
        ExtendedInstructionKind::Debug => lower_debug_instruction(context, span, &tokens),
        ExtendedInstructionKind::Emit => lower_emit_instruction(context, span, &tokens),
        ExtendedInstructionKind::Trace => lower_trace_instruction(context, span, &tokens),
        ExtendedInstructionKind::ErrorCode(build) => {
            lower_error_code_instruction(context, span, &tokens, spec.keyword, build)
        },
    }
}

struct ExtendedInstructionSpec {
    keyword: &'static str,
    kind: ExtendedInstructionKind,
}

#[derive(Clone, Copy)]
enum ExtendedInstructionKind {
    Push,
    Invocation(fn(ast::InvocationTarget) -> Instruction),
    Debug,
    Emit,
    Trace,
    ErrorCode(fn(ast::ErrorMsg) -> Instruction),
}

static EXTENDED_INSTRUCTION_SPECS: &[ExtendedInstructionSpec] = &[
    ExtendedInstructionSpec {
        keyword: "push",
        kind: ExtendedInstructionKind::Push,
    },
    ExtendedInstructionSpec {
        keyword: "exec",
        kind: ExtendedInstructionKind::Invocation(Instruction::Exec),
    },
    ExtendedInstructionSpec {
        keyword: "call",
        kind: ExtendedInstructionKind::Invocation(Instruction::Call),
    },
    ExtendedInstructionSpec {
        keyword: "syscall",
        kind: ExtendedInstructionKind::Invocation(Instruction::SysCall),
    },
    ExtendedInstructionSpec {
        keyword: "procref",
        kind: ExtendedInstructionKind::Invocation(Instruction::ProcRef),
    },
    ExtendedInstructionSpec {
        keyword: "debug",
        kind: ExtendedInstructionKind::Debug,
    },
    ExtendedInstructionSpec {
        keyword: "emit",
        kind: ExtendedInstructionKind::Emit,
    },
    ExtendedInstructionSpec {
        keyword: "trace",
        kind: ExtendedInstructionKind::Trace,
    },
    ExtendedInstructionSpec {
        keyword: "assert",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::AssertWithError),
    },
    ExtendedInstructionSpec {
        keyword: "assertz",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::AssertzWithError),
    },
    ExtendedInstructionSpec {
        keyword: "assert_eq",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::AssertEqWithError),
    },
    ExtendedInstructionSpec {
        keyword: "assert_eqw",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::AssertEqwWithError),
    },
    ExtendedInstructionSpec {
        keyword: "u32assert",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::U32AssertWithError),
    },
    ExtendedInstructionSpec {
        keyword: "u32assert2",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::U32Assert2WithError),
    },
    ExtendedInstructionSpec {
        keyword: "u32assertw",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::U32AssertWWithError),
    },
    ExtendedInstructionSpec {
        keyword: "mtree_verify",
        kind: ExtendedInstructionKind::ErrorCode(Instruction::MTreeVerifyWithError),
    },
];

/// Lowers all `push` spellings, including scalar lists, word literals, and slices.
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

        if rest.get(consumed).is_some_and(|token| token.kind() == SyntaxKind::LBracket) {
            let (range, used) = parse_push_slice_range(context, instruction_span, rest, consumed)?;
            if consumed + used == rest.len() {
                return Ok(Some(vec![inst_op(
                    instruction_span,
                    Instruction::PushSlice(imm.with_span(imm_span), range),
                )]));
            }
            return Err(malformed_instruction_error(instruction_span, "push"));
        }
    }

    lower_push_list(context, instruction_span, rest)
}

/// Lowers `exec`, `call`, `syscall`, and `procref` invocation forms.
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

/// Lowers all `debug.*` forms, including interval/range variants.
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

/// Lowers `emit.<const>` and `emit.event("name")`.
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

/// Lowers `trace.<u32>` immediates.
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

/// Lowers `.err=` forms for assertion-like instructions.
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

/// Lowers an invocation target operand into a symbol, path, or MAST-root reference.
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

/// Lowers a `push` list of integer immediates and/or constant references.
///
/// Each pushed element becomes a separate AST op so the rest of the pipeline sees the same shape
/// produced by the legacy parser.
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
            ParsedNumeric::Int(value) => {
                *element = Felt::new(value.as_int()).map_err(|_| ParsingError::InvalidLiteral {
                    span,
                    kind: LiteralErrorKind::FeltOverflow,
                })?
            },
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
    instruction_span: SourceSpan,
    tokens: &[SyntaxToken],
    start: usize,
) -> Result<(core::ops::Range<usize>, usize), ParsingError> {
    if tokens.get(start).is_none_or(|token| token.kind() != SyntaxKind::LBracket) {
        return Err(malformed_instruction_error(instruction_span, "push"));
    }

    let Some(first) = tokens.get(start + 1) else {
        return Err(malformed_instruction_error(instruction_span, "push"));
    };
    let begin = parse_push_slice_index(context, first)?;

    match (tokens.get(start + 2), tokens.get(start + 3), tokens.get(start + 4)) {
        (Some(rbracket), ..) if rbracket.kind() == SyntaxKind::RBracket => {
            let end = begin.checked_add(1).ok_or(ParsingError::ImmediateOutOfRange {
                span: join_spans(
                    context.parse().span_for_token(&tokens[start]),
                    context.parse().span_for_token(rbracket),
                ),
                range: 0..usize::MAX,
            })?;
            Ok((core::ops::Range { start: begin, end }, 3))
        },
        (Some(dotdot), Some(end), Some(rbracket))
            if dotdot.kind() == SyntaxKind::DotDot && rbracket.kind() == SyntaxKind::RBracket =>
        {
            let end = parse_push_slice_index(context, end)?;
            Ok((core::ops::Range { start: begin, end }, 5))
        },
        _ => Err(malformed_instruction_error(instruction_span, "push")),
    }
}

fn parse_push_slice_index(
    context: &LoweringContext<'_>,
    token: &SyntaxToken,
) -> Result<usize, ParsingError> {
    if token.kind() != SyntaxKind::Number {
        return Err(expected_integer_literal_error(context, token));
    }
    let Some(value) = parse_decimal_u64(token.text()) else {
        return Err(expected_integer_literal_error(context, token));
    };
    Ok(usize::try_from(value).ok().unwrap_or(usize::MAX))
}

fn expected_integer_literal_error(
    context: &LoweringContext<'_>,
    token: &SyntaxToken,
) -> ParsingError {
    ParsingError::UnrecognizedToken {
        span: context.parse().span_for_token(token),
        token: legacy_token_name(token),
        expected: vec!["integer literal".to_string()],
    }
}

fn legacy_token_name(token: &SyntaxToken) -> String {
    match token.kind() {
        SyntaxKind::Number if token.text().starts_with("0x") || token.text().starts_with("0X") => {
            "hex-encoded value".to_string()
        },
        SyntaxKind::Number if token.text().starts_with("0b") || token.text().starts_with("0B") => {
            "bin-encoded value".to_string()
        },
        SyntaxKind::Number => "integer".to_string(),
        SyntaxKind::Ident if token.text().chars().next().is_some_and(char::is_uppercase) => {
            "constant identifier".to_string()
        },
        SyntaxKind::Ident => "identifier".to_string(),
        _ => token.text().to_string(),
    }
}

fn malformed_instruction_error(span: SourceSpan, instruction: &str) -> ParsingError {
    ParsingError::InvalidSyntax {
        span,
        message: format!("invalid instruction `{instruction}` or malformed operands"),
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

/// Lowers a token that must represent a `u8` immediate or constant reference.
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

/// Returns the span covering the first through last token in `tokens`.
fn span_for_tokens(context: &LoweringContext<'_>, tokens: &[SyntaxToken]) -> SourceSpan {
    let first = tokens.first().expect("instruction operands should be non-empty");
    let last = tokens.last().expect("non-empty tokens");
    join_spans(context.parse().span_for_token(first), context.parse().span_for_token(last))
}

/// Removes the surrounding quotes from a string token, preserving diagnostics on malformed input.
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

/// Lowers felt-comparison instructions
fn lower_felt_comparison(
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

/// Lowers foldable felt-immediate arithmetic and applies the same peephole folds as the legacy
/// parser.
///
/// TODO(pauls): Remove folding after legacy parser removal, as this sort of optimization should not
/// be performed during parsing.
fn lower_felt_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    folder: fn(ast::ImmFelt, SourceSpan) -> Result<Vec<ast::Op>, ParsingError>,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_felt_immediate(context, token)? else {
        return Ok(None);
    };

    folder(imm, span).map(Some)
}

/// Lowers the two `exp` families: `exp.<felt>` and `exp.u<bits>`.
fn lower_exp_family(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    if token.kind() == SyntaxKind::Ident
        && let Some(bits) = token.text().strip_prefix('u')
        && let Some(bits) = parse_decimal_u64(bits)
    {
        if let Ok(bits) = u8::try_from(bits)
            && bits < 64
        {
            return Ok(Some(vec![inst_op(span, Instruction::ExpBitLength(bits))]));
        }

        return Err(ParsingError::InvalidLiteral {
            span: token_suffix_span(context.parse().span_for_token(token), 1),
            kind: LiteralErrorKind::InvalidBitSize,
        });
    }

    let Some(imm) = lower_felt_immediate(context, token)? else {
        return Ok(None);
    };
    Ok(Some(vec![inst_op(span, Instruction::ExpImm(imm))]))
}

/// Lowers `u32` immediates for instructions that keep the operand embedded in the AST opcode.
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

/// Lowers foldable `u32` immediate instruction families and preserves the legacy peephole folds.
fn lower_foldable_u32_instruction(
    context: &mut LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
    folder: fn(ast::ImmU32, SourceSpan) -> Result<Vec<ast::Op>, ParsingError>,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let Some(imm) = lower_u32_immediate(context, token)? else {
        return Ok(None);
    };

    folder(imm, span).map(Some)
}

/// Lowers `u16` immediates for local-memory operations.
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

/// Lowers shift/rotate instructions that accept `u8` immediates.
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

fn lower_push_mapvaln(
    context: &LoweringContext<'_>,
    span: SourceSpan,
    token: &SyntaxToken,
) -> Result<Option<Vec<ast::Op>>, ParsingError> {
    let immediate_span = context.parse().span_for_token(token);
    let Some(padding) = lower_decimal_u8_literal(token) else {
        return Ok(None);
    };
    let event = match padding {
        0 => SystemEventNode::PushMapValN0,
        4 => SystemEventNode::PushMapValN4,
        8 => SystemEventNode::PushMapValN8,
        _ => {
            return Err(ParsingError::InvalidPadValue { span: immediate_span, padding });
        },
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
            Ok(Some(Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            if token.text().starts_with("0b") || token.text().starts_with("0B") {
                return Ok(None);
            }

            match parse_numeric_token(span, token.text())? {
                ParsedNumeric::Int(value) => {
                    let value =
                        Felt::new(value.as_int()).map_err(|_| ParsingError::InvalidLiteral {
                            span,
                            kind: LiteralErrorKind::FeltOverflow,
                        })?;
                    Ok(Some(Immediate::Value(Span::new(span, value))))
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
            Ok(Some(Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            let Some(value) = lower_decimal_u64_literal(token) else {
                return Ok(None);
            };
            let Ok(value) = u16::try_from(value) else {
                return Err(ParsingError::ImmediateOutOfRange {
                    span,
                    range: 0..(u16::MAX as usize + 1),
                });
            };
            Ok(Some(Immediate::Value(Span::new(span, value))))
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
            Ok(Some(Immediate::Constant(context.lower_constant_ident_token(token)?)))
        },
        SyntaxKind::Number => {
            let Some(value) = lower_decimal_u64_literal(token) else {
                return Ok(None);
            };
            let Ok(value) = u8::try_from(value) else {
                return Err(ParsingError::ImmediateOutOfRange { span, range: 0..32 });
            };
            if value > 31 {
                return Err(ParsingError::ImmediateOutOfRange { span, range: 0..32 });
            }
            Ok(Some(Immediate::Value(Span::new(span, value))))
        },
        _ => Ok(None),
    }
}

/// Parses a decimal `u8` literal token without accepting non-decimal spellings.
fn lower_decimal_u8_literal(token: &SyntaxToken) -> Option<u8> {
    let value = lower_decimal_u64_literal(token)?;
    u8::try_from(value).ok()
}

/// Returns the suffix subspan of a token span, used for diagnostics like `exp.u65 -> 65`.
fn token_suffix_span(span: SourceSpan, prefix_len: u32) -> SourceSpan {
    SourceSpan::new(span.source_id(), span.start() + prefix_len..span.end())
}

/// Parses a decimal `u64` from a number token if the token is decimal-shaped.
fn lower_decimal_u64_literal(token: &SyntaxToken) -> Option<u64> {
    if token.kind() != SyntaxKind::Number {
        return None;
    }
    parse_decimal_u64(token.text())
}

/// Wraps an instruction in an AST op at `span`.
pub(super) fn inst_op(span: SourceSpan, instruction: Instruction) -> ast::Op {
    ast::Op::Inst(Span::new(span, instruction))
}

/// Builds a `push` op for a `u32` immediate or constant.
pub(super) fn push_u32_op(span: SourceSpan, imm: ast::ImmU32) -> ast::Op {
    let push = match imm {
        Immediate::Constant(name) => Immediate::Constant(name),
        Immediate::Value(value) => Immediate::Value(value.map(PushValue::from)),
    };
    inst_op(span, Instruction::Push(push))
}

/// Builds a `push.0` op at `span`.
pub(super) fn push_zero_op(span: SourceSpan) -> ast::Op {
    inst_op(span, Instruction::Push(Immediate::Value(Span::new(span, PushValue::from(0u8)))))
}
