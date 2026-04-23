use alloc::{string::ToString, vec::Vec};

use miden_assembly_syntax_cst::{
    SyntaxElement, SyntaxKind, SyntaxToken,
    ast::{
        AstNode, Block as CstBlock, IfOp as CstIfOp, Instruction as CstInstruction,
        Operation as CstOperation, RepeatOp as CstRepeatOp, WhileOp as CstWhileOp,
    },
    rowan,
};
use miden_debug_types::{SourceSpan, Span};

use super::{
    context::LoweringContext, fragments::lower_u32_immediate_token,
    instructions::try_lower_instruction,
};
use crate::{
    ast::{self, Instruction},
    parser::ParsingError,
};

/// Lowers `block` and rejects source-level empty bodies using `empty_message`.
///
/// Structured forms such as procedures, `while`, and `repeat` distinguish between a missing/empty
/// source block and an explicit lowered `nop` block, so callers choose the appropriate message.
pub(super) fn lower_required_block(
    context: &mut LoweringContext<'_>,
    block: &CstBlock,
    empty_message: &'static str,
) -> Result<ast::Block, ParsingError> {
    if !has_source_operations(block) {
        return Err(ParsingError::InvalidSyntax {
            span: context.parse().span_for_node(block.syntax()),
            message: empty_message.to_string(),
        });
    }

    lower_block(context, block)
}

/// Lowers a CST block into the AST block representation.
///
/// Each source operation may lower to one or more AST ops (for example `push.1.2`), so this also
/// enforces the code-block size limit after expansion.
pub(super) fn lower_block(
    context: &mut LoweringContext<'_>,
    block: &CstBlock,
) -> Result<ast::Block, ParsingError> {
    let span = context.parse().span_for_node(block.syntax());
    let mut ops = Vec::new();
    for op in block.operations() {
        ops.extend(lower_operation(context, &op)?);
        if ops.len() > u16::MAX as usize {
            return Err(ParsingError::CodeBlockTooBig { span });
        }
    }

    Ok(ast::Block::new(span, ops))
}

/// Dispatches a single CST operation to the corresponding structured-op or instruction lowerer.
fn lower_operation(
    context: &mut LoweringContext<'_>,
    op: &CstOperation,
) -> Result<Vec<ast::Op>, ParsingError> {
    match op {
        CstOperation::If(op) => Ok(vec![lower_if_op(context, op)?]),
        CstOperation::While(op) => Ok(vec![lower_while_op(context, op)?]),
        CstOperation::Repeat(op) => Ok(vec![lower_repeat_op(context, op)?]),
        CstOperation::Instruction(op) => lower_instruction(context, op),
    }
}

/// Lowers an `if.true` / `if.false` operation.
///
/// This preserves legacy semantics for empty branches: a missing `then` branch is only tolerated
/// when an `else` branch exists, in which case the empty side is lowered as an explicit `nop`.
fn lower_if_op(context: &mut LoweringContext<'_>, op: &CstIfOp) -> Result<ast::Op, ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    let cond = parse_if_condition(context, op)?;

    let then_node = op.then_block().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a block body for `if`".to_string(),
    })?;
    let else_node = op.else_block();

    let then_has_ops = has_source_operations(&then_node);
    let else_has_ops = else_node.as_ref().is_some_and(has_source_operations);

    let then_blk = if then_has_ops {
        lower_block(context, &then_node)?
    } else if else_node.is_some() {
        nop_block(span)
    } else {
        return Err(ParsingError::InvalidSyntax {
            span: context.parse().span_for_node(then_node.syntax()),
            message: "expected a non-empty `if` block".to_string(),
        });
    };

    let else_blk = match else_node {
        Some(else_node) => {
            if !else_has_ops {
                return Err(ParsingError::InvalidSyntax {
                    span: context.parse().span_for_node(else_node.syntax()),
                    message: "expected a non-empty `else` block".to_string(),
                });
            }
            lower_block(context, &else_node)?
        },
        None => nop_block(span),
    };

    if cond {
        Ok(ast::Op::If { span, then_blk, else_blk })
    } else {
        Ok(ast::Op::If {
            span,
            then_blk: else_blk,
            else_blk: then_blk,
        })
    }
}

/// Lowers a `while.true` operation and enforces a non-empty body.
fn lower_while_op(
    context: &mut LoweringContext<'_>,
    op: &CstWhileOp,
) -> Result<ast::Op, ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    parse_while_condition(context, op)?;
    let body = op.body().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a block body for `while`".to_string(),
    })?;
    let body = lower_required_block(context, &body, "expected a non-empty `while` block")?;
    Ok(ast::Op::While { span, body })
}

/// Lowers a `repeat.<count>` operation and validates the repeat-count immediate.
fn lower_repeat_op(
    context: &mut LoweringContext<'_>,
    op: &CstRepeatOp,
) -> Result<ast::Op, ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    let count = parse_repeat_count(context, op)?;
    let body = op.body().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a block body for `repeat`".to_string(),
    })?;
    let body = lower_required_block(context, &body, "expected a non-empty `repeat` block")?;
    Ok(ast::Op::Repeat { span, count, body })
}

/// Lowers a single instruction node, delegating operand decoding to `instructions.rs`.
///
/// Any instruction spelling that the direct lowerer does not recognize is reported using the
/// legacy “invalid instruction or malformed operands” surface.
fn lower_instruction(
    context: &mut LoweringContext<'_>,
    instruction: &CstInstruction,
) -> Result<Vec<ast::Op>, ParsingError> {
    if let Some(ops) = try_lower_instruction(context, instruction)? {
        return Ok(ops);
    }
    Err(invalid_instruction_error(context, instruction))
}

/// Parses the condition suffix of an `if` header.
///
/// The CST keeps `if.true` / `if.false` as ordinary tokens, so lowering reconstructs the
/// boolean condition from the header spelling.
fn parse_if_condition(context: &LoweringContext<'_>, op: &CstIfOp) -> Result<bool, ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    let tokens = header_tokens_before_first_block(op.syntax());
    match tokens.as_slice() {
        [keyword, dot, cond]
            if keyword.kind() == SyntaxKind::Ident
                && keyword.text() == "if"
                && dot.kind() == SyntaxKind::Dot =>
        {
            match cond.text() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(ParsingError::InvalidSyntax {
                    span: context.parse().span_for_token(cond),
                    message: "expected `true` or `false` after `if.`".to_string(),
                }),
            }
        },
        _ => Err(ParsingError::InvalidSyntax {
            span,
            message: "expected `if.true` or `if.false`".to_string(),
        }),
    }
}

/// Validates that a `while` header uses the only currently-supported condition spelling.
fn parse_while_condition(
    context: &LoweringContext<'_>,
    op: &CstWhileOp,
) -> Result<(), ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    let tokens = header_tokens_before_first_block(op.syntax());
    match tokens.as_slice() {
        [keyword, dot, cond]
            if keyword.kind() == SyntaxKind::Ident
                && keyword.text() == "while"
                && dot.kind() == SyntaxKind::Dot
                && cond.kind() == SyntaxKind::Ident
                && cond.text() == "true" =>
        {
            Ok(())
        },
        _ => Err(ParsingError::InvalidSyntax {
            span,
            message: "expected `while.true`".to_string(),
        }),
    }
}

/// Parses the immediate count in a `repeat.<count>` header.
fn parse_repeat_count(
    context: &mut LoweringContext<'_>,
    op: &CstRepeatOp,
) -> Result<ast::ImmU32, ParsingError> {
    let span = context.parse().span_for_node(op.syntax());
    let tokens = header_tokens_before_first_block(op.syntax());
    match tokens.as_slice() {
        [keyword, dot, count]
            if keyword.kind() == SyntaxKind::Ident
                && keyword.text() == "repeat"
                && dot.kind() == SyntaxKind::Dot =>
        {
            lower_u32_immediate_token(context, count)
        },
        _ => Err(ParsingError::InvalidSyntax {
            span,
            message: "expected `repeat.<count>`".to_string(),
        }),
    }
}

/// Collects the significant header tokens for a structured op up to, but not including, its
/// first nested block node.
///
/// Structured bodies are nested CST nodes, so header parsing only needs the tokens that precede
/// the first block child.
fn header_tokens_before_first_block(
    node: &miden_assembly_syntax_cst::syntax::SyntaxNode,
) -> Vec<SyntaxToken> {
    node.children_with_tokens()
        .take_while(|element| {
            !matches!(element, SyntaxElement::Node(child) if child.kind() == SyntaxKind::Block)
        })
        .filter_map(rowan::NodeOrToken::into_token)
        .filter(|token| !token.kind().is_trivia())
        .collect()
}

/// Returns true when the CST block contains at least one explicit source operation.
fn has_source_operations(block: &CstBlock) -> bool {
    block.operations().next().is_some()
}

/// Builds the legacy fallback diagnostic for malformed instruction spellings.
fn invalid_instruction_error(
    context: &LoweringContext<'_>,
    instruction: &CstInstruction,
) -> ParsingError {
    let span = context.parse().span_for_node(instruction.syntax());
    let message = instruction
        .syntax()
        .children_with_tokens()
        .filter_map(rowan::NodeOrToken::into_token)
        .find(|token| !token.kind().is_trivia())
        .and_then(|token| (token.kind() == SyntaxKind::Ident).then(|| token.text().to_string()))
        .map(|name| format!("invalid instruction `{name}` or malformed operands"))
        .unwrap_or_else(|| "invalid instruction syntax".to_string());

    ParsingError::InvalidSyntax { span, message }
}

/// Constructs the synthetic `nop` block used by legacy lowering for omitted `else` branches and
/// empty-then/with-else forms.
fn nop_block(span: SourceSpan) -> ast::Block {
    ast::Block::new(span, vec![ast::Op::Inst(Span::new(span, Instruction::Nop))])
}
