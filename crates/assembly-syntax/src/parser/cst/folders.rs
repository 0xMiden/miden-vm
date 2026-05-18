use alloc::vec::Vec;

use super::instructions::{inst_op, push_u32_op, push_zero_op};
use crate::{
    Felt,
    ast::{self, Instruction},
    debuginfo::SourceSpan,
    parser::ParsingError,
};

pub fn fold_add(imm: ast::ImmFelt, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == Felt::ZERO {
        Vec::new()
    } else if imm == Felt::ONE {
        vec![inst_op(span, Instruction::Incr)]
    } else {
        vec![inst_op(span, Instruction::AddImm(imm))]
    })
}

pub fn fold_sub(imm: ast::ImmFelt, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == Felt::ZERO {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::SubImm(imm))]
    })
}

pub fn fold_mul(imm: ast::ImmFelt, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == Felt::ZERO {
        vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
    } else if imm == Felt::ONE {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::MulImm(imm))]
    })
}

pub fn fold_div(imm: ast::ImmFelt, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    if imm == Felt::ZERO {
        return Err(ParsingError::DivisionByZero { span });
    }
    Ok(if imm == Felt::ONE {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::DivImm(imm))]
    })
}

pub fn fold_u32div(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    if imm == 0 {
        return Err(ParsingError::DivisionByZero { span });
    }
    Ok(if imm == 1 {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::U32DivImm(imm))]
    })
}

pub fn fold_u32divmod(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    if imm == 0 {
        return Err(ParsingError::DivisionByZero { span });
    }
    Ok(vec![inst_op(span, Instruction::U32DivModImm(imm))])
}

pub fn fold_u32mod(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    if imm == 0 {
        return Err(ParsingError::DivisionByZero { span });
    }
    Ok(vec![inst_op(span, Instruction::U32ModImm(imm))])
}

pub fn fold_u32and(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
    } else {
        vec![push_u32_op(span, imm), inst_op(span, Instruction::U32And)]
    })
}

pub fn fold_u32or(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        Vec::new()
    } else {
        vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Or)]
    })
}

pub fn fold_u32xor(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        Vec::new()
    } else {
        vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Xor)]
    })
}

pub fn fold_u32not(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Not)])
}

pub fn fold_u32wrapping_add(
    imm: ast::ImmU32,
    span: SourceSpan,
) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::U32WrappingAddImm(imm))]
    })
}

pub fn fold_u32wrapping_sub(
    imm: ast::ImmU32,
    span: SourceSpan,
) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::U32WrappingSubImm(imm))]
    })
}

pub fn fold_u32wrapping_mul(
    imm: ast::ImmU32,
    span: SourceSpan,
) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(if imm == 0 {
        vec![inst_op(span, Instruction::Drop), push_zero_op(span)]
    } else if imm == 1 {
        Vec::new()
    } else {
        vec![inst_op(span, Instruction::U32WrappingMulImm(imm))]
    })
}

pub fn fold_u32lt(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Lt)])
}

pub fn fold_u32lte(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Lte)])
}

pub fn fold_u32gt(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Gt)])
}

pub fn fold_u32gte(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Gte)])
}

pub fn fold_u32min(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Min)])
}

pub fn fold_u32max(imm: ast::ImmU32, span: SourceSpan) -> Result<Vec<ast::Op>, ParsingError> {
    Ok(vec![push_u32_op(span, imm), inst_op(span, Instruction::U32Max)])
}
