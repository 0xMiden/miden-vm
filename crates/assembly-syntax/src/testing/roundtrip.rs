//! Parser adapters for the generated text round-trip tests.
//!
//! The parser only has an entry point for whole modules, so each adapter wraps the printed text
//! in the smallest module that accepts it and extracts the parsed value again.

use alloc::{format, string::String, vec::Vec};

use super::SyntaxTestContext;
use crate::{
    Report,
    ast::{Attribute, ConstantExpr, Form, Ident, ProcedureName},
    debuginfo::SourceLanguage,
    parser::{IntValue, WordValue},
};

fn parse_forms(source: String) -> Result<Vec<Form>, Report> {
    let context = SyntaxTestContext::default();
    let source = context.source_manager().load(SourceLanguage::Masm, "roundtrip".into(), source);
    context.parse_forms(source)
}

fn missing(what: &str, source: &str) -> Report {
    Report::msg(format!("no {what} found in {source:?}"))
}

/// Parses `source` as the value of a constant definition.
pub fn parse_constant_expr(source: &str) -> Result<ConstantExpr, Report> {
    let forms = parse_forms(format!("const X = {source}\n"))?;
    forms
        .into_iter()
        .find_map(|form| match form {
            Form::Constant(constant) => Some(constant.value),
            _ => None,
        })
        .ok_or_else(|| missing("constant", source))
}

/// Parses `source` as an integer literal.
pub fn parse_int_value(source: &str) -> Result<IntValue, Report> {
    match parse_constant_expr(source)? {
        ConstantExpr::Int(value) => Ok(value.into_inner()),
        _ => Err(missing("integer literal", source)),
    }
}

/// Integer literals are printed without their width, so compare the values they denote.
pub fn int_value_eq(lhs: &IntValue, rhs: &IntValue) -> bool {
    lhs.as_int() == rhs.as_int()
}

/// Parses `source` as a word literal.
pub fn parse_word_value(source: &str) -> Result<WordValue, Report> {
    match parse_constant_expr(source)? {
        ConstantExpr::Word(value) => Ok(value.into_inner()),
        _ => Err(missing("word literal", source)),
    }
}

fn parse_procedure_forms(attribute: &str, name: &str) -> Result<Vec<Form>, Report> {
    parse_forms(format!("{attribute}\nproc {name}\n    nop\nend\n"))
}

/// Parses `source` as an attribute of a procedure.
pub fn parse_attribute(source: &str) -> Result<Attribute, Report> {
    parse_procedure_forms(source, "p")?
        .into_iter()
        .find_map(|form| match form {
            Form::Procedure(procedure) => procedure.attributes().iter().next().cloned(),
            _ => None,
        })
        .ok_or_else(|| missing("attribute", source))
}

/// Parses `source` as the name of a procedure.
pub fn parse_procedure_name(source: &str) -> Result<ProcedureName, Report> {
    parse_procedure_forms("", source)?
        .into_iter()
        .find_map(|form| match form {
            Form::Procedure(procedure) => Some(procedure.name().clone()),
            _ => None,
        })
        .ok_or_else(|| missing("procedure", source))
}

/// Parses `source` as an identifier, using a procedure name since it accepts any identifier.
pub fn parse_ident(source: &str) -> Result<Ident, Report> {
    parse_procedure_name(source).map(Ident::from)
}

/// The `Arbitrary` identifier generators also produce Latin-1 letters, which `Ident` accepts but
/// the MASM lexer only allows inside quoted strings, so values printed with them are skipped.
pub fn is_masm_text(source: &str) -> bool {
    source.is_ascii()
}
