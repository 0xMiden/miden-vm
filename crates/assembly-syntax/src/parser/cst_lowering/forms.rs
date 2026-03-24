use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use miden_assembly_syntax_cst::ast::{
    AstNode, Constant as CstConstant, Import as CstImport, Item as CstItem,
    Procedure as CstProcedure, SourceFile as CstSourceFile, TypeDecl as CstTypeDecl,
};
use miden_debug_types::{SourceSpan, Span};

use super::{
    context::LoweringContext,
    fragments::{
        lower_constant_expr, lower_enum_decl_from_body, lower_function_type_from_signature,
        lower_type_expr_from_alias_body,
    },
};
use crate::{ast, parser::ParsingError};

pub(super) fn lower_source_file(
    context: &mut LoweringContext<'_>,
) -> Result<Vec<ast::Form>, ParsingError> {
    let source_file = CstSourceFile::cast(context.parse().syntax()).expect("source file");
    let items = source_file.items().collect::<Vec<_>>();
    let mut forms = Vec::with_capacity(items.len());
    let mut index = 0usize;

    while index < items.len() {
        if index == 0 && is_doc_item(&items[index]) {
            let end = extend_leading_module_doc_group(context, &items, index);
            forms.push(lower_doc_group(context, &items[index..end], true));
            index = end;
            continue;
        }

        match &items[index] {
            CstItem::ModuleDoc(_) => {
                let end = extend_doc_group(context, &items, index);
                forms.push(lower_doc_group(context, &items[index..end], true));
                index = end;
            },
            CstItem::Doc(_) => {
                let end = extend_doc_group(context, &items, index);
                forms.push(lower_doc_group(context, &items[index..end], false));
                index = end;
            },
            CstItem::Import(import) => {
                forms.push(lower_import(context, import)?);
                index += 1;
            },
            CstItem::Constant(constant) => {
                forms.push(lower_constant(context, constant)?);
                index += 1;
            },
            CstItem::TypeDecl(type_decl) => {
                forms.push(lower_type_decl(context, type_decl)?);
                index += 1;
            },
            CstItem::Procedure(procedure) => {
                preflight_procedure_header(context, procedure)?;
                forms.push(lower_item_with_fallback(
                    context,
                    &CstItem::Procedure(procedure.clone()),
                )?);
                index += 1;
            },
            item => {
                forms.push(lower_item_with_fallback(context, item)?);
                index += 1;
            },
        }
    }

    Ok(forms)
}

fn extend_leading_module_doc_group(
    context: &LoweringContext<'_>,
    items: &[CstItem],
    start: usize,
) -> usize {
    let mut end = start + 1;
    while end < items.len()
        && is_doc_item(&items[end])
        && !has_blank_line_between(context, &items[end - 1], &items[end])
    {
        end += 1;
    }
    end
}

fn extend_doc_group(context: &LoweringContext<'_>, items: &[CstItem], start: usize) -> usize {
    let mut end = start + 1;
    while end < items.len()
        && same_doc_kind(&items[start], &items[end])
        && !has_blank_line_between(context, &items[end - 1], &items[end])
    {
        end += 1;
    }
    end
}

fn same_doc_kind(lhs: &CstItem, rhs: &CstItem) -> bool {
    matches!(
        (lhs, rhs),
        (CstItem::ModuleDoc(_), CstItem::ModuleDoc(_)) | (CstItem::Doc(_), CstItem::Doc(_))
    )
}

fn is_doc_item(item: &CstItem) -> bool {
    matches!(item, CstItem::ModuleDoc(_) | CstItem::Doc(_))
}

fn has_blank_line_between(context: &LoweringContext<'_>, lhs: &CstItem, rhs: &CstItem) -> bool {
    let lhs = item_span(context, lhs);
    let rhs = item_span(context, rhs);
    let between = context
        .source_file()
        .source_slice(lhs.end().to_usize()..rhs.start().to_usize())
        .expect("doc spans should produce valid interstitial text");
    count_line_breaks(between) > 1
}

fn count_line_breaks(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut count = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                count += 1;
                index += 1;
            },
            b'\r' => {
                count += 1;
                index += 1;
                if index < bytes.len() && bytes[index] == b'\n' {
                    index += 1;
                }
            },
            _ => index += 1,
        }
    }
    count
}

fn lower_doc_group(
    context: &LoweringContext<'_>,
    items: &[CstItem],
    is_module_doc: bool,
) -> ast::Form {
    let first_span = item_span(context, &items[0]);
    let last_span = item_span(context, items.last().expect("non-empty doc group"));
    let span = SourceSpan::new(context.source_file().id(), first_span.start()..last_span.end());

    let mut text = String::new();
    for item in items {
        let line = match item {
            CstItem::ModuleDoc(_) | CstItem::Doc(_) => doc_text(context, item),
            _ => unreachable!("expected only doc items in doc group"),
        };
        text.push_str(&line);
    }

    let docs = Span::new(span, text);
    if is_module_doc {
        ast::Form::ModuleDoc(docs)
    } else {
        ast::Form::Doc(docs)
    }
}

fn doc_text(context: &LoweringContext<'_>, item: &CstItem) -> String {
    let span = item_span(context, item);
    let raw = context.source_text(span);
    let raw = raw.strip_prefix("#!").expect("doc nodes should start with `#!`");
    let raw = raw.strip_prefix(' ').unwrap_or(raw);
    let mut text = String::with_capacity(raw.len() + 1);
    text.push_str(raw);
    text.push('\n');
    text
}

fn lower_import(
    context: &mut LoweringContext<'_>,
    import: &CstImport,
) -> Result<ast::Form, ParsingError> {
    let Some(path) = import.path() else {
        return lower_item_with_fallback(context, &CstItem::Import(import.clone()));
    };

    let visibility = context.lower_visibility(import.visibility());
    let target = context.lower_path(&path)?;
    if target.as_ident().is_some() {
        return Err(ParsingError::UnqualifiedImport { span: target.span() });
    }

    let name = match import.alias_token() {
        Some(alias) => context.lower_ident_token(&alias)?,
        None => {
            let last = target
                .last()
                .expect("validated import targets should always contain at least one segment");
            context.lower_ident_text(target.span(), last)?
        },
    };

    Ok(ast::Form::Alias(ast::Alias::new(
        visibility,
        name,
        ast::AliasTarget::Path(target),
    )))
}

fn lower_constant(
    context: &mut LoweringContext<'_>,
    constant: &CstConstant,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(constant.syntax());
    let visibility = context.lower_visibility(constant.visibility());
    let name = match constant.name_token() {
        Some(token) => context.lower_constant_ident_token(&token)?,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a constant name".to_string(),
            });
        },
    };
    let expr = match constant.expr() {
        Some(expr) => lower_constant_expr(context, &expr)?,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a constant expression".to_string(),
            });
        },
    };

    Ok(ast::Form::Constant(ast::Constant::new(span, visibility, name, expr)))
}

fn lower_type_decl(
    context: &mut LoweringContext<'_>,
    type_decl: &CstTypeDecl,
) -> Result<ast::Form, ParsingError> {
    let keyword = match type_decl.keyword_token() {
        Some(token) => token,
        None => return lower_item_with_fallback(context, &CstItem::TypeDecl(type_decl.clone())),
    };

    let span = context.parse().span_for_node(type_decl.syntax());
    let visibility = context.lower_visibility(type_decl.visibility());
    let name = match type_decl.name_token() {
        Some(token) => context.lower_ident_token(&token)?,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a type name".to_string(),
            });
        },
    };
    let body = match type_decl.body() {
        Some(body) => body,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected `=` in type declaration".to_string(),
            });
        },
    };

    match keyword.text() {
        "type" => {
            let mut ty = lower_type_expr_from_alias_body(context, &body)?;
            ty.set_name(name.clone());
            Ok(ast::Form::Type(ast::TypeAlias::new(visibility, name, ty).with_span(span)))
        },
        "enum" => {
            let enum_ty = lower_enum_decl_from_body(context, visibility, name, &body, span)?;
            Ok(ast::Form::Enum(enum_ty))
        },
        _ => lower_item_with_fallback(context, &CstItem::TypeDecl(type_decl.clone())),
    }
}

fn preflight_procedure_header(
    context: &mut LoweringContext<'_>,
    procedure: &CstProcedure,
) -> Result<(), ParsingError> {
    if let Some(name) = procedure.name_token() {
        let _ = context.lower_procedure_name_token(&name)?;
    }

    if let Some(signature) = procedure.signature() {
        let _ = lower_function_type_from_signature(context, &signature)?;
    }

    Ok(())
}

fn lower_item_with_fallback(
    context: &mut LoweringContext<'_>,
    item: &CstItem,
) -> Result<ast::Form, ParsingError> {
    context.lower_form_with_legacy_parser(item_span(context, item))
}

fn item_span(context: &LoweringContext<'_>, item: &CstItem) -> SourceSpan {
    match item {
        CstItem::ModuleDoc(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Doc(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Import(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Constant(node) => context.parse().span_for_node(node.syntax()),
        CstItem::TypeDecl(node) => context.parse().span_for_node(node.syntax()),
        CstItem::AdviceMap(node) => context.parse().span_for_node(node.syntax()),
        CstItem::BeginBlock(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Procedure(node) => context.parse().span_for_node(node.syntax()),
    }
}
