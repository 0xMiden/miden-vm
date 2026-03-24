use alloc::{string::String, vec::Vec};

use miden_assembly_syntax_cst::ast::{AstNode, Item as CstItem, SourceFile as CstSourceFile};
use miden_debug_types::{SourceSpan, Span};

use super::context::LoweringContext;
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
            item => {
                forms.push(context.lower_form_with_legacy_parser(item_span(context, item))?);
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
