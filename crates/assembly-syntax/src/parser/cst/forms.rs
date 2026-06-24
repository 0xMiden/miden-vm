use alloc::{
    collections::btree_map::Entry,
    string::{String, ToString},
    vec::Vec,
};

use miden_assembly_syntax_cst::ast::{
    AdviceMap as CstAdviceMap, AstNode, BeginBlock as CstBeginBlock, Constant as CstConstant,
    ExternPackage as CstExternPackage, Import as CstImport, ImportKind as CstImportKind,
    Item as CstItem, Namespace as CstNamespace, Procedure as CstProcedure,
    Submodule as CstSubmodule, TypeDecl as CstTypeDecl,
};
use miden_debug_types::{SourceSpan, Span, Spanned};

use super::{
    blocks::lower_required_block,
    context::LoweringContext,
    fragments::{
        lower_advice_map_decl, lower_attribute, lower_constant_expr, lower_enum_decl_from_body,
        lower_function_type_from_signature, lower_type_expr_from_alias_body,
    },
};
use crate::{Report, ast, parser::ParsingError};

/// Lowers the CST source file into the top-level `Form` sequence expected by the rest of the parser
/// pipeline.
///
/// This is the main top-level bridge from the lossless CST to the historic AST boundary.
pub(super) fn lower_source_file(
    context: &mut LoweringContext<'_>,
) -> Result<Vec<ast::Form>, Report> {
    let source_file = context.parse().root();
    let items = source_file.items().collect::<Vec<_>>();
    let mut forms = Vec::with_capacity(items.len());
    let mut index = 0usize;

    while index < items.len() {
        if let Some(is_module_doc) = doc_group_kind(context, &items, index) {
            let end = extend_doc_group(context, &items, index);
            forms.push(lower_doc_group(context, &items[index..end], is_module_doc)?);
            index = end;
            continue;
        }

        match &items[index] {
            CstItem::Doc(_) => unreachable!("doc items handled above"),
            CstItem::Namespace(namespace) => {
                forms.push(lower_namespace(context, namespace)?);
                index += 1;
            },
            CstItem::ExternPackage(extern_package) => {
                forms.push(lower_extern_package(context, extern_package)?);
                index += 1;
            },
            CstItem::Submodule(submodule) => {
                forms.push(lower_submodule(context, submodule)?);
                index += 1;
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
            CstItem::AdviceMap(advice_map) => {
                forms.push(lower_advice_map(context, advice_map)?);
                index += 1;
            },
            CstItem::BeginBlock(begin) => {
                forms.push(lower_begin_block(context, begin)?);
                index += 1;
            },
            CstItem::Procedure(procedure) => {
                forms.push(lower_procedure(context, procedure)?);
                index += 1;
            },
        }
    }

    Ok(forms)
}

/// Returns `Some(true/false)` when `items[index]` starts a doc-comment group.
///
/// The boolean indicates whether the group should become `Form::ModuleDoc` (`true`) or ordinary
/// item docs (`false`). Non-doc items return `None`.
fn doc_group_kind(context: &LoweringContext<'_>, items: &[CstItem], index: usize) -> Option<bool> {
    let item = items.get(index)?;
    matches!(item, CstItem::Doc(_)).then(|| index == 0 && starts_at_file_beginning(context, item))
}

/// Extends a doc-comment run until the next non-doc item or blank-line separator.
fn extend_doc_group(context: &LoweringContext<'_>, items: &[CstItem], start: usize) -> usize {
    let mut end = start + 1;
    while end < items.len()
        && matches!(items[end], CstItem::Doc(_))
        && !has_blank_line_between(context, &items[end - 1], &items[end])
    {
        end += 1;
    }
    end
}

/// Returns true when `item` begins on the first line in the source file.
fn starts_at_file_beginning(context: &LoweringContext<'_>, item: &CstItem) -> bool {
    context.source_file().location(item_span(context, item)).line().to_u32() == 1
}

/// Returns true when the source text between `lhs` and `rhs` contains a blank line.
///
/// Doc groups are split on blank lines to preserve the distinction between contiguous doc blocks
/// and separated documentation sections.
fn has_blank_line_between(context: &LoweringContext<'_>, lhs: &CstItem, rhs: &CstItem) -> bool {
    let lhs = item_span(context, lhs);
    let rhs = item_span(context, rhs);
    let between = context
        .source_file()
        .source_slice(lhs.end().to_usize()..rhs.start().to_usize())
        .expect("doc spans should produce valid interstitial text");
    count_line_breaks(between) > 1
}

/// Counts line terminators in `text`, treating CRLF as a single logical line break.
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

/// Lowers a contiguous run of doc-comment items into either `Form::ModuleDoc` or `Form::Doc`.
fn lower_doc_group(
    context: &LoweringContext<'_>,
    items: &[CstItem],
    is_module_doc: bool,
) -> Result<ast::Form, Report> {
    let first_span = item_span(context, &items[0]);
    let last_span = item_span(context, items.last().expect("non-empty doc group"));
    let span = SourceSpan::new(context.source_file().id(), first_span.start()..last_span.end());

    let mut text = String::new();
    for item in items {
        let line = match item {
            CstItem::Doc(_) => doc_text(context, item),
            _ => unreachable!("expected only doc items in doc group"),
        };
        text.push_str(&line);
    }

    let docs = Span::new(span, text);
    if docs.len() > u16::MAX as usize {
        return Err(ParsingError::DocsTooLarge { span }.into());
    }

    Ok(if is_module_doc {
        ast::Form::ModuleDoc(docs)
    } else {
        ast::Form::Doc(docs)
    })
}

/// Extracts the normalized text payload for a single doc-comment item.
///
/// The returned string is normalized and always includes a trailing newline so grouped docs
/// concatenate without additional bookkeeping.
fn doc_text(context: &LoweringContext<'_>, item: &CstItem) -> String {
    let span = item_span(context, item);
    let raw = context.source_text(span);
    let raw = raw.strip_prefix("#!").expect("doc nodes should start with `#!`");
    let raw = raw.trim();
    let mut text = String::with_capacity(raw.len() + 1);
    text.push_str(raw);
    text.push('\n');
    text
}

/// Lowers a `namespace` declaration.
fn lower_namespace(
    context: &mut LoweringContext<'_>,
    namespace: &CstNamespace,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(namespace.syntax());
    let path = namespace.path().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a namespace path".to_string(),
    })?;
    Ok(ast::Form::Namespace(context.lower_path(&path)?))
}

/// Lowers an `extern package` declaration.
fn lower_extern_package(
    context: &mut LoweringContext<'_>,
    extern_package: &CstExternPackage,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(extern_package.syntax());
    let package = extern_package.package_token().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a package name".to_string(),
    })?;
    Ok(ast::Form::ExternPackage(context.lower_ident_or_string_token(&package)?))
}

/// Lowers a `mod` or `pub mod` declaration.
fn lower_submodule(
    context: &mut LoweringContext<'_>,
    submodule: &CstSubmodule,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(submodule.syntax());
    let visibility = context.lower_visibility(submodule.visibility());
    let name = submodule.name_token().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected a submodule name".to_string(),
    })?;

    Ok(ast::Form::Submodule(ast::SubmoduleDecl {
        visibility,
        name: context.lower_ident_token(&name)?,
    }))
}

/// Lowers a source `use` form into the explicit import representation.
fn lower_import(
    context: &mut LoweringContext<'_>,
    import: &CstImport,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(import.syntax());
    let visibility = context.lower_visibility(import.visibility());

    match import.kind() {
        CstImportKind::Module => {
            let module_path = import.module_path().ok_or_else(|| ParsingError::InvalidSyntax {
                span,
                message: "expected an import path".to_string(),
            })?;
            let path = context.lower_path(&module_path)?;
            let local_name = match import.module_alias_token() {
                Some(alias) => context.lower_ident_token(&alias)?,
                None => {
                    let last = module_path.segments().last().ok_or_else(|| {
                        ParsingError::InvalidSyntax {
                            span: path.span(),
                            message: "expected an import path".to_string(),
                        }
                    })?;
                    context.lower_ident_token(&last)?
                },
            };
            Ok(ast::Form::Import(ast::ImportDecl::Module(ast::ModuleImport::new(
                span, visibility, path, local_name,
            ))))
        },
        CstImportKind::Items => {
            let module_path = import.module_path().ok_or_else(|| ParsingError::InvalidSyntax {
                span,
                message: "expected a module path after `from`".to_string(),
            })?;
            let path = context.lower_path(&module_path)?;
            let mut specs = Vec::new();
            for spec in import.item_specs() {
                let name = spec.name_token().ok_or_else(|| ParsingError::InvalidSyntax {
                    span: context.parse().span_for_node(spec.syntax()),
                    message: "expected an imported item name".to_string(),
                })?;
                let source_name = context.lower_ident_token(&name)?;
                let local_name = match spec.alias_token() {
                    Some(alias) => context.lower_ident_token(&alias)?,
                    None => source_name.clone(),
                };
                specs.push(ast::ImportSpec::new(source_name, local_name));
            }

            if specs.is_empty() {
                return Err(ParsingError::InvalidSyntax {
                    span,
                    message: "import lists must contain at least one item".to_string(),
                });
            }

            Ok(ast::Form::Import(ast::ImportDecl::Items(ast::ItemImportGroup::new(
                span, visibility, path, specs,
            ))))
        },
    }
}

/// Lowers a constant declaration and validates its name/value pair.
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

/// Lowers either a `type` alias or an `enum` declaration from the shared CST form.
fn lower_type_decl(
    context: &mut LoweringContext<'_>,
    type_decl: &CstTypeDecl,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(type_decl.syntax());
    let keyword = type_decl.keyword_token().ok_or_else(|| ParsingError::InvalidSyntax {
        span,
        message: "expected `type` or `enum` in type declaration".to_string(),
    })?;
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
            let enum_ty =
                lower_enum_decl_from_body(context, visibility, name, &body, span)?.with_span(span);
            Ok(ast::Form::Enum(enum_ty))
        },
        _ => Err(ParsingError::InvalidSyntax {
            span: context.parse().span_for_token(&keyword),
            message: "expected `type` or `enum` in type declaration".to_string(),
        }),
    }
}

/// Validates the parts of a procedure header that do not depend on body lowering.
///
/// This keeps header diagnostics stable even when later body lowering fails.
fn preflight_procedure_header(
    context: &mut LoweringContext<'_>,
    procedure: &CstProcedure,
) -> Result<(ast::ProcedureName, Option<ast::FunctionType>), ParsingError> {
    let span = context.parse().span_for_node(procedure.syntax());
    let name = match procedure.name_token() {
        Some(name) => context.lower_procedure_name_token(&name)?,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a procedure name".to_string(),
            });
        },
    };

    let signature = if let Some(signature) = procedure.signature() {
        Some(lower_function_type_from_signature(context, &signature)?)
    } else {
        None
    };

    Ok((name, signature))
}

/// Lowers an `adv_map` declaration into the corresponding top-level form.
fn lower_advice_map(
    context: &mut LoweringContext<'_>,
    advice_map: &CstAdviceMap,
) -> Result<ast::Form, ParsingError> {
    Ok(ast::Form::AdviceMapEntry(lower_advice_map_decl(context, advice_map)?))
}

/// Lowers the entry `begin ... end` block for a program/module source file.
fn lower_begin_block(
    context: &mut LoweringContext<'_>,
    begin: &CstBeginBlock,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(begin.syntax());
    let block = match begin.block() {
        Some(block) => lower_required_block(context, &block, "expected a non-empty entry block")?,
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a block body".to_string(),
            });
        },
    };

    Ok(ast::Form::Begin(re_span_block(span, &block)))
}

/// Lowers a procedure declaration, including signature preflight, body lowering, and attributes.
fn lower_procedure(
    context: &mut LoweringContext<'_>,
    procedure: &CstProcedure,
) -> Result<ast::Form, ParsingError> {
    let span = context.parse().span_for_node(procedure.syntax());
    let visibility = context.lower_visibility(procedure.visibility());
    let (name, signature) = preflight_procedure_header(context, procedure)?;
    let body = match procedure.block() {
        Some(block) => {
            lower_required_block(context, &block, "expected a non-empty procedure body")?
        },
        None => {
            return Err(ParsingError::InvalidSyntax {
                span,
                message: "expected a procedure body".to_string(),
            });
        },
    };

    let mut proc = ast::Procedure::new(span, visibility, name, 0, body);
    if let Some(signature) = signature {
        proc = proc.with_signature(signature);
    }

    let attrs = procedure
        .attributes()
        .map(|attribute| lower_attribute(context, &attribute))
        .collect::<Result<Vec<_>, _>>()?;
    apply_procedure_attributes(&mut proc, attrs)?;

    Ok(ast::Form::Procedure(proc))
}

/// Applies lowered attributes to a procedure while preserving legacy attribute semantics.
///
/// This is responsible for duplicate detection, `@callconv` validation, `@locals` validation, and
/// the historical rule that some validated attributes are reflected into dedicated procedure
/// fields rather than staying in the generic attribute set.
fn apply_procedure_attributes(
    procedure: &mut ast::Procedure,
    annotations: Vec<ast::Attribute>,
) -> Result<(), ParsingError> {
    let mut cc = None;
    let mut num_locals = None;
    {
        let attributes = procedure.attributes_mut();

        for attr in annotations {
            match attr {
                ast::Attribute::KeyValue(kv) => match attributes.entry(kv.id()) {
                    ast::AttributeSetEntry::Vacant(entry) => {
                        entry.insert(ast::Attribute::KeyValue(kv));
                    },
                    ast::AttributeSetEntry::Occupied(mut entry) => {
                        let value = entry.get_mut();
                        match value {
                            ast::Attribute::KeyValue(existing_kvs) => {
                                for (k, v) in kv.into_iter() {
                                    let span = k.span();
                                    match existing_kvs.entry(k) {
                                        Entry::Vacant(entry) => {
                                            entry.insert(v);
                                        },
                                        Entry::Occupied(entry) => {
                                            let prev = entry.get();
                                            return Err(ParsingError::AttributeKeyValueConflict {
                                                span,
                                                prev: prev.span(),
                                            });
                                        },
                                    }
                                }
                            },
                            other => {
                                return Err(ParsingError::AttributeConflict {
                                    span: kv.span(),
                                    prev: other.span(),
                                });
                            },
                        }
                    },
                },
                ast::Attribute::List(list) if list.name() == "callconv" && list.len() == 1 => {
                    match attributes.entry(list.id()) {
                        ast::AttributeSetEntry::Vacant(entry) => {
                            let valid_cc = match &list.as_slice()[0] {
                                ast::MetaExpr::Ident(cc) => {
                                    cc.as_str().parse::<ast::types::CallConv>().ok()
                                },
                                ast::MetaExpr::String(cc) => {
                                    cc.as_str().parse::<ast::types::CallConv>().ok()
                                },
                                _ => None,
                            };
                            if let Some(valid_cc) = valid_cc {
                                cc = Some(valid_cc);
                                entry.insert(ast::Attribute::List(list));
                            } else {
                                return Err(ParsingError::UnrecognizedCallConv {
                                    span: list.span(),
                                });
                            }
                        },
                        ast::AttributeSetEntry::Occupied(entry) => {
                            let prev_attr = entry.get();
                            return Err(ParsingError::AttributeConflict {
                                span: list.span(),
                                prev: prev_attr.span(),
                            });
                        },
                    }
                },
                ast::Attribute::List(list) if list.name() == "locals" && list.len() == 1 => {
                    match attributes.entry(list.id()) {
                        ast::AttributeSetEntry::Vacant(entry) => {
                            let valid_num_locals = match &list.as_slice()[0] {
                                ast::MetaExpr::Int(value) => match value.inner() {
                                    crate::parser::IntValue::U8(n) => Some(*n as u16),
                                    crate::parser::IntValue::U16(n) => Some(*n),
                                    _ => None,
                                },
                                other => {
                                    return Err(ParsingError::InvalidLocalsAttr {
                                        span: other.span(),
                                        message: "expected an integer literal".to_string(),
                                    });
                                },
                            };

                            match valid_num_locals {
                                Some(n) if n > (u16::MAX / 4) * 4 => {
                                    return Err(ParsingError::InvalidLocalsAttr {
                                        span: list.span(),
                                        message: "number of locals exceeds the maximum of 65532"
                                            .to_string(),
                                    });
                                },
                                Some(n) => {
                                    num_locals = Some(n);
                                    entry.insert(ast::Attribute::List(list));
                                },
                                None => {
                                    return Err(ParsingError::ImmediateOutOfRange {
                                        span: list.span(),
                                        range: 0..((u16::MAX as usize) + 1),
                                    });
                                },
                            }
                        },
                        ast::AttributeSetEntry::Occupied(entry) => {
                            let prev_attr = entry.get();
                            return Err(ParsingError::AttributeConflict {
                                span: list.span(),
                                prev: prev_attr.span(),
                            });
                        },
                    }
                },
                attr => match attributes.entry(attr.id()) {
                    ast::AttributeSetEntry::Vacant(entry) => {
                        entry.insert(attr);
                    },
                    ast::AttributeSetEntry::Occupied(entry) => {
                        let prev_attr = entry.get();
                        return Err(ParsingError::AttributeConflict {
                            span: attr.span(),
                            prev: prev_attr.span(),
                        });
                    },
                },
            }
        }

        if num_locals.is_some() {
            attributes.remove("locals");
        }

        if cc.is_some() {
            attributes.remove("callconv");
        }
    }

    if let Some(num_locals) = num_locals {
        procedure.set_num_locals(num_locals);
    }

    if let Some(cc) = cc
        && let Some(signature) = procedure.signature_mut()
    {
        signature.cc = cc;
    }

    Ok(())
}

/// Rebuilds an AST block with a new outer span while preserving its operations unchanged.
///
/// Top-level `begin` forms and procedures historically use the enclosing form span rather than the
/// nested body span reported by the CST block node itself.
fn re_span_block(span: SourceSpan, block: &ast::Block) -> ast::Block {
    ast::Block::new(span, block.iter().cloned().collect())
}

/// Returns the source span for any top-level CST item variant.
fn item_span(context: &LoweringContext<'_>, item: &CstItem) -> SourceSpan {
    match item {
        CstItem::Doc(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Namespace(node) => context.parse().span_for_node(node.syntax()),
        CstItem::ExternPackage(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Submodule(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Import(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Constant(node) => context.parse().span_for_node(node.syntax()),
        CstItem::TypeDecl(node) => context.parse().span_for_node(node.syntax()),
        CstItem::AdviceMap(node) => context.parse().span_for_node(node.syntax()),
        CstItem::BeginBlock(node) => context.parse().span_for_node(node.syntax()),
        CstItem::Procedure(node) => context.parse().span_for_node(node.syntax()),
    }
}
