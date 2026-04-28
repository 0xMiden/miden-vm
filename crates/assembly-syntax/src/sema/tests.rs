use alloc::{
    string::{String, ToString},
    sync::Arc,
};

use miden_debug_types::{Span, Spanned};

use crate::{
    MAX_REPEAT_COUNT, Path,
    ast::{
        Constant, ConstantExpr, Export, Module, ModuleKind, TypeAlias, TypeExpr, Visibility, types,
    },
    diagnostics::reporting::PrintDiagnostic,
    sema::SemanticAnalysisError,
    testing::SyntaxTestContext,
};

fn exported_constant<'a>(module: &'a Module, name: &str) -> &'a Constant {
    match module
        .items()
        .iter()
        .find(|item| item.name().as_str() == name && item.visibility().is_public())
    {
        Some(Export::Constant(constant)) => constant,
        Some(item) => panic!("expected exported constant named {name}, found {item:?}"),
        None => panic!("expected exported constant named {name}"),
    }
}

fn assert_symbol_conflict(error: &miden_utils_diagnostics::Report, symbol: &str) {
    let syntax_error = error
        .downcast_ref::<crate::sema::SyntaxError>()
        .expect("expected SyntaxError report");

    let (span, prev_span) = syntax_error
        .errors
        .iter()
        .find_map(|err| match err {
            SemanticAnalysisError::SymbolConflict { span, prev_span } => Some((span, prev_span)),
            _ => None,
        })
        .expect("expected at least one SymbolConflict error");

    assert_ne!(span, prev_span, "conflicting definitions should point at distinct spans");
    assert_eq!(
        span.source_id(),
        prev_span.source_id(),
        "conflict spans should refer to the same source file"
    );

    let span_text = syntax_error
        .source_file
        .source_slice(*span)
        .expect("conflict span should be valid");
    let prev_span_text = syntax_error
        .source_file
        .source_slice(*prev_span)
        .expect("previous conflict span should be valid");

    assert!(
        span_text.contains(symbol),
        "conflict span should include symbol '{symbol}', got: {span_text:?}"
    );
    assert!(
        prev_span_text.contains(symbol),
        "previous conflict span should include symbol '{symbol}', got: {prev_span_text:?}"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefinitionKind {
    Alias,
    Procedure,
    Constant,
    Type,
}

impl DefinitionKind {
    fn declaration(self, symbol: &str) -> String {
        match self {
            Self::Alias => format!("use ::dep::{}", quote_ident_if_needed(symbol)),
            Self::Procedure => {
                format!("proc {}\n    nop\nend", quote_ident_if_needed(symbol))
            },
            Self::Constant => format!("const {symbol} = 1"),
            Self::Type => format!("type {} = felt", quote_ident_if_needed(symbol)),
        }
    }
}

fn quote_ident_if_needed(symbol: &str) -> String {
    let is_bare_ident = symbol
        .bytes()
        .all(|b| b == b'_' || b.is_ascii_lowercase() || b.is_ascii_digit());
    if is_bare_ident {
        symbol.to_string()
    } else {
        format!("\"{symbol}\"")
    }
}

fn assert_cross_kind_conflict(first: DefinitionKind, second: DefinitionKind) {
    if is_constant_type_pair(first, second) {
        assert_constant_type_conflict_via_module_api(first, second);
        return;
    }

    let symbol = if matches!(first, DefinitionKind::Constant)
        || matches!(second, DefinitionKind::Constant)
    {
        "THING"
    } else {
        "thing"
    };
    let context = SyntaxTestContext::default();
    let source = format!("{}\n{}\n", first.declaration(symbol), second.declaration(symbol));
    let message = format!("expected symbol conflict during analysis ({first:?} then {second:?})");
    let error = context.parse_module(source).expect_err(&message);
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    if error.downcast_ref::<crate::sema::SyntaxError>().is_none() {
        panic!("expected SyntaxError ({first:?} then {second:?}), got: {rendered}");
    }
    assert_symbol_conflict(&error, symbol);
    assert!(rendered.contains("symbol conflict"));
    assert!(rendered.contains(symbol));
}

fn is_constant_type_pair(first: DefinitionKind, second: DefinitionKind) -> bool {
    matches!(
        (first, second),
        (DefinitionKind::Constant, DefinitionKind::Type)
            | (DefinitionKind::Type, DefinitionKind::Constant)
    )
}

fn assert_constant_type_conflict_via_module_api(first: DefinitionKind, second: DefinitionKind) {
    let symbol = "dup";
    let mut module = Module::new(ModuleKind::Library, Path::new("mod"));

    match first {
        DefinitionKind::Constant => module
            .define_constant(constant_with_name(symbol))
            .expect("expected initial constant definition to succeed"),
        DefinitionKind::Type => module
            .define_type(type_alias_with_name(symbol))
            .expect("expected initial type definition to succeed"),
        _ => unreachable!("only constant/type pairs should use this helper"),
    }

    let result = match second {
        DefinitionKind::Constant => module.define_constant(constant_with_name(symbol)),
        DefinitionKind::Type => module.define_type(type_alias_with_name(symbol)),
        _ => unreachable!("only constant/type pairs should use this helper"),
    };
    assert!(
        matches!(result, Err(SemanticAnalysisError::SymbolConflict { .. })),
        "expected SymbolConflict when defining {second:?} after {first:?}, got {result:?}"
    );
}

fn ident_with_name(name: &str) -> crate::ast::Ident {
    crate::ast::Ident::from_raw_parts(Span::unknown(Arc::<str>::from(name)))
}

fn constant_with_name(name: &str) -> Constant {
    let ident = ident_with_name(name);
    Constant::new(
        ident.span(),
        Visibility::Private,
        ident,
        ConstantExpr::String(ident_with_name("value")),
    )
}

fn type_alias_with_name(name: &str) -> TypeAlias {
    TypeAlias::new(
        Visibility::Private,
        ident_with_name(name),
        TypeExpr::Primitive(Span::unknown(types::Type::Felt)),
    )
}

#[test]
fn repeat_count_zero_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program("begin repeat.0 nop end end")
        .expect_err("expected repeat.0 to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_too_large_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = format!("begin repeat.{repeat_count} nop end end");
    let error = context
        .parse_program(source)
        .expect_err("expected repeat count above limit to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_at_limit_allowed_in_analysis() {
    let context = SyntaxTestContext::default();
    let source = format!("begin repeat.{MAX_REPEAT_COUNT} nop end end");
    let _module = context
        .parse_program(source)
        .expect("expected repeat count at limit to be accepted during analysis");
}

#[test]
fn repeat_count_constant_zero_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program("const REPEAT_COUNT = 0\nbegin repeat.REPEAT_COUNT nop end end")
        .expect_err("expected repeat.0 from constant to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_constant_at_limit_allowed_in_analysis() {
    let context = SyntaxTestContext::default();
    let source =
        format!("const REPEAT_COUNT = {MAX_REPEAT_COUNT}\nbegin repeat.REPEAT_COUNT nop end end");
    let _module = context
        .parse_program(source)
        .expect("expected repeat count at limit from constant to be accepted during analysis");
}

#[test]
fn repeat_count_constant_too_large_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source =
        format!("const REPEAT_COUNT = {repeat_count}\nbegin repeat.REPEAT_COUNT nop end end");
    let error = context.parse_program(source).expect_err(
        "expected repeat count above limit from constant to be rejected during analysis",
    );
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn exported_constant_with_private_local_dependency_is_fully_evaluated_in_analysis() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module_with_path(
            "wallet::memory",
            "
const ACCOUNT_ID_AND_NONCE_OFFSET = 4
pub const ACCOUNT_ID_SUFFIX_OFFSET = ACCOUNT_ID_AND_NONCE_OFFSET + 2
",
        )
        .expect("expected semantic analysis to succeed");

    let exported = exported_constant(&module, "ACCOUNT_ID_SUFFIX_OFFSET");
    assert_eq!(exported.value.expect_int().as_int(), 6);
    assert!(
        exported.value.references().is_empty(),
        "expected semantic analysis to remove private local constant references from exported constants",
    );
}

#[test]
fn define_items_detect_cross_kind_duplicates_for_all_pairs_and_orders() {
    let kinds = [
        DefinitionKind::Alias,
        DefinitionKind::Procedure,
        DefinitionKind::Constant,
        DefinitionKind::Type,
    ];
    for first in kinds {
        for second in kinds {
            if first == second {
                continue;
            }
            assert_cross_kind_conflict(first, second);
        }
    }
}
