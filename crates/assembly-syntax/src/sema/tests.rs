use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_debug_types::{Span, Spanned};

use crate::{
    MAX_REPEAT_COUNT, Path,
    ast::{
        Constant, ConstantExpr, ImportKind, Item, Module, ModuleKind, SymbolResolutionError,
        TypeAlias, TypeExpr, Visibility, constants::ConstEvalError, types,
    },
    diagnostics::reporting::PrintDiagnostic,
    sema::{SemanticAnalysisError, SyntaxError},
    testing::SyntaxTestContext,
};

fn exported_constant<'a>(module: &'a Module, name: &str) -> &'a Constant {
    match module
        .items()
        .iter()
        .find(|item| item.name().as_str() == name && item.visibility().is_public())
    {
        Some(Item::Constant(constant)) => constant,
        Some(item) => panic!("expected exported constant named {name}, found {item:?}"),
        None => panic!("expected exported constant named {name}"),
    }
}

fn assert_symbol_conflict(error: &miden_utils_diagnostics::Report, symbol: &str) {
    let syntax_error = syntax_error(error);

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

fn syntax_error(error: &miden_utils_diagnostics::Report) -> &SyntaxError {
    error.downcast_ref::<SyntaxError>().expect("expected SyntaxError report")
}

fn assert_undefined_symbol(error: &miden_utils_diagnostics::Report) {
    let syntax_error = syntax_error(error);
    assert!(
        syntax_error.errors.iter().any(|err| matches!(
            err,
            SemanticAnalysisError::SymbolResolutionError(inner)
                if matches!(**inner, SymbolResolutionError::UndefinedSymbol { .. })
        ) || matches!(
            err,
            SemanticAnalysisError::ConstEvalError(ConstEvalError::UndefinedSymbol { .. })
        )),
        "expected at least one undefined-symbol error, got: {:?}",
        syntax_error.errors
    );
}

fn unused_import_slices(error: &miden_utils_diagnostics::Report) -> Vec<String> {
    let syntax_error = syntax_error(error);
    syntax_error
        .errors
        .iter()
        .filter_map(|err| match err {
            SemanticAnalysisError::UnusedImport { span } => Some(
                syntax_error
                    .source_file
                    .source_slice(*span)
                    .expect("unused import span should be valid")
                    .to_string(),
            ),
            _ => None,
        })
        .collect()
}

fn assert_import(module: &Module, name: &str, kind: ImportKind, used: bool) {
    let import = module
        .imports()
        .find(|import| import.local_name().as_str() == name)
        .unwrap_or_else(|| panic!("expected import named {name}"));
    assert_eq!(import.kind(), kind);
    assert_eq!(import.is_used(), used);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DefinitionKind {
    ModuleImport,
    ItemImport,
    Procedure,
    Constant,
    Type,
}

impl DefinitionKind {
    fn declaration(self, symbol: &str) -> String {
        match self {
            Self::ModuleImport => format!("use ::dep::{}", quote_ident_if_needed(symbol)),
            Self::ItemImport => format!("use {{{}}} from ::dep", quote_ident_if_needed(symbol)),
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
    let error = context.parse_module(&source).expect_err(&message);
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    if error.downcast_ref::<SyntaxError>().is_none() {
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
fn empty_enum_still_reports_type_name_conflicts() {
    let context = SyntaxTestContext::default();
    let source = "\
namespace test
type thing = felt
enum thing: u8 {}
";
    let error = context
        .parse_module(source)
        .expect_err("expected symbol conflict when enum name matches existing type");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert_symbol_conflict(&error, "thing");
    assert!(rendered.contains("symbol conflict"));
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
        .parse_program(&source)
        .expect_err("expected repeat count above limit to be rejected during analysis");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_at_limit_allowed_in_analysis() {
    let context = SyntaxTestContext::default();
    let source = format!("begin repeat.{MAX_REPEAT_COUNT} nop end end");
    let _module = context
        .parse_program(&source)
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
        .parse_program(&source)
        .expect("expected repeat count at limit from constant to be accepted during analysis");
}

#[test]
fn repeat_count_constant_too_large_rejected_in_analysis() {
    let context = SyntaxTestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source =
        format!("const REPEAT_COUNT = {repeat_count}\nbegin repeat.REPEAT_COUNT nop end end");
    let error = context.parse_program(&source).expect_err(
        "expected repeat count above limit from constant to be rejected during analysis",
    );
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn expected_path_is_used_when_namespace_is_omitted() {
    let context = SyntaxTestContext::default();
    let mut parser = Module::parser(None);
    let module = parser
        .parse_str(
            Some(Path::new("app::helpers")),
            "pub proc helper\n    push.1\nend",
            context.source_manager(),
        )
        .expect("expected parser-provided namespace to be applied");

    assert_eq!(module.path(), Path::new("::app::helpers"));
    assert!(module.namespace_decl.is_none());
}

#[test]
fn explicit_namespace_is_normalized_before_expected_path_check() {
    let context = SyntaxTestContext::default();
    let mut parser = Module::parser(None);
    let module = parser
        .parse_str(
            Some(Path::new("app::helpers")),
            "namespace app::helpers\n\npub proc helper\n    push.1\nend",
            context.source_manager(),
        )
        .expect("expected matching relative namespace declaration to be accepted");

    assert_eq!(module.path(), Path::new("::app::helpers"));
}

#[test]
fn explicit_namespace_conflict_still_reports_expected_path() {
    let context = SyntaxTestContext::default();
    let mut parser = Module::parser(None);
    let error = parser
        .parse_str(
            Some(Path::new("app::helpers")),
            "namespace other::helpers\n\npub proc helper\n    push.1\nend",
            context.source_manager(),
        )
        .expect_err("expected mismatched namespace declaration to be rejected");

    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("conflicting module namespace specification"));
    assert!(rendered.contains("expected '::app::helpers'"));
    assert!(rendered.contains("got '::other::helpers'"));
}

#[test]
fn exported_constant_with_private_local_dependency_is_fully_evaluated_in_analysis() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_module(
            "
namespace wallet::memory

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
fn exported_proc_signature_rejects_private_local_type() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            "
namespace test

type PrivateType = felt

pub proc check(value: PrivateType)
    nop
end
",
        )
        .expect_err("expected exported procedure signature to reject private local type");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("private type in exported procedure signature"));
}

#[test]
fn exported_type_alias_rejects_private_type() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            "
namespace test

type PrivateType = felt
pub type PublicAlias = PrivateType
",
        )
        .expect_err("expected exported type alias to reject private type");
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("private type in exported type declaration"));
}

#[test]
fn exported_proc_signature_rejects_private_local_type_via_absolute_path() {
    let context = SyntaxTestContext::default();
    let mut parser = Module::parser(None);
    let error = parser
        .parse_str(
            Some(Path::new("wallet::memory")),
            "
type PrivateType = felt

pub proc check(value: ::wallet::memory::PrivateType)
    nop
end
",
            context.source_manager(),
        )
        .expect_err(
            "expected exported procedure signature to reject private local type via absolute path",
        );
    let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("private type in exported procedure signature"));
}

#[test]
fn private_proc_signature_allows_private_local_type() {
    let context = SyntaxTestContext::default();
    context
        .parse_module(
            "
namespace test

type PrivateType = felt

proc check(value: PrivateType)
    nop
end
",
        )
        .expect("expected private procedure signature to allow private local type");
}

#[test]
fn sema_import_define_items_detect_cross_kind_duplicates_for_all_pairs_and_orders() {
    let kinds = [
        DefinitionKind::ModuleImport,
        DefinitionKind::ItemImport,
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

#[test]
fn sema_import_single_segment_module_import_resolves_qualified_invocation() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use foo
begin
    exec.foo::procedure
end
",
        )
        .expect("expected single-segment module import to resolve qualified invocation");

    assert_import(&module, "foo", ImportKind::Module, true);
}

#[test]
fn sema_import_multi_segment_module_import_resolves_via_last_segment() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use some::module
begin
    exec.module::procedure
end
",
        )
        .expect("expected multi-segment module import to bind final path segment");

    assert_import(&module, "module", ImportKind::Module, true);
}

#[test]
fn sema_import_module_alias_resolves_qualified_invocation() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use some::module as sm
begin
    exec.sm::procedure
end
",
        )
        .expect("expected module import alias to resolve qualified invocation");

    assert_import(&module, "sm", ImportKind::Module, true);
}

#[test]
fn sema_import_module_import_rejects_unqualified_proc_reference() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program(
            "
use foo
begin
    exec.foo
end
",
        )
        .expect_err("module imports must not resolve unqualified procedure references");

    assert_undefined_symbol(&error);
}

#[test]
fn sema_import_module_import_rejects_unqualified_const_reference() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program(
            "
use FOO
begin
    push.FOO
end
",
        )
        .expect_err("module imports must not resolve unqualified constant references");

    assert_undefined_symbol(&error);
}

#[test]
fn sema_import_module_import_rejects_unqualified_type_reference() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_program(
            "
use foo
type T = foo
begin
    nop
end
",
        )
        .expect_err("module imports must not resolve unqualified type references");

    assert_undefined_symbol(&error);
}

#[test]
fn sema_import_item_proc_resolves_unqualified_invocation() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {procedure} from some::module
begin
    exec.procedure
end
",
        )
        .expect("expected item import to resolve unqualified procedure invocation");

    assert_import(&module, "procedure", ImportKind::Item, true);
}

#[test]
fn sema_import_item_const_resolves_constant_reference() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {VALUE} from some::module
begin
    push.VALUE
end
",
        )
        .expect("expected item import to resolve unqualified constant reference");

    assert_import(&module, "VALUE", ImportKind::Item, true);
}

#[test]
fn sema_import_item_type_resolves_type_reference() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {ForeignType} from some::module
type LocalType = ForeignType
begin
    nop
end
",
        )
        .expect("expected item import to resolve unqualified type reference");

    assert_import(&module, "ForeignType", ImportKind::Item, true);
}

#[test]
fn sema_import_renamed_proc_resolves_local_name() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {procedure as local_procedure} from some::module
begin
    exec.local_procedure
end
",
        )
        .expect("expected renamed procedure item import to resolve by local name");

    assert_import(&module, "local_procedure", ImportKind::Item, true);
}

#[test]
fn sema_import_renamed_const_resolves_local_name() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {VALUE as LOCAL_VALUE} from some::module
begin
    push.LOCAL_VALUE
end
",
        )
        .expect("expected renamed constant item import to resolve by local name");

    assert_import(&module, "LOCAL_VALUE", ImportKind::Item, true);
}

#[test]
fn sema_import_renamed_type_resolves_local_name() {
    let context = SyntaxTestContext::default();
    let module = context
        .parse_program(
            "
use {ForeignType as LocalImportType} from some::module
type LocalType = LocalImportType
begin
    nop
end
",
        )
        .expect("expected renamed type item import to resolve by local name");

    assert_import(&module, "LocalImportType", ImportKind::Item, true);
}

#[test]
fn sema_import_duplicate_local_names_in_item_group_conflict() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            "
namespace test
use {foo, bar as foo} from some::module
",
        )
        .expect_err("duplicate local item import names should conflict");

    assert_symbol_conflict(&error, "foo");
}

#[test]
fn sema_import_item_import_conflicts_with_proc_const_type_and_submodule() {
    let context = SyntaxTestContext::default();
    for source in [
        "namespace test\nuse {foo} from dep\nproc foo\n    nop\nend\n",
        "namespace test\nproc foo\n    nop\nend\nuse {foo} from dep\n",
        "namespace test\nuse {VALUE} from dep\nconst VALUE = 1\n",
        "namespace test\nconst VALUE = 1\nuse {VALUE} from dep\n",
        "namespace test\nuse {Thing} from dep\ntype Thing = felt\n",
        "namespace test\ntype Thing = felt\nuse {Thing} from dep\n",
        "namespace test\nuse {foo} from dep\nmod foo\n",
        "namespace test\nmod foo\nuse {foo} from dep\n",
    ] {
        let error = context
            .parse_module(source)
            .expect_err("item import should conflict with local namespace declaration");
        let expected = if source.contains("VALUE") {
            "VALUE"
        } else if source.contains("Thing") {
            "Thing"
        } else {
            "foo"
        };
        assert_symbol_conflict(&error, expected);
    }
}

#[test]
fn sema_import_item_import_conflicts_with_module_import_alias() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            "
namespace test
use dep
use {foo as dep} from other
",
        )
        .expect_err("item import should conflict with existing module import alias");

    assert_symbol_conflict(&error, "dep");
}

#[test]
fn sema_import_module_import_alias_conflicts_with_item_import() {
    let context = SyntaxTestContext::default();
    let error = context
        .parse_module(
            "
namespace test
use {foo as dep} from other
use dep
",
        )
        .expect_err("module import alias should conflict with existing item import");

    assert_symbol_conflict(&error, "dep");
}

#[test]
fn sema_import_unused_module_import_warns_on_local_name_span() {
    let context = SyntaxTestContext::new().with_warnings_as_errors(true);
    let error = context
        .parse_module(
            "
namespace test
use some::module as sm
",
        )
        .expect_err("unused module import should warn on local name span");

    assert_eq!(unused_import_slices(&error), vec!["sm"]);
}

#[test]
fn sema_import_unused_grouped_items_warn_on_each_item_local_name_span() {
    let context = SyntaxTestContext::new().with_warnings_as_errors(true);
    let error = context
        .parse_module(
            "
namespace test
use {foo, bar as baz} from some::module
",
        )
        .expect_err("unused grouped item imports should warn on each local name span");

    assert_eq!(unused_import_slices(&error), vec!["foo", "baz"]);
}

#[test]
fn sema_import_used_grouped_item_suppresses_only_that_item_warning() {
    let context = SyntaxTestContext::new().with_warnings_as_errors(true);
    let error = context
        .parse_module(
            "
namespace test
use {foo, bar as baz} from some::module
proc local
    exec.foo
end
",
        )
        .expect_err("only unused grouped item imports should warn");

    assert_eq!(unused_import_slices(&error), vec!["baz"]);
}

#[test]
fn docs_import_docstrings_before_imports_and_reexports_warn_and_do_not_attach() {
    let context = SyntaxTestContext::new().with_warnings_as_errors(true);
    for source in [
        "
namespace test
#! import docs
use dep
",
        "
namespace test
#! import docs
use {foo} from dep
",
        "
namespace test
#! re-export docs
pub use {foo} from dep
",
    ] {
        let error = context
            .parse_module(source)
            .expect_err("doc comments before imports and re-exports should warn");
        let syntax_error = syntax_error(&error);
        assert!(
            syntax_error
                .errors
                .iter()
                .any(|err| matches!(err, SemanticAnalysisError::ImportDocstring { .. })),
            "expected ImportDocstring warning, got: {:?}",
            syntax_error.errors
        );

        let rendered = format!("{}", PrintDiagnostic::new_without_color(&error));
        assert!(rendered.contains("imports and re-exports cannot have docstrings"), "{rendered}");
    }
}

#[test]
fn sema_import_old_no_brace_item_import_not_usable_as_proc_const_or_type() {
    let context = SyntaxTestContext::default();
    for source in [
        "use dep::foo\nbegin\n    exec.foo\nend\n",
        "use dep::FOO\nbegin\n    push.FOO\nend\n",
        "use dep::Foo\ntype T = Foo\nbegin\n    nop\nend\n",
    ] {
        let error = context
            .parse_program(source)
            .expect_err("old no-brace item import syntax should behave as a module import");
        assert_undefined_symbol(&error);
    }
}

#[test]
fn name_map_stays_consistent_after_take_items() {
    // Verify that take_items() clears the name index, so re-adding the same
    // name after a take does not trigger a false conflict.
    let mut module = Module::new(ModuleKind::Library, Path::new("mod"));
    module
        .define_constant(constant_with_name("foo"))
        .expect("first insertion should succeed");

    let _items = module.take_items();

    // After take_items(), name_map is cleared — same name should succeed again.
    module
        .define_constant(constant_with_name("foo"))
        .expect("re-insertion after take_items should succeed");
}

#[test]
fn name_map_detects_conflict_via_define_api() {
    // Verify that duplicate names are detected through the define_* API.
    let mut module = Module::new(ModuleKind::Library, Path::new("mod"));
    module
        .define_constant(constant_with_name("dup"))
        .expect("first insertion should succeed");

    let result = module.define_constant(constant_with_name("dup"));
    assert!(
        matches!(result, Err(SemanticAnalysisError::SymbolConflict { .. })),
        "expected SymbolConflict for duplicate name, got {result:?}"
    );
}

#[test]
fn name_map_rebuilds_after_mutable_item_rename() {
    let mut module = Module::new(ModuleKind::Library, Path::new("mod"));
    module
        .define_constant(constant_with_name("old"))
        .expect("first insertion should succeed");

    for item in module.items_mut() {
        let Item::Constant(constant) = item else {
            continue;
        };
        constant.name = ident_with_name("dup");
    }

    let result = module.define_type(type_alias_with_name("dup"));
    assert!(
        matches!(result, Err(SemanticAnalysisError::SymbolConflict { .. })),
        "expected SymbolConflict after renaming through items_mut(), got {result:?}"
    );
}

#[test]
fn name_map_drops_old_name_after_mutable_item_rename() {
    let mut module = Module::new(ModuleKind::Library, Path::new("mod"));
    module
        .define_constant(constant_with_name("old"))
        .expect("first insertion should succeed");

    for item in module.items_mut() {
        let Item::Constant(constant) = item else {
            continue;
        };
        constant.name = ident_with_name("new");
    }

    module
        .define_type(type_alias_with_name("old"))
        .expect("old name should be available after the name map is rebuilt");
}

#[test]
fn enum_variant_matching_enum_name_reports_symbol_conflict() {
    let context = SyntaxTestContext::default();
    let source = "\
namespace test

enum DUP : u8 {
    DUP,
}
";
    let error = context
        .parse_module(source)
        .expect_err("expected symbol conflict when enum variant matches enum name");
    assert_symbol_conflict(&error, "DUP");
}
