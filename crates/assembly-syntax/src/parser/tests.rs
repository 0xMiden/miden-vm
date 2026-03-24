use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use miden_core::assert_matches;
use miden_debug_types::{SourceFile, SourceId, SourceLanguage, Uri};

use super::*;

fn test_source_file(source: &str) -> Arc<SourceFile> {
    Arc::new(SourceFile::new(
        SourceId::default(),
        SourceLanguage::Masm,
        Uri::new("memory:///parser-backend-test.masm"),
        source.to_string().into_boxed_str(),
    ))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root should be two levels above crates/assembly-syntax")
        .to_path_buf()
}

fn checked_in_masm_corpus() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    for relative in [
        "crates/lib/core/asm",
        "crates/project/examples",
        "miden-vm/masm-examples",
        "miden-vm/tests/integration/cli/data",
    ] {
        collect_masm_files(&root.join(relative), &mut files);
    }
    files.sort();
    files
}

fn collect_masm_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| {
            panic!("failed to read a directory entry under {}: {error}", dir.display())
        });
        let path = entry.path();
        if path.is_dir() {
            collect_masm_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "masm") {
            files.push(path);
        }
    }
}

fn load_source_file(path: &Path) -> Arc<SourceFile> {
    let source = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    Arc::new(SourceFile::new(
        SourceId::default(),
        SourceLanguage::Masm,
        Uri::new(format!("file://{}", path.display())),
        source.into_boxed_str(),
    ))
}

// This test checks the lexer behavior with regard to tokenizing `exp(.u?[\d]+)?`
#[test]
fn lex_exp() {
    let source_id = SourceId::default();
    let scanner = Scanner::new("begin exp.u9 end");
    let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
    assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
    assert_matches!(lexer.next(), Some(Ok(Token::ExpU)));
    assert_matches!(lexer.next(), Some(Ok(Token::Int(n))) if n == 9);
    assert_matches!(lexer.next(), Some(Ok(Token::End)));
}

#[test]
fn lex_block() {
    let source_id = SourceId::default();
    let scanner = Scanner::new(
        "\
const ERR1 = 1

begin
    u32assertw
    u32assertw.err=ERR1
    u32assertw.err=2
end
",
    );
    let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
    assert_matches!(lexer.next(), Some(Ok(Token::Const)));
    assert_matches!(lexer.next(), Some(Ok(Token::ConstantIdent("ERR1"))));
    assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
    assert_matches!(lexer.next(), Some(Ok(Token::Int(1))));
    assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
    assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
    assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
    assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
    assert_matches!(lexer.next(), Some(Ok(Token::Err)));
    assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
    assert_matches!(lexer.next(), Some(Ok(Token::ConstantIdent("ERR1"))));
    assert_matches!(lexer.next(), Some(Ok(Token::U32Assertw)));
    assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
    assert_matches!(lexer.next(), Some(Ok(Token::Err)));
    assert_matches!(lexer.next(), Some(Ok(Token::Equal)));
    assert_matches!(lexer.next(), Some(Ok(Token::Int(2))));
    assert_matches!(lexer.next(), Some(Ok(Token::End)));
    assert_matches!(lexer.next(), Some(Ok(Token::Eof)));
}

#[test]
fn lex_emit() {
    let source_id = SourceId::default();
    let scanner = Scanner::new(
        "\
begin
    push.1
    emit.event(\"abc\")
end
",
    );
    let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));
    assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
    assert_matches!(lexer.next(), Some(Ok(Token::Push)));
    assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
    assert_matches!(lexer.next(), Some(Ok(Token::Int(1))));
    assert_matches!(lexer.next(), Some(Ok(Token::Emit)));
    assert_matches!(lexer.next(), Some(Ok(Token::Dot)));
    assert_matches!(lexer.next(), Some(Ok(Token::Event)));
    assert_matches!(lexer.next(), Some(Ok(Token::Lparen)));
    assert_matches!(lexer.next(), Some(Ok(Token::QuotedIdent("abc"))));
    assert_matches!(lexer.next(), Some(Ok(Token::Rparen)));
    assert_matches!(lexer.next(), Some(Ok(Token::End)));
    assert_matches!(lexer.next(), Some(Ok(Token::Eof)));
}

#[test]
fn lex_invalid_token_after_whitespace_returns_error() {
    let source_id = SourceId::default();
    let scanner = Scanner::new("begin \u{0001}\nend\n");
    let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));

    assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
    assert_matches!(
        lexer.next(),
        Some(Err(ParsingError::InvalidToken { span })) if span.into_range() == (6..7)
    );
}

#[test]
fn lex_invalid_underscore_token_span() {
    let source_id = SourceId::default();
    let scanner = Scanner::new("begin _-\nend\n");
    let mut lexer = Lexer::new(source_id, scanner).map(|result| result.map(|(_, t, _)| t));

    assert_matches!(lexer.next(), Some(Ok(Token::Begin)));
    assert_matches!(
        lexer.next(),
        Some(Err(ParsingError::InvalidToken { span })) if span.into_range() == (6..7)
    );
}

#[test]
fn lex_single_char_token_and_ident_spans() {
    let source_id = SourceId::default();
    let scanner = Scanner::new("@\nA\n");
    let mut lexer = Lexer::new(source_id, scanner);

    assert_matches!(lexer.next(), Some(Ok((0, Token::At, 1))));
    assert_matches!(lexer.next(), Some(Ok((2, Token::ConstantIdent("A"), 3))));
}

#[test]
fn overlong_path_component_is_rejected_without_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::{
        debuginfo::DefaultSourceManager,
        parse::{Parse, ParseOptions},
    };

    let big_component = "a".repeat(256);
    let source = format!("begin\n    exec.{big_component}::x::foo\nend\n");

    let source_manager = Arc::new(DefaultSourceManager::default());
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        source.parse_with_options(source_manager, ParseOptions::default())
    }));

    assert!(parsed.is_ok(), "parsing panicked, expected a structured error");
    let err = parsed.unwrap().expect_err("parsing succeeded, expected an error");
    crate::assert_diagnostic!(err, "length exceeds the maximum of 255 bytes");
}

#[test]
fn parse_forms_uses_cst_backend_by_default_under_std() {
    let source = test_source_file(
        "\
const ERR = 1
begin
    push.1
    add
end
",
    );

    let default = parse_forms(source.clone()).expect("default parser should succeed");
    let cst = parse_forms_with_backend(source.clone(), ParserBackend::Cst)
        .expect("cst backend should succeed");
    let legacy = parse_forms_with_backend(source, ParserBackend::Legacy)
        .expect("legacy parser should succeed");

    assert_eq!(default, cst);
    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_top_level_form_sequences() {
    let source = test_source_file(
        "\
#! Module docs line 1
#! Module docs line 2

#! Import docs
use std::math::u64

#! Constant docs
const ERR = 1

type FeltAlias = felt
adv_map TABLE = [1, 2]
begin
    nop
end

@locals(1)
pub proc foo
    loc_load.0
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_doc_comment_trimming() {
    let source = test_source_file(
        "\
#! heading
#!  - bullet
#!    continuation

#!  item docs
const VALUE = 1
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_doc_kind_after_leading_line_comment() {
    let source = test_source_file(
        "\
# heading comment

#! item docs
pub proc foo
    nop
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_path_import_forms() {
    let source = test_source_file(
        "\
use std::math::u64
pub use ::std::math::u64->math_u64
use foo::\"miden::base/account@0.1.0\"->account
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_digest_import_forms() {
    let source = test_source_file(
        "\
use 0x0000000000000000000000000000000000000000000000000000000000000000->entry
pub use 0x0000000000000000000000000000000000000000000000000000000000000000->public_entry
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_reports_unnamed_digest_imports() {
    let source = test_source_file(
        "\
use 0x0000000000000000000000000000000000000000000000000000000000000000
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::UnnamedReexportOfMastRoot { .. }));
    assert_matches!(cst, Err(ParsingError::UnnamedReexportOfMastRoot { .. }));
}

#[test]
fn cst_backend_reports_invalid_digest_imports() {
    let source = test_source_file("use 0x1234->entry\n");

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::InvalidMastRoot { .. }));
    assert_matches!(cst, Err(ParsingError::InvalidMastRoot { .. }));
}

#[test]
fn cst_backend_matches_legacy_constant_forms() {
    let source = test_source_file(
        "\
const WORD = [1, 2, 3, 4]
const DIGEST = word(\"miden::digest\")
const EVENT_ID = event(\"miden::event\")
const VALUE = (parts::COUNT + 3) // 2
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_string_constant_forms() {
    let source = test_source_file("const ERR = \"failed to load the circuit description\"\n");

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_type_alias_forms() {
    let source = test_source_file(
        "\
type WordAlias = word
type Buffer = ptr<u8, addrspace(byte)>
type Digest = [u32; 4]
type Point = struct @align(16) { x: u32, y: ptr<u8, addrspace(byte)> }
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_enum_forms() {
    let source = test_source_file(
        "\
enum Tag : u8 {
    A,
    B = 2,
    C = B * 2,
    D,
}

pub enum Result : felt {
    OK = 1,
    ERR = OK + 1,
}
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_procedure_signatures() {
    let source = test_source_file(
        "\
pub proc println(message: ptr<u8, addrspace(byte)>) -> ptr<u8, addrspace(byte)>
    nop
end

pub proc classify(value: felt) -> (ok: i1, words: [u32; 4])
    push.1
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_advice_map_and_begin_forms() {
    let source = test_source_file(
        "\
adv_map TABLE = [1, 2, 3]
adv_map DIGEST([1, 2, 3, 4]) = [5, 6]

begin
    push.1
    add
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_procedure_attributes() {
    let source = test_source_file(
        "\
@inline
@storage(offset = 1)
@storage(size = 2)
@callconv(\"C\")
@locals(4)
pub proc foo(a: felt) -> felt
    push.1
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_nested_structured_blocks() {
    let source = test_source_file(
        "\
const COUNT = 3

begin
    if.true
        add.0
    else
        push.1
    end

    if.false
        push.2
    else
        mul
    end

    while.true
        repeat.COUNT
            push.1
        end
        neq.0
    end
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_primitive_instruction_blocks() {
    let source = test_source_file(
        "\
begin
    add
    eq
    dup
    swap
    assert
    adv.insert_hdword
    adv.push_mapvaln
    emit
    debug.stack
    mem_load
    u32div
    add.1
    dup.3
    adv.push_mapvaln.4
    u32shl.1
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_immediate_instruction_blocks() {
    let source = test_source_file(
        "\
begin
    add.1
    eq.FLAG
    lt.3
    exp.u32
    exp.POWER
    mem_load.0b1010
    locaddr.LOCAL
    adv_push.1
    dup.3
    swap.2
    movup.4
    adv.push_mapvaln.8
    u32div.1
    u32wrapping_mul.0
    u32and.MASK
    u32shl.SHIFT
    debug.stack.4
    push.1
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_extended_instruction_blocks() {
    let source = test_source_file(
        "\
begin
    push.1.2.3
    push.[1,2,3,4]
    push.[1,2,3,4][1]
    push.[1,2,3,4][1..3]
    exec.foo
    call.foo::bar
    syscall.0x065c394c00227acff3545da5493cf1b79d9a9f5628db553d240edf8ef0cca04a
    procref.foo::bar
    debug.adv_stack
    debug.adv_stack.2
    debug.mem.1
    debug.mem.1.2
    debug.local.3
    debug.local.3.4
    emit.EVENT_ID
    emit.event(\"abc\")
    trace.7
    assert.err=\"oops\"
    u32assert.err=ERR_CODE
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy)
        .expect("legacy parser should succeed");
    let cst =
        parse_forms_with_backend(source, ParserBackend::Cst).expect("cst backend should succeed");

    assert_eq!(cst, legacy);
}

#[test]
fn cst_backend_matches_legacy_checked_in_masm_corpus() {
    let files = checked_in_masm_corpus();
    assert!(
        !files.is_empty(),
        "expected the checked-in MASM corpus to contain at least one source file"
    );

    for path in files {
        let source = load_source_file(&path);
        let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
        let cst = parse_forms_with_backend(source, ParserBackend::Cst);
        assert_eq!(cst, legacy, "parser backend mismatch for {}", path.display());
    }
}

#[test]
fn cst_backend_reports_unqualified_imports() {
    let source = test_source_file("use foo\n");

    let err = parse_forms_with_backend(source, ParserBackend::Cst)
        .expect_err("cst backend should reject unqualified imports");

    assert_matches!(err, ParsingError::UnqualifiedImport { .. });
}

#[test]
fn cst_backend_reports_invalid_struct_repr_from_direct_type_lowering() {
    let source = test_source_file("type Foo = struct @align { x: u32 }\n");

    let err = parse_forms_with_backend(source, ParserBackend::Cst)
        .expect_err("cst backend should reject invalid struct repr");

    assert_matches!(err, ParsingError::InvalidStructRepr { .. });
}

#[test]
fn cst_backend_reports_attribute_key_value_conflicts() {
    let source = test_source_file(
        "\
@storage(offset = 1)
@storage(offset = 2)
proc foo
    nop
end
",
    );

    let err = parse_forms_with_backend(source, ParserBackend::Cst)
        .expect_err("cst backend should reject conflicting attribute keys");

    assert_matches!(err, ParsingError::AttributeKeyValueConflict { .. });
}

#[test]
fn cst_backend_reports_invalid_advice_map_keys() {
    let source = test_source_file("adv_map TABLE(1) = [1]\n");

    let err = parse_forms_with_backend(source, ParserBackend::Cst)
        .expect_err("cst backend should reject invalid advice-map keys");

    assert_matches!(err, ParsingError::InvalidAdvMapKey { .. });
}

#[test]
fn cst_backend_reports_direct_division_by_zero_for_foldable_instructions() {
    let source = test_source_file(
        "\
begin
    u32div.0
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::DivisionByZero { .. }));
    assert_matches!(cst, Err(ParsingError::DivisionByZero { .. }));
}

#[test]
fn cst_backend_reports_direct_invalid_pad_values() {
    let source = test_source_file(
        "\
begin
    adv.push_mapvaln.5
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::InvalidPadValue { .. }));
    assert_matches!(cst, Err(ParsingError::InvalidPadValue { .. }));
}

#[test]
fn cst_backend_reports_direct_invalid_mast_roots() {
    let source = test_source_file(
        "\
begin
    exec.0x1234
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::InvalidMastRoot { .. }));
    assert_matches!(cst, Err(ParsingError::InvalidMastRoot { .. }));
}

#[test]
fn cst_backend_reports_direct_push_overflow() {
    let source = test_source_file(
        "\
begin
    push.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::PushOverflow { count: 17, .. }));
    assert_matches!(cst, Err(ParsingError::PushOverflow { count: 17, .. }));
}

#[test]
fn cst_backend_reports_direct_deprecated_memory_word_aliases() {
    let source = test_source_file(
        "\
begin
    mem_loadw.1
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::DeprecatedInstruction { .. }));
    assert_matches!(cst, Err(ParsingError::DeprecatedInstruction { .. }));
}

#[test]
fn cst_backend_reports_direct_deprecated_local_word_aliases() {
    let source = test_source_file(
        "\
begin
    loc_storew.0
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert_matches!(legacy, Err(ParsingError::DeprecatedInstruction { .. }));
    assert_matches!(cst, Err(ParsingError::DeprecatedInstruction { .. }));
}

#[test]
fn cst_backend_reports_direct_invalid_instruction_syntax() {
    let source = test_source_file(
        "\
begin
    u32widening_mulx
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert!(legacy.is_err(), "legacy parser should reject invalid instructions");
    assert_matches!(cst, Err(ParsingError::InvalidSyntax { .. }));
}

#[test]
fn cst_backend_rejects_empty_while_blocks() {
    let source = test_source_file(
        "\
begin
    while.true
    end
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert!(legacy.is_err(), "legacy parser should reject empty while blocks");
    assert!(cst.is_err(), "cst backend should reject empty while blocks");
}

#[test]
fn cst_backend_rejects_empty_if_then_without_else() {
    let source = test_source_file(
        "\
begin
    if.true
    end
end
",
    );

    let legacy = parse_forms_with_backend(source.clone(), ParserBackend::Legacy);
    let cst = parse_forms_with_backend(source, ParserBackend::Cst);

    assert!(legacy.is_err(), "legacy parser should reject empty if-then blocks");
    assert!(cst.is_err(), "cst backend should reject empty if-then blocks");
}

#[test]
fn cst_backend_reports_cst_parse_errors() {
    let source = test_source_file("begin\n    if.true\n        add\n");

    let err = parse_forms_with_backend(source, ParserBackend::Cst)
        .expect_err("cst backend should surface a parse error");

    assert_matches!(
        err,
        ParsingError::InvalidSyntax { message, .. } if message.contains("expected `end`")
    );
}
