use std::{
    fs,
    path::{Path, PathBuf},
    string::String,
    sync::Arc,
};

use miden_core::assert_matches;
use miden_debug_types::{SourceFile, SourceId, SourceLanguage, Uri};

use super::*;
use crate::ast::{Form, Immediate, Instruction, Op};

fn test_source_file(source: &str) -> Arc<SourceFile> {
    Arc::new(SourceFile::new(
        SourceId::default(),
        SourceLanguage::Masm,
        Uri::new("memory:///parser-test.masm"),
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

fn render_diagnostic(diag: impl AsRef<dyn crate::diagnostics::Diagnostic>) -> String {
    crate::diagnostics::reporting::PrintDiagnostic::new_without_color(diag).to_string()
}

fn assert_parses(source: Arc<SourceFile>) {
    parse_forms(source).expect("parser should succeed");
}

#[test]
fn overlong_path_component_is_rejected_without_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::{
        debuginfo::DefaultSourceManager,
        parse::{Parse, ParseOptions},
    };

    let big_component = "a".repeat(u16::MAX as usize);
    let source = format!("begin\n    exec.{big_component}::x::foo\nend\n");

    let source_manager = Arc::new(DefaultSourceManager::default());
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        source.parse_with_options(source_manager, ParseOptions::default())
    }));

    assert!(parsed.is_ok(), "parsing panicked, expected a structured error");
    let err = parsed.unwrap().expect_err("parsing succeeded, expected an error");
    crate::assert_diagnostic!(err, "invalid item path: too long (max 65535 bytes)");
}

#[test]
fn parse_forms_parses_basic_program_forms() {
    let source = test_source_file(
        "\
const ERR = 1
begin
    push.1
    add
end
",
    );

    let forms = parse_forms(source).expect("parser should succeed");
    assert_eq!(forms.len(), 2);
}

#[test]
fn parse_top_level_form_sequences() {
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

    assert_parses(source);
}

#[test]
fn parse_doc_comment_trimming() {
    let source = test_source_file(
        "\
#! heading
#!  - bullet
#!    continuation

#!  item docs
const VALUE = 1
",
    );

    assert_parses(source);
}

#[test]
fn parse_doc_kind_after_leading_line_comment() {
    let source = test_source_file(
        "\
# heading comment

#! item docs
pub proc foo
    nop
end
",
    );

    assert_parses(source);
}

#[test]
fn parse_path_import_forms() {
    let source = test_source_file(
        "\
use std::math::u64
pub use ::std::math::u64->math_u64
use foo::\"miden::base/account@0.1.0\"->account
",
    );

    assert_parses(source);
}

#[test]
fn parse_digest_import_forms() {
    let source = test_source_file(
        "\
use 0x0000000000000000000000000000000000000000000000000000000000000000->entry
pub use 0x0000000000000000000000000000000000000000000000000000000000000000->public_entry
",
    );

    assert_parses(source);
}

#[test]
fn parser_reports_unnamed_digest_imports() {
    let source = test_source_file(
        "\
use 0x0000000000000000000000000000000000000000000000000000000000000000
",
    );

    let err = parse_forms(source).expect_err("expected unnamed reexport error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("re-exporting a procedure identified by digest requires giving it a name"));
}

#[test]
fn parser_reports_invalid_digest_imports() {
    let source = test_source_file("use 0x1234->entry\n");

    let err = parse_forms(source).expect_err("expected invalid digest error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid MAST root literal"));
}

#[test]
fn parse_constant_forms() {
    let source = test_source_file(
        "\
const WORD = [1, 2, 3, 4]
const DIGEST = word(\"miden::digest\")
const EVENT_ID = event(\"miden::event\")
const VALUE = (parts::COUNT + 3) // 2
",
    );

    assert_parses(source);
}

#[test]
fn parser_preserves_literal_constant_expr_tree() {
    let source = test_source_file("const VALUE = 1 + 2 * 3\n");
    let forms = parse_forms(source).expect("parser should succeed");
    let [Form::Constant(constant)] = forms.as_slice() else {
        panic!("expected one constant form, got {forms:?}");
    };

    let ast::ConstantExpr::BinaryOp { op, lhs, rhs, .. } = &constant.value else {
        panic!("expected addition expression, got {:?}", constant.value);
    };
    assert_eq!(*op, ast::ConstantOp::Add);
    assert!(matches!(lhs.as_ref(), ast::ConstantExpr::Int(value)
        if *value.inner() == IntValue::U8(1)));

    let ast::ConstantExpr::BinaryOp { op, lhs, rhs, .. } = rhs.as_ref() else {
        panic!("expected multiplication expression, got {rhs:?}");
    };
    assert_eq!(*op, ast::ConstantOp::Mul);
    assert!(matches!(lhs.as_ref(), ast::ConstantExpr::Int(value)
        if *value.inner() == IntValue::U8(2)));
    assert!(matches!(rhs.as_ref(), ast::ConstantExpr::Int(value)
        if *value.inner() == IntValue::U8(3)));
}

#[test]
fn parse_string_constant_forms() {
    let source = test_source_file("const ERR = \"failed to load the circuit description\"\n");

    assert_parses(source);
}

#[test]
fn parse_type_alias_forms() {
    let source = test_source_file(
        "\
type WordAlias = word
type Buffer = ptr<u8, addrspace(byte)>
type Digest = [u32; 4]
type Point = struct @align(16) { x: u32, y: ptr<u8, addrspace(byte)> }
",
    );

    assert_parses(source);
}

#[test]
fn parse_enum_forms() {
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

    assert_parses(source);
}

#[test]
fn parse_procedure_signatures() {
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

    assert_parses(source);
}

#[test]
fn parse_advice_map_and_begin_forms() {
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

    assert_parses(source);
}

#[test]
fn parse_procedure_attributes() {
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

    assert_parses(source);
}

#[test]
fn parse_nested_structured_blocks() {
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

    assert_parses(source);
}

#[test]
fn parse_empty_else_block() {
    let source = test_source_file(
        "\
begin
    if.true
        add
    else
    end
end
",
    );

    parse_forms(source).expect("parser should accept an empty else block");
}

#[test]
fn parse_if_false_with_else() {
    let source = test_source_file(
        "\
begin
    if.false
        add
    else
        mul
    end
end
",
    );

    parse_forms(source).expect("parser should accept if.false with else");
}

#[test]
fn parse_primitive_instruction_blocks() {
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
    mem_load
    u32div
    add.1
    dup.3
    adv.push_mapvaln.4
    u32shl.1
end
",
    );

    assert_parses(source);
}

#[test]
fn parse_immediate_instruction_blocks() {
    let source = test_source_file(
        "\
begin
    add.1
    eq.FLAG
    exp.u32
    exp.POWER
    mem_load.0b1010
    locaddr.LOCAL
    dup.3
    swap.2
    movup.4
    adv.push_mapvaln.8
    u32div.1
    u32wrapping_mul.0
    u32and.MASK
    u32shl.SHIFT
    push.1
end
",
    );

    assert_parses(source);
}

#[test]
fn parser_preserves_explicit_zero_shift_rotate_instructions() {
    let source = test_source_file(
        "\
begin
    u32shl.0
    u32shr.0
    u32rotl.0
    u32rotr.0
end
",
    );

    let forms = parse_forms(source).expect("parser should succeed");
    let [Form::Begin(block)] = forms.as_slice() else {
        panic!("expected a single begin block, got {forms:?}");
    };

    let ops = block.iter().collect::<Vec<_>>();
    assert_eq!(
        ops.len(),
        4,
        "expected each explicit zero shift/rotate spelling to be preserved"
    );
    assert_zero_u8_instruction(ops[0], |instruction| {
        matches!(instruction, Instruction::U32ShlImm(_))
    });
    assert_zero_u8_instruction(ops[1], |instruction| {
        matches!(instruction, Instruction::U32ShrImm(_))
    });
    assert_zero_u8_instruction(ops[2], |instruction| {
        matches!(instruction, Instruction::U32RotlImm(_))
    });
    assert_zero_u8_instruction(ops[3], |instruction| {
        matches!(instruction, Instruction::U32RotrImm(_))
    });
}

fn assert_zero_u8_instruction(op: &Op, matches_instruction: impl FnOnce(&Instruction) -> bool) {
    let Op::Inst(instruction) = op else {
        panic!("expected instruction op, got {op:?}");
    };
    assert!(
        matches_instruction(instruction.inner()),
        "unexpected instruction: {instruction:?}"
    );
    let imm = match instruction.inner() {
        Instruction::U32ShlImm(imm)
        | Instruction::U32ShrImm(imm)
        | Instruction::U32RotlImm(imm)
        | Instruction::U32RotrImm(imm) => imm,
        other => panic!("expected u32 shift/rotate immediate, got {other:?}"),
    };
    assert_matches!(imm, Immediate::Value(value) if *value.inner() == 0);
}

#[test]
fn parse_extended_instruction_blocks() {
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
    emit.EVENT_ID
    emit.event(\"abc\")
    assert.err=\"oops\"
    u32assert.err=ERR_CODE
end
",
    );

    assert_parses(source);
}

#[test]
fn parser_accepts_checked_in_masm_corpus() {
    let files = checked_in_masm_corpus();
    assert!(
        !files.is_empty(),
        "expected the checked-in MASM corpus to contain at least one source file"
    );

    for path in files {
        let source = load_source_file(&path);
        parse_forms(source).map_err(render_diagnostic).unwrap_or_else(|diagnostic| {
            panic!("parser failed for {}:\n{diagnostic}", path.display())
        });
    }
}

#[test]
fn parser_reports_unqualified_imports() {
    let source = test_source_file("use foo\n");

    let err = parse_forms(source).expect_err("parser should reject unqualified imports");

    assert_matches!(render_diagnostic(err), diag if diag.contains("expected a fully-qualified module path"));
}

#[test]
fn parser_reports_invalid_struct_repr_from_direct_type_lowering() {
    let source = test_source_file("type Foo = struct @align { x: u32 }\n");

    let err = parse_forms(source).expect_err("parser should reject invalid struct repr");

    assert_matches!(render_diagnostic(err), diag if diag.contains("invalid struct representation"));
}

#[test]
fn parser_reports_attribute_key_value_conflicts() {
    let source = test_source_file(
        "\
@storage(offset = 1)
@storage(offset = 2)
proc foo
    nop
end
",
    );

    let err = parse_forms(source).expect_err("parser should reject conflicting attribute keys");

    assert_matches!(render_diagnostic(err), diag if diag.contains("conflicting key-value attributes"));
}

#[test]
fn parser_reports_invalid_advice_map_keys() {
    let source = test_source_file("adv_map TABLE(1) = [1]\n");

    let err = parse_forms(source).expect_err("parser should reject invalid advice-map keys");

    assert_matches!(render_diagnostic(err), diag if diag.contains("invalid Advice Map key"));
}

#[test]
fn parser_preserves_immediate_spellings_without_rewrites() {
    let source = test_source_file(
        "\
begin
    add.0
    mul.1
    u32div.0
    u32and.0
    u32wrapping_mul.0
end
",
    );
    let forms = parse_forms(source).expect("parser should succeed");
    let [Form::Begin(block)] = forms.as_slice() else {
        panic!("expected a single begin block, got {forms:?}");
    };

    let ops = block.iter().collect::<Vec<_>>();
    assert_eq!(ops.len(), 6);
    assert!(matches!(
        instruction_at(ops[0]),
        Instruction::AddImm(Immediate::Value(value)) if *value.inner() == crate::Felt::ZERO
    ));
    assert!(matches!(
        instruction_at(ops[1]),
        Instruction::MulImm(Immediate::Value(value)) if *value.inner() == crate::Felt::ONE
    ));
    assert!(matches!(
        instruction_at(ops[2]),
        Instruction::U32DivImm(Immediate::Value(value)) if *value.inner() == 0
    ));
    assert!(matches!(
        instruction_at(ops[3]),
        Instruction::Push(Immediate::Value(value))
            if *value.inner() == PushValue::Int(IntValue::U32(0))
    ));
    assert!(matches!(instruction_at(ops[4]), Instruction::U32And));
    assert!(matches!(
        instruction_at(ops[5]),
        Instruction::U32WrappingMulImm(Immediate::Value(value)) if *value.inner() == 0
    ));
}

fn instruction_at(op: &Op) -> &Instruction {
    let Op::Inst(instruction) = op else {
        panic!("expected instruction op, got {op:?}");
    };
    instruction.inner()
}

#[test]
fn parser_reports_direct_invalid_pad_values() {
    let source = test_source_file(
        "\
begin
    adv.push_mapvaln.5
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid pad value error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid padding value"));
}

#[test]
fn parser_reports_stack_immediate_errors() {
    let source = test_source_file(
        "\
begin
    dup.16
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid immediate error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid immediate"));
}

#[test]
fn parser_reports_bit_size_errors() {
    let source = test_source_file(
        "\
begin
    exp.u65
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid bit-size error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid literal: expected value to be a valid bit size"));
}

#[test]
fn parser_rejects_oversized_bit_size_without_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let source = test_source_file(
        "\
begin
    exp.u256
end
",
    );

    let parsed = catch_unwind(AssertUnwindSafe(|| parse_forms(source.clone())));
    assert!(parsed.is_ok(), "parser panicked for oversized bit-size");

    let cst = parsed.unwrap().expect_err("expected invalid bit-size error");
    let rendered = render_diagnostic(&cst);

    assert!(
        rendered.contains("invalid literal: expected value to be a valid bit size"),
        "{rendered}"
    );
    assert!(rendered.contains("exp.u256"), "{rendered}");
}

#[test]
fn parser_reports_suffixless_primitive_syntax_errors() {
    let source = test_source_file(
        "\
begin
    neg.1
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid syntax error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid syntax") || diag.contains("invalid instruction"));
}

#[test]
fn parser_reports_direct_invalid_mast_roots() {
    let source = test_source_file(
        "\
begin
    exec.0x1234
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid mast root error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid MAST root literal"));
}

#[test]
fn parser_reports_direct_push_overflow() {
    let source = test_source_file(
        "\
begin
    push.1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17
end
",
    );

    let err = parse_forms(source).expect_err("expected push overflow error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("too many operands for `push`"));
}

#[test]
fn parser_reports_direct_malformed_push_slice_ranges() {
    for source in [
        "\
const X = [1, 2, 3, 4]
begin
    push.X[0xff..0xff]
end
",
        "\
begin
    push.[1, 2, 3, 4][0xff..0xff]
end
",
    ] {
        let source = test_source_file(source);
        let err = parse_forms(source).expect_err("expected malformed push slice error");

        assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid syntax"));
    }
}

#[test]
fn parser_reports_direct_deprecated_memory_word_aliases() {
    let source = test_source_file(
        "\
begin
    mem_loadw.1
end
",
    );

    let err = parse_forms(source).expect_err("expected deprecated instruction error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("deprecated instruction"));
}

#[test]
fn parser_reports_direct_deprecated_local_word_aliases() {
    let source = test_source_file(
        "\
begin
    loc_storew.0
end
",
    );

    let err = parse_forms(source).expect_err("expected deprecated instruction error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("deprecated instruction"));
}

#[test]
fn parser_reports_direct_invalid_instruction_syntax() {
    let source = test_source_file(
        "\
begin
    u32widening_mulx
end
",
    );

    let err = parse_forms(source).expect_err("expected invalid instruction error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("invalid instruction"));
}

#[test]
fn parser_rejects_empty_while_blocks() {
    let source = test_source_file(
        "\
begin
    while.true
    end
end
",
    );

    let err = parse_forms(source).expect_err("expected empty while block error");

    assert_matches!(render_diagnostic(&err), diag if diag.contains("expected a non-empty `while` block"));
}

#[test]
fn parser_rejects_empty_if_then_without_else() {
    let source = test_source_file(
        "\
begin
    if.true
    end
end
",
    );

    let parsed = parse_forms(source);

    assert!(parsed.is_err(), "parser should reject empty if-then blocks");
}

#[test]
fn parser_reports_parse_errors() {
    let source = test_source_file("begin\n    if.true\n        add\n");

    let err = parse_forms(source).expect_err("parser should surface a parse error");

    assert_matches!(render_diagnostic(err), diag if diag.contains("expected `end`"));
}

#[test]
fn parser_rejects_debug_instructions() {
    for spelling in ["debug.stack.4", "debug.mem", "debug.local.0.2", "debug.adv_stack.4"] {
        let source = test_source_file(&format!("begin\n    {spelling}\nend\n"));
        let err = parse_forms(source).expect_err("debug.* should be rejected");
        assert_matches!(
            render_diagnostic(err),
            diag if diag.contains("invalid syntax") || diag.contains("invalid instruction")
        );
    }
}
