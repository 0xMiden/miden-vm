use alloc::{
    boxed::Box,
    collections::BTreeSet,
    string::{String, ToString},
    vec::Vec,
};
use core::{assert_matches, fmt::Write, str::FromStr};
use std::{eprintln, sync::Arc};

use miden_assembly_syntax::{
    MAX_REPEAT_COUNT,
    ast::{Ident, Path},
    diagnostics::WrapErr,
};
use miden_core::{
    Felt, Word,
    events::EventId,
    field::PrimeField64,
    mast::{MastNode, MastNodeExt},
    operations::{AssemblyOp, Operation},
    program::Program,
    serde::{Deserializable, Serializable},
};
use miden_mast_package::{
    MastForest, Package, PackageExport, PackageModule, PackageSubmodule, ProcedureExport,
    TargetType,
};
use miden_project::Linkage;

use crate::{
    Assembler, PathBuf, SourceSpan, Span,
    assembler::{MAX_CONTROL_FLOW_NESTING, MAX_PROC_LOCALS},
    ast::{
        Block, Instruction, Module, Op, Procedure, ProcedureName, QualifiedProcedureName,
        Visibility,
    },
    diagnostics::{IntoDiagnostic, Report},
    fmp::fmp_initialization_sequence,
    mast_forest_builder::MastForestBuilder,
    report,
    testing::{
        TestContext, assert_diagnostic, assert_diagnostic_lines, parse_module, regex, source_file,
    },
};

type TestResult = Result<(), Report>;

fn assert_all_nodes_reachable_from_roots(forest: &MastForest) {
    let mut reachable = BTreeSet::new();
    let mut worklist = forest.procedure_roots().to_vec();

    while let Some(node_id) = worklist.pop() {
        if reachable.insert(node_id) {
            forest[node_id].append_children_to(&mut worklist);
        }
    }

    assert_eq!(
        reachable.len(),
        forest.num_nodes() as usize,
        "finalized MAST forest contains nodes unreachable from any procedure root",
    );
}

fn assert_package_has_source_asm_ops(package: &Package, message: &str) {
    let debug_info = package
        .debug_info()
        .expect("package debug info should decode")
        .expect("package should contain debug info");
    let has_source_asm_ops = debug_info
        .source_map()
        .is_some_and(|source_map| !source_map.asm_ops().is_empty());
    assert!(has_source_asm_ops, "{message}");
}

mod package;

// Note: where possible, prefer insta to pretty_assertions for snapshot testing.
//
// - For tests against expected values that can't be expressed as a string literal, we still use
//   pretty-assertions' assert_eq for backward compatibility.
// - For new tests using string literals, or when you need auto-updating snapshots, use [insta](https://insta.rs/):
//
// Example:
// insta::assert_snapshot!(actual_output)
//
// To update snapshots on a per-test basis automatically:
// cargo insta review (after `cargo install cargo-insta`)

macro_rules! assert_assembler_diagnostic {
    ($context:ident, $source:expr, $($expected:literal),+) => {{
        let error = $context
            .assemble($source)
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($context:ident, $source:expr, $($expected:expr),+) => {{
        let error = $context
            .assemble($source)
            .expect_err("expected diagnostic to be raised, but compilation succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

// SIMPLE PROGRAMS
// ================================================================================================

#[test]
fn simple_instructions() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.0 assertz end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    let source = source_file!(&context, "begin push.10 push.50 push.2 u32wrapping_madd end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    let source = source_file!(&context, "begin push.10 push.50 push.2 u32wrapping_add3 end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly?
#[test]
#[ignore]
fn empty_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn empty_if() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin if.true end end");
    let err = context.assemble(source).expect_err("expected empty if block to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected a non-empty `if` block");
    assert_diagnostic!(&err, "begin if.true end end");
}

#[test]
fn empty_if_true_then_branch() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin if.true nop end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly
#[test]
#[ignore]
fn empty_while() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin while.true end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// TODO(pauls): Do we want to allow this in Miden Assembly
#[test]
#[ignore]
fn empty_repeat() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin repeat.5 end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// This test ensures that all iterations of a repeat control block are merged into a single basic
/// block.
#[test]
fn repeat_basic_blocks_merged() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin mul repeat.5 add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // Also ensure that dead code elimination works properly
    assert_eq!(program.mast_forest().num_nodes(), 1);
    Ok(())
}

/// A tail-controlled `do`..`while` loop lowers to a *bare* LOOP node, with no SPLIT wrapper
/// (unlike the head-controlled `while.true`, which adds a SPLIT for the entry check). The loop
/// body merges the `body` and `condition` sections into a single basic block.
#[test]
fn do_while_lowers_to_bare_loop() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin do push.1 while eq.0 end end");
    let program = context.assemble(source)?;
    let forest = program.mast_forest();

    let num_loops = forest.nodes().iter().filter(|n| matches!(n, MastNode::Loop(_))).count();
    let num_splits = forest.nodes().iter().filter(|n| matches!(n, MastNode::Split(_))).count();
    assert_eq!(num_loops, 1, "expected exactly one LOOP node");
    assert_eq!(num_splits, 0, "expected no SPLIT node for a do-while loop");

    let loop_node = forest
        .nodes()
        .iter()
        .find_map(|n| match n {
            MastNode::Loop(loop_node) => Some(loop_node),
            _ => None,
        })
        .unwrap();
    assert_matches!(&forest[loop_node.body()], MastNode::Block(_));
    Ok(())
}

/// Ensures `repeat` supports dynamic iteration counts provided via constants.
#[test]
fn repeat_dynamic_iteration_count() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "const A = 5 begin repeat.A add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn single_basic_block() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn basic_block_and_simple_if_true() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(&context, "begin push.2 push.3 if.true add else mul end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // if without else
    let source = source_file!(&context, "begin push.2 push.3 if.true add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn basic_block_and_simple_if_false() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(&context, "begin push.2 push.3 if.false add else mul end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // if without else
    let source = source_file!(&context, "begin push.2 push.3 if.false add end end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

// LIBRARIES
// ================================================================================================

#[test]
fn library_exports() -> Result<(), Report> {
    let context = TestContext::new();

    // build the first library
    let baz = r#"
        namespace lib1::baz

        pub proc baz1
            push.7 push.8 sub
        end
    "#;
    let baz = parse_module!(&context, baz);

    let lib1 = Assembler::new(context.source_manager()).assemble_library(
        "lib1",
        baz,
        None::<Box<Module>>,
    )?;

    // build the second library
    let foo = r#"
        namespace lib2::foo
        proc foo1
            push.1 add
        end

        pub proc foo2
            push.2 add
            exec.foo1
        end

        pub proc foo3
            push.3 mul
            exec.foo1
            exec.foo2
        end
    "#;
    let foo = parse_module!(&context, foo);

    // declare root module
    let root = r#"
        namespace lib2

        pub mod foo

        pub use {baz1 as bar1} from lib1::baz

        pub use {foo2 as bar2} from self::foo

        pub proc bar3
            exec.foo::foo2
        end

        proc bar4
            push.1 push.2 mul
        end

        pub proc bar5
            push.3 sub
            exec.foo::foo2
            exec.bar1
            exec.bar2
            exec.bar4
        end
    "#;
    let root = parse_module!(&context, root);

    let lib2 = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib1), Linkage::Dynamic)?
        .assemble_library("lib2", root, [foo])?;

    let foo2 = Path::new("::lib2::foo::foo2");
    let foo3 = Path::new("::lib2::foo::foo3");
    let bar1 = Path::new("::lib2::bar1");
    let bar2 = Path::new("::lib2::bar2");
    let bar3 = Path::new("::lib2::bar3");
    let bar5 = Path::new("::lib2::bar5");

    // make sure the library exports all exported procedures
    let expected_exports: BTreeSet<Arc<Path>> =
        [foo2.into(), foo3.into(), bar1.into(), bar2.into(), bar3.into(), bar5.into()].into();
    let actual_exports: BTreeSet<_> = lib2.manifest.exports().map(PackageExport::path).collect();
    assert_eq!(expected_exports, actual_exports);

    // make sure foo2, bar2, and bar3 map to the same MastNode
    assert_eq!(lib2.get_export_node_id(foo2), lib2.get_export_node_id(bar2));
    assert_eq!(lib2.get_export_node_id(foo2), lib2.get_export_node_id(bar3));
    assert_all_nodes_reachable_from_roots(lib2.mast_forest());

    // make sure there are 6 roots in the MAST (foo1, foo2, foo3, bar1, bar4, and bar5)
    assert_eq!(lib2.mast_forest().num_procedures(), 6);

    // bar1 should be the only re-export (i.e. the only procedure re-exported from a dependency)
    assert!(!lib2.is_reexport(foo2));
    assert!(!lib2.is_reexport(foo3));
    assert!(lib2.is_reexport(bar1));
    assert!(!lib2.is_reexport(bar2));
    assert!(!lib2.is_reexport(bar3));
    assert!(!lib2.is_reexport(bar5));

    Ok(())
}

#[test]
#[ignore = "disabled until #3040 is resolved"]
fn library_procedure_collision() -> Result<(), Report> {
    let context = TestContext::new();

    // build the first library
    let foo = r#"
        namespace lib1::foo
        pub proc foo1
            push.1
            if.true
                push.1 push.2 add
            else
                push.1 push.2 mul
            end
        end
    "#;
    let foo = parse_module!(&context, foo);
    let lib1 = Assembler::new(context.source_manager()).assemble_library(
        "lib1",
        foo,
        None::<Box<Module>>,
    )?;

    // build the second library which defines the same procedure as the first one
    let bar = r#"
        namespace lib2::bar

        pub use {foo1 as bar1} from lib1::foo

        pub proc bar2
            push.1
            if.true
                push.1 push.2 add
            else
                push.1 push.2 mul
            end
        end
    "#;
    let bar = parse_module!(&context, bar);
    let lib2 = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib1), Linkage::Dynamic)?
        .assemble_library("lib2", bar, None::<Box<Module>>)?;

    // make sure lib2 has the expected exports (i.e., bar1 and bar2)
    assert_eq!(lib2.manifest.num_exports(), 2);

    // The re-exported procedure and the locally defined procedure have the same MAST shape, so
    // they share the same node.
    let lib2_bar_bar1 = QualifiedProcedureName::from_str("lib2::bar::bar1").unwrap();
    let lib2_bar_bar2 = QualifiedProcedureName::from_str("lib2::bar::bar2").unwrap();
    let export_id_bar1 = lib2.get_export_node_id(&lib2_bar_bar1);
    assert!(lib2.mast_forest()[export_id_bar1].is_external());
    let export_id_bar2 = lib2.get_export_node_id(&lib2_bar_bar2);
    assert!(!lib2.mast_forest()[export_id_bar2].is_external());
    assert_ne!(export_id_bar1, export_id_bar2);

    // Keeping those procedures distinct adds one more node to the library forest.
    assert_eq!(lib2.mast_forest().num_nodes(), 6);

    Ok(())
}

#[test]
fn get_module_by_path() {
    let context = TestContext::new();
    // declare foo module
    let foo_source = r#"
        namespace test::foo
        pub proc foo
            add
        end
    "#;
    let foo = parse_module!(&context, foo_source);

    // create the bundle with locations
    let bundle = Assembler::new(context.source_manager())
        .assemble_library("test", foo, None::<Box<Module>>)
        .unwrap();

    let foo_module_descriptor = bundle.module_descriptors().next().unwrap();
    assert_eq!(foo_module_descriptor.path(), &PathBuf::new("::test::foo").unwrap());

    let (_, foo_proc) = foo_module_descriptor.procedures().next().unwrap();
    assert_eq!(foo_proc.name, ProcedureName::new("foo").unwrap());
}

#[test]
fn get_proc_digest_by_name() -> Result<(), Report> {
    let context = TestContext::new();

    let testing_module_source = "
        namespace test::names
        pub proc foo
            push.1.2 add drop
        end

        pub proc bar
            push.5.6 sub drop
        end
    ";
    let testing_module = parse_module!(&context, testing_module_source);

    // create the bundle with locations
    let package = Assembler::new(context.source_manager())
        .assemble_library("test", testing_module, None::<Box<Module>>)
        .context("failed to assemble library from testing module")?;

    // get the vector of library procedure digests
    let library_procedure_digests = package
        .manifest
        .exports()
        .filter_map(|export| match export {
            PackageExport::Procedure(export) => Some(export.digest),
            _ => None,
        })
        .collect::<Vec<Word>>();

    // valid procedure names
    assert!(
        library_procedure_digests.contains(
            &package
                .get_procedure_root_by_path("test::names::foo")
                .expect("procedure with name 'foo' must exist in the test library")
        )
    );
    assert!(
        library_procedure_digests.contains(
            &package
                .get_procedure_root_by_path("test::names::bar")
                .expect("procedure with name 'bar' must exist in the test library")
        )
    );

    // invalid procedure name
    assert_eq!(None, package.get_procedure_root_by_path("test::names::baz"));

    // invalid namespace
    assert_eq!(None, package.get_procedure_root_by_path("invalid::namespace::foo"));

    Ok(())
}

// PROGRAM WITH $main CALL
// ================================================================================================

#[test]
fn simple_main_call() -> TestResult {
    let mut context = TestContext::default();

    // compile account module
    let account_code = context.parse_module(source_file!(
        &context,
        "\
        namespace context::account
        pub proc account_method_1
            push.2.1 add
        end

        pub proc account_method_2
            push.3.1 sub
        end
        "
    ))?;

    context.add_module(account_code)?;

    // compile note 1 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_1
        end
        "
    ))?;

    // compile note 2 program
    context.assemble(source_file!(
        &context,
        "
        use context::account
        begin
          call.account::account_method_2
        end
        "
    ))?;
    Ok(())
}

#[test]
fn call_without_path() -> TestResult {
    let context = TestContext::default();

    let account_code1_src = source_file!(
        &context,
        "\
namespace account_code1

pub proc account_method_1
    push.2.1 add
end

pub proc account_method_2
    push.3.1 sub
end
"
    );
    let account_code2_src = source_file!(
        &context,
        "\
namespace account_code2

pub proc account_method_1
    push.2.2 add
end

pub proc account_method_2
    push.4.1 sub
end
"
    );

    // compile program in which functions from different modules but with equal names are called
    let main_src = source_file!(
        &context,
        "
        begin
            # call the account_method_1 from the first module (account_code1)
            call.0x81e0b1afdbd431e4c9d4b86599b82c3852ecf507ae318b71c099cdeba0169068

            # call the account_method_2 from the first module (account_code1)
            call.0x1bc375fc794af6637af3f428286bf6ac1a24617640ed29f8bc533f48316c6d75

            # call the account_method_1 from the second module (account_code2)
            call.0xcfadd74886ea075d15826a4f59fb4db3a10cde6e6e953603cba96b4dcbb94321

            # call the account_method_2 from the second module (account_code2)
            call.0x1976bf72d457bd567036d3648b7e3f3c22eca4096936931e59796ec05c0ecb10
        end
        "
    );

    let account_code1 = context.parse_module(account_code1_src)?;
    let account_code2 = context.parse_module(account_code2_src)?;
    let main = context.parse_program(main_src)?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.compile_and_statically_link_all([account_code1, account_code2])?;
    assembler.assemble_program("main", main)?;

    Ok(())
}

// PROGRAM WITH PROCREF
// ================================================================================================

#[test]
fn procref_call() -> TestResult {
    let mut context = TestContext::default();
    // compile first module
    context.add_module(source_file!(
        &context,
        "
        namespace module::path::one

        pub proc aaa
            push.7.8
        end

        pub proc foo
            push.1.2
        end"
    ))?;

    // compile second module
    context.add_module(source_file!(
        &context,
        "
        namespace module::path::two

        use module::path::one
        pub use {foo} from module::path::one

        pub proc bar
            procref.one::aaa
        end"
    ))?;

    // compile program with procref calls
    context.assemble(source_file!(
        &context,
        "
        use module::path::two

        @locals(4)
        proc baz
            push.3.4
        end

        begin
            procref.two::bar
            procref.two::foo
            procref.baz
        end"
    ))?;
    Ok(())
}

#[test]
fn get_proc_name_of_unknown_module() -> TestResult {
    let context = TestContext::default();
    // Module `two` is unknown, our error should identify that it is undefined
    let module_source1 = source_file!(
        &context,
        "
    namespace module::path::one

    use module::path::two

    pub proc foo
        procref.two::bar
    end"
    );
    let module1 = context.parse_module(module_source1)?;

    let report = Assembler::new(context.source_manager())
        .assemble_library("test", module1, None::<Box<Module>>)
        .expect_err("expected unknown module error");

    assert_diagnostic!(&report, "undefined item 'module::path::two'");
    assert_diagnostic!(&report, "use module::path::two");
    assert_diagnostic!(&report, "you might be missing an import");

    Ok(())
}

// CONSTANTS
// ================================================================================================

#[test]
fn simple_constant() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 7
    begin
        push.TEST_CONSTANT
    end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn enum_explicit_discriminants() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
enum Status : u16 {
    OK = 200,
    NOT_FOUND = 404,
    SERVER_ERROR = 500,
}

begin
    push.OK
    push.NOT_FOUND
    push.SERVER_ERROR
end
"#
    );
    let _program = context.assemble(source)?;
    Ok(())
}

#[test]
fn enum_discriminants_can_reference_constants() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
const BASE = 10

enum Status : u16 {
    OK = BASE,
    NOT_FOUND = OK + 1,
}

begin
    push.OK
    push.NOT_FOUND
end
"#
    );
    let _program = context.assemble(source)?;
    Ok(())
}

#[test]
fn enum_felt_repr_variants() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
enum Status : felt {
    OK = 1,
}

begin
    push.OK
end
"#
    );
    let _program = context.assemble(source)?;
    Ok(())
}

#[test]
fn enum_felt_discriminant_negative_is_rejected() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
enum Status : felt {
    BAD = 0 - 1,
}

begin
    push.BAD
end
"#
    );
    let err = context
        .assemble(source)
        .expect_err("expected negative discriminant to be rejected");
    assert_diagnostic!(err, "invalid constant expression: value is larger than expected range");
}

#[test]
fn enum_felt_discriminant_too_large_is_rejected() {
    let context = TestContext::default();
    let modulus = Felt::ORDER_U64;
    let source = source_file!(
        &context,
        format!(
            r#"
enum Status : felt {{
    BAD = {modulus},
}}

begin
    push.BAD
end
"#
        )
    );
    let err = context
        .assemble(source)
        .expect_err("expected out-of-range felt discriminant to be rejected");
    assert_diagnostic!(err, "invalid literal: value overflowed the field modulus");
}

#[test]
fn constant_expression_overflow_is_rejected() {
    let context = TestContext::default();
    let modulus_minus_one = Felt::ORDER_U64 - 1;
    let source = source_file!(
        &context,
        format!(
            "const TOO_BIG = {modulus_minus_one} + {modulus_minus_one}\nbegin\n    push.TOO_BIG\nend\n"
        )
    );
    let err = context
        .assemble(source)
        .expect_err("expected constant expression overflow to be rejected");
    assert_diagnostic!(err, "invalid constant expression: value is larger than expected range");
}

#[test]
fn multiple_constants_push() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const CONSTANT_1 = 21 \
    const CONSTANT_2 = 44 \
    begin \
    push.CONSTANT_1.64.CONSTANT_2.72 \
    end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn constant_numeric_expression() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 11-2+4*(12-(10+1))+9+8//4*2 \
    begin \
    push.TEST_CONSTANT \
    end \
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn constant_alphanumeric_expression() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT_1 = (18-1+10)*6-((13+7)*2) \
    const TEST_CONSTANT_2 = 11-2+4*(12-(10+1))+9
    const TEST_CONSTANT_3 = (TEST_CONSTANT_1-(TEST_CONSTANT_2+10))//5+3
    begin \
    push.TEST_CONSTANT_3 \
    end \
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn constant_hexadecimal_value() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 0xFF \
    begin \
    push.TEST_CONSTANT \
    end \
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn constant_field_division() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = (17//4)/4*(1//2)+2 \
    begin \
    push.TEST_CONSTANT \
    end \
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn constant_err_const_not_initialized() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 5+A \
    begin \
    push.TEST_CONSTANT \
    end"
    );
    let err = context.assemble(source).expect_err("expected undefined constant diagnostic");
    assert_diagnostic!(&err, "undefined constant 'A'");
    assert_diagnostic!(&err, "the constant referenced here is not defined in the current scope");
    assert_diagnostic!(&err, "are you missing an import?");
}

#[test]
fn constant_err_div_by_zero() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 5/0 \
    begin \
    push.TEST_CONSTANT \
    end"
    );
    let err = context.assemble(source).expect_err("expected division by zero diagnostic");
    assert_diagnostic!(&err, "invalid constant expression: division by zero");
    assert_diagnostic!(&err, "const TEST_CONSTANT = 5/0");

    let source = source_file!(
        &context,
        "\
    const TEST_CONSTANT = 5//0 \
    begin \
    push.TEST_CONSTANT \
    end"
    );
    let err = context.assemble(source).expect_err("expected division by zero diagnostic");
    assert_diagnostic!(&err, "invalid constant expression: division by zero");
    assert_diagnostic!(&err, "const TEST_CONSTANT = 5//0");
}

#[test]
fn constant_err_div_by_zero_indirect() {
    let context = TestContext::default();

    let source = source_file!(
        &context,
        "\
    const NUMERATOR = 10
    const DENOMINATOR = 0
    const BAD_DIV = NUMERATOR / DENOMINATOR

    begin
        push.BAD_DIV
    end"
    );

    let err = context.assemble(source).expect_err("expected division by zero diagnostic");
    assert_diagnostic!(&err, "invalid constant expression: division by zero");
    assert_diagnostic!(&err, "const BAD_DIV = NUMERATOR / DENOMINATOR");
}

#[test]
fn constant_err_div_by_zero_link_time() -> TestResult {
    let mut context = TestContext::default();

    let module_a = source_file!(
        &context,
        "namespace module_a

        pub const NUMERATOR = 10
        pub const DENOMINATOR = 0"
    );

    context.add_module(module_a)?;

    let source = source_file!(
        &context,
        "\
    use {NUMERATOR, DENOMINATOR} from module_a

    const BAD_DIV = NUMERATOR / DENOMINATOR

    begin
        push.BAD_DIV
    end"
    );

    let err = context.assemble(source).expect_err("expected division by zero diagnostic");
    assert_diagnostic!(&err, "invalid constant expression: division by zero");
    assert_diagnostic!(&err, "const BAD_DIV = NUMERATOR / DENOMINATOR");

    Ok(())
}

#[test]
fn constants_must_be_uppercase() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const constant_1 = 12 \
    begin \
    push.constant_1 \
    end"
    );

    let err = context.assemble(source).expect_err("expected lowercase constant diagnostic");
    assert_diagnostic!(
        &err,
        "invalid identifier: only uppercase characters or underscores are allowed"
    );
    assert_diagnostic!(&err, "const constant_1 = 12");
}

#[test]
fn duplicate_constant_name() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const CONSTANT = 12 \
    const CONSTANT = 14 \
    begin \
    push.CONSTANT \
    end"
    );

    let err = context.assemble(source).expect_err("expected duplicate constant diagnostic");
    assert_diagnostic!(&err, "symbol conflict: found duplicate definitions of the same name");
    assert_diagnostic!(&err, "conflict occurs here");
    assert_diagnostic!(&err, "previously defined here");
}

#[test]
fn constant_must_be_valid_felt() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const CONSTANT = 1122INVALID \
    begin \
    push.CONSTANT \
    end"
    );

    let err = context.assemble(source).expect_err("expected invalid felt diagnostic");
    assert_diagnostic!(&err, "invalid syntax: unexpected trailing tokens in expression");
    assert_diagnostic!(&err, "unexpected trailing tokens in expression");
}

#[test]
fn constant_must_be_within_valid_felt_range() {
    let context = TestContext::default();

    // test the u64::MAX value
    let source = source_file!(
        &context,
        "\
    const CONSTANT = 18446744073709551615 \
    begin \
    push.CONSTANT \
    end"
    );

    let err = context.assemble(source).expect_err("expected felt overflow diagnostic");
    assert_diagnostic!(&err, "invalid literal: value overflowed the field modulus");
    assert_diagnostic!(&err, "18446744073709551615");

    // test the field modulus value in u64 form
    let source = source_file!(
        &context,
        "\
    const CONSTANT = 18446744069414584321 \
    begin \
    push.CONSTANT \
    end"
    );

    let err = context.assemble(source).expect_err("expected felt overflow diagnostic");
    assert_diagnostic!(&err, "invalid literal: value overflowed the field modulus");
    assert_diagnostic!(&err, "18446744069414584321");

    // test the field modulus value in hex form
    let source = source_file!(
        &context,
        "\
    const CONSTANT = 0xFFFFFFFF00000001 \
    begin \
    push.CONSTANT \
    end"
    );

    let err = context.assemble(source).expect_err("expected felt overflow diagnostic");
    assert_diagnostic!(&err, "invalid literal: value overflowed the field modulus");
    assert_diagnostic!(&err, "0xFFFFFFFF00000001");
}

#[test]
fn constants_defined_in_global_scope() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "
    begin \
    const CONSTANT = 12
    push.CONSTANT \
    end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected block-local constants to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `begin` block before top-level item");
    assert_diagnostic!(&err, "unexpected top-level token");
}

#[test]
fn constant_not_found() {
    let context = TestContext::new();
    let source = source_file!(
        &context,
        "
    begin \
    push.CONSTANT \
    end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "undefined constant 'CONSTANT'",
        regex!(r#",-\[test[\d]+:2:16\]"#),
        "1 |",
        "2 |     begin push.CONSTANT end",
        "  :                ^^^^|^^^",
        "  :                    `-- the constant referenced here is not defined in the current scope",
        "  `----",
        "help: are you missing an import?"
    );
}

#[test]
fn mem_operations_with_constants() -> TestResult {
    let context = TestContext::default();

    // Define constant values
    const PROC_LOC_STORE_PTR: u64 = 0;
    const PROC_LOC_LOAD_PTR: u64 = 1;
    const PROC_LOC_STOREW_PTR: u64 = 4;
    const PROC_LOC_LOADW_PTR: u64 = 8;
    const GLOBAL_STORE_PTR: u64 = 12;
    const GLOBAL_LOAD_PTR: u64 = 13;
    const GLOBAL_STOREW_PTR: u64 = 16;
    const GLOBAL_LOADW_PTR: u64 = 20;

    let source = source_file!(
        &context,
        format!(
            "\
    const PROC_LOC_STORE_PTR = {PROC_LOC_STORE_PTR}
    const PROC_LOC_LOAD_PTR = {PROC_LOC_LOAD_PTR}
    const PROC_LOC_STOREW_PTR = {PROC_LOC_STOREW_PTR}
    const PROC_LOC_LOADW_PTR = {PROC_LOC_LOADW_PTR}
    const GLOBAL_STORE_PTR = {GLOBAL_STORE_PTR}
    const GLOBAL_LOAD_PTR = {GLOBAL_LOAD_PTR}
    const GLOBAL_STOREW_PTR = {GLOBAL_STOREW_PTR}
    const GLOBAL_LOADW_PTR = {GLOBAL_LOADW_PTR}

    @locals(12)
    proc test_const_loc
        # constant should resolve using locaddr operation
        locaddr.PROC_LOC_STORE_PTR

        # constant should resolve using loc_store operation
        loc_store.PROC_LOC_STORE_PTR

        # constant should resolve using loc_load operation
        loc_load.PROC_LOC_LOAD_PTR

        # constant should resolve using loc_storew_be operation
        loc_storew_be.PROC_LOC_STOREW_PTR

        # constant should resolve using loc_loadw_be opeartion
        loc_loadw_be.PROC_LOC_LOADW_PTR
    end

    begin
        # inline procedure
        exec.test_const_loc

        # constant should resolve using mem_store operation
        mem_store.GLOBAL_STORE_PTR

        # constant should resolve using mem_load operation
        mem_load.GLOBAL_LOAD_PTR

        # constant should resolve using mem_storew_be operation
        mem_storew_be.GLOBAL_STOREW_PTR

        # constant should resolve using mem_loadw_be operation
        mem_loadw_be.GLOBAL_LOADW_PTR
    end
    "
        )
    );
    let program = context.assemble(source)?;

    // Define expected
    let expected = source_file!(
        &context,
        format!(
            "\
    @locals(12)
    proc test_const_loc
        # constant should resolve using locaddr operation
        locaddr.{PROC_LOC_STORE_PTR}

        # constant should resolve using loc_store operation
        loc_store.{PROC_LOC_STORE_PTR}

        # constant should resolve using loc_load operation
        loc_load.{PROC_LOC_LOAD_PTR}

        # constant should resolve using loc_storew_be operation
        loc_storew_be.{PROC_LOC_STOREW_PTR}

        # constant should resolve using loc_loadw_be opeartion
        loc_loadw_be.{PROC_LOC_LOADW_PTR}
    end

    begin
        # inline procedure
        exec.test_const_loc

        # constant should resolve using mem_store operation
        mem_store.{GLOBAL_STORE_PTR}

        # constant should resolve using mem_load operation
        mem_load.{GLOBAL_LOAD_PTR}

        # constant should resolve using mem_storew_be operation
        mem_storew_be.{GLOBAL_STOREW_PTR}

        # constant should resolve using mem_loadw_be operation
        mem_loadw_be.{GLOBAL_LOADW_PTR}
    end
    "
        )
    );
    let expected_program = context.assemble(expected)?;
    assert_eq!(expected_program.to_string(), program.to_string());
    Ok(())
}

#[test]
fn const_conversion_failed_to_u16() {
    // Define constant value greater than u16::MAX
    let constant_value: u64 = u16::MAX as u64 + 1;

    let context = TestContext::default();
    let source = source_file!(
        &context,
        format!(
            "\
    const CONSTANT = {constant_value}

    @locals(1)
    proc test_constant_overflow
        loc_load.CONSTANT
    end

    begin
        exec.test_constant_overflow
    end
    "
        )
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "invalid immediate: value is larger than expected range",
        regex!(r#",-\[test[\d]+:5:18\]"#),
        "4 |     proc test_constant_overflow",
        "5 |         loc_load.CONSTANT",
        "  :                  ^^^^^^^^",
        "6 |     end",
        "  `----"
    );
}

#[test]
fn const_conversion_failed_to_u32() {
    let context = TestContext::default();
    // Define constant value greater than u16::MAX
    let constant_value: u64 = u32::MAX as u64 + 1;

    let source = source_file!(
        &context,
        format!(
            "\
    const CONSTANT = {constant_value}

    begin
        mem_load.CONSTANT
    end
    "
        )
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "invalid immediate: value is larger than expected range",
        regex!(r#",-\[test[\d]+:4:18\]"#),
        "3 |     begin",
        "4 |         mem_load.CONSTANT",
        "  :                  ^^^^^^^^",
        "5 |     end",
        "  `----"
    );
}

#[test]
fn deprecated_mem_loadw_instruction() {
    let context = TestContext::default();

    let source = source_file!(
        &context,
        "\
    begin
        mem_loadw
    end
    "
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "deprecated instruction: `mem_loadw` has been removed",
        regex!(r#",-\[test[\d]+:2:9\]"#),
        "1 | begin",
        "2 |         mem_loadw",
        regex!(r#"^ *: *\^+"#),
        regex!(r#"this instruction is no longer supported"#),
        "3 |     end",
        "  `----",
        regex!(r#"help:.*use.*mem_loadw_be.*instead"#)
    );
}

#[test]
fn deprecated_loc_loadw_instruction() {
    let context = TestContext::default();

    let source = source_file!(
        &context,
        "\
    @locals(8)
    proc foo
        loc_loadw.0
    end
    begin
        exec.foo
    end
    "
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "deprecated instruction: `loc_loadw` has been removed",
        regex!(r#",-\[test[\d]+:3:9\]"#),
        "2 |     proc foo",
        "3 |         loc_loadw.0",
        regex!(r#"^ *: *\^+"#),
        regex!(r#"this instruction is no longer supported"#),
        "4 |     end",
        "  `----",
        regex!(r#"help:.*use.*loc_loadw_be.*instead"#)
    );
}

#[test]
fn deprecated_loc_storew_instruction() {
    let context = TestContext::default();

    let source = source_file!(
        &context,
        "\
    @locals(8)
    proc foo
        loc_storew.0
    end
    begin
        exec.foo
    end
    "
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "deprecated instruction: `loc_storew` has been removed",
        regex!(r#",-\[test[\d]+:3:9\]"#),
        "2 |     proc foo",
        "3 |         loc_storew.0",
        regex!(r#"^ *: *\^+"#),
        regex!(r#"this instruction is no longer supported"#),
        "4 |     end",
        "  `----",
        regex!(r#"help:.*use.*loc_storew_be.*instead"#)
    );
}

#[test]
fn const_word_from_string() -> TestResult {
    let context = TestContext::default();
    let sample_source_string = "lorem ipsum";

    let source = source_file!(
        &context,
        format!(
            r#"
    const SAMPLE_WORD = word("{sample_source_string}")

    begin
        push.SAMPLE_WORD
    end
    "#
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);

    Ok(())
}

/// Check that the event ID conversion during compilation is consistent with
/// string_to_event_id.
#[test]
fn const_event_from_string() -> TestResult {
    let context = TestContext::default();
    let sample_event_name = "miden::test::constant";
    let expected_felt = EventId::from_name(sample_event_name);

    let source1 = source_file!(
        &context,
        format!(
            r#"
    begin
        emit.event("{sample_event_name}")
    end
    "#
        )
    );
    let source2 = source_file!(
        &context,
        format!(
            r#"
    begin
        push.{expected_felt}
        emit
        drop
    end
    "#
        )
    );

    let program1 = context.assemble(source1)?;
    let program2 = context.assemble(source2)?;
    assert_eq!(program1.hash(), program2.hash());

    Ok(())
}

#[test]
fn test_push_word_slice() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const SAMPLE_WORD = [2, 3, 4, 5]
    const SAMPLE_HEX_WORD = 0x0600000000000000070000000000000008000000000000000900000000000000

    begin
        push.SAMPLE_WORD[1..3]
        push.SAMPLE_WORD[0]
        push.[10, 11, 12, 13][1..3]

        push.SAMPLE_HEX_WORD[2..4]
        push.0x0600000000000000070000000000000008000000000000000900000000000000[0..2]
    end
    "
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_push_word_slice_invalid() {
    let context = TestContext::default();
    let source_invalid_range = source_file!(
        &context,
        "\
    const SAMPLE_WORD = [2, 3, 4, 5]

    begin
        push.SAMPLE_WORD[6..3]
    end
    "
    );
    assert!(context.assemble(source_invalid_range).is_err());

    let source_empty_range = source_file!(
        &context,
        "\
    const SAMPLE_WORD = [2, 3, 4, 5]

    begin
        push.SAMPLE_WORD[2..2]
    end
    "
    );
    assert!(context.assemble(source_empty_range).is_err());

    let source_invalid_constant_type = source_file!(
        &context,
        "\
    const SAMPLE_VALUE = 6
    begin
        push.SAMPLE_VALUE[1..3]
    end
    "
    );
    assert!(context.assemble(source_invalid_constant_type).is_err());

    let source_invalid_constant_type = source_file!(
        &context,
        "\
    begin
        push.5[0..2]
    end
    "
    );
    assert!(context.assemble(source_invalid_constant_type).is_err());
}

#[test]
fn link_time_const_evaluation_succeeds() -> TestResult {
    let context = TestContext::default();
    let a = r#"
            namespace lib::a

            pub const FOO = 1
            pub proc f
                push.FOO
            end
        "#;
    let a = parse_module!(&context, a);

    let lib =
        Assembler::new(context.source_manager()).assemble_library("lib", a, None::<Box<Module>>)?;

    let program_source = source_file!(
        &context,
        "\
        use lib::a
        use {FOO} from lib::a
        begin
            push.FOO
            exec.a::f
            add
            add
        end"
    );

    let program = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib), Linkage::Dynamic)?
        .assemble_program("program", program_source)?
        .unwrap_program();
    insta::assert_snapshot!(program);

    Ok(())
}

#[test]
fn link_time_const_evaluation_undefined_symbol() -> TestResult {
    let context = TestContext::default();
    let a = r#"
            namespace lib::a

            pub proc f
                push.1
            end
        "#;
    let a = parse_module!(&context, a);

    let lib =
        Assembler::new(context.source_manager()).assemble_library("lib", a, None::<Box<Module>>)?;

    let source = source_file!(
        &context,
        "\
        use {FOO} from lib::a
        begin
            push.FOO
            exec.lib::a::f
            add
        end"
    );

    let error = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib), Linkage::Dynamic)?
        .assemble_program("program", source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");
    assert_diagnostic_lines!(
        error,
        "undefined item 'lib::a::FOO'",
        regex!(r#",-\[test[\d]+:1:6\]"#),
        "1 | use {FOO} from lib::a",
        "  :      ^^^",
        "2 |         begin",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );

    Ok(())
}

#[test]
fn link_time_const_evaluation_invalid_constant() -> TestResult {
    let context = TestContext::default();
    let a = r#"
            namespace lib::a

            pub proc f
                push.1
            end
        "#;
    let a = parse_module!(&context, a);

    let lib =
        Assembler::new(context.source_manager()).assemble_library("lib", a, None::<Box<Module>>)?;

    let source = source_file!(
        &context,
        "\
    use {f} from lib::a
    begin
        push.f
    end"
    );

    let error = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib), Linkage::Dynamic)?
        .assemble_program("program", source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");

    assert_diagnostic_lines!(
        error,
        "invalid identifier: only uppercase characters or underscores are allowed, and must start with an alphabetic character",
        "invalid identifier: only uppercase characters or underscores are allowed, and must start with an alphabetic character",
        regex!(r#",-\[test[\d]+:3:14\]"#),
        "2 |     begin",
        "3 |         push.f",
        "  :              ^",
        "4 |     end",
        "  `----",
        "help: bare identifiers must be lowercase alphanumeric with '_', quoted identifiers can include any graphical character"
    );

    Ok(())
}

// ASSERTIONS
// ================================================================================================

#[test]
fn assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert
        assert.err=ERR1
        assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assertz_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assertz
        assertz.err=ERR1
        assertz.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assert_eq_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eq
        assert_eq.err=ERR1
        assert_eq.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn assert_eqw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        assert_eqw
        assert_eqw.err=ERR1
        assert_eqw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assert_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert
        u32assert.err=ERR1
        u32assert.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assert2_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assert2
        u32assert2.err=ERR1
        u32assert2.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn u32assertw_with_code() -> TestResult {
    let context = TestContext::default();
    let err_msg = "Oh no";
    let source = source_file!(
        &context,
        format!(
            "\
    const ERR1 = \"{err_msg}\"

    begin
        u32assertw
        u32assertw.err=ERR1
        u32assertw.err=\"{err_msg}\"
    end
    "
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

/// Ensure that assertion and `mtree_verify` error codes are preserved after assembly, including
/// through duplicate procedures with metadata-neutral MAST roots.
#[test]
fn asserts_and_mpverify_with_code_in_duplicate_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    proc f1
        u32assert.err=\"1\"
    end
    proc f2
        u32assert.err=\"2\"
    end
    proc f12
        u32assert.err=\"1\"
        u32assert.err=\"2\"
    end
    proc f21
        u32assert.err=\"2\"
        u32assert.err=\"1\"
    end
    proc g1
        assert.err=\"1\"
    end
    proc g2
        assert.err=\"2\"
    end
    proc g12
        assert.err=\"1\"
        assert.err=\"2\"
    end
    proc g21
        assert.err=\"2\"
        assert.err=\"1\"
    end
    proc fg
        assert.err=\"1\"
        u32assert.err=\"1\"
        assert.err=\"2\"
        u32assert.err=\"2\"

        u32assert.err=\"1\"
        assert.err=\"1\"
        u32assert.err=\"2\"
        assert.err=\"2\"
    end

    proc mpverify
        mtree_verify.err=\"1\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"2\"
        mtree_verify.err=\"1\"
    end

    begin
        exec.f1
        exec.f2
        exec.f12
        exec.f21
        exec.g1
        exec.g2
        exec.g12
        exec.g21
        exec.fg
        exec.mpverify
    end
    "
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn dynamic_link_to_ambiguous_same_digest_export_is_rejected() -> TestResult {
    let context = TestContext::default();
    let library_module = parse_module!(
        &context,
        r#"
        namespace lib::a
        pub proc f1
            assert.err="1"
        end

        pub proc f2
            assert.err="2"
        end
        "#
    );
    let library = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        library_module,
        None::<Box<Module>>,
    )?;

    let f1 = QualifiedProcedureName::from_str("lib::a::f1").unwrap();
    let f2 = QualifiedProcedureName::from_str("lib::a::f2").unwrap();
    assert_eq!(library.get_procedure_root_by_path(&f1), library.get_procedure_root_by_path(&f2));
    assert_ne!(library.get_export_node_id(&f1), library.get_export_node_id(&f2));

    let source = source_file!(
        &context,
        "\
        use lib::a

        begin
            exec.a::f2
        end
        "
    );
    let err = Assembler::new(context.source_manager())
        .with_package(Arc::from(library), Linkage::Dynamic)?
        .assemble_program("program", source)
        .expect_err("expected ambiguous dynamic link diagnostic");

    assert_diagnostic!(&err, "ambiguous dynamic procedure link for MAST root");
    assert_diagnostic!(
        &err,
        "dynamic reference cannot select one of the same-digest exported roots"
    );

    Ok(())
}

#[test]
fn mtree_verify_with_code() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
    const ERR1 = \"1\"

    begin
        mtree_verify
        mtree_verify.err=ERR1
        mtree_verify.err=\"2\"
    end
    "
    );

    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

// NESTED CONTROL BLOCKS
// ================================================================================================

#[test]
fn nested_control_blocks() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(
        &context,
        "begin \
        push.2 push.3 \
        if.true \
            add while.true push.7 push.11 add end \
        else \
            mul repeat.2 push.8 end if.true mul end  \
        end
        push.3 add
        end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

fn nested_if_source(depth: usize) -> String {
    let mut source = String::from("begin\n");
    for _ in 0..depth {
        source.push_str("push.1\nif.true\n");
    }
    source.push_str("push.1\n");
    for _ in 0..depth {
        source.push_str("end\n");
    }
    source.push_str("end\n");
    source
}

#[test]
fn control_flow_nesting_depth_boundary() -> TestResult {
    let context = TestContext::default();
    let source = nested_if_source(MAX_CONTROL_FLOW_NESTING);
    let source = source_file!(&context, source.as_str());
    context.assemble(source)?;
    Ok(())
}

#[test]
fn control_flow_nesting_depth_exceeded() {
    let context = TestContext::default();
    let source = nested_if_source(MAX_CONTROL_FLOW_NESTING + 1);
    let source = source_file!(&context, source.as_str());
    let error = context
        .assemble(source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");
    assert_diagnostic!(&error, "control-flow nesting depth exceeded");
}

// PROGRAMS WITH PROCEDURES
// ================================================================================================

#[test]
fn program_with_one_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_nested_procedure() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        proc foo push.3 push.7 mul end \
        proc bar push.5 exec.foo add end \
        begin push.2 push.4 add exec.foo push.11 exec.bar sub end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_proc_locals() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
        @locals(4) proc foo \
            loc_store.0 \
            add \
            loc_load.0 \
            mul \
        end \
        begin \
            push.10 push.9 push.8 \
            exec.foo \
        end"
    );
    let program = context.assemble(source)?;
    // Note: 18446744069414584317 == -4 (mod 2^64 - 2^32 + 1)
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_proc_locals_fail() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
proc foo
    loc_store.0
    add
    loc_load.0
    mul
end
begin
    push.4 push.3 push.2
    exec.foo
end"
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid procedure local reference to be rejected");
    assert_diagnostic!(&err, "invalid procedure local reference");
    assert_diagnostic!(&err, "the procedure local index referenced here is invalid");
    assert_diagnostic!(&err, "this procedure definition does not allocate any locals");
    assert_diagnostic!(&err, "loc_store.0");
}

#[test]
fn program_with_exported_procedure() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "pub proc foo push.3 push.7 mul end begin push.2 push.3 add exec.foo end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected exported program procedure to be rejected");
    assert_diagnostic!(&err, "invalid program: procedure exports are not allowed");
    assert_diagnostic!(&err, "perhaps you meant to use `proc` instead of `export`");
    assert_diagnostic!(&err, "pub proc foo");
}

// PROGRAMS WITH DYNAMIC CODE BLOCKS
// ================================================================================================

#[test]
fn program_with_dynamic_code_execution() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin dynexec end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_dynamic_code_execution_in_new_context() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin dyncall end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

// MAST ROOT CALLS
// ================================================================================================

#[test]
fn program_with_incorrect_mast_root_length() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin call.0x1234 end");

    let err = context
        .assemble(source)
        .expect_err("expected incorrect MAST root length to be rejected");
    assert_diagnostic!(&err, "invalid MAST root literal");
    assert_diagnostic!(&err, "begin call.0x1234 end");
}

#[test]
fn program_with_invalid_mast_root_chars() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a21xyzb end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected invalid MAST root chars to be rejected");
    assert_diagnostic!(&err, "invalid literal: expected 2, 4, 8, 16, or 64 hex digits");
    assert_diagnostic!(&err, "xyzb");
}

#[test]
fn program_with_invalid_rpo_digest_call() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected invalid RPO digest call to be rejected");
    assert_diagnostic!(&err, "invalid literal: value overflowed the field modulus");
    assert_diagnostic!(
        &err,
        "call.0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    );
}

#[test]
fn program_with_phantom_mast_call() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "begin call.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae end"
    );
    let ast = context.parse_program(source)?;

    let assembler = Assembler::new(context.source_manager());
    assembler.assemble_program("test", ast)?;
    Ok(())
}

// IMPORTS
// ================================================================================================

#[test]
fn program_with_one_import_and_hex_call() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            call.0x20234ee941e53a15886e733cc8e041198c6e90d2a16ea18ce1030e8c3596dd38
        end"#
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_two_imported_procs_with_same_mast_root() -> TestResult {
    const MODULE: &str = "dummy::math::u256";
    const PROCEDURE: &str = r#"
        pub proc iszero_unsafe_dup
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end

        pub proc iszero_unsafe
            eq.0
            repeat.7
                swap
                eq.0
                and
            end
        end"#;

    let mut context = TestContext::default();
    let ast =
        context.parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))?;
    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::iszero_unsafe
            exec.u256::iszero_unsafe_dup
        end"#
        )
    );
    context.assemble(source)?;
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy1", ast, [ref_ast])
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_custom_alias_in_same_library() -> TestResult {
    // exprted proc is in same library
    const REF_MODULE: &str = "dummy1::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        # checked_eqz checks if the value is u32 and zero and returns 1 if it is, 0 otherwise
        pub use {checked_eqz} from dummy1::math::u64 # re-export

        # unchecked_eqz checks if the value is zero and returns 1 if it is, 0 otherwise
        pub use {unchecked_eqz as notchecked_eqz} from dummy1::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::new();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))
        .unwrap();

    let ref_ast = context
        .parse_module(source_file!(&context, format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")))
        .unwrap();

    let library = Assembler::new(context.source_manager())
        .assemble_library("dummy1", ast, [ref_ast])
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE} as myu256
        begin
            push.4 push.3
            exec.myu256::checked_eqz
            exec.myu256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn program_with_reexported_proc_in_another_library() -> TestResult {
    // when re-exported proc is part of a different library
    const REF_MODULE: &str = "dummy2::math::u64";
    const REF_MODULE_BODY: &str = r#"
        pub proc checked_eqz
            u32assert2
            eq.0
            swap
            eq.0
            and
        end
        pub proc unchecked_eqz
            eq.0
            swap
            eq.0
            and
        end
    "#;

    const MODULE: &str = "dummy1::math::u256";
    const MODULE_BODY: &str = r#"
        pub use {checked_eqz} from dummy2::math::u64 # re-export
        pub use {unchecked_eqz as notchecked_eqz} from dummy2::math::u64 # re-export with alias
    "#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    // We reference code in this module
    let ref_ast = context.parse_module(source_file!(
        &context,
        format!("namespace {REF_MODULE}\n{REF_MODULE_BODY}")
    ))?;
    // But only exports from this module are exposed by the library
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{MODULE_BODY}")))?;

    let dummy_library = {
        let mut assembler = Assembler::new(source_manager);
        assembler.compile_and_statically_link(ref_ast)?;
        Arc::<Package>::from(assembler.assemble_library("dummy1", ast, None::<Box<Module>>)?)
    };

    // Now we want to use the the library we've compiled
    context.add_library(dummy_library.clone())?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {MODULE}
        begin
            push.4 push.3
            exec.u256::checked_eqz
            exec.u256::notchecked_eqz
        end"#
        )
    );
    let program = context.assemble(source)?;

    insta::assert_snapshot!(program);

    // We also want to assert that exports from the referenced module do not leak
    let mut context = TestContext::default();
    context.add_library(dummy_library)?;

    let source = source_file!(
        &context,
        format!(
            r#"
        use {REF_MODULE}
        begin
            push.4 push.3
            exec.u64::checked_eqz
            exec.u64::notchecked_eqz
        end"#
        )
    );
    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'dummy2::math::u64'",
        regex!(r#",-\[test[\d]+:2:13\]"#),
        "1 |",
        "2 |         use dummy2::math::u64",
        "  :             ^^^^^^^^^^^^^^^^^",
        "3 |         begin",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
    Ok(())
}

#[test]
fn module_alias() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let library = Assembler::new(source_manager)
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    let source = source_file!(
        &context,
        "
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);

    // --- invalid module alias -----------------------------------------------
    let source = source_file!(
        &context,
        r#"
        use dummy::math::u64 as "bad name"

        begin
            push.1.0
            push.2.0
            exec."bad name"::checked_add
        end"#
    );
    let err = context
        .assemble(source)
        .expect_err("expected invalid quoted module alias to be rejected");
    assert_diagnostic!(&err, "expected an alias name after `as`");
    assert_diagnostic!(&err, "bad name");

    Ok(())
}

#[test]
//#[ignore = "disabled until unused import accuracy is improved"]
fn module_alias_unused_import() -> TestResult {
    const MODULE: &str = "dummy::math::u64";
    const PROCEDURE: &str = r#"
        pub proc checked_add
            swap
            movup.3
            u32assert2
            u32widening_add
            movup.3
            movup.3
            u32assert2
            u32widening_add3
            eq.0
            assert
        end"#;

    let mut context = TestContext::default();
    let source_manager = context.source_manager();
    let ast = context
        .parse_module(source_file!(&context, format!("namespace {MODULE}\n{PROCEDURE}")))
        .unwrap();
    let library = Assembler::new(source_manager)
        .assemble_library("dummy", ast, None::<Box<Module>>)
        .unwrap();

    context.add_library(Arc::from(library))?;

    // --- duplicate module import --------------------------------------------
    let source = source_file!(
        &context,
        "
        use dummy::math::u64
        use dummy::math::u64 as bigint

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
        end"
    );

    let err = context
        .assemble(source)
        .expect_err("expected unused duplicate import to be rejected");
    assert_diagnostic!(&err, "unused import");
    assert_diagnostic!(&err, "this import is never used and can be safely removed");
    assert_diagnostic!(&err, "use dummy::math::u64");
    assert_diagnostic!(&err, "use dummy::math::u64 as bigint");

    // --- duplicate module imports with different aliases --------------------
    // TODO: Do we actually want this to be a warning/error? If the imports
    // have different aliases, there might be some use for that when refactoring
    // code or something. Anyway, I'm disabling the test that expects this to
    // fail for the time being
    /*
    let source = source_file!(
    &context,
        "
        use dummy::math::u64 as bigint
        use dummy::math::u64 as bigint2

        begin
            push.1.0
            push.2.0
            exec.bigint::checked_add
            exec.bigint2::checked_add
        end"
    );
    */
    Ok(())
}

#[test]
fn program_with_import_errors() {
    let context = TestContext::default();
    // --- non-existent import ------------------------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u512
        begin \
            push.4 push.3 \
            exec.u512::iszero_unsafe \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u512'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u512",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u512::iszero_unsafe end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );

    // --- non-existent procedure in import -----------------------------------
    let source = source_file!(
        &context,
        "\
        use miden::core::math::u256
        begin \
            push.4 push.3 \
            exec.u256::foo \
        end"
    );

    assert_assembler_diagnostic!(
        context,
        source,
        "undefined item 'miden::core::math::u256'",
        regex!(r#",-\[test[\d]+:1:5\]"#),
        "1 | use miden::core::math::u256",
        "  :     ^^^^^^^^^^^^^^^^^^^^^^^",
        "2 |         begin push.4 push.3 exec.u256::foo end",
        "  `----",
        "help: you might be missing an import, or the containing library has not been linked"
    );
}

// COMMENTS
// ================================================================================================

#[test]
fn comment_simple() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin # simple comment \n push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_in_nested_control_blocks() -> TestResult {
    let context = TestContext::default();

    // if with else
    let source = source_file!(
        &context,
        "begin \
        push.1 push.2 \
        if.true \
            # nested comment \n\
            add while.true push.7 push.11 add end \
        else \
            mul repeat.2 push.8 end if.true mul end  \
            # nested comment \n\
        end
        push.3 add
        end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_before_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "# starting comment \n begin push.1 push.2 add end");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn comment_after_program() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 push.2 add end # closing comment");
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn can_push_constant_word() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
const A = 0x0200000000000000030000000000000004000000000000000500000000000000
begin
    push.A
end"
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_advmap_push() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A(0x0200000000000000020000000000000002000000000000000200000000000000) = [0x01]
begin push.A adv.push_mapval assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_advmap_push_nokey() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A = [0x01]
begin push.A adv.push_mapval assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

#[test]
fn test_adv_has_map_key() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
adv_map A(0x0200000000000000020000000000000002000000000000000200000000000000) = [0x01]
begin adv.has_mapkey assert end"
    );

    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

// ERRORS
// ================================================================================================

#[test]
fn invalid_empty_program() {
    let context = TestContext::default();
    for _ in 0..2 {
        let err = context
            .assemble(source_file!(&context, "namespace foo"))
            .expect_err("expected empty program to be rejected");
        assert_diagnostic!(&err, "unable to assemble program: source is not an executable module");
    }
}

#[test]
fn invalid_program_unrecognized_token() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "none"))
        .expect_err("expected unexpected top-level token to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "unexpected top-level token");
    assert_diagnostic!(&err, "none");
}

#[test]
fn invalid_program_unmatched_begin() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "begin add"))
        .expect_err("expected unmatched begin to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `begin` block");
    assert_diagnostic!(&err, "begin add");
}

#[test]
fn invalid_program_invalid_top_level_token() {
    let context = TestContext::default();
    let err = context
        .assemble(source_file!(&context, "begin add end mul"))
        .expect_err("expected invalid top-level token to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "unexpected top-level token");
    assert_diagnostic!(&err, "begin add end mul");
}

#[test]
fn removed_debug_instructions_are_rejected_by_assembler() {
    let context = TestContext::default();

    for spelling in ["debug.stack.4", "debug.mem", "debug.local.0.2", "debug.adv_stack.4"] {
        let source = source_file!(&context, format!("begin {spelling} end"));
        let error = context
            .assemble(source)
            .expect_err("removed debug.* instruction should be rejected");
        assert_diagnostic!(&error, "invalid instruction");
    }
}

#[test]
fn invalid_proc_missing_end_unexpected_begin() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected procedure missing end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close procedure before top-level item");
    assert_diagnostic!(&err, "proc foo add mul begin push.1 end");
}

#[test]
fn invalid_proc_missing_end_unexpected_proc() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul proc bar push.3 end begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected procedure missing end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close procedure before top-level item");
    assert_diagnostic!(&err, "proc foo add mul proc bar push.3 end begin push.1 end");
}

#[test]
fn invalid_proc_undefined_local() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc foo add mul end begin push.1 exec.bar end");
    let err = context
        .assemble(source)
        .expect_err("expected undefined local proc to be rejected");
    assert_diagnostic!(&err, "undefined symbol reference");
    assert_diagnostic!(&err, "this symbol path could not be resolved");
    assert_diagnostic!(&err, "maybe you are missing an import");
    assert_diagnostic!(&err, "exec.bar");
}

#[test]
fn missing_import() {
    let context = TestContext::new();
    let source = source_file!(
        &context,
        r#"
    begin
        exec.u64::add
    end"#
    );

    let err = context.assemble(source).expect_err("expected missing import to be rejected");
    assert_diagnostic!(&err, "invalid relative item path 'u64::add'");
    assert_diagnostic!(&err, "absolute, local, or qualified by an import or submodule");
    assert_diagnostic!(&err, "exec.u64::add");
}

#[test]
fn invalid_proc_invalid_numeric_name() {
    let context = TestContext::default();
    let source = source_file!(&context, "proc 123 add mul end begin push.1 exec.123 end");
    let err = context
        .assemble(source)
        .expect_err("expected numeric procedure name to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected a procedure name");
    assert_diagnostic!(&err, "unexpected token in block");
}

#[test]
fn invalid_proc_duplicate_procedure_name() {
    let context = TestContext::default();
    let source =
        source_file!(&context, "proc foo add mul end proc foo push.3 end begin push.1 end");
    let err = context
        .assemble(source)
        .expect_err("expected duplicate procedure name to be rejected");
    assert_diagnostic!(&err, "symbol conflict: found duplicate definitions of the same name");
    assert_diagnostic!(&err, "conflict occurs here");
    assert_diagnostic!(&err, "previously defined here");
    assert_diagnostic!(&err, "proc foo add mul end proc foo push.3 end begin push.1 end");
}

#[test]
fn invalid_if_missing_end_no_else() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 add if.true mul");
    let err = context.assemble(source).expect_err("expected missing if end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `if`");
    assert_diagnostic!(&err, "begin push.1 add if.true mul");
}

#[test]
fn invalid_else_with_no_if() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 add else mul end");
    let err = context.assemble(source).expect_err("expected unmatched else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `begin` block before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");

    let source = source_file!(&context, "begin push.1 while.true add else mul end end");
    let err = context.assemble(source).expect_err("expected while-local else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `while` before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");
}

#[test]
fn invalid_unmatched_else_within_if_else() {
    let context = TestContext::default();

    let source =
        source_file!(&context, "begin push.1 if.true add else mul else push.1 end end end");
    let err = context.assemble(source).expect_err("expected duplicate else to be rejected");
    assert_diagnostic!(&err, "Multiple syntax errors were identified");
    assert_diagnostic!(&err, "expected `end` to close `if` before `else`");
    assert_diagnostic!(&err, "expected `end` to close `begin` block before `else`");
    assert_diagnostic!(&err, "unexpected top-level token");
}

#[test]
fn invalid_if_else_no_matching_end() {
    let context = TestContext::default();

    let source = source_file!(&context, "begin push.1 add if.true mul else add");
    let err = context
        .assemble(source)
        .expect_err("expected missing if/else end to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `if`");
    assert_diagnostic!(&err, "begin push.1 add if.true mul else add");
}

#[test]
fn invalid_repeat() {
    let context = TestContext::default();

    // unmatched repeat
    let source = source_file!(&context, "begin push.1 add repeat.10 mul");
    let err = context.assemble(source).expect_err("expected unmatched repeat to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `repeat`");
    assert_diagnostic!(&err, "begin push.1 add repeat.10 mul");

    // invalid iter count
    let source = source_file!(&context, "begin push.1 add repeat.23x3 mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected malformed repeat count to be rejected");
    assert_diagnostic!(&err, "invalid syntax: invalid instruction `x3` or malformed operands");
    assert_diagnostic!(&err, "begin push.1 add repeat.23x3 mul end end");

    // Overflow iter count
    let count: u64 = u32::MAX as u64 + 1;
    let source = source_file!(
        &context,
        format!(
            "\
            const CONSTANT = {count}
            begin
                repeat.CONSTANT
                    add
                end
            end
            "
        )
    );
    let err = context
        .assemble(source)
        .expect_err("expected overflowing repeat count to be rejected");
    assert_diagnostic!(&err, "invalid immediate: value is larger than expected range");
    assert_diagnostic!(&err, "repeat.CONSTANT");
}

#[test]
fn invalid_repeat_count_zero() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin repeat.0 nop end end");
    let error = context.assemble(source).expect_err("expected repeat.0 to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_zero_in_procedure() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        "\
proc foo
    repeat.0
        nop
    end
end

begin
    call.foo
end"
    );
    let error = context.assemble(source).expect_err("expected repeat.0 to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_too_large() {
    let context = TestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = source_file!(&context, format!("begin repeat.{repeat_count} nop end end"));
    let error = context
        .assemble(source)
        .expect_err("expected repeat count above limit to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_constant_zero() {
    let context = TestContext::default();
    let source =
        source_file!(&context, "const REPEAT_COUNT = 0\nbegin repeat.REPEAT_COUNT nop end end");
    let error = context
        .assemble(source)
        .expect_err("expected repeat.0 from constant to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn invalid_repeat_count_constant_too_large() {
    let context = TestContext::default();
    let repeat_count = MAX_REPEAT_COUNT + 1;
    let source = source_file!(
        &context,
        format!("const REPEAT_COUNT = {repeat_count}\nbegin repeat.REPEAT_COUNT nop end end")
    );
    let error = context
        .assemble(source)
        .expect_err("expected repeat count above limit from constant to be rejected");
    let rendered =
        format!("{}", crate::diagnostics::reporting::PrintDiagnostic::new_without_color(&error));
    assert!(rendered.contains("invalid repeat count"));
}

#[test]
fn repeat_count_constant_at_limit_allowed() {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        format!("const REPEAT_COUNT = {MAX_REPEAT_COUNT}\nbegin repeat.REPEAT_COUNT nop end end")
    );
    context
        .parse_program(source)
        .expect("expected repeat count at limit from constant to parse and analyze");
}

#[test]
fn const_folding_modulus_aliasing_must_be_rejected() {
    let program_src = r#"
const ALIAS = 18446744069414584320+1

begin
    push.ALIAS
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected constants >= field modulus to be rejected (must not silently alias to 0)"
    );
}

#[test]
fn const_evaluator_modulus_aliasing_must_be_rejected() {
    let program_src = r#"
const X = 18446744069414584320
const Y = 1
const ALIAS = X+Y

begin
    push.ALIAS
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected out-of-range constant results to be rejected (must not silently alias via `Felt::new_unchecked`)"
    );
}

#[test]
fn const_folding_u64_overflow_must_not_panic_and_must_error() {
    let program_src = r#"
const WRAP = 18446744069414584320+18446744069414584320

begin
    push.WRAP
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while folding a constant expression with u64 overflow"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected the assembler to reject constant expressions which overflow u64 during folding"
    );
}

#[test]
fn const_folding_subtraction_underflow_must_be_rejected() {
    let program_src = r#"
const UNDERFLOW = 0-1

begin
    push.UNDERFLOW
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected subtraction underflow in constant expressions to be rejected"
    );
}

#[test]
fn const_division_slash_must_not_match_int_division() {
    let program_src = r#"
const A1 = 3/2
const B1 = 3//2

const X = 3
const Y = 2
const A2 = X/Y
const B2 = X//Y

begin
    push.A1
    push.B1
    push.A2
    push.B2
end
"#;

    let program = Assembler::default()
        .assemble_program("test", program_src)
        .expect("program assembly must succeed")
        .unwrap_program();

    let entry = program.get_node_by_id(program.entrypoint()).expect("missing entrypoint node");
    let mast = format!("{}", entry.to_display(program.mast_forest()));

    let toks: Vec<&str> = mast.split_whitespace().collect();
    let pad_incr_pairs = toks.windows(2).filter(|w| w[0] == "pad" && w[1] == "incr").count();

    assert_eq!(
        pad_incr_pairs, 2,
        "expected `/` (field division) to not fold to the same value as `//` (integer division)"
    );
}

#[test]
fn const_division_by_zero_must_error() {
    let program_src = r#"
const BAD = 1/0

begin
    push.BAD
end
"#;

    let assembled = Assembler::default().assemble_program("test", program_src);
    assert!(
        assembled.is_err(),
        "expected division by zero in constant expressions to be rejected"
    );
}

#[test]
fn push_word_slice_u64_max_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[18446744073709551615]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[...] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[...] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn push_word_slice_range_u64_max_end_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[0..18446744073709551615]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[0..] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[0..] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn push_word_slice_range_u64_max_start_must_not_panic_and_must_error() {
    let program_src = r#"
const WORD = [1,2,3,4]

begin
    push.WORD[18446744073709551615..0]
end
"#;

    let assembled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Assembler::default().assemble_program("test", program_src)
    }));

    assert!(
        assembled.is_ok(),
        "assembler panicked while parsing push.WORD[..0] with an out-of-range index"
    );

    let assembled = assembled.unwrap();
    assert!(
        assembled.is_err(),
        "expected push.WORD[..0] with an out-of-range index to be rejected with an error"
    );
}

#[test]
fn invalid_while() {
    let context = TestContext::default();

    let source = source_file!(&context, "begin push.1 add while mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected invalid while spelling to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected `while.true`");
    assert_diagnostic!(&err, "begin push.1 add while mul end end");

    let source = source_file!(&context, "begin push.1 add while.abc mul end end");
    let err = context
        .assemble(source)
        .expect_err("expected invalid while spelling to be rejected");
    assert_diagnostic!(&err, "invalid syntax: expected `while.true`");
    assert_diagnostic!(&err, "begin push.1 add while.abc mul end end");

    let source = source_file!(&context, "begin push.1 add while.true mul");
    let err = context.assemble(source).expect_err("expected unmatched while to be rejected");
    assert_diagnostic!(&err, "syntax error");
    assert_diagnostic!(&err, "expected `end` to close `while`");
    assert_diagnostic!(&err, "begin push.1 add while.true mul");
}

// COMPILED LIBRARIES
// ================================================================================================
#[test]
fn test_compiled_library() {
    let context = TestContext::new();
    let root = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib

    pub mod mod1
    pub mod mod2
    "
            ))
            .unwrap()
    };
    let mod1 = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib::mod1

    proc internal
        push.5
    end
    pub proc foo
        push.1
        drop
    end
    pub proc bar
        exec.internal
        drop
    end
    "
            ))
            .unwrap()
    };

    let mod2 = {
        context
            .parse_module(source_file!(
                &context,
                "
    namespace mylib::mod2

    pub proc foo
        push.7
        add.5
    end
    # Same definition as mod1::foo
    pub proc bar
        push.1
        drop
    end
    "
            ))
            .unwrap()
    };

    let compiled_library = {
        let assembler = Assembler::new(context.source_manager());
        assembler.assemble_library("mylib", root, [mod1, mod2]).unwrap()
    };

    assert_eq!(compiled_library.manifest.num_exports(), 4);

    // Compile program that uses compiled library
    let mut assembler = Assembler::new(context.source_manager());

    assembler.link_package(Arc::from(compiled_library), Linkage::Dynamic).unwrap();

    let program_source = "
    use mylib::mod1
    use mylib::mod2

    proc foo
        push.1
        drop
    end

    begin
        exec.mod1::foo
        exec.mod1::bar
        exec.mod2::foo
        exec.mod2::bar
        exec.foo
    end
    ";

    let _program = assembler.assemble_program("test", program_source).unwrap();
}

#[test]
fn test_reexported_proc_with_same_name_as_local_proc_diff_locals() {
    let context = TestContext::new();
    let root = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test

            pub mod mod1
            pub mod mod2
            "
            ))
            .unwrap()
    };
    let mod1 = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test::mod1

            @locals(8) pub proc foo
                push.1
                drop
            end
            "
            ))
            .unwrap()
    };

    let mod2 = {
        context
            .parse_module(source_file!(
                &context,
                "namespace test::mod2

            use test::mod1
            pub proc foo
                exec.mod1::foo
            end
            "
            ))
            .unwrap()
    };

    let compiled_library = {
        let assembler = Assembler::new(context.source_manager());
        assembler.assemble_library("test", root, [mod1, mod2]).unwrap()
    };

    assert_eq!(compiled_library.manifest.num_exports(), 2);

    // Compile program that uses compiled library
    let mut assembler = Assembler::new(context.source_manager());

    assembler.link_package(Arc::from(compiled_library), Linkage::Dynamic).unwrap();

    let program_source = "
    use test::mod1
    use test::mod2

    @locals(4)
    proc foo
        exec.mod1::foo
        exec.mod2::foo
    end

    begin
        exec.foo
    end
    ";

    let _program = assembler.assemble_program("test", program_source).unwrap();
}

// PROGRAM SERIALIZATION AND DESERIALIZATION
// ================================================================================================
#[test]
fn test_program_serde_simple() {
    let source = "
    begin
        push.1.2
        add
        drop
    end
    ";

    let assembler = Assembler::default();
    let original_program = assembler.assemble_program("test", source).unwrap().unwrap_program();

    let mut target = Vec::new();
    original_program.write_into(&mut target);
    let deserialized_program = Program::read_from_bytes(&target).unwrap();

    assert_eq!(original_program, deserialized_program);
}

// MAST BUILDER ACCEPTANCE CORPUS
// ================================================================================================

#[test]
fn mast_builder_acceptance_corpus() -> TestResult {
    let context = TestContext::default();
    let mut summary = String::new();

    let cases = [
        (
            "straight_line_events",
            source_file!(
                &context,
                r#"
                const EVT = event("acceptance::straight_line")

                begin
                    push.1 push.2 add
                    emit.EVT
                end
                "#
            ),
        ),
        (
            "nested_control_flow",
            source_file!(
                &context,
                r#"
                begin
                    push.1
                    if.true
                        push.2
                    else
                        push.3
                    end

                    repeat.3
                        push.1 add
                    end
                end
                "#
            ),
        ),
        (
            "procedure_calls_and_repeated_subtrees",
            source_file!(
                &context,
                r#"
                proc repeated_a
                    push.9 push.3 add
                end

                proc repeated_b
                    push.9 push.3 add
                end

                proc decorated
                    push.0 drop
                end

                begin
                    exec.repeated_a
                    exec.repeated_b
                    exec.decorated
                end
                "#
            ),
        ),
    ];

    for (case_name, source) in cases {
        let program = context.assemble(source)?;
        append_program_acceptance_summary(&mut summary, case_name, &program);
    }

    let mut static_context = TestContext::default();
    static_context.add_module(source_file!(
        &static_context,
        r#"
            namespace acceptance::helpers

            pub proc inc
                push.1 add
            end

            pub proc inspect
                push.0 drop
            end
            "#
    ))?;
    let static_program = static_context.assemble(source_file!(
        &static_context,
        r#"
        use acceptance::helpers

        begin
            push.41
            exec.helpers::inc
            exec.helpers::inspect
        end
        "#
    ))?;
    append_program_acceptance_summary(&mut summary, "static_imports", &static_program);

    insta::assert_snapshot!("mast_builder_acceptance_corpus", summary);

    Ok(())
}

fn append_program_acceptance_summary(output: &mut String, case_name: &str, program: &Program) {
    let forest = program.mast_forest();
    let serialized_program_len = program.to_bytes().len();
    let serialized_forest_len = forest.to_bytes().len();

    writeln!(output, "=== {case_name} ===").unwrap();
    writeln!(output, "program_hash={:?}", program.hash()).unwrap();
    writeln!(output, "entrypoint={}", u32::from(program.entrypoint())).unwrap();
    writeln!(output, "num_procedures={}", program.num_procedures()).unwrap();
    writeln!(output, "num_nodes={}", forest.num_nodes()).unwrap();
    writeln!(output, "forest_commitment={:?}", forest.commitment()).unwrap();
    writeln!(output, "serialized_program_len={serialized_program_len}").unwrap();
    writeln!(output, "serialized_forest_len={serialized_forest_len}").unwrap();

    let roots = forest
        .procedure_roots()
        .iter()
        .map(|&node_id| u32::from(node_id))
        .collect::<Vec<_>>();
    let procedure_digests = forest.procedure_digests().collect::<Vec<_>>();
    let node_digests = forest.nodes().iter().map(MastNodeExt::digest).collect::<Vec<_>>();
    writeln!(output, "roots={roots:?}").unwrap();
    writeln!(output, "procedure_digests={procedure_digests:?}").unwrap();
    writeln!(output, "node_digests={node_digests:?}").unwrap();
}

#[test]
fn vendoring() -> TestResult {
    let context = TestContext::new();
    let vendor_lib = {
        let mod1 = context
            .parse_module(source_file!(
                &context,
                "namespace test::mod1
pub proc bar push.1 end pub proc prune push.2 end"
            ))
            .unwrap();
        Assembler::default()
            .assemble_library("vendor", mod1, None::<Box<Module>>)
            .unwrap()
    };

    let lib = {
        let mod2 = context
            .parse_module(source_file!(
                &context,
                "namespace test::mod2
pub proc foo exec.::test::mod1::bar end"
            ))
            .unwrap();

        let mut assembler = Assembler::default();
        assembler.link_package(Arc::from(vendor_lib), Linkage::Static)?;
        Arc::<Package>::from(assembler.assemble_library("lib", mod2, None::<Box<Module>>).unwrap())
    };

    // Rigorous testing of vendoring functionality

    // 1. The vendored library (lib) has `exec.::test::mod1::bar` which is a 0-cycle instruction.
    // 0-cycle instructions like `exec` don't generate AssemblyOps because they don't execute
    // any VM operations. The debug info may still have procedure names, error codes, etc.
    // The vendor_lib (mod1) has actual instructions (push.1, push.2) which do have AssemblyOps.

    // 2. Create an equivalent expected library for structural comparison
    let expected_lib = {
        let mod2 = context
            .parse_module(source_file!(
                &context,
                "namespace test::expected\npub proc foo push.1 end"
            ))
            .unwrap();
        Assembler::default()
            .assemble_library("test", mod2, None::<Box<Module>>)
            .unwrap()
    };

    // 3. Verify that the expected library (which has push.1) has package-owned AssemblyOps.
    assert_package_has_source_asm_ops(
        &expected_lib,
        "Expected library should have package-owned AssemblyOps for instruction tracking",
    );

    // 4. Verify we can create an assembler that successfully links the vendored library
    let mut assembler_with_vendored_lib = Assembler::default();
    let link_result = assembler_with_vendored_lib.link_package(lib.clone(), Linkage::Static);
    assert!(link_result.is_ok(), "Should be able to link the vendored library");

    // 5. Test that a simple program can be assembled with the linked library
    let program_with_lib_source = r#"
    begin
        push.1
        push.2
        add
    end
    "#;
    let assemble_result =
        assembler_with_vendored_lib.assemble_program("test", program_with_lib_source);
    assert!(
        assemble_result.is_ok(),
        "Should be able to assemble program with linked library"
    );
    let assembled_program = assemble_result.unwrap();

    // Verify the assembled program has package-owned debug info (AssemblyOps).
    assert_package_has_source_asm_ops(
        &assembled_program,
        "Assembled program with library should have package-owned AssemblyOps for instruction tracking",
    );

    // 6. Verify the vendored library contains the expected structure
    let mast_forest = lib.mast_forest();
    assert!(mast_forest.num_nodes() > 0, "Vendored library should have nodes");

    // Verify there are root procedures (the first node is usually a root for libraries)
    let nodes = mast_forest.nodes();
    assert!(!nodes.is_empty(), "Vendored library should have root procedures");

    Ok(())
}

// EMIT EVENT SYNTAX VALIDATION
// ================================================================================================

#[test]
fn emit_u32_immediate_is_rejected() {
    let context = TestContext::new();
    let program_source = r#"
        begin
            emit.32
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.<u32> should be rejected; only event("...") is allowed"#);
}

#[test]
fn emit_const_must_be_event_hash() {
    let context = TestContext::new();
    // CONST defined as plain number should not be accepted by emit.CONST
    let program_source = r#"
        const BAD = 100
        begin
            emit.BAD
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.CONST should require const defined via event("...")"#);

    // CONST defined via word("...") should also be rejected by emit.CONST
    let program_source = r#"
        const BADW = word("foo")
        begin
            emit.BADW
        end
    "#;
    context
        .assemble(program_source)
        .expect_err(r#"emit.CONST should require const defined via event("...")"#);
}

#[test]
#[should_panic(expected = "expected 3 lines, but got 1")]
fn assert_diagnostic_lines_rejects_missing_actual_lines() {
    assert_diagnostic_lines!(report!("the error string"), "the error string", "other", "lines");
}

#[test]
#[should_panic(expected = "expected 1 lines, but got 2")]
fn assert_diagnostic_lines_rejects_extra_actual_lines() {
    assert_diagnostic_lines!(report!("the first line\nthe second line"), "the first line");
}

// MAST TESTS
// ================================================================================================

#[test]
fn nested_blocks() -> Result<(), Report> {
    const KERNEL: &str = r#"
        pub proc foo
            add
        end"#;
    const MODULE_PROCEDURE: &str = r#"
        namespace libs::helpers

        pub proc help
            push.29
        end"#;

    let context = TestContext::new();
    let assembler = {
        let kernel_lib = Assembler::new(context.source_manager())
            .assemble_kernel("kernel", context.parse_kernel(source_file!(&context, KERNEL))?, None)
            .map(Arc::<Package>::from)
            .unwrap();

        let dummy_module = context.parse_module(MODULE_PROCEDURE)?;
        let dummy_library = Assembler::new(context.source_manager())
            .assemble_library("dummy", dummy_module, None::<Box<Module>>)
            .unwrap();

        let mut assembler = Assembler::with_kernel(context.source_manager(), kernel_lib)?;
        assembler.link_package(Arc::from(dummy_library), Linkage::Dynamic).unwrap();

        assembler
    };

    // The expected `MastForest` for the program (that we will build by hand)
    let mut expected_mast_forest_builder = MastForestBuilder::default();

    // fetch the kernel digest and store into a syscall block
    //
    // Note: this assumes the current internal implementation detail that `assembler.mast_forest`
    // contains the MAST nodes for the kernel after a call to
    // `Assembler::with_kernel_from_module()`.
    let syscall_foo_node_id = {
        let kernel_foo_node_ref = expected_mast_forest_builder
            .ensure_block_ref(vec![Operation::Add], vec![], vec![])
            .unwrap();

        expected_mast_forest_builder
            .ensure_call_node_ref(
                kernel_foo_node_ref,
                true,
                AssemblyOp::new(None, "test".into(), 1, "syscall.foo".into()),
            )
            .unwrap()
    };

    let program = r#"
    use libs::helpers

    proc foo
        push.19
    end

    proc bar
        push.17
        exec.foo
    end

    begin
        push.2
        if.true
            push.3
        else
            push.5
        end
        if.true
            if.true
                push.7
            else
                push.11
            end
        else
            push.13
            while.true
                exec.bar
                push.23
            end
        end
        exec.helpers::help
        syscall.foo
    end"#;

    let program = assembler.assemble_program("program", program).unwrap().unwrap_program();

    // basic block representing foo::bar.baz procedure
    let exec_foo_bar_baz_node_ref = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(29))], vec![], vec![])
        .unwrap();

    let fmp_initialization = expected_mast_forest_builder
        .ensure_block_ref(fmp_initialization_sequence(), vec![], vec![])
        .unwrap();

    let before = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(2))], vec![], vec![])
        .unwrap();

    let r#true1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(3))], vec![], vec![])
        .unwrap();
    let r#false1 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(5))], vec![], vec![])
        .unwrap();
    let r#if1 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true1, r#false1],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let r#true3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(7))], vec![], vec![])
        .unwrap();
    let r#false3 = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(11))], vec![], vec![])
        .unwrap();
    let r#true2 = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true3, r#false3],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let r#while = {
        let body_node_ref = expected_mast_forest_builder
            .ensure_block_ref(
                vec![
                    Operation::Push(Felt::from_u32(17)),
                    Operation::Push(Felt::from_u32(19)),
                    Operation::Push(Felt::from_u32(23)),
                ],
                vec![],
                vec![],
            )
            .unwrap();

        let asm_op = AssemblyOp::new(None, "test".into(), 1, "while.true".into());
        let loop_node_ref = expected_mast_forest_builder
            .ensure_loop_node_ref(body_node_ref, asm_op.clone())
            .unwrap();
        let noop_node_ref = expected_mast_forest_builder
            .ensure_block_ref(vec![Operation::Noop], vec![], vec![])
            .unwrap();

        expected_mast_forest_builder
            .ensure_split_node_ref([loop_node_ref, noop_node_ref], asm_op)
            .unwrap()
    };
    let push_13_basic_block_ref = expected_mast_forest_builder
        .ensure_block_ref(vec![Operation::Push(Felt::from_u32(13))], vec![], vec![])
        .unwrap();

    let r#false2 = expected_mast_forest_builder
        .join_node_refs(vec![push_13_basic_block_ref, r#while], None)
        .unwrap();
    let nested = expected_mast_forest_builder
        .ensure_split_node_ref(
            [r#true2, r#false2],
            AssemblyOp::new(None, "test".into(), 1, "if.true".into()),
        )
        .unwrap();

    let combined_node_ref = expected_mast_forest_builder
        .join_node_refs(
            vec![
                fmp_initialization,
                before,
                r#if1,
                nested,
                exec_foo_bar_baz_node_ref,
                syscall_foo_node_id,
            ],
            None,
        )
        .unwrap();

    expected_mast_forest_builder.record_procedure_root_ref(combined_node_ref);
    let (mut expected_mast_forest, node_remapping) =
        expected_mast_forest_builder.build().unwrap().into_parts();
    expected_mast_forest.make_root(node_remapping[&combined_node_ref]);
    let expected_program =
        Program::new(expected_mast_forest.into(), node_remapping[&combined_node_ref]);
    assert_eq!(expected_program.hash(), program.hash());

    // also check that the program has the right number of procedures (which excludes the dummy
    // library and kernel)
    assert_eq!(program.num_procedures(), 3);

    Ok(())
}

/// Ensures that the arguments of `emit` do indeed modify the digest of a basic block
#[test]
fn emit_instruction_digest() {
    let context = TestContext::new();

    let program_source = r#"
        const EVT1 = event("miden::test::event_one")
        const EVT2 = event("miden::test::event_two")

        proc foo
            emit.EVT1
        end

        proc bar
            emit.EVT2
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();

    let procedure_digests: Vec<Word> = program.mast_forest().procedure_digests().collect();

    // foo, bar and entrypoint
    assert_eq!(3, procedure_digests.len());

    // Ensure that foo, bar and entrypoint all have different digests
    assert_ne!(procedure_digests[0], procedure_digests[1]);
    assert_ne!(procedure_digests[0], procedure_digests[2]);
    assert_ne!(procedure_digests[1], procedure_digests[2]);
}

/// Tests that emitting events with immediate values has the same MAST representation
/// regardless of whether using emit.value or push.value emit syntax
#[test]
fn emit_syntax_equivalence() {
    let context = TestContext::new();

    // First program uses a constant
    let program1_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            emit.EVT
        end
    "#;

    // Second program uses inline emit.event("...")
    let program2_source = r#"
        begin
            emit.event("miden::test::equiv")
        end
    "#;

    // Third program uses manual emit with constant event name
    let program3_source = r#"
        const EVT = event("miden::test::equiv")
        begin
            push.EVT
            emit
            drop
        end
    "#;

    let program1 = context.assemble(program1_source).unwrap();
    let program2 = context.assemble(program2_source).unwrap();
    let program3 = context.assemble(program3_source).unwrap();

    // Get the MAST forest digests for both programs
    let digest1 = program1.hash();
    let digest2 = program2.hash();
    let digest3 = program3.hash();

    // Both programs should have identical MAST representations
    assert_eq!(digest1, digest2, "MAST digests differ between programs 1 and 2");
    assert_eq!(digest1, digest3, "MAST digests differ between programs 1 and 3");

    // Verify the procedure count is 1 (just the entrypoint) for both programs
    assert_eq!(program1.num_procedures(), 1);
    assert_eq!(program2.num_procedures(), 1);
    assert_eq!(program3.num_procedures(), 1);
}

/// Since `foo` and `bar` have the same body, we only expect them to be added once to the program.
#[test]
fn duplicate_procedure() {
    let context = TestContext::new();

    let program_source = r#"
        proc foo
            add
            mul
        end

        proc bar
            add
            mul
        end

        begin
            # specific impl irrelevant
            exec.foo
            exec.bar
        end
    "#;

    let program = context.assemble(program_source).unwrap();
    // `foo` and `bar` have the same body, so they are deduplicated. The entrypoint is the second
    // procedure.
    assert_eq!(program.num_procedures(), 2);
}

#[test]
fn distinguish_grandchildren_correctly() {
    let context = TestContext::new();

    let program_source = r#"
    begin
        if.true
            while.true
                push.2
                drop
                push.1
            end
        end

        if.true
            while.true
                push.1
            end
        end
    end
    "#;

    let program = context.assemble(program_source).unwrap();

    let join_node = &program.mast_forest()[program.entrypoint()].unwrap_join();

    // Make sure that both `if.true` blocks compile down to a different MAST node.
    assert_ne!(join_node.first(), join_node.second());
}

#[test]
fn explicit_fully_qualified_procedure_references() -> Result<(), Report> {
    const ROOT: &str = r#"
        namespace foo

        pub mod bar
        pub mod baz
    "#;
    const BAR: &str = r#"
        namespace foo::bar

        pub proc bar
            add
        end"#;
    const BAZ: &str = r#"
        namespace foo::baz

        pub proc baz
            exec.::foo::bar::bar
        end"#;

    let context = TestContext::default();
    let root = context.parse_module(ROOT)?;
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, root, [bar, baz]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    begin
        exec.::foo::baz::baz
    end"#;

    assert_matches!(assembler.assemble_program("program", program), Ok(_));
    Ok(())
}

#[test]
fn re_exports() -> Result<(), Report> {
    const BAR: &str = r#"
        namespace foo::bar

        pub proc baz
            add
        end"#;

    const BAZ: &str = r#"
        namespace foo::baz

        pub use {baz} from foo::bar

        pub proc qux
            push.1 push.2 add
        end"#;

    let context = TestContext::new();
    let bar = context.parse_module(BAR)?;
    let baz = context.parse_module(BAZ)?;
    let library = context.assemble_library("foo", None, baz, [bar]).unwrap();

    let assembler = Assembler::new(context.source_manager())
        .with_package(library.into(), Linkage::Dynamic)
        .unwrap();

    let program = r#"
    use foo::baz

    begin
        push.1 push.2
        exec.baz::baz
        push.3 push.4
        exec.baz::qux
    end"#;

    assert_matches!(assembler.assemble_program("test", program), Ok(_));
    Ok(())
}

#[test]
fn module_ordering_can_be_arbitrary() -> Result<(), Report> {
    const A: &str = r#"
        namespace a

        pub proc foo
            add
        end"#;

    const B: &str = r#"
        namespace b

        pub proc bar
            push.1 push.2 exec.::a::foo
        end"#;

    const C: &str = r#"
        namespace c

        pub proc baz
            exec.::b::bar
        end"#;

    let context = TestContext::new();
    let a = context.parse_module(A)?;
    let b = context.parse_module(B)?;
    let c = context.parse_module(C)?;

    let mut assembler = Assembler::new(context.source_manager());
    assembler.compile_and_statically_link(b)?.compile_and_statically_link(a)?;
    assembler.assemble_library("lib", c, None::<Box<Module>>)?;

    Ok(())
}

#[test]
fn can_assemble_a_multi_module_kernel() -> Result<(), Report> {
    const KERNEL: &str = r#"
        mod helpers
        use external::helpers as h
        pub proc foo
            exec.h::get_caller
            exec.helpers::get_caller
        end"#;
    const HELPERS: &str = r#"
        namespace $kernel::helpers

        pub proc get_caller
            caller
        end"#;
    const EXTERNAL_HELPERS: &str = r#"
        namespace external::helpers

        pub proc get_caller
            caller
        end"#;
    const PROGRAM: &str = r#"
        begin
            syscall.foo
        end"#;

    let context = TestContext::new();

    let kernel_lib = {
        let helpers = context.parse_module(HELPERS)?;
        let external_helpers = context.parse_module(EXTERNAL_HELPERS)?;
        let kernel = context.parse_kernel(source_file!(&context, KERNEL)).unwrap();

        let mut assembler = Assembler::new(context.source_manager());
        assembler.compile_and_statically_link(external_helpers)?;
        assembler.assemble_kernel("kernel", kernel, [helpers]).unwrap()
    };

    assert_eq!(kernel_lib.to_kernel_descriptor().ok().map(|k| k.proc_hashes().len()), Some(1));

    Assembler::with_kernel(context.source_manager(), Arc::from(kernel_lib))?
        .assemble_program("program", PROGRAM)?;

    Ok(())
}

#[test]
fn regression_empty_kernel_is_rejected() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "pub const FOO = 1\n";
    let err = Assembler::new(source_manager)
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_masm)).unwrap(),
            None,
        )
        .expect_err("expected empty kernel to be rejected");
    assert_diagnostic_lines!(err, "package must contain at least one exported procedure");
}

#[test]
fn regression_empty_kernel_with_submodule_is_rejected() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "mod sub\n\npub const FOO = 1\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(source_manager)
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected empty kernel to be rejected");
    assert_diagnostic_lines!(err, "package must contain at least one exported procedure");
}

#[test]
fn regression_empty_kernel_with_nonempty_submodule_is_rejected() {
    let context = TestContext::default();

    // A kernel module with no exported procedures should be rejected.
    let kernel_masm = "mod sub\n\npub use {foo} from self::sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let err = context
        .parse_kernel(source_file!(&context, kernel_masm))
        .expect_err("expected sema to reject re-export from kernel module");
    assert_diagnostic!(err, "invalid re-exported procedure");
}

#[test]
fn regression_reexport_of_kernel_procedure_from_kernel_submodule_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm =
        "namespace $kernel::sub\n\npub use {root} from $kernel\n\npub proc foo push.1 end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected kernel submodule re-exporting kernel syscall to be rejected");
    assert_diagnostic!(err, "invalid re-export of kernel syscall");
}

#[test]
fn regression_exec_of_kernel_procedure_is_rejected() {
    let context = TestContext::default();

    // The root kernel module is allowed to exec other syscalls, as shown here, but submodules
    // are not allowed to do this, as procedures exported from submodules are not required to be
    // invoked with `syscall`, so we must enforce the syscall constraint on all modules other than
    // the kernel module itself
    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n\npub proc other exec.root end";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo exec.$kernel::root end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let err = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect_err("expected assembler to reject exec of syscall from within kernel submodule");
    assert_diagnostic!(err, "kernel procedure '::$kernel::root' can only be invoked via syscall");
}

#[test]
fn regression_syscall_of_kernel_submodule_procedure_is_rejected() {
    let context = TestContext::default();

    let kernel_masm = "pub mod sub\n\npub const FOO = 1\n\npub proc root push.FOO end\n";
    let submodule_masm = "namespace $kernel::sub\n\npub proc foo syscall.root end\n";
    let program_masm = "begin syscall.::$kernel::sub::foo end\n";
    let kernel_module = context.parse_kernel(source_file!(&context, kernel_masm)).unwrap();
    let submodule = context.parse_module(source_file!(&context, submodule_masm)).unwrap();
    let _kernel = Assembler::new(context.source_manager())
        .assemble_kernel("kernel", kernel_module, [submodule])
        .expect("expected valid kernel");
    let err = context
        .parse_module(source_file!(&context, program_masm))
        .expect_err("expected sema to reject syscall of non-syscall procedure");
    assert_diagnostic!(err, "invalid syscall: callee must be resolvable to kernel module");
}

/// Reproduces issue #3035: a MAST with padded basic blocks must not grow during self-merge.
#[test]
fn issue_3035_self_merge_does_not_grow_mast() -> TestResult {
    let context = TestContext::default();
    let module = context.parse_module(source_file!(
        &context,
        "
            namespace issue_3035::repro

            pub proc repro
                add
                push.100
            end
            "
    ))?;

    let library = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        module,
        None::<Box<Module>>,
    )?;
    let forest = library.mast_forest().as_ref().clone();
    assert!(
        forest
            .nodes()
            .iter()
            .filter_map(|node| node.get_basic_block())
            .any(|block| { block.operations().count() > block.raw_operations().count() }),
        "test input must create at least one padded basic block"
    );

    let original_size = forest.to_bytes().len();
    let explicit_size = {
        let mut bytes = Vec::new();
        forest.write_into(&mut bytes);
        bytes.len()
    };
    let original_nodes = forest.nodes().len();
    let (merged, _) = MastForest::merge([&forest]).into_diagnostic()?;
    let merged_size = merged.to_bytes().len();
    let merged_explicit_size = {
        let mut bytes = Vec::new();
        merged.write_into(&mut bytes);
        bytes.len()
    };
    let merged_nodes = merged.nodes().len();

    assert!(
        merged_size <= original_size,
        "MastForest self-merge increased serialized execution size: \
         original={original_size}, merged={merged_size}, \
         explicit={explicit_size}, merged_explicit={merged_explicit_size}, \
         original_nodes={original_nodes}, merged_nodes={merged_nodes}"
    );

    Ok(())
}

/// Test for issue #1644: verify that single-forest merge doesn't preserves node digests
#[test]
fn issue_1644_single_forest_merge_identity() -> TestResult {
    // Test to more precisely demonstrate MastForest::merge non-identity behavior
    // This test focuses on the case where merge operation does not preserve identity for single
    // forests

    let context = TestContext::new();

    // Create a simple program that will result in specific basic block structures

    let program_source = r#"
    proc test
        push.1
        push.2
        push.3
    end

    proc main
        push.10
        if.true
            exec.test
            push.20
        else
            push.30
        end
        push.40
    end

    begin
        exec.main
    end"#;

    let program = context.assemble(program_source)?;
    let original_forest = program.mast_forest().clone();

    // Core test: Merge the forest with itself
    // This should act as identity (return the same forest) but doesn't
    let (merged_forest, _) = MastForest::merge([&*original_forest]).into_diagnostic()?;

    // Assert that the merged forest still contains the same join structure even if finalization
    // order changes where that join appears.
    let original_join = original_forest
        .nodes()
        .iter()
        .find_map(|node| match node {
            MastNode::Join(join) => Some(join),
            _ => None,
        })
        .expect("original forest must contain a join node");
    let merged_join = merged_forest
        .nodes()
        .iter()
        .find_map(|node| match node {
            MastNode::Join(join) => Some(join),
            _ => None,
        })
        .expect("merged forest must contain a join node");

    // Check that they have the same structure. Finalization may remap node IDs, so compare the
    // children by content commitment rather than by positional ID.
    assert_eq!(
        original_forest[original_join.first()].digest(),
        merged_forest[merged_join.first()].digest(),
    );
    assert_eq!(
        original_forest[original_join.second()].digest(),
        merged_forest[merged_join.second()].digest(),
    );
    assert_eq!(original_join.digest(), merged_join.digest());

    //Assert that merging is idempotent
    let (new_merged_forest, _) = MastForest::merge([&merged_forest]).into_diagnostic()?;
    let mut should_panic = false;

    // The merge operation does not act as identity for single-element arrays
    // Check 1: Forest structure should be identical (same number of nodes)
    if new_merged_forest.nodes().len() != merged_forest.nodes().len() {
        eprintln!(
            "Forest node count differs: original={}, merged={}",
            new_merged_forest.nodes().len(),
            merged_forest.nodes().len()
        );
        eprintln!("This violates the identity requirement for merge operation");

        should_panic = true;
    }

    // Check 2: Each node should have identical digest (strict identity)
    for (i, (orig_node, merged_node)) in
        new_merged_forest.nodes().iter().zip(merged_forest.nodes().iter()).enumerate()
    {
        if orig_node.digest() != merged_node.digest() {
            eprintln!("Node {i} digest violation:");
            eprintln!("   Original: {orig_node:?}");
            eprintln!("   Merged:   {merged_node:?}");
            eprintln!("   Original digest: {:?}", orig_node.digest());
            eprintln!("   Merged digest:   {:?}", merged_node.digest());

            should_panic = true;
        }
    }

    // Check 3: Roots should be identical
    for (i, (orig_root, merged_root)) in new_merged_forest
        .procedure_roots()
        .iter()
        .zip(merged_forest.procedure_roots())
        .enumerate()
    {
        if new_merged_forest[*orig_root].digest() != merged_forest[*merged_root].digest() {
            eprintln!("Root {i} digest violation:");
            eprintln!("   Original: {:?}", original_forest[*orig_root].digest());
            eprintln!("   Merged:   {:?}", merged_forest[*merged_root].digest());
            should_panic = true;
        }
    }

    if should_panic {
        panic!("Merge idempotence violation");
    }

    eprintln!("Merge identity test passed - no violations detected");
    Ok(())
}

#[test]
fn overlong_total_path_is_rejected_without_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::testing::TestContext;

    // Build a valid path where each component is within the per-component limit (255 bytes),
    // but the total byte length exceeds u16::MAX (the binary serialization length prefix).
    let component = "a".repeat(255);
    let num_components: usize = 300;
    let mut path_str = String::with_capacity(num_components * (component.len() + 2));
    for i in 0..num_components {
        if i > 0 {
            path_str.push_str("::");
        }
        path_str.push_str(&component);
    }

    let context = TestContext::default();
    let lib_src = format!(
        r#"
namespace {path_str}

pub proc add
    add.1
end
"#
    );

    let parsed = catch_unwind(AssertUnwindSafe(|| context.parse_module(lib_src.as_str())));

    assert!(
        parsed.is_ok(),
        "overlong total path caused a panic; expected a structured error"
    );
    let parsed = parsed.unwrap();
    let err = parsed.expect_err("expected overlong path to be rejected");
    assert_diagnostic!(err, "invalid item path: too long");
}

#[test]
fn public_item_import_exports_without_alias_symbol() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace root

        pub use {foo as bar} from dep
        "#
    ))?;
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub proc foo
            push.1
        end
        "#
    ))?;

    let library = Assembler::new(context.source_manager()).assemble_library("pkg", root, [dep])?;
    let exports = library.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert_eq!(exports.len(), 1);
    assert!(exports.contains(&Arc::from(Path::new("::root::bar"))));

    Ok(())
}

#[test]
fn link_import_module_and_item_forms_resolve() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::math

        pub const VALUE = 7
        pub type WordType = felt

        pub proc procedure
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use lib::math
        use lib::math as m
        use {procedure as imported_proc, VALUE, WordType} from lib::math

        pub const LOCAL = VALUE + 1

        pub proc entry(value: WordType)
            exec.imported_proc
            exec.math::procedure
            exec.m::procedure
            push.LOCAL
            drop
        end
        "#
    ))?;

    let package =
        Assembler::new(context.source_manager()).assemble_library("app", consumer, [dep])?;
    let exports = package.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert!(exports.contains(&Arc::from(Path::new("::app::entry"))));

    Ok(())
}

#[test]
fn link_import_single_segment_module_import_resolves() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace foo

        pub proc procedure
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use foo

        pub proc entry
            exec.foo::procedure
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", consumer, [dep])?;

    Ok(())
}

#[test]
fn link_import_item_form_rejects_submodule_target() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub mod child
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep::child

        pub proc entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {child} from dep

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [dep, child])
        .expect_err("item import of a submodule should be rejected");

    assert_diagnostic!(&err, "item import target '::dep::child' resolved to a module");

    Ok(())
}

#[test]
fn link_import_public_item_reexport_chain_resolves_order_independently() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub const VALUE = 1
        "#
    ))?;
    let mid = context.parse_module(source_file!(
        &context,
        r#"
        namespace mid

        pub use {VALUE as MID_VALUE} from dep
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {MID_VALUE as VALUE} from mid

        pub proc entry
            push.VALUE
            drop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", consumer, [mid, dep])?;

    Ok(())
}

#[test]
fn link_import_self_relative_public_item_reexport_resolves() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace dep

        pub proc helper
            nop
        end
        "#
    ))?;
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        pub mod child

        use {ALIAS as imported} from self::child

        pub proc entry
            exec.imported
            exec.self::child::ALIAS
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace app::child

        pub use {helper as ALIAS} from dep
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("app", root, [child, dep])?;

    Ok(())
}

#[test]
fn link_import_public_item_reexport_cycle_is_rejected() -> TestResult {
    let context = TestContext::new();
    let a = context.parse_module(source_file!(
        &context,
        r#"
        namespace a

        pub use {B as A} from b
        "#
    ))?;
    let b = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {A as B} from a
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {A} from a

        pub proc entry
            push.A
            drop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [a, b])
        .expect_err("public item re-export cycle should be rejected");

    assert_diagnostic!(&err, "import re-export cycle");

    Ok(())
}

#[test]
fn link_import_public_item_reexport_cycle_with_self_relative_target_is_rejected() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace root

        pub mod child
        pub use {B as A} from self::child
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace root::child

        pub use {A as B} from root
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace app

        use {A} from root

        pub proc entry
            push.A
            drop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("app", consumer, [root, child])
        .expect_err("public item re-export cycle should be rejected");

    assert_diagnostic!(&err, "import re-export cycle");

    Ok(())
}

#[test]
fn package_module_surface_allows_downstream_import_of_root_module() -> TestResult {
    let context = TestContext::new();
    let dep_root = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib

        pub mod api
        "#
    ))?;
    let dep_api = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::api

        pub proc foo
            push.1
        end
        "#
    ))?;

    let dep =
        Assembler::new(context.source_manager()).assemble_library("dep", dep_root, [dep_api])?;
    assert!(dep.manifest.get_module(Path::new("::pkg::lib")).is_some());
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::api")).is_some());

    let dep_bytes = dep.to_bytes();
    let dep = Arc::new(Package::read_from_bytes(&dep_bytes).map_err(Report::msg)?);
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace consumer

        use pkg::lib

        pub proc call
            exec.lib::api::foo
        end
        "#
    ))?;

    let package = Assembler::new(context.source_manager())
        .with_package(dep, Linkage::Static)?
        .assemble_library("consumer", consumer, None::<Box<Module>>)?;
    let exports = package.manifest.exports().map(PackageExport::path).collect::<BTreeSet<_>>();

    assert!(exports.contains(&Arc::from(Path::new("::consumer::call"))));

    Ok(())
}

#[test]
fn package_module_surface_omits_private_submodules() -> TestResult {
    let context = TestContext::new();
    let dep_root = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib

        pub mod api
        mod internal
        "#
    ))?;
    let dep_api = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::api

        use pkg::lib::internal

        pub proc foo
            exec.internal::hidden
        end
        "#
    ))?;
    let dep_internal = context.parse_module(source_file!(
        &context,
        r#"
        namespace pkg::lib::internal

        pub proc hidden
            push.1
        end
        "#
    ))?;

    let dep = Assembler::new(context.source_manager()).assemble_library(
        "dep",
        dep_root,
        [dep_api, dep_internal],
    )?;
    let root_surface = dep
        .manifest
        .get_module(Path::new("::pkg::lib"))
        .expect("root surface should be present");
    let submodules = root_surface
        .submodules()
        .iter()
        .map(|submodule| submodule.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(submodules, vec!["api"]);
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::api")).is_some());
    assert!(dep.manifest.get_module(Path::new("::pkg::lib::internal")).is_none());

    let dep = Arc::new(Package::read_from_bytes(&dep.to_bytes()).map_err(Report::msg)?);
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace consumer

        use pkg::lib

        pub proc call
            exec.lib::api::foo
        end
        "#
    ))?;

    Assembler::new(context.source_manager())
        .with_package(dep, Linkage::Static)?
        .assemble_library("consumer", consumer, None::<Box<Module>>)?;

    Ok(())
}

fn package_with_single_proc_export(
    context: &TestContext,
    export_path: &'static str,
    modules: impl IntoIterator<Item = PackageModule>,
) -> Result<Arc<Package>, Report> {
    let seed = context.parse_module(source_file!(
        context,
        r#"
        namespace seed

        pub proc foo
            push.1
        end
        "#
    ))?;
    let seed = Assembler::new(context.source_manager()).assemble_library(
        "seed",
        seed,
        None::<Box<Module>>,
    )?;
    let (node, digest) = seed
        .manifest
        .exports()
        .find_map(|export| export.as_procedure())
        .map(|export| (export.node, export.digest))
        .expect("seed package should export one procedure");
    let export = PackageExport::Procedure(ProcedureExport::new(
        Arc::from(Path::new(export_path)),
        node,
        digest,
        None,
    ));

    Package::create_with_modules(
        "dep".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(seed.mast_forest()),
        [export],
        modules,
        None,
    )
    .map(Arc::new)
    .map_err(Report::msg)
}

#[test]
fn package_link_rejects_missing_module_surface_metadata() -> TestResult {
    let context = TestContext::new();
    let dep = package_with_single_proc_export(&context, "::dep::foo", [])?;

    let err = match Assembler::new(context.source_manager()).with_package(dep, Linkage::Static) {
        Ok(_) => panic!("compiled packages without module surfaces should be rejected"),
        Err(err) => err,
    };

    assert_diagnostic!(&err, "invalid module surface metadata for package 'dep'");
    assert_diagnostic!(&err, "package manifest declares export '::dep::foo' in module '::dep'");
    assert_diagnostic!(&err, "no module surface was provided for that module");

    Ok(())
}

#[test]
fn package_link_rejects_incomplete_declared_submodule_surface_metadata() -> TestResult {
    let context = TestContext::new();
    let dep = package_with_single_proc_export(
        &context,
        "::dep::api::foo",
        [PackageModule::new(
            Arc::from(Path::new("::dep")),
            [PackageSubmodule::new(Ident::new("api").unwrap())],
        )],
    )?;

    let err = match Assembler::new(context.source_manager()).with_package(dep, Linkage::Static) {
        Ok(_) => panic!("compiled packages with incomplete module surfaces should be rejected"),
        Err(err) => err,
    };

    assert_diagnostic!(&err, "invalid module surface metadata for package 'dep'");
    assert_diagnostic!(
        &err,
        "package manifest declares submodule '::dep::api' from module '::dep'"
    );
    assert_diagnostic!(&err, "no module surface was provided for it");

    Ok(())
}

#[test]
fn link_diagnostic_for_missing_declared_submodule() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod missing

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, None::<Box<Module>>)
        .expect_err("declared missing child module should be rejected");

    assert_diagnostic!(&err, "undefined module '::diag::root::missing'");

    Ok(())
}

#[test]
fn link_diagnostic_for_undeclared_child_module() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("undeclared child module should be rejected");

    assert_diagnostic!(&err, "module '::diag::root::child' is not declared");
    assert_diagnostic!(&err, "`mod child` or `pub mod child`");

    Ok(())
}

#[test]
fn link_diagnostic_for_private_submodule_import() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::root::child

        pub proc entry
            exec.child::child_entry
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("private submodule import should be rejected");

    assert_diagnostic!(&err, "private submodule '::diag::root::child'");
    assert_diagnostic!(&err, "only public submodules can be imported from another module");

    Ok(())
}

#[test]
fn private_submodule_is_visible_to_descendants_of_its_parent() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod internal
        pub mod api

        pub proc entry
            nop
        end
        "#
    ))?;
    let internal = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::internal

        pub const VALUE = 1
        pub proc internal_entry
            nop
        end
        "#
    ))?;
    let api = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::api

        use {VALUE} from diag::root::internal
        use diag::root::internal as internal_api

        pub proc entry
            push.VALUE
            exec.internal_api::internal_entry
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [internal, api])?;

    Ok(())
}

#[test]
fn private_nested_submodule_is_not_visible_to_sibling_of_parent() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod parent
        pub mod sibling

        pub proc entry
            nop
        end
        "#
    ))?;
    let parent = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::parent

        mod hidden
        "#
    ))?;
    let hidden = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::parent::hidden

        pub const VALUE = 1
        "#
    ))?;
    let sibling = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::sibling

        use {VALUE} from diag::root::parent::hidden

        pub proc entry
            push.VALUE
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [parent, hidden, sibling])
        .expect_err("private nested submodule should not be visible to sibling of its parent");

    assert_diagnostic!(&err, "private submodule '::diag::root::parent::hidden'");
    assert_diagnostic!(&err, "only public submodules can be imported from another module");

    Ok(())
}

#[test]
fn link_diagnostic_for_module_reexport() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        pub use {child} from diag::root

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("module re-export should be rejected");

    assert_diagnostic!(&err, "item import target '::diag::root::child' resolved to a module");
    assert_diagnostic!(&err, "item-form imports may only import procedures, constants, or types");

    Ok(())
}

#[test]
fn link_diagnostic_for_import_target_through_import_alias() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub const VALUE = 1
        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::root::child
        use {VALUE} from child

        pub proc entry
            push.VALUE
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [root, child])
        .expect_err("import through another import should be rejected");

    assert_diagnostic!(
        &err,
        "import target 'child::VALUE' cannot be resolved through import 'child'"
    );
    assert_diagnostic!(&err, "imports are resolved independently");

    Ok(())
}

#[test]
fn pub_use_through_import_alias_is_rejected_even_when_global_path_exists() -> TestResult {
    let context = TestContext::new().with_warnings_as_errors(false);
    let imported = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep::child

        pub proc p
            push.1
        end
        "#
    ))?;
    let global = context.parse_module(source_file!(
        &context,
        r#"
        namespace child

        pub proc p
            push.2
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::dep::child
        pub use {p as alias} from child

        pub proc entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [imported, global])
        .expect_err("pub use through another import should be rejected before global lookup");

    assert_diagnostic!(&err, "import target 'child::p' cannot be resolved through import 'child'");
    assert_diagnostic!(&err, "imports are resolved independently");

    Ok(())
}

#[test]
fn link_diagnostic_for_self_referential_module_import() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        use diag::root::child

        pub proc child_entry
            exec.child::child_entry
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("module import of itself should be rejected");

    assert_diagnostic!(&err, "self-referential import of module 'diag::root::child'");
    assert_diagnostic!(&err, "a module cannot import itself");

    Ok(())
}

#[test]
fn link_diagnostic_for_importing_same_scope_submodule_with_alias() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child
        use diag::root::child as child_api

        pub proc entry
            exec.child_api::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("same-scope submodule imports should be rejected even when aliased");

    assert_diagnostic!(&err, "cannot import submodule '::diag::root::child'");
    assert_diagnostic!(&err, "submodule-qualified path");

    Ok(())
}

#[test]
fn link_diagnostic_for_importing_same_scope_submodule_with_self_alias() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child
        use self::child as child_api

        pub proc entry
            exec.child_api::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("self-relative same-scope submodule imports should be rejected");

    assert_diagnostic!(&err, "cannot import submodule '::diag::root::child'");
    assert_diagnostic!(&err, "submodule-qualified path");

    Ok(())
}

#[test]
fn code_paths_can_reference_current_and_descendant_items_absolutely() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        proc local_helper
            nop
        end

        pub proc entry
            exec.::diag::root::local_helper
            exec.::diag::root::child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn code_paths_can_reference_local_submodules_without_imports() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        mod child

        pub proc entry
            exec.child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn link_diagnostic_for_relative_global_like_code_path() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        pub proc entry
            exec.diag::root::child::child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child])
        .expect_err("relative paths should not fall back to the global namespace");

    assert_diagnostic!(&err, "invalid relative item path 'diag::root::child::child_entry'");
    assert_diagnostic!(&err, "absolute, local, or qualified by an import or submodule");

    Ok(())
}

#[test]
fn code_paths_can_reference_imported_module_subpaths() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep

        pub mod child

        pub proc entry
            nop
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep::child

        pub proc child_entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use diag::dep as dep

        pub proc entry
            exec.dep::child::child_entry
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", consumer, [dep, child])?;

    Ok(())
}

#[test]
fn self_relative_import_walks_public_submodules() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        use {child_entry} from self::child

        pub proc entry
            exec.child_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        pub proc child_entry
            push.1
        end
        "#
    ))?;

    Assembler::new(context.source_manager()).assemble_library("diag", root, [child])?;

    Ok(())
}

#[test]
fn self_relative_import_rejects_private_descendant() -> TestResult {
    let context = TestContext::new();
    let root = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root

        pub mod child

        use self::child::hidden

        pub proc entry
            exec.hidden::hidden_entry
        end
        "#
    ))?;
    let child = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child

        mod hidden
        "#
    ))?;
    let hidden = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::root::child::hidden

        pub proc hidden_entry
            nop
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", root, [child, hidden])
        .expect_err("private descendant import should be rejected");

    assert_diagnostic!(&err, "private submodule '::diag::root::child::hidden'");

    Ok(())
}

#[test]
fn link_diagnostic_for_subpath_through_non_module_item() -> TestResult {
    let context = TestContext::new();
    let dep = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::dep

        pub const VALUE = 1
        pub proc entry
            nop
        end
        "#
    ))?;
    let consumer = context.parse_module(source_file!(
        &context,
        r#"
        namespace diag::consumer

        use {nested as NESTED} from diag::dep::VALUE

        pub proc entry
            exec.NESTED
        end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("diag", consumer, [dep])
        .expect_err("subpath through item should be rejected");

    assert_diagnostic!(&err, "invalid symbol path");
    assert_diagnostic!(&err, "all ancestors of a path must be modules");

    Ok(())
}

#[test]
fn imported_error_message_alias_is_resolved_without_panicking() {
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        sync::Arc,
    };

    use miden_assembly_syntax::Parse;

    use crate::{Assembler, DefaultSourceManager};

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());

    // Library module `b` exports a string constant and an alias to it.
    let module_b_src = r#"
namespace b

pub const ERR1 = "oops"
pub const ERR2 = ERR1
"#;
    let module_b = <&str as Parse>::parse(module_b_src, false, source_manager.clone())
        .expect("module b parsing must succeed");

    // Executable module imports `ERR2` and uses it as an assertion error message.
    let module_a_src = r#"
use {ERR2} from b

begin
    assert.err=ERR2
end
"#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        let mut assembler = Assembler::new(source_manager);
        assembler
            .compile_and_statically_link(module_b)
            .expect("linking module b must succeed");
        assembler.assemble_program("test", module_a_src)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    assembled
        .unwrap()
        .expect("expected imported error message alias to assemble successfully");
}

#[test]
fn test_issue_2181_locaddr_bug_assembly() -> TestResult {
    let context = TestContext::default();
    let source = source_file!(
        &context,
        r#"
proc some_proc
    nop
end

@locals(4)
proc main
    locaddr.0
    locaddr.0
    locaddr.0
    exec.some_proc
    dropw
end

begin
    exec.main
end"#
    );
    let program = context.assemble(source)?;
    insta::assert_snapshot!(program);
    Ok(())
}

/// Tests conditional debug info functionality
///
/// This test is disabled because with debug mode always enabled (issue #1821),
/// we no longer have the ability to turn debug mode off. The old functionality
#[test]
fn test_assembler_debug_info_present() {
    let context = TestContext::default();
    let source = r#"
    namespace test::foo

    pub proc foo
        push.1 push.2 add
    end
    "#;

    let module = parse_module!(&context, source);

    // Test: With debug mode always enabled (issue #1821), debug info should always be present
    let assembler = Assembler::default();
    let library = assembler.assemble_library("test", module, None::<Box<Module>>).unwrap();
    // Debug info should be present since debug mode is enabled by default.
    // AssemblyOps are stored in package-owned source debug metadata.
    assert_package_has_source_asm_ops(
        &library,
        "Package-owned AssemblyOps should be present for tracking instructions",
    );
}

#[test]
fn test_cross_module_constant_resolution() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            pub const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use cycle::module_a
            pub const B_VAL = module_a::A_VAL + 5  # <-- Should work but fails
            pub proc b_proc
                push.B_VAL
            end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());

    let _ = assembler.assemble_library("test", module_a, [module_b])?;

    Ok(())
}

#[test]
fn test_cross_module_constant_resolution_as_local_definition() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            pub const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());

    let _ = assembler.assemble_library("cycle", module_a, [module_b])?;

    Ok(())
}

#[test]
fn importing_private_constant_from_another_module_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private constant import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn importing_private_constant_from_another_module_by_absolute_path_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            const A_VAL = 10
            pub proc a_proc
                push.A_VAL
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {A_VAL} from ::cycle::module_a
            pub proc b_proc
                push.A_VAL
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private absolute constant import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn importing_private_type_from_another_module_is_rejected() -> TestResult {
    let context = TestContext::default();

    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_a

            type PrivateType = felt
            pub proc a_proc
                nop
            end
        "#
    ))?;

    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module_b

            use {PrivateType} from cycle::module_a
            pub proc b_proc(value: PrivateType)
                nop
            end
        "#
    ))?;

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module_a, [module_b])
        .expect_err("expected private type import to be rejected");
    assert_diagnostic!(&err, "private symbol reference");
    assert_diagnostic!(&err, "only public items can be referenced from another module");

    Ok(())
}

#[test]
fn public_item_import_reexporting_private_signature_is_rejected() {
    let context = TestContext::default();

    let module = context
        .parse_module(source_file!(
            &context,
            r#"
                namespace cycle::module_a

                type PrivateType = felt

                pub use {hidden as exposed} from self

                proc hidden(value: PrivateType)
                    nop
                end
            "#
        ))
        .expect("private procedure signature should be valid before public re-export");

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module, None::<Box<Module>>)
        .expect_err("expected public re-export of private signature to be rejected");

    assert_diagnostic!(&err, "private type in exported procedure signature");
    assert_diagnostic!(&err, "exported procedure signatures may only reference public types");
}

#[test]
fn public_item_import_reexporting_private_type_is_rejected() {
    let context = TestContext::default();

    let module = context
        .parse_module(source_file!(
            &context,
            r#"
                namespace cycle::module_a

                type PrivateType = felt

                pub use {PrivateType as PublicType} from self
            "#
        ))
        .expect("private type should be valid before public re-export");

    let err = Assembler::new(context.source_manager())
        .assemble_library("library", module, None::<Box<Module>>)
        .expect_err("expected public re-export of private type to be rejected");

    assert_diagnostic!(&err, "private type in exported type declaration");
    assert_diagnostic!(&err, "exported type declarations may only reference public types");
}

#[test]
fn test_cross_module_constant_reexport_chain_in_procedure_scope() -> TestResult {
    let context = TestContext::new();

    let root = parse_module!(
        &context,
        r#"
            namespace dcrc

            pub mod a
            pub mod b
            pub mod c
        "#
    );

    let a = parse_module!(
        &context,
        r#"
            namespace dcrc::a

            pub const VAL = 99
            pub proc use_val
                push.VAL
                drop
            end
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace dcrc::b

            use dcrc::a
            pub const STEP = a::VAL + 1
            pub proc dummy
                push.STEP
                drop
            end
        "#
    );

    let c = parse_module!(
        &context,
        r#"
            namespace dcrc::c

            use dcrc::b
            pub const FINAL_VAL = b::STEP + 1
            pub proc dummy
                push.FINAL_VAL
                drop
            end
        "#
    );

    let lib = Assembler::new(context.source_manager()).assemble_library("dcrc", root, [a, b, c])?;

    let src = source_file!(
        &context,
        r#"
            use dcrc::c
            const LOCAL = c::FINAL_VAL
            begin
                push.LOCAL
                drop
            end
        "#
    );

    let _program = Assembler::new(context.source_manager())
        .with_package(Arc::from(lib), Linkage::Dynamic)?
        .assemble_program("test", src)?;

    Ok(())
}

#[test]
fn test_issue_2696_imported_constant_with_private_dependency() -> TestResult {
    let context = TestContext::new();

    let root = parse_module!(
        &context,
        r#"
            namespace wallet

            pub mod memory
            pub mod account
        "#
    );

    let memory = parse_module!(
        &context,
        r#"
            namespace wallet::memory

            const ACCOUNT_ID_AND_NONCE_OFFSET = 4
            pub const ACCOUNT_ID_SUFFIX_OFFSET = ACCOUNT_ID_AND_NONCE_OFFSET + 2
        "#
    );

    let account = parse_module!(
        &context,
        r#"
            namespace wallet::account

            use {ACCOUNT_ID_SUFFIX_OFFSET} from wallet::memory

            pub proc use_suffix
                push.ACCOUNT_ID_SUFFIX_OFFSET
                drop
            end
        "#
    );

    Assembler::new(context.source_manager()).assemble_library("wallet", root, [memory, account])?;

    Ok(())
}

#[test]
fn imported_main_alias_self_call_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let program = r#"
        use {"$main" as alias_main} from ::$exec

        begin
            call.alias_main
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_program("test", program)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled
        .unwrap()
        .expect_err("expected self-referential alias call to be rejected");
    assert_diagnostic!(&err, "found a cycle in the call graph");
    assert_diagnostic!(&err, "::$exec::$main");
}

#[test]
fn rootless_call_cycle_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let program = r#"
        begin
            call.b
        end

        proc b
            call."$main"
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_program("test", program)
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled.unwrap().expect_err("expected cyclic program to be rejected");
    assert_diagnostic!(&err, "found a cycle in the call graph");
    assert_diagnostic!(&err, "::$exec::$main");
    assert_diagnostic!(&err, "b");
}

#[test]
fn cyclic_link_retry_is_structured_error_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::linker::Linker;

    let context = TestContext::new();
    let module = context
        .parse_program(source_file!(
            &context,
            r#"
                begin
                    call.b
                end

                proc b
                    call."$main"
                end
            "#
        ))
        .expect("program parsing must succeed");
    let source_manager = context.source_manager();

    let first_attempt = catch_unwind(AssertUnwindSafe(|| {
        let mut linker = Linker::new(source_manager.clone());
        let first_err = linker
            .link([module.clone()], None::<Box<Module>>)
            .expect_err("expected cyclic program to be rejected on first link");
        let second_err = linker
            .link(core::iter::empty::<Box<Module>>(), None::<Box<Module>>)
            .expect_err("expected cyclic program to be rejected on second link");
        (first_err, second_err)
    }));

    assert!(first_attempt.is_ok(), "linker panicked while retrying a cyclic link");
    let (first_err, second_err) = first_attempt.unwrap();
    assert!(first_err.to_string().contains("found a cycle in the call graph"));
    assert!(second_err.to_string().contains("found a cycle in the call graph"));
}

#[test]
fn test_cross_module_constant_cycle_in_procedure_scope_is_structured_error() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::a

            use cycle::b

            pub proc use_cycle
                push.A
                drop
            end

            pub const A = b::B + 1
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::b

            use cycle::a
            pub const B = a::A + 1
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled.unwrap().expect_err("expected cyclic constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const A = b::B + 1");
    assert_diagnostic!(&err, "pub const B = a::A + 1");
}

#[test]
fn imported_error_message_cycle_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();

    let a = parse_module!(
        &context,
        r#"
            namespace cycle::errs::a

            use cycle::errs::b

            pub proc use_cycle
                assert.err=ERR_A
            end

            pub const ERR_A = b::ERR_B
        "#
    );

    let b = parse_module!(
        &context,
        r#"
            namespace cycle::errs::b

            use cycle::errs::a
            pub const ERR_B = a::ERR_A
        "#
    );

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::new(context.source_manager()).assemble_library("cycle", a, [b])
    }));

    assert!(assembled.is_ok(), "assembler panicked during assembly");
    let err = assembled
        .unwrap()
        .expect_err("expected cyclic error message constants to be rejected");
    assert_diagnostic!(&err, "constant evaluation terminated due to infinite recursion");
    assert_diagnostic!(&err, "pub const ERR_A = b::ERR_B");
    assert_diagnostic!(&err, "pub const ERR_B = a::ERR_A");
}

#[test]
fn asm_import_source_digest_reexport_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        context.parse_module(source_file!(
            &context,
            "namespace m::n\n\npub use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000\n"
        ))
    }));

    assert!(parsed.is_ok(), "parser panicked, expected a structured error");
    let err = parsed
        .unwrap()
        .expect_err("expected source-level digest re-export to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn asm_import_source_digest_alias_chain_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let parsed = catch_unwind(AssertUnwindSafe(|| {
        context.parse_module(source_file!(
            &context,
            r#"
                    namespace m::n

                    pub use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000
                    pub use {foo as bar} from m::n

                    pub proc calls_bar
                        call.bar
                    end
                "#
        ))
    }));

    assert!(parsed.is_ok(), "parser panicked, expected a structured error");
    let err = parsed
        .unwrap()
        .expect_err("expected source-level digest alias chain to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn asm_import_direct_digest_invoke_assembles_without_source_import() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let program = r#"
        begin
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::default().assemble_program("program", program)
    }));

    assert!(
        assembled.is_ok(),
        "assembly panicked, expected direct opaque digest invoke to be allowed"
    );
    assembled
        .unwrap()
        .expect("expected direct digest invocation to assemble successfully");
}

#[test]
fn asm_import_direct_digest_invoke_parses_with_warnings_as_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let program = r#"
        begin
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, program, source_manager)
        .expect("expected direct digest invocation to parse without import warnings");
}

#[test]
fn asm_import_direct_digest_forward_decl_assembles_without_source_import() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let program = r#"
        proc helper
            exec.0xc2545da99d3a1f3f38d957c7893c44d78998d8ea8b11aba7e22c8c2b2a213dae
        end

        begin
            call.helper
        end
    "#;

    Assembler::new(source_manager)
        .assemble_program("program", program)
        .expect("expected direct digest invocation in helper proc to assemble");
}

#[test]
fn forward_declared_import_used_by_type_ref_is_not_reported_unused_when_warnings_are_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        type Local = foo::Type
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by type ref to count as used");
}

#[test]
fn forward_declared_import_used_by_proc_signature_is_not_reported_unused_when_warnings_are_errors()
{
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        pub proc check(value: foo::Type) -> foo::Type
            nop
        end
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by signature type to count as used");
}

#[test]
fn kernel_import_used_by_proc_signature_is_not_reported_unused_when_warnings_are_errors() {
    let context = TestContext::new();
    context
        .parse_kernel(source_file!(
            &context,
            r#"
            namespace $kernel

            use external::module as foo

            pub proc check(value: foo::Type) -> foo::Type
                nop
            end
            "#
        ))
        .expect("expected kernel signature type import to count as used");
}

#[test]
fn forward_declared_import_used_by_constant_ref_is_not_reported_unused_when_warnings_are_errors() {
    use std::sync::Arc;

    use crate::DefaultSourceManager;

    let source_manager: Arc<dyn crate::SourceManager> = Arc::new(DefaultSourceManager::default());
    let module = r#"
        namespace m

        const LOCAL = foo::BAR
        use external::module as foo
    "#;

    let mut parser = Module::parser(None);
    parser.set_warnings_as_errors(true);

    parser
        .parse_str(None, module, source_manager)
        .expect("expected forward-declared import used by constant ref to count as used");
}

#[test]
fn asm_import_source_digest_import_is_rejected_without_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let program = r#"
        use {foo} from 0x0000000000000000000000000000000000000000000000000000000000000000

        begin
            exec.foo
        end
    "#;

    let assembled = catch_unwind(AssertUnwindSafe(|| {
        Assembler::default().assemble_program("program", program)
    }));

    assert!(assembled.is_ok(), "assembly panicked, expected a structured error");
    let err = assembled
        .unwrap()
        .expect_err("expected source-level digest import to be rejected");
    assert_diagnostic!(&err, "digest imports are not supported in source `use` declarations");
}

#[test]
fn invoking_local_type_alias_returns_error_instead_of_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let masm = "type foo = u32\nbegin\n    exec.foo\nend\n";

    let result =
        catch_unwind(AssertUnwindSafe(|| Assembler::default().assemble_program("program", masm)));

    let result = result.expect("assembly panicked, expected a structured error");
    let err = result.expect_err("assembly unexpectedly succeeded");
    assert_diagnostic!(&err, "invalid symbol reference: wrong type");
    assert_diagnostic!(&err, "expected this symbol to reference a procedure item");
}

#[test]
fn invoking_local_type_alias_is_rejected_during_semantic_analysis() {
    let context = TestContext::new();
    let masm = source_file!(&context, "type foo = u32\nbegin\n    exec.foo\nend\n");

    let err = context
        .parse_program(masm)
        .expect_err("semantic analysis unexpectedly accepted invoking a local type alias");
    assert_diagnostic!(&err, "invalid symbol reference: wrong type");
    assert_diagnostic!(&err, "expected this symbol to reference a procedure item");
}

#[test]
fn invoking_imported_type_alias_returns_error_instead_of_panicking() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::new();
    let lib_src = source_file!(
        &context,
        "\
namespace test::types

pub type foo = u32

pub proc fun(in: foo)
    push.1
end"
    );
    let lib = context.parse_module(lib_src).expect("library module parsing must succeed");
    let library = Assembler::new(context.source_manager())
        .assemble_library("test", lib, None::<Box<Module>>)
        .expect("library assembly must succeed");

    let mut assembler = Assembler::new(context.source_manager());
    assembler
        .link_package(Arc::from(library), Linkage::Dynamic)
        .expect("library linking must succeed");

    let program = "use test::types\nbegin\n    exec.types::foo\nend\n";
    let result = catch_unwind(AssertUnwindSafe(|| assembler.assemble_program("program", program)));

    let result = result.expect("assembly panicked, expected a structured error");
    let err = result.expect_err("assembly unexpectedly succeeded");
    assert_diagnostic!(&err, "invalid procedure reference: path refers to a non-procedure item");
    assert_diagnostic!(&err, "test::types::foo");
}

#[test]
fn test_cross_module_quoted_identifier_resolution() -> TestResult {
    let context = TestContext::default();

    // Module A defines and exports a constant
    let module_a = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::"module::a"

            # Checks local path resolution
            pub proc "$item::<T>::fun"
                exec."$item::<T>::get"
            end

            # Checks absolute path resolution to a local item
            proc "$item::<T>::get"
                exec.::cycle::"module::a"::"$item::<T>::get_impl"
            end

            proc "$item::<T>::get_impl"
                push.1
            end
        "#
    ))?;

    // Module B imports Module A and defines a constant using it
    let module_b = context.parse_module(source_file!(
        &context,
        r#"
            namespace cycle::module::b

            # Checks that import resolution with quoted path components works
            use cycle::"module::a" as a

            # Checks that link-time cross-module resolution with quoted path components works
            pub proc b_proc
                exec.a::"$item::<T>::fun"
            end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());

    let _ = assembler.assemble_library("cycle", module_a, [module_b])?;

    Ok(())
}

#[test]
fn regression_symbol_resolution_duplicate_module_paths_are_rejected_during_linking() {
    fn try_assemble_program_with_link_order(libs: &[Arc<Package>]) -> Result<(), Report> {
        let program_source = r#"
begin
    exec.::foo::bar::add
end
"#;

        let mut assembler = Assembler::default();
        for lib in libs {
            assembler.link_package(lib.clone(), Linkage::Static)?;
        }

        assembler.assemble_program("program", program_source).map(|_| ())
    }

    let context = TestContext::default();
    let source_manager = context.source_manager();

    let legit_mod = context
        .parse_module(
            r#"
namespace ::foo::bar

pub proc add
    add.1
end
"#,
        )
        .expect("module must parse and analyse");

    let attacker_mod = context
        .parse_module(
            r##"namespace ::foo::"bar"

pub proc add add.2 end"##,
        )
        .expect("module must parse and analyse");

    let legit_lib = Assembler::new(source_manager.clone())
        .assemble_library("legit", legit_mod, None::<Box<Module>>)
        .map(Arc::<Package>::from)
        .expect("library assembly must succeed");
    let attacker_lib = Assembler::new(source_manager)
        .assemble_library("legit", attacker_mod, None::<Box<Module>>)
        .map(Arc::<Package>::from)
        .expect("library assembly must succeed");

    let err = try_assemble_program_with_link_order(&[legit_lib.clone(), attacker_lib.clone()])
        .expect_err("expected duplicate canonical module namespace to be rejected");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");

    let err = try_assemble_program_with_link_order(&[attacker_lib, legit_lib])
        .expect_err("expected duplicate canonical module namespace to be rejected");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");
}

#[test]
fn regression_symbol_resolution_in_library_canonical_export_collision_is_rejected() {
    let context = TestContext::default();
    let source_manager = context.source_manager();
    let legit_mod = context
        .parse_module("namespace ::foo::bar\n\npub proc add add.1 end")
        .expect("module must parse and analyse");
    let attacker_mod = context
        .parse_module(
            r##"namespace ::foo::"bar"

pub proc add add.2 end"##,
        )
        .expect("module must parse and analyse");

    let err = Assembler::new(source_manager)
        .assemble_library("lib", legit_mod, [attacker_mod])
        .expect_err("expected duplicate canonical export paths to be rejected during assembly");
    assert_diagnostic!(err, "duplicate definition found for module '::foo::bar'");
}

#[test]
fn regression_symbol_resolution_export_leaf_name_collision_should_be_rejected() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            r#"
namespace lib

pub proc p
    push.1
end
"#,
        )
        .expect("base module parsing must succeed");
    let base = Assembler::new(context.source_manager())
        .assemble_library("lib", module, None::<Box<Module>>)
        .expect("base library assembly must succeed");
    let (node, digest) = base
        .manifest
        .exports()
        .find_map(|e| e.as_procedure())
        .map(|e| (e.node, e.digest))
        .expect("expected at least one procedure export");

    let quoted = Arc::<Path>::from(Path::validate(r#"::foo::"bar""#).unwrap());
    let unquoted = Arc::<Path>::from(Path::validate("::foo::bar").unwrap());

    let exports = vec![
        PackageExport::Procedure(ProcedureExport::new(quoted, node, digest, None)),
        PackageExport::Procedure(ProcedureExport::new(unquoted, node, digest, None)),
    ];

    Package::create(
        "test".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(base.mast_forest()),
        exports,
        None,
    )
    .expect_err("duplicate export paths must be rejected");
}

#[test]
fn executable_package_main_export_points_to_entrypoint_source_root() -> TestResult {
    let context = TestContext::default();
    let lib_module = context.parse_module(
        r#"
        namespace lib::lib

        pub proc lib_proc
            push.1
        end
        "#,
    )?;
    let lib = Assembler::new(context.source_manager().clone())
        .assemble_library("lib", lib_module, None::<Box<Module>>)
        .map(Arc::<Package>::from)?;
    let package = Assembler::new(context.source_manager())
        .with_package(lib, Linkage::Static)?
        .assemble_program(
            "program",
            r#"
            use lib::lib

            begin
                exec.lib::lib_proc
            end
            "#,
        )?;

    let main_path = Path::exec_path().join(ProcedureName::MAIN_PROC_NAME);
    let entrypoint = package
        .get_procedure_node_by_path(&main_path)
        .expect("main procedure should have an execution node");
    let main_export = package
        .manifest
        .get_export(&main_path)
        .and_then(PackageExport::as_procedure)
        .expect("main export should exist");
    let source_node = main_export.source_node.expect("main export should retain source debug root");
    let debug_info = package
        .debug_info()
        .expect("package debug info should decode")
        .expect("package should contain source debug info");

    assert_eq!(debug_info.source_node(source_node).unwrap().exec_node, entrypoint);
    Ok(())
}

#[test]
fn regression_symbol_resolution_malformed_quoted_export_leaf_should_return_error_not_panic() {
    let context = TestContext::default();
    let module = context
        .parse_module(
            r#"
namespace test

pub proc p
    push.1
end
"#,
        )
        .expect("base module parsing must succeed");
    let base = Assembler::new(context.source_manager())
        .assemble_library("test", module, None::<Box<Module>>)
        .expect("base library assembly must succeed");
    let (node, digest) = base
        .manifest
        .exports()
        .find_map(|e| e.as_procedure())
        .map(|e| (e.node, e.digest))
        .expect("expected at least one procedure export");

    let bad = Arc::<Path>::from(Path::validate(r#"::foo::"bad name""#).unwrap());

    let exports = vec![PackageExport::Procedure(ProcedureExport::new(bad, node, digest, None))];

    Package::create(
        "test".into(),
        "0.0.0".parse().unwrap(),
        TargetType::Library,
        Arc::clone(base.mast_forest()),
        exports,
        None,
    )
    .expect_err("expected malformed procedure export leaf names to be rejected");
}

#[test]
fn test_kernel_linking_against_its_own_library() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub mod lib

        proc internal_proc
            caller
            drop
            exec.$kernel::lib::lib_proc
        end

        pub proc kernel_proc
            exec.internal_proc
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace $kernel::lib

            pub proc lib_proc
                swap
            end
            "#
    ))?;

    let _ = Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, [lib])?;

    Ok(())
}

#[test]
fn test_syscall_resolution_uses_kernel_module() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end

        pub proc bar
            caller
            drop
            push.2
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace userspace

            pub proc bar
                push.0
            end
            "#
    ))?;

    let source = source_file!(
        &context,
        r#"
        use {bar} from userspace

        proc foo
            push.0
        end

        begin
            syscall.foo
            syscall.bar
        end
        "#
    );

    let kernel =
        Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, None)?;
    let kernel_bar_root = kernel.as_ref().get_procedure_root_by_path("::$kernel::bar").unwrap();
    let kernel_foo_root = kernel.as_ref().get_procedure_root_by_path("::$kernel::foo").unwrap();

    let mut assembler = Assembler::with_kernel(context.source_manager(), Arc::from(kernel))?;
    assembler.compile_and_statically_link(lib)?;
    let program = assembler.assemble_program("program", source)?.unwrap_program();

    let mast = {
        let entry = program.get_node_by_id(program.entrypoint()).unwrap();
        format!("{}", entry.to_display(program.mast_forest()))
    };

    let expected = format!(
        r#"join
    join
        basic_block push(2147483648) push(4294967294) mstore drop noop end
        syscall.{kernel_foo_root}
    end
    syscall.{kernel_bar_root}
end"#
    );
    assert_eq!(mast, expected);

    Ok(())
}

#[test]
fn test_syscall_resolution_to_non_kernel_path_is_checked() -> TestResult {
    let context = TestContext::default();

    let kernel = context.parse_kernel(source_file!(
        &context,
        r#"
        pub proc foo
            caller
            drop
            push.1
        end
        "#
    ))?;

    let lib = context.parse_module(source_file!(
        &context,
        r#"
            namespace userspace

            pub proc bar
                push.0
            end
            "#
    ))?;

    let source = source_file!(
        &context,
        r#"
        begin
            syscall.userspace::bar
        end
        "#
    );

    let kernel =
        Assembler::new(context.source_manager()).assemble_kernel("kernel", kernel, None)?;
    let lib = Assembler::new(context.source_manager()).assemble_library(
        "lib",
        lib,
        None::<Box<Module>>,
    )?;

    let error = Assembler::with_kernel(context.source_manager(), Arc::from(kernel))?
        .with_package(Arc::from(lib), Linkage::Static)?
        .assemble_program("program", source)
        .expect_err("expected diagnostic to be raised, but compilation succeeded");

    assert_diagnostic!(&error, "invalid syscall: callee must be resolvable to kernel module");
    assert_diagnostic!(&error, "syscall.userspace::bar");

    Ok(())
}

#[test]
fn syscall_validation_does_not_panic_on_same_digest_userspace_procedure() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .expect("kernel assembly must succeed");

    let assembler = Assembler::with_kernel(source_manager, Arc::from(kernel_lib))
        .expect("test package should be valid");

    let program_src = r#"
proc dup
    push.1
end

begin
    exec.dup
    syscall.k1
end
"#;

    let assembled =
        catch_unwind(AssertUnwindSafe(|| assembler.assemble_program("program", program_src)));
    assert!(assembled.is_ok(), "assembler panicked while assembling a valid program");
    assert!(assembled.unwrap().is_ok(), "expected program assembly to succeed");
}

#[test]
fn syscall_by_unknown_digest_is_rejected_at_assembly_time_when_kernel_is_configured() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel_lib = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .expect("kernel assembly must succeed");

    let assembler = Assembler::with_kernel(source_manager, Arc::from(kernel_lib))
        .expect("test kernel should be valid");

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let err = assembler
        .assemble_program("program", program_src)
        .expect_err("expected unknown digest syscall to be rejected");
    assert_diagnostic!(err, "invalid syscall");
}

#[test]
fn syscall_without_kernel_is_rejected_at_assembly_time() {
    let context = TestContext::default();
    let assembler = Assembler::new(context.source_manager());

    let program_src = r#"
begin
    syscall.0x0000000000000000000000000000000000000000000000000000000000000000
end
"#;

    let err = assembler
        .assemble_program("program", program_src)
        .expect_err("expected syscall without kernel to be rejected");
    assert_diagnostic!(err, "invalid syscall");
}

#[test]
fn regression_kernel_exports_are_syscall_only_for_all_non_syscall_entrypoints() {
    let context = TestContext::default();
    let source_manager = context.source_manager();

    let kernel_src = r#"
pub proc k1
    push.1
end
"#;

    let kernel = Assembler::new(source_manager.clone())
        .assemble_kernel(
            "kernel",
            context.parse_kernel(source_file!(&context, kernel_src)).unwrap(),
            None,
        )
        .map(Arc::<Package>::from)
        .expect("kernel assembly must succeed");

    let cases = vec![
        (
            "exec",
            "proc user\n    exec.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "call",
            "proc user\n    call.::$kernel::k1\nend\n\nbegin\n    call.user\nend\n".to_string(),
        ),
        (
            "procref",
            "proc user\n    procref.::$kernel::k1\n    dropw\nend\n\nbegin\n    call.user\nend\n"
                .to_string(),
        ),
    ];

    for (kind, program_src) in cases {
        let err = Assembler::with_kernel(source_manager.clone(), Arc::clone(&kernel))
            .expect("test kernel should be valid")
            .assemble_program("program", program_src)
            .expect_err(&format!("kernel exports should be syscall-only, but {kind} succeeded"));
        assert_diagnostic!(err, "syscall");
    }
}

#[test]
fn test_linking_imported_symbols_with_duplicate_prefix_components() -> TestResult {
    let context = TestContext::default();

    // The name of this library is `lib::lib` on purpose
    let lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace lib::lib

        pub proc lib_proc
            swap
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let lib = assembler.assemble_library("lib", lib, None::<Box<Module>>)?;

    // This import's default alias is `lib`, which is also the first component of its global
    // target. That must still resolve globally rather than being mistaken for an import-through-
    // import attempt.
    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.with_package(Arc::from(lib), Linkage::Static)?.assemble_program(
        "program",
        r#"
        use lib::lib

        begin
            exec.lib::lib_proc
        end
        "#,
    )?;

    Ok(())
}

#[test]
#[ignore = "leave disabled until either symbol resolution is rewritten or path semantics are refined"]
fn test_linking_recursive_expansion() -> TestResult {
    let context = TestContext::default();

    let a_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace a

        pub use {a} from b
        pub proc x
            push.1
        end
        "#
    ))?;

    let b_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {a} from a
        pub proc foo
            exec.a::x
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.assemble_library("lib", a_lib, [b_lib])?;

    Ok(())
}

#[test]
#[ignore = "leave disabled until either symbol resolution is rewritten or path semantics are refined"]
fn test_linking_recursive_expansion_via_renamed_aliases() -> TestResult {
    let context = TestContext::default();

    let a_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace a::a

        pub use {a2} from b
        pub proc x
            push.1
        end
        "#
    ))?;

    let b_lib = context.parse_module(source_file!(
        &context,
        r#"
        namespace b

        pub use {a as a2} from a
        pub proc foo
            exec.a2::x
        end
        "#
    ))?;

    let assembler = Assembler::new(context.source_manager());
    let _ = assembler.assemble_library("lib", a_lib, [b_lib])?;

    Ok(())
}

/// Parses a single-procedure module that uses a local (so codegen emits the frame-pointer
/// sequence), overrides the procedure's local count via the public AST API - bypassing the parser's
/// `@locals` cap - and assembles it into a library.
fn assemble_library_with_num_locals(
    context: &TestContext,
    num_locals: u16,
) -> Result<Box<Package>, Report> {
    let source = source_file!(
        &context,
        "  namespace test::repro
          @locals(1)
          pub proc foo
              loc_load.0
              drop
          end
          "
    );

    let mut module = context.parse_module(source)?;
    for proc in module.procedures_mut() {
        proc.set_num_locals(num_locals);
    }

    Assembler::new(context.source_manager()).assemble_library("test", module, None::<Box<Module>>)
}

#[test]
fn test_num_locals_above_max_is_rejected() {
    let context = TestContext::default();

    // Assembly must reject this gracefully (return Err), not overflow or panic.
    let err = assemble_library_with_num_locals(&context, 65535)
        .expect_err("assembling a procedure with 65535 locals should fail, not panic");
    assert_diagnostic!(&err, "number of procedure locals 65535 exceeds the maximum of 65532");
}

#[test]
fn test_num_locals_at_max_is_accepted() {
    let context = TestContext::default();

    // Assembly must succeed (return Ok) as long as the number of locals is up to the maximum.
    assemble_library_with_num_locals(&context, MAX_PROC_LOCALS)
        .expect("assembling a procedure with MAX_PROC_LOCALS should succeed");
}

#[test]
fn test_num_locals_one_above_max_is_rejected() {
    let context = TestContext::default();
    let err = assemble_library_with_num_locals(&context, MAX_PROC_LOCALS + 1)
        .expect_err("assembling a procedure with MAX_PROC_LOCALS + 1 should fail");
    assert_diagnostic!(&err, "number of procedure locals 65533 exceeds the maximum of 65532");
}

/// Regression test for the AST-producer path in issue #3331.
///
/// The `@locals(..)` grammar cannot attach locals to a `begin`..`end` block, so the parser can
/// never produce an entrypoint with locals. On the contrary, the AST API can, the entrypoint
/// compiles to an ordinary procedure reachable via `Module::procedures_mut`, and
/// `Procedure::set_num_locals` bypasses the parser entirely. An entrypoint with locals is an
/// unrecoverable producer bug, so the invariant is enforced at the mutation site and must panic
/// there.
#[test]
#[should_panic(expected = "program entrypoint cannot have locals")]
fn test_entrypoint_with_locals_via_setter_panics() {
    let context = TestContext::default();
    let source = source_file!(&context, "begin push.1 drop end");
    let mut program = context.parse_program(source).expect("failed to parse executable module");

    for proc in program.procedures_mut() {
        proc.set_num_locals(4);
    }
}

/// The assembler keeps its own assertion as a backstop for entrypoints constructed with locals
/// directly via `Procedure::new`, which bypasses the `set_num_locals` guard. This
/// mirrors how the semantic analyzer lowers a `begin`..`end` block into a `main` procedure, but
/// with a non-zero local count. See issue #3331.
#[test]
#[should_panic(expected = "program entrypoint cannot have locals")]
fn test_entrypoint_with_locals_via_constructor_panics() {
    let context = TestContext::default();

    let body = Block::new(
        SourceSpan::default(),
        Vec::from([Op::Inst(Span::unknown(Instruction::Assertz))]),
    );
    let main =
        Procedure::new(SourceSpan::default(), Visibility::Public, ProcedureName::main(), 4, body);

    let mut module = Module::new_executable();
    module
        .define_procedure(main, context.source_manager())
        .expect("failed to define entrypoint");

    let _ = Assembler::new(context.source_manager()).assemble_program("test", module);
}
