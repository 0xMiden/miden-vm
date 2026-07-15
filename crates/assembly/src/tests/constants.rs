// CONSTANTS
// ================================================================================================

use super::*;

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
