use alloc::{string::ToString, vec::Vec};

use miden_debug_types::{SourceSpan, Span};
use miden_utils_diagnostics::Report;
use pretty_assertions::assert_eq;

use crate::{
    Felt, PathBuf, assert_diagnostic, assert_diagnostic_lines,
    ast::{types::Type, *},
    parser::{IntValue, WordValue},
    regex, source_file,
    testing::SyntaxTestContext,
};

macro_rules! id {
    ($name:ident) => {
        Ident::new(stringify!($name)).unwrap()
    };

    ($name:ty) => {
        Ident::new(stringify!($name)).unwrap()
    };
}

macro_rules! path {
    ($path:literal) => {
        Span::unknown(PathBuf::new($path).expect("invalid path").into())
    };

    ($path:ident) => {
        Span::unknown(PathBuf::new(stringify!($path)).expect("invalid path").into())
    };

    ($path:ty) => {
        Span::unknown(PathBuf::new(stringify!($path)).expect("invalid path").into())
    };
}

macro_rules! inst {
    ($inst:ident($value:expr)) => {
        Op::Inst(Span::unknown(Instruction::$inst($value)))
    };

    ($inst:ident) => {
        Op::Inst(Span::unknown(Instruction::$inst))
    };
}

macro_rules! exec {
    ($name:ident) => {
        inst!(Exec(InvocationTarget::Symbol(
            stringify!($name).parse().expect("invalid procedure name")
        )))
    };

    ($name:path) => {{
        let path = stringify!($name).parse::<PathBuf>().expect("invalid procedure path");
        let path = path.into_boxed_path().into();

        inst!(Exec(InvocationTarget::Path(Span::unknown(path))))
    }};
}

#[allow(unused_macros)]
macro_rules! call {
    ($name:ident) => {
        inst!(Call(InvocationTarget::Symbol(stringify!($name).parse())))
    };

    ($name:path) => {{
        let path = stringify!($name).parse().expect("invalid procedure path");

        inst!(Call(InvocationTarget::Path(path)))
    }};
}

macro_rules! block {
    ($($insts:expr),+) => {
        Block::new(Default::default(), Vec::from([$($insts),*]))
    }
}

macro_rules! moduledoc {
    ($doc:literal) => {
        Form::ModuleDoc(Span::unknown($doc.to_string()))
    };

    ($doc:ident) => {
        Form::ModuleDoc(Span::unknown($doc.to_string()))
    };
}

macro_rules! doc {
    ($doc:literal) => {
        Form::Doc(Span::unknown($doc.to_string()))
    };

    ($doc:ident) => {
        Form::Doc(Span::unknown($doc.to_string()))
    };
}

macro_rules! begin {
    ($($insts:expr),+) => {
        Form::Begin(block!($($insts),*))
    }
}

macro_rules! if_true {
    ($then_blk:expr) => {
        Op::If {
            span: Default::default(),
            then_blk: $then_blk,
            else_blk: Block::default(),
        }
    };

    ($then_blk:expr, $else_blk:expr) => {
        Op::If {
            span: Default::default(),
            then_blk: $then_blk,
            else_blk: $else_blk,
        }
    };
}

macro_rules! while_true {
    ($body:expr) => {
        Op::While { span: Default::default(), body: $body }
    };
}

macro_rules! type_alias {
    ($alias:ident, $ty:expr) => {
        Form::Type(TypeAlias::new(Visibility::Private, id!($alias), $ty.into()))
    };

    ($alias:ty, $ty:expr) => {
        Form::Type(TypeAlias::new(Visibility::Private, id!($alias), $ty.into()))
    };
}

macro_rules! type_ref {
    ($path:literal) => {
        TypeExpr::Ref(path!($path))
    };

    ($alias:ident) => {
        TypeExpr::Ref(path!($alias))
    };

    ($alias:ty) => {
        TypeExpr::Ref(path!($alias))
    };
}

macro_rules! struct_ty {
    ($($field_name:ident : $field_ty:expr),+) => {
        TypeExpr::Struct(StructType::new([
            $(
                StructField {
                    span: SourceSpan::UNKNOWN,
                    name: id!($field_name),
                    ty: $field_ty.into(),
                }
            ),*
        ]))
    }
}

macro_rules! array_ty {
    ($element_ty:expr, $arity:literal) => {
        TypeExpr::Array(ArrayType::new($element_ty.into(), $arity))
    };
}

macro_rules! function_ty {
    ($($arg_ty:expr),* => $($result_ty:expr),*) => {
        FunctionType::new(types::CallConv::Fast, vec![$($arg_ty),*], vec![$($result_ty),*])
    }
}

macro_rules! enum_ty {
    ($name:ident, $ty:expr, $($variant:expr),+) => {
        Form::Enum(EnumType::new(Visibility::Private, id!($name), $ty.into(), [$($variant),*]))
    };

    ($name:ty, $ty:expr, $($variant:expr),+) => {
        Form::Enum(EnumType::new(Visibility::Private, id!($name), $ty.into(), [$($variant),*]))
    };
}

macro_rules! variant {
    ($name:ident, $discriminant:expr) => {
        Variant::new(id!($name), $discriminant.into())
    };
}

macro_rules! const_int {
    ($value:literal) => {
        ConstantExpr::Int(Span::unknown(IntValue::from($value)))
    };
}

macro_rules! const_ref {
    ($path:literal) => {
        ConstantExpr::Var(path!($path))
    };

    ($name:ident) => {
        ConstantExpr::Var(path!($name))
    };
}

macro_rules! const_mul {
    ($lhs:expr, $rhs:expr) => {
        ConstantExpr::BinaryOp {
            span: SourceSpan::UNKNOWN,
            op: ConstantOp::Mul,
            lhs: alloc::boxed::Box::new($lhs),
            rhs: alloc::boxed::Box::new($rhs),
        }
    };
}

macro_rules! const_add {
    ($lhs:expr, $rhs:expr) => {
        ConstantExpr::BinaryOp {
            span: SourceSpan::UNKNOWN,
            op: ConstantOp::Add,
            lhs: alloc::boxed::Box::new($lhs),
            rhs: alloc::boxed::Box::new($rhs),
        }
    };
}

macro_rules! import {
    ($name:literal) => {{
        let path = $name.parse::<PathBuf>().expect("invalid import path");
        let name = Ident::new(path.last().unwrap()).unwrap();
        Form::Alias(Alias::new(
            Visibility::Private,
            name,
            AliasTarget::Path(Span::unknown(path.into())),
        ))
    }};

    ($name:literal -> $alias:literal) => {
        let path = $name.parse::<PathBuf>().expect("invalid import path").into();
        let name = $alias.parse().expect("invalid import alias");
        Form::Alias(Alias::new(Visibility::Private, name, AliasTarget::Path(Span::unknown(path))))
    };
}

macro_rules! proc {
    ($name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(Procedure::new(
            Default::default(),
            Visibility::Private,
            stringify!($name).parse().expect("invalid procedure name"),
            $num_locals,
            $body,
        ))
    };

    ([$($attr:expr),*], $name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Private,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_attributes([$($attr),*]),
        )
    };

    ($docs:literal, $name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Private,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_docs(Some(Span::unknown($docs.to_string()))),
        )
    };

    ($docs:literal, [$($attr:expr),*], $name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Private,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_docs($docs)
            .with_attributes([$($attr),*]),
        )
    };
}

macro_rules! export {
    ($name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(Procedure::new(
            Default::default(),
            Visibility::Public,
            stringify!($name).parse().expect("invalid procedure name"),
            $num_locals,
            $body,
        ))
    };

    ($docs:expr, $name:ident, $num_locals:literal, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Public,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_docs(Some(Span::unknown($docs.to_string()))),
        )
    };
}

macro_rules! typed_export {
    ($name:ident, $num_locals:literal, $signature:expr, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Public,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_signature($signature),
        )
    };

    ($docs:expr, $name:ident, $num_locals:literal, $signature:expr, $body:expr) => {
        Form::Procedure(
            Procedure::new(
                Default::default(),
                Visibility::Public,
                stringify!($name).parse().expect("invalid procedure name"),
                $num_locals,
                $body,
            )
            .with_signature($signature)
            .with_docs(Some(Span::unknown($docs.to_string()))),
        )
    };
}

macro_rules! module {
    ($($forms:expr),+) => {
        Vec::<Form>::from([
            $(
                Form::from($forms),
            )*
        ])
    }
}

macro_rules! assert_forms {
    ($context:ident, $source:expr, $expected:expr) => {
        match $context.parse_forms($source.clone()) {
            Ok(forms) => assert_eq!(forms, $expected),
            Err(report) => {
                panic!(
                    "expected parsing to succeed but failed with error:
{}",
                    crate::diagnostics::reporting::PrintDiagnostic::new_without_color(report)
                );
            },
        }
    };
}

macro_rules! assert_parse_diagnostic {
    ($source:expr, $expected:literal) => {{
        let source = $source.clone();
        let error = crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic!(error, $expected);
    }};

    ($source:expr, $expected:expr) => {{
        let source = $source.clone();
        let error = crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic!(error, $expected);
    }};
}

macro_rules! assert_parse_diagnostic_lines {
    ($source:expr, $($expected:literal),+) => {{
        let error = crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($source:expr, $($expected:expr),+) => {{
        let source = $source.clone();
        let error = crate::parser::parse_forms(source.clone())
            .map_err(|err| Report::new(err).with_source_code(source))
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

macro_rules! assert_module_diagnostic_lines {
    ($context:ident, $source:expr, $($expected:literal),+) => {{
        let error = $context
            .parse_module($source)
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($context:ident, $source:expr, $($expected:expr),+) => {{
        let error = $context
            .parse_module($source)
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

#[allow(unused_macros)]
macro_rules! assert_program_diagnostic_lines {
    ($context:ident, $source:expr, $($expected:literal),+) => {{
        let error = $context
            .parse_program($source)
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};

    ($context:ident, $source:expr, $($expected:expr),+) => {{
        let error = $context
            .parse_program($source)
            .expect_err("expected diagnostic to be raised, but parsing succeeded");
        assert_diagnostic_lines!(error, $($expected),*);
    }};
}

// UNIT TESTS
// ================================================================================================

/// Tests the AST parsing
#[test]
fn test_ast_parsing_program_simple() -> Result<(), Report> {
    let context = SyntaxTestContext::new();

    let source = source_file!(&context, "begin push.0 assertz add.1 end");
    let forms = module!(begin!(
        inst!(Push(Immediate::Value(Span::unknown(IntValue::U8(0).into())))),
        inst!(Assertz),
        inst!(Incr)
    ));

    assert_eq!(context.parse_forms(source)?, forms);

    Ok(())
}

#[test]
fn test_ast_parsing_program_push() -> Result<(), Report> {
    let context = SyntaxTestContext::new();

    let source = source_file!(
        &context,
        r#"
    begin
        push.10 push.500 push.70000 push.5000000000
        push.5000000000.7000000000.9000000000.11000000000
        push.5.7
        push.500.700
        push.70000.90000
        push.5000000000.7000000000

        push.0x0000000000000000010000000000000002000000000000000300000000000000
    end"#
    );
    let forms = module!(begin!(
        inst!(Push(Immediate::Value(Span::unknown(10u8.into())))),
        inst!(Push(Immediate::Value(Span::unknown(500u16.into())))),
        inst!(Push(Immediate::Value(Span::unknown(70000u32.into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(5000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(5000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(7000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(9000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(11000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(5u8.into())))),
        inst!(Push(Immediate::Value(Span::unknown(7u8.into())))),
        inst!(Push(Immediate::Value(Span::unknown(500u16.into())))),
        inst!(Push(Immediate::Value(Span::unknown(700u16.into())))),
        inst!(Push(Immediate::Value(Span::unknown(70000u32.into())))),
        inst!(Push(Immediate::Value(Span::unknown(90000u32.into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(5000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(Felt::new(7000000000_u64).into())))),
        inst!(Push(Immediate::Value(Span::unknown(
            WordValue([Felt::new(0), Felt::new(1), Felt::new(2), Felt::new(3)]).into()
        ))))
    ));

    assert_eq!(context.parse_forms(source)?, forms);

    // Push a hexadecimal string containing more than 4 values
    let source_too_long = source_file!(
        &context,
        "begin push.0x00000000000000001000000000000000200000000000000030000000000000004000000000000000"
    );
    assert_parse_diagnostic!(source_too_long, "long hex strings must contain exactly 64 digits");

    // Push a hexadecimal string containing less than 4 values
    let source_too_long = source_file!(&context, "begin push.0x00000000000000001000000000000000");
    assert_parse_diagnostic!(source_too_long, "expected 2, 4, 8, 16, or 64 hex digits");

    Ok(())
}

#[test]
fn test_ast_parsing_program_u32() -> Result<(), Report> {
    let context = SyntaxTestContext::new();

    let source = source_file!(
        &context,
        r#"
    begin
        push.3

        u32wrapping_add.5
        u32overflowing_add.5

        u32wrapping_sub.1
        u32overflowing_sub.1

        u32wrapping_mul.2
        u32overflowing_mul.2

    end"#
    );
    let forms = module!(begin!(
        inst!(Push(Immediate::Value(Span::unknown(3u8.into())))),
        inst!(U32WrappingAddImm(5u32.into())),
        inst!(U32OverflowingAddImm(5u32.into())),
        inst!(U32WrappingSubImm(1u32.into())),
        inst!(U32OverflowingSubImm(1u32.into())),
        inst!(U32WrappingMulImm(2u32.into())),
        inst!(U32OverflowingMulImm(2u32.into()))
    ));

    assert_eq!(context.parse_forms(source)?, forms);

    Ok(())
}

#[test]
fn test_ast_parsing_program_proc() -> Result<(), Report> {
    let context = SyntaxTestContext::new();

    let source = source_file!(
        &context,
        r#"
    @locals(1)
    proc foo
        loc_load.0
    end
    @locals(2)
    proc bar
        padw
    end
    begin
        exec.foo
        exec.bar
    end"#
    );

    let forms = module!(
        proc!(foo, 1, block!(inst!(LocLoad(0u16.into())))),
        proc!(bar, 2, block!(inst!(PadW))),
        begin!(exec!(foo), exec!(bar))
    );
    assert_eq!(context.parse_forms(source)?, forms);

    Ok(())
}

#[test]
fn test_ast_parsing_module() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
    @locals(1)
    pub proc foo
        loc_load.0
    end"#
    );
    let forms = module!(export!(foo, 1, block!(inst!(LocLoad(0u16.into())))));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_adv_ops() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(&context, "begin adv_push.1 adv_loadw end");
    let forms = module!(begin!(inst!(AdvPush(1u8.into())), inst!(AdvLoadW)));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_adv_injection() -> Result<(), Report> {
    use super::SystemEventNode::*;

    let context = SyntaxTestContext::new();
    let source = source_file!(&context, "begin adv.push_mapval adv.insert_mem end");
    let forms = module!(begin!(inst!(SysEvent(PushMapVal)), inst!(SysEvent(InsertMem))));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_bitwise_counters() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(&context, "begin u32clz u32ctz u32clo u32cto end");
    let forms = module!(begin!(inst!(U32Clz), inst!(U32Ctz), inst!(U32Clo), inst!(U32Cto)));

    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_ilog2() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(&context, "begin push.8 ilog2 end");
    let forms =
        module!(begin!(inst!(Push(Immediate::Value(Span::unknown(8u8.into())))), inst!(ILog2)));

    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_use() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
    use miden::core::abc::foo
    begin
        exec.foo::bar
    end"#
    );
    let forms = module!(import!("miden::core::abc::foo"), begin!(exec!(foo::bar)));
    assert_eq!(context.parse_forms(source)?, forms);
    // TODO: Assert fully-resolved name is `std::abc::foo::bar`
    Ok(())
}

#[test]
fn test_ast_parsing_module_nested_if() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
    proc foo
        push.1
        if.true
            push.0
            push.1
            if.true
                push.0
                sub
            else
                push.1
                sub
            end
        end
    end"#
    );

    let forms = module!(proc!(
        foo,
        0,
        block!(
            inst!(Push(Immediate::Value(Span::unknown(1u8.into())))),
            if_true!(
                block!(
                    inst!(Push(Immediate::Value(Span::unknown(0u8.into())))),
                    inst!(Push(Immediate::Value(Span::unknown(1u8.into())))),
                    if_true!(
                        block!(
                            inst!(Push(Immediate::Value(Span::unknown(0u8.into())))),
                            inst!(Sub)
                        ),
                        block!(
                            inst!(Push(Immediate::Value(Span::unknown(1u8.into())))),
                            inst!(Sub)
                        )
                    )
                ),
                block!(inst!(Nop))
            )
        )
    ));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_module_sequential_if() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
    proc foo
        push.1
        if.true
            push.5
            push.1
        end
        if.true
            push.0
            sub
        else
            push.1
            sub
        end
    end"#
    );

    let forms = module!(proc!(
        foo,
        0,
        block!(
            inst!(Push(Immediate::Value(Span::unknown(1u8.into())))),
            if_true!(
                block!(
                    inst!(Push(Immediate::Value(Span::unknown(5u8.into())))),
                    inst!(Push(Immediate::Value(Span::unknown(1u8.into()))))
                ),
                block!(inst!(Nop))
            ),
            if_true!(
                block!(inst!(Push(Immediate::Value(Span::unknown(0u8.into())))), inst!(Sub)),
                block!(inst!(Push(Immediate::Value(Span::unknown(1u8.into())))), inst!(Sub))
            )
        )
    ));

    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_while_if_body() {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        "\
    begin
        push.1
        while.true
            mul
        end
        add
        if.true
            div
        end
        mul
    end
    "
    );

    let forms = module!(begin!(
        inst!(Push(Immediate::Value(Span::unknown(1u8.into())))),
        while_true!(block!(inst!(Mul))),
        inst!(Add),
        if_true!(block!(inst!(Div)), block!(inst!(Nop))),
        inst!(Mul)
    ));

    assert_forms!(context, source, forms);
}

#[test]
fn test_ast_parsing_attributes() -> Result<(), Report> {
    let context = SyntaxTestContext::new();

    let source = source_file!(
        &context,
        r#"
    # Simple marker attribute
    @inline
    @locals(1)
    proc foo
        loc_load.0
    end

    # List attribute
    @inline(always)
    @locals(2)
    proc bar
        padw
    end

    # Key value attributes of various kinds
    @numbers(decimal = 1, hex = 0xdeadbeef)
    @props(name = baz)
    @props(string = "not a valid quoted identifier")
    @locals(2)
    proc baz
        padw
    end

    begin
        exec.foo
        exec.bar
        exec.baz
    end"#
    );

    let inline = Attribute::Marker(id!(inline));
    let inline_always = Attribute::List(MetaList::new(id!(inline), [MetaExpr::Ident(id!(always))]));
    let numbers = Attribute::new(
        id!(numbers),
        [(id!(decimal), MetaExpr::from(1u8)), (id!(hex), MetaExpr::from(0xdeadbeefu32))],
    );
    let props = Attribute::new(
        id!(props),
        [
            (id!(name), MetaExpr::from(id!(baz))),
            (id!(string), MetaExpr::from("not a valid quoted identifier")),
        ],
    );

    let forms = module!(
        proc!([inline], foo, 1, block!(inst!(LocLoad(0u16.into())))),
        proc!([inline_always], bar, 2, block!(inst!(PadW))),
        proc!([numbers, props], baz, 2, block!(inst!(PadW))),
        begin!(exec!(foo), exec!(bar), exec!(baz))
    );
    assert_eq!(context.parse_forms(source)?, forms);

    Ok(())
}

// INVALID BODY TESTS
// ================================================================================================

#[test]
fn test_use_in_proc_body() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        r#"
    @locals(1)
    pub proc foo
        loc_load.0
        use
    end"#
    );

    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:5:9\]"#),
        "4 |         loc_load.0",
        "5 |         use",
        " :         ^|^",
        "  :          `-- found a use here",
        "6 |     end",
        "  `----",
        r#" help: expected primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn test_unterminated_proc() {
    let context = SyntaxTestContext::default();
    let source = source_file!(&context, "proc foo add mul begin push.1 end");

    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:1:18\]"#),
        "1 | proc foo add mul begin push.1 end",
        "  :                  ^^|^^",
        "  :                    `-- found a begin here",
        "  `----",
        r#" help: expected ".", or primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn test_unterminated_if() {
    let context = SyntaxTestContext::default();
    let source = source_file!(&context, "proc foo add mul if.true add.2 begin push.1 end");

    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:1:32\]"#),
        "1 | proc foo add mul if.true add.2 begin push.1 end",
        "  :                                ^^|^^",
        "  :                                  `-- found a begin here",
        "  `----",
        r#" help: expected primitive opcode (e.g. "add"), or "else", or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn test_invalid_mapvaln_pad() {
    let context = SyntaxTestContext::default();
    let source = source_file!(&context, "begin adv.push_mapvaln.3 end");

    assert_parse_diagnostic_lines!(
        source,
        "invalid padding value for the `adv.push_mapvaln` instruction: 3",
        regex!(r#",-\[test[\d]+:1:24\]"#),
        "1 | begin adv.push_mapvaln.3 end",
        "  :                        ^",
        "  `----",
        " help: valid padding values are 0, 4, and 8"
    );
}

// DOCUMENTATION PARSING TESTS
// ================================================================================================

#[test]
fn test_ast_parsing_simple_docs() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
    #! proc doc
    @locals(1)
    pub proc foo
        loc_load.0
    end"#
    );

    let forms = module!(doc!("proc doc\n"), export!(foo, 1, block!(inst!(LocLoad(0u16.into())))));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_ast_parsing_module_docs_valid() {
    let context = SyntaxTestContext::new();

    let source = source_file!(
        &context,
        "\
#! Test documentation for the whole module in parsing test. Lorem ipsum dolor sit amet,
#! consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
#!
#! This comment is intentionally longer than 256 characters, since we need to be sure that the size
#! of the comments is correctly parsed. There was a bug here earlier.


#! Test documentation for export procedure foo in parsing test. Lorem ipsum dolor sit amet,
#! consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.
#! This comment is intentionally longer than 256 characters, since we need to be sure that the size
#! of the comments is correctly parsed. There was a bug here earlier.
@locals(1)
pub proc foo
    loc_load.0
end

#! Test documentation for internal procedure bar in parsing test. Lorem ipsum dolor sit amet,
#! consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
#! aliqua.
@locals(2)
proc bar
    padw
end

#! Test documentation for export procedure baz in parsing test. Lorem ipsum dolor sit amet,
#! consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
#! aliqua.
@locals(3)
pub proc baz
    padw
    push.0
end"
    );

    const MODULE_DOC: &str = "Test documentation for the whole module in parsing test. \
    Lorem ipsum dolor sit amet,\n\
    consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\
    \n\n\
    This comment is intentionally longer than 256 characters, since we need to be sure that the size\n\
    of the comments is correctly parsed. There was a bug here earlier.\n";

    const FOO_DOC: &str = "Test documentation for export procedure foo in parsing test. \
    Lorem ipsum dolor sit amet,\n\
    consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n\
    This comment is intentionally longer than 256 characters, since we need to be sure that the size\n\
    of the comments is correctly parsed. There was a bug here earlier.\n";

    const BAR_DOC: &str = "Test documentation for internal procedure bar in parsing test. Lorem ipsum dolor sit amet,\n\
    consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna\n\
    aliqua.\n";

    const BAZ_DOC: &str = "Test documentation for export procedure baz in parsing test. Lorem ipsum dolor sit amet,\n\
    consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna\n\
    aliqua.\n";

    let expected_forms = module!(
        moduledoc!(MODULE_DOC),
        doc!(FOO_DOC),
        export!(foo, 1, block!(inst!(LocLoad(0u16.into())))),
        doc!(BAR_DOC),
        proc!(bar, 2, block!(inst!(PadW))),
        doc!(BAZ_DOC),
        export!(
            baz,
            3,
            block!(inst!(PadW), inst!(Push(Immediate::Value(Span::unknown(0u8.into())))))
        )
    );

    let actual_forms = context.parse_forms(source.clone()).unwrap();
    assert_eq!(actual_forms, expected_forms);

    let module = context.parse_module(source).unwrap();
    assert_eq!(module.docs(), Some(Span::unknown(MODULE_DOC)));
    let baz = "baz".parse().unwrap();
    let baz_idx = module.index_of_name(&baz).expect("could not find baz");
    let baz_docs = module.get(baz_idx).unwrap().docs();
    assert_eq!(baz_docs, Some(BAZ_DOC));
}

#[test]
fn test_ast_parsing_module_docs_fail() {
    let context = SyntaxTestContext::new().with_warnings_as_errors(true);
    let source = source_file!(
        &context,
        "\
    #! module doc

    #! proc doc
    @locals(1)
    pub proc foo
        loc_load.0
    end

    #! malformed doc
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "Warning:   ! unused docstring",
        regex!(r#",-\[test[\d]+:9:5\]"#),
        " 8 |",
        " 9 |     #! malformed doc",
        "   :     ^^^^^^^^^^^^^^^^^",
        "10 |",
        "   `----",
        "help: this docstring is immediately followed by at least one empty line, then another docstring,if you intended these to be a single docstring, you should remove the empty lines"
    );

    let source = source_file!(
        &context,
        "\
    #! proc doc
    @locals(1)
    pub proc foo
        loc_load.0
    end

    #! malformed doc
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "Warning:   ! unused docstring",
        regex!(r#",-\[test[\d]+:7:5\]"#),
        "6 |",
        "7 |     #! malformed doc",
        "  :     ^^^^^^^^^^^^^^^^^",
        "8 |",
        "  `----",
        "help: this docstring is immediately followed by at least one empty line, then another docstring,if you intended these to be a single docstring, you should remove the empty lines"
    );

    let source = source_file!(
        &context,
        "\
    #! module doc

    #! malformed doc
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "Warning:   ! unused docstring",
        regex!(r#",-\[test[\d]+:3:5\]"#),
        "2 |",
        "3 |     #! malformed doc",
        "  :     ^^^^^^^^^^^^^^^^^",
        "4 |",
        "  `----",
        "help: this docstring is immediately followed by at least one empty line, then another docstring,if you intended these to be a single docstring, you should remove the empty lines"
    );

    let source = source_file!(
        &context,
        "\
    @locals(1)
    pub proc foo
        loc_load.0
    end

    #! malformed doc
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "Warning:   ! unused docstring",
        regex!(r#",-\[test[\d]+:6:5\]"#),
        "5 |",
        "6 |     #! malformed doc",
        "  :     ^^^^^^^^^^^^^^^^^",
        "7 |",
        "  `----",
        "help: this docstring is immediately followed by at least one empty line, then another docstring,if you intended these to be a single docstring, you should remove the empty lines"
    );

    let source = source_file!(
        &context,
        "\
    #! module doc

    @locals(1)
    pub proc foo
        loc_load.0
    end

    #! malformed doc
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "syntax error",
        "help: see emitted diagnostics for details",
        "Warning:   ! unused docstring",
        regex!(r#",-\[test[\d]+:8:5\]"#),
        "7 |",
        "8 |     #! malformed doc",
        "  :     ^^^^^^^^^^^^^^^^^",
        "9 |",
        "  `----",
        "help: this docstring is immediately followed by at least one empty line, then another docstring,if you intended these to be a single docstring, you should remove the empty lines"
    );

    let source = source_file!(
        &context,
        "\
    #! proc doc
    @locals(1)
    pub proc foo
        #! malformed doc
        loc_load.0
    end
    "
    );
    assert_module_diagnostic_lines!(
        context,
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:4:9\]"#),
        "3 |     pub proc foo",
        "4 |         #! malformed doc",
        "  :         ^^^^^^^^|^^^^^^^^",
        "  :                 `-- found a doc comment here",
        "5 |         loc_load.0",
        "6 |     end",
        "  `----",
        r#" help: expected "(", or primitive opcode (e.g. "add"), or control flow opcode (e.g. "if.true")"#
    );
}

// BEGIN
// ================================================================================================

#[test]
fn assert_parsing_line_unmatched_begin() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        "\
        begin
          push.1.2

        add
        mul"
    );
    assert_parse_diagnostic_lines!(
        source,
        "unexpected end of file",
        regex!(r#",-\[test[\d]+:5:12\]"#),
        "4 |         add",
        "5 |         mul",
        "  `----",
        r#"help: expected ".", or primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn assert_parsing_line_extra_param() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        "\
        begin
          add.1.2
        end"
    );
    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:2:16\]"#),
        "1 | begin",
        "2 |           add.1.2",
        "  :                |",
        "  :                `-- found a . here",
        "3 |         end",
        "  `----",
        r#" help: expected primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn assert_parsing_line_invalid_op() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        "\
    begin
        repeat.3
            push.1
            push.0.1
        end

        # some comments

        if.true
            and
            loc_store.0
        else
            padw
        end

        # more comments
        # to test if line is correct

        while.true
            push.5.7
            u32wrapping_add
            loc_store.4
            push.0
        end

        repeat.3
            push.2
            u32overflowing_mulx
        end

    end"
    );
    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:28:13\]"#),
        "27 |             push.2",
        "28 |             u32overflowing_mulx",
        "   :             ^^^^^^^^^|^^^^^^^^^",
        "   :                      `-- found a identifier here",
        "29 |         end",
        "   `----",
        r#" help: expected ".", or primitive opcode (e.g. "add"), or "end", or control flow opcode (e.g. "if.true")"#
    );
}

#[test]
fn assert_parsing_line_unexpected_token() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        "\
    proc foo
      add
    end

    mul"
    );
    assert_parse_diagnostic_lines!(
        source,
        "invalid syntax",
        regex!(r#",-\[test[\d]+:5:5\]"#),
        "4 |",
        "5 |     mul",
        "  :     ^|^",
        "  :      `-- found a mul here",
        "  `----",
        r#" help: expected "@", or "adv_map", or "begin", or "const", or "enum", or "proc", or "pub", or "type", or "use", or end of file, or doc comment"#
    );
}

/// This test evaluates that we get the expected formatted Miden Assembly output when parsing some
/// Miden Assembly source code into the AST, and then formatting the AST.
///
/// NOTE: Due to current limitations of the parser, round-tripping is currently somewhat lossy:
///
/// - Line comments (i.e. not docstrings) are not preserved, and so do not end up in the output
/// - The original choice to place a sequence of instructions on the same line or multiple lines is
///   not preserved in the AST, so the formatter always places them on individual lines.
/// - References to constant values by name are replaced with their value during semantic analysis,
///   so no named constants appear in the formatted output.
/// - Constant declarations are not preserved by the parser, and so are not shown in the output
#[test]
fn test_roundtrip_formatting() {
    let source = "\
#! module doc
#!
#! with spaces

#! constant doc
#!
#! with spaces
const DEFAULT_CONST = 100

#! Perform `a + b`, `n` times
#!
#! with spaces
proc add_n_times # [n, b, a]
    dup.0
    push.0
    u32gt
    if.true
        push.0.1
        while.true  # [total, n, b, a]
            dup.3 dup.3
            u32wrapping_add3 # [total', n, b, a]
            swap.1
            push.1
            u32overflowing_sub  # [overflowed, n - 1, total', b, a]
            swap.1 movdn.3      # [overflowed, total', n', b, a]
            push.0              # [0, overflowed, total, n', total', b, a]
            dup.1               # [overflowed, 0, overflowed, total', n', b, a]
            cdrop               # [continue, total', n', b, a]
        end
        movdn.3
        drop drop drop
    else
        u32wrapping_add
    end
end

begin
    push.1.1.DEFAULT_CONST
    exec.add_n_times
    push.20
    assert_eq

    trace.DEFAULT_CONST
end
";

    let context = SyntaxTestContext::default();
    let source = source_file!(&context, source);

    let module =
        Module::parse(Path::exec_path(), ModuleKind::Executable, source, context.source_manager())
            .unwrap_or_else(|err| panic!("{err}"));

    let formatted = module.to_string();
    let expected = "\
#! module doc
#!
#! with spaces

#! constant doc
#!
#! with spaces
const DEFAULT_CONST = 100

#! Perform `a + b`, `n` times
#!
#! with spaces
proc add_n_times
    dup.0
    push.0
    u32gt
    if.true
        push.0
        push.1
        while.true
            dup.3
            dup.3
            u32wrapping_add3
            swap.1
            push.1
            u32overflowing_sub
            swap.1
            movdn.3
            push.0
            dup.1
            cdrop
        end
        movdn.3
        drop
        drop
        drop
    else
        u32wrapping_add
    end
end

begin
    push.1
    push.1
    push.100
    exec.add_n_times
    push.20
    assert_eq
    trace.100
end
";

    assert_eq!(&formatted, expected);
}

#[test]
fn test_words_roundtrip_formatting() {
    let source = "\
const A = 0x0200000000000000030000000000000004000000000000000500000000000000
const B = [2,3,4,5]
begin
    push.0x0200000000000000030000000000000004000000000000000500000000000000
    push.A.6
    push.B.6
    push.2.3.4.5
    push.A.B
end
";

    let context = SyntaxTestContext::default();
    let source = source_file!(&context, source);

    let module =
        Module::parse(Path::exec_path(), ModuleKind::Executable, source, context.source_manager())
            .unwrap();

    let formatted = module.to_string();
    let expected = "\
const A = [2,3,4,5]

const B = [2,3,4,5]

begin
    push.[2,3,4,5]
    push.[2,3,4,5]
    push.6
    push.[2,3,4,5]
    push.6
    push.2
    push.3
    push.4
    push.5
    push.[2,3,4,5]
    push.[2,3,4,5]
end
";

    assert_eq!(&formatted, expected);
}

#[test]
fn cannot_mem_store_word() {
    let context = SyntaxTestContext::default();
    let source = source_file!(
        &context,
        r#"
const A = [2,3,4,5]
begin
    mem_store.A
end"#
    );

    // Instead of the usual macro that does only parsing we need to use this
    // parse function that also performs the semantic analysis to realize that
    // the constant is of the wrong type.
    let error =
        Module::parse(Path::exec_path(), ModuleKind::Executable, source, context.source_manager())
            .expect_err("expected diagnostic to be raised, but parsing succeeded");

    assert_diagnostic_lines!(
        error,
        "syntax error",
        "help: see emitted diagnostics for details",
        "invalid constant",
        regex!(r#",-\[test[\d]+:4:15\]"#),
        "3 | begin",
        "4 |     mem_store.A",
        "  :               |",
        "  :               `-- expected u32",
        "5 | end",
        "  `----",
        r#" help: this constant does not resolve to a value of the right type"#
    );
}

// TYPES
// ================================================================================================

#[test]
fn test_type_declarations() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
type t = felt
type Int8 = u8
type Int64 = struct { hi: u32, lo: u32 }
type Int128 = struct { hi: Int64, lo: Int64 }
type Hash = [u8; 32]
"#
    );

    let forms = module!(
        type_alias!(t, Type::Felt),
        type_alias!(Int8, Type::U8),
        type_alias!(Int64, struct_ty!(hi: Type::U32, lo: Type::U32)),
        type_alias!(Int128, struct_ty!(hi: type_ref!(Int64), lo: type_ref!(Int64))),
        type_alias!(Hash, array_ty!(Type::U8, 32))
    );
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_enum_declarations() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
enum Tag : u8 {
    A,
    B = 2,
    C = B * 2,
    D,
}
"#
    );

    let forms = module!(enum_ty!(
        Tag,
        Type::U8,
        variant!(A, const_int!(0u8)),
        variant!(B, const_int!(2u8)),
        variant!(C, const_mul!(const_ref!(B), const_int!(2u8))),
        variant!(D, const_add!(const_ref!(C), const_int!(1u8)))
    ));
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}

#[test]
fn test_type_signatures() -> Result<(), Report> {
    let context = SyntaxTestContext::new();
    let source = source_file!(
        &context,
        r#"
use miden::core::math::u64

type Int64 = struct { hi: u32, lo: u32 }

pub proc mul(a: Int64, b: Int64) -> Int64
    exec.u64::wrapping_mul
end

enum Bool : i1 {
    FALSE,
    TRUE,
}

pub proc is_number(a: Int64) -> Bool
    push.TRUE
end
"#
    );

    let forms = module!(
        import!("miden::core::math::u64"),
        type_alias!(Int64, struct_ty!(hi: Type::U32, lo: Type::U32)),
        typed_export!(
            mul,
            0,
            function_ty!(type_ref!(Int64), type_ref!(Int64) => type_ref!(Int64)),
            block!(exec!(u64::wrapping_mul))
        ),
        enum_ty!(
            Bool,
            Type::I1,
            variant!(FALSE, const_int!(0u8)),
            variant!(TRUE, const_add!(const_ref!(FALSE), const_int!(1u8)))
        ),
        typed_export!(
            is_number,
            0,
            function_ty!(type_ref!(Int64) => type_ref!(Bool)),
            block!(inst!(Push(Immediate::Constant(id!(TRUE)))))
        )
    );
    assert_eq!(context.parse_forms(source)?, forms);
    Ok(())
}
