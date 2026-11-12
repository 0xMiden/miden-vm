use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::ops::ControlFlow;

use miden_core::events::EventId;
use miden_debug_types::{SourceId, SourceSpan, Span, Spanned};

use super::*;
use crate::{
    Felt, Path,
    ast::{Visit, VisitMut, types::Type},
    parser::{IntValue, WordValue},
    prettier::PrettyPrint,
};

fn int() -> ConstantExpr {
    ConstantExpr::Int(Span::unknown(IntValue::U8(42)))
}

fn event_named(name: &str) -> ConstantExpr {
    let name = Ident::from_raw_parts(Span::unknown(name.into()));
    ConstantExpr::Hash(HashKind::Event, name)
}

fn string() -> ConstantExpr {
    ConstantExpr::String(Ident::new("message").unwrap())
}

fn reference() -> ConstantExpr {
    ConstantExpr::Var(Span::unknown(Arc::from(Path::new("OTHER"))))
}

fn u8_ty() -> TypeExpr {
    TypeExpr::Primitive(Span::unknown(Type::U8))
}

fn declaration_span() -> SourceSpan {
    SourceSpan::new(SourceId::from(0), 10u32..30u32)
}

fn constant_decl_fixture(value: ConstantExpr, ty: Option<TypeExpr>) -> ConstantDecl {
    let name = Ident::new("VALUE").unwrap();
    match ty {
        Some(ty) => {
            ConstantDecl::new_with_ty(declaration_span(), Visibility::Public, name, value, ty)
        },
        None => ConstantDecl::new(declaration_span(), Visibility::Public, name, value),
    }
}

/// Records type and initializer visits to test traversal order and early exit behavior for both
/// `Visit` and `VisitMut`.
#[derive(Default)]
struct ConstantVisitor {
    /// Ordered visit events recorded by the visitor.
    visited: Vec<&'static str>,
    /// Whether visiting a type reference should stop traversal.
    break_on_type: bool,
}

impl ConstantVisitor {
    fn record_type(&mut self) -> ControlFlow<()> {
        self.visited.push("type");
        if self.break_on_type {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    fn record_initializer(&mut self) -> ControlFlow<()> {
        self.visited.push("initializer");
        ControlFlow::Continue(())
    }
}

impl Visit for ConstantVisitor {
    fn visit_type_ref(&mut self, _path: &Span<Arc<Path>>) -> ControlFlow<()> {
        self.record_type()
    }

    fn visit_constant_ref(&mut self, _path: &Span<Arc<Path>>) -> ControlFlow<()> {
        self.record_initializer()
    }
}

impl VisitMut for ConstantVisitor {
    fn visit_mut_type_ref(&mut self, _path: &mut Span<Arc<Path>>) -> ControlFlow<()> {
        self.record_type()
    }

    fn visit_mut_constant_ref(&mut self, _path: &mut Span<Arc<Path>>) -> ControlFlow<()> {
        self.record_initializer()
    }
}

fn foreign_type() -> TypeExpr {
    TypeExpr::Ref(Span::unknown(Arc::from(Path::new("ForeignType"))))
}

#[test]
fn constant_annotation_is_visited_before_initializer() {
    let constant = constant_decl_fixture(reference(), Some(foreign_type()));
    let mut visitor = ConstantVisitor::default();

    assert_eq!(visitor.visit_constant(&constant), ControlFlow::Continue(()));
    assert_eq!(visitor.visited, vec!["type", "initializer"]);
}

#[test]
fn constant_annotation_is_visited_before_initializer_mut() {
    let mut constant = constant_decl_fixture(reference(), Some(foreign_type()));
    let mut visitor = ConstantVisitor::default();

    assert_eq!(visitor.visit_mut_constant(&mut constant), ControlFlow::Continue(()));
    assert_eq!(visitor.visited, vec!["type", "initializer"]);
}

/// Checks that immutable traversal propagates an annotation break without visiting the initializer.
#[test]
fn constant_annotation_break_skips_initializer() {
    let constant = constant_decl_fixture(reference(), Some(foreign_type()));
    let mut visitor = ConstantVisitor {
        break_on_type: true,
        ..Default::default()
    };

    assert_eq!(visitor.visit_constant(&constant), ControlFlow::Break(()));
    assert_eq!(visitor.visited, vec!["type"]);
}

/// Checks that mutable traversal propagates an annotation break without visiting the initializer.
#[test]
fn constant_annotation_break_skips_initializer_mut() {
    let mut constant = constant_decl_fixture(reference(), Some(foreign_type()));
    let mut visitor = ConstantVisitor {
        break_on_type: true,
        ..Default::default()
    };

    assert_eq!(visitor.visit_mut_constant(&mut constant), ControlFlow::Break(()));
    assert_eq!(visitor.visited, vec!["type"]);
}

#[test]
fn unannotated_constant_initializer_is_visited() {
    let constant = constant_decl_fixture(reference(), None);
    let mut visitor = ConstantVisitor::default();

    assert_eq!(visitor.visit_constant(&constant), ControlFlow::Continue(()));
    assert_eq!(visitor.visited, vec!["initializer"]);
}

#[test]
fn unannotated_constant_initializer_is_visited_mut() {
    let mut constant = constant_decl_fixture(reference(), None);
    let mut visitor = ConstantVisitor::default();

    assert_eq!(visitor.visit_mut_constant(&mut constant), ControlFlow::Continue(()));
    assert_eq!(visitor.visited, vec!["initializer"]);
}

/// An expression and its expected kind with either annotation state.
struct ExpressionCase {
    /// Expression under test.
    value: ConstantExpr,
    /// Kind without a type annotation.
    untyped_kind: ConstantKind,
    /// Kind with a type annotation.
    typed_kind: ConstantKind,
}

fn expression_cases() -> [ExpressionCase; 7] {
    [
        ExpressionCase {
            value: event_named("test::event"),
            untyped_kind: ConstantKind::Event,
            typed_kind: ConstantKind::Event,
        },
        ExpressionCase {
            value: int(),
            untyped_kind: ConstantKind::Untyped,
            typed_kind: ConstantKind::Typed,
        },
        ExpressionCase {
            value: string(),
            untyped_kind: ConstantKind::String,
            typed_kind: ConstantKind::String,
        },
        ExpressionCase {
            value: reference(),
            untyped_kind: ConstantKind::Untyped,
            typed_kind: ConstantKind::Typed,
        },
        ExpressionCase {
            value: ConstantExpr::Word(Span::unknown(WordValue(
                [1, 2, 3, 4].map(|value| Felt::new(value).unwrap()),
            ))),
            untyped_kind: ConstantKind::Untyped,
            typed_kind: ConstantKind::Typed,
        },
        ExpressionCase {
            value: ConstantExpr::Hash(
                HashKind::Word,
                Ident::from_raw_parts(Span::unknown("test::word".into())),
            ),
            untyped_kind: ConstantKind::Untyped,
            typed_kind: ConstantKind::Typed,
        },
        ExpressionCase {
            value: ConstantExpr::BinaryOp {
                span: declaration_span(),
                op: ConstantOp::Add,
                lhs: Box::new(int()),
                rhs: Box::new(reference()),
            },
            untyped_kind: ConstantKind::Untyped,
            typed_kind: ConstantKind::Typed,
        },
    ]
}

fn declarations() -> [ConstantDecl; 4] {
    [
        constant_decl_fixture(int(), None),
        constant_decl_fixture(int(), Some(u8_ty())),
        constant_decl_fixture(event_named("test::event"), None),
        constant_decl_fixture(string(), None),
    ]
    .map(|constant| constant.with_docs(Some(Span::unknown(String::from("Constant docs")))))
}

#[test]
fn kind_follows_expression_without_annotation() {
    for ExpressionCase { value, untyped_kind, .. } in expression_cases() {
        let constant = constant_decl_fixture(value, None);
        assert_eq!(constant.kind(), untyped_kind);
        assert_eq!(constant.ty(), None);
    }
}

#[test]
fn kind_follows_expression_with_annotation() {
    let ty = u8_ty();
    for ExpressionCase { value, typed_kind, .. } in expression_cases() {
        let constant = constant_decl_fixture(value, Some(ty.clone()));
        assert_eq!(constant.kind(), typed_kind);
        assert_eq!(constant.ty(), Some(&ty));
    }
}

#[test]
fn event_id_requires_event_expression() {
    for ty in [None, Some(u8_ty())] {
        for ExpressionCase { value, untyped_kind, .. } in expression_cases() {
            let constant = constant_decl_fixture(value, ty.clone());
            let expected =
                (untyped_kind == ConstantKind::Event).then(|| EventId::from_name("test::event"));
            assert_eq!(constant.event_id(), expected);
        }
    }
}

fn assert_kind_and_event_id_follow_value_mutation(ty: Option<TypeExpr>) {
    let has_type_annotation = ty.is_some();
    for through_definition in [false, true] {
        let mut constant = constant_decl_fixture(reference(), ty.clone())
            .with_docs(Some(Span::unknown(String::from("Constant docs"))));
        let initial_kind = if has_type_annotation {
            ConstantKind::Typed
        } else {
            ConstantKind::Untyped
        };
        assert_eq!(constant.kind(), initial_kind);
        assert_eq!(constant.event_id(), None);

        for ExpressionCase { value, untyped_kind, typed_kind } in expression_cases() {
            let value_mut = if through_definition {
                constant.definition_mut().value_mut()
            } else {
                constant.value_mut()
            };
            *value_mut = value.clone();

            let expected_kind = if has_type_annotation { typed_kind } else { untyped_kind };
            assert_eq!(constant.kind(), expected_kind);
            assert_eq!(
                constant.event_id(),
                (untyped_kind == ConstantKind::Event).then(|| EventId::from_name("test::event")),
            );
            assert_eq!(constant.value(), &value);
            assert_eq!(constant.ty(), ty.as_ref());
            assert_eq!(constant.span(), declaration_span());
            assert_eq!(constant.name().as_str(), "VALUE");
            assert_eq!(constant.visibility(), Visibility::Public);
            assert_eq!(constant.docs().unwrap().into_inner(), "Constant docs");
        }
    }
}

#[test]
fn untyped_kind_and_event_id_follow_value_mutation() {
    assert_kind_and_event_id_follow_value_mutation(None);
}

#[test]
fn typed_kind_and_event_id_follow_value_mutation() {
    assert_kind_and_event_id_follow_value_mutation(Some(u8_ty()));
}

#[test]
fn event_id_follows_event_name_mutation() {
    for ty in [None, Some(u8_ty())] {
        for through_definition in [false, true] {
            let mut constant = constant_decl_fixture(event_named("test::event"), ty.clone());
            assert_eq!(constant.kind(), ConstantKind::Event);
            assert_eq!(constant.event_id(), Some(EventId::from_name("test::event")));

            let value_mut = if through_definition {
                constant.definition_mut().value_mut()
            } else {
                constant.value_mut()
            };
            *value_mut = event_named("test::renamed_event");

            assert_eq!(constant.kind(), ConstantKind::Event);
            assert_eq!(constant.event_id(), Some(EventId::from_name("test::renamed_event")));
            assert_eq!(constant.value(), &event_named("test::renamed_event"));
        }
    }
}

#[test]
fn definition_conversion_preserves_metadata() {
    for ExpressionCase { value, untyped_kind, .. } in expression_cases() {
        let definition = ConstantDefinition::new(
            declaration_span(),
            Visibility::Public,
            Ident::new("VALUE").unwrap(),
            value,
        )
        .with_docs(Some(Span::unknown(String::from("Constant docs"))));
        let constant = ConstantDecl::from(definition.clone());

        assert_eq!(constant.definition(), &definition);
        assert_eq!(constant.kind(), untyped_kind);
        assert_eq!(constant.ty(), None);
        assert_eq!(constant.span(), declaration_span());
        assert_eq!(constant.docs().unwrap().into_inner(), "Constant docs");
    }
}

#[test]
fn declarations_expose_definition_and_render_correctly() {
    for constant in declarations() {
        let definition = constant.definition();
        assert_eq!(constant.name().as_str(), "VALUE");
        assert_eq!(constant.visibility(), Visibility::Public);
        assert_eq!(constant.span(), declaration_span());
        assert_eq!(constant.span(), definition.span());
        assert_eq!(constant.docs().unwrap().into_inner(), "Constant docs");
        assert_eq!(constant.value(), definition.value());

        let (expected, annotated) = match constant.kind() {
            ConstantKind::Untyped => ("#! Constant docs\npub const VALUE = 42\n", false),
            ConstantKind::Typed => ("#! Constant docs\npub const VALUE: u8 = 42\n", true),
            ConstantKind::Event => {
                ("#! Constant docs\npub const VALUE = event(\"test::event\")\n", false)
            },
            ConstantKind::String => ("#! Constant docs\npub const VALUE = \"message\"\n", false),
        };
        assert_eq!(constant.ty().is_some(), annotated);
        assert_eq!(constant.to_pretty_string(), expected);
    }
}

#[test]
fn event_and_string_annotations_render_correctly() {
    for (value, expected) in [
        (event_named("test::event"), "pub const VALUE: u8 = event(\"test::event\")\n"),
        (string(), "pub const VALUE: u8 = \"message\"\n"),
    ] {
        assert_eq!(constant_decl_fixture(value, Some(u8_ty())).to_pretty_string(), expected);
    }
}

#[test]
fn declarations_allow_explicit_definition_mutation() {
    for mut constant in declarations() {
        *constant.definition_mut().name_mut() = Ident::new("RENAMED").unwrap();
        let constant = constant.with_docs(Some(Span::unknown(String::from("New docs"))));

        assert_eq!(constant.name().as_str(), "RENAMED");
        assert_eq!(constant.docs().unwrap().into_inner(), "New docs");
    }
}

#[test]
fn equality_ignores_definition_docs_and_span() {
    for ty in [None, Some(u8_ty())] {
        let constant = constant_decl_fixture(int(), ty.clone())
            .with_docs(Some(Span::unknown(String::from("Constant docs"))));
        let other = match ty {
            Some(ty) => ConstantDecl::new_with_ty(
                SourceSpan::UNKNOWN,
                Visibility::Public,
                Ident::new("VALUE").unwrap(),
                int(),
                ty,
            ),
            None => ConstantDecl::new(
                SourceSpan::UNKNOWN,
                Visibility::Public,
                Ident::new("VALUE").unwrap(),
                int(),
            ),
        };
        assert_eq!(constant, other);
    }
}

#[test]
fn equality_preserves_type_annotation() {
    assert_ne!(constant_decl_fixture(int(), None), constant_decl_fixture(int(), Some(u8_ty())));
}
