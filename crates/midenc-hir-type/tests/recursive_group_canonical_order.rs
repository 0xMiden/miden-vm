#![cfg(feature = "serde")]

use std::{collections::BTreeMap, sync::Arc};

use miden_serde_utils::{Deserializable, Serializable};
use midenc_hir_type::{RecursiveTypeBuilder, StructTemplate, Type, TypeRepr, TypeTemplate};

fn group_with_completed_reference(declared_name: Option<&str>) -> BTreeMap<Arc<str>, Type> {
    let mut a = StructTemplate::new(
        TypeRepr::Default,
        [
            ("f0", TypeTemplate::ptr(Type::Felt)),
            ("f1", TypeTemplate::ptr(TypeTemplate::rec("A"))),
            ("f2", TypeTemplate::list(TypeTemplate::rec("B"))),
        ],
    );
    let mut b = StructTemplate::new(
        TypeRepr::Default,
        [
            ("f0", TypeTemplate::ptr(TypeTemplate::rec("C"))),
            ("f1", TypeTemplate::list(TypeTemplate::rec("A"))),
            ("f2", TypeTemplate::from(Type::U8)),
        ],
    );
    a.name = declared_name.map(Into::into);
    b.name = declared_name.map(Into::into);
    let mut builder = RecursiveTypeBuilder::new();
    builder
        .define_struct("A", a)
        .define_struct("B", b)
        .define_struct("C", StructTemplate::new(TypeRepr::Default, [("f0", Type::U128)]));
    builder.build().expect("group should build")
}

fn assert_roundtrips(built: BTreeMap<Arc<str>, Type>) {
    assert_ne!(built["A"], built["B"], "distinct definitions must remain distinct");
    for key in ["A", "B", "C"] {
        let ty = built.get(key).expect(key);
        let bytes = ty.to_bytes();
        let decoded = Type::read_from_bytes(&bytes).expect("type should decode");
        assert_eq!(&decoded, ty, "type {key} should round-trip");
        assert_eq!(decoded.to_bytes(), bytes, "type {key} should preserve its wire encoding");
    }
}

#[test]
fn anonymous_group_with_completed_reference_roundtrips() {
    assert_roundtrips(group_with_completed_reference(None));
}

#[test]
fn group_with_tied_nonempty_names_roundtrips() {
    assert_roundtrips(group_with_completed_reference(Some("T")));
}
