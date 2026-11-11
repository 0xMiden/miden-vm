use alloc::sync::Arc;

use miden_assembly_syntax::ast::types::{ArrayType, StructType};
use miden_core::Word;
use miden_debug_types::{ColumnNumber, LineNumber};
use miden_mast_package::debug_info::{
    DebugFileInfo, DebugFunctionInfo, DebugTypeIdx, PackageDebugInfoBuilder,
};

use super::*;

fn felt(value: u64) -> Felt {
    Felt::try_from(value).expect("value exceeds field modulus")
}

fn render(ty: &Type, felts: &[Felt]) -> Option<String> {
    format_value(ty, |count| (felts.len() >= count).then(|| felts[..count].to_vec()))
}

#[test]
fn formats_account_id_struct() {
    let account_id = Type::from(StructType::named(
        Arc::from("miden:base/core-types@1.0.0/account-id"),
        [(Arc::from("prefix"), Type::Felt), (Arc::from("suffix"), Type::Felt)],
    ));
    let felts = [felt(0xa591_009a_3022_e801), felt(0x788f_9ed1_77dc_db00)];

    assert_eq!(
        render(&account_id, &felts).as_deref(),
        Some("account-id(0xa591009a3022e801788f9ed177dcdb)")
    );

    let procedure = TypedProcedure::new(
        "take-account",
        FunctionType::new(CallConv::ComponentModel, [account_id], []),
    )
    .unwrap();
    assert_eq!(procedure.encode_args(&["0xa591009a3022e801788f9ed177dcdb"]).unwrap(), felts);
}

#[test]
fn rejects_structurally_invalid_account_ids() {
    let codec = AccountIdCodec;

    for account_id in [
        // Only version 1 is supported by the current core-types ABI.
        "0xa591009a3022e800788f9ed177dcdb",
        "0xa591009a3022e802788f9ed177dcdb",
        // The suffix must fit in 63 bits before its padding byte is removed.
        "0xa591009a3022e801f88f9ed177dcdb",
    ] {
        assert!(codec.encode(account_id).is_err(), "accepted invalid account ID {account_id}");
    }

    let valid_prefix = felt(0xa591_009a_3022_e801);
    let valid_suffix = felt(0x788f_9ed1_77dc_db00);
    for felts in [
        [felt(valid_prefix.as_canonical_u64() & !0x0f), valid_suffix],
        [valid_prefix, felt(valid_suffix.as_canonical_u64() | 1)],
        [valid_prefix, felt(0x8000_0000_0000_0000)],
    ] {
        assert!(codec.decode(&felts).is_err(), "rendered invalid account ID {felts:?}");
    }
}

#[test]
fn encodes_and_decodes_rust_abi_values() {
    let procedure = TypedProcedure::new(
        "roundtrip",
        FunctionType::new(CallConv::ComponentModel, [Type::U64, Type::I1], [Type::U64]),
    )
    .unwrap();

    assert_eq!(
        procedure.encode_args(&["4294967303", "true"]).unwrap(),
        [felt(7), felt(1), felt(1)]
    );
    assert_eq!(
        procedure.decode_result(&[felt(7), felt(1)]).unwrap().as_deref(),
        Some("4294967303u64")
    );
}

#[test]
fn formats_anonymous_struct_shape() {
    let point =
        Type::from(StructType::new([(Arc::from("x"), Type::Felt), (Arc::from("y"), Type::Felt)]));

    assert_eq!(render(&point, &[felt(3), felt(4)]).as_deref(), Some("{ x: 3, y: 4 }"));
}

#[test]
fn formats_fixed_array() {
    let array = Type::Array(Arc::new(ArrayType::new(Type::U32, 3)));

    assert_eq!(render(&array, &[felt(5), felt(6), felt(7)]).as_deref(), Some("[5, 6, 7]"));
}

/// Adds `name` to `builder` as a function that returns `return_type_idx`.
fn add_function(
    builder: &mut PackageDebugInfoBuilder,
    name: &str,
    linkage_name: Option<&str>,
    return_type_idx: Option<DebugTypeIdx>,
) {
    let name_idx = builder.add_string(Arc::from(name));
    let path_idx = builder.add_string(Arc::from("lib.rs"));
    let file_idx = builder.add_file_info(DebugFileInfo::new(path_idx));
    let signature = builder.add_type(DebugTypeInfo::Function {
        return_type_idx,
        param_type_indices: Vec::new(),
    });
    let mut info = DebugFunctionInfo::new(
        None,
        name_idx,
        file_idx,
        LineNumber::new(1).unwrap(),
        ColumnNumber::new(1).unwrap(),
        Word::default(),
    )
    .with_type(signature);
    if let Some(linkage_name) = linkage_name {
        info = info.with_linkage_name(builder.add_string(Arc::from(linkage_name)));
    }
    builder.add_function(info);
}

#[test]
fn return_felt_counts() {
    let mut builder = PackageDebugInfoBuilder::default();
    let felt = builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
    // A `Word` is emitted as `[Felt; 4]`
    let word = builder.add_type(DebugTypeInfo::Array {
        element_type_idx: felt,
        count: Some(4),
    });
    let void = builder.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void));
    add_function(&mut builder, "felt_fn", None, Some(felt));
    add_function(&mut builder, "word_fn", None, Some(word));
    add_function(&mut builder, "void_fn", None, Some(void));
    add_function(&mut builder, "no_return_fn", None, None);
    add_function(&mut builder, "source_fn", Some("linked_fn"), Some(felt));
    let info = builder.build();

    let count = |name: &str| {
        info.functions()
            .iter()
            .find(|function| {
                info.get_string(function.name_idx).as_deref() == Some(name)
                    || function
                        .linkage_name_idx
                        .into_option()
                        .is_some_and(|idx| info.get_string(idx).as_deref() == Some(name))
            })
            .and_then(|function| return_felt_count(&info, function))
    };
    assert_eq!(count("felt_fn"), Some(1));
    assert_eq!(count("word_fn"), Some(4));
    assert_eq!(count("void_fn"), Some(0));
    assert_eq!(count("no_return_fn"), Some(0));
    assert_eq!(count("source_fn"), Some(1));
    assert_eq!(count("linked_fn"), Some(1));
    assert_eq!(count("missing_fn"), None);
}
