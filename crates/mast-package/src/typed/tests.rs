use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_assembly_syntax::ast::types::{CallConv, FunctionType, NameAndType, StructType, Type};
use miden_core::Felt;

use super::{MIDEN_CORE_TYPES, TypedError, TypedProcInfo, WitScalarCodec};

// FIXTURES
// ================================================================================================

/// The `felt` core type, the way the compiler writes it: a named struct with one field element.
fn felt_ty() -> Type {
    named_struct("miden:base/core-types@1.0.0/felt", [("inner", Type::Felt)])
}

/// A record with two `felt` fields. Its name has no WIT interface in front.
fn point_ty() -> Type {
    named_struct("point", [("x", felt_ty()), ("y", felt_ty())])
}

/// The `account-id` core type. A codec from the user takes over this shape.
fn account_id_ty() -> Type {
    named_struct(
        "miden:base/core-types@1.0.0/account-id",
        [("prefix", felt_ty()), ("suffix", felt_ty())],
    )
}

fn named_struct<const N: usize>(name: &str, fields: [(&str, Type); N]) -> Type {
    Type::Struct(Arc::new(StructType::named(
        Arc::from(name),
        fields.map(|(name, ty)| (Arc::<str>::from(name), ty)),
    )))
}

fn tuple_struct<const N: usize>(name: &str, fields: [Type; N]) -> Type {
    Type::Struct(Arc::new(StructType::named(Arc::from(name), fields)))
}

fn unnamed_record<const N: usize>(fields: [(&str, Type); N]) -> Type {
    Type::Struct(Arc::new(StructType::new(
        fields.map(|(name, ty)| (Arc::<str>::from(name), ty)),
    )))
}

fn unnamed_tuple<const N: usize>(fields: [Type; N]) -> Type {
    Type::Struct(Arc::new(StructType::new(fields)))
}

/// Builds a typed view without a package, so a test can name its own types.
fn proc(
    name: &str,
    params: impl IntoIterator<Item = Type>,
    results: impl IntoIterator<Item = Type>,
) -> TypedProcInfo {
    TypedProcInfo::new(name, FunctionType::new(CallConv::Fast, params, results))
}

fn felts(values: impl IntoIterator<Item = u32>) -> Vec<Felt> {
    values.into_iter().map(Felt::from_u32).collect()
}

/// Stands in for the `account-id` codec of the CLI: one token in, two felts out. It lives here so
/// the tests can use the user path without protocol rules.
struct TestAccountIdCodec;

impl WitScalarCodec for TestAccountIdCodec {
    fn wit_name(&self) -> &str {
        "account-id"
    }

    fn wit_interface(&self) -> Option<&str> {
        Some(MIDEN_CORE_TYPES)
    }

    fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedError> {
        let hex = token.strip_prefix("0x").ok_or_else(|| TypedError::InvalidScalar {
            wit_name: self.wit_name().to_string(),
            token: token.to_string(),
            reason: "expected a 0x-prefixed value".to_string(),
        })?;
        let value: u32 = hex.parse().map_err(|_| TypedError::InvalidScalar {
            wit_name: self.wit_name().to_string(),
            token: token.to_string(),
            reason: "expected digits after 0x".to_string(),
        })?;
        Ok(felts([value, 0]))
    }

    fn decode(&self, felts: &[Felt]) -> Result<String, TypedError> {
        let [prefix, ..] = felts else {
            return Err(TypedError::MalformedResult {
                ty: self.wit_name().to_string(),
                reason: "an account-id needs at least a prefix felt",
            });
        };
        Ok(format!("account-id(0x{})", prefix.as_canonical_u64()))
    }
}

/// A codec that takes a type it does not fit. It tests the width check.
struct NarrowCodec;

impl WitScalarCodec for NarrowCodec {
    fn wit_name(&self) -> &str {
        "account-id"
    }

    fn wit_interface(&self) -> Option<&str> {
        Some(MIDEN_CORE_TYPES)
    }

    fn encode(&self, _token: &str) -> Result<Vec<Felt>, TypedError> {
        Ok(felts([1]))
    }

    fn decode(&self, _felts: &[Felt]) -> Result<String, TypedError> {
        Err(TypedError::MalformedResult {
            ty: self.wit_name().to_string(),
            reason: "this codec renders nothing",
        })
    }
}

fn with_account_id(info: TypedProcInfo) -> TypedProcInfo {
    info.with_scalar_codec(Box::new(TestAccountIdCodec))
}

// SIGNATURE RENDERING
// ================================================================================================

#[test]
fn signature_renders_bare_type_names() {
    let info = proc("add-points", [point_ty(), point_ty()], [point_ty()]);
    assert_eq!(info.to_string(), "add-points(point, point) -> point");
}

#[test]
fn signature_strips_the_wit_interface_prefix() {
    let info = proc("take-account-id", [account_id_ty()], [account_id_ty()]);
    assert_eq!(info.to_string(), "take-account-id(account-id) -> account-id");
}

#[test]
fn signature_without_results_has_no_arrow() {
    let info = proc("reset-count", [], []);
    assert_eq!(info.to_string(), "reset-count()");
}

#[test]
fn signature_renders_several_results_as_a_tuple() {
    let info = proc("split", [point_ty()], [felt_ty(), Type::U32]);
    assert_eq!(info.to_string(), "split(point) -> (felt, u32)");
}

// ARGUMENT COUNTING
// ================================================================================================

#[test]
fn aggregates_take_one_token_per_leaf() {
    let info = proc("add-points", [point_ty(), point_ty()], [point_ty()]);
    assert_eq!(info.expected_token_count(), Some(4));
}

#[test]
fn an_unregistered_scalar_type_falls_back_to_its_fields() {
    let info = proc("take-account-id", [account_id_ty()], []);
    assert_eq!(info.expected_token_count(), Some(2));
}

#[test]
fn a_builtin_codec_does_not_claim_a_same_named_type_from_another_interface() {
    // Some other `word` is not the core `word`. It has the same plain name and the same width.
    // Without the interface check, `WordCodec` would take it: one hex token in, `word(0x..)` out,
    // for a type it does not know.
    let foreign_word = named_struct(
        "mypkg:types/shapes@1.0.0/word",
        [("a", Type::Felt), ("b", Type::Felt), ("c", Type::Felt), ("d", Type::Felt)],
    );
    let info = proc("take-word", [foreign_word], []);

    // Four tokens, one per field. `WordCodec` would take only one token.
    assert_eq!(info.expected_token_count(), Some(4));
    assert_eq!(info.encode_args(&["1", "2", "3", "4"]).unwrap(), felts([1, 2, 3, 4]));
}

#[test]
fn a_builtin_codec_claims_its_type_across_core_type_versions() {
    // We do not match the version, so a codec still works with a new version of the core types.
    let core_word = named_struct(
        "miden:base/core-types@9.9.9/word",
        [("a", Type::Felt), ("b", Type::Felt), ("c", Type::Felt), ("d", Type::Felt)],
    );
    let info = proc("take-word", [core_word], []);

    assert_eq!(info.expected_token_count(), Some(1));
}

#[test]
fn a_codec_narrower_than_its_type_is_reported() {
    // We ignore the version when we match the interface. So a future core `word` could be wider
    // than the four felts `WordCodec` prints. Then it must say so, and not show the first four as
    // if they were the whole value.
    let wide_word = named_struct(
        "miden:base/core-types@2.0.0/word",
        [
            ("a", Type::Felt),
            ("b", Type::Felt),
            ("c", Type::Felt),
            ("d", Type::Felt),
            ("e", Type::Felt),
        ],
    );
    let info = proc("get-word", [], [wide_word]);

    assert_eq!(info.output_felt_count(), Some(5));
    assert!(matches!(
        info.decode_result(&felts([1, 2, 3, 4, 5])),
        Err(TypedError::MalformedResult { .. })
    ));
}

#[test]
fn shapes_without_an_encoding_have_no_token_count() {
    let info = proc("take-list", [Type::List(Arc::new(Type::U32))], []);
    assert_eq!(info.expected_token_count(), None);
}

#[test]
fn u256_has_no_token_or_felt_count() {
    // `u256` has a place on the stack, but the encoder and the decoder both say no. If we gave
    // it a size, the caller would ask the user for arguments and only then fail, with a wrong
    // argument count instead of the real reason.
    assert_eq!(proc("take-u256", [Type::U256], []).expected_token_count(), None);
    assert_eq!(proc("get-u256", [], [Type::U256]).output_felt_count(), None);
}

// ENCODING
// ================================================================================================

#[test]
fn encoding_flattens_aggregate_fields_in_order() {
    let info = proc("add-points", [point_ty(), point_ty()], [point_ty()]);
    assert_eq!(info.encode_args(&["3", "4", "5", "6"]).unwrap(), felts([3, 4, 5, 6]));
}

#[test]
fn a_codec_encodes_its_type_from_one_token() {
    let info = with_account_id(proc("take-account-id", [account_id_ty()], []));
    assert_eq!(info.encode_args(&["0x7"]).unwrap(), felts([7, 0]));
}

#[test]
fn a_wrong_argument_count_names_the_procedure_and_both_numbers() {
    let info = proc("add-points", [point_ty(), point_ty()], [point_ty()]);

    let too_few = info.encode_args(&["3", "4", "5"]).unwrap_err();
    assert_eq!(too_few.to_string(), "procedure 'add-points' expects 4 argument(s), got 3");

    assert!(matches!(
        info.encode_args(&["3", "4", "5", "6", "7"]),
        Err(TypedError::ArgumentCount { expected: 4, actual: 5, .. })
    ));
}

#[test]
fn a_parameter_that_cannot_be_encoded_names_the_procedure() {
    let info = proc("take-list", [Type::List(Arc::new(Type::U32))], []);
    assert_eq!(
        info.encode_args(&["1"]).unwrap_err().to_string(),
        "procedure 'take-list' takes a parameter that cannot be given as an argument"
    );
}

#[test]
fn a_codec_that_disagrees_with_its_type_width_is_rejected() {
    let info =
        proc("take-account-id", [account_id_ty()], []).with_scalar_codec(Box::new(NarrowCodec));
    assert!(matches!(
        info.encode_args(&["0x7"]),
        Err(TypedError::CodecWidthMismatch { expected: 2, actual: 1, .. })
    ));
}

#[test]
fn integers_are_range_checked() {
    let info = proc("take-u8", [Type::U8], []);
    assert_eq!(info.encode_args(&["255"]).unwrap(), felts([255]));
    assert!(matches!(info.encode_args(&["256"]), Err(TypedError::IntOutOfRange { .. })));
}

// RESULT DECODING
// ================================================================================================

#[test]
fn results_are_sized_by_their_leaves() {
    let info = proc("add-points", [], [point_ty()]);
    assert_eq!(info.output_felt_count(), Some(2));
    assert_eq!(proc("reset-count", [], []).output_felt_count(), Some(0));
}

#[test]
fn integers_round_trip_through_the_stack() {
    // `i8` at `-1` and `u8` at `255` are left out: `signed_small_integers_fill_their_stack_slot`
    // and `unsigned_small_integers_are_masked_to_their_own_width` pin their exact felts, which
    // says more than a round trip.
    for (ty, token) in [
        (Type::I8, "-128"),
        (Type::I8, "127"),
        (Type::I16, "-1"),
        (Type::I16, "-32768"),
        (Type::I32, "-1"),
        (Type::I64, "-1"),
        (Type::I128, "-1"),
        (Type::U32, "4294967295"),
        (Type::U64, "18446744073709551615"),
    ] {
        let info = proc("f", [ty.clone()], [ty.clone()]);
        let encoded = info.encode_args(&[token]).unwrap();
        let decoded = info.decode_result(&encoded).unwrap().unwrap();

        // The text has the type name after it, like `-1i8`, so we compare only the value.
        assert!(decoded.starts_with(token), "{ty}: encoded {token}, decoded {decoded}");
    }
}

#[test]
fn a_named_record_decodes_with_its_field_names() {
    let info = proc("add-points", [], [point_ty()]);
    assert_eq!(info.decode_result(&felts([3, 4])).unwrap().unwrap(), "point { x: 3, y: 4 }");
}

#[test]
fn a_tuple_struct_decodes_without_field_names() {
    let info = proc("split", [], [tuple_struct("pair", [Type::U32, Type::U32])]);
    assert_eq!(info.decode_result(&felts([3, 4])).unwrap().unwrap(), "pair(3, 4)");
}

#[test]
fn an_anonymous_struct_renders_its_body_instead_of_a_name() {
    // A struct with no name shows its body. Field names still choose record or tuple, and the
    // signature shows the shape instead of a name.
    let info = proc("f", [], [unnamed_record([("x", felt_ty()), ("y", felt_ty())])]);
    assert_eq!(info.decode_result(&felts([3, 4])).unwrap().unwrap(), "{ x: 3, y: 4 }");

    let info = proc("f", [], [unnamed_tuple([Type::U32, Type::U32])]);
    assert_eq!(info.decode_result(&felts([3, 4])).unwrap().unwrap(), "(3, 4)");
    assert_eq!(info.to_string(), "f() -> (u32, u32)");
}

#[test]
fn a_struct_mixing_named_and_unnamed_fields_is_invalid_type_info() {
    // The compiler never writes this shape, so we call the type info bad instead of guessing.
    let mixed = Type::Struct(Arc::new(StructType::named(
        Arc::from("half-named"),
        [
            NameAndType::from((Arc::<str>::from("x"), Type::U32)),
            NameAndType::from(Type::U32),
        ],
    )));
    assert!(matches!(
        proc("f", [], [mixed]).decode_result(&felts([3, 4])),
        Err(TypedError::InvalidTypeInfo(_))
    ));
}

#[test]
fn a_codec_decodes_its_own_type() {
    let info = with_account_id(proc("take-account-id", [], [account_id_ty()]));
    assert_eq!(info.decode_result(&felts([7, 0])).unwrap().unwrap(), "account-id(0x7)");
}

#[test]
fn a_codec_rejecting_a_value_reaches_the_caller() {
    // The codec holds the real check for its type. When it says no, we must not fall back to the
    // field by field way: `account-id { prefix: 7, suffix: 0 }` would show a bad value as a good
    // one. We must not turn it into "nothing to show" either.
    let info =
        proc("get-account-id", [], [account_id_ty()]).with_scalar_codec(Box::new(NarrowCodec));

    assert!(matches!(
        info.decode_result(&felts([7, 0])),
        Err(TypedError::MalformedResult { .. })
    ));
}

#[test]
fn primitive_results_carry_their_type_but_bools_do_not() {
    assert_eq!(
        proc("f", [], [Type::U32]).decode_result(&felts([42])).unwrap().unwrap(),
        "42u32"
    );
    assert_eq!(proc("f", [], [Type::I1]).decode_result(&felts([1])).unwrap().unwrap(), "true");
    assert_eq!(proc("f", [], [felt_ty()]).decode_result(&felts([9])).unwrap().unwrap(), "9");
}

#[test]
fn a_procedure_with_no_results_decodes_to_nothing() {
    // The only case that is not a problem: nothing to show, and nothing to report.
    assert_eq!(proc("reset-count", [], []).decode_result(&felts([1, 2])).unwrap(), None);
}

#[test]
fn a_short_stack_names_the_procedure_and_both_counts() {
    let info = proc("add-points", [], [point_ty()]);
    assert!(matches!(
        info.decode_result(&felts([3])),
        Err(TypedError::ResultStackTooShort { expected: 2, actual: 1, .. })
    ));
}

#[test]
fn an_out_of_range_limb_is_reported_as_malformed() {
    // A `u8` uses one limb of 32 bits. A wider value in it is bad output, not a small value.
    let info = proc("f", [], [Type::U8]);
    assert!(matches!(
        info.decode_result(&felts([300])),
        Err(TypedError::MalformedResult { .. })
    ));
}

#[test]
fn signed_small_integers_fill_their_stack_slot() {
    // `i8` and `i16` are the only types whose slot is wider than the type: they travel
    // sign-extended across a whole 32-bit slot, so `-1i8` is `0xffffffff`, not the byte `0xff`.
    // The compiler's `identity-i8: func(x: s8) -> s8` ends in `push.255 u32and` followed by an
    // `or` of `0xffffff00` when the sign bit is set. Reading only the low byte would take
    // `0xffffffff` for an out-of-range value and refuse to print any negative result.
    let i8_info = proc("f", [Type::I8], [Type::I8]);
    assert_eq!(i8_info.encode_args(&["-1"]).unwrap(), felts([u32::MAX]));
    assert_eq!(i8_info.decode_result(&felts([u32::MAX])).unwrap().unwrap(), "-1i8");

    let i16_info = proc("f", [Type::I16], [Type::I16]);
    assert_eq!(i16_info.encode_args(&["-2"]).unwrap(), felts([u32::MAX - 1]));
    assert_eq!(i16_info.decode_result(&felts([u32::MAX - 1])).unwrap().unwrap(), "-2i16");
}

#[test]
fn unsigned_small_integers_are_masked_to_their_own_width() {
    // `identity-u8` ends in `push.255 u32and` and nothing else, so an unsigned value never fills
    // more of the slot than its type. Anything wider is bad output, not a value to cut down.
    let info = proc("f", [Type::U8], [Type::U8]);
    assert_eq!(info.encode_args(&["255"]).unwrap(), felts([255]));
    assert_eq!(info.decode_result(&felts([255])).unwrap().unwrap(), "255u8");
    assert!(matches!(
        info.decode_result(&felts([256])),
        Err(TypedError::MalformedResult { .. })
    ));
}

#[test]
fn a_signed_slot_outside_the_range_of_its_type_is_reported() {
    // `0xffffff00` is `-256` across the slot, which no `i8` can hold.
    let info = proc("f", [], [Type::I8]);
    assert!(matches!(
        info.decode_result(&felts([0xffff_ff00])),
        Err(TypedError::MalformedResult { .. })
    ));
}
