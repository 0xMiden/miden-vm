use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_core::Felt;
use midenc_hir_type::{ArrayType, CallConv, FunctionType, NameAndType, StructType, Type};

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
    Type::from(StructType::named(
        Arc::from(name),
        fields.map(|(name, ty)| (Arc::<str>::from(name), ty)),
    ))
}

/// A struct whose first field has a name and whose second does not, so it is neither a record nor
/// a tuple. No compiler writes this shape.
fn half_named_struct(name: &str, named: (&str, Type), unnamed: Type) -> Type {
    Type::from(StructType::named(
        Arc::from(name),
        [
            NameAndType::from((Arc::<str>::from(named.0), named.1)),
            NameAndType::from(unnamed),
        ],
    ))
}

fn tuple_struct<const N: usize>(name: &str, fields: [Type; N]) -> Type {
    Type::from(StructType::named(Arc::from(name), fields))
}

fn unnamed_record<const N: usize>(fields: [(&str, Type); N]) -> Type {
    Type::from(StructType::new(fields.map(|(name, ty)| (Arc::<str>::from(name), ty))))
}

fn unnamed_tuple<const N: usize>(fields: [Type; N]) -> Type {
    Type::from(StructType::new(fields))
}

/// Builds a typed view without a package, so a test can name its own types.
///
/// Every fixture is `component-model`. That is the one convention this crate encodes, and the
/// compiler gives it to every high-level export of a component. See
/// [`only_the_canonical_calling_convention_has_the_layout_we_encode`].
#[test]
fn a_recursive_struct_argument_is_refused_rather_than_walked_forever() {
    use midenc_hir_type::{RecursiveTypeBuilder, StructTemplate, TypeRepr, TypeTemplate};

    // A recursive aggregate always reaches itself through a pointer, list, or function, and this
    // module takes none of those from a user. So walking one terminates instead of unfolding
    // forever, and the argument is refused rather than promising a stack shape the encoder
    // cannot produce.
    let mut builder = RecursiveTypeBuilder::new();
    builder.define_struct(
        "node",
        StructTemplate::named(
            "node",
            TypeRepr::Default,
            [
                ("value", TypeTemplate::from(Type::U32)),
                ("next", TypeTemplate::ptr(TypeTemplate::rec("node"))),
            ],
        ),
    );
    let node = builder.build().expect("node should build").remove("node").expect("node");

    let info = proc("f", [node.clone()], []);
    assert!(matches!(info.encode_args(&["1"]), Err(TypedError::UnsupportedParameter { .. })));

    let info = proc("f", [], [node]);
    assert!(matches!(
        info.decode_result(&felts([1, 2])),
        Err(TypedError::UnsupportedResult { .. })
    ));
}

#[test]
fn an_anonymous_recursive_signature_formats_without_aborting() {
    use midenc_hir_type::{RecursiveTypeBuilder, StructTemplate, TypeRepr, TypeTemplate};

    let mut builder = RecursiveTypeBuilder::new();
    builder.define_struct(
        "node",
        StructTemplate::new(TypeRepr::Default, [TypeTemplate::ptr(TypeTemplate::rec("node"))]),
    );
    let node = builder.build().expect("node should build").remove("node").expect("node");
    let info = proc("f", [node], []);

    assert!(!info.to_string().is_empty());
}

fn proc(
    name: &str,
    params: impl IntoIterator<Item = Type>,
    results: impl IntoIterator<Item = Type>,
) -> TypedProcInfo {
    TypedProcInfo::new(name, FunctionType::new(CallConv::ComponentModel, params, results))
        .expect("component-model is the convention this crate takes")
}

fn felts(values: impl IntoIterator<Item = u32>) -> Vec<Felt> {
    values.into_iter().map(Felt::from_u32).collect()
}

/// The normal case: one token in, the two felts of `account-id` out, and its own way to print
/// them, like `account-id(0x7)`. It stands in for the `account-id` codec of the CLI, without the
/// protocol rules.
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

/// A codec that does not fit the type it claims, in both directions: `encode` makes one felt where
/// `account-id` takes two, and `decode` refuses every value. The first is rejected on the width.
/// The second has to reach the caller instead of falling back to the fields.
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

/// A codec that takes a token and makes no felts, because its type takes none. It fits its type,
/// unlike [`NarrowCodec`]. Its type is the struct `empty`, whose name has no WIT interface, so the
/// codec matches on the bare name.
struct TokenOnlyCodec;

impl WitScalarCodec for TokenOnlyCodec {
    fn wit_name(&self) -> &str {
        "empty"
    }

    fn wit_interface(&self) -> Option<&str> {
        None
    }

    fn encode(&self, _token: &str) -> Result<Vec<Felt>, TypedError> {
        Ok(Vec::new())
    }

    fn decode(&self, _felts: &[Felt]) -> Result<String, TypedError> {
        Ok("empty".to_string())
    }
}

fn array_of(ty: Type, len: usize) -> Type {
    Type::Array(Arc::new(ArrayType::new(ty, len)))
}

fn with_account_id(info: TypedProcInfo) -> TypedProcInfo {
    info.with_scalar_codec(Box::new(TestAccountIdCodec))
}

// CALLING CONVENTION
// ================================================================================================

#[test]
fn only_the_canonical_calling_convention_has_the_layout_we_encode() {
    // A signature names its calling convention, and the convention says how a value is laid out in
    // felts. Under `component-model`, the canonical one, every field of a struct gets its own
    // stack slot. The reason is the component export: a caller reaches it with the `call`
    // instruction, which starts a new memory context.
    //
    // The `Fast` convention is the other way round. A caller reaches such a procedure with `exec`
    // instruction , which runs it in the caller's own context and memory, so a struct can travel as
    // its image in that memory. `pair` is two bytes and a felt holds four, so under `fast` both
    // fields fit in one stack value.
    let pair = named_struct("pair", [("a", Type::U8), ("b", Type::U8)]);
    assert_eq!(pair.size_in_felts(), 1);

    // So the value `pair { a: 1, b: 2 }` is one felt under `Fast` and two felts under the
    // Canonical convention. We can only make the second, so we refuse every other convention
    // instead of sending felts of the wrong shape. `Fast` has its own test,
    // [`a_fast_procedure_reads_our_felts_as_a_different_value`], for what it reads there.
    for cc in [CallConv::C, CallConv::Wasm] {
        let refused =
            TypedProcInfo::new("f", FunctionType::new(cc.clone(), [pair.clone()], [pair.clone()]));
        assert!(matches!(refused, Err(TypedError::UnsupportedCallConv { .. })), "{cc}");
    }

    // Under `component-model` the two fields really are two stack values, in field order.
    let info = proc("f", [pair.clone()], [pair]);
    assert_eq!(info.encode_args(&["1", "2"]).unwrap(), felts([1, 2]));
    assert_eq!(info.decode_result(&felts([1, 2])).unwrap().unwrap(), "pair { a: 1, b: 2 }");
}

#[test]
fn a_fast_procedure_reads_our_felts_as_a_different_value() {
    // A procedure with the `Fast` calling convention takes `pair` as one felt, the image it has in
    // memory: `a` in the low byte, `b` in the next. So `pair { a: 1, b: 2 }` is the single value
    // `2 * 256 + 1`, that is 513, to it, and `[1, 2]` to us.
    //
    // If we pushed `[1, 2]`, the procedure would read one felt, our `1`. Its low byte is 1 and the
    // next byte is 0, so it sees `pair { a: 1, b: 0 }`, and our `2` stays on the stack as an
    // argument nobody took. Its result goes the same way: `pair { a: 1, b: 0 }` comes back as the
    // single felt `1`, and we would read a second felt for `b`. That felt is not part of the
    // result. It is whatever the program left on the stack, and we would print it as the value of
    // `b`. Nothing reports any of this. A wrong value looks exactly like a right one, so we refuse
    // the signature.
    let pair = named_struct("pair", [("a", Type::U8), ("b", Type::U8)]);
    assert_eq!(pair.size_in_felts(), 1);

    let refused =
        TypedProcInfo::new("f", FunctionType::new(CallConv::Fast, [pair.clone()], [pair]));
    assert!(matches!(refused, Err(TypedError::UnsupportedCallConv { .. })));
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
fn a_codec_names_its_type_in_the_signature_whatever_its_fields_look_like() {
    // A codec takes one token for the whole type and never reads the fields, so the signature has
    // to show the name it takes that token for. Printing the fields tells the user to pass one
    // token per field, and `encode_args` then refuses the count the signature asked for.
    let account_id = half_named_struct(
        "miden:base/core-types@1.0.0/account-id",
        ("prefix", felt_ty()),
        felt_ty(),
    );
    let info = with_account_id(proc("f", [account_id], []));

    assert_eq!(info.expected_token_count(), Some(1));
    assert_eq!(info.encode_args(&["0x7"]).unwrap(), felts([7, 0]));
    assert_eq!(info.to_string(), "f(account-id)");
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

#[test]
fn a_count_that_does_not_fit_a_usize_is_no_count_at_all() {
    // A `u8` takes one token, so an array of `half` of them takes `half` tokens. Two such
    // parameters ask for `2 * half`, which is exactly one more than a `usize` holds, and wraps to
    // `0`. Every count is checked, so we say `None` here instead.
    //
    // `0` is what makes this worth a test: `encode_args` would take an empty argument list as the
    // right count, and the encoder would then walk half of a `usize` worth of elements.
    let half = usize::MAX / 2 + 1;
    let huge = array_of(Type::U8, half);
    let info = proc("f", [huge.clone(), huge.clone()], []);
    assert_eq!(info.expected_token_count(), None);
    assert!(matches!(
        info.encode_args::<&str>(&[]),
        Err(TypedError::UnsupportedParameter { .. })
    ));

    // The felts of a result are counted the same way.
    let info = proc("f", [], [huge.clone(), huge]);
    assert_eq!(info.output_felt_count(), None);
    assert!(matches!(
        info.decode_result(&felts([1])),
        Err(TypedError::UnsupportedResult { .. })
    ));
}

// ENCODING
// ================================================================================================

#[test]
fn encoding_flattens_aggregate_fields_in_order() {
    let info = proc("add-points", [point_ty(), point_ty()], [point_ty()]);
    assert_eq!(info.encode_args(&["3", "4", "5", "6"]).unwrap(), felts([3, 4, 5, 6]));

    // An array flattens the same way, one element after another. Its length is part of the type,
    // so it asks for exactly that many tokens.
    let info = proc("f", [array_of(Type::U32, 3)], []);
    assert_eq!(info.expected_token_count(), Some(3));
    assert_eq!(info.encode_args(&["7", "8", "9"]).unwrap(), felts([7, 8, 9]));

    // Two levels at once: every field of every element takes its own slot, in order.
    let info = proc("f", [array_of(point_ty(), 2)], []);
    assert_eq!(info.expected_token_count(), Some(4));
    assert_eq!(info.encode_args(&["1", "2", "3", "4"]).unwrap(), felts([1, 2, 3, 4]));
}

#[test]
fn a_codec_encodes_its_type_from_one_token() {
    let info = with_account_id(proc("take-account-id", [account_id_ty()], []));
    assert_eq!(info.encode_args(&["0x7"]).unwrap(), felts([7, 0]));
}

#[test]
fn the_word_codec_reads_one_felt_from_every_eight_bytes_of_the_hex() {
    // `word` is the built-in codec with a text form of its own, and the form is not obvious. The
    // hex is four groups of eight bytes, one felt each, and every group is little-endian. So the
    // felt `1` is written `0100000000000000`, not `0000000000000001`.
    let word = named_struct(
        "miden:base/core-types@1.0.0/word",
        [("a", Type::Felt), ("b", Type::Felt), ("c", Type::Felt), ("d", Type::Felt)],
    );
    let info = proc("f", [word.clone()], [word]);
    let hex = "0x0100000000000000020000000000000003000000000000000400000000000000";

    assert_eq!(info.expected_token_count(), Some(1));
    assert_eq!(info.encode_args(&[hex]).unwrap(), felts([1, 2, 3, 4]));
    assert_eq!(
        info.decode_result(&felts([1, 2, 3, 4])).unwrap().unwrap(),
        format!("word({hex})")
    );

    // A token the codec cannot read reaches the caller: too short, not hex at all, or a group that
    // is no field element.
    let over_the_modulus = "0xffffffffffffffff000000000000000000000000000000000000000000000000";
    for bad in ["0xdeadbeef", "not-hex", over_the_modulus] {
        assert!(
            matches!(info.encode_args(&[bad]), Err(TypedError::InvalidScalar { .. })),
            "{bad}"
        );
    }
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

#[test]
fn a_type_that_occupies_no_felts_never_reaches_the_stack() {
    let empty = named_struct("empty", []);

    // On its own the type asks for nothing: no token to type, no felt on the stack. So a procedure
    // that takes one takes no arguments.
    let plain = proc("f", [empty.clone()], []);
    assert_eq!(plain.expected_token_count(), Some(0));
    assert_eq!(plain.encode_args::<&str>(&[]).unwrap(), felts([]));

    // A codec takes one token for the whole type, whatever its width. So the same parameter asks
    // for one token now, and still makes no felts.
    let with_codec = proc("f", [empty.clone()], []).with_scalar_codec(Box::new(TokenOnlyCodec));
    assert_eq!(with_codec.expected_token_count(), Some(1));
    assert_eq!(with_codec.encode_args(&["a"]).unwrap(), felts([]));

    // Once for every field of a struct, the same way.
    let wrapper = named_struct("wrapper", [("a", empty.clone()), ("b", empty.clone())]);
    let info = proc("f", [wrapper], []).with_scalar_codec(Box::new(TokenOnlyCodec));
    assert_eq!(info.expected_token_count(), Some(2));
    assert_eq!(info.encode_args(&["a", "b"]).unwrap(), felts([]));

    // Five of them in an array are still nothing to type. Decoding such an array is refused
    // instead, in [`an_array_of_elements_that_take_no_felts_is_not_decoded`].
    let info = proc("f", [array_of(empty.clone(), 5)], []);
    assert_eq!(info.expected_token_count(), Some(0));
    assert_eq!(info.encode_args::<&str>(&[]).unwrap(), felts([]));

    // A million of them are nothing to type either, and the encoder sees that without walking them
    // one by one.
    let info = proc("f", [array_of(empty.clone(), 1_000_000)], []);
    assert_eq!(info.expected_token_count(), Some(0));
    assert_eq!(info.encode_args::<&str>(&[]).unwrap(), felts([]));

    // The whole round trip: the procedure takes one and returns one, nothing is typed, nothing
    // goes on the stack, and the result still has a name.
    let info = proc("f", [empty.clone()], [empty]);
    assert_eq!(info.to_string(), "f(empty) -> empty");
    assert_eq!(info.encode_args::<&str>(&[]).unwrap(), felts([]));
    assert_eq!(info.decode_result(&[]).unwrap().unwrap(), "empty()");
}

#[test]
fn a_codec_reads_its_token_for_every_array_element() {
    // The array skips its elements only when they read no tokens. A codec gives this one a token,
    // so the loop runs twice and takes both "a" and "b", even though neither makes a felt.
    let info = proc("f", [array_of(named_struct("empty", []), 2)], [])
        .with_scalar_codec(Box::new(TokenOnlyCodec));

    assert_eq!(info.expected_token_count(), Some(2));
    assert_eq!(info.encode_args(&["a", "b"]).unwrap(), felts([]));
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
    //
    // Every value wider than one felt is here twice: once as all ones, once as something else. All
    // ones reads the same in either limb order, so alone it would let a swapped round trip pass.
    for (ty, token) in [
        (Type::I8, "-128"),
        (Type::I8, "127"),
        (Type::I16, "-1"),
        (Type::I16, "-32768"),
        (Type::I32, "-1"),
        (Type::I64, "-1"),
        (Type::I64, "-2"),
        (Type::I128, "-1"),
        (Type::I128, "-2"),
        (Type::U32, "4294967295"),
        (Type::U64, "4294967303"),
        (Type::U64, "18446744073709551615"),
    ] {
        let info = proc("f", [ty.clone()], [ty.clone()]);
        let encoded = info.encode_args(&[token]).unwrap();
        let decoded = info.decode_result(&encoded).unwrap().unwrap();

        // The text has the type name after it, like `-1i8`, so we build the same thing to compare.
        assert_eq!(decoded, format!("{token}{ty}"));
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
    assert_eq!(info.to_string(), "f() -> { x: felt, y: felt }");

    let info = proc("f", [], [unnamed_tuple([Type::U32, Type::U32])]);
    assert_eq!(info.decode_result(&felts([3, 4])).unwrap().unwrap(), "(3, 4)");
    assert_eq!(info.to_string(), "f() -> (u32, u32)");
}

#[test]
fn a_struct_mixing_named_and_unnamed_fields_is_invalid_type_info() {
    // `x` has a name and the second field does not, so we cannot tell whether this struct is a
    // record or a tuple.
    let mixed = half_named_struct("half-named", ("x", Type::U32), Type::U32);
    // The signature marks the field we could not name with `?`, and keeps the name and the types,
    // so the reader can tell which type is bad.
    let info = proc("f", [], [mixed.clone()]);
    assert_eq!(info.to_string(), "f() -> half-named { x: u32, ?: u32 }");
    assert!(matches!(
        info.decode_result(&felts([3, 4])),
        Err(TypedError::InvalidTypeInfo { .. })
    ));

    // As a parameter it still encodes: field names do not decide where a field sits on the stack,
    // only how we label it.
    let info = proc("f", [mixed.clone()], []);
    assert_eq!(info.to_string(), "f(half-named { x: u32, ?: u32 })");
    assert_eq!(info.encode_args(&["3", "4"]).unwrap(), felts([3, 4]));

    // Nested one level down, the `?` marker cannot help: `point` has a name, so the signature is
    // just that name and never shows the field that carries the bad struct. The error is then the
    // only place it can be named.
    let info = proc("f", [], [named_struct("point", [("x", mixed), ("y", felt_ty())])]);
    assert_eq!(info.to_string(), "f() -> point");
    let err = info.decode_result(&felts([3, 4, 5])).unwrap_err().to_string();
    assert!(err.contains("half-named"), "the error does not say which struct is bad: {err}");
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
fn a_result_that_takes_no_felts_is_still_a_result() {
    // `reset-count` declares no results, so there is nothing to show and nothing to report,
    // whatever is left on the stack: `None`.
    let info = proc("reset-count", [], []);
    assert!(!info.returns_value());
    assert_eq!(info.decode_result(&felts([1, 2])).unwrap(), None);

    // An empty struct takes no room on the stack either, but the procedure does return it, so
    // `None` is wrong.
    let info = proc("f", [], [named_struct("empty", [])]);
    assert_eq!(info.to_string(), "f() -> empty");
    assert_eq!(info.decode_result(&felts([1, 2])).unwrap().unwrap(), "empty()");
    assert!(info.returns_value());
    assert_eq!(info.output_felt_count(), Some(0));

    // Same for an array of length zero: `0 * 1 felt` is still a returned `[u32; 0]`.
    let info = proc("f", [], [Type::Array(Arc::new(ArrayType::new(Type::U32, 0)))]);
    assert_eq!(info.to_string(), "f() -> [u32; 0]");
    assert_eq!(info.decode_result(&felts([1, 2])).unwrap().unwrap(), "[]");

    // A codec type that occupies no felts is broken debug info, not a procedure that returns
    // nothing: `felt` must have exactly one field. The error says so instead of printing nothing.
    let info = proc("f", [], [named_struct("miden:base/core-types@1.0.0/felt", [])]);
    assert!(matches!(
        info.decode_result(&felts([1, 2])),
        Err(TypedError::MalformedResult { .. })
    ));
}

#[test]
fn an_array_of_elements_that_take_no_felts_is_not_decoded() {
    // Such an array reads nothing from the stack, so nothing limits its length. A manifest of a few
    // bytes asked for a million elements.
    let empty = named_struct("empty", []);
    for len in [5, 1_000_000] {
        let info = proc("f", [], [array_of(empty.clone(), len)]);
        assert_eq!(info.output_felt_count(), Some(0));
        assert!(matches!(info.decode_result(&[]), Err(TypedError::ZeroWidthArray { .. })));
    }

    // However deep it sits, so nesting does not multiply out either.
    let nested = proc("f", [], [array_of(array_of(empty.clone(), 1000), 1000)]);
    assert!(matches!(nested.decode_result(&[]), Err(TypedError::ZeroWidthArray { .. })));

    // An array of empty arrays is the same thing in other words.
    let of_empty_arrays = proc("f", [], [array_of(array_of(Type::U32, 0), 3)]);
    assert!(matches!(
        of_empty_arrays.decode_result(&[]),
        Err(TypedError::ZeroWidthArray { .. })
    ));

    // A length of zero is still fine, and so is the type on its own.
    assert_eq!(proc("f", [], [empty.clone()]).decode_result(&[]).unwrap().unwrap(), "empty()");
    assert_eq!(proc("f", [], [array_of(empty, 0)]).decode_result(&[]).unwrap().unwrap(), "[]");
    assert_eq!(
        proc("f", [], [array_of(Type::U32, 0)]).decode_result(&[]).unwrap().unwrap(),
        "[]"
    );

    // An array whose elements do take felts still stops at its own length instead of eating the
    // rest of the stack.
    let info = proc("f", [], [array_of(Type::U32, 3)]);
    assert_eq!(info.decode_result(&felts([7, 8, 9, 10])).unwrap().unwrap(), "[7, 8, 9]");

    // Elements with fields of their own read the same way: four felts, two points.
    let info = proc("f", [], [array_of(point_ty(), 2)]);
    assert_eq!(
        info.decode_result(&felts([1, 2, 3, 4])).unwrap().unwrap(),
        "[point { x: 1, y: 2 }, point { x: 3, y: 4 }]"
    );
}

#[test]
fn a_result_that_cannot_be_decoded_names_the_procedure() {
    let info = proc("get-list", [], [Type::List(Arc::new(Type::U32))]);
    assert_eq!(
        info.decode_result(&felts([1])).unwrap_err().to_string(),
        "procedure 'get-list' returns a value that cannot be decoded"
    );
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
fn a_bool_is_the_felt_0_or_the_felt_1_and_nothing_else() {
    // The VM has no bool of its own: `true` is the felt 1 and `false` is the felt 0. A user may
    // type the word or the digit, in any case.
    let info = proc("f", [Type::I1], [Type::I1]);
    for token in ["true", "TRUE", "1"] {
        assert_eq!(info.encode_args(&[token]).unwrap(), felts([1]), "{token}");
    }
    for token in ["false", "False", "0"] {
        assert_eq!(info.encode_args(&[token]).unwrap(), felts([0]), "{token}");
    }
    assert!(matches!(info.encode_args(&["maybe"]), Err(TypedError::InvalidBool(_))));

    // A third value coming back is bad output, not a `true`. Reading every non-zero felt as `true`
    // would print a wrong result as a right one.
    assert_eq!(info.decode_result(&felts([0])).unwrap().unwrap(), "false");
    assert_eq!(info.decode_result(&felts([1])).unwrap().unwrap(), "true");
    assert!(matches!(
        info.decode_result(&felts([2])),
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
fn a_wide_integer_holds_its_low_limb_on_top_of_the_stack() {
    // `2^32 + 7` tells the two limb orders apart, which no all-ones value can do. The compiler
    // pushes the high limb first in `push_u64` (`codegen/masm/src/emit/int64.rs`), so the low limb
    // ends up on top. miden-debug reads a real run back the same way: `FromMidenRepr for u64` in
    // `crates/engine/src/felt.rs` takes `lo | (hi << 32)` from `felts[0]` and `felts[1]`.
    let info = proc("f", [Type::U64], [Type::U64]);
    assert_eq!(info.encode_args(&["4294967303"]).unwrap(), felts([7, 1]));
    assert_eq!(info.decode_result(&felts([7, 1])).unwrap().unwrap(), "4294967303u64");

    // Why a test pins the order, and not only a round trip: swapped, the same two felts are
    // `7 * 2^32 + 1`. That is an ordinary `u64`, and it would print without a word.
    assert_eq!(info.decode_result(&felts([1, 7])).unwrap().unwrap(), "30064771073u64");
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
