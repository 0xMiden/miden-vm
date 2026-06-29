//! Typed view over a [`Package`]'s debug sections: signature rendering, argument encoding,
//! and result decoding for a single procedure.
//!
//! The debug sections carry the high-level (Component Model/WIT) signature of each exported
//! procedure, while the VM stack only carries felts. [`TypedProcInfo`] bridges the two: it
//! renders the typed signature for display, lowers argument tokens into the flat felt vector the
//! procedure expects on the stack, and lifts the felts a procedure returns back into a typed
//! rendering.
//!
//! WIT scalar types that encode from a single token (e.g. `word`, `account-id`) are handled by
//! [`WitScalarCodec`]s. The `word` codec is built in; codecs for types validated with rules
//! defined outside this crate are registered by the consumer via
//! [`TypedProcInfo::with_scalar_codec`].

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use miden_core::Felt;

use self::{
    decode::{decode_value, stack_felt_count},
    encode::{arg_token_count, encode_tokens},
    lookup::{find_debug_fn, proc_display_name, read_debug_sections},
    signature::format_type,
};
use super::{
    DebugFunctionInfo, DebugFunctionsSection, DebugPrimitiveType, DebugTypeIdx, DebugTypeInfo,
    DebugTypesSection,
};
use crate::{Package, PackageDebugInfoError};

mod codec;
mod decode;
mod encode;
mod errors;
mod lookup;
mod signature;
mod sizing;

/// Maximum recursion depth when walking the type graph in the encode/decode/sizing helpers.
///
/// The [`DebugTypesSection`] comes from a package and is not checked for cycles, so a cyclic
/// (`A -> B -> A`) or very deep type could otherwise recurse until the stack overflows.
pub(super) const MAX_TYPE_DEPTH: usize = 64;

/// The biggest unsigned value that fits in `bits` bits. Also used as a mask for the low `bits`
/// bits. Both encode and decode use it.
pub(super) fn max_for_bits(bits: u32) -> u128 {
    if bits >= 128 { u128::MAX } else { (1u128 << bits) - 1 }
}

pub use self::{
    codec::{WitScalarCodec, WordCodec},
    errors::TypedDebugInfoError,
};

// TYPED PROCEDURE INFO
// ================================================================================================

/// The typed signature of one procedure, resolved from a [`Package`]'s debug sections.
///
/// Construct with [`Self::from_package`]; encode arguments by walking [`Self::param_type_indices`]
/// through [`Self::encode_arg`], and render results with [`Self::decode_result`].
/// The [`fmt::Display`] impl renders the signature, e.g. `get-count() -> Felt`.
pub struct TypedProcInfo {
    /// The package's debug type table; all type indices below point into it.
    types: DebugTypesSection,
    /// Display name of the procedure (bare kebab-case leaf, e.g. `get-count`).
    name: String,
    /// Type of the procedure's return value, if it has one.
    return_type_idx: Option<DebugTypeIdx>,
    /// The procedure's parameters, in declaration order.
    params: Vec<TypedParam>,
    /// Registered WIT scalar codecs, matched by bare type name during encoding and decoding.
    codecs: Vec<Box<dyn WitScalarCodec>>,
}

/// One parameter of a procedure: its display name and its type in the debug type table.
struct TypedParam {
    name: String,
    type_idx: DebugTypeIdx,
}

impl TypedProcInfo {
    /// Resolves the typed signature of `procedure_name` from `package`'s debug sections.
    ///
    /// `Ok(None)` if the package has no debug info or no entry for `procedure_name`; `Err` if the
    /// package's debug sections are present but untrusted or malformed.
    ///
    /// The returned info has the built-in [`WordCodec`] registered; add further scalar codecs
    /// with [`Self::with_scalar_codec`].
    pub fn from_package(
        package: &Package,
        procedure_name: &str,
    ) -> Result<Option<Self>, PackageDebugInfoError> {
        let Some((funcs, types)) = read_debug_sections(package)? else {
            return Ok(None);
        };
        let Some(func) = find_debug_fn(&funcs, procedure_name) else {
            return Ok(None);
        };
        let name = func_display_name(func, &funcs, procedure_name);
        let (return_type_idx, fallback_param_types) = extract_signature_types(func, &types);
        let params = build_params(&fallback_param_types);
        Ok(Some(Self {
            types,
            name,
            return_type_idx,
            params,
            codecs: alloc::vec![Box::new(WordCodec)],
        }))
    }

    /// Registers a [`WitScalarCodec`], letting it override the generic struct handling for the
    /// WIT type it names. A codec registered earlier wins on a name collision.
    #[must_use]
    pub fn with_scalar_codec(mut self, codec: Box<dyn WitScalarCodec>) -> Self {
        self.codecs.push(codec);
        self
    }

    /// Number of argument tokens the procedure expects, summed over its parameters
    /// (codec-handled scalars like `word` and `account-id` take one token each; other structs
    /// take one per leaf field). `None` if any parameter has no statically-known token count
    /// (e.g. a dynamic array).
    pub fn expected_arg_count(&self) -> Option<usize> {
        let view = self.view();
        self.params.iter().map(|p| arg_token_count(&view, p.type_idx)).sum()
    }

    /// Type-table indices of the procedure's parameters, in declaration order. Pair with
    /// [`Self::encode_arg`] to encode argument tokens parameter by parameter; the orchestration
    /// (iterating parameters and validating the total argument count) is left to the caller, since
    /// turning user-supplied strings into arguments is an application concern.
    pub fn param_type_indices(&self) -> Vec<DebugTypeIdx> {
        self.params.iter().map(|p| p.type_idx).collect()
    }

    /// Encodes the argument tokens for the parameter (or any type) at `idx` into its stack felts,
    /// consuming exactly the tokens that type needs from `tokens` and using the registered scalar
    /// codecs. Codec-handled scalars (`word`, `account-id`, ..) each parse from a single token;
    /// other structs expect one token per leaf field.
    ///
    /// Exposed per parameter rather than as a whole-signature call so the caller owns the argument
    /// policy — how many are expected (see [`Self::expected_arg_count`] and
    /// [`Self::param_type_indices`]) and how a wrong count is reported — since turning
    /// user-supplied strings into arguments is an application concern.
    pub fn encode_arg<I: Iterator<Item = String>>(
        &self,
        tokens: &mut I,
        idx: DebugTypeIdx,
    ) -> Result<Vec<Felt>, TypedDebugInfoError> {
        encode_tokens(tokens, &self.view(), idx)
    }

    /// Number of felts the procedure pushes on the stack for its return value. `Some(0)` if
    /// there is no return type; `None` if the return type has no statically-known felt size.
    pub fn output_felt_count(&self) -> Option<usize> {
        match self.return_type_idx {
            Some(idx) => stack_felt_count(&self.view(), idx),
            None => Some(0),
        }
    }

    /// Formats the procedure's return value as a string, reading its felts from the start of
    /// `stack`. Returns `None` if there is no return type, its felt size can't be determined,
    /// or `stack` is too short to hold it.
    pub fn decode_result(&self, stack: &[Felt]) -> Option<String> {
        let return_idx = self.return_type_idx?;
        let view = self.view();
        let n = stack_felt_count(&view, return_idx)?;
        if n == 0 || n > stack.len() {
            return None;
        }
        let slice = &stack[..n];
        let return_ty = self.types.get_type(return_idx);
        let (rendered, rest) = decode_value(slice, &view, return_idx)?;
        if !rest.is_empty() {
            return None;
        }
        Some(match return_ty {
            Some(DebugTypeInfo::Primitive(p)) => {
                format!("{}({rendered})", format!("{p:?}").to_lowercase())
            },
            _ => rendered,
        })
    }

    fn view(&self) -> TypedView<'_> {
        TypedView { types: &self.types, codecs: &self.codecs }
    }
}

/// Renders the typed signature, e.g. `take-account-id(id: account-id) -> account-id`.
impl fmt::Display for TypedProcInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(", self.name)?;
        for (i, p) in self.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {}", p.name, format_type(&self.types, p.type_idx, 0))?;
        }
        write!(f, ")")?;
        if let Some(idx) = self.return_type_idx {
            write!(f, " -> {}", format_type(&self.types, idx, 0))?;
        }
        Ok(())
    }
}

// TYPED VIEW
// ================================================================================================

/// Borrowed view threaded through the encode/decode helpers: the debug type table plus the
/// registered scalar codecs.
struct TypedView<'a> {
    types: &'a DebugTypesSection,
    codecs: &'a [Box<dyn WitScalarCodec>],
}

impl TypedView<'_> {
    /// The registered codec for the bare WIT type name `short`, if any.
    fn codec_for(&self, short: &str) -> Option<&dyn WitScalarCodec> {
        self.codecs.iter().find(|c| c.wit_name() == short).map(AsRef::as_ref)
    }
}

// HELPERS
// ================================================================================================

fn func_display_name(
    func: &DebugFunctionInfo,
    funcs: &DebugFunctionsSection,
    fallback: &str,
) -> String {
    funcs
        .strings
        .get(func.name_idx as usize)
        .map_or_else(|| fallback.to_string(), |s| proc_display_name(s.as_ref()).to_string())
}

/// `(return_type, param_types)` from the `Function`-typed debug entry, or `(None, vec![])` if
/// the entry has no Function type. A `Void` return type is normalized to `None`
fn extract_signature_types(
    func: &DebugFunctionInfo,
    types: &DebugTypesSection,
) -> (Option<DebugTypeIdx>, Vec<DebugTypeIdx>) {
    match func.type_idx.and_then(|i| types.get_type(i)) {
        Some(DebugTypeInfo::Function { return_type_idx, param_type_indices }) => {
            let return_type_idx = return_type_idx.filter(|i| {
                !matches!(
                    types.get_type(*i),
                    Some(DebugTypeInfo::Primitive(DebugPrimitiveType::Void))
                )
            });
            (return_type_idx, param_type_indices.clone())
        },
        _ => (None, Vec::new()),
    }
}

/// Builds the parameter list from the function-type signature: one [`TypedParam`] per positional
/// index, named `arg1`, `arg2`, .... Returns an empty list when the debug entry has no `Function`
/// type, which (since argument variables are no longer attached to functions) is the only source of
/// parameter info.
fn build_params(fallback_indices: &[DebugTypeIdx]) -> Vec<TypedParam> {
    fallback_indices
        .iter()
        .enumerate()
        .map(|(i, t)| TypedParam {
            name: format!("arg{}", i + 1),
            type_idx: *t,
        })
        .collect()
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::{sync::Arc, vec};

    use super::{
        super::{DebugFieldInfo, DebugPrimitiveType, DebugTypeInfo},
        *,
    };

    fn make_proc(
        types: DebugTypesSection,
        name: &str,
        return_type_idx: Option<DebugTypeIdx>,
        params: Vec<TypedParam>,
    ) -> TypedProcInfo {
        TypedProcInfo {
            types,
            name: name.to_string(),
            return_type_idx,
            params,
            codecs: vec![Box::new(WordCodec)],
        }
    }

    fn felt(v: u64) -> Felt {
        Felt::try_from(v).unwrap()
    }

    /// Encodes all of `proc`'s arguments by walking its parameters through `encode_tokens`, the
    /// same way a consumer (e.g. the CLI) orchestrates encoding.
    fn encode_all(proc: &TypedProcInfo, tokens: &[&str]) -> Vec<Felt> {
        let mut iter = tokens.iter().map(ToString::to_string);
        let mut felts = Vec::new();
        for idx in proc.param_type_indices() {
            felts.extend(proc.encode_arg(&mut iter, idx).unwrap());
        }
        assert!(iter.next().is_none(), "encode_all must consume every token");
        felts
    }

    /// Minimal stand-in codec for exercising registration and the struct-override path. The real
    /// protocol-aware `account-id` codec lives downstream in the CLI (`miden-cli`'s
    /// `AccountIdCodec`); this crate can't depend on it, so the tests use this stub. It only does
    /// enough to be observable: one `<a>:<b>` token in, two felts out.
    struct TestIdCodec;

    impl WitScalarCodec for TestIdCodec {
        fn wit_name(&self) -> &str {
            "account-id"
        }

        fn felt_count(&self) -> usize {
            2
        }

        fn encode(&self, token: &str) -> Result<Vec<Felt>, TypedDebugInfoError> {
            let (a, b) = token.split_once(':').expect("test tokens are always `<a>:<b>`");
            Ok(vec![felt(a.parse().unwrap()), felt(b.parse().unwrap())])
        }

        fn decode(&self, felts: &[Felt]) -> Option<String> {
            let [a, b, ..] = felts else { return None };
            Some(format!("account-id({}:{})", a.as_canonical_u64(), b.as_canonical_u64()))
        }
    }

    /// A two-felt struct named like the WIT `account-id`, for codec dispatch tests.
    fn account_id_type(types: &mut DebugTypesSection) -> DebugTypeIdx {
        let felt_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        let aid_name = types.add_string(Arc::from("miden:base/core-types@1.0.0/account-id"));
        let prefix_n = types.add_string(Arc::from("prefix"));
        let suffix_n = types.add_string(Arc::from("suffix"));
        types.add_type(DebugTypeInfo::Struct {
            name_idx: aid_name,
            size: 16,
            fields: vec![
                DebugFieldInfo {
                    name_idx: prefix_n,
                    type_idx: felt_t,
                    offset: 0,
                },
                DebugFieldInfo {
                    name_idx: suffix_n,
                    type_idx: felt_t,
                    offset: 8,
                },
            ],
        })
    }

    /// A four-felt struct named like the WIT `word`.
    fn word_struct_type(types: &mut DebugTypesSection) -> DebugTypeIdx {
        let felt_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        let f_n = types.add_string(Arc::from("f"));
        let word_name = types.add_string(Arc::from("miden:base/core-types@1.0.0/word"));
        types.add_type(DebugTypeInfo::Struct {
            name_idx: word_name,
            size: 32,
            fields: (0..4)
                .map(|i| DebugFieldInfo {
                    name_idx: f_n,
                    type_idx: felt_t,
                    offset: i * 8,
                })
                .collect(),
        })
    }

    #[test]
    fn felt_roundtrip() {
        let mut types = DebugTypesSection::new();
        let felt_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        let proc = make_proc(
            types,
            "take-felt",
            Some(felt_idx),
            vec![TypedParam {
                name: "f".to_string(),
                type_idx: felt_idx,
            }],
        );

        let encoded = encode_all(&proc, &["42"]);
        assert_eq!(encoded, vec![felt(42)]);

        assert_eq!(proc.decode_result(&[felt(42)]).as_deref(), Some("felt(42)"));
        assert_eq!(proc.to_string(), "take-felt(f: Felt) -> Felt");
    }

    #[test]
    fn bool_roundtrip() {
        let mut types = DebugTypesSection::new();
        let bool_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Bool));
        let proc = make_proc(
            types,
            "take-bool",
            Some(bool_idx),
            vec![TypedParam {
                name: "b".to_string(),
                type_idx: bool_idx,
            }],
        );

        assert_eq!(encode_all(&proc, &["true"]), vec![felt(1)]);
        assert_eq!(encode_all(&proc, &["false"]), vec![felt(0)]);

        assert_eq!(proc.decode_result(&[felt(1)]).as_deref(), Some("bool(true)"));
        assert_eq!(proc.decode_result(&[felt(0)]).as_deref(), Some("bool(false)"));
        assert_eq!(proc.decode_result(&[felt(2)]), None);
        assert_eq!(proc.to_string(), "take-bool(b: Bool) -> Bool");
    }

    #[test]
    fn u32_roundtrip() {
        let mut types = DebugTypesSection::new();
        let u32_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
        let proc = make_proc(
            types,
            "take-u32",
            Some(u32_idx),
            vec![TypedParam { name: "n".to_string(), type_idx: u32_idx }],
        );

        let encoded = encode_all(&proc, &["4294967295"]);
        assert_eq!(encoded, vec![felt(4_294_967_295)]);

        assert_eq!(proc.decode_result(&[felt(4_294_967_295)]).as_deref(), Some("u32(4294967295)"));
        assert_eq!(proc.to_string(), "take-u32(n: U32) -> U32");
    }

    #[test]
    fn sub_word_int_out_of_range_is_rejected() {
        // Types narrower than their 32-bit limb must reject a felt that doesn't fit the declared
        // width instead of masking it down (300 & 0xFF = 44), which would hide malformed output.
        let u8_proc = prim_proc(DebugPrimitiveType::U8, "take-u8");
        assert_eq!(u8_proc.decode_result(&[felt(255)]).as_deref(), Some("u8(255)"));
        assert_eq!(u8_proc.decode_result(&[felt(300)]), None);

        let i8_proc = prim_proc(DebugPrimitiveType::I8, "take-i8");
        // 0xFF is the in-range two's-complement encoding of -1; 300 is out of range.
        assert_eq!(i8_proc.decode_result(&[felt(0xff)]).as_deref(), Some("i8(-1)"));
        assert_eq!(i8_proc.decode_result(&[felt(300)]), None);

        let u16_proc = prim_proc(DebugPrimitiveType::U16, "take-u16");
        assert_eq!(u16_proc.decode_result(&[felt(65_535)]).as_deref(), Some("u16(65535)"));
        assert_eq!(u16_proc.decode_result(&[felt(65_536)]), None);
    }

    #[test]
    fn u64_roundtrip() {
        let mut types = DebugTypesSection::new();
        let u64_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U64));
        let proc = make_proc(
            types,
            "take-u64",
            Some(u64_idx),
            vec![TypedParam { name: "n".to_string(), type_idx: u64_idx }],
        );

        // A `u64` occupies two 32-bit limbs, least-significant first (the stdlib layout).
        let v: u64 = 1_234_567_890_123;
        let lo = felt(v & 0xffff_ffff);
        let hi = felt(v >> 32);
        assert_eq!(encode_all(&proc, &["1234567890123"]), vec![lo, hi]);
        assert_eq!(proc.decode_result(&[lo, hi]).as_deref(), Some("u64(1234567890123)"));
        assert_eq!(proc.output_felt_count(), Some(2));
        assert_eq!(proc.to_string(), "take-u64(n: U64) -> U64");
    }

    /// Helper: a single-primitive `take-x` proc whose param and return type are `p`.
    fn prim_proc(p: DebugPrimitiveType, name: &str) -> TypedProcInfo {
        let mut types = DebugTypesSection::new();
        let idx = types.add_type(DebugTypeInfo::Primitive(p));
        make_proc(
            types,
            name,
            Some(idx),
            vec![TypedParam { name: "x".to_string(), type_idx: idx }],
        )
    }

    #[test]
    fn i32_signed_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::I32, "take-i32");
        // -1 is stored as the 32-bit two's-complement limb 0xFFFFFFFF.
        let neg_one = felt(0xffff_ffff);
        assert_eq!(encode_all(&proc, &["-1"]), vec![neg_one]);
        assert_eq!(proc.decode_result(&[neg_one]).as_deref(), Some("i32(-1)"));
        // Positive values round-trip unchanged.
        assert_eq!(encode_all(&proc, &["42"]), vec![felt(42)]);
        assert_eq!(proc.decode_result(&[felt(42)]).as_deref(), Some("i32(42)"));
    }

    #[test]
    fn i64_signed_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::I64, "take-i64");
        // -2 across two limbs: low = 0xFFFFFFFE, high = 0xFFFFFFFF.
        let encoded = encode_all(&proc, &["-2"]);
        assert_eq!(encoded, vec![felt(0xffff_fffe), felt(0xffff_ffff)]);
        assert_eq!(proc.decode_result(&encoded).as_deref(), Some("i64(-2)"));
    }

    #[test]
    fn u128_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::U128, "take-u128");
        let v: u128 = (1u128 << 96) + (2u128 << 64) + (3u128 << 32) + 4;
        let encoded = encode_all(&proc, &[&v.to_string()]);
        assert_eq!(encoded, vec![felt(4), felt(3), felt(2), felt(1)]);
        assert_eq!(proc.output_felt_count(), Some(4));
        assert_eq!(proc.decode_result(&encoded).as_deref(), Some(&*format!("u128({v})")));
    }

    #[test]
    fn i128_signed_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::I128, "take-i128");
        let encoded = encode_all(&proc, &["-1"]);
        // -1 is all-ones across four 32-bit limbs.
        assert_eq!(encoded, vec![felt(0xffff_ffff); 4]);
        assert_eq!(proc.decode_result(&encoded).as_deref(), Some("i128(-1)"));
    }

    #[test]
    fn f32_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::F32, "take-f32");
        let bits = 1.5f32.to_bits();
        let encoded = encode_all(&proc, &["1.5"]);
        // A 32-bit float fits in a single limb (one felt), not two.
        assert_eq!(encoded, vec![felt(bits as u64)]);
        assert_eq!(proc.output_felt_count(), Some(1));
        assert_eq!(proc.decode_result(&encoded).as_deref(), Some("f32(1.5)"));
    }

    #[test]
    fn f64_roundtrip() {
        let proc = prim_proc(DebugPrimitiveType::F64, "take-f64");
        let bits = 1.5f64.to_bits();
        let encoded = encode_all(&proc, &["1.5"]);
        assert_eq!(encoded, vec![felt(bits & 0xffff_ffff), felt(bits >> 32)]);
        assert_eq!(proc.decode_result(&encoded).as_deref(), Some("f64(1.5)"));
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        // A u32 token larger than u32::MAX must be rejected, not silently truncated into a felt.
        let u32_proc = prim_proc(DebugPrimitiveType::U32, "take-u32");
        let mut over = ["4294967296".to_string()].into_iter();
        assert!(matches!(
            u32_proc.encode_arg(&mut over, u32_proc.param_type_indices()[0]),
            Err(TypedDebugInfoError::IntOutOfRange { .. })
        ));

        // An i8 below its signed minimum is rejected too.
        let i8_proc = prim_proc(DebugPrimitiveType::I8, "take-i8");
        let mut under = ["-129".to_string()].into_iter();
        assert!(matches!(
            i8_proc.encode_arg(&mut under, i8_proc.param_type_indices()[0]),
            Err(TypedDebugInfoError::IntOutOfRange { .. })
        ));
    }

    #[test]
    fn two_args_encode_in_sequence() {
        // `(a: f32, b: u32)`: `b` must sit right after `a`'s single felt. When f32 wrongly took two
        // felts, `b` was pushed one slot down, so this guards that regression across two args.
        let mut types = DebugTypesSection::new();
        let f32_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::F32));
        let u32_idx = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::U32));
        let proc = make_proc(
            types,
            "take-two",
            None,
            vec![
                TypedParam { name: "a".to_string(), type_idx: f32_idx },
                TypedParam { name: "b".to_string(), type_idx: u32_idx },
            ],
        );

        // a -> the f32 bits (one felt), then b -> 7 (one felt).
        let bits = 1.5f32.to_bits();
        assert_eq!(encode_all(&proc, &["1.5", "7"]), vec![felt(bits as u64), felt(7)]);
    }

    #[test]
    fn registered_codec_overrides_struct_handling() {
        let mut types = DebugTypesSection::new();
        let aid_idx = account_id_type(&mut types);
        let proc = make_proc(
            types,
            "take-account-id",
            Some(aid_idx),
            vec![TypedParam {
                name: "id".to_string(),
                type_idx: aid_idx,
            }],
        )
        .with_scalar_codec(Box::new(TestIdCodec));

        let encoded = encode_all(&proc, &["7:42"]);
        assert_eq!(encoded, vec![felt(7), felt(42)]);

        assert_eq!(proc.decode_result(&encoded).as_deref(), Some("account-id(7:42)"));
        assert_eq!(proc.to_string(), "take-account-id(id: account-id) -> account-id");
    }

    #[test]
    fn unregistered_scalar_falls_back_to_field_encoding() {
        // Without the codec the same struct encodes field by field: two tokens, two felts.
        let mut types = DebugTypesSection::new();
        let aid_idx = account_id_type(&mut types);
        let proc = make_proc(
            types,
            "take-account-id",
            Some(aid_idx),
            vec![TypedParam {
                name: "id".to_string(),
                type_idx: aid_idx,
            }],
        );

        assert_eq!(proc.expected_arg_count(), Some(2));
        let encoded = encode_all(&proc, &["7", "42"]);
        assert_eq!(encoded, vec![felt(7), felt(42)]);
        assert_eq!(
            proc.decode_result(&encoded).as_deref(),
            Some("account-id(prefix=7, suffix=42)")
        );
    }

    #[test]
    fn word_struct_one_hex_token_roundtrips() {
        let mut types = DebugTypesSection::new();
        let word_t = word_struct_type(&mut types);
        let proc = make_proc(
            types,
            "take-word",
            Some(word_t),
            vec![TypedParam { name: "w".to_string(), type_idx: word_t }],
        );

        let hex = "0x0100000000000000020000000000000003000000000000000400000000000000";
        let encoded = encode_all(&proc, &[hex]);
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0].as_canonical_u64(), 1);
        assert_eq!(encoded[3].as_canonical_u64(), 4);

        assert_eq!(proc.decode_result(&encoded), Some(format!("word({hex})")));
        assert_eq!(proc.to_string(), "take-word(w: word) -> word");
    }

    /// Feeds exactly `arg_token_count` tokens, then checks `encode_tokens` reads all of them and
    /// produces `stack_felt_count` felts. Keeps the three functions in sync: a codec or special
    /// case added to one (e.g. `void`) but not the others fails here.
    fn assert_counts_consistent(view: &TypedView<'_>, idx: DebugTypeIdx, tokens: &[&str]) {
        let want_tokens = arg_token_count(view, idx).expect("static token count");
        assert_eq!(want_tokens, tokens.len(), "test must feed exactly the expected token count");

        let mut iter = tokens.iter().map(ToString::to_string);
        let felts = encode_tokens(&mut iter, view, idx).unwrap();
        assert!(iter.next().is_none(), "encode_tokens must consume every token");
        assert_eq!(
            Some(felts.len()),
            stack_felt_count(view, idx),
            "stack_felt_count must equal the felts encode_tokens produces"
        );
    }

    #[test]
    fn token_and_felt_counts_match_actual_consumption() {
        let mut types = DebugTypesSection::new();
        let felt_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        let word_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Word));
        let void_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void));
        let f_n = types.add_string(Arc::from("f"));

        let aid_t = account_id_type(&mut types);
        let word_struct_t = word_struct_type(&mut types);

        // A struct mixing a zero-token `void` field with a `felt` field.
        let mixed_name = types.add_string(Arc::from("pkg/mixed"));
        let mixed_t = types.add_type(DebugTypeInfo::Struct {
            name_idx: mixed_name,
            size: 8,
            fields: vec![
                DebugFieldInfo {
                    name_idx: f_n,
                    type_idx: void_t,
                    offset: 0,
                },
                DebugFieldInfo {
                    name_idx: f_n,
                    type_idx: felt_t,
                    offset: 0,
                },
            ],
        });

        let codecs: Vec<Box<dyn WitScalarCodec>> = vec![Box::new(WordCodec), Box::new(TestIdCodec)];
        let view = TypedView { types: &types, codecs: &codecs };

        let hex_word = "0x0100000000000000020000000000000003000000000000000400000000000000";

        assert_counts_consistent(&view, felt_t, &["7"]);
        assert_counts_consistent(&view, word_t, &[hex_word]);
        assert_counts_consistent(&view, void_t, &[]);
        assert_counts_consistent(&view, aid_t, &["7:42"]);
        assert_counts_consistent(&view, word_struct_t, &[hex_word]);
        assert_counts_consistent(&view, mixed_t, &["7"]);
    }

    #[test]
    fn anonymous_struct_falls_back_to_field_shape() {
        let mut types = DebugTypesSection::new();
        let felt_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Felt));
        let anon = types.add_string(Arc::from("<anon>"));
        let x = types.add_string(Arc::from("x"));
        let y = types.add_string(Arc::from("y"));
        let point = types.add_type(DebugTypeInfo::Struct {
            name_idx: anon,
            size: 8,
            fields: vec![
                DebugFieldInfo { name_idx: x, type_idx: felt_t, offset: 0 },
                DebugFieldInfo { name_idx: y, type_idx: felt_t, offset: 4 },
            ],
        });
        let proc = make_proc(
            types,
            "take-point",
            Some(point),
            vec![TypedParam { name: "p".to_string(), type_idx: point }],
        );

        assert_eq!(proc.to_string(), "take-point(p: {x: Felt, y: Felt}) -> {x: Felt, y: Felt}");
        assert_eq!(proc.decode_result(&[felt(3), felt(4)]).as_deref(), Some("{x=3, y=4}"));
    }

    /// A cyclic type graph (a struct field pointing back at the struct) must be rejected
    /// gracefully by the depth guard, not recursed into until the stack overflows. The debug
    /// sections are read from a package and are not validated to be acyclic.
    #[test]
    fn cyclic_type_is_rejected_without_stack_overflow() {
        let mut types = DebugTypesSection::new();
        let name = types.add_string(Arc::from("pkg/cyclic"));
        let f_n = types.add_string(Arc::from("f"));
        // The struct is the first type added, so it gets index 0; make its only field point at
        // itself.
        let self_ref = DebugTypeIdx::from(0);
        let idx = types.add_type(DebugTypeInfo::Struct {
            name_idx: name,
            size: 8,
            fields: vec![DebugFieldInfo {
                name_idx: f_n,
                type_idx: self_ref,
                offset: 0,
            }],
        });
        assert_eq!(idx, self_ref, "struct must be self-referential for this test");

        let codecs: Vec<Box<dyn WitScalarCodec>> = vec![Box::new(WordCodec)];
        let view = TypedView { types: &types, codecs: &codecs };

        assert_eq!(stack_felt_count(&view, idx), None);
        assert_eq!(arg_token_count(&view, idx), None);
        assert!(decode_value(&[felt(1)], &view, idx).is_none());
        let mut iter = core::iter::empty::<String>();
        assert!(matches!(
            encode_tokens(&mut iter, &view, idx),
            Err(TypedDebugInfoError::RecursionLimit)
        ));
    }

    /// An array of a zero-width element type (`void`) with a huge `count` occupies no felts and
    /// must terminate immediately rather than spin / pre-allocate billions of entries.
    #[test]
    fn huge_array_of_zero_width_elements_terminates() {
        let mut types = DebugTypesSection::new();
        let void_t = types.add_type(DebugTypeInfo::Primitive(DebugPrimitiveType::Void));
        let arr = types.add_type(DebugTypeInfo::Array {
            element_type_idx: void_t,
            count: Some(u32::MAX),
        });

        let codecs: Vec<Box<dyn WitScalarCodec>> = vec![Box::new(WordCodec)];
        let view = TypedView { types: &types, codecs: &codecs };

        assert_eq!(stack_felt_count(&view, arr), Some(0));

        let (_rendered, rest) = decode_value(&[], &view, arr).expect("decode must terminate");
        assert!(rest.is_empty());

        let mut iter = core::iter::empty::<String>();
        assert!(encode_tokens(&mut iter, &view, arr).expect("encode must terminate").is_empty());
    }
}
