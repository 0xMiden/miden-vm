//! Proc macros for serde roundtrip testing in Miden VM
//!
//! This crate provides the `serde_test` macro for generating round-trip serialization tests.
extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{ToTokens, quote};
use syn::{AttributeArgs, Ident, Item, Lit, Meta, MetaList, NestedMeta, Type, parse_macro_input};

/// This macro is used to generate round-trip serialization tests.
///
/// By appending `serde_test` to a struct or enum definition, you automatically derive
/// serialization tests that employ Serde for round-trip testing. The procedure in the generated
/// tests is:
/// 1. Instantiate the type being tested
/// 2. Serialize the instance, ensuring the operation's success
/// 3. Deserialize the serialized data, comparing the resulting instance with the original one
///
/// The type being tested must meet the following requirements:
/// * Implementations of `Debug` and `PartialEq` traits
/// * Implementation of `Arbitrary` trait
/// * Implementations of `Serialize` and `DeserializeOwned` traits
///
/// When using the winter_serde annotation, the type furthermore must implement the
/// Winterfell `Serializable` and `Deserializable` traits.
///
/// # Configuration Attributes
///
/// The macro supports configuration attributes to control test generation:
///
/// | Attribute   | Type | Default | Purpose | Features Required |
/// |-------------|------|---------|---------|-------------------|
/// | `serde_test` | `bool` | `true` | Generate standard Serde round-trip tests | `arbitrary`, `serde`, `test` |
/// | `winter_serde` | `bool` | `false` | Generate Winterfell-style round-trip tests | `arbitrary`, `test` |
/// | `types(...)` | - | none | Specify type parameters for generics | - |
///
/// ## Usage Examples
///
/// Default (Serde tests only):
/// ```rust
/// # use miden_serde_test_macros::serde_test;
/// # use proptest_derive::Arbitrary;
/// # use serde::{Deserialize, Serialize};
/// #[serde_test]
/// #[derive(Debug, PartialEq, Arbitrary, Serialize, Deserialize)]
/// struct Simple {
///     value: u64,
/// }
/// ```
///
/// Winterfell tests only:
/// ```rust
/// # use miden_serde_test_macros::serde_test;
/// # use proptest_derive::Arbitrary;
/// #[serde_test(winter_serde(true), serde_test(false))]
/// #[derive(Debug, PartialEq, Arbitrary)]
/// struct WinterTest {
///     data: [u8; 32],
/// }
/// ```
///
/// Both test types:
/// ```rust
/// # use miden_serde_test_macros::serde_test;
/// # use proptest_derive::Arbitrary;
/// # use serde::{Deserialize, Serialize};
/// #[serde_test(winter_serde(true))]
/// #[derive(Debug, PartialEq, Arbitrary, Serialize, Deserialize)]
/// struct DualTest {
///     name: u32,
///     value: u64,
/// }
/// ```
///
/// Generic types:
/// ```rust
/// # use miden_serde_test_macros::serde_test;
/// # use proptest_derive::Arbitrary;
/// # use serde::{Deserialize, Serialize};
/// #[serde_test(types(u64, "Vec<u64>"), types(u32, bool))]
/// #[derive(Debug, PartialEq, Arbitrary, Serialize, Deserialize)]
/// struct Generic<T1, T2> {
///     t1: T1,
///     t2: T2,
/// }
/// ```
///
/// # Generated Test Names
/// - Serde tests: `test_serde_roundtrip_{struct_name}_{index}`
/// - Winter tests: `test_winter_serde_roundtrip_{struct_name}_{index}`
#[proc_macro_attribute]
pub fn serde_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as Item);

    let name = match &input {
        Item::Struct(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        _ => panic!("This macro only works on structs and enums"),
    };

    // Parse arguments.
    let mut types = Vec::new();
    let mut winter_serde = false;
    let mut serde_test = true;
    for arg in args {
        match arg {
            // List arguments (as in #[serde_test(arg(val))])
            NestedMeta::Meta(Meta::List(MetaList { path, nested, .. })) => match path.get_ident() {
                Some(id) if *id == "types" => {
                    let params = nested.iter().map(parse_type).collect::<Vec<_>>();
                    types.push(quote!(<#name<#(#params),*>>));
                },

                Some(id) if *id == "winter_serde" => {
                    assert!(nested.len() == 1, "winter_serde attribute takes 1 argument");
                    match &nested[0] {
                        NestedMeta::Lit(Lit::Bool(b)) => {
                            winter_serde = b.value;
                        },
                        _ => panic!("winter_serde argument must be a boolean"),
                    }
                },

                Some(id) if *id == "serde_test" => {
                    assert!(nested.len() == 1, "serde_test attribute takes 1 argument");
                    match &nested[0] {
                        NestedMeta::Lit(Lit::Bool(b)) => {
                            serde_test = b.value;
                        },
                        _ => panic!("serde_test argument must be a boolean"),
                    }
                },

                _ => panic!("invalid attribute {path:?}"),
            },

            _ => panic!("invalid argument {arg:?}"),
        }
    }

    if types.is_empty() {
        // If no explicit type parameters were given for us to test with, assume the type under test
        // takes no type parameters.
        types.push(quote!(<#name>));
    }

    let mut output = quote! {
        #input
    };

    for (i, ty) in types.into_iter().enumerate() {
        let serde_test = if serde_test {
            let test_name =
                Ident::new(&format!("test_serde_roundtrip_{}_{}", name, i), Span::mixed_site());
            quote! {
                #[cfg(all(feature = "arbitrary", feature = "serde", test))]
                proptest::proptest!{
                    #[test]
                    fn #test_name(obj in proptest::prelude::any::#ty()) {
                        use alloc::string::ToString;
                        let buf = serde_json::to_vec(&obj)
                            .map_err(|err| proptest::test_runner::TestCaseError::fail(err.to_string()))?;
                        proptest::prop_assert_eq!(
                            obj,
                            serde_json::from_slice::#ty(&buf)
                                .map_err(|err| proptest::test_runner::TestCaseError::fail(err.to_string()))?
                        );
                    }
                }
            }
        } else {
            quote! {}
        };

        let winter_test = if winter_serde {
            let test_name =
                Ident::new(&format!("test_winter_serde_roundtrip_{name}_{i}"), Span::mixed_site());
            quote! {
                #[cfg(all(feature = "arbitrary", test))]
                proptest::proptest!{
                    #[test]
                    fn #test_name(obj in proptest::prelude::any::#ty()) {
                        let bytes = obj.to_bytes();
                        let deser = #ty::read_from_bytes(&bytes).unwrap();
                        proptest::prop_assert_eq!(obj, deser);
                    }
                }
            }
        } else {
            quote! {}
        };

        output = quote! {
            #output
            #serde_test
            #winter_test
        };
    }

    output.into()
}

fn parse_type(m: &NestedMeta) -> Type {
    match m {
        NestedMeta::Lit(Lit::Str(s)) => syn::parse_str(&s.value()).unwrap(),
        NestedMeta::Meta(Meta::Path(p)) => syn::parse2(p.to_token_stream()).unwrap(),
        _ => {
            panic!("expected type");
        },
    }
}
