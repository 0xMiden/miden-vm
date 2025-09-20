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
/// For testing generic types, use the `types(...)` attribute to list type parameters for testing,
/// separated by commas. For complex types (e.g., ones where type parameters have their own
/// parameters), enclose them in quotation marks. To test different combinations of type parameters,
/// `types` can be used multiple times.
///
/// # Example
/// ```
/// use miden_serde_test_macros::serde_test;
/// use proptest_derive::Arbitrary;
/// use serde::{Deserialize, Serialize};
///
/// // The macro derives serialization tests using an arbitrary instance.
/// #[serde_test(types(u64, "Vec<u64>"), types(u32, bool))]
/// #[derive(Debug, Default, PartialEq, Arbitrary, Serialize, Deserialize)]
/// struct Generic<T1, T2> {
///     t1: T1,
///     t2: T2,
/// }
/// ```
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
    for arg in args {
        match arg {
            // List arguments (as in #[serde_test(arg(val))])
            NestedMeta::Meta(Meta::List(MetaList { path, nested, .. })) => match path.get_ident() {
                Some(id) if *id == "types" => {
                    let params = nested.iter().map(parse_type).collect::<Vec<_>>();
                    types.push(quote!(<#name<#(#params),*>>));
                },
                _ => panic!("invalid attribute {:?}", path),
            },

            _ => panic!("invalid argument {:?}", arg),
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
        let serde_test = {
            let test_name =
                Ident::new(&format!("test_serde_roundtrip_{}_{}", name, i), Span::mixed_site());
            quote! {
                #[cfg(all(feature = "serde", feature = "arbitrary", test))]
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
        };

        output = quote! {
            #output
            #serde_test
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
