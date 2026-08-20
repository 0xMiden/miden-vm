//! Proc macros for serialization round-trip testing in Miden VM.
extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{ToTokens, quote};
use syn::{AttributeArgs, Ident, Item, Lit, Meta, MetaList, NestedMeta, Type, parse_macro_input};

/// Generates a property test which round-trips arbitrary values through
/// `Serializable::to_bytes` and `Deserializable::read_from_bytes`.
///
/// Generic types can be supplied with one or more `types(...)` arguments:
/// ```rust
/// # use miden_test_serialization_macros::serialization_test;
/// # use proptest_derive::Arbitrary;
/// #[serialization_test(types(u64, "Vec<u64>"), types(u32, bool))]
/// #[derive(Debug, PartialEq, Arbitrary)]
/// struct Generic<T1, T2> {
///     t1: T1,
///     t2: T2,
/// }
/// ```
#[proc_macro_attribute]
pub fn serialization_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as Item);

    let name = match &input {
        Item::Type(item) => &item.ident,
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
        let test_name =
            Ident::new(&format!("test_serialization_roundtrip_{name}_{i}"), Span::mixed_site());
        let test = quote! {
            #[cfg(all(feature = "arbitrary", test))]
            proptest::proptest!{
                #![proptest_config(proptest::test_runner::Config::with_cases(100))]
                #[test]
                fn #test_name(obj in proptest::prelude::any::#ty()) {
                    let bytes = obj.to_bytes();
                    let deser = #ty::read_from_bytes(&bytes).unwrap();
                    proptest::prop_assert_eq!(obj, deser);
                }
            }
        };

        output = quote! {
            #output
            #test
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
