//! Proc macros for serialization round-trip testing in Miden VM.
extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::{ToTokens, quote};
use syn::{
    AttributeArgs, Ident, Item, Lit, Meta, MetaList, MetaNameValue, NestedMeta, Path, Type,
    parse_macro_input,
};

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

/// Generates a property test which round-trips arbitrary values through their MASM text form.
///
/// Each value is printed, parsed back with the function given in `parse`, and compared with the
/// original. `parse` must name a function `fn(&str) -> Result<T, E>` where `E: Debug`; it is
/// typically an adapter that wraps the printed text in a containing module and extracts the
/// parsed value again.
///
/// Optional arguments:
/// * `print`: a function `fn(&T) -> String`, defaults to `ToString::to_string`.
/// * `eq`: a function `fn(&T, &T) -> bool` for types whose `PartialEq` does not match the meaning
///   of the text, e.g. because printing normalizes the value. Defaults to `PartialEq`.
/// * `accept`: a function `fn(&str) -> bool` which rejects printed values that fall outside the
///   syntax, for generators that produce more values than the syntax can express.
///
/// ```rust
/// # use miden_test_serialization_macros::text_roundtrip_test;
/// # use proptest_derive::Arbitrary;
/// fn parse_flag(source: &str) -> Result<Flag, String> {
///     source.parse::<bool>().map(Flag).map_err(|err| err.to_string())
/// }
///
/// #[text_roundtrip_test(parse = "parse_flag")]
/// #[derive(Debug, PartialEq, Arbitrary)]
/// struct Flag(bool);
///
/// impl core::fmt::Display for Flag {
///     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
///         write!(f, "{}", self.0)
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn text_roundtrip_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as Item);

    let name = match &input {
        Item::Type(item) => &item.ident,
        Item::Struct(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        _ => panic!("This macro only works on structs and enums"),
    };

    // Parse arguments.
    let mut parse = None;
    let mut print = None;
    let mut eq = None;
    let mut accept = None;
    for arg in args {
        match arg {
            NestedMeta::Meta(Meta::NameValue(MetaNameValue {
                path, lit: Lit::Str(value), ..
            })) => {
                let func: Path = value.parse().expect("expected a function path");
                match path.get_ident() {
                    Some(id) if *id == "parse" => parse = Some(func),
                    Some(id) if *id == "print" => print = Some(func),
                    Some(id) if *id == "eq" => eq = Some(func),
                    Some(id) if *id == "accept" => accept = Some(func),
                    _ => panic!("invalid attribute {path:?}"),
                }
            },

            _ => panic!("invalid argument {arg:?}"),
        }
    }

    let parse = parse.expect("missing `parse` argument");
    let print = match print {
        Some(print) => quote!(#print(&obj)),
        None => quote!(::alloc::string::ToString::to_string(&obj)),
    };
    // Rejected values do not count as cases, so allow enough rejects for generators whose values
    // are mostly outside the syntax.
    let config = if accept.is_some() {
        quote!(proptest::test_runner::Config {
            max_global_rejects: 65536,
            ..proptest::test_runner::Config::with_cases(100)
        })
    } else {
        quote!(proptest::test_runner::Config::with_cases(100))
    };
    let accept = accept.map(|accept| quote!(proptest::prop_assume!(#accept(&text));));
    let check = match eq {
        Some(eq) => quote! {
            proptest::prop_assert!(#eq(&obj, &parsed), "{:?} was printed as {:?} and parsed as {:?}", obj, text, parsed);
        },
        None => quote! {
            proptest::prop_assert_eq!(&obj, &parsed, "printed as {:?}", text);
        },
    };

    let test_name = Ident::new(&format!("test_text_roundtrip_{name}"), Span::mixed_site());
    let output = quote! {
        #input

        #[cfg(all(feature = "arbitrary", test))]
        proptest::proptest!{
            #![proptest_config(#config)]
            #[test]
            fn #test_name(obj in proptest::prelude::any::<#name>()) {
                let text = #print;
                #accept
                let parsed: #name = match #parse(&text) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        return Err(proptest::test_runner::TestCaseError::fail(::alloc::format!(
                            "{:?} was printed as {:?}, which failed to parse: {:?}",
                            obj, text, err
                        )));
                    },
                };
                #check
            }
        }
    };

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
