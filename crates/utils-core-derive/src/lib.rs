//! Proc macro to derive enum dispatch trait implementations for Miden core utilities
//!
//! This crate provides proc macros for enums that need to dispatch trait method calls to their
//! variants:
//! - `MastNodeExt` derive macro: generates MastNodeExt trait implementations for enums
//! - `MastForestContributor` derive macro: generates MastForestContributor trait implementations
//!   for enums
//!
//! This crate provides enum dispatch functionality with:
//! - Zero-cost enum dispatch without external dependencies
//! - Better control over generated code
//! - Support for complex trait patterns
//! - Cleaner, more maintainable implementations
//!
//! # Example
//!
//! ```rust,ignore
//! use miden_utils_core_derive::MastForestContributor;
//!
//! #[derive(MastForestContributor)]
//! pub enum MyEnum {
//!     Variant1(Type1),
//!     Variant2(Type2),
//! }
//! ```

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Attribute, Data, DeriveInput, Fields, Ident, Lit, Meta, NestedMeta, Type, Variant,
    parse_macro_input,
};

/// Derive the MastNodeExt trait for an enum.
///
/// This macro automatically generates implementations for all methods in the MastNodeExt trait..
///
/// # Attributes
///
/// - `#[mast_node_ext(builder = "BuilderType")]` - Specifies the builder type to use
///
/// # Example
///
/// ```rust,ignore
/// use miden_utils_core_derive::MastNodeExt;
///
/// #[derive(MastNodeExt)]
/// #[mast_node_ext(builder = "MyBuilder")]
/// pub enum MyEnum {
///     Variant1(Type1),
///     Variant2(Type2),
///     // ... other variants
/// }
/// ```
#[proc_macro_derive(MastNodeExt, attributes(mast_node_ext))]
pub fn derive_mast_node_ext(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_name = &input.ident;
    let generics = &input.generics;

    // Parse the data to ensure it's an enum
    let enum_data = match &input.data {
        Data::Enum(data) => data,
        _ => panic!("MastNodeExt can only be derived for enums"),
    };

    // Extract the builder type from the attribute
    let builder_type = extract_builder_type(&input.attrs);

    // Extract variant information
    let variants: Vec<_> = enum_data.variants.iter().collect();
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let variant_fields: Vec<_> = variants.iter().map(|v| extract_single_field(v)).collect();

    // Get the list of methods to generate implementations for
    let methods = get_mast_node_ext_methods();

    let method_impls: Vec<proc_macro2::TokenStream> = methods
        .iter()
        .map(|method_name| {
            generate_method_impl_for_trait_method(
                enum_name,
                method_name,
                &variant_names,
                &variant_fields,
                &builder_type,
            )
        })
        .collect();

    // Build the trait implementation
    let trait_impl = quote! {
        impl #generics MastNodeExt for #enum_name #generics {
            type Builder = #builder_type;

            #(#method_impls)*
        }
    };

    TokenStream::from(trait_impl)
}

fn get_mast_node_ext_methods() -> Vec<&'static str> {
    vec![
        "digest",
        "before_enter",
        "after_exit",
        "remove_decorators",
        "to_display",
        "to_pretty_print",
        "has_children",
        "append_children_to",
        "for_each_child",
        "domain",
        "to_builder",
    ]
}

/// Generate method implementation with a more compact approach
fn generate_method_impl_for_trait_method(
    enum_name: &Ident,
    method_name: &str,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
    builder_type: &Type,
) -> proc_macro2::TokenStream {
    match method_name {
        "digest" => quote! {
            fn digest(&self) -> miden_crypto::Word {
                match self {
                    #(#enum_name::#variant_names(field) => field.digest()),*
                }
            }
        },
        "before_enter" => quote! {
            fn before_enter(&self) -> &[crate::mast::DecoratorId] {
                match self {
                    #(#enum_name::#variant_names(field) => field.before_enter()),*
                }
            }
        },
        "after_exit" => quote! {
            fn after_exit(&self) -> &[crate::mast::DecoratorId] {
                match self {
                    #(#enum_name::#variant_names(field) => field.after_exit()),*
                }
            }
        },
        "remove_decorators" => quote! {
            fn remove_decorators(&mut self) {
                match self {
                    #(#enum_name::#variant_names(field) => field.remove_decorators()),*
                }
            }
        },
        "to_display" => quote! {
            fn to_display<'a>(&'a self, mast_forest: &'a crate::mast::MastForest) -> Box<dyn core::fmt::Display + 'a> {
                match self {
                    #(#enum_name::#variant_names(field) => Box::new(field.to_display(mast_forest))),*
                }
            }
        },
        "to_pretty_print" => quote! {
            fn to_pretty_print<'a>(&'a self, mast_forest: &'a crate::mast::MastForest) -> Box<dyn miden_formatting::prettier::PrettyPrint + 'a> {
                match self {
                    #(#enum_name::#variant_names(field) => Box::new(field.to_pretty_print(mast_forest))),*
                }
            }
        },
        "has_children" => quote! {
            fn has_children(&self) -> bool {
                match self {
                    #(#enum_name::#variant_names(field) => field.has_children()),*
                }
            }
        },
        "append_children_to" => quote! {
            fn append_children_to(&self, target: &mut alloc::vec::Vec<crate::mast::MastNodeId>) {
                match self {
                    #(#enum_name::#variant_names(field) => field.append_children_to(target)),*
                }
            }
        },
        "for_each_child" => quote! {
            fn for_each_child<F>(&self, mut f: F) where F: FnMut(crate::mast::MastNodeId) {
                match self {
                    #(#enum_name::#variant_names(field) => field.for_each_child(f)),*
                }
            }
        },
        "domain" => quote! {
            fn domain(&self) -> miden_crypto::Felt {
                match self {
                    #(#enum_name::#variant_names(field) => field.domain()),*
                }
            }
        },
        "to_builder" => {
            generate_to_builder_method(enum_name, variant_names, variant_fields, builder_type)
        },
        _ => panic!("Unknown method: {}", method_name),
    }
}

/// Generate to_builder method implementation
///
/// Contains variant name mappings for compatibility with builder types.
fn generate_to_builder_method(
    enum_name: &Ident,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
    builder_type: &Type,
) -> proc_macro2::TokenStream {
    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        // Convert variant name to builder variant name
        let builder_variant_name = match variant.to_string().as_str() {
            "Block" => Ident::new("BasicBlock", Span::call_site()),
            _ => (*variant).clone(), // Use the same name for other variants
        };

        quote! {
            #enum_name::#variant(#field) => #builder_type::#builder_variant_name(#field.to_builder())
        }
    });

    quote! {
        fn to_builder(self) -> Self::Builder {
            match self {
                #(#match_arms),*
            }
        }
    }
}

/// Derive trait implementations for enums that dispatch to variant trait implementations.
///
/// This macro generates trait implementations that forward method calls to the corresponding
/// variant's trait implementation, similar to the `enum_dispatch` crate but without the
/// external dependency.
///
/// # Example
///
/// ```rust,ignore
/// use miden_utils_core_derive::MastForestContributor;
///
/// #[utils_core_derive(MyTrait)]
/// #[derive(MastForestContributor)]
/// pub enum MyEnum {
///     Variant1(Type1),
///     Variant2(Type2),
/// }
/// ```
#[proc_macro_derive(MastForestContributor)]
pub fn derive_mast_forest_contributor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_name = &input.ident;
    let generics = &input.generics;

    // Parse the data to ensure it's an enum
    let enum_data = match &input.data {
        Data::Enum(data) => data,
        _ => panic!("EnumThispatch can only be derived for enums"),
    };

    // Extract variant information
    let variants: Vec<_> = enum_data.variants.iter().collect();
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let variant_fields: Vec<_> = variants.iter().map(|v| extract_single_field(v)).collect();

    // Generate trait implementation by reading the trait definition
    let trait_impl =
        generate_mast_forest_contributor_impl(enum_name, generics, &variant_names, &variant_fields);

    TokenStream::from(trait_impl)
}

/// Generate MastForestContributor trait implementation for enum dispatch
fn generate_mast_forest_contributor_impl(
    enum_name: &Ident,
    generics: &syn::Generics,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
) -> proc_macro2::TokenStream {
    // For now, let's generate a simple implementation to test the macro
    let add_to_forest_arms =
        variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
            quote! {
                #enum_name::#variant(#field) => #field.add_to_forest(forest)
            }
        });

    quote! {
        impl #generics crate::mast::MastForestContributor for #enum_name #generics {
            fn add_to_forest(self, forest: &mut crate::mast::MastForest) -> Result<crate::mast::MastNodeId, crate::mast::MastForestError> {
                match self {
                    #(#add_to_forest_arms),*
                }
            }

            fn fingerprint_for_node(
                &self,
                forest: &crate::mast::MastForest,
                hash_by_node_id: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeFingerprint>,
            ) -> Result<crate::mast::MastNodeFingerprint, crate::mast::MastForestError> {
                match self {
                    #(#enum_name::#variant_names(field) => field.fingerprint_for_node(forest, hash_by_node_id)),*
                }
            }

            fn remap_children(self, remapping: &impl crate::LookupByIdx<crate::mast::MastNodeId, crate::mast::MastNodeId>) -> Self {
                match self {
                    #(#enum_name::#variant_names(field) => #enum_name::#variant_names(field.remap_children(remapping))),*
                }
            }

            fn with_before_enter(self, decorators: impl Into<alloc::vec::Vec<crate::mast::DecoratorId>>) -> Self {
                match self {
                    #(#enum_name::#variant_names(field) => #enum_name::#variant_names(field.with_before_enter(decorators))),*
                }
            }

            fn with_after_exit(self, decorators: impl Into<alloc::vec::Vec<crate::mast::DecoratorId>>) -> Self {
                match self {
                    #(#enum_name::#variant_names(field) => #enum_name::#variant_names(field.with_after_exit(decorators))),*
                }
            }

            fn append_before_enter(&mut self, decorators: impl IntoIterator<Item = crate::mast::DecoratorId>) {
                match self {
                    #(#enum_name::#variant_names(field) => field.append_before_enter(decorators)),*
                }
            }

            fn append_after_exit(&mut self, decorators: impl IntoIterator<Item = crate::mast::DecoratorId>) {
                match self {
                    #(#enum_name::#variant_names(field) => field.append_after_exit(decorators)),*
                }
            }

            fn with_digest(self, digest: crate::Word) -> Self {
                match self {
                    #(#enum_name::#variant_names(field) => #enum_name::#variant_names(field.with_digest(digest))),*
                }
            }
        }
    }
}

/// Extract the builder type from the #[mast_node_ext(builder = "...")] attribute
fn extract_builder_type(attrs: &[Attribute]) -> Type {
    for attr in attrs {
        if attr.path.is_ident("mast_node_ext") {
            let meta = attr.parse_meta().expect("Failed to parse mast_node_ext attribute");

            if let Meta::List(meta_list) = meta {
                for nested in meta_list.nested {
                    if let NestedMeta::Meta(Meta::NameValue(name_value)) = nested
                        && name_value.path.is_ident("builder")
                        && let Lit::Str(lit_str) = &name_value.lit
                    {
                        let type_str = lit_str.value();
                        return syn::parse_str::<Type>(&type_str)
                            .expect("Invalid builder type specification");
                    }
                }
            }
        }
    }

    panic!("Missing required attribute: #[mast_node_ext(builder = \"...\")]");
}

/// Extract the single field from a variant (e.g., BasicBlockNode from Block(BasicBlockNode))
fn extract_single_field(variant: &Variant) -> Ident {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            // For unnamed fields, we need to create a variable name
            // We'll use "node" as the field name in the generated code
            Ident::new("node", Span::call_site())
        },
        _ => panic!(
            "Each variant must have exactly one unnamed field, but {:?} does not",
            variant.ident
        ),
    }
}
