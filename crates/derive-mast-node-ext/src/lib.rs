//! Proc macro to derive MastNodeExt trait implementations and From conversions
//!
//! This crate provides proc macros for enums that wrap various node types:
//! - `MastNodeExt` derive macro: generates trait implementations that dispatch method calls
//! - `FromVariant` derive macro: generates `From<VariantType> for EnumType` implementations
//!
//! Both macros automatically generate boilerplate code for enum variants.

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
/// This macro generates an implementation of the MastNodeExt trait for an enum where each
/// variant contains a type that implements MastNodeExt. The macro handles dispatching method
/// calls to the appropriate variant and managing the associated Builder type.
///
/// # Attributes
///
/// - `#[mast_node_ext(builder = "MastNodeBuilder")]` - Specifies the builder type to use for the
///   associated `Builder` type in the trait implementation.
///
/// # Example
///
/// ```rust
/// use miden_derive_mast_node_ext::MastNodeExt;
///
/// #[derive(MastNodeExt)]
/// #[mast_node_ext(builder = "MastNodeBuilder")]
/// pub enum MastNode {
///     Block(BasicBlockNode),
///     Join(JoinNode),
///     Split(SplitNode),
///     // ... other variants
/// }
/// ```
/// Derive From implementations for converting each variant type to the enum.
///
/// This macro generates `From<VariantType> for EnumType` implementations for each variant
/// in an enum where each variant contains exactly one unnamed field. This eliminates boilerplate
/// code for conversions from variant types to the enum type.
///
/// # Example
///
/// ```rust
/// use miden_derive_mast_node_ext::FromVariant;
///
/// #[derive(FromVariant)]
/// pub enum MastNode {
///     Block(BasicBlockNode),
///     Join(JoinNode),
///     Split(SplitNode),
///     // ... other variants
/// }
/// ```
///
/// This will generate:
/// ```rust
/// impl From<BasicBlockNode> for MastNode {
///     fn from(node: BasicBlockNode) -> Self {
///         MastNode::Block(node)
///     }
/// }
///
/// impl From<JoinNode> for MastNode {
///     fn from(node: JoinNode) -> Self {
///         MastNode::Join(node)
///     }
/// }
/// // ... and so on for all variants
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

    // Generate method implementations
    let digest_impl =
        generate_method_impl(enum_name, "digest", &variant_names, &variant_fields, &[]);
    let before_enter_impl =
        generate_method_impl(enum_name, "before_enter", &variant_names, &variant_fields, &[]);
    let after_exit_impl =
        generate_method_impl(enum_name, "after_exit", &variant_names, &variant_fields, &[]);
    let append_before_enter_impl = generate_method_impl_with_args(
        enum_name,
        "append_before_enter",
        &variant_names,
        &variant_fields,
        &[Ident::new("decorator_ids", Span::call_site())],
    );
    let append_after_exit_impl = generate_method_impl_with_args(
        enum_name,
        "append_after_exit",
        &variant_names,
        &variant_fields,
        &[Ident::new("decorator_ids", Span::call_site())],
    );
    let remove_decorators_impl =
        generate_method_impl(enum_name, "remove_decorators", &variant_names, &variant_fields, &[]);
    let to_display_impl = generate_to_display_impl(enum_name, &variant_names, &variant_fields);
    let to_pretty_print_impl =
        generate_to_pretty_print_impl(enum_name, &variant_names, &variant_fields);
    let has_children_impl =
        generate_method_impl(enum_name, "has_children", &variant_names, &variant_fields, &[]);
    let append_children_to_impl = generate_method_impl_with_args(
        enum_name,
        "append_children_to",
        &variant_names,
        &variant_fields,
        &[Ident::new("target", Span::call_site())],
    );
    let for_each_child_impl =
        generate_for_each_child_impl(enum_name, &variant_names, &variant_fields);
    let domain_impl =
        generate_method_impl(enum_name, "domain", &variant_names, &variant_fields, &[]);
    let to_builder_impl =
        generate_to_builder_impl(enum_name, &variant_names, &variant_fields, &builder_type);

    let expanded = quote! {
        impl #generics MastNodeExt for #enum_name #generics {
            type Builder = #builder_type;

            fn digest(&self) -> miden_crypto::Word {
                #digest_impl
            }

            fn before_enter(&self) -> &[crate::mast::DecoratorId] {
                #before_enter_impl
            }

            fn after_exit(&self) -> &[crate::mast::DecoratorId] {
                #after_exit_impl
            }

            fn append_before_enter(&mut self, decorator_ids: &[crate::mast::DecoratorId]) {
                #append_before_enter_impl
            }

            fn append_after_exit(&mut self, decorator_ids: &[crate::mast::DecoratorId]) {
                #append_after_exit_impl
            }

            fn remove_decorators(&mut self) {
                #remove_decorators_impl
            }

            fn to_display<'a>(&'a self, mast_forest: &'a crate::mast::MastForest) -> Box<dyn core::fmt::Display + 'a> {
                #to_display_impl
            }

            fn to_pretty_print<'a>(&'a self, mast_forest: &'a crate::mast::MastForest) -> Box<dyn miden_formatting::prettier::PrettyPrint + 'a> {
                #to_pretty_print_impl
            }

            fn has_children(&self) -> bool {
                #has_children_impl
            }

            fn append_children_to(&self, target: &mut alloc::vec::Vec<crate::mast::MastNodeId>) {
                #append_children_to_impl
            }

            fn for_each_child<F>(&self, mut f: F)
            where
                F: FnMut(crate::mast::MastNodeId),
            {
                #for_each_child_impl
            }

            fn domain(&self) -> miden_crypto::Felt {
                #domain_impl
            }

            fn to_builder(self) -> Self::Builder {
                #to_builder_impl
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive From implementations for converting each variant type to the enum.
#[proc_macro_derive(FromVariant)]
pub fn derive_from_variant(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let enum_name = &input.ident;
    let generics = &input.generics;

    // Parse the data to ensure it's an enum
    let enum_data = match &input.data {
        Data::Enum(data) => data,
        _ => panic!("FromVariant can only be derived for enums"),
    };

    // Extract variant information
    let variants: Vec<_> = enum_data.variants.iter().collect();
    let variant_names: Vec<_> = variants.iter().map(|v| &v.ident).collect();
    let variant_types: Vec<_> = variants.iter().map(|v| extract_variant_type(v)).collect();

    // Generate From implementations
    let from_impls =
        variant_names.iter().zip(variant_types.iter()).map(|(variant, variant_type)| {
            quote! {
                impl From<#variant_type> for #enum_name #generics {
                    fn from(node: #variant_type) -> Self {
                        #enum_name::#variant(node)
                    }
                }
            }
        });

    let expanded = quote! {
        #(#from_impls)*
    };

    TokenStream::from(expanded)
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

/// Extract the type of the single field from a variant (e.g., BasicBlockNode from
/// Block(BasicBlockNode))
fn extract_variant_type(variant: &Variant) -> Type {
    match &variant.fields {
        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
            // Return the type of the single unnamed field
            fields.unnamed[0].ty.clone()
        },
        _ => panic!(
            "Each variant must have exactly one unnamed field, but {:?} does not",
            variant.ident
        ),
    }
}

/// Generate a simple method implementation that matches on all variants
fn generate_method_impl(
    enum_name: &Ident,
    method_name: &str,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
    _extra_args: &[Ident],
) -> proc_macro2::TokenStream {
    let method_ident = Ident::new(method_name, Span::call_site());

    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        quote! {
            #enum_name::#variant(#field) => #field.#method_ident()
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}

/// Generate a method implementation with arguments
fn generate_method_impl_with_args(
    enum_name: &Ident,
    method_name: &str,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
    arg_names: &[Ident],
) -> proc_macro2::TokenStream {
    let method_ident = Ident::new(method_name, Span::call_site());
    let args = quote! { #(#arg_names),* };

    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        quote! {
            #enum_name::#variant(#field) => #field.#method_ident(#args)
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}

/// Generate the to_display method implementation
fn generate_to_display_impl(
    enum_name: &Ident,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
) -> proc_macro2::TokenStream {
    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        quote! {
            #enum_name::#variant(#field) => Box::new(#field.to_display(mast_forest))
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}

/// Generate the to_pretty_print method implementation
fn generate_to_pretty_print_impl(
    enum_name: &Ident,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
) -> proc_macro2::TokenStream {
    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        quote! {
            #enum_name::#variant(#field) => Box::new(#field.to_pretty_print(mast_forest))
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}

/// Generate the for_each_child method implementation
fn generate_for_each_child_impl(
    enum_name: &Ident,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
) -> proc_macro2::TokenStream {
    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        quote! {
            #enum_name::#variant(#field) => #field.for_each_child(f)
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}

/// Generate the to_builder method implementation
fn generate_to_builder_impl(
    enum_name: &Ident,
    variant_names: &[&Ident],
    variant_fields: &[Ident],
    builder_type: &Type,
) -> proc_macro2::TokenStream {
    let match_arms = variant_names.iter().zip(variant_fields.iter()).map(|(variant, field)| {
        // Convert variant name to builder variant name (e.g., Block -> BasicBlock)
        let builder_variant_name = match variant.to_string().as_str() {
            "Block" => Ident::new("BasicBlock", Span::call_site()),
            "Join" => Ident::new("Join", Span::call_site()),
            "Split" => Ident::new("Split", Span::call_site()),
            "Loop" => Ident::new("Loop", Span::call_site()),
            "Call" => Ident::new("Call", Span::call_site()),
            "Dyn" => Ident::new("Dyn", Span::call_site()),
            "External" => Ident::new("External", Span::call_site()),
            _ => panic!("Unknown variant: {}", variant),
        };

        quote! {
            #enum_name::#variant(#field) => #builder_type::#builder_variant_name(#field.to_builder())
        }
    });

    quote! {
        match self {
            #(#match_arms),*
        }
    }
}
