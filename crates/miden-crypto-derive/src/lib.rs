use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type, parse_macro_input};

// SILENT DEBUG MACRO
// ================================================================================================

/// Derives a Debug implementation that elides secret values.
///
/// This macro generates a Debug implementation that outputs `<elided secret for TypeName>`
/// instead of the actual field values, preventing accidental leakage of sensitive data
/// in logs, error messages, or debug output.
///
/// # Example
///
/// ```ignore
/// #[derive(SilentDebug)]
/// pub struct SecretKey {
///     inner: [u8; 32],
/// }
///
/// let sk = SecretKey { inner: [0u8; 32] };
/// assert_eq!(format!("{:?}", sk), "<elided secret for SecretKey>");
/// ```
#[proc_macro_derive(SilentDebug)]
pub fn silent_debug(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    let expanded = quote! {
        // In order to ensure that secrets are never leaked, Debug is elided
        impl #impl_generics ::core::fmt::Debug for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}

// SILENT DISPLAY MACRO
// ================================================================================================

/// Derives a Display implementation that elides secret values.
///
/// This macro generates a Display implementation that outputs `<elided secret for TypeName>`
/// instead of the actual field values. While implementing Display for secret keys is
/// generally discouraged (as Display implies "user-facing output"), this safe implementation
/// prevents compilation errors in generic contexts while still protecting sensitive data.
///
/// # Example
///
/// ```ignore
/// #[derive(SilentDisplay)]
/// pub struct SecretKey {
///     inner: [u8; 32],
/// }
///
/// let sk = SecretKey { inner: [0u8; 32] };
/// assert_eq!(format!("{}", sk), "<elided secret for SecretKey>");
/// ```
#[proc_macro_derive(SilentDisplay)]
pub fn silent_display(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;
    let (impl_generics, ty_generics, where_clause) = ast.generics.split_for_impl();

    let expanded = quote! {
        // In order to ensure that secrets are never leaked, Display is elided
        impl #impl_generics ::core::fmt::Display for #name #ty_generics #where_clause {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "<elided secret for {}>", stringify!(#name))
            }
        }
    };

    TokenStream::from(expanded)
}

// WORD WRAPPER MACRO
// ================================================================================================

/// Generates accessor methods for tuple structs wrapping a `Word` type.
///
/// Automatically implements:
/// - `from_raw(Word) -> Self` - Construct without further checks
/// - `as_elements(&self) -> &[Felt]` - Returns the elements representation
/// - `as_bytes(&self) -> [u8; 32]` - Returns the byte representation
/// - `to_hex(&self) -> String` - Returns a big-endian, hex-encoded string
/// - `as_word(&self) -> Word` - Returns the underlying Word
///
/// Note: This macro does NOT generate `From` trait implementations. If you need conversions
/// to/from `Word` or `[u8; 32]`, implement them manually for your type.
///
/// # Example
///
/// ```ignore
/// #[derive(WordWrapper)]
/// pub struct NoteId(Word);
/// ```
///
/// This will generate implementations equivalent to:
///
/// ```ignore
/// impl NoteId {
///     /// Construct without further checks from a given `Word`
///     ///
///     /// # Warning
///     ///
///     /// This requires the caller to uphold the guarantees/invariants of this type (if any).
///     /// Check the type-level documentation for guarantees/invariants.
///     pub fn from_raw(word: Word) -> Self {
///         Self(word)
///     }
///
///     pub fn as_elements(&self) -> &[Felt] {
///         self.0.as_elements()
///     }
///
///     pub fn as_bytes(&self) -> [u8; 32] {
///         self.0.as_bytes()
///     }
///
///     pub fn to_hex(&self) -> String {
///         self.0.to_hex()
///     }
///
///     pub fn as_word(&self) -> Word {
///         self.0
///     }
/// }
/// ```
#[proc_macro_derive(WordWrapper)]
pub fn word_wrapper_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Validate that this is a tuple struct with a single field
    let field_type = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => match fields.unnamed.first() {
                Some(field) => &field.ty,
                None => {
                    return syn::Error::new_spanned(
                        &input,
                        "WordWrapper requires exactly one field",
                    )
                    .to_compile_error()
                    .into();
                },
            },
            _ => {
                return syn::Error::new_spanned(
                    &input,
                    "WordWrapper can only be derived for tuple structs with exactly one field",
                )
                .to_compile_error()
                .into();
            },
        },
        _ => {
            return syn::Error::new_spanned(&input, "WordWrapper can only be derived for structs")
                .to_compile_error()
                .into();
        },
    };

    // Verify that the field type is 'Word' (or a path ending in 'Word')
    if let Type::Path(type_path) = field_type {
        let last_segment = type_path.path.segments.last();
        if let Some(segment) = last_segment {
            if segment.ident != "Word" {
                return syn::Error::new_spanned(
                    field_type,
                    "WordWrapper can only be derived for types wrapping a 'Word' field",
                )
                .to_compile_error()
                .into();
            }
        } else {
            return syn::Error::new_spanned(
                field_type,
                "WordWrapper can only be derived for types wrapping a 'Word' field",
            )
            .to_compile_error()
            .into();
        }
    } else {
        return syn::Error::new_spanned(
            field_type,
            "WordWrapper can only be derived for types wrapping a 'Word' field",
        )
        .to_compile_error()
        .into();
    }

    let expanded = quote! {
        impl #impl_generics #name #ty_generics #where_clause {
            /// Construct without further checks from a given `Word`.
            ///
            /// # Warning
            ///
            /// This requires the caller to uphold the guarantees/invariants of this type (if any).
            /// Check the type-level documentation for guarantees/invariants.
            pub fn from_raw(word: Word) -> Self {
                Self(word)
            }

            /// Returns the elements representation of this value.
            pub fn as_elements(&self) -> &[Felt] {
                self.0.as_elements()
            }

            /// Returns the byte representation of this value.
            pub fn as_bytes(&self) -> [u8; 32] {
                self.0.as_bytes()
            }

            /// Returns a big-endian, hex-encoded string.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }

            /// Returns the underlying word of this value.
            pub fn as_word(&self) -> Word {
                self.0
            }
        }
    };

    TokenStream::from(expanded)
}
