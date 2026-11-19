//! Generates metadata for the diagnostic forms used by the VM.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Attribute, Data, DeriveInput, Fields, Ident, LitStr, Member, Token, Type,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};

#[derive(Default)]
struct Options {
    help: Option<TokenStream>,
    code: Option<syn::Path>,
    severity: Option<Ident>,
    forward: Option<Member>,
    transparent: bool,
}

impl Parse for Options {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut options = Self::default();
        while !input.is_empty() {
            let key: Ident = input.parse()?;
            if key == "transparent" {
                set_once(&mut options.transparent, &key)?;
            } else {
                let content;
                syn::parenthesized!(content in input);
                match key.to_string().as_str() {
                    "help" => {
                        // Rust's format! checks the arguments, including captured fields.
                        content.fork().parse::<LitStr>()?;
                        set_value(&mut options.help, content.parse()?, &key)?;
                    },
                    "code" => set_value(&mut options.code, content.parse()?, &key)?,
                    "severity" => {
                        let severity: Ident = content.parse()?;
                        if !matches!(severity.to_string().as_str(), "Error" | "Warning" | "Advice")
                        {
                            return Err(syn::Error::new(
                                severity.span(),
                                "unknown diagnostic severity",
                            ));
                        }
                        set_value(&mut options.severity, severity, &key)?;
                    },
                    "forward" => set_value(&mut options.forward, content.parse()?, &key)?,
                    _ => return Err(syn::Error::new(key.span(), "unsupported diagnostic option")),
                }
                if !content.is_empty() {
                    return Err(content.error("unexpected diagnostic arguments"));
                }
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(options)
    }
}

#[derive(Default)]
struct LabelOptions {
    primary: bool,
    collection: bool,
    message: Option<TokenStream>,
}

impl Parse for LabelOptions {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut options = Self::default();
        while !input.is_empty() {
            if input.peek(LitStr) {
                options.message = Some(input.parse()?);
                break;
            }
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "primary" => set_once(&mut options.primary, &key)?,
                "collection" => set_once(&mut options.collection, &key)?,
                _ => return Err(syn::Error::new(key.span(), "unsupported label option")),
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        if options.collection && (options.primary || options.message.is_some()) {
            return Err(
                input.error("label collections retain their own messages and primary flags")
            );
        }
        Ok(options)
    }
}

fn set_once(slot: &mut bool, key: &Ident) -> syn::Result<()> {
    if *slot {
        return Err(syn::Error::new(key.span(), "duplicate diagnostic option"));
    }
    *slot = true;
    Ok(())
}

fn set_value<T>(slot: &mut Option<T>, value: T, key: &Ident) -> syn::Result<()> {
    if slot.is_some() {
        return Err(syn::Error::new(key.span(), "duplicate diagnostic option"));
    }
    *slot = Some(value);
    Ok(())
}

fn attribute<'a>(attrs: &'a [Attribute], name: &str) -> syn::Result<Option<&'a Attribute>> {
    let mut found = None;
    for attr in attrs.iter().filter(|attr| attr.path.is_ident(name)) {
        if name != "diagnostic" && name != "label" && !attr.tokens.is_empty() {
            return Err(syn::Error::new_spanned(
                attr,
                "this diagnostic field attribute takes no arguments",
            ));
        }
        if found.is_some() {
            return Err(syn::Error::new_spanned(attr, "duplicate diagnostic attribute"));
        }
        found = Some(attr);
    }
    Ok(found)
}

fn type_name(ty: &Type) -> Option<&Ident> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        _ => None,
    }
}

fn formatted(arguments: TokenStream) -> TokenStream {
    if let Ok(literal) = syn::parse2::<LitStr>(arguments.clone())
        && !literal.value().contains(['{', '}'])
    {
        return quote!(#literal);
    }
    quote!(::alloc::format!(#arguments))
}

pub fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let name = &input.ident;
    let mut details = Vec::new();
    let mut severities = Vec::new();
    match &input.data {
        Data::Struct(data) => {
            let (pattern, metadata, severity) =
                expand_fields(quote!(Self), &data.fields, &input.attrs)?;
            details.push(quote!(#pattern => #metadata));
            severities.push(quote!(#pattern => #severity));
        },
        Data::Enum(data) => {
            if attribute(&input.attrs, "diagnostic")?.is_some() {
                return Err(syn::Error::new_spanned(
                    name,
                    "place diagnostic options on enum variants",
                ));
            }
            for variant in &data.variants {
                let variant_name = &variant.ident;
                let (pattern, metadata, severity) =
                    expand_fields(quote!(Self::#variant_name), &variant.fields, &variant.attrs)?;
                details.push(quote!(#pattern => #metadata));
                severities.push(quote!(#pattern => #severity));
            }
        },
        Data::Union(_) => {
            return Err(syn::Error::new_spanned(name, "Diagnostic requires a struct or enum"));
        },
    }
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::miden_utils_diagnostics::Diagnostic for #name #ty_generics #where_clause {
            // Format strings may capture any field. Unused bindings are local to generated code.
            #[allow(unused_variables)]
            fn details(&self) -> ::miden_utils_diagnostics::DiagnosticDetails<'_> {
                match self { #(#details,)* }
            }

            #[allow(unused_variables)]
            fn severity(&self) -> ::miden_utils_diagnostics::Severity {
                match self { #(#severities,)* }
            }
        }
    })
}

fn expand_fields(
    constructor: TokenStream,
    fields: &Fields,
    attrs: &[Attribute],
) -> syn::Result<(TokenStream, TokenStream, TokenStream)> {
    let options = attribute(attrs, "diagnostic")?
        .map(Attribute::parse_args::<Options>)
        .transpose()?
        .unwrap_or_default();
    let bindings: Vec<_> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| field.ident.clone().unwrap_or_else(|| format_ident!("field_{index}")))
        .collect();
    let pattern = match fields {
        Fields::Named(_) => quote!(#constructor { #(#bindings,)* }),
        Fields::Unnamed(_) => quote!(#constructor(#(#bindings,)*)),
        Fields::Unit => constructor,
    };
    let forwarded = if options.transparent {
        if fields.len() != 1 || options.forward.is_some() {
            return Err(syn::Error::new(
                fields.span(),
                "transparent diagnostics require exactly one field",
            ));
        }
        Some(&bindings[0])
    } else {
        options
            .forward
            .as_ref()
            .map(|member| {
                fields
                    .iter()
                    .enumerate()
                    .find_map(|(index, field)| {
                        let matches = match member {
                            Member::Named(name) => field.ident.as_ref() == Some(name),
                            Member::Unnamed(member) => {
                                field.ident.is_none() && member.index as usize == index
                            },
                        };
                        matches.then_some(&bindings[index])
                    })
                    .ok_or_else(|| {
                        syn::Error::new_spanned(member, "unknown forwarded diagnostic field")
                    })
            })
            .transpose()?
    };
    let mut assignments = Vec::new();
    let mut labels = Vec::new();
    let mut collection = None;
    let mut source_seen = false;
    let mut related_seen = false;
    let mut help_seen = options.help.is_some();
    for (field, binding) in fields.iter().zip(&bindings) {
        if let Some(attr) = attribute(&field.attrs, "source_code")? {
            set_once(&mut source_seen, &format_ident!("source_code", span = attr.span()))?;
            let source = if type_name(&field.ty).is_some_and(|name| name == "Option") {
                quote!(#binding.as_deref())
            } else {
                quote!(::core::option::Option::Some(&**#binding))
            };
            assignments.push(quote!(details.source = #source;));
        }
        if let Some(attr) = attribute(&field.attrs, "related")? {
            set_once(&mut related_seen, &format_ident!("related", span = attr.span()))?;
            assignments.push(quote! {
                details.related = #binding.iter()
                    .map(|error| error as &dyn ::miden_utils_diagnostics::Diagnostic).collect();
            });
        }
        if let Some(attr) = attribute(&field.attrs, "help")? {
            set_once(&mut help_seen, &format_ident!("help", span = attr.span()))?;
            let help = if type_name(&field.ty).is_some_and(|name| name == "Option") {
                quote!(#binding.as_deref().map(::core::convert::Into::into))
            } else {
                quote!(::core::option::Option::Some(#binding.as_str().into()))
            };
            assignments.push(quote!(details.help = #help;));
        }
        if let Some(attr) = attribute(&field.attrs, "label")? {
            let label = if attr.tokens.is_empty() {
                LabelOptions::default()
            } else {
                attr.parse_args()?
            };
            if label.collection {
                if collection.is_some() {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "only one label collection is supported",
                    ));
                }
                collection = Some(binding);
                continue;
            }
            let value = match (type_name(&field.ty), label.message) {
                (Some(name), None) if name == "Label" || name == "LabeledSpan" => {
                    quote!(#binding.clone())
                },
                (_, Some(message)) => {
                    let message = formatted(message);
                    quote!(::miden_utils_diagnostics::Label::new(
                        ::miden_utils_diagnostics::Spanned::span(#binding), #message
                    ))
                },
                (_, None) => quote!(::miden_utils_diagnostics::Label::underline(
                    ::miden_utils_diagnostics::Spanned::span(#binding)
                )),
            };
            labels.push(if label.primary { quote!(#value.primary()) } else { value });
        }
    }
    if options.transparent
        && (!assignments.is_empty()
            || !labels.is_empty()
            || collection.is_some()
            || options.help.is_some()
            || options.code.is_some()
            || options.severity.is_some())
    {
        return Err(syn::Error::new(
            fields.span(),
            "transparent diagnostics cannot override metadata",
        ));
    }
    if !labels.is_empty() {
        assignments.push(quote!(details.labels = ::alloc::vec![#(#labels,)*].into();));
        if let Some(collection) = collection {
            assignments.push(quote!(details.labels.to_mut().extend_from_slice(#collection);));
        }
    } else if let Some(collection) = collection {
        assignments.push(quote!(details.labels = #collection.as_slice().into();));
    }
    if let Some(help) = options.help {
        let help = formatted(help);
        assignments.push(quote!(details.help = ::core::option::Option::Some(#help.into());));
    }
    if let Some(code) = options.code {
        let code = LitStr::new(&quote!(#code).to_string().replace(' ', ""), code.span());
        assignments.push(quote!(details.code = ::core::option::Option::Some(#code);));
    }
    let initial = match forwarded {
        Some(binding) => {
            quote!({ use ::miden_utils_diagnostics::Diagnostic as _; #binding.details() })
        },
        None => quote!(::miden_utils_diagnostics::DiagnosticDetails::default()),
    };
    let severity = match (options.severity, forwarded) {
        (Some(severity), _) => quote!(::miden_utils_diagnostics::Severity::#severity),
        (None, Some(binding)) => {
            quote!({ use ::miden_utils_diagnostics::Diagnostic as _; #binding.severity() })
        },
        (None, None) => quote!(::miden_utils_diagnostics::Severity::Error),
    };
    let metadata = if assignments.is_empty() {
        initial
    } else {
        quote!({ let mut details = #initial; #(#assignments)* details })
    };
    Ok((pattern, metadata, severity))
}

#[cfg(test)]
mod tests {
    use super::expand;

    #[test]
    fn rejects_unsupported_and_ambiguous_metadata() {
        let cases = [
            ("union Error { value: u32 }", "requires a struct or enum"),
            ("#[diagnostic(other())] struct Error;", "unsupported diagnostic option"),
            ("#[diagnostic(severity(Fatal))] struct Error;", "unknown diagnostic severity"),
            (
                "#[diagnostic(help(\"a\"), help(\"b\"))] struct Error;",
                "duplicate diagnostic option",
            ),
            (
                "#[diagnostic(forward(missing))] struct Error { value: Inner }",
                "unknown forwarded diagnostic field",
            ),
            (
                "#[diagnostic(transparent)] struct Error(Inner, Inner);",
                "require exactly one field",
            ),
            (
                "#[diagnostic(transparent, help(\"a\"))] struct Error(Inner);",
                "cannot override metadata",
            ),
            (
                "struct Error { #[source_code] first: Source, #[source_code] second: Source }",
                "duplicate diagnostic option",
            ),
            ("struct Error { #[source_code(ignored)] source: Source }", "takes no arguments"),
            (
                "struct Error { #[label(collection, primary)] labels: Vec<Label> }",
                "retain their own messages",
            ),
            (
                "struct Error { #[label] #[label] span: SourceSpan }",
                "duplicate diagnostic attribute",
            ),
            (
                "#[diagnostic(help(\"a\"))] struct Error { #[help] help: String }",
                "duplicate diagnostic option",
            ),
        ];
        for (input, message) in cases {
            let input = syn::parse_str(input).expect("valid Rust declaration");
            let error = expand(input).expect_err("invalid diagnostic metadata");
            assert!(error.to_string().contains(message), "{error}");
        }
    }
}
