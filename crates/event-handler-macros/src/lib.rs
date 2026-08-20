//! Attribute macro for declaring Wasm-compiled Miden VM event handlers.
//!
//! `#[miden_event_handler("my::event::name")]` on a `fn name()` generates, for `wasm32` targets:
//!
//! - an exported wrapper function whose Wasm export name is the event name itself;
//! - a manifest record in the `miden:event-manifest` custom section, so package build tooling can
//!   derive the `(event, export)` manifest mechanically from the compiled module.
//!
//! The manifest record format is: one version byte (`1`), then the event name and the export
//! name, each as a little-endian `u32` length followed by the bytes. Multiple records may follow
//! each other in one section payload, and the linker may also emit multiple sections with the
//! same name.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn2::{ItemFn, LitStr, ReturnType, parse_macro_input, spanned::Spanned};

/// The version byte of one manifest record.
const RECORD_VERSION: u8 = 1;

/// Declares a function as a Wasm event handler for the given event name.
///
/// The function must have the exact signature `fn name()`. Report errors with the SDK's `fail`
/// function or with a panic.
#[proc_macro_attribute]
pub fn miden_event_handler(attr: TokenStream, item: TokenStream) -> TokenStream {
    let event_name = parse_macro_input!(attr as LitStr);
    let func = parse_macro_input!(item as ItemFn);

    if let Err(err) = validate(&event_name, &func) {
        return err.to_compile_error().into();
    }

    let event = event_name.value();
    let fn_ident = &func.sig.ident;
    let export_ident = format_ident!("__miden_event_export_{}", fn_ident);

    // The export name is the event name itself, so the manifest maps the event to an export
    // with the same string.
    let record = manifest_record(&event, &event);
    let record_len = record.len();

    quote! {
        #func

        #[cfg(target_arch = "wasm32")]
        const _: () = {
            #[unsafe(export_name = #event)]
            extern "C" fn #export_ident() {
                #fn_ident()
            }

            #[unsafe(link_section = "miden:event-manifest")]
            #[used]
            static MANIFEST_RECORD: [u8; #record_len] = [#(#record),*];
        };
    }
    .into()
}

/// Checks the event name and the handler signature.
fn validate(event_name: &LitStr, func: &ItemFn) -> Result<(), syn2::Error> {
    let event = event_name.value();
    if event.is_empty() {
        return Err(syn2::Error::new(event_name.span(), "event name cannot be empty"));
    }
    // A proc-macro crate cannot depend on `miden-core`, so the prefix is repeated here. Keep it
    // in sync with `miden_core::events::EventName::RESERVED_NAMESPACE`.
    if event.starts_with("sys::") {
        return Err(syn2::Error::new(
            event_name.span(),
            "the 'sys::' event namespace is reserved for system events",
        ));
    }

    let sig = &func.sig;
    let signature_error = |msg: &str| Err(syn2::Error::new(sig.span(), msg));
    if !sig.inputs.is_empty() {
        return signature_error("an event handler cannot take arguments; use the SDK queries");
    }
    if !matches!(sig.output, ReturnType::Default) {
        return signature_error(
            "an event handler must return (); report errors with `fail` or a panic",
        );
    }
    if sig.asyncness.is_some() || sig.unsafety.is_some() || !sig.generics.params.is_empty() {
        return signature_error("an event handler must be a plain non-generic fn");
    }
    Ok(())
}

/// Encodes one manifest record.
fn manifest_record(event: &str, export: &str) -> Vec<u8> {
    let mut record = vec![RECORD_VERSION];
    for name in [event, export] {
        record.extend((name.len() as u32).to_le_bytes());
        record.extend(name.as_bytes());
    }
    record
}
