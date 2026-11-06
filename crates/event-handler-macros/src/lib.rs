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
///
/// This crate repeats the wire constants instead of depending on the ABI crate, which a
/// proc-macro crate would build for the host. Keep the value in sync with
/// `miden_event_handler_abi::MANIFEST_RECORD_VERSION`; the tests in this crate pin it against
/// that crate through a dev-dependency.
const RECORD_VERSION: u8 = 1;

/// The name of the custom section that carries the manifest records.
///
/// Keep it in sync with `miden_event_handler_abi::MANIFEST_SECTION_NAME`; see
/// [`RECORD_VERSION`].
const MANIFEST_SECTION_NAME: &str = "miden:event-manifest";

/// The largest event name the package format accepts, in bytes.
///
/// Keep it in sync with `miden_mast_package::MAX_NAME_BYTES`; see [`RECORD_VERSION`].
const MAX_NAME_BYTES: usize = 255;

/// The name the module must give to its exported linear memory.
///
/// Keep it in sync with `miden_event_handler_abi::MEMORY_EXPORT`; see [`RECORD_VERSION`].
const MEMORY_EXPORT: &str = "memory";

/// Declares a function as a Wasm event handler for the given event name.
///
/// The function must have the exact signature `fn name()`. Report errors with the SDK's `fail`
/// function or with a panic.
///
/// The event name becomes the Wasm export name of the wrapper function, and therefore must:
///
/// - not be empty;
/// - not start with `sys::`, the namespace reserved for system events;
/// - be at most 255 UTF-8 bytes, the cap of the package format (bytes, not characters);
/// - not be `memory`, the name the module must keep for its exported linear memory.
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

            #[unsafe(link_section = #MANIFEST_SECTION_NAME)]
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
    // A proc-macro crate cannot depend on `miden-core`, so the prefix is repeated here. The
    // sync test pins it to `miden_core::events::EventName::RESERVED_NAMESPACE`.
    if event.starts_with("sys::") {
        return Err(syn2::Error::new(
            event_name.span(),
            "the 'sys::' event namespace is reserved for system events",
        ));
    }
    if event.len() > MAX_NAME_BYTES {
        return Err(syn2::Error::new(
            event_name.span(),
            format!("event name cannot be longer than {MAX_NAME_BYTES} bytes"),
        ));
    }
    // The export name is the event name, and the loader needs the linear memory under
    // `MEMORY_EXPORT`, so this name would make the module fail to load with an opaque error.
    if event == MEMORY_EXPORT {
        return Err(syn2::Error::new(
            event_name.span(),
            format!(
                "event name cannot be '{MEMORY_EXPORT}': the module exports its linear memory \
                 under that name"
            ),
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs the name and signature checks against a handler with the plain `fn name()` shape.
    fn check(event: &str) -> Result<(), syn2::Error> {
        let func: ItemFn = syn2::parse_str("fn handler() {}").expect("the fixture fn parses");
        // The span comes from the fixture, so the test names no `proc_macro2` dependency.
        let literal = LitStr::new(event, func.sig.ident.span());
        validate(&literal, &func)
    }

    #[test]
    fn a_plain_event_name_is_accepted() {
        check("test::wasm::a").expect("a plain name passes");
        check(&"e".repeat(MAX_NAME_BYTES)).expect("a name at the cap passes");
    }

    #[test]
    fn an_empty_event_name_is_rejected() {
        let err = check("").expect_err("an empty name fails");
        assert!(err.to_string().contains("cannot be empty"), "unexpected error: {err}");
    }

    #[test]
    fn a_reserved_event_name_is_rejected() {
        let err = check("sys::map_value_to_stack").expect_err("a reserved name fails");
        assert!(err.to_string().contains("reserved"), "unexpected error: {err}");
    }

    #[test]
    fn an_over_long_event_name_is_rejected() {
        let err = check(&"e".repeat(MAX_NAME_BYTES + 1)).expect_err("an over-long name fails");
        assert!(err.to_string().contains("longer than"), "unexpected error: {err}");
    }

    #[test]
    fn the_name_length_cap_counts_bytes_not_characters() {
        // The package format caps the name in bytes, so a multibyte name reaches the cap with
        // far fewer characters: '€' is three UTF-8 bytes.
        let at_the_cap = "€".repeat(MAX_NAME_BYTES / 3);
        assert_eq!(at_the_cap.len(), MAX_NAME_BYTES, "the fixture must sit exactly at the cap");
        check(&at_the_cap).expect("a multibyte name at the cap passes");

        // 128 characters, well under the cap in characters, but 384 bytes.
        let over_the_cap = "€".repeat(128);
        assert!(
            over_the_cap.chars().count() < MAX_NAME_BYTES,
            "the fixture must be short in chars"
        );
        let err = check(&over_the_cap).expect_err("an over-long multibyte name fails");
        assert!(err.to_string().contains("longer than"), "unexpected error: {err}");
    }

    #[test]
    fn the_memory_export_name_is_rejected() {
        let err = check(MEMORY_EXPORT).expect_err("the memory export name fails");
        assert!(err.to_string().contains("linear memory"), "unexpected error: {err}");
    }

    #[test]
    fn the_repeated_wire_constants_match_the_crates_that_own_them() {
        // This crate repeats these values instead of depending on the owning crates; the
        // dev-dependencies make the repetition checkable without adding a runtime dependency.
        assert_eq!(RECORD_VERSION, miden_event_handler_abi::MANIFEST_RECORD_VERSION);
        assert_eq!(MANIFEST_SECTION_NAME, miden_event_handler_abi::MANIFEST_SECTION_NAME);
        assert_eq!(MAX_NAME_BYTES, miden_mast_package::MAX_NAME_BYTES);
        assert_eq!(MEMORY_EXPORT, miden_event_handler_abi::MEMORY_EXPORT);
        assert_eq!("sys::", miden_core::events::EventName::RESERVED_NAMESPACE);
    }
}
