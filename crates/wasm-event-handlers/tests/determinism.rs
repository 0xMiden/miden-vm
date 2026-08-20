//! Determinism pins for the Wasm event handler host.
//!
//! A handler must give the same answer on every machine. SIMD and relaxed-SIMD instructions do
//! not give that guarantee, so the host must refuse a module that contains them.

use miden_event_handler_abi::ABI_VERSION;
use miden_processor::event::EventName;
use miden_wasm_event_handlers::{WasmHandlerLimits, WasmHandlerLoadError, WasmHandlerModule};

const EVENT: EventName = EventName::new("test::wasm::handler");

/// A module that is valid in all other respects, but whose handler body holds one v128
/// instruction.
const SIMD_WAT: &str = r#"(module
    (func (export "handler") (drop (v128.const i64x2 0 0))))"#;

/// Pins the rejection of SIMD instructions at load time.
///
/// The host gets this rejection from wasmi, which is built without its `simd` cargo feature.
/// Cargo unifies features over the whole dependency graph, so any crate that turns on
/// `wasmi/simd` also turns it on here. This test makes such a change fail loudly instead of
/// letting it void the determinism guarantee in silence.
#[test]
fn simd_instructions_are_rejected() {
    let wasm = wat::parse_str(SIMD_WAT).expect("fixture WAT must parse");
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, WasmHandlerLimits::default())
        .expect_err("a module with SIMD instructions must not load");
    assert!(matches!(err, WasmHandlerLoadError::InvalidModule(_)), "unexpected error: {err}");
}
