//! Determinism pins for the Wasm event handler host.
//!
//! A handler must give the same answer on every machine, and the same module must validate the
//! same way on every host. SIMD and relaxed-SIMD instructions give neither guarantee, so the
//! loader must refuse a module that contains them — on every host, whatever its dependency
//! graph looks like.

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
/// The loader enables wasmi's `simd` cargo feature on purpose and turns the SIMD features off
/// through `Config` — that is the only form of "off" that Cargo feature unification in a
/// consumer's dependency graph cannot flip back on. This test pins the rejection itself, and
/// its message check pins that the module was refused *because of SIMD*, not for an unrelated
/// reason.
#[test]
fn simd_instructions_are_rejected() {
    let wasm = wat::parse_str(SIMD_WAT).expect("fixture WAT must parse");
    let manifest = vec![(EVENT, "handler".to_string())];
    let err = WasmHandlerModule::new(&wasm, ABI_VERSION, manifest, WasmHandlerLimits::default())
        .expect_err("a module with SIMD instructions must not load");
    assert!(matches!(err, WasmHandlerLoadError::InvalidModule(_)), "unexpected error: {err}");
    let msg = err.to_string().to_lowercase();
    assert!(msg.contains("simd"), "the rejection must name SIMD as the cause: {err}");
}
