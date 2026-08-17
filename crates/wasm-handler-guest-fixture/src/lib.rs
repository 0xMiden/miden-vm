//! A Rust guest crate with Wasm event handlers, used by the host-adapter end-to-end tests.
//!
//! Compile with `--target wasm32-unknown-unknown` to get the handler module; the manifest is
//! embedded in the `miden:event-manifest` custom section by the SDK macro.

// no_std applies only on the wasm32 guest target; host builds of the workspace use std, which
// provides the panic machinery the cdylib crate type needs there.
#![cfg_attr(target_arch = "wasm32", no_std)]
// On non-wasm targets the generated export wrappers are compiled out, so the handler functions
// have no callers there.
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

use miden_event_handler_sdk as sdk;
#[cfg(target_arch = "wasm32")]
use sdk::abi::RawFelt;

/// Reads the stack element below the event ID, adds 100, and pushes the result to the advice
/// stack.
#[sdk::miden_event_handler("test::wasm::add_hundred")]
fn add_hundred() {
    #[cfg(target_arch = "wasm32")]
    {
        let value = sdk::stack_get(1);
        sdk::adv_stack_extend(&[RawFelt::new(value.as_u64() + 100)]);
    }
}

/// Panics; the panic handler forwards the message to the host.
#[sdk::miden_event_handler("test::wasm::always_panics")]
fn always_panics() {
    panic!("the fixture panicked on purpose");
}
