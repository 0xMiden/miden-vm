//! The Rust guest crate the fixture project declares through `[package.metadata.midenc.event-handlers]`.
//!
//! This crate compiles only for `wasm32-unknown-unknown` (see `../.cargo/config.toml`); the
//! manifest is embedded in the `miden:event-manifest` custom section by the SDK macro.

#![no_std]

use miden_event_handler_sdk as sdk;

/// Reads the stack element below the event ID, doubles it in the field, and pushes the result to
/// the advice stack.
#[sdk::miden_event_handler("test::project::double")]
fn double() {
    let value = sdk::stack_get(1);
    sdk::adv_stack_extend(&mut [value + value]);
}
