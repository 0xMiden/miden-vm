//! A Rust guest crate with Wasm event handlers, used by the host-adapter end-to-end tests.
//!
//! This crate compiles only for `wasm32-unknown-unknown` (see `../.cargo/config.toml`); the
//! manifest is embedded in the `miden:event-manifest` custom section by the SDK macro.

#![no_std]

use miden_event_handler_sdk as sdk;
use sdk::Felt;

/// Reads the stack element below the event ID, adds 100 in the field, and pushes the result to
/// the advice stack.
#[sdk::miden_event_handler("test::wasm::add_hundred")]
fn add_hundred() {
    let value = sdk::stack_get(1);
    sdk::adv_stack_extend(&mut [value + Felt::from_u32(100)]);
}

/// Panics; the panic handler forwards the message to the host.
#[sdk::miden_event_handler("test::wasm::always_panics")]
fn always_panics() {
    panic!("the fixture panicked on purpose");
}

/// Merges the two stack words below the event ID and pushes the four digest elements to the
/// advice stack, the digest's first element on top.
#[sdk::miden_event_handler("test::wasm::merge_words")]
fn merge_words() {
    let pair = [sdk::stack_get_word(1), sdk::stack_get_word(5)];
    let digest = sdk::poseidon2_merge(&pair, Felt::ZERO);
    sdk::adv_stack_extend(&mut digest.into_elements());
}
