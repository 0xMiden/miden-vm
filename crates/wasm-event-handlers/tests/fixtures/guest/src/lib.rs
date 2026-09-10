//! A Rust guest crate with Wasm event handlers, used by the host-adapter end-to-end tests.
//!
//! This crate compiles only for `wasm32-unknown-unknown` (see `../.cargo/config.toml`); the
//! manifest is embedded in the `miden:event-manifest` custom section by the SDK macro.

#![no_std]

use miden_event_handler_sdk as sdk;
use sdk::Felt;

/// Reads the first stack input, adds 100 in the field, and pushes the result to the advice
/// stack.
#[sdk::miden_event_handler("test::wasm::add_hundred")]
fn add_hundred() {
    if sdk::invocation_kind() != sdk::InvocationKind::Event {
        sdk::fail("add_hundred requires a regular event");
    }
    let value = sdk::stack_get(0);
    sdk::adv_stack_extend(&mut [value + Felt::from_u32(100)]);
}

/// Panics; the panic handler forwards the message to the host.
#[sdk::miden_event_handler("test::wasm::always_panics")]
fn always_panics() {
    panic!("the fixture panicked on purpose");
}

/// Merges the first two stack-input words and pushes the four digest elements to the advice
/// stack, the digest's first element on top.
#[sdk::miden_event_handler("test::wasm::merge_words")]
fn merge_words() {
    let pair = [sdk::stack_get_word(0), sdk::stack_get_word(4)];
    let digest = sdk::poseidon2_merge(&pair, Felt::ZERO);
    sdk::adv_stack_extend(&mut digest.into_elements());
}

/// Reports root-context membership and reads the same address from current and root memory.
#[sdk::miden_event_handler("test::wasm::context_memory")]
fn context_memory() {
    let in_root = if sdk::is_root_context() { Felt::ONE } else { Felt::ZERO };
    let mut values = [in_root, Felt::ZERO, Felt::ZERO];
    if sdk::mem_read(100, &mut values[1..2]) != sdk::abi::Status::Ok {
        sdk::fail("current memory read failed");
    }
    if sdk::mem_read_root(100, &mut values[2..3]) != sdk::abi::Status::Ok {
        sdk::fail("root memory read failed");
    }
    sdk::adv_stack_extend(&mut values);
}
