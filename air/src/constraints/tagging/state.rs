//! Thread-local tagging state for enforcing tag ordering and counts.

use alloc::vec::Vec;
use std::{
    cell::{Cell, RefCell},
    thread_local,
};
/// Active tagged block metadata.
#[derive(Debug)]
struct TagContext {
    namespace: &'static str,
    ids: Vec<usize>,
    next: usize,
}

thread_local! {
    static TAGGING_ENABLED: Cell<bool> = const { Cell::new(false) };
    static TAG_STACK: RefCell<Vec<TagContext>> = const { RefCell::new(Vec::new()) };
}

/// Returns `true` when tagging is enabled for the current thread.
pub fn is_enabled() -> bool {
    TAGGING_ENABLED.with(|flag| flag.get())
}

/// Enables or disables tagging for the current thread.
#[cfg(test)]
pub fn set_enabled(enabled: bool) {
    TAGGING_ENABLED.with(|flag| flag.set(enabled));
}

/// Run `f` under a tagged context with the provided IDs.
///
/// This enforces:
/// - exactly one tagged context at a time (no nesting),
/// - at least one ID,
/// - and the number of emitted assertions matches the ID list length.
pub fn with_tag<R>(ids: Vec<usize>, namespace: &'static str, f: impl FnOnce() -> R) -> R {
    if ids.is_empty() {
        panic!("tagged block '{namespace}' must include at least one id");
    }
    TAG_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if !stack.is_empty() {
            panic!("nested tagged blocks are not allowed");
        }
        stack.push(TagContext { namespace, ids, next: 0 });
    });

    let result = f();

    TAG_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let ctx = stack.pop().expect("tag stack underflow");
        if ctx.next != ctx.ids.len() {
            panic!(
                "tagged block '{}' expected {} asserts, saw {}",
                ctx.namespace,
                ctx.ids.len(),
                ctx.next
            );
        }
    });

    result
}

/// Consume the next tag ID for the current tagged context.
///
/// Panics if called outside a tagged block or if the block emits too many assertions.
#[cfg(test)]
pub fn consume_tag() -> (usize, &'static str) {
    TAG_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        let ctx = stack.last_mut().expect("assertion made without an active tagged block");
        if ctx.next >= ctx.ids.len() {
            panic!(
                "tagged block '{}' exceeded expected asserts ({})",
                ctx.namespace,
                ctx.ids.len()
            );
        }
        let id = ctx.ids[ctx.next];
        ctx.next += 1;
        (id, ctx.namespace)
    })
}
