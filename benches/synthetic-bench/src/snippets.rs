//! Static catalog of MASM snippets that drive individual VM components.
//!
//! The patterns are deliberately few and natural -- they mirror work a real transaction does,
//! rather than one synthetic op per chiplet:
//!
//! - **hasher** drives BlakeG compression via repeated `bcompress`. The state evolves between
//!   iterations (one `padw padw padw` as setup, no reset), so each compression has a distinct input
//!   and the compression AIR's multiplicity column does not collapse them.
//! - **bitwise** drives the bitwise chiplet via `u32split + u32xor`.
//! - **memory** drives the memory chiplet. The address advances by `4 * 65537 = 262148` per iter so
//!   the two 16-bit halves of the word index form disjoint contiguous bands.
//! - **decoder_pad** drives only the core (system/decoder/stack) trace so the solver can top up
//!   core-trace budget without adding chiplet rows.
//!
//! Each snippet is partitioned into `setup` / `body` / `cleanup` so that the body alone can be
//! wrapped in a `repeat.N ... end` block. The body must leave stack depth unchanged -- the repeat
//! block would otherwise drift the stack each iteration.
//!
//! Decoder-only programs also incur hasher rows from MAST hashing, so low hasher targets may be
//! unreachable; the solver clamps `hasher` iterations to zero in that case.

/// A workload category in the snippet catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Component {
    /// System + decoder + stack.
    Core,
    Hasher,
    Bitwise,
    Memory,
}

/// A MASM fragment that dominantly drives one component.
#[derive(Debug, Clone, Copy)]
pub struct Snippet {
    pub name: &'static str,
    /// Runs once, outside the `repeat.N ... end` block.
    pub setup: &'static str,
    /// Runs N times inside the repeat block. Must be stack-balanced.
    pub body: &'static str,
    /// Runs once, outside the repeat block.
    pub cleanup: &'static str,
    /// The primary component this snippet drives.
    pub dominant: Component,
}

/// The full snippet catalog, in solver order: chiplet drivers first so they saturate their
/// targets, `decoder_pad` last so it absorbs leftover main-trace budget.
pub const SNIPPETS: &[Snippet] = &[
    Snippet {
        name: "hasher",
        setup: "padw padw padw",
        body: "bcompress",
        cleanup: "dropw dropw dropw",
        dominant: Component::Hasher,
    },
    Snippet {
        name: "bitwise",
        setup: "push.1 neg",
        body: "u32split u32xor",
        cleanup: "drop",
        dominant: Component::Bitwise,
    },
    Snippet {
        name: "memory",
        // Advance the word-aligned address by `4 * 65537 = 262148` each iter so that both 16-bit
        // halves of the word index evolve as disjoint contiguous bands. This keeps address-derived
        // range-check multiplicities representative; `assert_counters_fit` guards the u32 bound.
        setup: "padw push.2621520000",
        body: "dup.4 mem_storew_le dup.4 mem_loadw_le movup.4 push.262148 add movdn.4",
        cleanup: "drop dropw",
        dominant: Component::Memory,
    },
    Snippet {
        name: "decoder_pad",
        setup: "",
        body: "swap dup.1 add",
        cleanup: "",
        dominant: Component::Core,
    },
];

/// Look up a snippet by name. Only used by tests.
#[cfg(test)]
pub(crate) fn find(name: &str) -> Option<&'static Snippet> {
    SNIPPETS.iter().find(|s| s.name == name)
}

/// Assemble a single snippet into a complete program body: the setup, followed by
/// `repeat.iters body end`, followed by the cleanup. Returned text has no `begin`/`end` wrapping --
/// caller composes multiple snippets.
pub fn render(snippet: &Snippet, iters: u64) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if !snippet.setup.is_empty() {
        writeln!(out, "    {}", snippet.setup).unwrap();
    }
    if iters > 0 {
        writeln!(out, "    repeat.{iters}").unwrap();
        writeln!(out, "        {}", snippet.body).unwrap();
        writeln!(out, "    end").unwrap();
    }
    if !snippet.cleanup.is_empty() {
        writeln!(out, "    {}", snippet.cleanup).unwrap();
    }
    out
}

/// Wrap a snippet fragment into a complete `begin ... end` program.
pub fn wrap_program(body: &str) -> String {
    format!("begin\n{body}end\n")
}

// COUNTER SAFETY
// ------------------------------------------------------------------------
//
// The memory snippet advances its address counter with plain field `add`; memory ops would fail at
// runtime if the address crossed `u32::MAX`. This helper exposes the limit so callers can validate
// a plan before emitting.

/// Starting value of `memory`'s address counter.
const MEMORY_COUNTER_START: u64 = 2_621_520_000;
const MEMORY_COUNTER_STRIDE: u64 = 262_148;

const U32_MAX: u64 = u32::MAX as u64;

/// Maximum iterations of `memory` before the address counter would exceed `u32::MAX`.
pub fn memory_max_iters() -> u64 {
    (U32_MAX - MEMORY_COUNTER_START) / MEMORY_COUNTER_STRIDE
}

#[cfg(test)]
mod tests {
    use miden_vm::Assembler;

    use super::*;

    #[test]
    fn catalog_has_one_snippet_per_solver_component() {
        let targets = [Component::Core, Component::Hasher, Component::Bitwise, Component::Memory];
        for target in targets {
            let count = SNIPPETS.iter().filter(|s| s.dominant == target).count();
            assert_eq!(count, 1, "expected exactly one snippet for {target:?}");
        }
    }

    #[test]
    fn each_snippet_assembles_as_a_standalone_program() {
        // Fail fast: if a snippet has malformed MASM, the calibrator will blow up at bench time.
        // Catch it in unit tests instead.
        for snippet in SNIPPETS {
            let source = wrap_program(&render(snippet, 4));
            Assembler::default()
                .assemble_program("program", &source)
                .unwrap_or_else(|e| panic!("snippet {:?} failed to assemble: {e}", snippet.name));
        }
    }

    #[test]
    fn counter_limits_cover_realistic_plans() {
        // Realistic plans for consume/create P2ID transactions produce ~1.2k memory iters.
        // This guard has plenty of headroom for that regime.
        assert!(memory_max_iters() >= 6_000);
    }

    #[test]
    fn render_emits_repeat_with_body() {
        let snippet = find("bitwise").expect("bitwise snippet");
        let out = render(snippet, 42);
        assert!(out.contains("repeat.42"));
        assert!(out.contains("u32split u32xor"));
        assert!(out.contains("push.1 neg"));
        assert!(out.contains("drop"));
    }

    #[test]
    fn render_with_zero_iters_still_emits_setup_and_cleanup() {
        let snippet = find("hasher").expect("hasher snippet");
        let out = render(snippet, 0);
        assert!(out.contains("padw padw padw"));
        assert!(out.contains("dropw dropw dropw"));
        assert!(!out.contains("repeat."));
    }
}
