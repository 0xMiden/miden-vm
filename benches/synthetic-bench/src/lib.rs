//! Synthetic benchmark generator for VM-level proving regression tests.
//!
//! Given a snapshot of per-component trace row counts captured by an external producer,
//! this crate calibrates a small catalog of MASM snippets against the current VM, solves
//! for iteration counts, emits a synthetic program, and verifies that the program lands
//! in the target core/chiplets padded brackets.
//!
//! The snapshot schema has two tiers:
//! - `trace`: hard totals (`core_rows`, `chiplets_rows`, `range_rows`)
//! - `shape`: advisory per-chiplet breakdown used by the solver
//!
//! See `README.md` for design rationale.

pub mod calibrator;

pub use miden_vm_synthetic_bench_core::{snapshot, snippets, solver, verifier};

#[cfg(test)]
mod tests {
    use miden_vm::Assembler;

    use crate::{
        calibrator::{calibrate, measure_program},
        snippets::{self, SNIPPETS},
        solver::{emit, solve},
    };

    #[test]
    fn each_snippet_assembles_as_a_standalone_program() {
        // Fail fast: if a snippet has malformed MASM, the calibrator will blow up at bench time.
        // Catch it in the harness tests instead.
        for snippet in SNIPPETS {
            let source = snippets::wrap_program(&snippets::render(snippet, 4));
            Assembler::default()
                .assemble_program(&source)
                .unwrap_or_else(|e| panic!("snippet {:?} failed to assemble: {e}", snippet.name));
        }
    }

    #[test]
    fn emitted_program_matches_padded_bracket() {
        let cal = calibrate().expect("calibrate");
        let target = miden_vm_synthetic_bench_core::snapshot::TraceShape::new(
            miden_vm_synthetic_bench_core::snapshot::TraceTotals {
                core_rows: 68_900,
                chiplets_rows: 10_501,
                range_rows: 40_000,
            },
            miden_vm_synthetic_bench_core::snapshot::TraceBreakdown {
                hasher_rows: 8_200,
                bitwise_rows: 0,
                memory_rows: 2_300,
                kernel_rom_rows: 0,
                ace_rows: 0,
            },
        );
        let plan = solve(&cal, &target);
        let source = emit(&plan);
        let actual = measure_program(&source).expect("measure emitted program");
        assert_eq!(
            actual.totals.padded_total(),
            target.totals.padded_total(),
            "padded trace length must match target bracket (got {} vs {})",
            actual.totals.padded_total(),
            target.totals.padded_total(),
        );
    }
}
