//! Solve for per-snippet iteration counts and emit the MASM program.
//!
//! The calibration matrix is close to diagonally dominant: each snippet primarily drives one
//! component and leaks small cross-terms into the others. A short Jacobi refinement with a
//! non-negativity clamp is enough for this problem size and handles infeasible targets gracefully.

use std::collections::BTreeMap;

use crate::{
    calibrator::Calibration,
    snapshot::TraceShape,
    snippets::{self, Component, SNIPPETS},
};

/// Small fixed-point refinement count. The calibrated systems in this crate converge in a few
/// passes, and the clamp keeps iteration counts non-negative.
const REFINEMENT_PASSES: usize = 8;

/// Iteration counts per snippet, ready to hand to the emitter.
///
/// Implemented as a sparse map where absence means "zero iterations"; the newtype hides the
/// `unwrap_or(0)` convention behind [`Plan::iters`] so call sites can't forget it.
#[derive(Debug, Default, Clone)]
pub struct Plan {
    entries: BTreeMap<&'static str, u64>,
}

impl Plan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Iteration count for `name`, or 0 if the snippet has no entry.
    pub fn iters(&self, name: &str) -> u64 {
        self.entries.get(name).copied().unwrap_or(0)
    }

    /// Set the iteration count for `name`, removing the entry entirely when `n == 0` so that
    /// `iters() == 0` is equivalent to the entry being absent.
    pub fn set(&mut self, name: &'static str, n: u64) {
        if n == 0 {
            self.entries.remove(name);
        } else {
            self.entries.insert(name, n);
        }
    }
}

/// Solve for iteration counts that reproduce the target's hard core, chiplets, and Eidos
/// compression totals plus its advisory memory composition.
pub fn solve(calibration: &Calibration, target: &TraceShape) -> Plan {
    let mut iters: BTreeMap<&'static str, f64> =
        SNIPPETS.iter().map(|s| (s.name, 0.0_f64)).collect();

    let component_target = |c: Component| -> f64 {
        match c {
            Component::Core => target.totals.core_rows as f64,
            Component::EidosCompression => target.totals.eidos_compression_rows as f64,
            // The chiplets total includes one mandatory structural padding row. Snippets only
            // need to reproduce the work rows that precede it.
            Component::Chiplets => target.totals.chiplets_rows.saturating_sub(1) as f64,
            Component::Memory => target.breakdown.memory_target() as f64,
        }
    };

    for _ in 0..REFINEMENT_PASSES {
        let snapshot = iters.clone();
        for snippet in SNIPPETS {
            let cost = match calibration.get(snippet.name) {
                Some(c) => *c,
                None => continue,
            };
            let rate = cost.get(snippet.dominant);
            if rate <= 0.0 {
                continue;
            }
            let target_rows = component_target(snippet.dominant);
            let cross_rows: f64 = SNIPPETS
                .iter()
                .filter(|s| s.name != snippet.name)
                .map(|s| {
                    let other =
                        calibration.get(s.name).map(|c| c.get(snippet.dominant)).unwrap_or(0.0);
                    other * snapshot[s.name]
                })
                .sum();
            let needed = (target_rows - cross_rows).max(0.0);
            iters.insert(snippet.name, needed / rate);
        }
    }

    let mut plan = Plan::new();
    for (name, v) in iters {
        plan.set(name, v.round().max(0.0) as u64);
    }
    plan
}

/// Render the plan as a single `begin ... end` program.
pub fn emit(plan: &Plan) -> String {
    use std::fmt::Write;
    let mut body = String::new();
    for snippet in SNIPPETS {
        let n = plan.iters(snippet.name);
        if n == 0 {
            continue;
        }
        write!(body, "{}", snippets::render(snippet, n)).unwrap();
    }
    snippets::wrap_program(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        calibrator::{calibrate, measure_program},
        snapshot::{TraceBreakdown, TraceTotals},
    };

    fn shape_of(
        core_rows: u64,
        byte_pair_lookup_rows: u64,
        eidos_compression: u64,
        controller_hasher: u64,
        bitwise: u64,
        memory: u64,
    ) -> TraceShape {
        let breakdown = TraceBreakdown {
            hasher_rows: controller_hasher,
            bitwise_rows: bitwise,
            memory_rows: memory,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let totals = TraceTotals {
            core_rows,
            chiplets_rows: breakdown.chiplets_sum(),
            eidos_compression_rows: eidos_compression,
            byte_pair_lookup_rows,
        };
        TraceShape::new(totals, breakdown)
    }

    fn low_compression_target() -> TraceShape {
        // The compression target is below the intrinsic work added by core and memory generation.
        shape_of(68900, 40000, 8200, 8200, 0, 2300)
    }

    fn high_compression_target() -> TraceShape {
        // A high standalone Eidos compression target with a much smaller controller-chiplets target
        // cannot be supplied by the memory filler alone, so the plan must contain explicit
        // compress work.
        shape_of(16000, 0, 32000, 1000, 0, 2000)
    }

    #[test]
    fn low_compression_target_does_not_add_compress() {
        let cal = calibrate().expect("calibrate");
        let plan = solve(&cal, &low_compression_target());
        assert_eq!(
            plan.iters("eidos_compression"),
            0,
            "when unavoidable work already exceeds the compression target, no compress iterations should be added",
        );
        assert!(plan.iters("memory") > 0);
    }

    #[test]
    fn high_compression_target_requires_compress() {
        let cal = calibrate().expect("calibrate");
        let plan = solve(&cal, &high_compression_target());
        assert!(
            plan.iters("eidos_compression") > 0,
            "a compression target above the core-induced floor should require compress iterations",
        );
    }

    #[test]
    fn controller_hasher_rows_do_not_substitute_for_compression_target() {
        let cal = calibrate().expect("calibrate");
        let target = shape_of(16_000, 0, 0, 32_000, 0, 2_000);
        let plan = solve(&cal, &target);

        assert_eq!(plan.iters("eidos_compression"), 0);
    }

    #[test]
    fn emitted_program_matches_padded_bracket() {
        let cal = calibrate().expect("calibrate");
        let target = low_compression_target();
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

    #[test]
    fn zero_target_yields_empty_program() {
        let cal = calibrate().expect("calibrate");
        let target = shape_of(0, 0, 0, 0, 0, 0);
        let plan = solve(&cal, &target);
        for snippet in SNIPPETS {
            assert_eq!(plan.iters(snippet.name), 0, "{}", snippet.name);
        }
        let source = emit(&plan);
        assert_eq!(source.trim(), "begin\nend");
    }
}
