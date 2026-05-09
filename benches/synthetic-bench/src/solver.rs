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

    /// Increment the iteration count for `name` by `delta`.
    pub fn add(&mut self, name: &'static str, delta: u64) {
        if delta == 0 {
            return;
        }
        self.set(name, self.iters(name) + delta);
    }

    /// Decrement the iteration count for `name` by `delta`, saturating at zero.
    pub fn sub_saturating(&mut self, name: &'static str, delta: u64) {
        self.set(name, self.iters(name).saturating_sub(delta));
    }
}

/// Solve for the iteration counts that reproduce `target`'s per-component row counts. Per-chiplet
/// targets come from the snapshot's advisory `shape` breakdown -- the solver uses them to keep the
/// synthetic program representative, but the verifier only hard-asserts totals/brackets.
pub fn solve(calibration: &Calibration, target: &TraceShape) -> Plan {
    let mut iters: BTreeMap<&'static str, f64> =
        SNIPPETS.iter().map(|s| (s.name, 0.0_f64)).collect();

    let component_target = |c: Component| -> f64 {
        match c {
            Component::Core => target.totals.core_rows as f64,
            Component::Hasher => target.breakdown.hasher_rows as f64,
            Component::Bitwise => target.breakdown.bitwise_rows as f64,
            Component::Memory => target.breakdown.memory_target() as f64,
            Component::Range => target.totals.range_rows as f64,
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
        range_rows: u64,
        hasher: u64,
        bitwise: u64,
        memory: u64,
    ) -> TraceShape {
        let breakdown = TraceBreakdown {
            hasher_rows: hasher,
            bitwise_rows: bitwise,
            memory_rows: memory,
            kernel_rom_rows: 0,
            ace_rows: 0,
        };
        let totals = TraceTotals {
            core_rows,
            chiplets_rows: breakdown.chiplets_sum(),
            range_rows,
        };
        TraceShape::new(totals, breakdown)
    }

    fn low_hasher_target() -> TraceShape {
        // core/hasher ratio of ~8, well below the intrinsic core/4 floor. Memory kept modest
        // (ratio core/memory ~30) so the test exercises the hasher-feasibility path without making
        // it infeasible via memory overshoot into core.
        shape_of(68900, 40000, 8200, 0, 2300)
    }

    fn high_hasher_target() -> TraceShape {
        // main/hasher ratio of ~2, above the intrinsic main/4 floor.
        shape_of(16000, 0, 8000, 0, 0)
    }

    #[test]
    fn low_hasher_target_does_not_add_hperm() {
        let cal = calibrate().expect("calibrate");
        let plan = solve(&cal, &low_hasher_target());
        assert_eq!(
            plan.iters("hasher"),
            0,
            "when the decoder (via memory + pad) already overshoots the hasher target, no hperm iterations should be added",
        );
        assert!(plan.iters("memory") > 0);
    }

    #[test]
    fn high_hasher_target_requires_hperm() {
        let cal = calibrate().expect("calibrate");
        let plan = solve(&cal, &high_hasher_target());
        assert!(
            plan.iters("hasher") > 0,
            "a hasher target above the main/4 floor should require hperm iterations",
        );
    }

    #[test]
    fn emitted_program_matches_padded_bracket() {
        let cal = calibrate().expect("calibrate");
        let target = low_hasher_target();
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
        let target = shape_of(0, 0, 0, 0, 0);
        let plan = solve(&cal, &target);
        for snippet in SNIPPETS {
            assert_eq!(plan.iters(snippet.name), 0, "{}", snippet.name);
        }
        let source = emit(&plan);
        assert_eq!(source.trim(), "begin\nend");
    }
}
