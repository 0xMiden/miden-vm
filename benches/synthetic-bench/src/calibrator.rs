//! Calibration and measurement helpers.
//!
//! Each snippet is run as a `repeat.K` loop, measured through the real trace builder, and
//! converted into per-iteration row costs. Calibration happens on every bench run so the synthetic
//! adapts to the current VM's row accounting.

use std::collections::BTreeMap;

use miden_processor::{DefaultHost, FastProcessor, StackInputs, trace::build_trace};
use miden_vm::Assembler;

use crate::{
    snapshot::{TraceBreakdown, TraceShape, TraceTotals},
    snippets::{self, Component, SNIPPETS},
};

pub const CALIBRATION_ITERS: u64 = 1000;

// MEASUREMENT
// ------------------------------------------------------------------------

/// Assemble and execute `source`, returning the shape of the resulting execution trace. Wraps
/// assembler + fast processor + trace builder.
pub fn measure_program(source: &str) -> Result<TraceShape, MeasurementError> {
    let program = Assembler::default()
        .assemble_program(source)
        .map_err(|e| MeasurementError::Assembly(format!("{e}")))?;

    let mut host = DefaultHost::default();
    let processor = FastProcessor::new(StackInputs::default());
    let trace_inputs = processor
        .execute_trace_inputs_sync(&program, &mut host)
        .map_err(|e| MeasurementError::Execution(format!("{e}")))?;
    let trace =
        build_trace(trace_inputs).map_err(|e| MeasurementError::TraceBuild(format!("{e}")))?;
    let summary = trace.trace_len_summary();
    let chiplets = summary.chiplets_trace_len();

    let breakdown = TraceBreakdown {
        hasher_rows: chiplets.hash_chiplet_len() as u64,
        bitwise_rows: chiplets.bitwise_chiplet_len() as u64,
        memory_rows: chiplets.memory_chiplet_len() as u64,
        kernel_rom_rows: chiplets.kernel_rom_len() as u64,
        ace_rows: chiplets.ace_chiplet_len() as u64,
    };
    let totals = TraceTotals {
        core_rows: summary.main_trace_len() as u64,
        chiplets_rows: chiplets.trace_len() as u64,
        range_rows: summary.range_trace_len() as u64,
    };

    // Cross-check our derived formulas against the processor's authoritative values; a drift here
    // means the AIR-side definitions have moved and the rest of the pipeline will silently
    // miscalibrate.
    let derived_chiplets = breakdown.chiplets_sum();
    if totals.chiplets_rows != derived_chiplets {
        return Err(MeasurementError::InvariantDrift {
            quantity: "chiplets_total",
            processor: totals.chiplets_rows,
            derived: derived_chiplets,
        });
    }
    let derived_padded = totals.padded_total();
    let processor_padded = summary.padded_trace_len() as u64;
    if derived_padded != processor_padded {
        return Err(MeasurementError::InvariantDrift {
            quantity: "padded_total",
            processor: processor_padded,
            derived: derived_padded,
        });
    }

    Ok(TraceShape::new(totals, breakdown))
}

#[derive(Debug, thiserror::Error)]
pub enum MeasurementError {
    #[error("failed to assemble program: {0}")]
    Assembly(String),
    #[error("failed to execute program: {0}")]
    Execution(String),
    #[error("failed to build trace: {0}")]
    TraceBuild(String),
    /// One of our derived formulas drifted from the processor's authoritative value; AIR-side
    /// definitions have probably changed and the snapshot/verifier formulas need updating.
    #[error(
        "invariant drift: {quantity} from processor = {processor}, but our derivation = {derived}"
    )]
    InvariantDrift {
        quantity: &'static str,
        processor: u64,
        derived: u64,
    },
}

// CALIBRATION
// ------------------------------------------------------------------------

/// Per-iteration row rates, kept as `f64` and rounded by the solver.
#[derive(Debug, Clone, Copy, Default)]
pub struct IterCost {
    pub core: f64,
    pub hasher: f64,
    pub bitwise: f64,
    pub memory: f64,
    pub range: f64,
}

impl IterCost {
    pub fn get(&self, component: Component) -> f64 {
        match component {
            Component::Core => self.core,
            Component::Hasher => self.hasher,
            Component::Bitwise => self.bitwise,
            Component::Memory => self.memory,
            Component::Range => self.range,
        }
    }
}

/// Per-snippet rows-per-iter across every tracked component. Cross-terms (e.g. a non-zero hasher
/// rate on the `decoder_pad` snippet) are measured so the solver can subtract them.
pub type Calibration = BTreeMap<&'static str, IterCost>;

/// Run every snippet through a single-point calibration at [`CALIBRATION_ITERS`] and record
/// per-iter cost in each component.
pub fn calibrate() -> Result<Calibration, MeasurementError> {
    let mut cal = Calibration::new();
    for snippet in SNIPPETS {
        let source = snippets::wrap_program(&snippets::render(snippet, CALIBRATION_ITERS));
        let shape = measure_program(&source)?;
        cal.insert(snippet.name, per_iter_cost(shape, CALIBRATION_ITERS));
    }
    Ok(cal)
}

fn per_iter_cost(shape: TraceShape, iters: u64) -> IterCost {
    let k = iters as f64;
    IterCost {
        core: shape.totals.core_rows as f64 / k,
        hasher: shape.breakdown.hasher_rows as f64 / k,
        bitwise: shape.breakdown.bitwise_rows as f64 / k,
        memory: shape.breakdown.memory_rows as f64 / k,
        range: shape.totals.range_rows as f64 / k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // MEASUREMENT TESTS
    // --------------------------------------------------------------------

    #[test]
    fn measures_trivial_program() {
        // `measure_program()` already cross-checks our derived totals against the processor's
        // authoritative values; this test just smoke-checks basic measurement.
        let shape = measure_program("begin push.1 drop end").expect("measure");
        assert!(shape.totals.core_rows > 0, "main trace should include framing rows");
        assert!(shape.totals.padded_total().is_power_of_two());
    }

    #[test]
    fn hperm_adds_rows_beyond_baseline() {
        let baseline = measure_program("begin push.1 drop end").expect("baseline");
        let with_hperm =
            measure_program("begin padw padw padw hperm dropw dropw dropw end").expect("hperm");
        assert!(
            with_hperm.breakdown.hasher_rows > baseline.breakdown.hasher_rows,
            "hperm should add hasher rows above the baseline ({} vs {})",
            with_hperm.breakdown.hasher_rows,
            baseline.breakdown.hasher_rows,
        );
    }

    // CALIBRATION TESTS
    // --------------------------------------------------------------------

    fn cal() -> Calibration {
        calibrate().expect("calibration should succeed")
    }

    #[test]
    fn every_snippet_has_an_entry() {
        let c = cal();
        for snippet in SNIPPETS {
            assert!(c.contains_key(snippet.name), "missing calibration for {}", snippet.name);
        }
    }

    #[test]
    fn hasher_snippet_is_hasher_dominant() {
        let c = cal();
        let hasher = c["hasher"];
        let pad = c["decoder_pad"];
        assert!(
            hasher.hasher > pad.hasher * 10.0,
            "hasher/iter ({}) not dominant over decoder_pad leak ({})",
            hasher.hasher,
            pad.hasher,
        );
    }

    #[test]
    fn bitwise_snippet_rows_match_op_cycle_len() {
        let c = cal();
        let bitwise = c["bitwise"];
        // OP_CYCLE_LEN = 8 per u32 bitwise op.
        assert!(
            bitwise.bitwise >= 7.5,
            "bitwise per-iter ({}) below OP_CYCLE_LEN",
            bitwise.bitwise
        );
        assert!(
            bitwise.bitwise <= 9.0,
            "bitwise per-iter ({}) above OP_CYCLE_LEN",
            bitwise.bitwise
        );
    }

    #[test]
    fn memory_snippet_two_rows_per_iter() {
        let c = cal();
        let memory = c["memory"];
        assert!(memory.memory >= 1.5, "memory per-iter ({}) too low", memory.memory);
        assert!(memory.memory <= 2.5, "memory per-iter ({}) too high", memory.memory);
    }

    #[test]
    fn u32arith_snippet_drives_range() {
        let c = cal();
        let arith = c["u32arith"];
        let pad = c["decoder_pad"];
        assert!(
            arith.range > pad.range * 5.0,
            "u32arith range/iter ({}) should dominate the baseline decoder_pad range/iter ({})",
            arith.range,
            pad.range,
        );
    }

    #[test]
    fn decoder_pad_is_core_dominant() {
        let c = cal();
        let pad = c["decoder_pad"];
        assert!(pad.core > 1.0, "decoder_pad core/iter should be > 1.0");
        assert!(
            pad.core > pad.hasher * 3.0,
            "decoder_pad core ({}) should dominate hasher ({})",
            pad.core,
            pad.hasher,
        );
    }
}
