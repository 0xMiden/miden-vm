//! Reviewable degree metadata for the distinct production AIR types.
//!
//! Capture always receives authored source AIRs. Production tables never feed this analysis.

use alloc::string::String;
use core::fmt::{Debug, Write};

use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    air::LiftedAir,
    capture::ir::{capture, constraint_degrees},
};

pub const VM_FILE: &str = "vm-degrees.rs";
pub const PRECOMPILE_FILE: &str = "precompile-degrees.rs";

/// Generate both tables keyed by canonical enum identity, independent of selected slice order.
pub fn generate() -> [(&'static str, String); 2] {
    [
        (VM_FILE, table(&crate::vm::AIRS)),
        (PRECOMPILE_FILE, table(&crate::precompile::Air::all())),
    ]
}

fn table<A: LiftedAir<Felt, QuadFelt> + Debug>(airs: &[A]) -> String {
    let mut output = String::from(
        "\
// GENERATED constraint degree multiples -- do not edit.
// Regenerate with `make regenerate-constraints`.
// Periodic values: 1; transition selectors: 0; empty classes: 0; no advisory hints.

impl Air {
    /// Raw symbolic degree multiples for this canonical AIR, without evaluating constraints.
    pub const fn degrees(self) -> ConstraintDegrees {
        match self {
",
    );
    for air in airs {
        let (graph, constraints) = capture(air);
        let degrees = constraint_degrees(&graph, &constraints);
        writeln!(
            output,
            "            Self::{air:?} => ConstraintDegrees {{ base: {}, ext: {} }},",
            degrees.base, degrees.ext
        )
        .unwrap();
    }
    output.push_str("        }\n    }\n}\n");
    output
}
