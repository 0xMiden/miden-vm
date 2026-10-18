//! Reviewable degree metadata for the distinct production AIR types.
//!
//! Capture always receives authored source AIRs. Production tables never feed this analysis.

use alloc::{format, string::String};
use core::fmt::{Debug, Write};
use std::{fs, path::Path};

use miden_core::{Felt, field::QuadFelt};
use miden_stark::{
    air::LiftedAir,
    capture::ir::{capture, constraint_degrees},
};

use super::Mode;

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

pub(super) fn deliver(root: &Path, tables: &[(&str, String)], mode: Mode) -> Result<(), String> {
    for (name, content) in tables {
        let path = root.join(name);
        match mode {
            Mode::Check => {
                let staged = fs::read_to_string(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                if staged != *content {
                    return Err(format!(
                        "{} differs from authored AIR metadata analysis",
                        path.display()
                    ));
                }
            },
            Mode::Write => {
                fs::write(&path, content).map_err(|error| format!("{}: {error}", path.display()))?
            },
        }
        std::println!(
            "{} {}",
            match mode {
                Mode::Check => "checked",
                Mode::Write => "wrote",
            },
            path.display()
        );
    }
    Ok(())
}
