//! Embed checked native source metadata without retaining or recapturing its source.
//!
//! The descriptor and the evaluator graph must come from the same canonical authored capture.
//! Arithmetic optimization may change expression structure, so the source fingerprint and degree
//! recipe are copied from that capture rather than derived from optimized row code. Fixed matrices
//! remain owned by setup; only their declared dimensions belong in this output.

use std::fmt::Write as _;

use miden_core::Felt;
use miden_stark::air::native::{AirDescriptor, DegreeOp};

/// One source descriptor to emit alongside its generated evaluator.
pub struct AirDescriptorEmitter<'a> {
    /// Suffix of the emitted function name (`descriptor_{name}`).
    pub name: &'a str,
    /// Source label used in the generated function's documentation.
    pub air_label: &'a str,
    pub descriptor: &'a AirDescriptor<Felt>,
}

/// Emit owned descriptor constructors for validated canonical source captures.
///
/// The output needs `alloc` and the same core/crypto/STARK dependencies as a native evaluator.
/// Construct each result once in the owning kernel; no relation evaluator, witness algorithm or
/// fixed-table factory is called. The existing checked constructors validate embedded metadata
/// before it becomes a descriptor. Pairing the output with its evaluator is a trusted codegen
/// responsibility, not something the fingerprint can authenticate at runtime.
pub fn emit_module(header: &str, descriptors: &[AirDescriptorEmitter<'_>]) -> String {
    let mut out = String::from(header);
    out.push_str(
        r"
extern crate alloc;

use miden_core::Felt;
use miden_stark::air::native::{
    AirAnalysis, AirDescriptor, AirSpec, ConstraintDegrees, ConstraintLayout,
    DegreeOp, DegreeProfile, DescriptorParts,
};
",
    );
    for item in descriptors {
        let descriptor = item.descriptor;
        let spec = descriptor.spec();
        let analysis = descriptor.analysis();
        let profile = analysis.degree_profile();
        let degrees = analysis.raw_degrees();
        let preprocessed = match spec.preprocessed {
            Some(fixed) => format!(
                "Some(miden_stark::air::native::PreprocessedSpec {{ width: {}, log_height: {} }})",
                fixed.width, fixed.log_height,
            ),
            None => "None".to_string(),
        };
        let columns = spec
            .periodic_columns
            .iter()
            .map(|column| {
                let values = column
                    .iter()
                    .map(|value| {
                        format!(
                            "<Felt as miden_crypto::field::PrimeCharacteristicRing>::from_u64({})",
                            value.as_canonical_u64(),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("alloc::vec![{values}]")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let ops = profile.ops().iter().map(degree_op).collect::<Vec<_>>().join(", ");
        let labels: Vec<_> = (0..analysis.layout().total_constraints())
            .map(|index| descriptor.label(index))
            .collect();
        let labels = if labels.iter().any(Option::is_some) {
            let entries = labels
                .iter()
                .map(|label| match label {
                    Some(text) => format!("Some({text:?}.into())"),
                    None => "None".to_string(),
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("Some(alloc::vec![{entries}])")
        } else {
            "None".to_string()
        };
        writeln!(
            out,
            r#"
/// Checked source descriptor for `{}`.
pub fn descriptor_{}() -> AirDescriptor<Felt> {{
    let spec = AirSpec {{
        main_width: {}, aux_width: {}, num_public_values: {},
        num_challenges: {}, num_exports: {}, preprocessed: {preprocessed},
        periodic_columns: alloc::borrow::Cow::Owned(alloc::vec![{columns}]),
    }};
    let layout = ConstraintLayout::new(alloc::vec!{:?}, alloc::vec!{:?})
        .expect("validated generated assertion layout");
    let ops: alloc::vec::Vec<DegreeOp> = alloc::vec![{ops}];
    let profile = DegreeProfile::new(ops, alloc::vec!{:?})
        .expect("validated generated degree recipe");
    let analysis = AirAnalysis::new(layout, ConstraintDegrees {{ base: {}, ext: {} }}, profile)
        .expect("validated generated degree roots");
    AirDescriptor::from_trusted_parts(DescriptorParts {{
        spec, analysis, fingerprint: {:?}, labels: {labels},
    }}).expect("validated generated source descriptor")
}}"#,
            item.air_label,
            item.name,
            spec.main_width,
            spec.aux_width,
            spec.num_public_values,
            spec.num_challenges,
            spec.num_exports,
            analysis.layout().base_indices(),
            analysis.layout().ext_indices(),
            profile.roots(),
            degrees.base,
            degrees.ext,
            descriptor.fingerprint(),
        )
        .unwrap();
    }
    out
}

fn degree_op(op: &DegreeOp) -> String {
    // Debug includes only the checked enum's name and integer operands, all valid Rust tokens.
    format!("DegreeOp::{op:?}")
}
