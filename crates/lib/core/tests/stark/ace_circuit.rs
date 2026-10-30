//! Generated ACE artifacts, protocol constants, and input-region bounds.

use miden_air::vm::config;
use miden_core::{Felt, field::QuadFelt};
#[cfg(feature = "constraints-tools")]
use miden_core_lib::constraints_regen;

use super::{pvm_layout_const, vm_layout_const};

#[cfg(feature = "constraints-tools")]
#[test]
fn generated_recursive_verifier_artifacts_match_air() {
    constraints_regen::run(constraints_regen::Mode::Check)
        .expect("recursive-verifier artifact drift check failed");
}

#[cfg(feature = "constraints-tools")]
#[test]
fn security_masm_matches_air() {
    constraints_regen::security_masm_matches_air().expect("security literal drift check failed");
}

#[test]
fn quotient_recomposition_constants_match_derivation() {
    // The generated evaluator serializes values derived from two independent protocol inputs:
    // quotient arity from the AIRs, and the canonical LDE shift from the PCS configuration. The VM
    // has arity = blowup = 8, so deriving all three from the blowup would produce the
    // same numbers and conceal the conflation that breaks relations where they differ.
    let masm = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/asm/sys/vm/constraints_eval.masm"
    ))
    .expect("read generated VM constraints evaluator");
    let masm_const = |name: &str| -> u64 {
        masm.lines()
            .find_map(|line| {
                let (lhs, rhs) = line.trim().strip_prefix("const ")?.split_once('=')?;
                if lhs.trim() != name {
                    return None;
                }
                Some(rhs.split_whitespace().next()?.parse().expect("parse const value"))
            })
            .unwrap_or_else(|| panic!("const {name} not found in VM constraints evaluator"))
    };

    let shift_ratio = Felt::new(masm_const("QUOTIENT_SHIFT_RATIO")).unwrap();
    let first_shift = Felt::new(masm_const("QUOTIENT_FIRST_SHIFT")).unwrap();
    let first_weight = Felt::new(masm_const("QUOTIENT_FIRST_WEIGHT")).unwrap();

    let log_quotient_degree = miden_air::vm::AIRS
        .iter()
        .map(miden_stark::log_quotient_degree::<Felt, QuadFelt, _>)
        .max()
        .expect("the Miden AIR set is non-empty");
    let expected = miden_stark::quotient_recomposition_inputs::<Felt>(
        log_quotient_degree,
        config::pcs_params().log_blowup(),
    )
    .expect("the Miden quotient degree fits its PCS blowup");

    assert_eq!(shift_ratio, expected.shift_ratio, "QUOTIENT_SHIFT_RATIO is stale");
    assert_eq!(first_shift, expected.first_shift, "QUOTIENT_FIRST_SHIFT is stale");
    assert_eq!(first_weight, expected.first_weight, "QUOTIENT_FIRST_WEIGHT is stale");
}

/// Fold coefficients follow the selector block and must fit before the ACE circuit stream.
/// The static memory-layout audit checks declared allocations and immediate addresses. These
/// writes use a computed base plus an offset, so check the evaluator's actual offset here.
#[test]
fn staged_fold_coefficients_fit_the_declared_ace_input_region() {
    const STAGING_PROC: &str = "stage_air_fold_coefficients";
    const OFFSET_SITE: &str = "exec.layout::auxiliary_ace_inputs_ptr add.";
    /// Base felts per staged coefficient (one quadratic-extension element).
    const COEFFICIENT_STRIDE: u32 = 2;

    let shared = include_str!("../../asm/stark/constraints_eval_inputs.masm");
    let masm_const = |source: &str, name: &str, what: &str| -> u32 {
        let prefix = format!("const {name} = ");
        source
            .lines()
            .find_map(|line| line.trim().strip_prefix(&prefix)?.parse::<u32>().ok())
            .unwrap_or_else(|| panic!("missing {what} constant {name}"))
    };

    let first_selector_offset = masm_const(shared, "FIRST_SELECTOR_OFFSET", "shared");
    let selector_stride = masm_const(shared, "SELECTOR_STRIDE", "shared");
    assert!(
        !shared.contains(&format!("proc {STAGING_PROC}")),
        "the shared module must not carry a second fold-coefficient algorithm"
    );

    for (relation, layout_const, evaluator) in [
        (
            "vm",
            vm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/vm/constraints_eval.masm"),
        ),
        (
            "pvm",
            pvm_layout_const as fn(&str) -> u32,
            include_str!("../../asm/sys/pvm/constraints_eval.masm"),
        ),
    ] {
        let num_airs = masm_const(evaluator, "NUM_AIRS", relation);
        let region_felts =
            layout_const("ACE_CIRCUIT_STREAM_PTR") - layout_const("AUXILIARY_ACE_INPUTS_PTR");

        // Walk the procedure declarations rather than the raw text so a rename fails here instead
        // of turning this guard into a silent no-op.
        let mut declares_staging = false;
        let mut in_staging = false;
        let mut staged_offset = None;
        for line in evaluator.lines() {
            let trimmed = line.trim();
            if let Some(rest) =
                trimmed.strip_prefix("pub proc ").or_else(|| trimmed.strip_prefix("proc "))
            {
                let name = rest.split(['(', ' ']).next().unwrap_or(rest);
                if name == STAGING_PROC {
                    assert!(
                        !trimmed.starts_with("pub "),
                        "{relation}: {STAGING_PROC} must stay private to the evaluator"
                    );
                }
                declares_staging |= name == STAGING_PROC;
                in_staging = name == STAGING_PROC;
            }
            if in_staging && let Some(offset) = trimmed.strip_prefix(OFFSET_SITE) {
                staged_offset = offset.parse::<u32>().ok();
            }
        }
        assert!(declares_staging, "{relation}: {STAGING_PROC} is no longer declared");
        let staged_offset =
            staged_offset.unwrap_or_else(|| panic!("{relation}: {STAGING_PROC} has no offset"));

        let selectors_end = first_selector_offset + selector_stride * num_airs;
        assert_eq!(
            staged_offset, selectors_end,
            "{relation}: the evaluator stages fold coefficients off the slot right after the \
             selector block"
        );
        let coefficients_end = selectors_end + COEFFICIENT_STRIDE * num_airs;
        assert!(
            coefficients_end <= region_felts,
            "{relation}: {num_airs} fold coefficients end at felt {coefficients_end}, past the \
             {region_felts}-felt AUXILIARY_ACE_INPUTS_PTR region; enlarge the region before \
             staging them"
        );
    }
}
