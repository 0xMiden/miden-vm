//! MASM generation for auxiliary LogUp verification.
//!
//! The AIR count determines the absorption, scatter and weighting code. The relation supplies
//! the procedure that computes its external boundary correction.

use std::{fmt::Write as _, format, string::String, vec::Vec};

use miden_core::WORD_SIZE;
use miden_crypto::hash::eidos::BLOCK_LEN;

use crate::{AceError, EXT_DEGREE, MAX_ORDER_AIRS};

/// Relation bindings for a stage with one normalized extension-field LogUp sum per AIR.
pub struct MasmAuxTraceConfig<'a> {
    /// Regeneration command shown in the generated module's header.
    pub generated_by: &'a str,
    /// Module exposing `AUX_BUS_BOUNDARY_PTR` for `num_airs` consecutive extension values,
    /// plus `AUX_BOUNDARY_WORD_n_PTR` aliases for each full word after the first.
    pub boundary_module: &'a str,
    /// Module containing the relation's boundary-correction procedure.
    pub correction_module: &'a str,
    /// Procedure returning the signed correction as `[c0, c1]` above the caller's stack.
    /// It depends only on stored challenges and the relation statement, and may write only
    /// relation-owned scratch. It preserves caller values, transcript state and proof advice.
    pub correction_procedure: &'a str,
    /// Number of AIRs, each supplying one normalized LogUp sum.
    pub num_airs: usize,
}

/// Generates a stage that absorbs one normalized LogUp sum per AIR and checks that their
/// trace-length-weighted sum plus the relation's boundary correction is zero.
///
/// At runtime, the caller must stage the relation's boundary inputs, validated canonical heights,
/// and a map from AIR ids to proof positions. The challenger input buffer must be empty.
/// Counts outside `2..=MAX_ORDER_AIRS` are rejected.
pub fn render_masm_aux_trace(config: &MasmAuxTraceConfig<'_>) -> Result<String, AceError> {
    let n = config.num_airs;
    if !(2..=MAX_ORDER_AIRS).contains(&n) {
        return Err(AceError::InvalidInputLayout {
            message: format!("LogUp staging needs 2..={MAX_ORDER_AIRS} AIRs, got {n}"),
        });
    }
    let coordinates = n * EXT_DEGREE;
    let words = coordinates / WORD_SIZE;

    let mut aliases = String::new();
    let mut boundary_imports = String::from("    AUX_BUS_BOUNDARY_PTR,\n");
    let mut scatter = String::new();
    let mut observe = String::new();
    let mut weighted = String::new();
    for air in 1..n {
        writeln!(
            aliases,
            "const AIR_{air}_PROOF_POSITION_PTR = PROOF_ORDER_POSITIONS_PTR + {air}"
        )
        .unwrap();
        writeln!(
            aliases,
            "const CANONICAL_AIR_{air}_LOG_HEIGHT_PTR = LOG_AIR_TRACE_LENGTHS_PTR + {air}"
        )
        .unwrap();
    }
    for air in (0..n).rev() {
        let position = if air == 0 {
            String::from("PROOF_ORDER_POSITIONS_PTR")
        } else {
            format!("AIR_{air}_PROOF_POSITION_PTR")
        };
        writeln!(scatter, "    mem_load.{position} exec.load_boundary_pair").unwrap();
    }
    writeln!(scatter, "    # => [canonical_sums({coordinates}), ...]").unwrap();
    for word in 0..words {
        let pointer = if word == 0 {
            String::from("AUX_BUS_BOUNDARY_PTR")
        } else {
            let pointer = format!("AUX_BOUNDARY_WORD_{word}_PTR");
            writeln!(boundary_imports, "    {pointer},").unwrap();
            pointer
        };
        writeln!(scatter, "    mem_storew_le.{pointer} dropw").unwrap();
        writeln!(
            observe,
            "    padw adv_loadw mem_storew_le.{pointer}\n    exec.random_coin::eidos_observe_word"
        )
        .unwrap();
    }
    // An odd AIR count leaves two coordinates. A word read would consume the next proof field.
    for offset in words * WORD_SIZE..coordinates {
        writeln!(scatter, "    push.AUX_BUS_BOUNDARY_PTR add.{offset} mem_store").unwrap();
        writeln!(
            observe,
            "    adv_push dup push.AUX_BUS_BOUNDARY_PTR add.{offset} mem_store\n    \
             exec.random_coin::observe_felt"
        )
        .unwrap();
    }
    for air in 0..n {
        let height = if air == 0 {
            String::from("LOG_AIR_TRACE_LENGTHS_PTR")
        } else {
            format!("CANONICAL_AIR_{air}_LOG_HEIGHT_PTR")
        };
        writeln!(
            weighted,
            "    mem_load.{height} push.{} exec.load_weighted_aux_sum",
            EXT_DEGREE * air
        )
        .unwrap();
        if air > 0 {
            weighted.push_str("    ext2add\n");
        }
    }
    let correction_alias = config.correction_module.rsplit("::").next().unwrap();
    Ok(include_str!("templates/aux_trace.masm")
        .replace("{{generated_by}}", config.generated_by)
        .replace("{{aliases}}", aliases.trim_end())
        .replace("{{boundary_imports}}", boundary_imports.trim_end())
        .replace("{{boundary_module}}", config.boundary_module)
        .replace("{{correction_module}}", config.correction_module)
        .replace(
            "{{correction_call}}",
            &format!("{correction_alias}::{}", config.correction_procedure),
        )
        .replace("{{num_airs}}", &n.to_string())
        .replace("{{buffered_felts}}", &((WORD_SIZE + coordinates) % BLOCK_LEN).to_string())
        .replace("{{scatter}}", scatter.trim_end())
        .replace("{{observe}}", observe.trim_end())
        .replace("{{weighted}}", weighted.trim_end()))
}

/// Emits fixed exponentiation: `[x0, x1, ...]` becomes `[(x^exponent)0, (x^exponent)1, ...]`,
/// preserving every caller value. Exponent zero returns the extension-field identity, including
/// for a zero base. The emitted instructions use no advice, memory, or runtime loop.
///
/// Powers of two need only squarings. Otherwise the odd part uses a retained base, consumed by
/// the final multiplication. The returned instruction lines have no indentation.
pub fn render_masm_ext2_power(exponent: u32) -> String {
    if exponent == 0 {
        return "drop drop push.0.1".into();
    }
    if exponent == 1 {
        // MASM requires a nonempty procedure body even for the identity operation.
        return "nop".into();
    }
    let mut operations = Vec::new();
    let squarings = exponent.trailing_zeros();
    operations.extend(core::iter::repeat_n("dup.1 dup.1 ext2mul", squarings as usize));
    let odd_part = exponent >> squarings;
    if odd_part > 1 {
        operations.push("dup.1 dup.1");
        // Keep the base below the accumulator while processing the remaining exponent bits.
        // The last bit is one, so its multiplication consumes the retained base.
        for bit in (0..odd_part.ilog2()).rev() {
            operations.push("dup.1 dup.1 ext2mul");
            if (odd_part >> bit) & 1 != 0 {
                if bit > 0 {
                    operations.push("dup.3 dup.3");
                }
                operations.push("ext2mul");
            }
        }
    }
    operations.join("\n")
}
