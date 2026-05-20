//! Structural and snapshot tests for the codegen.
//!
//! Two layers of coverage:
//!  - structural: assert that the emitted MASM contains the operations and offsets expected for
//!    each spec. Catches regressions where the emitter still produces something but the wrong thing
//!    (e.g., wrong h-storage offset, missing aux check).
//!  - snapshot: assert that the emitted module matches the checked-in artifact byte-for-byte.
//!    Catches any drift; CI runs `regen --check` to enforce that artifacts stay in sync.

use miden_sz_codegen::{
    emit_masm, emit_module,
    spec::{AuxCheck, PolyRef},
    specs,
};

// ----- MODMUL_K1_BASE -----------------------------------------------------------------------

#[test]
fn modmul_k1_base_emits_signed_carry() {
    let s = emit_masm(&specs::MODMUL_K1_BASE);
    assert!(
        s.contains("ext2sub                               # pos_h - neg_h"),
        "expected pos - neg subtraction in carry term"
    );
    assert!(
        s.contains("ext2mul                               # (W - alpha) * (pos - neg)"),
        "expected signed-carry ext2mul"
    );
    assert!(s.contains("e_pos_30 must be 0"));
    assert!(s.contains("e_pos_31 must be 0"));
    assert!(s.contains("e_neg_30 must be 0"));
    assert!(s.contains("e_neg_31 must be 0"));
}

#[test]
fn modmul_k1_base_emits_fused_canonical_check() {
    let s = emit_masm(&specs::MODMUL_K1_BASE);
    assert!(
        s.contains("# ----- fused canonical check: c < p -----"),
        "expected fused canonical-check block"
    );
    assert!(s.contains("dupw.1\n    dupw.1"), "expected dupw.1 dupw.1 to preserve c");
    assert!(s.contains("c < p violated"));
}

#[test]
#[should_panic(expected = "must declare exactly one LessThan aux check")]
fn modmul_spec_without_canonical_check_is_rejected() {
    const AUX_WITHOUT_LT: &[AuxCheck] = &[
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_pos"), index: 31 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 30 },
        AuxCheck::LimbIsZero { poly: PolyRef("e_neg"), index: 31 },
    ];

    let mut rel = specs::MODMUL_K1_BASE;
    rel.aux_checks = AUX_WITHOUT_LT;
    let _ = emit_masm(&rel);
}

#[test]
fn modmul_k1_base_emits_fs_check() {
    let s = emit_masm(&specs::MODMUL_K1_BASE);
    assert!(s.contains("alpha_0 mismatch (Fiat-Shamir failure)"));
    assert!(s.contains("alpha_1 mismatch (Fiat-Shamir failure)"));
}

// ----- snapshot tests -----------------------------------------------------------------------
//
// Compare each emitted MASM module to the checked-in artifact byte-for-byte. If these tests
// fail, either the emitter changed unexpectedly or the artifact is stale. Running
// `cargo run -p miden-sz-codegen --bin regen` regenerates artifacts to match the spec.

#[test]
fn modmul_k1_base_matches_checked_in_artifact() {
    let emitted = emit_module(&specs::MODMUL_K1_BASE);
    let on_disk = include_str!("../../lib/core/asm/math/u256_sz_modmul_k1_base.masm");
    assert_eq!(
        emitted, on_disk,
        "u256_sz_modmul_k1_base.masm is out of sync with MODMUL_K1_BASE spec; run regen"
    );
}

#[test]
fn modmul_k1_scalar_matches_checked_in_artifact() {
    let emitted = emit_module(&specs::MODMUL_K1_SCALAR);
    let on_disk = include_str!("../../lib/core/asm/math/u256_sz_modmul_k1_scalar.masm");
    assert_eq!(
        emitted, on_disk,
        "u256_sz_modmul_k1_scalar.masm is out of sync with MODMUL_K1_SCALAR spec; run regen"
    );
}
