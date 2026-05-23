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
    // Aux-check error messages name the limb being asserted; these are user-visible at trap
    // time, so they get explicit coverage beyond the byte-for-byte snapshot.
    assert!(s.contains("e_pos_30 must be 0"));
    assert!(s.contains("e_pos_31 must be 0"));
    assert!(s.contains("e_neg_30 must be 0"));
    assert!(s.contains("e_neg_31 must be 0"));
}

#[test]
fn modmul_k1_base_emits_fused_canonical_check() {
    let s = emit_masm(&specs::MODMUL_K1_BASE);
    // First-limb delta for k1 base: 2^256 - p with p = 2^256 - 2^32 - 977 gives delta_0 = 977.
    assert!(
        s.contains("dup.0 push.0x3d1 u32widening_add drop"),
        "expected first-limb add of delta_0 = 0x3d1"
    );
    assert!(
        s.contains("c < p violated"),
        "expected user-visible canonical-check error message"
    );
}

#[test]
fn modmul_k1_scalar_names_group_order_in_generated_masm() {
    let s = emit_masm(&specs::MODMUL_K1_SCALAR);
    assert!(s.contains("q(alpha) * n(alpha)"), "expected scalar identity to use n(alpha)");
    assert!(s.contains("c < n violated"), "expected scalar canonical-check error to use n");
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
    assert!(s.contains("fixed modulus commitment mismatch"));
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
