//! Small conversion and packing helpers used by the signature test harness.

use miden_core::Felt;
use miden_signature::{Goldilocks, QuadExt};

use super::transcript::SigTranscript;

// NOTE: The signature crate uses `p3_goldilocks::Goldilocks`, while the VM/test
// harness uses `miden_core::Felt`. They are layout-compatible, so we transmute
// for zero-copy conversions. This is intentionally isolated here so it’s easy
// to swap to safe conversions once the types are unified.
pub(crate) fn g_to_felt(g: Goldilocks) -> Felt {
    unsafe { core::mem::transmute(g) }
}

pub(crate) fn g4_to_felt4(g: &[Goldilocks; 4]) -> [Felt; 4] {
    core::array::from_fn(|i| g_to_felt(g[i]))
}

pub(crate) fn g4_to_u64(g: &[Goldilocks; 4]) -> [u64; 4] {
    g4_to_felt4(g).map(|f| f.as_canonical_u64())
}

pub(crate) fn ef_to_felts(ef: &QuadExt) -> [Felt; 2] {
    unsafe { core::mem::transmute_copy(ef) }
}

pub(crate) fn ef_to_u64_pair(ef: &QuadExt) -> [u64; 2] {
    ef_to_felts(ef).map(|f| f.as_canonical_u64())
}

pub(crate) fn absorb_ext_group_full_rate(t: &mut SigTranscript, group: &[QuadExt]) {
    let felts: Vec<Felt> = group
        .iter()
        .flat_map(|ef| {
            let p = ef_to_felts(ef);
            [p[0], p[1]]
        })
        .collect();
    assert_eq!(felts.len() % 8, 0, "ext OOD group must be multiple of 8");
    for chunk in felts.chunks(8) {
        t.absorb_full_rate(chunk[0..4].try_into().unwrap(), chunk[4..8].try_into().unwrap());
    }
}

pub(crate) fn absorb_base_group_full_rate(t: &mut SigTranscript, group: &[Goldilocks]) {
    let felts: Vec<Felt> = group.iter().map(|&g| g_to_felt(g)).collect();
    assert_eq!(felts.len() % 8, 0, "base OOD group must be multiple of 8");
    for chunk in felts.chunks(8) {
        t.absorb_full_rate(chunk[0..4].try_into().unwrap(), chunk[4..8].try_into().unwrap());
    }
}

pub(crate) fn append_ext_group_full_rate_advice(adv: &mut Vec<u64>, group: &[QuadExt]) {
    let felts: Vec<u64> = group
        .iter()
        .flat_map(|ef| {
            let p = ef_to_u64_pair(ef);
            [p[0], p[1]]
        })
        .collect();
    assert_eq!(felts.len() % 8, 0, "ext OOD group must be multiple of 8");
    adv.extend_from_slice(&felts);
}

pub(crate) fn append_base_group_full_rate_advice(adv: &mut Vec<u64>, group: &[Goldilocks]) {
    let felts: Vec<u64> = group.iter().map(|&g| g_to_felt(g).as_canonical_u64()).collect();
    assert_eq!(felts.len() % 8, 0, "base OOD group must be multiple of 8");
    adv.extend_from_slice(&felts);
}

pub(crate) fn deep_coeffs_padded_desc(coeffs: &[QuadExt]) -> Vec<QuadExt> {
    assert!(!coeffs.is_empty(), "deep coeffs must be non-empty");
    let padded_len = coeffs.len().next_power_of_two();
    let zero = QuadExt::default();
    let mut out = Vec::with_capacity(padded_len);
    out.resize(padded_len - coeffs.len(), zero);
    out.extend(coeffs.iter().rev().copied());
    out
}

pub(crate) fn absorb_deep_poly_full_rate(t: &mut SigTranscript, coeffs: &[QuadExt]) {
    let padded_desc = deep_coeffs_padded_desc(coeffs);
    let felts: Vec<Felt> = padded_desc
        .iter()
        .flat_map(|ef| {
            let p = ef_to_felts(ef);
            [p[0], p[1]]
        })
        .collect();
    assert_eq!(felts.len() % 8, 0, "DEEP coeff stream must be multiple of 8");
    for chunk in felts.chunks(8) {
        t.absorb_full_rate(chunk[0..4].try_into().unwrap(), chunk[4..8].try_into().unwrap());
    }
}

pub(crate) fn append_deep_poly_full_rate_advice(adv: &mut Vec<u64>, coeffs: &[QuadExt]) {
    let padded_desc = deep_coeffs_padded_desc(coeffs);
    let felts: Vec<u64> = padded_desc
        .iter()
        .flat_map(|ef| {
            let p = ef_to_u64_pair(ef);
            [p[0], p[1]]
        })
        .collect();
    assert_eq!(felts.len() % 8, 0, "DEEP coeff advice stream must be multiple of 8");
    adv.extend_from_slice(&felts);
}
