//! MASM emitter. Turns a [`LinearRelation`] into a fully-specialized MASM proc.
//!
//! The output is plain text, intended to be written into a checked-in `.masm` file. The emitter
//! is straight-line, with small spec-driven optimizations where they materially reduce VM work.
//!
//! # Memory layout
//!
//! ```text
//! mem[0..4]:  alpha word (alpha_0 at 0, alpha_1 at 1; cells 2..4 padding)
//! mem[4..]:   each poly in `rel.polys` order, packed by storage form
//!               - PerU16: u16_coeff_count felts (one per coefficient)
//!               - PerU32: u16_coeff_count / 2 felts (one per u32 limb)
//! mem[h..]:   alpha-evaluation storage, 2 felts per poly that is alpha-evaluated
//! ```
//!
//! The total local frame size is what the emitted `@locals(N)` declares.

use alloc::{format, string::String, vec::Vec};

use miden_core::{Felt, crypto::hash::Poseidon2};

use crate::spec::{AuxCheck, LinearRelation, OutputForm, Poly, PolyRef, PolyRole, Sign, Storage};

/// Resolved memory layout for a [`LinearRelation`].
struct Layout {
    entries: Vec<LayoutEntry>,
    /// Total felts allocated (= `@locals(N)`).
    total: usize,
}

struct LayoutEntry {
    name: &'static str,
    /// First memory cell of this poly's coefficient block.
    poly_offset: usize,
    /// First memory cell of this poly's alpha-evaluation pair (basis_0, basis_1).
    h_offset: usize,
}

impl Layout {
    fn compute(rel: &LinearRelation) -> Self {
        // Cells 0..4 reserved for the alpha word (alpha_0 at 0, alpha_1 at 1; cells 2..4 padding).
        let mut poly_offset: usize = 4;
        let mut entries: Vec<LayoutEntry> = Vec::with_capacity(rel.polys.len());
        for poly in rel.polys {
            entries.push(LayoutEntry {
                name: poly.name,
                poly_offset,
                h_offset: 0,
            });
            poly_offset += felts_for(poly);
        }
        // After all poly offsets are placed, the h-storage block starts at the running offset.
        // 2 felts per poly for the (basis_0, basis_1) coords of poly(alpha) in the extension.
        let h_storage_start = poly_offset;
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.h_offset = h_storage_start + 2 * i;
        }
        let total = h_storage_start + 2 * entries.len();
        Layout { entries, total }
    }

    fn entry(&self, name: &str) -> &LayoutEntry {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("poly {name} not declared in spec"))
    }

    fn poly_offset(&self, name: &str) -> usize {
        self.entry(name).poly_offset
    }

    fn h_offset(&self, name: &str) -> usize {
        self.entry(name).h_offset
    }
}

/// Number of memory felts a polynomial occupies given its storage form. Constant polys and
/// fixed-vector polys reserve no coefficient cells in the local layout (they are streamed
/// through advice each call, never persisted past the absorb).
fn felts_for(poly: &Poly) -> usize {
    if matches!(poly.role, PolyRole::Constant { .. } | PolyRole::FixedU32Vector { .. },) {
        return 0;
    }
    match poly.storage {
        Storage::PerU16 => poly.u16_coeff_count,
        Storage::PerU32 => {
            assert!(
                poly.u16_coeff_count.is_multiple_of(2),
                "PerU32 storage requires even u16_coeff_count (got {})",
                poly.u16_coeff_count
            );
            poly.u16_coeff_count / 2
        },
    }
}

/// Resolves a [`PolyRef`] to its [`Poly`] in the spec.
fn resolve(rel: &LinearRelation, r: PolyRef) -> &Poly {
    rel.polys
        .iter()
        .find(|p| p.name == r.0)
        .unwrap_or_else(|| panic!("PolyRef({}) not declared in spec", r.0))
}

/// Emits a fully-specialized MASM proc for the given [`LinearRelation`]. The output is just the
/// proc (doc comment, `@locals`, signature, body, `end`); use [`emit_module`] for a standalone
/// `.masm` file with the necessary imports and constants.
pub fn emit_masm(rel: &LinearRelation) -> String {
    let layout = Layout::compute(rel);
    let mut out = String::new();

    emit_doc_comment(rel, &mut out);
    out.push_str(&format!("@locals({})\n", layout.total));
    emit_signature(rel, &mut out);

    emit_event(rel, &mut out);
    emit_input_store(rel, &layout, &mut out);
    emit_alpha_pop(&mut out);
    out.push('\n');
    emit_streaming(rel, &layout, &mut out);
    out.push('\n');
    emit_aux_checks_after_stream(rel, &layout, &mut out);
    out.push('\n');
    emit_fs_check(&mut out);
    out.push('\n');
    emit_input_horner(rel, &layout, &mut out);
    out.push('\n');
    emit_identity_check(rel, &layout, &mut out);
    out.push('\n');
    emit_outputs(rel, &layout, &mut out);

    out.push_str("end\n");
    out
}

/// Emits a complete standalone MASM module file for the given relation: file-level header,
/// type alias, `use` declarations, event constant, then the proc itself.
pub fn emit_module(rel: &LinearRelation) -> String {
    let mut out = String::new();
    out.push_str(&format!("#! Generated MASM module for the SZ {} verifier.\n", rel.name));
    out.push_str(
        "#! DO NOT EDIT BY HAND. Regenerate via `cargo run -p miden-sz-codegen --bin regen`.\n\n",
    );
    // u256 type alias matching the canonical declaration in u256.masm.
    out.push_str("pub type u256 = struct { lo: u128, hi: u128 }\n\n");
    out.push_str("use miden::core::crypto::hashes::poseidon2\n\n");
    // LessThan checks resolve `exec.::miden::core::math::u256::lt` via fully-qualified path; no
    // `use miden::core::math::u256` is needed (and adding one would collide with the local
    // `pub type u256` alias).
    out.push_str(&format!(
        "const {} = event(\"{}\")\n\n",
        event_const_name(rel),
        event_qualified_name(rel)
    ));
    out.push_str(&emit_masm(rel));
    out
}

fn emit_doc_comment(rel: &LinearRelation, out: &mut String) {
    out.push_str(&format!(
        "#! Schwartz-Zippel-based {} modular-multiplication verifier.\n",
        rel.name
    ));
    out.push_str("#! Main checked identity:\n");
    out.push_str(&format!("#!   {}\n", render_identity(rel)));
    out.push_str(
        "#! at a Fiat-Shamir-derived alpha in the Miden base-field extension (W = 2^16).\n",
    );
}

fn emit_signature(rel: &LinearRelation, out: &mut String) {
    out.push_str(&format!("pub proc {}{}\n", rel.name, rel.signature));
}

fn emit_event(rel: &LinearRelation, out: &mut String) {
    out.push_str(&format!("    emit.{}\n", event_const_name(rel)));
}

/// MASM `const` identifier for this spec's event, e.g.
/// `modmul_k1_base` -> `U256_MODMUL_K1_BASE_EVENT`.
fn event_const_name(rel: &LinearRelation) -> String {
    format!("U256_{}_EVENT", rel.name.to_uppercase())
}

/// MASM `event(...)` argument, matching the host-side handler's `EventName`.
fn event_qualified_name(rel: &LinearRelation) -> String {
    format!("miden::core::math::u256::u256_{}", rel.name)
}

/// Stores operand-stack polys into their memory slots. Each PerU32 OperandStack poly is laid
/// out as 8 u32 felts at its offset. Store order follows operand-stack depth (lowest first).
fn emit_input_store(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let mut inputs: Vec<&Poly> = rel
        .polys
        .iter()
        .filter(|p| matches!(p.role, PolyRole::OperandStack { .. }))
        .collect();
    inputs.sort_by_key(|p| match p.role {
        PolyRole::OperandStack { depth_start } => depth_start,
        _ => unreachable!(),
    });
    assert!(
        !inputs.is_empty(),
        "spec `{}` must declare at least one OperandStack poly",
        rel.name
    );

    // Caller pushed inputs in reverse depth order, each as 8 u32 felts ([lo(4), hi(4)] with
    // lo on top). For a 2-input modmul: [b_lo(4), b_hi(4), a_lo(4), a_hi(4), ...]. For the
    // last input we skip the trailing dropws: those 8 residual felts become the initial rate
    // for the modulus prefix's first adv_pipe to overwrite.
    let last_idx = inputs.len() - 1;
    let names: Vec<&str> = inputs.iter().map(|p| p.name).collect();
    let last_name = names[last_idx];
    out.push_str(&format!(
        "    # Store inputs to local memory; leave the last one ({last_name}) on stack as the\n"
    ));
    out.push_str("    # initial rate for the first fixed-prefix absorb.\n");
    for (i, poly) in inputs.iter().enumerate() {
        assert!(matches!(poly.storage, Storage::PerU32));
        let off = layout.poly_offset(poly.name);
        if i < last_idx {
            out.push_str(&format!("    loc_storew_le.{off} dropw\n"));
            out.push_str(&format!("    loc_storew_le.{} dropw\n", off + 4));
        } else {
            out.push_str(&format!("    loc_storew_le.{off}\n"));
            out.push_str("    swapw\n");
            out.push_str(&format!("    loc_storew_le.{}\n", off + 4));
        }
    }
    out.push_str(&format!("    # => [{last_name}_hi(4), {last_name}_lo(4), ...]\n"));
}

fn emit_alpha_pop(out: &mut String) {
    // Store the advice-supplied FS alpha into mem[0..2] for the later FS check.
    // Net stack change: zero.
    out.push_str("    # Store the advice-supplied FS alpha into mem[0..2].\n");
    out.push_str("    adv_push\n");
    out.push_str("    adv_push\n");
    out.push_str("    loc_store.0\n");
    out.push_str("    loc_store.1\n");
}

/// Builds the FS transcript while Horner-evaluating advice-backed polynomials at alpha. The fixed
/// prefix is advice-loaded and commitment-checked first. Input polys are absorbed via
/// `mem_stream`; their alpha-evaluation runs later in [`emit_input_horner`].
fn emit_streaming(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let first_input_offset = rel
        .polys
        .iter()
        .find(|p| matches!(p.role, PolyRole::OperandStack { .. }))
        .map(|p| layout.poly_offset(p.name))
        .expect("at least one OperandStack poly required");
    let first_witness_offset = rel
        .polys
        .iter()
        .find(|p| matches!(p.role, PolyRole::Witness))
        .map(|p| layout.poly_offset(p.name))
        .expect("at least one Witness poly required");
    // Name of the last operand-stack input — its [{l}_hi(4), {l}_lo(4)] halves are the
    // residual sitting on stack from emit_input_store (will be overwritten by the first
    // adv_pipe in the modulus prefix as the initial rate).
    let l = rel
        .polys
        .iter()
        .filter(|p| matches!(p.role, PolyRole::OperandStack { .. }))
        .max_by_key(|p| match p.role {
            PolyRole::OperandStack { depth_start } => depth_start,
            _ => unreachable!(),
        })
        .expect("at least one OperandStack poly required")
        .name;

    // Build the Poseidon-shaped frame the next phases need:
    //   [R(8), C(4), ptr, alpha_addr, acc_0, acc_1, ...]
    // where R = rate (top 8), C = capacity (next 4), ptr/alpha_addr at depths 12-13,
    // and the 2-felt extension-field Horner accumulator at depths 14-15.
    out.push_str("    # ----- transcript absorb + polynomial evaluation setup -----\n");
    out.push_str("    # Build the [R(8), C(4), ptr, alpha_addr, acc(2), ...] frame that\n");
    out.push_str("    # adv_pipe / horner_eval_base / permute expect.\n");
    out.push_str("    push.0 push.0\n");
    out.push_str("    locaddr.0\n");
    out.push_str(&format!("    locaddr.{first_witness_offset}\n"));
    emit_committed_fixed_prefix(rel, layout, first_input_offset, l, out);

    // Walk polys in order, consolidating consecutive operand-stack absorbs into a single
    // `repeat.N` block (no horner happens during these chunks, so chunks of the same shape can
    // share the loop body). Witness polys each get their own block (each one needs an h-store
    // and an acc reset between blocks).
    let mut i = 0;
    while i < rel.polys.len() {
        let poly = &rel.polys[i];
        match poly.role {
            PolyRole::OperandStack { .. } => {
                let mut total_chunks = 0;
                let mut names: Vec<&str> = Vec::new();
                while i < rel.polys.len()
                    && matches!(rel.polys[i].role, PolyRole::OperandStack { .. })
                {
                    total_chunks += chunks_for(&rel.polys[i]);
                    names.push(rel.polys[i].name);
                    i += 1;
                }
                let names_joined = names.join(", ");
                out.push('\n');
                out.push_str(&format!(
                    "    # ----- absorb inputs ({names_joined}) via mem_stream -----\n"
                ));
                out.push_str("    # mem_stream overwrites the rate with mem[ptr..ptr+8] and advances ptr by 8.\n");
                out.push_str("    # No horner here; input alpha-evaluation happens in the per-input Horner blocks below.\n");
                out.push_str(&format!("    repeat.{total_chunks}\n"));
                out.push_str("        mem_stream\n");
                out.push_str("        exec.poseidon2::permute\n");
                out.push_str("    end\n");
                out.push_str("    # => [state(12), ptr, alpha_addr, acc(2), ...]\n");
            },
            PolyRole::Witness => {
                let chunks = chunks_for(poly);
                let name = poly.name;
                out.push('\n');
                out.push_str(&format!("    # ----- absorb witness {name} via adv_pipe -----\n"));
                out.push_str(&format!(
                    "    # adv_pipe streams 8 {name} coefficients into the rate, mirrors them to\n"
                ));
                out.push_str("    # mem[ptr..ptr+8], and advances ptr. Coefficients are u32-bounded (not u16);\n");
                out.push_str(
                    "    # u32assertw range-checks both halves of the rate. horner_eval_base\n",
                );
                out.push_str(&format!(
                    "    # accumulates {name}(alpha) into acc at depths 14/15.\n"
                ));
                out.push_str(&format!("    repeat.{chunks}\n"));
                out.push_str("        adv_pipe\n");
                out.push_str("        u32assertw\n");
                out.push_str("        swapw u32assertw swapw\n");
                out.push_str("        horner_eval_base\n");
                out.push_str("        exec.poseidon2::permute\n");
                out.push_str("    end\n");
                out.push_str(&format!(
                    "    # => [state(12), ptr, alpha_addr, {name}(alpha), ...]\n"
                ));
                let h = layout.h_offset(poly.name);
                if !is_last_witness(rel, poly.name) {
                    let next = next_witness_name(rel, name);
                    out.push('\n');
                    out.push_str(&format!(
                        "    # Snapshot {name}(alpha) and reset depths 14/15 for {next}.\n"
                    ));
                    out.push_str(&format!("    movup.14 loc_store.{h} push.0 movdn.14\n"));
                    out.push_str(&format!("    movup.15 loc_store.{} push.0 movdn.15\n", h + 1));
                    out.push_str("    # => [state(12), ptr, alpha_addr, 0, 0, ...]\n");
                } else {
                    // Last witness: dup-snapshot (cheap at any depth, unlike movup.14+ which
                    // costs 4 cyc). Acc stays at depths 14, 15 — discarded by the FS
                    // check's teardown.
                    out.push('\n');
                    out.push_str(&format!(
                        "    # Snapshot {name}(alpha) via dup; acc stays in place (discarded by the FS-check teardown).\n"
                    ));
                    out.push_str(&format!("    dup.14 loc_store.{h}\n"));
                    out.push_str(&format!("    dup.15 loc_store.{}\n", h + 1));
                }
                i += 1;
            },
            PolyRole::Constant { .. } | PolyRole::FixedU32Vector { .. } => {
                // Fixed-statement polys (modulus + offset) were handled by
                // `emit_committed_fixed_prefix`.
                i += 1;
            },
        }
    }
}

/// Returns the name of the witness poly that follows `name` in `rel.polys`. Caller must
/// ensure `name` is not the last witness (use `is_last_witness` to check).
fn next_witness_name<'a>(rel: &'a LinearRelation, name: &str) -> &'a str {
    let idx = rel.polys.iter().position(|p| p.name == name).expect("poly not found");
    rel.polys[idx + 1..]
        .iter()
        .find(|p| matches!(p.role, PolyRole::Witness))
        .map(|p| p.name)
        .expect("no following witness; check is_last_witness first")
}

/// Number of rate-8 chunks the streaming load consumes for a poly.
fn chunks_for(poly: &Poly) -> usize {
    let felts = felts_for(poly);
    assert!(
        felts.is_multiple_of(8),
        "poly {} felts ({felts}) must be a multiple of rate 8",
        poly.name
    );
    felts / 8
}

/// Emits the advice-loaded fixed-statement prefix (modulus || offset_vector):
/// - start from a zero Poseidon state,
/// - stream the fixed modulus from advice while evaluating `modulus(alpha)`,
/// - snapshot `modulus(alpha)` and reset the Horner accumulator,
/// - stream the fixed offset vector from advice while evaluating `offset(alpha)`,
/// - assert the resulting Poseidon digest against the hardcoded combined commitment,
/// - snapshot `offset(alpha)` to mem and retarget the stream pointer to the first input.
fn emit_committed_fixed_prefix(
    rel: &LinearRelation,
    layout: &Layout,
    first_input_offset: usize,
    last_input: &str,
    out: &mut String,
) {
    let (modulus_poly, modulus) = fixed_modulus(rel);
    let (offset_poly, offset) = fixed_offset(rel);
    let m = modulus_poly.name;
    let o = offset_poly.name;
    let l = last_input;
    let state = fixed_prefix_seeded_initial_state(modulus, offset);
    let modulus_h = layout.h_offset(m);
    let offset_h = layout.h_offset(o);
    let modulus_chunks = modulus.len() / 8;
    let offset_chunks = offset.len() / 8;

    // padw + swapdw shapes the stack into the [R(8), C(4), ptr, alpha_addr, acc(2), ...]
    // layout that adv_pipe / horner_eval_base / permute expect. After swapdw, the 8 operand-
    // stack-residual felts (last-input halves) sit at depths 0-7 as the initial rate, which
    // the first adv_pipe will overwrite.
    out.push_str("    padw\n");
    out.push_str("    swapdw\n");
    out.push_str(&format!(
        "    # => [{l}_hi(4), {l}_lo(4), R_pad(4), ptr, alpha_addr, acc(2), ...]\n"
    ));
    out.push('\n');
    out.push_str(
        "    # ----- fixed-statement prefix: modulus || carry-shift offset vector -----\n",
    );
    out.push_str(&format!(
        "    # Phase A: adv_pipe streams {m} in {modulus_chunks} rate chunks, mirrors those limbs\n"
    ));
    out.push_str(&format!(
        "    # to scratch memory, and advances ptr. horner_eval_base accumulates {m}(alpha).\n"
    ));
    out.push_str(&format!("    repeat.{modulus_chunks}\n"));
    out.push_str("        adv_pipe\n");
    out.push_str("        horner_eval_base\n");
    out.push_str("        exec.poseidon2::permute\n");
    out.push_str("    end\n");
    out.push_str(&format!("    # => [state(12), ptr, alpha_addr, {m}(alpha), ...]\n"));
    out.push('\n');
    out.push_str(&format!("    # Snapshot {m}(alpha) and reset acc for Phase B.\n"));
    out.push_str(&format!("    movup.14 loc_store.{modulus_h} push.0 movdn.14\n"));
    out.push_str(&format!("    movup.15 loc_store.{} push.0 movdn.15\n", modulus_h + 1));
    out.push_str("    # => [state(12), ptr, alpha_addr, 0, 0, ...]\n");
    out.push('\n');
    out.push_str(&format!(
        "    # Phase B: adv_pipe streams {o} in {offset_chunks} rate chunks, mirrors those values\n"
    ));
    out.push_str(
        "    # to scratch memory, and advances ptr. The combined `assert_eqw` below pins both\n",
    );
    out.push_str(&format!("    # {m} and {o}; horner_eval_base accumulates {o}(alpha).\n"));
    out.push_str(&format!("    repeat.{offset_chunks}\n"));
    out.push_str("        adv_pipe\n");
    out.push_str("        horner_eval_base\n");
    out.push_str("        exec.poseidon2::permute\n");
    out.push_str("    end\n");
    out.push_str(&format!("    # => [state(12), ptr, alpha_addr, {o}(alpha), ...]\n"));
    out.push('\n');
    out.push_str(&format!(
        "    # Assert the post-absorb state[0..4] equals the pinned digest of ({m} || {o}).\n"
    ));
    out.push_str(&format!(
        "    push.{}.{}.{}.{}\n",
        state[3].as_canonical_u64(),
        state[2].as_canonical_u64(),
        state[1].as_canonical_u64(),
        state[0].as_canonical_u64(),
    ));
    out.push_str(
        "    assert_eqw.err=\"sz: fixed-statement commitment mismatch (modulus + offset)\"\n",
    );
    out.push_str(&format!(
        "    # => [state[4..12], ptr, alpha_addr, {o}(alpha), ...]  (popped 8: pinned + state[0..4])\n"
    ));
    out.push('\n');
    out.push_str(&format!(
        "    # Snapshot {o}(alpha), reset the accumulator, retarget ptr to the first input,\n"
    ));
    out.push_str("    # and restore four zero rate lanes for the next absorb.\n");
    out.push_str(&format!("    movup.10 loc_store.{offset_h} push.0 movdn.10\n"));
    out.push_str(&format!("    movup.11 loc_store.{} push.0 movdn.11\n", offset_h + 1));
    out.push_str(&format!("    movup.8 drop locaddr.{first_input_offset} movdn.8\n"));
    out.push_str("    padw\n");
    out.push_str(&format!(
        "    # => [0(4), state[4..12], locaddr.{first_input_offset}, alpha_addr, 0, 0, ...]\n"
    ));
}

/// Returns the fixed modulus polynomial and its u16 limbs. The emitted modmul shape has exactly
/// one constant polynomial; absence or multiplicity is a spec-authoring bug.
fn fixed_modulus(rel: &LinearRelation) -> (&Poly, &'static [u16]) {
    let mut found = None;
    for poly in rel.polys {
        if let PolyRole::Constant { u16_limbs } = poly.role {
            assert!(
                found.is_none(),
                "spec `{}` has more than one Constant poly; the emitter expects a single fixed modulus",
                rel.name
            );
            assert!(
                matches!(poly.storage, Storage::PerU16),
                "fixed modulus `{}` must use PerU16 storage",
                poly.name
            );
            assert_eq!(
                poly.u16_coeff_count,
                u16_limbs.len(),
                "fixed modulus `{}` declares {} coefficients but provides {} limbs",
                poly.name,
                poly.u16_coeff_count,
                u16_limbs.len()
            );
            assert_eq!(u16_limbs.len(), 16, "fixed modulus `{}` must be 16 u16 limbs", poly.name);
            found = Some((poly, u16_limbs));
        }
    }
    found
        .unwrap_or_else(|| panic!("spec `{}` has no Constant poly for the fixed modulus", rel.name))
}

/// Returns the fixed offset polynomial and its u32 values. The emitted modmul shape has exactly
/// one `FixedU32Vector` polynomial (the carry-shift offset vector).
fn fixed_offset(rel: &LinearRelation) -> (&Poly, &'static [u32]) {
    let mut found = None;
    for poly in rel.polys {
        if let PolyRole::FixedU32Vector { u32_values } = poly.role {
            assert!(
                found.is_none(),
                "spec `{}` has more than one FixedU32Vector poly; the emitter expects exactly one",
                rel.name
            );
            assert_eq!(
                poly.u16_coeff_count,
                u32_values.len(),
                "fixed-vector `{}` declares {} coefficients but provides {} values",
                poly.name,
                poly.u16_coeff_count,
                u32_values.len()
            );
            assert!(
                u32_values.len().is_multiple_of(8),
                "fixed-vector `{}` length must be a multiple of 8 (rate); got {}",
                poly.name,
                u32_values.len()
            );
            found = Some((poly, u32_values));
        }
    }
    found.unwrap_or_else(|| {
        panic!("spec `{}` has no FixedU32Vector poly for the carry-shift offset", rel.name)
    })
}

/// Poseidon2 sponge state after absorbing the fixed-statement prefix: modulus followed by the
/// carry-shift offset vector. Both are absorbed in the same order the MASM verifier advice-loads
/// them for `horner_eval_base`: highest limb first, 8 limbs per chunk.
///
/// Mirrored by `miden_core_lib::handlers::u256_modmul::fixed_prefix_seeded_initial_state`.
/// Cross-crate agreement is pinned by the `k1_{base,scalar}_precomputed_initial_state_pin`
/// core-lib tests.
pub fn fixed_prefix_seeded_initial_state(
    modulus_u16: &[u16],
    offset_u32: &[u32],
) -> [Felt; Poseidon2::STATE_WIDTH] {
    const RATE: usize = 8;
    assert_eq!(
        modulus_u16.len(),
        16,
        "fixed_prefix_seeded_initial_state expects 16 u16 modulus limbs (got {})",
        modulus_u16.len(),
    );
    assert!(
        offset_u32.len().is_multiple_of(RATE),
        "offset vector length must be a multiple of {RATE} (got {})",
        offset_u32.len(),
    );
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    // Phase A: modulus (highest u16 limb first, 8 limbs per chunk).
    for chunk_idx in 0..(modulus_u16.len() / RATE) {
        for j in 0..RATE {
            state[j] =
                Felt::from_u32(modulus_u16[modulus_u16.len() - 1 - (chunk_idx * RATE + j)] as u32);
        }
        Poseidon2::apply_permutation(&mut state);
    }
    // Phase B: offset (highest u32 value first, 8 values per chunk). For the canonical
    // `[CARRY_SHIFT; 32]` vector this reversal has no observable effect, but the convention
    // matches the adv_pipe consumption pattern for all other polys.
    for chunk_idx in 0..(offset_u32.len() / RATE) {
        for j in 0..RATE {
            state[j] = Felt::from_u32(offset_u32[offset_u32.len() - 1 - (chunk_idx * RATE + j)]);
        }
        Poseidon2::apply_permutation(&mut state);
    }
    state
}

/// `true` iff `name` is the last `Witness` poly. Used to decide whether to reset the Horner
/// accumulator between streaming blocks (the last witness's accumulator is what we save and
/// then read back during the identity check, so we leave it alone).
fn is_last_witness(rel: &LinearRelation, name: &str) -> bool {
    rel.polys
        .iter()
        .rev()
        .find(|p| matches!(p.role, PolyRole::Witness))
        .map(|p| p.name)
        == Some(name)
}

/// Emits `LimbEquals` aux checks. Fires after the streaming load completes (so memory holds
/// the witness data) but before the FS-equality check. For `value == 0` the emitter uses the
/// cheaper `assertz` (2 cyc); for other values it uses `push.value assert_eq` (3 cyc) which is
/// what the shifted-carry top checks need (top coefficients equal `2^31`, not 0). `LessThan`
/// aux checks need the polynomials in u32 limb form, which is produced during output emission,
/// so they are emitted fused with the output recombination (see [`emit_outputs`]).
fn emit_aux_checks_after_stream(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let mut first = true;
    for check in rel.aux_checks {
        if let AuxCheck::LimbEquals { poly, index, value } = check {
            if first {
                out.push_str(
                    "    # ----- top-carry limb checks (each line is net-zero on the stack) -----\n",
                );
                first = false;
            }
            let p = resolve(rel, *poly);
            let off = layout.poly_offset(p.name);
            let mem_index = limb_to_mem_index(p, off, *index);
            if *value == 0 {
                out.push_str(&format!(
                    "    loc_load.{mem_index} assertz.err=\"sz: {}_{index} must be 0 (top carry coefficient)\"\n",
                    p.name
                ));
            } else {
                out.push_str(&format!(
                    "    loc_load.{mem_index} push.{value} assert_eq.err=\"sz: {}_{index} must equal {value} (top carry coefficient)\"\n",
                    p.name
                ));
            }
        }
    }
}

/// Locates the `LessThan { lhs, rhs }` aux check for a spec's single u32-form output, where
/// `rhs` is a `Constant`. Such a check is emitted fused with the output recombination so the
/// u32 form of the output is shared between the canonical-form check and the operand-stack
/// output; see [`emit_outputs`].
///
/// The emitted modmul shape has exactly one such check: the canonical reduction `c < modulus`.
/// A missing or non-fusable `LessThan` is a spec-authoring bug.
fn find_output_fused_lessthan(rel: &LinearRelation) -> (PolyRef, PolyRef) {
    assert_eq!(rel.expose.len(), 1, "spec `{}` must expose exactly one output", rel.name);
    let output = &rel.expose[0];
    assert!(
        matches!(output.form, OutputForm::U32Limbs),
        "spec `{}` output must be U32Limbs",
        rel.name,
    );
    let mut found = None;
    for check in rel.aux_checks {
        if let AuxCheck::LessThan { lhs, rhs } = check {
            assert_eq!(
                lhs.0, output.poly.0,
                "spec `{}` LessThan lhs (`{}`) must match the exposed output (`{}`)",
                rel.name, lhs.0, output.poly.0,
            );
            let rhs_p = resolve(rel, *rhs);
            assert!(
                matches!(rhs_p.role, PolyRole::Constant { .. }),
                "spec `{}` LessThan rhs (`{}`) must be a Constant poly",
                rel.name,
                rhs.0,
            );
            assert!(found.is_none(), "spec `{}` has more than one LessThan aux check", rel.name);
            found = Some((*lhs, *rhs));
        }
    }
    found.unwrap_or_else(|| {
        panic!(
            "spec `{}` must declare exactly one LessThan aux check for exposed output `{}`",
            rel.name, output.poly.0
        )
    })
}

/// u16-to-u32 recombination emitted as part of output exposure. Loads each 4-felt word from
/// local memory with `padw loc_loadw_le`, then combines the two `(hi, lo)` pairs in the word as
/// `hi * W + lo`. `u32assert2` after each pair forces canonical W^2-base limbs.
///
/// `PerU16` memory layout is reversed (highest coefficient at lowest address), so word `k`
/// (k = 0..n/4) holds `(c[n-1-4k], c[n-2-4k], c[n-3-4k], c[n-4-4k])` from low to high address,
/// corresponding to `c_u32[(n/2)-1-2k]` and `c_u32[(n/2)-2-2k]`.
fn emit_recombine_u16_to_u32(poly: &Poly, layout: &Layout, out: &mut String) {
    assert!(matches!(poly.storage, Storage::PerU16));
    assert!(
        poly.u16_coeff_count.is_multiple_of(4),
        "PerU16 recombine requires u16_coeff_count multiple of 4 for word-aligned loads (got {})",
        poly.u16_coeff_count
    );
    let off = layout.poly_offset(poly.name);
    let n = poly.u16_coeff_count;
    let n_words = n / 4;
    let name = poly.name;
    // Build the explicit shape ([name_u32[0], name_u32[1], ..., name_u32[k+1]]) that the
    // stack holds after each chunk's mul-add+u32assert2 pair completes.
    for k in 0..n_words {
        let word_addr = off + 4 * k;
        let hi_idx = (n / 2) - 1 - 2 * k; // first c_u32 built from this word
        let lo_idx = hi_idx - 1; // second c_u32 from same word
        if k == 0 {
            // First load absorbs the 4 residual felts from the identity check; no padw.
            out.push_str(&format!("    loc_loadw_le.{word_addr}\n"));
        } else {
            out.push_str(&format!("    padw loc_loadw_le.{word_addr}\n"));
        }
        out.push_str("    mul.65536 add\n");
        out.push_str("    movdn.2 mul.65536 add\n");
        out.push_str("    u32assert2\n");
        let shape: Vec<String> = (lo_idx..(n / 2)).map(|i| format!("{name}_u32[{i}]")).collect();
        out.push_str(&format!("    # => [{}, ...]\n", shape.join(", ")));
    }
}

/// Maps a polynomial coefficient index (0..u16_coeff_count) to its memory cell. Witness PerU16
/// polys are stored REVERSED (highest-index coefficient at lowest memory address) so that
/// `horner_eval_base` processes them highest-degree-first.
fn limb_to_mem_index(poly: &Poly, base_offset: usize, coeff_index: usize) -> usize {
    assert!(coeff_index < poly.u16_coeff_count);
    match poly.storage {
        Storage::PerU16 => {
            // Reversed: coeff[u16_coeff_count - 1] at base_offset, coeff[0] at base_offset + N - 1.
            base_offset + (poly.u16_coeff_count - 1 - coeff_index)
        },
        Storage::PerU32 => {
            // Two coefficients per cell: lo at even index, hi at odd. Not reversed at felt level.
            base_offset + coeff_index / 2
        },
    }
}

fn emit_fs_check(out: &mut String) {
    // The Poseidon state's top 2 felts (state[0], state[1]) are the FS-derived alpha after
    // all absorbs. assert_eq compares those squeezed felts against the prover-hinted alpha
    // at mem[0..2]; mismatch => prover used a non-transcript alpha. The final dropw drop
    // chain clears the remaining 14 residual felts (state[2..12] + ptr + alpha_addr + acc(2)).
    out.push_str("    # ----- Fiat-Shamir equality check -----\n");
    out.push_str("    loc_load.0\n");
    out.push_str("    assert_eq.err=\"sz: alpha_0 mismatch (Fiat-Shamir failure)\"\n");
    out.push_str("    loc_load.1\n");
    out.push_str("    assert_eq.err=\"sz: alpha_1 mismatch (Fiat-Shamir failure)\"\n");
    out.push_str("    dropw dropw dropw drop drop\n");
    out.push_str("    # Transcript frame cleared.\n");
}

/// Horner-eval the polys whose horner step was deferred (PerU32 OperandStack inputs). Each is
/// evaluated by loading its u32 limbs in two 4-word chunks (high half first), splitting each via
/// `u32divmod.65536` to expose u16 limbs, and feeding 8 u16 coefficients per `horner_eval_base`
/// call.
fn emit_input_horner(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let inputs: Vec<&Poly> = rel
        .polys
        .iter()
        .filter(|p| matches!(p.role, PolyRole::OperandStack { .. }))
        .collect();
    let n_inputs = inputs.len();
    for (i, poly) in inputs.iter().enumerate() {
        assert!(matches!(poly.storage, Storage::PerU32));
        assert!(
            poly.u16_coeff_count == 16,
            "OperandStack input polys must be 16 u16 coefficients (8 u32); got {} for `{}`",
            poly.u16_coeff_count,
            poly.name,
        );

        let off = layout.poly_offset(poly.name);
        let is_first = i == 0;
        let is_last = i == n_inputs - 1;

        let name = poly.name;
        if is_first {
            out.push_str(&format!("    # ----- {name}(alpha) horner eval -----\n"));
            // Fresh frame for input horner: [pad(5), alpha_addr@5, acc(2)@6,7]. After a 4-u32
            // load + 4 splits, the 8 u16 coefs land at depths 0-7, shifting alpha_addr to
            // depth 13 and acc to 14/15 — the layout horner_eval_base's ABI requires.
            out.push_str("    push.0 push.0\n");
            out.push_str("    locaddr.0\n");
            out.push_str("    padw push.0\n");
            out.push_str("    # => [pad(5), alpha_addr, acc_0=0, acc_1=0, ...]\n");
        } else {
            out.push('\n');
            out.push_str(&format!("    # ----- {name}(alpha) horner eval -----\n"));
            out.push_str("    # Frame layout is identical to the first horner eval above; acc was zeroed by the snapshot.\n");
        }

        // High half: load + split + horner.
        out.push_str(&format!("    padw loc_loadw_le.{}\n", off + 4));
        emit_u16_split_quad(out);
        out.push_str(&format!("    # => [{name}_u16[15..8], pad(5), alpha_addr, acc(2), ...]\n"));
        out.push_str("    horner_eval_base\n");
        out.push_str("    dropw\n");
        out.push_str(&format!(
            "    # => [{name}_u16[11..8], pad(5), alpha_addr, partial-{name}(alpha) for high u16s, ...]\n"
        ));

        // Low half: loadw overwrites the 4-u16 residual; split + horner finishes {name}(alpha).
        out.push_str(&format!("    loc_loadw_le.{off}\n"));
        emit_u16_split_quad(out);
        out.push_str(&format!("    # => [{name}_u16[7..0], pad(5), alpha_addr, acc(2), ...]\n"));
        out.push_str("    horner_eval_base\n");
        out.push_str("    dropw dropw\n");
        out.push_str(&format!("    # => [pad(5), alpha_addr, {name}(alpha), ...]\n"));

        let h = layout.h_offset(poly.name);
        if is_last {
            // Last input: dup-snapshot at depths 6/7 (dup is 1 cyc at any depth, unlike
            // movup.6+). Acc stays on stack — the residual gets absorbed by the identity
            // check's opening loc_loadw_le and the recombine's first loadw.
            out.push('\n');
            out.push_str(&format!("    # Snapshot {name}(alpha) via dup; acc stays in place.\n"));
            out.push_str(&format!("    dup.6 loc_store.{h}\n"));
            out.push_str(&format!("    dup.7 loc_store.{}\n", h + 1));
        } else {
            // Non-last: snapshot AND reset acc to (0, 0) in place so the next input's
            // horner reuses the same alpha_addr + 5-zero pad frame.
            let next_input = inputs[i + 1].name;
            out.push('\n');
            out.push_str(&format!(
                "    # Snapshot {name}(alpha) and reset depths 6/7 for {next_input}.\n"
            ));
            out.push_str(&format!("    movup.6 loc_store.{h} push.0 movdn.6\n"));
            out.push_str(&format!("    movup.7 loc_store.{} push.0 movdn.7\n", h + 1));
            out.push_str("    # => [pad(5), alpha_addr, 0, 0, ...]\n");
        }
    }
}

/// Emits the 4-u32 -> 8-u16 split sequence: u32divmod by 65536 produces (lo_u16, hi_u16);
/// swap puts hi_u16 on top. movup.2/4/6 brings the next unsplit u32 to top as the prior
/// splits push prior u16 results downward. Final stack has the 8 u16s in descending limb
/// order on top, ready for `horner_eval_base` to consume.
fn emit_u16_split_quad(out: &mut String) {
    out.push_str("    u32divmod.65536 swap\n");
    out.push_str("    movup.2 u32divmod.65536 swap\n");
    out.push_str("    movup.4 u32divmod.65536 swap\n");
    out.push_str("    movup.6 u32divmod.65536 swap\n");
}

/// Emits the extension-field identity check, specialized to the modmul shape:
/// `a*b - q*m - c = (W - alpha) * (shifted - offset)`.
///
/// Computes `(alpha - W) * (offset - shifted) + q*m + c - a*b` and asserts both
/// extension-field coordinates are zero. The factor and operand sign-flips relative to the
/// docstring identity are algebraically equivalent and let the emitted MASM use a single
/// natural-order word load for the (shifted, offset) ext2 pair stored adjacently in mem.
///
/// Panics if the spec is not the modmul shape (2 products, 1 linear, 1 carry term) or if
/// the witness h-storage layout violates the word-load adjacency the emitted sequence
/// assumes (see the asserts below).
fn emit_identity_check(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    assert_eq!(
        rel.identity.products.len(),
        2,
        "identity check expects exactly 2 products (a*b - q*modulus), got {}",
        rel.identity.products.len()
    );
    assert_eq!(
        rel.identity.linears.len(),
        1,
        "identity check expects exactly 1 linear (-c), got {}",
        rel.identity.linears.len()
    );
    let pos_prod = rel
        .identity
        .products
        .iter()
        .find(|p| p.sign == Sign::Plus)
        .expect("identity check expects exactly one positive product (a*b)");
    let neg_prod = rel
        .identity
        .products
        .iter()
        .find(|p| p.sign == Sign::Minus)
        .expect("identity check expects exactly one negative product (-q*modulus)");
    let neg_lin = rel
        .identity
        .linears
        .iter()
        .find(|l| l.sign == Sign::Minus)
        .expect("identity check expects exactly one negative linear (-c)");
    let carry = rel.identity.carry;

    let h_a = layout.h_offset(pos_prod.lhs.0);
    let h_b = layout.h_offset(pos_prod.rhs.0);
    let h_q = layout.h_offset(neg_prod.lhs.0);
    let h_c = layout.h_offset(neg_lin.poly.0);
    let modulus_name = neg_prod.rhs.0;
    assert!(
        matches!(resolve(rel, neg_prod.rhs).role, PolyRole::Constant { .. }),
        "identity check expects the negative product RHS `{modulus_name}` to be the fixed modulus"
    );
    let h_modulus = layout.h_offset(modulus_name);
    let h_shifted = layout.h_offset(carry.shifted.0);
    let h_offset = layout.h_offset(carry.offset.0);
    assert_eq!(h_b, h_a + 2, "h_b must equal h_a + 2 (got h_a={h_a}, h_b={h_b})");
    assert_eq!(h_c, h_q + 2, "h_c must equal h_q + 2 (got h_q={h_q}, h_c={h_c})");
    assert_eq!(
        h_offset,
        h_shifted + 2,
        "h_offset must equal h_shifted + 2 (got h_shifted={h_shifted}, h_offset={h_offset})"
    );
    assert!(
        h_a.is_multiple_of(4) && h_q.is_multiple_of(4) && h_shifted.is_multiple_of(4),
        "h-offsets for (a, q, shifted) must be word-aligned (got h_a={h_a}, h_q={h_q}, h_shifted={h_shifted})"
    );

    let w = carry.multiplier;
    let m = modulus_name;
    let s = carry.shifted.0;
    let o = carry.offset.0;
    out.push_str("    # ----- extension-field identity check -----\n");
    // Entry has 8 residual felts on top (per emit_input_horner's last-input teardown).
    // The opening loc_loadw_le overwrites the first 4; the remaining 4 are carried below the
    // identity-check arithmetic and absorbed by emit_recombine_u16_to_u32's first loadw after
    // the assertz pair.
    //
    // q*{modulus} is computed FIRST so T1 lands naturally on top of q*{modulus}; this skips
    // the movup.5 movup.5 that would otherwise be needed to align T1 above q*{modulus} for
    // ext2add.
    out.push_str(&format!("    loc_loadw_le.{h_q}\n"));
    out.push_str("    # => [q, c, residual(4), ...]\n");
    out.push('\n');
    out.push_str(&format!(
        "    # q*{m} first: this puts T1 directly above q*{m} (no movup needed for T2 = T1 + q*{m}).\n"
    ));
    out.push_str(&format!("    loc_load.{}\n", h_modulus + 1));
    out.push_str(&format!("    loc_load.{h_modulus}\n"));
    out.push_str("    ext2mul\n");
    out.push_str(&format!("    # => [q*{m}, c, residual(4), ...]\n"));
    out.push('\n');
    out.push_str(&format!(
        "    # T1 = (W - alpha) * ({s}(alpha) - {o}(alpha)), computed as the equivalent\n"
    ));
    out.push_str(&format!(
        "    # (alpha - W) * ({o}(alpha) - {s}(alpha)) so a single loadw on the adjacent ({s}, {o})\n"
    ));
    out.push_str("    # ext2 pair feeds ext2sub directly.\n");
    out.push_str(&format!("    padw loc_loadw_le.{h_shifted}\n"));
    out.push_str("    ext2sub\n");
    out.push_str("    loc_load.1\n");
    out.push_str(&format!("    loc_load.0 sub.{w}\n"));
    out.push_str("    ext2mul\n");
    out.push_str(&format!("    # => [T1, q*{m}, c, residual(4), ...]\n"));
    out.push('\n');
    out.push_str("    ext2add\n");
    out.push_str("    ext2add\n");
    out.push_str(&format!("    # => [T3 = T1 + q*{m} + c, residual(4), ...]\n"));
    out.push('\n');
    out.push_str("    # LHS = a*b; identity is T3 - LHS == 0.\n");
    out.push_str(&format!("    padw loc_loadw_le.{h_a}\n"));
    out.push_str("    ext2mul\n");
    out.push_str("    ext2sub\n");
    out.push_str("    assertz.err=\"sz: identity check failed at basis coord 0\"\n");
    out.push_str("    assertz.err=\"sz: identity check failed at basis coord 1\"\n");
    out.push_str("    # => [residual(4), ...]  (absorbed by the next loadw)\n");
}

/// Emits the output exposure: recombines u16 pairs of `c` into u32 limbs, then runs the
/// canonical-form check (`c < rhs`) over those same u32 limbs ([`emit_fused_lessthan`]).
fn emit_outputs(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let (fused_lhs, fused_rhs) = find_output_fused_lessthan(rel);
    let output = &rel.expose[0];
    let output_poly = resolve(rel, output.poly);
    match output.form {
        OutputForm::U32Limbs => {
            emit_u32_recombine(output_poly, layout, out);
            emit_fused_lessthan(rel, fused_lhs, fused_rhs, out);
        },
    }
}

/// Emits the canonical-form check `lhs < rhs` (rhs a `Constant` poly) fused with the output
/// recombination. Stack on entry: `[c0..c7, ...]` (c0 on top, freshly recombined).
///
/// Check: `c < rhs` iff `(c + delta) < 2^256` iff the u256 sum produces no carry, where
/// `delta = 2^256 - rhs`. The chain unrolls per limb with `u32widening_add` for limbs where
/// `delta == 0` and `u32widening_add3` (with `delta[i]` pushed as an immediate) elsewhere.
/// `dup.N` references c[N] without consuming it so c stays on stack as the proc's return
/// value.
fn emit_fused_lessthan(rel: &LinearRelation, lhs: PolyRef, rhs: PolyRef, out: &mut String) {
    let lhs_p = resolve(rel, lhs);
    let rhs_p = resolve(rel, rhs);
    let u16_limbs = match rhs_p.role {
        PolyRole::Constant { u16_limbs } => u16_limbs,
        _ => panic!("emit_fused_lessthan: rhs `{}` is not a Constant poly", rhs_p.name),
    };
    assert_eq!(
        u16_limbs.len(),
        16,
        "fused canonical check expects 16 u16 limbs (8 u32) for rhs `{}`",
        rhs_p.name
    );

    // Pack 16 u16 -> 8 u32 LE limbs, then delta = 2^256 - rhs via two's complement (~rhs + 1).
    let mut rhs_u32 = [0u32; 8];
    for i in 0..8 {
        rhs_u32[i] = (u16_limbs[2 * i] as u32) | ((u16_limbs[2 * i + 1] as u32) << 16);
    }
    assert!(
        rhs_u32.iter().any(|&x| x != 0),
        "fused canonical check requires rhs `{}` > 0",
        rhs_p.name
    );
    let mut delta = [0u32; 8];
    let mut carry: u64 = 1;
    for i in 0..8 {
        let v = (!rhs_u32[i] as u64) + carry;
        delta[i] = v as u32;
        carry = v >> 32;
    }
    // For any rhs in (0, 2^256), 2^256 - rhs fits in 256 bits, so the two's complement carry
    // out of the top limb is exactly 0.
    assert_eq!(carry, 0, "delta two's-complement overflow (rhs={} >= 2^256?)", rhs_p.name);
    assert!(
        delta[0] != 0,
        "fused canonical check needs delta[0] != 0 (rhs={} divisible by 2^32 is unusual)",
        rhs_p.name
    );

    out.push('\n');
    out.push_str(&format!("    # ----- canonical check: {} < {} -----\n", lhs_p.name, rhs_p.name,));
    out.push_str(&format!(
        "    # {} < {} iff ({} + delta) does not overflow 2^256; delta = 2^256 - {}.\n",
        lhs_p.name, rhs_p.name, lhs_p.name, rhs_p.name,
    ));
    out.push_str(&format!(
        "    # Carry chain: dup each {}_u32 limb (preserving {} on stack as the proc return) and\n",
        lhs_p.name, lhs_p.name,
    ));
    out.push_str("    # add it to delta[i] + prior carry; assertz the final carry.\n");
    let c_name = lhs_p.name;
    for (i, delta_i) in delta.iter().enumerate() {
        // c[0] is at depth 0 initially; after iter 0 a carry sits on top, so c[i] for i >= 1
        // is at depth i + 1.
        let dup_depth = if i == 0 { 0 } else { i + 1 };
        let op = if i == 0 {
            format!("dup.{dup_depth} push.0x{delta_i:x} u32widening_add drop")
        } else if *delta_i != 0 {
            format!("dup.{dup_depth} push.0x{delta_i:x} u32widening_add3 drop")
        } else {
            format!("dup.{dup_depth} u32widening_add drop")
        };
        out.push_str(&format!("    {op}\n"));
    }
    out.push_str(&format!("    assertz.err=\"sz: {} < {} violated\"\n", lhs_p.name, rhs_p.name,));
    out.push_str(&format!("    # => [{c_name}_u32(8), ...]\n"));
}

fn emit_u32_recombine(poly: &Poly, layout: &Layout, out: &mut String) {
    let n_u32 = poly.u16_coeff_count / 2;
    out.push_str(&format!(
        "    # ----- recombine {}: {} u16 limbs -> {} u32 limbs -----\n",
        poly.name, poly.u16_coeff_count, n_u32
    ));
    emit_recombine_u16_to_u32(poly, layout, out);
}

/// Renders a human-readable identity equation, e.g. for `modmul_k1_base`:
/// `a(alpha) * b(alpha) - q(alpha) * m(alpha) - c(alpha)
///     = (W - alpha) * (e_shifted(alpha) - offset(alpha))`.
fn render_identity(rel: &LinearRelation) -> String {
    let mut s = String::new();
    let mut first = true;
    for prod in rel.identity.products {
        if !first || prod.sign == Sign::Minus {
            s.push_str(if prod.sign == Sign::Plus { " + " } else { " - " });
        }
        first = false;
        s.push_str(&format!("{}(alpha) * {}(alpha)", prod.lhs.0, prod.rhs.0));
    }
    for lin in rel.identity.linears {
        s.push_str(if lin.sign == Sign::Plus { " + " } else { " - " });
        s.push_str(&format!("{}(alpha)", lin.poly.0));
    }
    let carry = &rel.identity.carry;
    s.push_str(&format!(
        " = (W - alpha) * ({}(alpha) - {}(alpha))",
        carry.shifted.0, carry.offset.0,
    ));
    s
}
