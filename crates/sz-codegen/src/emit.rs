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

/// Resolved memory layout for a [`LinearRelation`]. Computed once per emit; both `poly_offset`
/// and `h_offset` are O(N) name lookups against `entries`, which is fine for the small N we run
/// at (currently 7 polys for each k1 modmul spec).
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

/// Number of memory felts a polynomial occupies given its storage form. `Constant` polys are
/// hardcoded into the emitted MASM as immediate `push.<value>` sequences, so they claim no
/// memory cells (only an h-storage pair for `poly(alpha)`).
fn felts_for(poly: &Poly) -> usize {
    if matches!(poly.role, PolyRole::Constant { .. }) {
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
    emit_streaming(rel, &layout, &mut out);
    emit_aux_checks_after_stream(rel, &layout, &mut out);
    emit_fs_check(&mut out);
    emit_input_horner(rel, &layout, &mut out);
    emit_constant_horner(rel, &layout, &mut out);
    emit_identity_check(rel, &layout, &mut out);
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
/// out as 8 u32 felts at its offset. Store order follows operand-stack depth (lowest first), so
/// the first poly consumed is the one closest to the top of the stack.
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

    for poly in inputs {
        assert!(matches!(poly.storage, Storage::PerU32));
        let off = layout.poly_offset(poly.name);
        // Two `loc_storew_le` words cover 8 u32 limbs at mem[off..off+8]. Each `loc_storew_le.X`
        // consumes 4 stack items (top first) and writes mem[X..X+4].
        out.push_str(&format!(
            "    loc_storew_le.{} dropw\n    loc_storew_le.{} dropw\n",
            off,
            off + 4,
        ));
    }
}

fn emit_alpha_pop(out: &mut String) {
    out.push_str("    adv_push                              # alpha_1\n");
    out.push_str("    adv_push                              # alpha_0 (top)\n");
    out.push_str("    loc_store.0                           # mem[0] = alpha_0\n");
    out.push_str("    loc_store.1                           # mem[1] = alpha_1\n");
}

/// Streaming pass: absorb every poly into the FS hash; horner-evaluate witness polys at alpha.
/// Input polys (operand stack -> memory) are absorbed via `mem_stream` (no horner; their
/// alpha-evaluation runs in [`emit_input_horner`]). Witness polys are absorbed via `adv_pipe`
/// with `horner_eval_base` interleaved.
fn emit_streaming(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let first_input_offset = rel
        .polys
        .iter()
        .find(|p| matches!(p.role, PolyRole::OperandStack { .. }))
        .map(|p| layout.poly_offset(p.name))
        .expect("at least one OperandStack poly required");

    out.push_str("    # ----- transcript absorb + polynomial evaluation setup -----\n");
    out.push_str("    push.0 push.0                         # acc placeholders (depths 14, 15 once filled)\n");
    out.push_str("    locaddr.0                             # alpha_addr\n");
    out.push_str(&format!(
        "    locaddr.{first_input_offset}                             # ptr = first poly start\n"
    ));
    emit_initial_sponge_state(rel, out);

    // Walk polys in order, consolidating consecutive operand-stack absorbs into a single
    // `repeat.N` block (no horner happens during these chunks, so chunks of the same shape can
    // share the loop body). Witness polys each get their own block (each one needs an h-store
    // and an acc reset between blocks).
    let mut first_witness = true;
    let mut i = 0;
    while i < rel.polys.len() {
        let poly = &rel.polys[i];
        match poly.role {
            PolyRole::OperandStack { .. } => {
                // Coalesce consecutive operand-stack polys into a single repeat block (no horner
                // step interleaved here, so the body is uniform).
                let mut total_chunks = 0;
                while i < rel.polys.len()
                    && matches!(rel.polys[i].role, PolyRole::OperandStack { .. })
                {
                    total_chunks += chunks_for(&rel.polys[i]);
                    i += 1;
                }
                out.push_str(&format!(
                    "    repeat.{total_chunks}\n        mem_stream\n        exec.poseidon2::permute\n    end\n"
                ));
            },
            PolyRole::Witness => {
                if first_witness {
                    // Coefficient range note: u32assertw enforces u32, not u16. Non-u16
                    // coefficients are valid non-canonical base-W representations; the SZ
                    // identity binds the provided coefficients, and the final `c < modulus`
                    // check pins the returned residue. See the spec docstring for the full
                    // soundness argument.
                    out.push_str(
                        "    # Witness coefficients are u32-bounded, not u16-bounded, by design.\n",
                    );
                    first_witness = false;
                }
                let chunks = chunks_for(poly);
                out.push_str(&format!(
                    "    repeat.{chunks}\n        adv_pipe\n        u32assertw\n        swapw u32assertw swapw\n        horner_eval_base\n        exec.poseidon2::permute\n    end\n"
                ));
                let h = layout.h_offset(poly.name);
                out.push_str(&format!(
                    "    dup.14 loc_store.{h}\n    dup.15 loc_store.{}\n",
                    h + 1
                ));
                if !is_last_witness(rel, poly.name) {
                    out.push_str("    movup.14 drop push.0 movdn.14\n");
                    out.push_str("    movup.15 drop push.0 movdn.15\n");
                }
                i += 1;
            },
            PolyRole::Constant { .. } => {
                // Constants are public and hardcoded into the emitted MASM. The modulus is
                // already bound into the FS seed, so constants are not absorbed again online.
                // Their alpha-evaluation runs separately in `emit_constant_horner`.
                i += 1;
            },
        }
    }
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

/// Emits the initial sponge state for the FS streaming loop. The active specs all have a
/// `Constant` modulus poly named `p`; the capacity lanes are precomputed as the capacity part
/// of `modulus_seeded_initial_state(modulus_u16)` and pushed as a single 4-felt immediate.
/// The rate lanes go in as `padw padw` zeros because the first `mem_stream` overwrites them
/// before any permutation.
fn emit_initial_sponge_state(rel: &LinearRelation, out: &mut String) {
    let modulus = modulus_limbs(rel);
    let state = modulus_seeded_initial_state(modulus);
    out.push_str("    # ----- precomputed capacity from Poseidon(modulus); rate words are zero-\n");
    out.push_str(
        "    # initialized because the first `mem_stream` overwrites them before any permute.\n",
    );
    // Stack target: [R0(4)=zeros, R1(4)=zeros, C(4)=capacity, ptr, ...]. push.A.B.C.D
    // pushes A first leaving D on top, so to land C[3..0] at depths 8..11 we push the
    // capacity word first (it ends up deepest), then `padw padw` for the rate words.
    out.push_str(&format!(
        "    push.{}.{}.{}.{}        # C = precomputed capacity\n",
        state[11].as_canonical_u64(),
        state[10].as_canonical_u64(),
        state[9].as_canonical_u64(),
        state[8].as_canonical_u64(),
    ));
    out.push_str(
        "    padw padw                              # R1, R0 zero-init (overwritten by first absorb)\n",
    );
}

/// Extracts the modulus's u16 limbs from a spec's `Constant` poly named `p`. Every spec the
/// emitter supports today is a modmul shape that includes such a poly; the absence of one is
/// a spec-authoring bug, not a runtime branch worth supporting.
fn modulus_limbs(rel: &LinearRelation) -> &'static [u16] {
    for poly in rel.polys {
        if poly.name == "p"
            && let PolyRole::Constant { u16_limbs } = poly.role
        {
            return u16_limbs;
        }
    }
    panic!(
        "spec `{}` has no `Constant` poly named `p` (required for the modulus-seeded FS transcript)",
        rel.name
    );
}

/// Poseidon2 sponge state after absorbing the modulus (16 u16 limbs, natural low-to-high
/// order, two rate-8 chunks) from a zero-initialized state.
///
/// Only the capacity lanes (`state[8..12]`) are load-bearing; the first online absorb
/// overwrites the rate. The MASM verifier therefore only embeds the capacity (see
/// [`emit_initial_sponge_state`]).
///
/// Mirrored by `miden_core_lib::handlers::u256_modmul::modulus_seeded_initial_state`.
/// Cross-crate agreement is pinned by the `k1_{base,scalar}_precomputed_initial_state_pin`
/// core-lib tests.
pub fn modulus_seeded_initial_state(modulus_u16: &[u16]) -> [Felt; Poseidon2::STATE_WIDTH] {
    const RATE: usize = 8;
    assert_eq!(
        modulus_u16.len(),
        16,
        "modulus_seeded_initial_state expects 16 u16 limbs (got {})",
        modulus_u16.len(),
    );
    let n_chunks = modulus_u16.len() / RATE;
    let mut state = [Felt::ZERO; Poseidon2::STATE_WIDTH];
    for chunk_idx in 0..n_chunks {
        for j in 0..RATE {
            state[j] = Felt::from_u32(modulus_u16[chunk_idx * RATE + j] as u32);
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

/// Emits `LimbIsZero` aux checks. Fires after the streaming load completes (so memory holds
/// the witness data) but before the FS-equality check. `LessThan` aux checks need the
/// polynomials in u32 limb form, which is produced during output emission, so they are emitted
/// fused with the output recombination (see [`emit_outputs`]).
fn emit_aux_checks_after_stream(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    for check in rel.aux_checks {
        if let AuxCheck::LimbIsZero { poly, index } = check {
            let p = resolve(rel, *poly);
            let off = layout.poly_offset(p.name);
            let mem_index = limb_to_mem_index(p, off, *index);
            out.push_str(&format!(
                "    loc_load.{mem_index} assertz.err=\"sz: {}_{index} must be 0 (top carry coefficient)\"\n",
                p.name
            ));
        }
    }
}

/// Locates the `LessThan { lhs, rhs }` aux check for a spec's single u32-form output, where
/// `rhs` is a `Constant`. Such a check is emitted fused with the output recombination so the
/// u32 form of the output is shared between the canonical-form check and the operand-stack
/// output; see [`emit_outputs`].
///
/// Every spec the emitter supports today has exactly one such check (the canonical reduction
/// `c < p`), so a missing or non-fusable `LessThan` is a spec-authoring bug.
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

/// Pushes a `Constant` poly's 8 u32 limbs onto the stack with limb 0 on top. Each u32 limb is
/// `u16_limbs[2i] + W * u16_limbs[2i+1]` and gets emitted as a single `push.<u32>` immediate.
fn emit_push_constant_as_u32(poly: &Poly, u16_limbs: &[u16], out: &mut String) {
    assert!(
        poly.u16_coeff_count == 16,
        "constant u32 push expects 16 u16 = 8 u32 limbs (got {} u16 coefficients)",
        poly.u16_coeff_count
    );
    assert_eq!(u16_limbs.len(), 16);
    // Push limb 7 first so limb 0 lands on top.
    for u32_idx in (0..8).rev() {
        let lo = u16_limbs[2 * u32_idx] as u32;
        let hi = u16_limbs[2 * u32_idx + 1] as u32;
        let value = lo | (hi << 16);
        out.push_str(&format!("    push.{value}        # {}_u32[{u32_idx}]\n", poly.name));
    }
}

/// u16-to-u32 recombination loop emitted as part of output exposure. Each adjacent pair of
/// `u16` memory cells is recombined as `hi * W + lo` and pushed onto the stack with
/// `u32assert2` every two pushes for soundness (forces canonical W^2-base limbs).
fn emit_recombine_u16_to_u32(poly: &Poly, layout: &Layout, out: &mut String) {
    assert!(matches!(poly.storage, Storage::PerU16));
    assert!(poly.u16_coeff_count.is_multiple_of(2));
    let off = layout.poly_offset(poly.name);
    let n = poly.u16_coeff_count;
    for u32_idx in (0..(n / 2)).rev() {
        let lo_mem = off + (n - 1 - 2 * u32_idx);
        let hi_mem = off + (n - 2 - 2 * u32_idx);
        out.push_str(&format!(
            "    loc_load.{hi_mem} push.65536 mul loc_load.{lo_mem} add        # {}_u32[{u32_idx}]\n",
            poly.name,
        ));
        if u32_idx % 2 == 0 {
            out.push_str("    u32assert2\n");
        }
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
    out.push_str("    # ----- Fiat-Shamir equality check -----\n");
    out.push_str("    loc_load.0\n");
    out.push_str("    assert_eq.err=\"sz: alpha_0 mismatch (Fiat-Shamir failure)\"\n");
    out.push_str("    loc_load.1\n");
    out.push_str("    assert_eq.err=\"sz: alpha_1 mismatch (Fiat-Shamir failure)\"\n");
    out.push_str("    dropw dropw dropw drop drop           # drop residual state + ptr + alpha_addr + acc\n");
}

/// Horner-eval the polys whose horner step was deferred (PerU32 OperandStack inputs). Each is
/// evaluated by loading its u32 limbs in two 4-word chunks (high half first), splitting each via
/// `u32divmod.65536` to expose u16 limbs, and feeding 8 u16 coefficients per `horner_eval_base`
/// call.
fn emit_input_horner(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    for poly in rel.polys {
        let PolyRole::OperandStack { .. } = poly.role else {
            continue;
        };
        assert!(matches!(poly.storage, Storage::PerU32));
        assert!(
            poly.u16_coeff_count == 16,
            "OperandStack input polys must be 16 u16 coefficients (8 u32); got {} for `{}`",
            poly.u16_coeff_count,
            poly.name,
        );

        let off = layout.poly_offset(poly.name);
        out.push_str(&format!("    # ----- {}(alpha) horner eval -----\n", poly.name));
        out.push_str("    push.0 push.0\n");
        out.push_str("    locaddr.0\n");
        out.push_str(
            "    push.0 push.0 push.0 push.0 push.0    # [pad x5, alpha_addr, acc_1, acc_0, ...]\n",
        );

        // High half (limbs 4..8) first so horner sees descending degree.
        out.push_str(&format!(
            "    padw loc_loadw_le.{}                   # high u32 limbs\n",
            off + 4
        ));
        emit_u16_split_quad(out);
        out.push_str("    horner_eval_base\n    dropw dropw\n");

        out.push_str(&format!("    padw loc_loadw_le.{off}                   # low u32 limbs\n"));
        emit_u16_split_quad(out);
        out.push_str("    horner_eval_base\n    dropw dropw\n");

        let h = layout.h_offset(poly.name);
        out.push_str(&format!("    dup.6 loc_store.{h}\n"));
        out.push_str(&format!("    dup.7 loc_store.{}\n", h + 1));
        out.push_str("    dropw dropw\n");
    }
}

/// Emits the 4-u32 -> 8-u16 split sequence (one u32divmod.65536 per limb, with movups to align
/// pairs for `horner_eval_base`).
fn emit_u16_split_quad(out: &mut String) {
    out.push_str("    u32divmod.65536 swap\n");
    out.push_str("    movup.2 u32divmod.65536 swap\n");
    out.push_str("    movup.4 u32divmod.65536 swap\n");
    out.push_str("    movup.6 u32divmod.65536 swap\n");
}

/// Horner-eval `Constant` polys at alpha. Coefficients are emitted as immediate `push.<u16>`
/// instructions in chunks of 8, with the highest-degree coefficient ending on top of the stack
/// (the order `horner_eval_base` consumes). Mirrors `emit_input_horner`'s setup + chunk loop +
/// h-storage save shape; differs only in how coefficients reach the stack.
fn emit_constant_horner(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    for poly in rel.polys {
        let PolyRole::Constant { u16_limbs } = poly.role else {
            continue;
        };
        assert_eq!(
            poly.u16_coeff_count,
            u16_limbs.len(),
            "Constant {} declares {} coefficients but provides {} limbs",
            poly.name,
            poly.u16_coeff_count,
            u16_limbs.len()
        );
        assert!(
            poly.u16_coeff_count % 8 == 0,
            "Constant {} u16_coeff_count must be a multiple of 8 (got {})",
            poly.name,
            poly.u16_coeff_count
        );
        let n_chunks = poly.u16_coeff_count / 8;

        out.push_str(&format!("    # ----- {}(alpha) horner eval (constant) -----\n", poly.name));
        out.push_str("    push.0 push.0\n");
        out.push_str("    locaddr.0\n");
        out.push_str(
            "    push.0 push.0 push.0 push.0 push.0    # [pad x5, alpha_addr, acc_1, acc_0, ...]\n",
        );

        // Chunks processed high-degree first (chunk 0 = highest).
        for chunk_idx in 0..n_chunks {
            let d_top = poly.u16_coeff_count - 1 - 8 * chunk_idx;
            let d_bot = d_top - 7;
            // Push lowest-degree first so highest-degree lands on top.
            for d in d_bot..=d_top {
                out.push_str(&format!(
                    "    push.{}        # {}_u16[{d}]\n",
                    u16_limbs[d], poly.name
                ));
            }
            out.push_str("    horner_eval_base\n    dropw dropw\n");
        }

        let h = layout.h_offset(poly.name);
        out.push_str(&format!("    dup.6 loc_store.{h}\n"));
        out.push_str(&format!("    dup.7 loc_store.{}\n", h + 1));
        out.push_str("    dropw dropw\n");
    }
}

/// Emits the extension-field identity check.
///
/// Strategy: the identity
/// `sum(signed_terms) - (W - alpha) * (carry.pos(alpha) - carry.neg(alpha)) = 0`
/// is rewritten as `LHS = RHS` where:
///   - `LHS` = sum of terms with sign Plus
///   - `RHS` = sum of terms with sign Minus (sign-flipped onto the RHS)
///       + `(W - alpha) * (pos - neg)`
/// Then the check is `LHS - RHS == (0, 0)`.
///
/// This shape builds RHS first, then LHS on top, so `movdn.3 movdn.3 ext2sub` can check
/// `LHS - RHS == 0`.
fn emit_identity_check(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    out.push_str("    # ----- extension-field identity check -----\n");

    // ----- Build RHS: starts with (W - alpha) * carry, then add each Minus-signed term. -----
    out.push_str(&format!(
        "    push.0 push.{w}                     # W = ({w}, 0)\n",
        w = rel.identity.carry.multiplier
    ));
    out.push_str(
        "    loc_load.1\n    loc_load.0\n    ext2sub                               # (W - alpha)\n",
    );

    // Verified carry is `pos - neg`; load both, ext2sub to get the difference, then ext2mul
    // to fold (W - alpha) in. Push `pos` first (lower on stack), then `neg` (top); ext2sub
    // yields `pos - neg` (bottom - top).
    let carry = rel.identity.carry;
    emit_load_h_pair(layout, carry.pos.0, out);
    emit_load_h_pair(layout, carry.neg.0, out);
    out.push_str("    ext2sub                               # pos_h - neg_h\n");
    out.push_str("    ext2mul                               # (W - alpha) * (pos - neg)\n");

    // Minus-signed products and linears contribute positively to RHS.
    for prod in rel.identity.products.iter().filter(|p| p.sign == Sign::Minus) {
        emit_load_h_pair(layout, prod.lhs.0, out);
        emit_load_h_pair(layout, prod.rhs.0, out);
        out.push_str("    ext2mul\n    ext2add                               # RHS += minus-product (sign-flipped)\n");
    }
    for lin in rel.identity.linears.iter().filter(|l| l.sign == Sign::Minus) {
        emit_load_h_pair(layout, lin.poly.0, out);
        out.push_str(
            "    ext2add                               # RHS += minus-linear (sign-flipped)\n",
        );
    }

    // ----- Build LHS on top of RHS: first positive product initializes; rest accumulate. -----
    let pos_products: Vec<_> =
        rel.identity.products.iter().filter(|p| p.sign == Sign::Plus).collect();
    assert!(
        !pos_products.is_empty(),
        "identity must have at least one positive product (spec `{}` has none)",
        rel.name
    );
    for (i, prod) in pos_products.iter().enumerate() {
        emit_load_h_pair(layout, prod.lhs.0, out);
        emit_load_h_pair(layout, prod.rhs.0, out);
        if i == 0 {
            out.push_str(
                "    ext2mul                               # LHS = first positive product\n",
            );
        } else {
            out.push_str("    ext2mul\n    ext2add                               # LHS += positive product\n");
        }
    }
    for lin in rel.identity.linears.iter().filter(|l| l.sign == Sign::Plus) {
        emit_load_h_pair(layout, lin.poly.0, out);
        out.push_str("    ext2add                               # LHS += positive linear\n");
    }

    // ----- Check LHS - RHS == (0, 0). -----
    out.push_str("    movdn.3 movdn.3                       # reorder to [RHS_0, RHS_1, LHS_0, LHS_1, ...]\n");
    out.push_str("    ext2sub                               # bottom - top = LHS - RHS\n");
    out.push_str("    eq.0 assert.err=\"sz: identity check failed at basis coord 0\"\n");
    out.push_str("    eq.0 assert.err=\"sz: identity check failed at basis coord 1\"\n");
}

/// Loads `poly`'s h-storage pair onto the stack: basis_1 first, basis_0 on top.
fn emit_load_h_pair(layout: &Layout, poly_name: &str, out: &mut String) {
    let h = layout.h_offset(poly_name);
    out.push_str(&format!("    loc_load.{}\n    loc_load.{}\n", h + 1, h));
}

/// Emits the output exposure: recombines u16 pairs of `c` into u32 limbs, with `u32assert2`
/// every two pushes for soundness (forces canonical W^2-base limbs of the integer product).
///
/// The post-recombine block also runs the mandatory canonical check inline (duplicate output
/// via `dupw.1 dupw.1`, push the constant RHS, call `u256::lt`, assert) so the output
/// recombination is shared with the canonical check instead of running twice.
fn emit_outputs(rel: &LinearRelation, layout: &Layout, out: &mut String) {
    let (fused_lhs, fused_rhs) = find_output_fused_lessthan(rel);
    let output = &rel.expose[0];
    let p = resolve(rel, output.poly);
    match output.form {
        OutputForm::U32Limbs => {
            emit_u32_recombine(p, layout, out);
            emit_fused_lessthan(rel, fused_lhs, fused_rhs, out);
        },
    }
}

/// Emits the canonical-form check fused with the output recombination. Stack on entry:
/// `[c0..c7, ...]` (c0 on top, freshly recombined). The sequence is:
///
/// ```text
/// dupw.1 dupw.1                       # duplicate c word-pair: [c_copy, c_orig, ...]
/// push.<rhs[7]> ... push.<rhs[0]>     # push the Constant RHS as 8 u32 limbs
/// exec.::miden::core::math::u256::lt  # consumes [rhs, c_copy] -> flag = (c_copy < rhs)
/// assert.err=...
/// ```
///
/// The assert consumes the flag, leaving the original `c` as the proc's output. The fusion
/// lets one u16-to-u32 recombination serve both the canonical check and the output push.
fn emit_fused_lessthan(rel: &LinearRelation, lhs: PolyRef, rhs: PolyRef, out: &mut String) {
    let lhs_p = resolve(rel, lhs);
    let rhs_p = resolve(rel, rhs);
    let u16_limbs = match rhs_p.role {
        PolyRole::Constant { u16_limbs } => u16_limbs,
        _ => panic!("emit_fused_lessthan: rhs `{}` is not a Constant poly", rhs_p.name),
    };
    out.push_str(&format!(
        "    # ----- fused canonical check: {} < {} -----\n",
        lhs_p.name, rhs_p.name
    ));
    out.push_str("    dupw.1\n    dupw.1\n");
    emit_push_constant_as_u32(rhs_p, u16_limbs, out);
    out.push_str(&format!(
        "    exec.::miden::core::math::u256::lt\n    assert.err=\"sz: {} < {} violated\"\n",
        lhs_p.name, rhs_p.name
    ));
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
/// `a(alpha) * b(alpha) - q(alpha) * p(alpha) - c(alpha)
///     = (W - alpha) * (e_pos(alpha) - e_neg(alpha))`.
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
    s.push_str(&format!(" = (W - alpha) * ({}(alpha) - {}(alpha))", carry.pos.0, carry.neg.0));
    s
}
