//! LogUp adapter — natural last-row σ-closing.
//!
//! Re-uses miden-vm's closure-based lookup framework (`LookupAir`,
//! `LookupBuilder`, `LookupColumn`, `LookupGroup`, `LookupBatch`,
//! `LookupMessage`, `Challenges`, `LookupFractions`, `accumulate`) but
//! swaps the constraint-side column-0 finalization (and the matching
//! prover-side residue) for a **natural last-row σ-closing**.
//!
//! ## Closing the running sum
//!
//! Where miden's stock
//! [`ConstraintLookupBuilder`](miden_air::lookup::ConstraintLookupBuilder)
//! reserves a dead last row, this adapter closes the running sum on the
//! **live last row**:
//!
//! ```text
//! when_first:      acc[0] = 0
//! when_transition: D₀·(acc_next[0] − Σ_{i<L} acc[i]) − N₀ = 0
//! when_last:       D₀·(σ          − Σ_{i<L} acc[i]) − N₀ = 0
//! ungated (i>0):   D_i · acc[i] − N_i = 0
//! ```
//!
//! where `σ` lives at `permutation_values()[0]` and `L = num_logup_cols`
//! bounds the sum to the LogUp columns (trailing Schwartz–Zippel register
//! columns stay out of σ). The `acc[0] = 0` boundary plus the last-row
//! bind pin `σ = Σ_r delta_r` — the column's full LogUp residue — folding
//! the final row's interactions into the committed σ, so even a packed
//! chiplet whose last row fires (e.g. the 2^16 byte-pair table) closes
//! correctly. No padding row reserved, no `inv_n` public input. The col-0
//! transition/last gate costs +1 degree over the older ungated σ/n-cyclic
//! form; 0.26's per-AIR quotient coset absorbs it.
//!
//! Prover-side: [`build_logup_aux_trace`] runs miden's stock
//! `build_lookup_fractions` + `accumulate` to produce the multi-column
//! aux trace and reads the running sum's terminal as σ. Column 0 is the
//! plain running sum (`aux[r] = Σ_{i<r} delta_i`); no correction is
//! applied. Fraction columns are kept verbatim.
//!
//! ## Encoding
//!
//! Encoding is delegated to [`Challenges`]:
//!
//! ```text
//! encode(bus, elems) = bus_prefix[bus] + Σ β^i · elems[i]
//! bus_prefix[bus]    = α + (bus + 1) · β^W
//! ```
//!
//! where `W = `[`MAX_MESSAGE_WIDTH`]. Distinct bus ids live on disjoint
//! `β^W`-spaced offsets, so two `(bus, payload)` pairs collide only on
//! a vanishing-probability subset of `(α, β)`.
//!
//! [`lookup_challenges_from_slice`] builds a `Challenges<QuadFelt>` from
//! the flat `[α, β]` slice that `LiftedAir::build_aux_trace` is given —
//! sized to [`MAX_MESSAGE_WIDTH`] / [`NUM_BUS_IDS`] so prover and
//! verifier see identical prefixes.

mod aux_builder;
mod constraint;

pub use aux_builder::build_logup_aux_trace;
pub use constraint::{
    CombinedWindow, CyclicConstraintBatch, CyclicConstraintColumn, CyclicConstraintGroup,
    CyclicConstraintLookupBuilder, LookupMainWindow,
};

// Re-export miden-vm's framework so chiplets only need one `use`.
pub use miden_air::lookup::{
    BoundaryBuilder, Challenges, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
    LookupFractions, LookupGroup, LookupMessage, ProverLookupBuilder, accumulate,
    build_lookup_fractions,
};

use crate::relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS};
use miden_core::field::{PrimeCharacteristicRing, QuadFelt};

// CHALLENGES
// ================================================================================================

/// Number of extension-field challenges drawn by the verifier — one
/// global `(α, β)` pair, shared across every relation.
pub const NUM_RANDOMNESS: usize = 2;

/// Build a `Challenges<QuadFelt>` from the flat `[α, β]` slice handed to
/// [`AuxBuilder::build_aux_trace`](miden_lifted_air::AuxBuilder::build_aux_trace).
///
/// Sizes the precomputed tables to [`MAX_MESSAGE_WIDTH`] /
/// [`NUM_BUS_IDS`] so prover and verifier see identical prefixes.
pub fn lookup_challenges_from_slice(s: &[QuadFelt]) -> Challenges<QuadFelt> {
    debug_assert!(
        s.len() >= NUM_RANDOMNESS,
        "expected at least {NUM_RANDOMNESS} challenges, got {}",
        s.len(),
    );
    Challenges::new(s[0], s[1], MAX_MESSAGE_WIDTH, NUM_BUS_IDS)
}

// PUBLIC-INPUT LAYOUT
// ================================================================================================

/// Number of base-field public inputs the VM exposes: the 4-felt
/// transcript root (a Poseidon2 digest).
///
/// 0.26's `air_inputs` is a single slice every AIR reads, so every chiplet
/// declares the *same* count and they must agree. The root is the VM's one
/// genuine public input; only the transcript-eval chip reads it (pinning
/// its row-0 hash to `public_values()[0..4]`), the others just declare it.
/// The σ/n `inv_n` slot is gone — the natural last-row closing
/// (`constraint.rs`) needs no per-AIR height input, which is what lets a
/// per-AIR value drop out of the now-shared public inputs.
pub const NUM_PUBLIC_VALUES: usize = 4;

// PERMUTATION (σ) CONTRACT
// ================================================================================================

/// Number of permutation (σ) values every chiplet exposes: exactly
/// **one** — the running `σ = Σ_r delta_r` committed at aux column 0
/// and pinned by the last-row σ-closing constraint. (Aux *column* counts vary
/// per chiplet; this exposed-σ count does not.) Backs the
/// `LiftedAir::num_aux_values` method / the layout's
/// `num_permutation_values`. Shared so the single-σ shape reads as a
/// VM-wide convention, not a per-chiplet choice.
pub const NUM_SIGMA_VALUES: usize = 1;

/// Cross-AIR σ closure for
/// [`MultiAir::eval_external`](miden_lifted_air::MultiAir::eval_external):
/// sum every AIR's committed σ residue. Each AIR exposes exactly one —
/// aux column 0's full LogUp residue (see [`NUM_SIGMA_VALUES`]) — so
/// `aux_values[i][0]` is AIR `i`'s contribution. The cross-chiplet bus
/// identity `Σ σ = 0` holds iff the returned value is zero, which
/// `eval_external` surfaces as its single assertion expression.
pub fn sigma_sum(aux_values: &[&[QuadFelt]]) -> QuadFelt {
    aux_values
        .iter()
        .fold(QuadFelt::ZERO, |acc, av| acc + av[0])
}
