//! Per-compression algebraic fingerprint of the message schedule and initial chaining value.
//!
//! An auxiliary accumulator binds each compression's fused additions to the message words and
//! initial chaining value encoded in its footer.
//!
//! # Identity being checked
//!
//! For fused row `0 <= t < 28` and lane `0 <= g < 4`, write `a[t,g]` and `b[t,g]` for the packed
//! words and `k[t,g]` for the A-addition carry. Let `m[j]` and `h[g]` be the footer's message and
//! initial chaining value, and let `sigma(t,g)` select the scheduled message word. Define
//!
//! ```text
//! e[t,g] = a[t,g] + 2^32 k[t,g] - a[t-1,g] - b[t,g] - m[sigma(t,g)],
//! a[-1,g] = h[g].
//! ```
//!
//! Set `rho` to LogUp's beta challenge, sampled after committing the main trace. The polynomial
//! to be checked is
//!
//! ```text
//! P(rho) = sum_{t,g} rho^(4*(28-t)+g) e[t,g]
//!        + sum_g rho^(116+g) (b[0,g] - h[g+4]).
//! ```
//!
//! The 112 addition residuals occupy distinct powers 4 through 115; the four initial-B residuals
//! occupy powers 116 through 119. Thus a nonzero residual vector gives a nonzero polynomial of
//! degree at most [`FINGERPRINT_DEGREE`].
//!
//! # Computing the identity across a cycle
//!
//! Express the recurrence using weighted sums of the four lanes:
//!
//! ```text
//! q   = rho^4,
//! A_t = sum_g rho^g a[t,g],
//! B_t = sum_g rho^g b[t,g],
//! D_t = sum_g rho^g (2^32 k[t,g] - b[t,g]).
//! ```
//!
//! Start with `s = 0`. Each fused row applies `s <- q*(s + A_t + D_t) - A_t`; row 0 also adds
//! `rho^8 B_0`, and row 27 also adds `A_27`. Expanding these 28 steps gives
//! `sum_t q^(27-t) ((q-1) A_t + q D_t) + A_27 + rho^116 B_0`.
//! Here `rho^8 q^27 = rho^116`, and adding `A_27` restores its coefficient from `q-1` to `q`.
//! Taking `A_(-1) = 0` temporarily, the A terms telescope to
//! `sum_t q^(28-t) (A_t - A_(t-1))`. This accounts for all terms in `P` except the message words
//! and initial chaining value.
//!
//! The four footer rows subtract each message word once, with coefficient
//! `sum_{t,g: sigma(t,g)=j} rho^(4*(28-t)+g)`. The last footer also subtracts
//! `sum_g (rho^(112+g) h[g] + rho^(116+g) h[g+4])`, supplying the omitted initial-A term and
//! completing the initial-B residual. The value after the last footer is therefore `P(rho)`.
//!
//! The AIR enforces the recurrence across every row, including the last footer's edge to the
//! next cycle, and sets the register to zero at every cycle's first row. Hence each cycle must
//! satisfy `P(rho) = 0` independently, including the final cycle's wrap to the first trace row.
//!
//! # Error bound
//!
//! Fix a main witness with at least one nonzero residual vector before sampling `rho`. Acceptance
//! requires a root of that cycle's nonzero polynomial, so its probability is at most 119 times
//! the challenge's largest point probability. Choosing one bad cycle suffices: no cycle-count
//! multiplier is needed. For this fixed main trace, either the bus relation is false or a required
//! identity is nonzero. Acceptance is bounded by the corresponding error in each case, so the
//! joint bound is their maximum. The ordinary lookup budget covers this degree; sharing beta
//! does not require independence between the identity checks and LogUp.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{Algebra, ExtensionField, PrimeCharacteristicRing},
    utils::{Matrix, RowMajorMatrix},
};
use miden_stark::air::{LiftedAirBuilder, WindowAccess};

use super::{
    algebra::{footer_cv_word, footer_message_word, packed_fused_bytes},
    layout::*,
    schedule::fused_step_at,
    selectors::EidosCompressionSelectors,
};

/// Degree in the auxiliary challenge, independent of the AIR constraint degree.
pub(super) const FINGERPRINT_DEGREE: usize = INITIAL_B_EXPONENT + NUM_G - 1;

const INITIAL_A_EXPONENT: usize = NUM_G * FUSED_G_ROWS;
const INITIAL_B_EXPONENT: usize = INITIAL_A_EXPONENT + NUM_G;

struct Coefficients<E> {
    powers: [E; FINGERPRINT_DEGREE + 1],
    message_weights: [E; 16],
}

impl<E: PrimeCharacteristicRing> Coefficients<E> {
    fn new(rho: E) -> Self {
        let mut powers = core::array::from_fn(|_| E::ZERO);
        powers[0] = E::ONE;
        for i in 1..powers.len() {
            powers[i] = powers[i - 1].clone() * rho.clone();
        }
        let mut message_weights = core::array::from_fn(|_| E::ZERO);
        for t in 0..FUSED_G_ROWS {
            let step = fused_step_at(t).expect("fused row has a message schedule");
            for g in 0..NUM_G {
                message_weights[step.message_indices[g]] +=
                    powers[NUM_G * (FUSED_G_ROWS - t) + g].clone();
            }
        }
        Self { powers, message_weights }
    }
}

fn lane_sum<B, E>(lane: impl Fn(usize) -> B, coefficients: &Coefficients<E>) -> E
where
    B: PrimeCharacteristicRing,
    E: Algebra<B>,
{
    (0..NUM_G).map(|g| coefficients.powers[g].clone() * lane(g)).sum()
}

/// Returns `q*(acc + A_t + D_t)` and the `A_t` correction for the fused-row recurrence.
fn fused_update_terms<B, E>(
    at: impl Fn(usize) -> B,
    acc: E,
    coefficients: &Coefficients<E>,
) -> (E, E)
where
    B: PrimeCharacteristicRing,
    E: Algebra<B>,
{
    let a = lane_sum(|g| packed_fused_bytes(&at, G_AC_BYTE_SLOT_BASE_COL, g, 1), coefficients);
    let delta = lane_sum(
        |g| {
            B::from_u64(1 << 32) * at(g_k3_col(g))
                - packed_fused_bytes(&at, G_BD_ROT_SLOT_BASE_COL, g, 0)
        },
        coefficients,
    );
    let scaled = coefficients.powers[NUM_G].clone() * (acc + a.clone() + delta);
    (scaled, a)
}

fn next_accumulator<B, E>(
    at: impl Fn(usize) -> B,
    selectors: &EidosCompressionSelectors<B>,
    acc: E,
    coefficients: &Coefficients<E>,
) -> E
where
    B: PrimeCharacteristicRing,
    E: Algebra<B>,
{
    let powers = &coefficients.powers;
    let fused = selectors.is_ab() + selectors.is_cd();
    let (scaled, a) = fused_update_terms(&at, acc.clone(), coefficients);
    let fused_next = scaled - a.clone();
    let b = lane_sum(|g| packed_fused_bytes(&at, G_BD_ROT_SLOT_BASE_COL, g, 0), coefficients);
    let mut next = fused_next * fused + acc * selectors.is_footer();
    next += a * selectors.is_last_fused();
    next += powers[2 * NUM_G].clone() * b * selectors.is_first_fused();
    for g in 0..NUM_G {
        let weight: E = (0..FOOTER_ROWS)
            .map(|footer| {
                coefficients.message_weights[NUM_G * footer + g].clone()
                    * selectors.is_footer_row(footer)
            })
            .sum();
        next -= weight * footer_message_word(&at, g);
    }
    let mut initial_cv = E::ZERO;
    for g in 0..NUM_G {
        initial_cv += powers[INITIAL_A_EXPONENT + g].clone() * footer_cv_word(&at, g)
            + powers[INITIAL_B_EXPONENT + g].clone() * footer_cv_word(&at, g + NUM_G);
    }
    next -= initial_cv * selectors.is_footer_row(FOOTER_ROWS - 1);
    next
}

/// Enforces the accumulator's recurrence and per-cycle reset outside the LogUp prefix.
pub fn enforce_register_constraints<AB: LiftedAirBuilder<F = Felt>>(
    builder: &mut AB,
    aux_column: usize,
) {
    let main = builder.main();
    let local = main.current_slice();
    let aux = builder.permutation();
    let acc: AB::ExprEF = aux.current_slice()[aux_column].into();
    let acc_next: AB::ExprEF = aux.next_slice()[aux_column].into();
    let periodic: Vec<AB::Expr> = builder.periodic_values().iter().map(|&v| v.into()).collect();
    let selectors = EidosCompressionSelectors::new(&periodic, 0);
    let coefficients = Coefficients::new(builder.permutation_randomness()[1].into());
    builder.assert_zero_ext(
        acc_next
            - next_accumulator(|col| local[col].into(), &selectors, acc.clone(), &coefficients),
    );
    builder.assert_zero_ext(acc * selectors.is_first_fused());
}

/// Fills the auxiliary register at `aux_column`, preserving every other column.
///
/// `aux` must have the same height as `main`, and `aux_column` must be outside the LogUp prefix.
pub fn fill_aux_register<EF: ExtensionField<Felt>>(
    main: &RowMajorMatrix<Felt>,
    aux: &mut RowMajorMatrix<EF>,
    aux_column: usize,
    rho: EF,
) {
    assert_eq!(main.height(), aux.height());
    assert!(main.height().is_multiple_of(BLOCK_PERIOD));
    let width = aux.width;
    assert!(aux_column < width, "auxiliary register column is outside the trace");
    let coefficients = Coefficients::new(rho);
    use miden_crypto::parallel::*;
    // Each compression cycle starts at zero, so cycles can be built independently.
    aux.values
        .par_chunks_mut(BLOCK_PERIOD * width)
        .zip(main.values.par_chunks(BLOCK_PERIOD * main.width))
        .for_each(|(output, input)| {
            let mut acc = EF::ZERO;
            for (row, (out, values)) in
                output.chunks_exact_mut(width).zip(input.chunks_exact(main.width)).enumerate()
            {
                out[aux_column] = acc;
                let at = |col| values[col];
                if row < FUSED_G_ROWS {
                    let (scaled, a) = fused_update_terms(at, acc, &coefficients);
                    acc = scaled;
                    if row != FUSED_G_ROWS - 1 {
                        acc -= a;
                    }
                    if row == 0 {
                        let first_b = lane_sum(
                            |g| packed_fused_bytes(&at, G_BD_ROT_SLOT_BASE_COL, g, 0),
                            &coefficients,
                        );
                        acc += coefficients.powers[2 * NUM_G] * first_b;
                    }
                } else if row < BLOCK_PERIOD - 1 {
                    // The last footer's recurrence, including the initial CV, is checked by the
                    // AIR against zero at the next cycle's start; it needs no successor cell here.
                    let footer = row - FUSED_G_ROWS;
                    for g in 0..NUM_G {
                        acc -= coefficients.message_weights[NUM_G * footer + g]
                            * footer_message_word(at, g);
                    }
                }
            }
        });
}
