//! Bus shared definitions.
//!
//! This module provides shared indices for auxiliary (bus) constraints.
//! The bus columns live in the auxiliary trace and are ordered as follows:
//! - p1/p2/p3 (decoder)
//! - p1 (stack overflow, stack aux segment)
//! - b_range (range checker LogUp)
//! - b_hash_kernel (chiplets virtual table)
//! - b_chiplets (chiplets bus)
//! - v_wiring (ACE wiring LogUp)

/// Auxiliary trace column indices.
#[allow(dead_code)]
pub mod indices {
    /// Block stack table (decoder control flow)
    pub const P1_BLOCK_STACK: usize = 0;
    /// Block hash table (decoder digest tracking)
    pub const P2_BLOCK_HASH: usize = 1;
    /// Op group table (decoder operation batching)
    pub const P3_OP_GROUP: usize = 2;
    /// Stack overflow table (stack p1)
    pub const P1_STACK: usize = 3;
    /// Range checker bus
    pub const B_RANGE: usize = 4;
    /// Hash kernel bus: sibling table + ACE memory + log_precompile
    pub const B_HASH_KERNEL: usize = 5;
    /// Main chiplets bus
    pub const B_CHIPLETS: usize = 6;
    /// Wiring bus for ACE circuit connections
    pub const V_WIRING: usize = 7;
}

use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

/// Encodes multiset/LogUp contributions as **alpha + <beta, message>**
///
/// Structure:
/// - `alpha`: randomness base (alpha)
/// - `beta_powers`: powers of beta [beta^0, beta^1, beta^2, ..., beta^(N-1)]
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// This structure is shared with the processor's `Challenges<E>` for trace generation.
pub(crate) struct Challenges<AB, const N: usize>
where
    AB: MidenAirBuilder,
{
    alpha: AB::ExprEF,
    beta_powers: [AB::ExprEF; N],
}

impl<AB, const N: usize> Challenges<AB, N>
where
    AB: MidenAirBuilder,
{
    /// Builds `alpha` and `beta` powers from permutation challenges.
    #[inline]
    pub fn from_randomness(challenges: &[AB::RandomVar]) -> Self {
        assert!(challenges.len() >= 2, "need at least alpha and beta challenges");
        let alpha: AB::ExprEF = challenges[0].into();
        let beta: AB::ExprEF = challenges[1].into();
        let mut beta_powers = core::array::from_fn(|_| AB::ExprEF::ONE);
        for i in 1..N {
            beta_powers[i] = beta_powers[i - 1].clone() * beta.clone();
        }
        Self { alpha, beta_powers }
    }

    /// Encodes as **alpha + <beta, message>** with K consecutive elements.
    #[inline]
    pub fn encode_dense<const K: usize>(&self, elems: [AB::Expr; K]) -> AB::ExprEF {
        const { assert!(K <= N, "Message length exceeds beta_powers capacity") };
        let mut acc = self.alpha.clone();
        for (i, elem) in elems.iter().enumerate() {
            acc += self.beta_powers[i].clone() * elem.clone();
        }
        acc
    }

    /// Encodes as **alpha + <beta, message>** using a layout array and separate values.
    ///
    /// `layout[i]` gives the beta-power position for `values[i]`.
    #[inline]
    pub fn encode_sparse<const K: usize>(
        &self,
        layout: [usize; K],
        values: [AB::Expr; K],
    ) -> AB::ExprEF {
        let mut acc = self.alpha.clone();
        for i in 0..K {
            let idx = layout[i];
            debug_assert!(
                idx < self.beta_powers.len(),
                "encode_sparse index {} exceeds beta_powers length ({})",
                idx,
                self.beta_powers.len()
            );
            acc += self.beta_powers[idx].clone() * values[i].clone();
        }
        acc
    }
}
