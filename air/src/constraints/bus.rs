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

use miden_crypto::stark::air::MidenAirBuilder;

/// Converts permutation challenges into `ExprEF` alphas for bus encoding.
#[inline]
#[allow(dead_code)]
pub(crate) fn alphas_from_challenges<AB, const N: usize>(
    challenges: &[AB::RandomVar],
) -> [AB::ExprEF; N]
where
    AB: MidenAirBuilder,
{
    core::array::from_fn(|i| challenges[i].into())
}

/// Encodes grand-product (multiset) and LogUp messages as `alpha + sum_i beta[i] * elem[i]`.
///
/// `alpha` and `beta` are derived from the permutation challenges as:
/// - `alpha = challenges[0]`
/// - `beta[i] = challenges[i + 1]`
pub(crate) struct MessageEncoder<AB, const N: usize>
where
    AB: MidenAirBuilder,
{
    alpha: AB::ExprEF,
    betas: [AB::ExprEF; N],
}

impl<AB, const N: usize> MessageEncoder<AB, N>
where
    AB: MidenAirBuilder,
{
    /// Builds a message encoder from the permutation challenges.
    #[inline]
    pub fn from_challenges(challenges: &[AB::RandomVar]) -> Self {
        let alpha = challenges[0].into();
        let betas = core::array::from_fn(|i| challenges[i + 1].into());
        Self { alpha, betas }
    }

    /// Encodes a message using the encoder's alpha and betas.
    #[inline]
    pub fn encode(&self, elems: [AB::Expr; N]) -> AB::ExprEF {
        let mut acc = self.alpha.clone();
        for (beta, elem) in self.betas.iter().zip(elems.into_iter()) {
            acc += beta.clone() * elem;
        }
        acc
    }
}
