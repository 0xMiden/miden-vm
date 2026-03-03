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

/// Message-layout helper for sparse encodings.
///
/// `idx` holds the positions in the full message vector which are present in the sparse message.
pub(crate) struct MessageLayout<const K: usize> {
    idx: [usize; K],
}

impl<const K: usize> MessageLayout<K> {
    pub const fn new(idx: [usize; K]) -> Self {
        Self { idx }
    }
}

/// Encodes multiset/LogUp messages as `alpha + sum_i beta^i * elem[i]`.
///
/// `alpha` and `beta` are derived from the permutation challenges:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
pub(crate) struct Challenges<AB, const N: usize>
where
    AB: MidenAirBuilder,
{
    alpha: AB::ExprEF,
    beta_pows: [AB::ExprEF; N],
}

impl<AB, const N: usize> Challenges<AB, N>
where
    AB: MidenAirBuilder,
{
    /// Builds `alpha` and `beta` powers from permutation challenges.
    #[inline]
    pub fn from_randomness(challenges: &[AB::RandomVar]) -> Self {
        debug_assert!(challenges.len() >= 2);
        let alpha: AB::ExprEF = challenges[0].into();
        let beta: AB::ExprEF = challenges[1].into();
        let mut beta_pows = core::array::from_fn(|_| AB::ExprEF::ONE);
        for i in 1..N {
            beta_pows[i] = beta_pows[i - 1].clone() * beta.clone();
        }
        Self { alpha, beta_pows }
    }

    /// Encodes a dense message where elements occupy the first K positions.
    #[inline]
    pub fn encode_dense<const K: usize>(&self, elems: [AB::Expr; K]) -> AB::ExprEF {
        debug_assert!(K <= N);
        let mut acc = self.alpha.clone();
        for (i, elem) in elems.iter().enumerate() {
            acc += self.beta_pows[i].clone() * elem.clone();
        }
        acc
    }

    /// Encodes a sparse message defined by a layout of indices into the full message vector.
    #[inline]
    pub fn encode_layout<const K: usize>(
        &self,
        layout: &MessageLayout<K>,
        elems: [AB::Expr; K],
    ) -> AB::ExprEF {
        let mut acc = self.alpha.clone();
        for (i, elem) in elems.iter().enumerate() {
            let idx = layout.idx[i];
            acc += self.beta_pows[idx].clone() * elem.clone();
        }
        acc
    }
}
