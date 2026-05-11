//! PCS parameters.

use thiserror::Error;

use crate::pcs::{
    deep::DeepParams,
    fri::{FriParams, fold::FriFold},
};

/// Errors from invalid PCS parameter combinations.
#[derive(Clone, Debug, Error)]
pub enum PcsParamsError {
    #[error("invalid folding arity: log_arity {0} (must be 1, 2, or 3)")]
    InvalidFoldingArity(u8),
    #[error("log_blowup must be > 0")]
    ZeroBlowup,
    #[error("num_queries must be > 0")]
    ZeroQueries,
}

/// Complete PCS parameters combining DEEP and FRI parameters.
///
/// Constructed via [`PcsParams::new`], which validates all parameters.
/// Internal sub-parameters are accessible to crate-internal code only.
#[derive(Clone, Copy, Debug)]
pub struct PcsParams {
    /// Log₂ of the LDE blowup factor (LDE domain size / trace size).
    ///
    /// Higher values increase soundness per query but also proof size and prover time
    /// (LDE over a larger domain). Typical values: 2-4 (blowup factors of 4-16).
    pub(crate) log_blowup: u8,
    /// DEEP quotient parameters.
    pub(crate) deep: DeepParams,
    /// FRI protocol parameters.
    pub(crate) fri: FriParams,
    /// Number of query repetitions.
    pub(crate) num_queries: usize,
    /// Grinding bits before query index sampling.
    pub(crate) query_pow_bits: usize,
}

impl PcsParams {
    /// Create validated PCS parameters.
    ///
    /// # Errors
    ///
    /// - [`PcsParamsError::InvalidFoldingArity`] if `log_folding_arity` is not 1, 2, or 3.
    /// - [`PcsParamsError::ZeroBlowup`] if `log_blowup` is 0.
    /// - [`PcsParamsError::ZeroQueries`] if `num_queries` is 0.
    ///
    /// Field-relative bound checking (`log_final_degree + log_blowup ≤ F::TWO_ADICITY`)
    /// is deferred to [`crate::domain::TwoAdicSubgroup::new`] at the point a
    /// concrete domain is constructed; `PcsParams` itself is field-agnostic.
    pub fn new(
        log_blowup: u8,
        log_folding_arity: u8,
        log_final_degree: u8,
        folding_pow_bits: usize,
        deep_pow_bits: usize,
        num_queries: usize,
        query_pow_bits: usize,
    ) -> Result<Self, PcsParamsError> {
        let fold = FriFold::new(log_folding_arity)
            .ok_or(PcsParamsError::InvalidFoldingArity(log_folding_arity))?;
        if log_blowup == 0 {
            return Err(PcsParamsError::ZeroBlowup);
        }
        if num_queries == 0 {
            return Err(PcsParamsError::ZeroQueries);
        }
        Ok(Self {
            log_blowup,
            deep: DeepParams { deep_pow_bits },
            fri: FriParams { fold, log_final_degree, folding_pow_bits },
            num_queries,
            query_pow_bits,
        })
    }

    /// Log₂ of the blowup factor.
    #[inline]
    pub fn log_blowup(&self) -> u8 {
        self.log_blowup
    }

    /// Number of query repetitions.
    #[inline]
    pub fn num_queries(&self) -> usize {
        self.num_queries
    }

    /// Grinding bits before query index sampling.
    #[inline]
    pub fn query_pow_bits(&self) -> usize {
        self.query_pow_bits
    }

    /// Grinding bits before DEEP challenge sampling.
    #[inline]
    pub fn deep_pow_bits(&self) -> usize {
        self.deep.deep_pow_bits
    }

    /// Grinding bits before each FRI folding round.
    #[inline]
    pub fn folding_pow_bits(&self) -> usize {
        self.fri.folding_pow_bits
    }

    /// Log₂ of the FRI folding arity.
    #[inline]
    pub fn log_folding_arity(&self) -> u8 {
        self.fri.fold.log_arity()
    }

    /// Log₂ of the final polynomial degree bound.
    #[inline]
    pub fn log_final_degree(&self) -> u8 {
        self.fri.log_final_degree
    }
}
