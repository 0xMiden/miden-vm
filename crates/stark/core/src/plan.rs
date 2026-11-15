//! Shared proof-height validation and quotient allocation before transcript work.

use alloc::vec::Vec;

use p3_field::TwoAdicField;
use thiserror::Error;

use crate::{
    air::native::{AirKernel, AnalysisError, QuotientAllocationError, resolve_quotient_chunks},
    domain::{DomainError, LiftedDomain},
    order::{ShapeError, TraceOrder},
};

/// Invalid runtime height, execution allocation, or degree capacity.
#[derive(Debug, Error)]
pub enum PlanError {
    #[error("AIR {air}: this proof engine requires a positive auxiliary width")]
    AuxiliaryFree { air: usize },
    #[error(transparent)]
    Shape(#[from] ShapeError),
    #[error("AIR {air}: {source}")]
    Allocation {
        air: usize,
        source: QuotientAllocationError,
    },
    #[error("AIR {air}: {source}")]
    Capacity { air: usize, source: AnalysisError },
    #[error(transparent)]
    Domain(#[from] DomainError),
}

/// Own numeric metadata only; descriptors remain in the independently owned statement kernels.
pub(crate) struct ExecutionPlan<F: TwoAdicField> {
    pub order: TraceOrder,
    /// Quotient allocations in proof order, retaining safe over-allocation.
    pub log_quotient_degrees: Vec<u8>,
    pub max_log_quotient_degree: u8,
    pub max_lde_domain: LiftedDomain<F>,
    pub domains: Vec<LiftedDomain<F>>,
}

impl<F: TwoAdicField> ExecutionPlan<F> {
    pub fn new<K: AirKernel<F = F>>(
        airs: &[K],
        log_heights: Vec<u8>,
        log_blowup: u8,
    ) -> Result<Self, PlanError> {
        let order = TraceOrder::from_log_heights(airs, log_heights)?;
        let mut log_degrees = Vec::with_capacity(airs.len());
        for (air, kernel) in airs.iter().enumerate() {
            if kernel.descriptor().spec().aux_width == 0 {
                return Err(PlanError::AuxiliaryFree { air });
            }
            let chunks = resolve_quotient_chunks(kernel)
                .map_err(|source| PlanError::Allocation { air, source })?;
            kernel
                .descriptor()
                .analysis()
                .degree_profile()
                .validate_capacity(1usize << order.log_heights()[air], chunks)
                .map_err(|source| PlanError::Capacity { air, source })?;
            log_degrees.push(chunks.ilog2() as u8);
        }
        let max_log_quotient_degree =
            *log_degrees.iter().max().expect("TraceOrder rejects empty AIR collections");
        if max_log_quotient_degree > log_blowup {
            return Err(DomainError::ConstraintDegreeTooHigh {
                log_quotient: max_log_quotient_degree,
                log_blowup,
            }
            .into());
        }
        let max_lde_domain = LiftedDomain::try_canonical(order.max_log_height(), log_blowup)?;
        let domains = order
            .log_heights_proof()
            .into_iter()
            .map(|height| max_lde_domain.try_sub_domain(height))
            .collect::<Result<Vec<_>, _>>()?;
        let log_quotient_degrees = order.to_proof_order(&log_degrees);
        Ok(Self {
            order,
            log_quotient_degrees,
            max_log_quotient_degree,
            max_lde_domain,
            domains,
        })
    }
}
