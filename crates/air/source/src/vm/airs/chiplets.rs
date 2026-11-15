//! Authored Chiplets AIR constraints and lookup bindings.

use alloc::vec::Vec;
use core::borrow::Borrow;

use miden_core::{Felt, WORD_SIZE, field::ExtensionField};
use miden_stark::{
    air::{
        ReductionError, WindowAccess,
        native::migration::{LegacySink, SourceSnapshot},
    },
    lookup::{BoundaryBuilder, Challenges, ConstraintLookupBuilder},
};

use super::{MidenAir, MidenAirBuilder, boundary::ReduceBoundaryBuilder};
use crate::vm::{
    constraints::{self, columns::ChipletCols, lookup::chiplet_air::ChipletLookupBuilder},
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
};

// CHIPLETS AIR
// ================================================================================================

/// Chiplets trace AIR.
///
/// Enforces the chiplet selector hierarchy, chiplet transition constraints, and
/// chiplet-side LogUp buses.
#[derive(Copy, Clone, Debug, Default)]
pub struct ChipletsAir;

impl ChipletsAir {
    pub(super) fn width(self) -> usize {
        constraints::columns::NUM_CHIPLETS_COLS
    }

    pub(in crate::vm) fn periodic_columns(self) -> Vec<Vec<Felt>> {
        constraints::chiplets::columns::PeriodicCols::periodic_columns()
    }

    pub(super) fn aux_width(self) -> usize {
        constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE.len()
    }

    /// LogUp boundary correction for the chiplets trace.
    ///
    /// The boundary input slice contains the kernel-procedure digests; these statement values
    /// close the kernel-ROM bus.
    pub(super) fn boundary_correction<EF: ExtensionField<Felt>>(
        self,
        challenges: &Challenges<EF>,
        boundary_inputs: &[&[Felt]],
    ) -> Result<EF, ReductionError> {
        if boundary_inputs.len() != 1 {
            return Err(format!(
                "ChipletsAir expects 1 boundary input slice, got {}",
                boundary_inputs.len()
            )
            .into());
        }
        if !boundary_inputs[0].len().is_multiple_of(WORD_SIZE) {
            return Err(format!(
                "kernel digest felts length {} is not a multiple of {}",
                boundary_inputs[0].len(),
                WORD_SIZE
            )
            .into());
        }

        let mut reducer = ReduceBoundaryBuilder {
            challenges,
            var_len_public_inputs: boundary_inputs,
            sum: EF::ZERO,
            error: None,
        };
        constraints::lookup::miden_air::emit_chiplets_boundary(&mut reducer);
        reducer.finalize()
    }

    pub(super) fn eval<AB: MidenAirBuilder>(self, builder: &mut AB) {
        let snapshot = SourceSnapshot::new(builder, 0, self.aux_width());
        let frame = snapshot.frame();
        let local: &ChipletCols<AB::Expr> = frame.main.current.borrow();
        let next: &ChipletCols<AB::Expr> = frame.main.next.borrow();
        {
            let mut sink = LegacySink::new(builder);
            let selectors = constraints::chiplets::selectors::build_chiplet_selectors(
                &frame, &mut sink, local, next,
            );
            constraints::enforce_chiplets(&frame, &mut sink, local, next, &selectors);
        }

        let mut lb = ConstraintLookupBuilder::new(builder, &MidenAir::Chiplets);
        self.lookup_eval(&mut lb);
        lb.finish();
    }

    pub(super) fn lookup_column_shape(self) -> &'static [usize] {
        &constraints::lookup::chiplet_air::CHIPLET_COLUMN_SHAPE
    }

    pub(super) fn lookup_max_message_width(self) -> usize {
        MIDEN_MAX_MESSAGE_WIDTH
    }

    pub(super) fn lookup_num_bus_ids(self) -> usize {
        BusId::COUNT
    }

    pub(super) fn lookup_eval<LB: ChipletLookupBuilder>(self, builder: &mut LB) {
        let main = builder.main();
        let local: &ChipletCols<_> = main.current_slice().borrow();
        let next: &ChipletCols<_> = main.next_slice().borrow();

        constraints::lookup::chiplet_air::emit_chiplet_lookup_columns(builder, local, next);
    }

    pub(super) fn lookup_eval_boundary<B: BoundaryBuilder>(self, boundary: &mut B) {
        constraints::lookup::miden_air::emit_chiplets_boundary(boundary);
    }
}
