//! Captured AIRs and the geometry shared by relation artifact generators.

use miden_constraint_compiler::ir::{CapturedConstraints, Graph, capture_native};
use miden_core::{Felt, field::QuadFelt};
use miden_stark::air::{self, ConstraintCounts, ConstraintDegrees};

use crate::{
    AceError, EXT_DEGREE, InputCounts, InputKey, InputLayout, MAX_ORDER_AIRS,
    compiler::{AceCircuit, AceConfig, LayoutKind},
};

fn invalid(message: impl Into<String>) -> AceError {
    AceError::InvalidInputLayout { message: message.into() }
}

/// An AIR captured once for both native evaluator and ACE generation.
#[derive(Debug)]
pub struct CapturedAir {
    pub(crate) graph: Graph,
    pub(crate) constraints: CapturedConstraints,
    /// Raw AIR widths; the quotient chunk count is derived from this AIR's degree.
    pub(crate) counts: InputCounts,
    pub(crate) degrees: ConstraintDegrees,
    pub(crate) periodic_columns: Vec<Vec<Felt>>,
    /// Minimum trace height imposed by periodic columns, or zero when absent.
    pub(crate) max_periodic_length: usize,
    descriptor: air::AirDescriptor<Felt>,
}

impl CapturedAir {
    /// Capture an authored native source once for the existing compiler and ACE pipeline.
    ///
    /// Metadata comes from the same validated descriptor as the captured equations. The raw
    /// degree diagnostics retain height-independent artifact geometry; setup must separately
    /// check the descriptor's actual-height capacity before execution. No fixed-table factory
    /// or witness construction is invoked, and no prover capability is required.
    pub fn new_native<A: air::LiftedAir<F = Felt>>(air: &A) -> Result<Self, AceError> {
        let (graph, constraints, descriptor) = capture_native(air)
            .map_err(|error| invalid(format!("native AIR capture failed: {error}")))?;
        let spec = descriptor.spec();
        if spec.num_challenges != 2 {
            return Err(invalid(format!(
                "AIR must declare exactly 2 randomness challenges (alpha, beta), got {}",
                spec.num_challenges,
            )));
        }
        let degrees = descriptor.analysis().raw_degrees();
        let counts = InputCounts {
            preprocessed_width: spec.preprocessed_width(),
            width: spec.main_width,
            aux_width: spec.aux_width,
            num_aux_boundary: spec.num_exports,
            num_public: spec.num_public_values,
            num_randomness: spec.num_challenges,
            num_quotient_chunks: quotient_chunks(degrees.max())?,
        };
        let periodic_columns = spec.periodic_columns.to_vec();
        let max_periodic_length = spec.max_periodic_length();
        Ok(Self {
            graph,
            constraints,
            counts,
            degrees,
            periodic_columns,
            max_periodic_length,
            descriptor,
        })
    }

    /// The checked descriptor owned by this canonical authored capture.
    pub fn descriptor(&self) -> &air::AirDescriptor<Felt> {
        &self.descriptor
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    pub fn constraints(&self) -> &CapturedConstraints {
        &self.constraints
    }

    pub fn degrees(&self) -> ConstraintDegrees {
        self.degrees
    }

    pub(crate) fn constraint_counts(&self) -> ConstraintCounts {
        self.descriptor.analysis().counts()
    }
}

fn quotient_chunks(degree: usize) -> Result<usize, AceError> {
    degree
        .saturating_sub(1)
        .max(1)
        .checked_next_power_of_two()
        .ok_or_else(|| invalid("quotient chunk count overflow"))
}

/// A segment of a concatenated committed row, measured in base-field coordinates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowSegment {
    pub offset: usize,
    pub width: usize,
    pub raw_width: usize,
}

/// Physical row segments and constraint metadata for one canonical AIR position.
#[derive(Clone, Debug)]
pub struct AirGeometry {
    /// Public values are concatenated in canonical AIR order without padding.
    pub public_offset: usize,
    pub num_public: usize,
    pub preprocessed: RowSegment,
    pub main: RowSegment,
    pub aux: RowSegment,
    /// Boundary offsets count extension-field values rather than base coordinates.
    pub aux_boundary_offset: usize,
    pub num_aux_boundary: usize,
    pub constraint_counts: ConstraintCounts,
    pub degrees: ConstraintDegrees,
    pub period: usize,
}

/// Geometry derived from the captured AIRs, shared by every generated artifact.
#[derive(Clone, Debug)]
pub struct RelationGeometry {
    pub airs: Vec<AirGeometry>,
    pub preprocessed_width: usize,
    pub main_width: usize,
    /// Committed auxiliary base-field coordinates, including alignment padding.
    pub aux_width: usize,
    pub num_aux_boundary: usize,
    pub num_public: usize,
    pub num_randomness: usize,
    pub num_constraints: usize,
    pub max_constraint_degree: usize,
    pub num_quotient_chunks: usize,
    /// Committed quotient base-field coordinates, including alignment padding.
    pub quotient_width: usize,
    pub shared_period: usize,
    pub trace_alignment: usize,
}

impl RelationGeometry {
    fn derive(
        airs: &[&CapturedAir],
        alignment: usize,
        chunks: Option<usize>,
    ) -> Result<Self, AceError> {
        let first = airs
            .first()
            .ok_or_else(|| invalid("multi-AIR composition requires a nonempty AIR set"))?;
        if alignment == 0 {
            return Err(invalid("trace width alignment must be nonzero"));
        }
        let mut result = Self {
            airs: Vec::with_capacity(airs.len()),
            preprocessed_width: 0,
            main_width: 0,
            aux_width: 0,
            num_aux_boundary: 0,
            num_public: 0,
            num_randomness: first.counts.num_randomness,
            num_constraints: 0,
            max_constraint_degree: 0,
            num_quotient_chunks: 0,
            quotient_width: 0,
            shared_period: 1,
            trace_alignment: alignment,
        };
        for air in airs {
            let counts = air.counts;
            if counts.num_randomness != 2 {
                return Err(invalid(
                    "AIR must declare exactly 2 randomness challenges (alpha, beta)",
                ));
            }
            let preprocessed =
                allocate(&mut result.preprocessed_width, counts.preprocessed_width, alignment)?;
            let main = allocate(&mut result.main_width, counts.width, alignment)?;
            let aux_coords = counts
                .aux_width
                .checked_mul(EXT_DEGREE)
                .ok_or_else(|| invalid("auxiliary coordinate width overflow"))?;
            let aux = allocate(&mut result.aux_width, aux_coords, alignment)?;
            if !aux.width.is_multiple_of(EXT_DEGREE) {
                return Err(invalid(
                    "aligned auxiliary width must be divisible by the extension degree",
                ));
            }
            let constraint_counts = air.constraint_counts();
            result.airs.push(AirGeometry {
                public_offset: result.num_public,
                num_public: counts.num_public,
                preprocessed,
                main,
                aux,
                aux_boundary_offset: result.num_aux_boundary,
                num_aux_boundary: counts.num_aux_boundary,
                constraint_counts,
                degrees: air.degrees,
                period: air.max_periodic_length.max(1),
            });
            result.num_public = result
                .num_public
                .checked_add(counts.num_public)
                .ok_or_else(|| invalid("public input count overflow"))?;
            result.num_aux_boundary = result
                .num_aux_boundary
                .checked_add(counts.num_aux_boundary)
                .ok_or_else(|| invalid("auxiliary boundary count overflow"))?;
            result.num_constraints = result
                .num_constraints
                .checked_add(constraint_counts.base)
                .and_then(|count| count.checked_add(constraint_counts.ext))
                .ok_or_else(|| invalid("constraint count overflow"))?;
            result.max_constraint_degree = result.max_constraint_degree.max(air.degrees.max());
            result.shared_period = result.shared_period.max(air.max_periodic_length);
        }
        result.num_quotient_chunks =
            chunks.unwrap_or(quotient_chunks(result.max_constraint_degree)?);
        if result.num_quotient_chunks == 0 {
            return Err(invalid("num_quotient_chunks must be > 0"));
        }
        let coords = result
            .num_quotient_chunks
            .checked_mul(EXT_DEGREE)
            .ok_or_else(|| invalid("quotient coordinate width overflow"))?;
        result.quotient_width = aligned(coords, alignment)?;
        Ok(result)
    }

    /// Raw committed row widths, in base coordinates and canonical AIR order.
    pub fn raw_widths(&self) -> Vec<(usize, usize, usize)> {
        self.airs
            .iter()
            .map(|air| (air.preprocessed.raw_width, air.main.raw_width, air.aux.raw_width))
            .collect()
    }

    pub fn committed_width(&self) -> usize {
        self.preprocessed_width + self.main_width + self.aux_width + self.quotient_width
    }

    /// Checks the shape supported by the MASM LogUp, OOD and DEEP stages against the
    /// circuit's READ layout. AIRs must be in the same canonical order in both descriptions.
    ///
    /// Each AIR contributes one normalized boundary value. Committed groups are padded to eight
    /// base felts; OOD openings occupy one extension slot per committed coordinate, in two dense
    /// rows followed by the boundary values. Statement encoding and height rules remain the
    /// relation adapter's responsibility.
    pub fn validate_masm_layout(&self, layout: &InputLayout) -> Result<(), AceError> {
        let n = self.airs.len();
        if !(2..=MAX_ORDER_AIRS).contains(&n) || self.trace_alignment != 8 {
            return Err(invalid(format!(
                "MASM staging requires 2..={MAX_ORDER_AIRS} AIRs and eight-felt trace alignment"
            )));
        }
        if self.airs.iter().any(|air| air.num_aux_boundary != 1) || self.num_aux_boundary != n {
            return Err(invalid("MASM LogUp staging requires one boundary value per AIR"));
        }
        for (name, derived, actual) in [
            ("preprocessed", self.preprocessed_width, layout.counts.preprocessed_width),
            ("main", self.main_width, layout.counts.width),
            ("auxiliary-coordinate", self.aux_width / EXT_DEGREE, layout.counts.aux_width),
            ("auxiliary-boundary", self.num_aux_boundary, layout.counts.num_aux_boundary),
            ("public-input", self.num_public, layout.counts.num_public),
            ("lookup-challenge", self.num_randomness, layout.counts.num_randomness),
            ("quotient-chunk", self.num_quotient_chunks, layout.counts.num_quotient_chunks),
            ("quotient-coordinate", self.quotient_width, layout.quotient_width()),
        ] {
            if derived != actual {
                return Err(invalid(format!(
                    "AIR-derived {name} width {derived} disagrees with ACE input layout width {actual}"
                )));
            }
        }
        for (name, total, widths) in [
            (
                "preprocessed",
                self.preprocessed_width,
                self.airs.iter().map(|air| air.preprocessed.width).collect::<Vec<_>>(),
            ),
            ("main", self.main_width, self.airs.iter().map(|air| air.main.width).collect()),
            (
                "auxiliary-coordinate",
                self.aux_width,
                self.airs.iter().map(|air| air.aux.width).collect(),
            ),
        ] {
            if total == 0
                || widths.iter().any(|width| !width.is_multiple_of(8))
                || widths.iter().try_fold(0usize, |sum, width| sum.checked_add(*width))
                    != Some(total)
            {
                return Err(invalid(format!(
                    "MASM {name} group has inconsistent or unaligned AIR widths"
                )));
            }
        }
        if self.quotient_width == 0 || !self.quotient_width.is_multiple_of(8) {
            return Err(invalid("MASM quotient group must be nonempty and eight-felt aligned"));
        }
        let index = |key| {
            layout
                .index(key)
                .ok_or_else(|| invalid(format!("ACE input layout is missing {key:?}")))
        };
        let mut cursor = index(InputKey::Preprocessed { offset: 0, index: 0 })?;
        for offset in 0..2 {
            for (key, width) in [
                (InputKey::Preprocessed { offset, index: 0 }, self.preprocessed_width),
                (InputKey::Main { offset, index: 0 }, self.main_width),
                (InputKey::AuxCoord { offset, index: 0, coord: 0 }, self.aux_width),
                (InputKey::QuotientChunkCoord { offset, chunk: 0, coord: 0 }, self.quotient_width),
            ] {
                if index(key)? != cursor {
                    return Err(invalid(format!(
                        "ACE OOD group {key:?} does not follow the committed widths"
                    )));
                }
                cursor = cursor
                    .checked_add(width)
                    .ok_or_else(|| invalid("ACE OOD frame extent overflows"))?;
            }
        }
        if index(InputKey::AuxBusBoundary(0))? != cursor {
            return Err(invalid("ACE boundary values must follow the two OOD rows"));
        }
        let last_fold = index(InputKey::MultiAirFoldCoeff(n - 1))?;
        if last_fold >= layout.total_inputs {
            return Err(invalid("ACE fold coefficients fall outside the READ section"));
        }
        Ok(())
    }

    pub(crate) fn input_counts(&self) -> InputCounts {
        InputCounts {
            preprocessed_width: self.preprocessed_width,
            width: self.main_width,
            aux_width: self.aux_width / EXT_DEGREE,
            num_aux_boundary: self.num_aux_boundary,
            num_public: self.num_public,
            num_randomness: self.num_randomness,
            num_quotient_chunks: self.num_quotient_chunks,
        }
    }
}

fn aligned(width: usize, alignment: usize) -> Result<usize, AceError> {
    width
        .checked_next_multiple_of(alignment)
        .ok_or_else(|| invalid("aligned row width overflow"))
}

fn allocate(total: &mut usize, raw_width: usize, alignment: usize) -> Result<RowSegment, AceError> {
    let width = aligned(raw_width, alignment)?;
    let segment = RowSegment { offset: *total, width, raw_width };
    *total = total
        .checked_add(width)
        .ok_or_else(|| invalid("committed row width overflow"))?;
    Ok(segment)
}

/// A relation borrowing captured AIRs in canonical order.
#[derive(Debug)]
pub struct CompiledRelation<'a> {
    pub(crate) airs: Vec<&'a CapturedAir>,
    pub(crate) geometry: RelationGeometry,
}

impl<'a> CompiledRelation<'a> {
    pub fn from_captured(
        airs: &[&'a CapturedAir],
        trace_alignment: usize,
    ) -> Result<Self, AceError> {
        Self::with_quotient_chunks(airs, trace_alignment, None)
    }

    /// Derive artifact geometry with a caller-selected quotient allocation.
    ///
    /// `None` uses the existing raw-degree-derived allocation. `Some` preserves the caller's
    /// configuration, including a larger allocation. Setup must separately check actual-height
    /// descriptor capacity; artifact geometry does not establish that proof-engine requirement.
    pub fn with_quotient_chunks(
        airs: &[&'a CapturedAir],
        trace_alignment: usize,
        chunks: Option<usize>,
    ) -> Result<Self, AceError> {
        Ok(Self {
            geometry: RelationGeometry::derive(airs, trace_alignment, chunks)?,
            airs: airs.to_vec(),
        })
    }

    #[cfg(test)]
    pub(crate) fn airs(&self) -> &[&'a CapturedAir] {
        &self.airs
    }

    pub fn geometry(&self) -> &RelationGeometry {
        &self.geometry
    }

    pub fn build_circuit(&self, layout: LayoutKind) -> Result<AceCircuit<QuadFelt>, AceError> {
        crate::compiler::pipeline::build_circuit_for_relation(
            self,
            AceConfig {
                num_quotient_chunks: self.geometry.num_quotient_chunks,
                layout,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        borrow::Cow,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use air::LiftedAirBuilder as _;
    use miden_core::utils::RowMajorMatrix;
    use miden_crypto::field::PrimeCharacteristicRing;
    use p3_field::Dup;

    use super::*;

    struct PairedAir {
        main_width: usize,
        challenges: usize,
        offset: Felt,
        periodic: Vec<Vec<Felt>>,
        spec_reads: AtomicUsize,
        evaluations: AtomicUsize,
        fixed_builds: AtomicUsize,
    }

    impl PairedAir {
        fn new(challenges: usize, period: usize, offset: u32) -> Self {
            Self {
                main_width: 2,
                challenges,
                offset: Felt::from_u32(offset),
                periodic: vec![vec![Felt::ONE, Felt::TWO], vec![Felt::from_u32(offset); period]],
                spec_reads: AtomicUsize::new(0),
                evaluations: AtomicUsize::new(0),
                fixed_builds: AtomicUsize::new(0),
            }
        }
    }

    impl air::LiftedAir for PairedAir {
        type F = Felt;

        fn spec(&self) -> air::AirSpec<'_, Felt> {
            self.spec_reads.fetch_add(1, Ordering::Relaxed);
            air::AirSpec {
                main_width: self.main_width,
                aux_width: 2,
                num_public_values: 2,
                num_challenges: self.challenges,
                num_exports: 1,
                preprocessed: Some(air::PreprocessedSpec { width: 1, log_height: 3 }),
                periodic_columns: Cow::Borrowed(&self.periodic),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<RowMajorMatrix<Felt>> {
            self.fixed_builds.fetch_add(1, Ordering::Relaxed);
            Some(RowMajorMatrix::new(vec![Felt::ONE; 8], 1))
        }

        fn eval<B: air::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &air::Frame<'_, B>,
            inputs: air::Inputs<'_, B>,
            sink: &mut B,
        ) {
            self.evaluations.fetch_add(1, Ordering::Relaxed);
            let alpha = if self.challenges > 0 {
                inputs.challenge(0)
            } else {
                B::ExtExpr::ZERO
            };
            let beta = if self.challenges > 1 {
                inputs.challenge(1)
            } else {
                B::ExtExpr::ZERO
            };
            sink.when(frame.first_row()).assert_zero(
                frame.main.current[0].dup()
                    + frame.preprocessed.current[0].dup()
                    + inputs.public(0)
                    - self.offset,
            );
            sink.assert_zero_ext(frame.aux.current[0].dup() + alpha + inputs.export(0));
            sink.when(frame.transition()).assert_zero(
                frame.main.next[1].dup() - frame.main.current[1].dup().square()
                    + frame.preprocessed.next[0].dup()
                    + frame.periodic[0].dup(),
            );
            sink.when(frame.last_row()).assert_zero_ext(
                frame.aux.next[1].dup()
                    + beta * inputs.public(1)
                    + B::ExtExpr::from(frame.periodic[1].dup()),
            );
            // Both classes retain their zero-gated emissions at the original global positions.
            sink.when(B::Expr::ZERO).assert_zero(frame.main.current[0].dup());
            sink.when(B::Expr::ZERO).assert_zero_ext(frame.aux.current[0].dup());
        }
    }

    fn counts(air: &CapturedAir) -> [usize; 7] {
        let counts = air.counts;
        [
            counts.preprocessed_width,
            counts.width,
            counts.aux_width,
            counts.num_aux_boundary,
            counts.num_public,
            counts.num_randomness,
            counts.num_quotient_chunks,
        ]
    }

    #[test]
    fn native_capture_owns_checked_metadata_without_building_fixed_data() {
        let source = PairedAir::new(2, 4, 3);
        let captured = CapturedAir::new_native(&source).unwrap();
        assert_eq!(source.evaluations.load(Ordering::Relaxed), 1);
        assert_eq!(source.spec_reads.load(Ordering::Relaxed), 1);
        assert_eq!(source.fixed_builds.load(Ordering::Relaxed), 0);
        assert_eq!(captured.descriptor().analysis().layout().base_indices(), &[0, 2, 4]);
        assert_eq!(captured.descriptor().analysis().layout().ext_indices(), &[1, 3, 5]);
        assert_eq!(captured.constraint_counts(), ConstraintCounts { base: 3, ext: 3 });
        assert_eq!(counts(&captured), [1, 2, 2, 1, 2, 2, 1]);
        drop(source);
        assert_eq!(captured.descriptor().spec().periodic_columns[1].len(), 4);
    }

    #[test]
    fn native_constructor_keeps_ace_challenge_policy_and_checked_schema() {
        for challenges in [0, 1, 3] {
            let source = PairedAir::new(challenges, 4, 3);
            assert!(
                matches!(CapturedAir::new_native(&source), Err(AceError::InvalidInputLayout { message }) if message.contains("exactly 2 randomness challenges"))
            );
            assert_eq!(source.spec_reads.load(Ordering::Relaxed), 1);
            assert_eq!(source.evaluations.load(Ordering::Relaxed), 1);
            assert_eq!(source.fixed_builds.load(Ordering::Relaxed), 0);
        }
        let source = PairedAir { main_width: 0, ..PairedAir::new(2, 4, 3) };
        assert!(
            matches!(CapturedAir::new_native(&source), Err(AceError::InvalidInputLayout { message }) if message.contains("at least one main column"))
        );
        assert_eq!(source.spec_reads.load(Ordering::Relaxed), 1);
        assert_eq!(source.evaluations.load(Ordering::Relaxed), 0);
        assert_eq!(source.fixed_builds.load(Ordering::Relaxed), 0);
    }
}
