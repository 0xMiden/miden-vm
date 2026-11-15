//! Common committed-row geometry and independent symbolic security-shape validation.
use miden_ace::EXT_DEGREE;
#[cfg(any(test, feature = "compiler"))]
use miden_core::{Felt, field::QuadFelt};
#[cfg(any(test, feature = "compiler"))]
use miden_stark::air::native;
#[cfg(any(test, feature = "compiler"))]
use miden_stark::security::{AirShape, LookupShape};

/// Source-derived artifact geometry, preserving the conservative quotient allocation policy.
///
/// Each source is captured once. This does not invoke fixed factories or use the tighter
/// actual-height degree bound, which proof setup must check separately against its allocation.
#[cfg(any(test, feature = "compiler"))]
pub(crate) fn derive_air_shape<A: native::LiftedAir<F = Felt>>(
    airs: &[A],
    lookup: LookupShape,
    alignment: usize,
) -> Result<AirShape, native::DescriptorError> {
    let mut constraints = 0;
    let mut degree = 0;
    let mut raw_widths = alloc::vec::Vec::with_capacity(airs.len());
    for air in airs {
        let captured = native::capture_with::<_, QuadFelt>(air)?;
        let spec = captured.descriptor.spec();
        let analysis = captured.descriptor.analysis();
        constraints += analysis.layout().total_constraints();
        degree = degree.max(analysis.raw_degrees().max());
        raw_widths.push((spec.preprocessed_width(), spec.main_width, EXT_DEGREE * spec.aux_width));
    }
    Ok(shape_from_parts(constraints, degree, &raw_widths, lookup, alignment))
}

#[cfg(any(test, feature = "compiler"))]
fn shape_from_parts(
    constraints: usize,
    degree: usize,
    raw_widths: &[(usize, usize, usize)],
    lookup: LookupShape,
    alignment: usize,
) -> AirShape {
    // Canonical source lists and LMCS configuration establish these tooling invariants.
    assert!(!raw_widths.is_empty(), "security geometry requires at least one AIR");
    assert!(alignment > 0, "security geometry requires positive alignment");
    let chunks = degree.saturating_sub(1).max(1).next_power_of_two();
    AirShape {
        num_composed_constraints: (constraints + raw_widths.len() - 1) as u32,
        max_constraint_degree: degree as u32,
        num_quotient_chunks: chunks as u32,
        max_combo: NUM_OOD_POINTS,
        num_deep_terms: Some(num_deep_terms_for_widths(raw_widths, chunks, alignment)),
        lookup: Some(lookup),
    }
}

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
pub const NUM_OOD_POINTS: u32 = 2;

/// Number of DEEP terms for raw committed widths emitted by the relation compiler.
/// Widths are base-field coordinates; each matrix is padded independently.
pub fn num_deep_terms_for_widths(
    raw_widths: &[(usize, usize, usize)],
    chunks: usize,
    alignment: usize,
) -> u32 {
    let columns: usize = raw_widths
        .iter()
        .map(|&(preprocessed, main, aux)| {
            preprocessed.next_multiple_of(alignment)
                + main.next_multiple_of(alignment)
                + aux.next_multiple_of(alignment)
        })
        .sum();
    (columns + (chunks * EXT_DEGREE).next_multiple_of(alignment)) as u32 + NUM_OOD_POINTS
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use p3_field::Dup;

    use super::*;

    #[derive(Default)]
    struct CountingSource {
        spec_reads: AtomicUsize,
        evaluations: AtomicUsize,
    }

    impl native::LiftedAir for CountingSource {
        type F = Felt;

        fn spec(&self) -> native::AirSpec<'_, Felt> {
            self.spec_reads.fetch_add(1, Ordering::Relaxed);
            native::AirSpec {
                main_width: 1,
                aux_width: 1,
                num_public_values: 0,
                num_challenges: 1,
                num_exports: 0,
                preprocessed: Some(native::PreprocessedSpec { width: 1, log_height: 1 }),
                periodic_columns: Cow::Borrowed(&[]),
            }
        }

        fn build_preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<Felt>> {
            panic!("security geometry must not materialize fixed data");
        }

        fn eval<B: native::LiftedAirBuilder<F = Felt>>(
            &self,
            frame: &native::Frame<'_, B>,
            inputs: native::Inputs<'_, B>,
            sink: &mut B,
        ) {
            self.evaluations.fetch_add(1, Ordering::Relaxed);
            sink.assert_zero(frame.main.current[0].dup() * frame.main.current[0].dup());
            sink.assert_zero_ext(frame.aux.current[0].dup() - inputs.challenge(0));
        }
    }

    #[test]
    fn native_geometry_captures_once_and_pads_each_matrix_independently() {
        let sources = [CountingSource::default(), CountingSource::default()];
        let shape = derive_air_shape(
            &sources,
            LookupShape {
                fractions_per_row: 2,
                max_message_width: 1,
            },
            4,
        )
        .unwrap();
        assert_eq!(shape.num_composed_constraints, 5);
        assert_eq!(shape.max_constraint_degree, 2);
        assert_eq!(shape.num_quotient_chunks, 1);
        assert_eq!(shape.max_combo, 2);
        // Two AIRs each contribute pad(1)+pad(1)+pad(2)=12 coordinates; quotient=4, OOD=2.
        assert_eq!(shape.num_deep_terms, Some(30));
        for source in &sources {
            assert_eq!(source.spec_reads.load(Ordering::Relaxed), 1);
            assert_eq!(source.evaluations.load(Ordering::Relaxed), 1);
        }
    }
}
