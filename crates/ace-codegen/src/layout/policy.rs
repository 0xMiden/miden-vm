use core::num::NonZeroUsize;

use super::{
    InputCounts, InputLayout, InputRegion, LayoutRegions, MultiAirIndices, SELECTORS_PER_AIR,
    StarkVarIndices,
};
use crate::{EXT_DEGREE, randomness};

#[derive(Clone, Copy)]
enum Alignment {
    Unaligned = 1,
    Word = 2,
    DoubleWord = 4,
    QuadWord = 8,
}

#[derive(Clone, Copy)]
struct LayoutPolicy {
    public_values: Alignment,
    randomness: Alignment,
    preprocessed: Alignment,
    main: Alignment,
    aux: Alignment,
    quotient: Alignment,
    aux_bus_boundary: Alignment,
    stark_vars: Alignment,
    end_align: Option<Alignment>,
}

/// Selects single-AIR inputs or per-AIR selectors and fold coefficients.
#[derive(Clone, Copy)]
enum AirComposition {
    Single,
    Multi { air_count: NonZeroUsize },
}

impl AirComposition {
    fn multi_air(air_count: usize) -> Self {
        let air_count =
            NonZeroUsize::new(air_count).expect("multi-AIR layout requires at least one AIR");
        Self::Multi { air_count }
    }

    fn extra_stark_slots(self) -> usize {
        match self {
            Self::Single => 0,
            Self::Multi { air_count } => air_count.get() * (SELECTORS_PER_AIR + 1),
        }
    }

    fn multi_air_indices(self, stark_start: usize, base_slots: usize) -> Option<MultiAirIndices> {
        match self {
            Self::Single => None,
            Self::Multi { air_count } => {
                let selector_start = stark_start + base_slots;
                Some(MultiAirIndices {
                    air_count,
                    selector_start,
                    fold_coeff_start: selector_start + air_count.get() * SELECTORS_PER_AIR,
                })
            },
        }
    }
}

impl LayoutPolicy {
    fn native() -> Self {
        Self {
            public_values: Alignment::Unaligned,
            randomness: Alignment::Unaligned,
            preprocessed: Alignment::Unaligned,
            main: Alignment::Unaligned,
            aux: Alignment::Unaligned,
            quotient: Alignment::Unaligned,
            aux_bus_boundary: Alignment::Unaligned,
            stark_vars: Alignment::Unaligned,
            end_align: None,
        }
    }

    fn masm() -> Self {
        Self {
            public_values: Alignment::QuadWord,
            randomness: Alignment::Word,
            preprocessed: Alignment::DoubleWord,
            main: Alignment::DoubleWord,
            aux: Alignment::DoubleWord,
            quotient: Alignment::DoubleWord,
            aux_bus_boundary: Alignment::Word,
            stark_vars: Alignment::Word,
            end_align: Some(Alignment::DoubleWord),
        }
    }
}

struct LayoutBuilder {
    offset: usize,
}

impl LayoutBuilder {
    fn new() -> Self {
        Self { offset: 0 }
    }

    fn align(&mut self, alignment: Alignment) {
        self.offset = self.offset.next_multiple_of(alignment as usize);
    }

    fn alloc(&mut self, width: usize, alignment: Alignment) -> InputRegion {
        self.align(alignment);
        let region = InputRegion { offset: self.offset, width };
        self.offset += width;
        region
    }
}

impl InputLayout {
    /// Build a native layout with no alignment padding.
    pub fn new(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native(), AirComposition::Single)
    }

    /// Build the MASM-compatible layout.
    pub fn new_masm(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm(), AirComposition::Single)
    }

    /// Build a native layout for a multi-AIR relation.
    pub fn new_multi_air(counts: InputCounts, num_airs: usize) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native(), AirComposition::multi_air(num_airs))
    }

    /// Build the MASM-compatible layout for a multi-AIR relation.
    pub fn new_masm_multi_air(counts: InputCounts, num_airs: usize) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm(), AirComposition::multi_air(num_airs))
    }

    fn build_with_policy(
        counts: InputCounts,
        policy: LayoutPolicy,
        composition: AirComposition,
    ) -> Self {
        const NUM_RANDOMNESS_INPUTS: usize = 2;
        assert_eq!(
            counts.num_randomness, NUM_RANDOMNESS_INPUTS,
            "ACE layouts require exactly alpha and beta randomness inputs"
        );

        // Every ACE input slot is an extension-field element. Slots 7-9 carry base-field values
        // embedded as `(value, 0)`.
        const NUM_STARK_VARS_BASE: usize = 10;
        let num_stark_vars = NUM_STARK_VARS_BASE + composition.extra_stark_slots();

        let mut builder = LayoutBuilder::new();

        let public_values = builder.alloc(counts.num_public, policy.public_values);
        let randomness = builder.alloc(NUM_RANDOMNESS_INPUTS, policy.randomness);
        let (aux_rand_alpha, aux_rand_beta) = randomness::aux_rand_indices(randomness);
        let preprocessed_curr = builder.alloc(counts.preprocessed_width, policy.preprocessed);
        let main_curr = builder.alloc(counts.width, policy.main);
        let aux_coord_width = counts.aux_width * EXT_DEGREE;
        let aux_curr = builder.alloc(aux_coord_width, policy.aux);
        let quotient_curr = builder.alloc(counts.num_quotient_chunks * EXT_DEGREE, policy.quotient);
        let preprocessed_next = builder.alloc(counts.preprocessed_width, policy.preprocessed);
        let main_next = builder.alloc(counts.width, policy.main);
        let aux_next = builder.alloc(aux_coord_width, policy.aux);
        let quotient_next = builder.alloc(counts.num_quotient_chunks * EXT_DEGREE, policy.quotient);
        let aux_bus_boundary = builder.alloc(counts.num_aux_boundary, policy.aux_bus_boundary);
        let stark_vars = builder.alloc(num_stark_vars, policy.stark_vars);

        let b = stark_vars.offset;
        let alpha = b;
        let z_pow_n = b + 1;
        let z_k = b + 2;
        let is_first = b + 3;
        let is_last = b + 4;
        let is_transition = b + 5;
        let reserved = b + 6;
        let weight0 = b + 7;
        let f = b + 8;
        let s0 = b + 9;
        let multi_air = composition.multi_air_indices(b, NUM_STARK_VARS_BASE);

        if let Some(end_align) = policy.end_align {
            builder.align(end_align);
        }

        Self {
            regions: LayoutRegions {
                public_values,
                randomness,
                preprocessed_curr,
                main_curr,
                aux_curr,
                quotient_curr,
                preprocessed_next,
                main_next,
                aux_next,
                quotient_next,
                aux_bus_boundary,
                stark_vars,
            },
            aux_rand_alpha,
            aux_rand_beta,
            stark: StarkVarIndices {
                alpha,
                z_pow_n,
                z_k,
                is_first,
                is_last,
                is_transition,
                reserved,
                weight0,
                f,
                s0,
                multi_air,
            },
            total_inputs: builder.offset,
            counts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{InputCounts, InputKey, InputLayout};

    fn test_counts() -> InputCounts {
        InputCounts {
            preprocessed_width: 0,
            width: 1,
            aux_width: 1,
            num_aux_boundary: 3,
            num_public: 8,
            num_randomness: 2,
            num_quotient_chunks: 1,
        }
    }

    #[test]
    fn multi_air_layout_indexes_air_slots() {
        let layout = InputLayout::new_masm_multi_air(test_counts(), 3);

        let first0 = layout.index(InputKey::IsFirstAir(0)).unwrap();
        assert_eq!(first0, layout.regions.stark_vars.offset + 10);
        assert_eq!(layout.index(InputKey::IsLastAir(0)), Some(first0 + 1));
        assert_eq!(layout.index(InputKey::IsTransitionAir(0)), Some(first0 + 2));
        assert_eq!(layout.index(InputKey::IsFirstAir(1)), Some(first0 + 3));
        assert_eq!(layout.index(InputKey::IsFirstAir(2)), Some(first0 + 6));
        assert_eq!(layout.index(InputKey::IsFirstAir(3)), None);
    }

    #[test]
    #[should_panic(expected = "multi-AIR layout requires at least one AIR")]
    fn multi_air_layout_rejects_zero_airs() {
        let _ = InputLayout::new_masm_multi_air(test_counts(), 0);
    }

    #[test]
    fn canonical_multi_air_layout_adds_fold_coefficient_slots_after_selectors() {
        let layout = InputLayout::new_masm_multi_air(test_counts(), 3);

        // One `adv_pipe` block carries four extension-field slots (eight base-field felts).
        assert!(layout.total_inputs.is_multiple_of(4));

        let first_selector = layout.index(InputKey::IsFirstAir(0)).unwrap();
        assert_eq!(first_selector, layout.regions.stark_vars.offset + 10);

        // Selectors occupy 3 AIRs * 3 selectors = 9 EF slots after the prologue.
        let last_selector = layout.index(InputKey::IsTransitionAir(2)).unwrap();
        assert_eq!(last_selector, first_selector + 8);

        // Each fold coefficient occupies one EF slot immediately after the selectors.
        let coeff0 = layout.index(InputKey::MultiAirFoldCoeff(0)).unwrap();
        assert_eq!(coeff0, last_selector + 1);
        assert_eq!(layout.index(InputKey::MultiAirFoldCoeff(1)), Some(coeff0 + 1));
        assert_eq!(layout.index(InputKey::MultiAirFoldCoeff(2)), Some(coeff0 + 2));
        assert_eq!(layout.index(InputKey::MultiAirFoldCoeff(3)), None);

        // MASM uses felt offsets: 20 for the prologue, then 6 per AIR for selectors.
        let stark_base = layout.regions.stark_vars.offset;
        assert_eq!((coeff0 - stark_base) * crate::EXT_DEGREE, 20 + 6 * 3);

        layout.validate();
    }

    #[test]
    fn canonical_multi_air_native_layout_has_fold_coefficient_slots() {
        let layout = InputLayout::new_multi_air(test_counts(), 2);
        assert!(layout.index(InputKey::MultiAirFoldCoeff(0)).is_some());
        assert!(layout.index(InputKey::MultiAirFoldCoeff(1)).is_some());
        assert_eq!(layout.index(InputKey::MultiAirFoldCoeff(2)), None);
        layout.validate();
    }
}
