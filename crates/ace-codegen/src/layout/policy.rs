use super::{
    InputCounts, InputLayout, InputRegion, LayoutRegions, StarkVarIndices, plan::MultiAirVarIndices,
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
    main: Alignment,
    aux: Alignment,
    quotient: Alignment,
    aux_bus_boundary: Alignment,
    stark_vars: Alignment,
    end_align: Option<Alignment>,
}

impl LayoutPolicy {
    fn native() -> Self {
        Self {
            public_values: Alignment::Unaligned,
            randomness: Alignment::Unaligned,
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
            main: Alignment::DoubleWord,
            aux: Alignment::DoubleWord,
            quotient: Alignment::DoubleWord,
            aux_bus_boundary: Alignment::Word,
            stark_vars: Alignment::Word,
            end_align: Some(Alignment::Word),
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
    /// Build a native layout (no alignment/padding).
    pub fn new(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native(), 1)
    }

    /// Build a MASM-compatible layout (alignment/padding enforced).
    pub fn new_masm(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm(), 1)
    }

    /// Build a native multi-AIR layout for a combined circuit over `num_airs` traces.
    pub fn new_multi_air(counts: InputCounts, num_airs: usize) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native(), num_airs)
    }

    /// Build a MASM-compatible multi-AIR layout (alignment/padding enforced; reserves
    /// extra stark-vars slots for the per-AIR β coefficients and lifted selectors).
    pub fn new_masm_multi_air(counts: InputCounts, num_airs: usize) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm(), num_airs)
    }

    fn build_with_policy(counts: InputCounts, policy: LayoutPolicy, num_airs: usize) -> Self {
        assert!(num_airs >= 1, "layout requires at least one AIR");

        // Number of EF slots in the stark-vars block. Every ACE input slot is an
        // extension-field element (QuadFelt). Some stark vars are base-field values
        // embedded as (val, 0); see the slot table below for which is which.
        // A multi-AIR layout (num_airs >= 2) appends 4 more per AIR: one β coefficient
        // and a (is_first, is_last, is_transition) lifted-selector triple.
        const NUM_STARK_VARS_BASE: usize = 10;
        let is_multi_air = num_airs >= 2;
        let num_stark_vars = NUM_STARK_VARS_BASE + if is_multi_air { 4 * num_airs } else { 0 };

        let mut builder = LayoutBuilder::new();

        let public_values = builder.alloc(counts.num_public, policy.public_values);
        /// Number of randomness inputs (alpha + beta).
        const NUM_RANDOMNESS_INPUTS: usize = 2;
        let randomness = builder.alloc(NUM_RANDOMNESS_INPUTS, policy.randomness);
        let (aux_rand_alpha, aux_rand_beta) = randomness::aux_rand_indices(randomness);
        let main_curr = builder.alloc(counts.width, policy.main);
        let aux_coord_width = counts.aux_width * EXT_DEGREE;
        let aux_curr = builder.alloc(aux_coord_width, policy.aux);
        let quotient_curr = builder.alloc(counts.num_quotient_chunks * EXT_DEGREE, policy.quotient);
        let main_next = builder.alloc(counts.width, policy.main);
        let aux_next = builder.alloc(aux_coord_width, policy.aux);
        let quotient_next = builder.alloc(counts.num_quotient_chunks * EXT_DEGREE, policy.quotient);
        let aux_bus_boundary = builder.alloc(counts.num_aux_boundary, policy.aux_bus_boundary);

        let stark_vars = builder.alloc(num_stark_vars, policy.stark_vars);

        // Matches utils::set_up_auxiliary_inputs_ace layout (EF slots).
        //
        // Extension-field values are grouped first (slots 0-6), then base-field
        // values stored as (val, 0) in EF slots (slots 7-9).
        //
        //  Slot  Value               Field
        //  ----  ------------------  -----
        //   0    alpha               EF      Composition challenge (Horner multiplier)
        //   1    z^N                 EF      Trace-length power (quotient deltas + vanishing
        //   2    z_k                 EF      Periodic column eval point
        //   3    is_first            EF      Precomputed: (z^N - 1) / (z - 1)
        //   4    is_last             EF      Precomputed: (z^N - 1) / (z - g^{-1})
        //   5    is_transition       EF      Precomputed: z - g^{-1}
        //   6    reserved            EF      Alignment padding (zero)
        //   7    weight0             base    First barycentric weight
        //   8    f                   base    Chunk shift ratio h^N
        //   9    s0                  base    First coset shift offset^N
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
        // Multi-AIR block: β coefficients at b+10..b+10+num_airs, then one selector
        // triple per AIR. For num_airs = 2 this is slots 10-11 (betas) and 12-17
        // (selectors), matching `set_up_auxiliary_inputs_ace` in MASM.
        let multi_air = is_multi_air.then_some(MultiAirVarIndices { base: b + 10, num_airs });

        if let Some(end_align) = policy.end_align {
            builder.align(end_align);
        }

        Self {
            regions: LayoutRegions {
                public_values,
                randomness,
                main_curr,
                aux_curr,
                quotient_curr,
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

    #[test]
    fn multi_air_layout_generalizes_over_num_airs() {
        let counts = InputCounts {
            width: 1,
            aux_width: 1,
            num_aux_boundary: 3,
            num_public: 8,
            num_randomness: 2,
            num_periodic: 0,
            num_quotient_chunks: 1,
        };

        // 3-AIR layout: betas first (instance order), then one selector triple per AIR.
        let layout = InputLayout::new_multi_air(counts, 3);
        let base = layout.index(InputKey::MultiAirBeta(0)).unwrap();
        assert_eq!(layout.index(InputKey::MultiAirBeta(2)), Some(base + 2));
        assert_eq!(layout.index(InputKey::IsFirstAir(0)), Some(base + 3));
        assert_eq!(layout.index(InputKey::IsTransitionAir(2)), Some(base + 3 + 3 * 2 + 2));
        assert_eq!(layout.index(InputKey::MultiAirBeta(3)), None, "AIR index out of range");
        assert_eq!(layout.index(InputKey::IsFirstAir(3)), None, "AIR index out of range");

        // 2-AIR layout keeps the slot positions the MASM verifier writes:
        // betas at base..base+1, selector triples at base+2..base+7.
        let layout2 = InputLayout::new_multi_air(counts, 2);
        let base2 = layout2.index(InputKey::MultiAirBeta(0)).unwrap();
        assert_eq!(layout2.index(InputKey::MultiAirBeta(1)), Some(base2 + 1));
        assert_eq!(layout2.index(InputKey::IsFirstAir(0)), Some(base2 + 2));
        assert_eq!(layout2.index(InputKey::IsTransitionAir(1)), Some(base2 + 7));
    }
}
