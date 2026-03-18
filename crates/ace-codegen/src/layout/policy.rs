use super::{InputCounts, InputLayout, InputRegion, LayoutRegions, StarkVarIndices};
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
    vlpi: Alignment,
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
            vlpi: Alignment::Unaligned,
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
            vlpi: Alignment::Word,
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
    pub(crate) fn new(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native())
    }

    /// Build a MASM-compatible layout (alignment/padding enforced).
    pub(crate) fn new_masm(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm())
    }

    fn build_with_policy(counts: InputCounts, policy: LayoutPolicy) -> Self {
        // Number of EF slots in the stark-vars block. Every ACE input slot is an
        // extension-field element (QuadFelt). Some stark vars are base-field values
        // embedded as (val, 0); see the slot table below for which is which.
        const NUM_STARK_VARS: usize = 10;

        let mut builder = LayoutBuilder::new();

        let public_values = builder.alloc(counts.num_public, policy.public_values);
        let vlpi_reductions = builder.alloc(counts.num_vlpi, policy.vlpi);
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
        let aux_bus_boundary = builder.alloc(counts.aux_width, policy.aux_bus_boundary);

        let stark_vars = builder.alloc(NUM_STARK_VARS, policy.stark_vars);

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
        //   6    gamma               EF      Batching challenge
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
        let gamma = b + 6;
        let weight0 = b + 7;
        let f = b + 8;
        let s0 = b + 9;

        if let Some(end_align) = policy.end_align {
            builder.align(end_align);
        }

        Self {
            regions: LayoutRegions {
                public_values,
                vlpi_reductions,
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
                gamma,
                weight0,
                f,
                s0,
            },
            total_inputs: builder.offset,
            counts,
        }
    }
}
