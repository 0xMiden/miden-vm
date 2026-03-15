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
    pub(crate) fn new(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::native())
    }

    /// Build a MASM-compatible layout (alignment/padding enforced).
    pub(crate) fn new_masm(counts: InputCounts) -> Self {
        Self::build_with_policy(counts, LayoutPolicy::masm())
    }

    fn build_with_policy(counts: InputCounts, policy: LayoutPolicy) -> Self {
        /// Minimum number of EF slots reserved for verifier "stark vars".
        const STARK_BASE_VARS: usize = 14;

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
        let aux_bus_boundary = builder.alloc(counts.aux_width, policy.aux_bus_boundary);

        let stark_base_width = counts.num_aux_inputs.max(STARK_BASE_VARS);
        let stark_vars = builder.alloc(stark_base_width, policy.stark_vars);

        // Matches utils::set_up_auxiliary_inputs_ace layout (EF slots):
        // [z, alpha, g^-1, z^N, g^-2, z^k, weight0, g, s0, 0,
        //  inv(z-g^-1), inv(z-1), inv(z^N-1), 0]
        let z = stark_vars.offset;
        let alpha = stark_vars.offset + 1;
        let g_inv = stark_vars.offset + 2;
        let z_pow_n = stark_vars.offset + 3;
        let g_inv2 = stark_vars.offset + 4;
        let z_k = stark_vars.offset + 5;
        let weight0 = stark_vars.offset + 6;
        let g = stark_vars.offset + 7;
        let s0 = stark_vars.offset + 8;
        let inv_z_minus_g_inv = stark_vars.offset + 10;
        let inv_z_minus_one = stark_vars.offset + 11;
        let inv_vanishing = stark_vars.offset + 12;

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
                z,
                alpha,
                g_inv,
                z_pow_n,
                g_inv2,
                z_k,
                weight0,
                g,
                s0,
                inv_z_minus_g_inv,
                inv_z_minus_one,
                inv_vanishing,
            },
            total_inputs: builder.offset,
            counts,
        }
    }
}
