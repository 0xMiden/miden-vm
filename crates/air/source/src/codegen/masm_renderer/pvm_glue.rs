//! Numeric presentation schedules for the canonical PVM hooks. No assembly fragments.

use std::vec::Vec;

use miden_crypto::hash::eidos::{BLOCK_LEN, DIGEST_WIDTH};

use super::{HeightRule, PvmGlueInput, V1RenderInput};

#[derive(Clone, Debug)]
pub(crate) struct AirSlot {
    pub id: usize,
    pub height: HeightRule,
    pub boundary_offset: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct UintPush {
    pub ptr: u32,
    pub bound_ptr: u32,
    pub repeated_limb: u32,
    pub repeat_count: usize,
    pub limbs: Vec<u32>,
}

#[derive(Clone, Debug)]
pub(crate) struct PvmGluePlan {
    pub airs: Vec<AirSlot>,
    pub scatter_reads: Vec<usize>,
    pub boundary_word_offsets: Vec<usize>,
    pub public_offsets: Vec<usize>,
    pub num_public_values: usize,
    pub max_aux_inputs: usize,
    pub num_aux_inputs: usize,
    pub statement_felts: usize,
    pub statement_and_shape_felts: usize,
    pub setup_buffered: usize,
    pub shape_buffered: usize,
    pub aux_felts: usize,
    pub aux_buffered: usize,
    pub uints: Vec<UintPush>,
    pub groups: Vec<Vec<u32>>,
    pub fixed_messages: usize,
    pub uint_bus_scale: u32,
    pub ec_bus_scale: u32,
    pub max_message_width: usize,
}

impl PvmGluePlan {
    pub fn new(input: &V1RenderInput, glue: &PvmGlueInput) -> Self {
        let n = input.geometry.main.len();
        assert_eq!(n, 12, "canonical PVM has twelve instances");
        assert_eq!(glue.airs.len(), n, "AIR schedule must match geometry");
        assert_eq!(input.counts.num_aux_boundary, n, "one boundary value per AIR");
        assert_eq!(glue.num_public_values, DIGEST_WIDTH, "four root limbs");
        assert_eq!(glue.num_public_values, input.counts.num_public);
        assert_eq!(glue.max_aux_inputs, 0, "no auxiliary statement inputs");
        assert_eq!(glue.num_aux_inputs, 0, "no auxiliary statement inputs");
        let mut airs = Vec::with_capacity(n);
        for (id, air) in glue.airs.iter().enumerate() {
            let log = match air.height {
                HeightRule::Minimum(log) | HeightRule::Fixed(log) => log,
            };
            assert!((1..=29).contains(&log), "AIR height rule outside supported range");
            assert_eq!(
                input.read_layout.aux_bus_boundary.checked_add(id),
                Some(air.boundary_slot),
                "boundary slots must follow canonical AIR order"
            );
            airs.push(AirSlot {
                id,
                height: air.height,
                boundary_offset: 2 * id,
            });
        }
        assert_eq!(glue.max_message_width, input.security.max_message_width as usize);
        assert_eq!(glue.max_message_width, 18, "fixed gamma kernel computes beta^18");
        assert!(glue.uint_bus_scale > 0 && glue.ec_bus_scale > 0);
        assert_ne!(glue.uint_bus_scale, glue.ec_bus_scale);
        assert_eq!(glue.uints.len(), 16, "canonical fixed uint environment");
        assert_eq!(glue.groups.len(), 3, "canonical fixed curve environment");
        assert_eq!(
            glue.uints.len() + glue.groups.len(),
            input.security.boundary_lookup_terms as usize
        );

        // Preserve the legacy instruction schedule: bounds first, then dependent pointers in
        // increasing order. The authored iterator instead groups coefficients before endomorphisms.
        let mut uints = glue.uints.clone();
        uints.sort_by_key(|msg| (msg.ptr != msg.bound_ptr, msg.ptr));
        assert!(
            !uints.iter().enumerate().any(|(i, msg)| {
                msg.ptr == 0 || uints[..i].iter().any(|previous| previous.ptr == msg.ptr)
            }),
            "fixed uint pointers must be nonzero and unique"
        );
        let uints = uints
            .iter()
            .map(|msg| {
                // Keep the original first-three-bounds push/dup compression. General compression
                // would change instruction grouping and therefore procedure roots.
                let repeated = if msg.ptr == msg.bound_ptr && msg.ptr <= 3 {
                    msg.limbs.iter().rev().take_while(|&&limb| limb == u32::MAX).count()
                } else {
                    0
                };
                UintPush {
                    ptr: msg.ptr,
                    bound_ptr: msg.bound_ptr,
                    repeated_limb: u32::MAX,
                    repeat_count: repeated,
                    limbs: msg.limbs[..8 - repeated].iter().rev().copied().collect(),
                }
            })
            .collect();
        // Default statement: length, base-field root, max auxiliary count, auxiliary count.
        let statement_felts = 1 + glue.num_public_values + 2 + glue.num_aux_inputs;
        let statement_and_shape_felts = statement_felts + 1 + n;
        let setup_buffered = DIGEST_WIDTH % BLOCK_LEN;
        let aux_felts = DIGEST_WIDTH + 2 * n;
        Self {
            airs,
            scatter_reads: (0..n).rev().collect(),
            boundary_word_offsets: (0..2 * n).step_by(DIGEST_WIDTH).collect(),
            public_offsets: (0..glue.num_public_values).map(|i| 2 * i).collect(),
            num_public_values: glue.num_public_values,
            max_aux_inputs: glue.max_aux_inputs,
            num_aux_inputs: glue.num_aux_inputs,
            statement_felts,
            statement_and_shape_felts,
            setup_buffered,
            shape_buffered: (setup_buffered + statement_and_shape_felts) % BLOCK_LEN,
            aux_felts,
            aux_buffered: aux_felts % BLOCK_LEN,
            uints,
            groups: glue
                .groups
                .iter()
                .map(|payload| payload.iter().rev().copied().collect())
                .collect(),
            fixed_messages: glue.uints.len() + glue.groups.len(),
            uint_bus_scale: glue.uint_bus_scale,
            ec_bus_scale: glue.ec_bus_scale,
            max_message_width: glue.max_message_width,
        }
    }
}
