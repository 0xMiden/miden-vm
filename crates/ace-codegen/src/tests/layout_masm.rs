use crate::{InputCounts, InputKey, InputLayout};

#[test]
fn masm_layout_aligns_and_maps_aux_inputs() {
    let counts = InputCounts {
        width: 3,
        aux_width: 2,
        num_public: 5,
        num_randomness: 16,
        num_randomness_inputs: 2,
        num_periodic: 1,
        num_aux_inputs: 14,
        num_quotient_chunks: 2,
        ext_degree: 2,
    };
    let layout = InputLayout::new_masm(counts);

    let public_base = layout.index(InputKey::Public(0)).unwrap();
    assert_eq!(public_base % 8, 0);
    let rand_base = layout.index(InputKey::AuxRandBeta).unwrap();
    assert_eq!(rand_base % 2, 0);
    let main_curr_base = layout.index(InputKey::Main { offset: 0, index: 0 }).unwrap();
    assert_eq!(main_curr_base % 4, 0);
    let aux_curr_base = layout.index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }).unwrap();
    assert_eq!(aux_curr_base % 4, 0);
    let quotient_curr_base = layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    assert_eq!(quotient_curr_base % 4, 0);
    let main_next_base = layout.index(InputKey::Main { offset: 1, index: 0 }).unwrap();
    assert_eq!(main_next_base % 4, 0);
    let aux_next_base = layout.index(InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }).unwrap();
    assert_eq!(aux_next_base % 4, 0);
    let quotient_next_base = layout
        .index(InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 })
        .unwrap();
    assert_eq!(quotient_next_base % 4, 0);
    let aux_bus_base = layout.index(InputKey::AuxBusBoundary(0)).unwrap();
    assert_eq!(aux_bus_base % 2, 0);
    let stark_base = layout.index(InputKey::Z).unwrap();
    assert_eq!(stark_base % 2, 0);
    assert_eq!(layout.index(InputKey::AuxRandBeta), Some(rand_base));
    assert_eq!(layout.index(InputKey::AuxRandAlpha), Some(rand_base + 1));
    assert_eq!(layout.index(InputKey::Randomness(0)), None);

    let base = layout.index(InputKey::Z).unwrap();
    assert_eq!(layout.index(InputKey::Z), Some(base));
    assert_eq!(layout.index(InputKey::Alpha), Some(base + 1));
    assert_eq!(layout.index(InputKey::GInv), Some(base + 2));
    assert_eq!(layout.index(InputKey::ZPowN), Some(base + 3));
    assert_eq!(layout.index(InputKey::GInv2), Some(base + 4));
    assert_eq!(layout.index(InputKey::ZK), Some(base + 5));
    assert_eq!(layout.index(InputKey::Weight0), Some(base + 6));
    assert_eq!(layout.index(InputKey::G), Some(base + 7));
    assert_eq!(layout.index(InputKey::S0), Some(base + 8));
    assert_eq!(layout.index(InputKey::InvZMinusGInv), Some(base + 10));
    assert_eq!(layout.index(InputKey::InvZMinusOne), Some(base + 11));
    assert_eq!(layout.index(InputKey::InvVanishing), Some(base + 12));

    let aux_base = layout.index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }).unwrap();
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 0, index: 0, coord: 0 }),
        Some(aux_base)
    );
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 0, index: 0, coord: 1 }),
        Some(aux_base + 1)
    );
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 0, index: 1, coord: 0 }),
        Some(aux_base + 2)
    );
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 0, index: 1, coord: 1 }),
        Some(aux_base + 3)
    );

    let aux_next = layout.index(InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }).unwrap();
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 1, index: 0, coord: 0 }),
        Some(aux_next)
    );
    assert_eq!(
        layout.index(InputKey::AuxCoord { offset: 1, index: 0, coord: 1 }),
        Some(aux_next + 1)
    );

    let quotient_base = layout
        .index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 })
        .unwrap();
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 0 }),
        Some(quotient_base)
    );
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 0, chunk: 0, coord: 1 }),
        Some(quotient_base + 1)
    );
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 0, chunk: 1, coord: 0 }),
        Some(quotient_base + 2)
    );
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 0, chunk: 1, coord: 1 }),
        Some(quotient_base + 3)
    );

    let quotient_next = layout
        .index(InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 })
        .unwrap();
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 0 }),
        Some(quotient_next)
    );
    assert_eq!(
        layout.index(InputKey::QuotientChunkCoord { offset: 1, chunk: 0, coord: 1 }),
        Some(quotient_next + 1)
    );
}
