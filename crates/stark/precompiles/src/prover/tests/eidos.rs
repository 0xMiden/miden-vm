//! Tests for the deferred transcript's native 32-row Eidos compression AIR.

use {
    std::collections::HashMap,
    std::vec,
    std::vec::Vec,
};

use miden_air_definitions::precompiles::primitives::byte_pair_lut::eidos;
use {
    miden_core::Felt,
    miden_core::deferred::DEFERRED_AND_FRAME,
    miden_core::deferred::deferred_chunks_frame,
    miden_core::field::PrimeCharacteristicRing,
    miden_core::field::QuadFelt,
    miden_core::utils::RowMajorMatrix,
};
use miden_core::crypto::hash::Eidos;
use {
    miden_precompiles::CurvePrecompile,
    miden_precompiles::Keccak256Precompile,
};
use {
    miden_stark::air::BaseAir,
    miden_stark::air::ConstraintDegrees,
    miden_stark::air::LiftedAir,
    miden_stark::lookup::debug::ValidateLayout,
    miden_stark::lookup::debug::ValidateLookupAir,
};

use {
    crate::prover::logup::Challenges,
    crate::prover::logup::LookupMessage,
    crate::prover::logup::NUM_RANDOMNESS,
    crate::prover::logup::build_lookup_fractions,
    crate::prover::relations::BusId,
    crate::prover::relations::MAX_MESSAGE_WIDTH,
    crate::prover::relations::NUM_BUS_IDS,
    crate::prover::session::Session,
    crate::prover::transcript::eidos::COL_CHAIN_HEAD_ID,
    crate::prover::transcript::eidos::COL_EIDOS_COMPRESSION_END,
    crate::prover::transcript::eidos::COL_HAS_SUCCESSOR,
    crate::prover::transcript::eidos::COL_IN_MULTIPLICITY,
    crate::prover::transcript::eidos::COL_INITIAL_MULTIPLICITY,
    crate::prover::transcript::eidos::COL_IS_CONTINUATION,
    crate::prover::transcript::eidos::COL_OUT_MULTIPLICITY,
    crate::prover::transcript::eidos::EidosBlockMsg,
    crate::prover::transcript::eidos::EidosCompressionAir,
    crate::prover::transcript::eidos::EidosDigest,
    crate::prover::transcript::eidos::EidosInitMsg,
    crate::prover::transcript::eidos::EidosOutMsg,
    crate::prover::transcript::eidos::INTERNAL_CV_BUS_ID,
    crate::prover::transcript::eidos::NUM_AUX_COLS,
    crate::prover::transcript::eidos::NUM_MAIN_COLS,
    crate::prover::transcript::eidos::compression::layout::BLOCK_PERIOD as EIDOS_COMPRESSION_CYCLE_LEN,
    crate::prover::transcript::eidos::compression::layout::BYTE_SLOT_WIDTH,
    crate::prover::transcript::eidos::compression::layout::BYTES_PER_WORD,
    crate::prover::transcript::eidos::compression::layout::F_COMPRESSION_CYCLE_ID_COL,
    crate::prover::transcript::eidos::compression::layout::F_CV_STORAGE_COLS,
    crate::prover::transcript::eidos::compression::layout::F_TOP_BIT_MASK,
    crate::prover::transcript::eidos::compression::layout::F_TOP_BIT_SLOT_BASE_COL,
    crate::prover::transcript::eidos::compression::layout::FOOTER_START,
    crate::prover::transcript::eidos::compression::layout::G_COMPRESSION_CYCLE_ID_COL,
    crate::prover::transcript::eidos::compression::layout::NUM_COLS as NUM_EIDOS_COMPRESSION_COLS,
    crate::prover::transcript::eidos::compression::layout::footer_digest_col,
    crate::prover::transcript::eidos::compression::layout::footer_r_col,
    crate::prover::transcript::eidos::compression::layout::g_bd_rot_slot_col,
    crate::prover::transcript::eidos::compression::testing::EidosCompressionFeltTraceBlock,
    crate::prover::transcript::eidos::compression::testing::generate_felt_trace_block_with_cycle_id,
    crate::prover::transcript::eidos::compression::testing::rewrite_felt_footer_for_test,
    crate::prover::transcript::eidos::compression::trace::set_cycle_metadata as write_cycle_metadata,
    crate::prover::transcript::eidos::compression::trace::set_footer_multiplicity,
    crate::prover::transcript::eidos::trace::EidosRequires,
    crate::prover::transcript::eidos::trace::testing::generate_trace,
    crate::prover::transcript::eidos::trace::testing::total_cycles,
};

const NUM_INTERFACE_AUX_COLS: usize = 3;
const NUM_LOOKUP_COLS: usize = NUM_AUX_COLS - 1;
const INTERFACE_AUX_BEGIN: usize = NUM_LOOKUP_COLS - NUM_INTERFACE_AUX_COLS;

fn block(a: u32) -> ([Felt; 4], [Felt; 4]) {
    (
        core::array::from_fn(|i| Felt::from(a + i as u32)),
        core::array::from_fn(|i| Felt::from(a + 4 + i as u32)),
    )
}

#[test]
fn full_empty_session_bus_stack_balances() {
    let mut session = Session::new();
    let root = session.assert_and_fold(core::iter::empty());
    let traces = session.finish(root);
    let challenges = Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let residual = crate::prover::tests::bus_balance::session_stack_residual(
        &traces.mains(),
        &[],
        &challenges,
    );
    assert!(residual.is_empty(), "{residual:#?}");
}

fn as_block((lo, hi): ([Felt; 4], [Felt; 4])) -> [Felt; 8] {
    let mut out = [Felt::ZERO; 8];
    out[..4].copy_from_slice(&lo);
    out[4..].copy_from_slice(&hi);
    out
}

fn unpack_felts<const N: usize>(values: &[Felt]) -> [u32; N] {
    let words: Vec<u32> = values
        .iter()
        .flat_map(|value| {
            let packed = value.as_canonical_u64();
            [packed as u32, (packed >> 32) as u32]
        })
        .collect();
    words.try_into().unwrap_or_else(|words: Vec<u32>| {
        panic!("expected {N} unpacked words, got {}", words.len())
    })
}

fn two_cycle_matrix(
    first: &EidosCompressionFeltTraceBlock,
    second: &EidosCompressionFeltTraceBlock,
) -> RowMajorMatrix<Felt> {
    let values = first
        .rows
        .iter()
        .chain(&second.rows)
        .flat_map(|row| row.iter().copied())
        .collect();
    RowMajorMatrix::new(values, NUM_EIDOS_COMPRESSION_COLS)
}

fn parent_matrix_from_core(trace: &RowMajorMatrix<Felt>) -> RowMajorMatrix<Felt> {
    let mut result = trace.clone();
    for rows in result
        .values
        .as_chunks_mut::<{ EIDOS_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS }>()
        .0
        .iter_mut()
    {
        let head = rows[F_COMPRESSION_CYCLE_ID_COL];
        write_cycle_metadata(rows, Felt::ZERO, Felt::ZERO, Felt::ZERO, Felt::ZERO, head);
    }
    result
}

fn set_cycle_metadata(
    trace: &mut RowMajorMatrix<Felt>,
    cycle: usize,
    in_mult: Felt,
    out_mult: Felt,
    is_continuation: Felt,
    has_successor: Felt,
    chain_head_id: Felt,
) {
    let stride = EIDOS_COMPRESSION_CYCLE_LEN * NUM_MAIN_COLS;
    write_cycle_metadata(
        &mut trace.values[cycle * stride..(cycle + 1) * stride],
        in_mult,
        out_mult,
        is_continuation,
        has_successor,
        chain_head_id,
    );
}

fn cycle_digest(trace: &RowMajorMatrix<Felt>, cycle: usize) -> [Felt; 4] {
    let footer = (cycle + 1) * EIDOS_COMPRESSION_CYCLE_LEN - 1;
    core::array::from_fn(|idx| trace.values[footer * NUM_MAIN_COLS + footer_digest_col(idx)])
}

fn lookup_challenges() -> Challenges<QuadFelt> {
    Challenges::new(
        QuadFelt::from_u64(101),
        QuadFelt::from_u64(103),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    )
}

fn eidos_balance(trace: &RowMajorMatrix<Felt>) -> HashMap<QuadFelt, Felt> {
    let air = EidosCompressionAir;
    let fractions =
        build_lookup_fractions(&air, trace, None, &air.periodic_columns(), &lookup_challenges());
    lookup_balance(fractions.fractions())
}

fn continuation_balance(trace: &RowMajorMatrix<Felt>) -> HashMap<QuadFelt, Felt> {
    let air = EidosCompressionAir;
    let fractions =
        build_lookup_fractions(&air, trace, None, &air.periodic_columns(), &lookup_challenges());
    let mut offset = 0;
    let mut links = Vec::new();
    for (slot, &count) in fractions.counts().iter().enumerate() {
        if slot % NUM_LOOKUP_COLS == INTERFACE_AUX_BEGIN + 2 {
            links.extend_from_slice(&fractions.fractions()[offset..offset + count]);
        }
        offset += count;
    }
    lookup_balance(&links)
}

fn lookup_balance(fractions: &[(Felt, QuadFelt)]) -> HashMap<QuadFelt, Felt> {
    let mut balance = HashMap::new();
    for &(multiplicity, denominator) in fractions {
        *balance.entry(denominator).or_insert(Felt::ZERO) += multiplicity;
    }
    balance.retain(|_, multiplicity| *multiplicity != Felt::ZERO);
    balance
}

fn net_multiplicity(balance: &HashMap<QuadFelt, Felt>, denominator: QuadFelt) -> Felt {
    balance.get(&denominator).copied().unwrap_or(Felt::ZERO)
}

#[test]
fn frames_match_vm_sources() {
    let len_bytes = 136u32;
    assert_eq!(deferred_chunks_frame(3).params(), [24, 0, 0]);
    assert_eq!(DEFERRED_AND_FRAME.params(), [0; 3]);
    assert_eq!(
        Keccak256Precompile::assert_frame(len_bytes).params(),
        [Keccak256Precompile::ASSERT_OP_ID, len_bytes, 0],
    );
    assert_eq!(
        CurvePrecompile::msm_frame(5).params(),
        [CurvePrecompile::MSM_OP_ID as u32, 5, 0],
    );
}

#[test]
fn eidos_interface_messages_bind_their_ids_and_payloads() {
    let challenges = Challenges::<QuadFelt>::new(
        QuadFelt::from_u64(7),
        QuadFelt::from_u64(5),
        MAX_MESSAGE_WIDTH,
        NUM_BUS_IDS,
    );
    let compression_id = Felt::from_u32(1);
    let chain_head_id = Felt::from_u32(2);
    let block = core::array::from_fn(|idx| Felt::from_u32(10 + idx as u32));
    let initial_cv = core::array::from_fn(|idx| Felt::from_u32(30 + idx as u32));
    let encoded_block = EidosBlockMsg { compression_id, block }.encode(&challenges);
    let encoded_init = EidosInitMsg { compression_id, initial_cv }.encode(&challenges);
    let encoded_out = EidosOutMsg {
        chain_head_id,
        compression_id,
        digest: initial_cv,
    }
    .encode(&challenges);

    let [b0, b1, b2, b3, b4, b5, b6, b7] = block;
    let [cv0, cv1, cv2, cv3] = initial_cv;
    assert_eq!(
        encoded_block,
        challenges
            .encode(BusId::EidosBlock as usize, [compression_id, b0, b1, b2, b3, b4, b5, b6, b7],),
        "Eidos block field order drifted",
    );
    assert_eq!(
        encoded_init,
        challenges.encode(BusId::EidosInit as usize, [compression_id, cv0, cv1, cv2, cv3]),
        "Eidos initial-CV field order drifted",
    );
    assert_eq!(
        encoded_out,
        challenges
            .encode(BusId::EidosOut as usize, [chain_head_id, compression_id, cv0, cv1, cv2, cv3],),
        "Eidos output field order drifted",
    );

    for field in 0..8 {
        let mut mutated = block;
        mutated[field] += Felt::ONE;
        assert_ne!(
            encoded_block,
            EidosBlockMsg { compression_id, block: mutated }.encode(&challenges),
            "block field {field} was not bound",
        );
    }
    for field in 0..4 {
        let mut mutated = initial_cv;
        mutated[field] += Felt::ONE;
        assert_ne!(
            encoded_init,
            EidosInitMsg { compression_id, initial_cv: mutated }.encode(&challenges),
            "initial-CV field {field} was not bound",
        );
    }
    assert_ne!(
        encoded_block,
        EidosBlockMsg {
            compression_id: compression_id + Felt::ONE,
            block
        }
        .encode(&challenges),
    );
    assert_ne!(encoded_block, encoded_init);
    assert_ne!(encoded_init, encoded_out);
    assert_ne!(
        encoded_out,
        EidosOutMsg {
            chain_head_id: chain_head_id + Felt::ONE,
            compression_id,
            digest: initial_cv,
        }
        .encode(&challenges),
    );
    assert_ne!(
        encoded_out,
        EidosOutMsg {
            chain_head_id,
            compression_id: compression_id + Felt::ONE,
            digest: initial_cv,
        }
        .encode(&challenges),
    );
}

#[test]
fn air_layout_matches_32_row_eidos_compression_spec() {
    assert_eq!(EIDOS_COMPRESSION_CYCLE_LEN, 32);
    assert_eq!(COL_EIDOS_COMPRESSION_END, 104);
    assert_eq!(COL_IN_MULTIPLICITY, 94);
    assert_eq!(COL_INITIAL_MULTIPLICITY, 64);
    assert_eq!(COL_OUT_MULTIPLICITY, 64);
    assert_eq!(COL_IS_CONTINUATION, 96);
    assert_eq!(COL_CHAIN_HEAD_ID, 93);
    assert_eq!(NUM_MAIN_COLS, 104);
    assert_eq!(NUM_AUX_COLS, 20);

    let layout =
        <EidosCompressionAir as LiftedAir<Felt, QuadFelt>>::air_layout(&EidosCompressionAir);
    assert_eq!(layout.preprocessed_width, 0);
    assert_eq!(layout.main_width, NUM_MAIN_COLS);
    assert_eq!(layout.num_public_values, 0);
    assert_eq!(layout.permutation_width, NUM_AUX_COLS);
    assert_eq!(layout.num_permutation_challenges, NUM_RANDOMNESS);
    assert_eq!(layout.num_permutation_values, 1);
    assert_eq!(layout.num_periodic_columns, 10);
    assert_eq!(
        <EidosCompressionAir as BaseAir<Felt>>::periodic_columns(&EidosCompressionAir)
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![EIDOS_COMPRESSION_CYCLE_LEN; 10],
    );
}

#[test]
fn constraint_degree_remains_three() {
    let degree = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&EidosCompressionAir);
    assert_eq!(degree, ConstraintDegrees { base: 3, ext: 3 });
    assert_eq!(crate::prover::tests::log_quotient_degree(&EidosCompressionAir), 1);
}

#[test]
fn lookup_degree_annotations_match_the_unified_layout() {
    EidosCompressionAir
        .validate(ValidateLayout {
            preprocessed_width: 0,
            trace_width: NUM_MAIN_COLS,
            num_public_values: 0,
            num_periodic_columns: 10,
            permutation_width: NUM_LOOKUP_COLS,
            num_permutation_challenges: NUM_RANDOMNESS,
            num_permutation_values: 1,
        })
        .unwrap_or_else(|error| panic!("PVM Eidos compression lookup validation failed: {error}"));
}

#[test]
fn lookup_interaction_liveness_matches_the_nineteen_lookup_columns() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(10)]);
    requires.require_digest(output.digest);
    let compression = generate_trace(requires);

    let fractions = build_lookup_fractions(
        &EidosCompressionAir,
        &compression,
        None,
        &EidosCompressionAir.periodic_columns(),
        &lookup_challenges(),
    );
    let mut expected_shape = [2; NUM_LOOKUP_COLS];
    expected_shape[INTERFACE_AUX_BEGIN..].copy_from_slice(&[1, 1, 1]);
    assert_eq!(fractions.shape(), &expected_shape);

    for row in 0..EIDOS_COMPRESSION_CYCLE_LEN {
        let actual = &fractions.counts()[row * NUM_LOOKUP_COLS..(row + 1) * NUM_LOOKUP_COLS];
        let core = &actual[..INTERFACE_AUX_BEGIN];
        if row < FOOTER_START {
            assert_eq!(core, &[2; INTERFACE_AUX_BEGIN], "fused row {row}");
        } else {
            let mut expected = [0; INTERFACE_AUX_BEGIN];
            expected[..9].fill(2);
            expected[11..13].fill(2);
            expected[13] = 1;
            expected[14] = 2;

            assert_eq!(core, &expected, "footer row {row}");
            assert_eq!(core.iter().sum::<usize>(), 25);
        }

        let expected = match row {
            30 => [0, 1, 0],
            31 => [1, 1, 0],
            _ => [0, 0, 0],
        };
        assert_eq!(&actual[INTERFACE_AUX_BEGIN..], &expected, "interface row {row}");
    }
}

#[test]
fn digests_match_eidos_framing_and_integrated_eidos_compression_air_holds() {
    let and_block = block(10);
    let chunk_blocks = [block(20), block(30), block(40)];
    let msm_blocks = [block(50), block(60)];
    let chunks_frame = deferred_chunks_frame(chunk_blocks.len() as u32);
    let msm_frame = CurvePrecompile::msm_frame(msm_blocks.len() as u32);

    let mut requires = EidosRequires::new();
    let and = requires.require_absorption(DEFERRED_AND_FRAME, [and_block]);
    let chunks = requires.require_absorption(chunks_frame, chunk_blocks);
    let msm = requires.require_absorption(msm_frame, msm_blocks);
    for digest in [and.digest, chunks.digest, msm.digest] {
        requires.require_digest(digest).expect("recorded digest");
    }

    let expected_and =
        Eidos::compress(DEFERRED_AND_FRAME.initial_chaining_word(), as_block(and_block));
    assert_eq!(and.digest, EidosDigest(expected_and.into_elements()));

    let mut expected_chunks = chunks_frame.initial_chaining_word();
    for input in chunk_blocks {
        expected_chunks = Eidos::compress(expected_chunks, as_block(input));
    }
    assert_eq!(chunks.digest, EidosDigest(expected_chunks.into_elements()));

    let mut expected_msm = msm_frame.initial_chaining_word();
    for input in msm_blocks {
        expected_msm = Eidos::compress(expected_msm, as_block(input));
    }
    assert_eq!(msm.digest, EidosDigest(expected_msm.into_elements()));
    assert_eq!(total_cycles(&requires), 6);

    let compression = generate_trace(requires);
    crate::prover::tests::check_local(EidosCompressionAir, &compression);

    // Six real compressions occupy six full 32-row cycles, padded to eight cycles.
    assert_eq!(compression.values.len() / NUM_MAIN_COLS, 8 * 32);
    let row = |cycle: usize, c: usize| {
        let phase = if c == COL_IS_CONTINUATION { 30 } else { 31 };
        compression.values[(cycle * EIDOS_COMPRESSION_CYCLE_LEN + phase) * NUM_MAIN_COLS + c]
    };
    assert_eq!(row(0, COL_IS_CONTINUATION), Felt::ZERO);
    assert_eq!(row(1, COL_IS_CONTINUATION), Felt::ZERO);
    assert_eq!(row(2, COL_IS_CONTINUATION), Felt::ONE);
    assert_eq!(row(3, COL_IS_CONTINUATION), Felt::ONE);
    assert_eq!(row(4, COL_IS_CONTINUATION), Felt::ZERO);
    assert_eq!(row(5, COL_IS_CONTINUATION), Felt::ONE);
    assert_eq!(row(0, COL_CHAIN_HEAD_ID), Felt::ZERO);
    assert_eq!(row(1, COL_CHAIN_HEAD_ID), Felt::ONE);
    assert_eq!(row(2, COL_CHAIN_HEAD_ID), Felt::ONE);
    assert_eq!(row(3, COL_CHAIN_HEAD_ID), Felt::ONE);
    assert_eq!(row(4, COL_CHAIN_HEAD_ID), Felt::from_u8(4));
    assert_eq!(row(5, COL_CHAIN_HEAD_ID), Felt::from_u8(4));
    for cycle in 0..6 {
        assert_eq!(row(cycle, F_COMPRESSION_CYCLE_ID_COL), Felt::from_usize(cycle));
        assert_eq!(row(cycle, COL_IN_MULTIPLICITY), Felt::ONE);
        assert_eq!(
            compression.values[((cycle + 1) * EIDOS_COMPRESSION_CYCLE_LEN - 1) * NUM_MAIN_COLS
                + COL_OUT_MULTIPLICITY],
            Felt::ONE
        );
    }
    for cycle in 6..8 {
        assert_eq!(row(cycle, COL_IN_MULTIPLICITY), Felt::ZERO);
        assert_eq!(
            compression.values[((cycle + 1) * EIDOS_COMPRESSION_CYCLE_LEN - 1) * NUM_MAIN_COLS
                + COL_OUT_MULTIPLICITY],
            Felt::ZERO
        );
        assert_eq!(row(cycle, COL_IS_CONTINUATION), Felt::ZERO);
        assert_eq!(row(cycle, COL_CHAIN_HEAD_ID), Felt::from_usize(cycle));
    }

    // The PVM output relation reads the digest directly from the native Eidos compression footer.
    // There is no bridge trace between the compression witness and the value seen by transcript
    // consumers.
    let footer_digest = |cycle: usize| {
        let footer = cycle * EIDOS_COMPRESSION_CYCLE_LEN + EIDOS_COMPRESSION_CYCLE_LEN - 1;
        core::array::from_fn(|i| compression.values[footer * NUM_MAIN_COLS + footer_digest_col(i)])
    };
    assert_eq!(footer_digest(0), and.digest.as_array());
    assert_eq!(footer_digest(3), chunks.digest.as_array());
    assert_eq!(footer_digest(5), msm.digest.as_array());

    for (cycle, outgoing) in [0, 1, 1, 0, 1, 0, 0, 0].into_iter().enumerate() {
        let footer2 = (cycle * EIDOS_COMPRESSION_CYCLE_LEN + 30) * NUM_MAIN_COLS;
        let footer3 = footer2 + NUM_MAIN_COLS;
        assert_eq!(
            compression.values[footer2 + COL_INITIAL_MULTIPLICITY],
            compression.values[footer3 + COL_IN_MULTIPLICITY]
        );
        assert_eq!(compression.values[footer3 + COL_HAS_SUCCESSOR], Felt::from_u8(outgoing));
    }
}

#[test]
fn distinct_generic_absorptions_use_consecutive_physical_cycles() {
    let payload = block(70);
    let mut requires = EidosRequires::new();
    let first = requires.require_absorption(Keccak256Precompile::assert_frame(8), [payload]);
    let second = requires.require_absorption(Keccak256Precompile::assert_frame(9), [payload]);
    assert_ne!(first.digest, second.digest);
    assert_eq!(total_cycles(&requires), 2);

    let compression = generate_trace(requires);
    let row = |cycle: usize, col: usize| {
        let phase = if col == COL_IS_CONTINUATION { 30 } else { 31 };
        compression.values[(cycle * EIDOS_COMPRESSION_CYCLE_LEN + phase) * NUM_MAIN_COLS + col]
    };

    assert_eq!(row(0, F_COMPRESSION_CYCLE_ID_COL), Felt::ZERO);
    assert_eq!(row(1, F_COMPRESSION_CYCLE_ID_COL), Felt::ONE);
    for cycle in 0..2 {
        assert_eq!(row(cycle, COL_IS_CONTINUATION), Felt::ZERO);
        assert_eq!(row(cycle, COL_IN_MULTIPLICITY), Felt::ONE);
    }
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn fingerprint_rejects_two_cycle_cv_swap() {
    let block_a = core::array::from_fn(|i| 10 + i as u32);
    let block_b = core::array::from_fn(|i| 100 + i as u32);
    let cv_a = core::array::from_fn(|i| 1_000 + i as u32);
    let cv_b = core::array::from_fn(|i| 2_000 + i as u32);

    // Each computation consumes the other cycle's CV while its footer advertises its own.
    // Per-cycle consistency checks prevent cancellation between those cycles.
    let mut forged_a = generate_felt_trace_block_with_cycle_id(block_a, cv_b, 0);
    let mut forged_b = generate_felt_trace_block_with_cycle_id(block_b, cv_a, 1);
    rewrite_felt_footer_for_test(&mut forged_a.rows, block_a, cv_a, forged_a.final_v, 0);
    rewrite_felt_footer_for_test(&mut forged_b.rows, block_b, cv_b, forged_b.final_v, 1);

    let forged_core = two_cycle_matrix(&forged_a, &forged_b);
    // The AIR rejects the substituted CV even when no external input is consumed.
    let forged = parent_matrix_from_core(&forged_core);
    crate::prover::tests::check_local(EidosCompressionAir, &forged);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn fingerprint_rejects_two_cycle_message_swap() {
    let block_a = core::array::from_fn(|i| 10 + i as u32);
    let block_b = core::array::from_fn(|i| 100 + i as u32);
    let cv_a = core::array::from_fn(|i| 1_000 + i as u32);
    let cv_b = core::array::from_fn(|i| 2_000 + i as u32);

    // Each computation consumes the other cycle's block. Replace only its footer's advertised
    // block, leaving the computed Eidos compression output intact.
    let mut forged_a = generate_felt_trace_block_with_cycle_id(block_b, cv_a, 0);
    let mut forged_b = generate_felt_trace_block_with_cycle_id(block_a, cv_b, 1);
    rewrite_felt_footer_for_test(&mut forged_a.rows, block_a, cv_a, forged_a.final_v, 0);
    rewrite_felt_footer_for_test(&mut forged_b.rows, block_b, cv_b, forged_b.final_v, 1);

    let forged = parent_matrix_from_core(&two_cycle_matrix(&forged_a, &forged_b));
    crate::prover::tests::check_local(EidosCompressionAir, &forged);
}

#[test]
fn top_bit_overlay_lookup_rejects_the_other_locally_valid_branch() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut trace_block = generate_felt_trace_block_with_cycle_id(block, cv, 0);

    let matrix = |rows: &[[Felt; NUM_EIDOS_COMPRESSION_COLS]; EIDOS_COMPRESSION_CYCLE_LEN]| {
        RowMajorMatrix::new(rows.iter().flatten().copied().collect(), NUM_EIDOS_COMPRESSION_COLS)
    };
    let honest = parent_matrix_from_core(&matrix(&trace_block.rows));

    let footer = EIDOS_COMPRESSION_CYCLE_LEN - 1;
    let row = &mut trace_block.rows[footer];
    let a = row[F_TOP_BIT_SLOT_BASE_COL];
    let mask = Felt::from_u8(F_TOP_BIT_MASK);
    let valid_h = Felt::from_u8((a.as_canonical_u64() as u8) & F_TOP_BIT_MASK);
    let wrong_h = mask - valid_h;
    let wrong_x = a + mask - wrong_h.double();
    let lookup_byte_position = (F_TOP_BIT_SLOT_BASE_COL / BYTE_SLOT_WIDTH) % BYTES_PER_WORD;
    row[F_TOP_BIT_SLOT_BASE_COL + 2] = eidos::denormalize(lookup_byte_position, wrong_x);

    // The footer digest masks this bit as `out_odd - 2^24*h` before packing at weight 2^32.
    // Adjusting it by `-2^56 * (wrong_h - valid_h)` keeps every base constraint satisfied.
    let digest_delta = -Felt::from_u64(1 << 56) * (wrong_h - valid_h);
    row[footer_digest_col(3)] += digest_delta;
    // Digest coordinate 3 overlays byte 3 of the first C word. Preserve the footer CV value by
    // compensating its 2^24 byte weight through that word's 2^32 footer-storage coordinate.
    row[F_CV_STORAGE_COLS[0]] -= digest_delta / Felt::from_u16(1 << 8);

    let forged = parent_matrix_from_core(&matrix(&trace_block.rows));
    crate::prover::tests::check_local(EidosCompressionAir, &forged);

    let challenges = lookup_challenges();
    let honest_report = eidos_balance(&honest);
    let forged_report = eidos_balance(&forged);
    let encode = |x| challenges.encode(BusId::BytePairLut as usize, [a, mask, x]);
    let correct_x = Felt::from_u8((a.as_canonical_u64() as u8) ^ F_TOP_BIT_MASK);

    assert_eq!(
        net_multiplicity(&forged_report, encode(correct_x)) + Felt::ONE,
        net_multiplicity(&honest_report, encode(correct_x)),
    );
    assert_eq!(
        net_multiplicity(&forged_report, encode(wrong_x)),
        net_multiplicity(&honest_report, encode(wrong_x)) + Felt::ONE,
    );
}

#[test]
fn dedicated_rotation_bus_encodes_the_normalized_physical_contribution() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut trace_block = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let matrix = |rows: &[[Felt; NUM_EIDOS_COMPRESSION_COLS]; EIDOS_COMPRESSION_CYCLE_LEN]| {
        RowMajorMatrix::new(rows.iter().flatten().copied().collect(), NUM_EIDOS_COMPRESSION_COLS)
    };

    let row = 0;
    let byte_position = 1;
    let base = g_bd_rot_slot_col(0, byte_position, 0);
    let a = trace_block.rows[row][base];
    let b = trace_block.rows[row][base + 1];
    let correct_physical = trace_block.rows[row][base + 2];
    assert_eq!(
        correct_physical,
        Felt::from(eidos::contribution(
            eidos::Rotation::Rot12,
            byte_position,
            a.as_canonical_u64() as u8,
            b.as_canonical_u64() as u8,
        )),
    );

    let honest = parent_matrix_from_core(&matrix(&trace_block.rows));
    trace_block.rows[row][base + 2] += Felt::ONE;
    let wrong_physical = trace_block.rows[row][base + 2];
    let forged = parent_matrix_from_core(&matrix(&trace_block.rows));

    let challenges = lookup_challenges();
    let honest_report = eidos_balance(&honest);
    let forged_report = eidos_balance(&forged);
    let encode = |physical| {
        challenges.encode(
            BusId::EidosRot12Pos1 as usize,
            [a, b, eidos::normalize(byte_position, physical)],
        )
    };

    assert_eq!(
        net_multiplicity(&forged_report, encode(correct_physical)) + Felt::ONE,
        net_multiplicity(&honest_report, encode(correct_physical)),
    );
    assert_eq!(
        net_multiplicity(&forged_report, encode(wrong_physical)),
        net_multiplicity(&honest_report, encode(wrong_physical)) + Felt::ONE,
    );
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_is_pinned_to_zero() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let first = generate_felt_trace_block_with_cycle_id(block, cv, 1);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);

    let trace = parent_matrix_from_core(&two_cycle_matrix(&first, &second));
    crate::prover::tests::check_local(EidosCompressionAir, &trace);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_is_constant_across_fused_rows() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 1);
    first.rows[1][G_COMPRESSION_CYCLE_ID_COL] = Felt::ONE;

    let trace = parent_matrix_from_core(&two_cycle_matrix(&first, &second));
    crate::prover::tests::check_local(EidosCompressionAir, &trace);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_bridges_fused_rows_to_footer() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let mut first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);
    rewrite_felt_footer_for_test(&mut first.rows, block, cv, first.final_v, 1);

    let trace = parent_matrix_from_core(&two_cycle_matrix(&first, &second));
    crate::prover::tests::check_local(EidosCompressionAir, &trace);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn physical_cycle_id_increments_between_cycles() {
    let block = core::array::from_fn(|i| 10 + i as u32);
    let cv = core::array::from_fn(|i| 1_000 + i as u32);
    let first = generate_felt_trace_block_with_cycle_id(block, cv, 0);
    let second = generate_felt_trace_block_with_cycle_id(block, cv, 2);

    let trace = parent_matrix_from_core(&two_cycle_matrix(&first, &second));
    crate::prover::tests::check_local(EidosCompressionAir, &trace);
}

#[test]
#[should_panic(expected = "packed Eidos compression input must be a canonical field element")]
fn pvm_trace_writer_rejects_noncanonical_packed_input() {
    let mut block = [0; 16];
    block[0] = 1;
    block[1] = u32::MAX;
    let _ = generate_felt_trace_block_with_cycle_id(block, [0; 8], 0);
}

#[test]
fn interning_reuses_logical_span_and_tallies_multiplicity() {
    let mut requires = EidosRequires::new();
    let frame = deferred_chunks_frame(2);
    let first = requires.require_absorption(frame, vec![block(7), block(17)]);
    let second = requires.require_absorption(frame, vec![block(7), block(17)]);
    for _ in 0..3 {
        requires.require_digest(first.digest).expect("interned digest");
    }

    assert_eq!(first.digest, second.digest);
    assert_eq!(first.head(), second.head());
    assert_eq!(first.span.tail(), second.span.tail());
    assert_eq!(total_cycles(&requires), 2);

    let compression = generate_trace(requires);
    for (index, row) in compression.values.as_chunks::<NUM_MAIN_COLS>().0.iter().enumerate() {
        if index % EIDOS_COMPRESSION_CYCLE_LEN == EIDOS_COMPRESSION_CYCLE_LEN - 2 {
            assert_eq!(row[COL_INITIAL_MULTIPLICITY], Felt::from_u8(2));
        }
        if index % EIDOS_COMPRESSION_CYCLE_LEN == EIDOS_COMPRESSION_CYCLE_LEN - 1 {
            assert_eq!(row[COL_IN_MULTIPLICITY], Felt::from_u8(2));
            assert_eq!(row[COL_OUT_MULTIPLICITY], Felt::from_u8(3));
        }
    }
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
}

#[test]
fn output_only_physical_chain_unbalances_its_owner_messages() {
    let mut session = Session::new();
    let lhs = session.zero();
    let rhs = session.zero();
    let root = session.assert_and(lhs, rhs);
    let traces = session.finish(root);
    let mains = traces.mains();
    let challenges = lookup_challenges();

    assert!(
        crate::prover::tests::bus_balance::session_stack_net(&mains, &[], &challenges)
            .values()
            .all(|(multiplicity, _)| *multiplicity == Felt::ZERO),
        "the valid one-cycle session must balance",
    );
    let mut output_only = mains[1].clone();
    set_cycle_metadata(
        &mut output_only,
        0,
        Felt::ZERO,
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    );

    // Multiplicities are intentionally bus-bound rather than locally equated. The controller
    // alone therefore permits an output-only cycle, while the full owner/controller composition
    // must reject it.
    crate::prover::tests::check_local(EidosCompressionAir, &output_only);

    // Encode the unchanged AND owner messages directly from their relation schemas. Do not use
    // the controller's lookup report to discover which messages the mutation removed.
    let expected_block = challenges.encode(BusId::EidosBlock as usize, [Felt::ZERO; 9]);
    let [cv0, cv1, cv2, cv3] = DEFERRED_AND_FRAME.initial_chaining_word().into_elements();
    let expected_init =
        challenges.encode(BusId::EidosInit as usize, [Felt::ZERO, cv0, cv1, cv2, cv3]);

    let net = crate::prover::tests::bus_balance::session_stack_net(
        &mains,
        &[(1, &output_only)],
        &challenges,
    );
    let multiplicity =
        |denominator| net.get(&denominator).map_or(Felt::ZERO, |(multiplicity, _)| *multiplicity);
    assert_eq!(multiplicity(expected_block), Felt::ONE);
    assert_eq!(multiplicity(expected_init), Felt::ONE);
    assert_eq!(
        net.values().filter(|(multiplicity, _)| *multiplicity != Felt::ZERO).count(),
        2,
        "only the owner's unconsumed block and initial-CV messages may remain",
    );
}

#[test]
fn link_flags_are_boolean_on_both_footer_rows() {
    let mut requires = EidosRequires::new();
    requires.require_absorption(DEFERRED_AND_FRAME, [block(10)]);
    let compression = generate_trace(requires);
    for (incoming, outgoing) in [
        (Felt::from_u8(2), Felt::ZERO),
        (Felt::ZERO, Felt::from_u8(2)),
        (-Felt::ONE, Felt::ZERO),
        (Felt::ZERO, -Felt::ONE),
    ] {
        let mut forged = compression.clone();
        set_cycle_metadata(&mut forged, 0, Felt::ZERO, Felt::ZERO, incoming, outgoing, Felt::ZERO);
        crate::prover::tests::assert_local_rejects(EidosCompressionAir, &forged);
    }
}

#[test]
fn continuation_requires_both_unit_weight_endpoints() {
    let mut requires = EidosRequires::new();
    requires.require_absorption(deferred_chunks_frame(2), [block(10), block(20)]);
    let compression = generate_trace(requires);
    assert!(continuation_balance(&compression).is_empty());
    for (outgoing, incoming) in [(0, 1), (1, 0)] {
        let mut forged = compression.clone();
        set_cycle_metadata(
            &mut forged,
            0,
            Felt::ZERO,
            Felt::ZERO,
            Felt::ZERO,
            Felt::from_u8(outgoing),
            Felt::ZERO,
        );
        set_cycle_metadata(
            &mut forged,
            1,
            Felt::ZERO,
            Felt::ZERO,
            Felt::from_u8(incoming),
            Felt::ZERO,
            Felt::from_u8(1 - incoming),
        );
        crate::prover::tests::check_local(EidosCompressionAir, &forged);
        assert_eq!(continuation_balance(&forged).len(), 1);
    }
}

#[test]
fn continuation_link_rejects_padding_with_the_wrong_cv() {
    let mut requires = EidosRequires::new();
    let and = requires.require_absorption(DEFERRED_AND_FRAME, [block(1)]);
    let chunks = requires.require_absorption(deferred_chunks_frame(2), [block(10), block(20)]);
    requires.require_digest(and.digest);
    requires.require_digest(chunks.digest);
    let mut compression = generate_trace(requires);
    assert!(continuation_balance(&compression).is_empty());
    // Keep both flags and head IDs consistent. The padding cycle has zero caller multiplicities,
    // but the unit-weight link still detects its CV mismatch with the preceding compression.
    set_cycle_metadata(&mut compression, 2, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE);
    set_cycle_metadata(
        &mut compression,
        3,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ONE,
        Felt::ZERO,
        Felt::ONE,
    );
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
    assert_eq!(continuation_balance(&compression).len(), 2);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn input_multiplicity_must_match_between_footers() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(10)]);
    requires.require_digest(output.digest);
    let mut compression = generate_trace(requires);

    let start = 30 * NUM_MAIN_COLS;
    set_footer_multiplicity(
        &mut compression.values[start..start + NUM_MAIN_COLS],
        Felt::from_u8(2),
    );
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn fresh_cycle_must_name_its_physical_id_as_chain_head() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(10)]);
    requires.require_digest(output.digest);
    let mut compression = generate_trace(requires);

    set_cycle_metadata(
        &mut compression,
        0,
        Felt::ONE,
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
        Felt::from_u8(7),
    );
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
}

#[test]
fn chain_links_close_at_both_physical_boundaries() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(10)]);
    requires.require_digest(output.digest);
    let compression = generate_trace(requires);
    assert!(continuation_balance(&compression).is_empty());
    for (incoming, outgoing) in [(1, 0), (0, 1), (1, 1)] {
        let mut forged = compression.clone();
        set_cycle_metadata(
            &mut forged,
            0,
            Felt::ZERO,
            Felt::ZERO,
            Felt::from_u8(incoming),
            Felt::from_u8(outgoing),
            Felt::ZERO,
        );
        crate::prover::tests::check_local(EidosCompressionAir, &forged);
        assert!(!continuation_balance(&forged).is_empty());
    }
}

#[test]
fn continuation_cannot_relabel_a_terminal_output_as_a_fresh_chain() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(deferred_chunks_frame(2), [block(10), block(20)]);
    requires.require_digest(output.digest);
    let mut compression = generate_trace(requires);

    // The terminal compression is physical cycle 1, but it belongs to the chain headed at cycle
    // 0. Relabelling it as a one-cycle chain would let callers splice valid native computations if
    // the continuation constraint did not bind the head across the edge.
    assert!(continuation_balance(&compression).is_empty());
    set_cycle_metadata(&mut compression, 1, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ONE);
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
    assert_eq!(continuation_balance(&compression).len(), 2);
}

#[test]
fn splitting_a_valid_chain_changes_its_boundary_relations() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(deferred_chunks_frame(2), [block(10), block(20)]);
    requires.require_digest(output.digest);
    let compression = generate_trace(requires);
    let digest = cycle_digest(&compression, 1);
    let challenges = lookup_challenges();
    let original_output = EidosOutMsg {
        chain_head_id: Felt::ZERO,
        compression_id: Felt::ONE,
        digest,
    }
    .encode(&challenges);
    assert_eq!(net_multiplicity(&eidos_balance(&compression), original_output), -Felt::ONE);

    // The second compression already starts from the first compression's digest, so it is also a
    // locally valid fresh chain. Splitting the chain must nevertheless change the output relation
    // from span (0, 1) to span (1, 1).
    let mut split = compression;
    set_cycle_metadata(&mut split, 0, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO);
    set_cycle_metadata(&mut split, 1, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ONE);
    crate::prover::tests::check_local(EidosCompressionAir, &split);
    assert!(continuation_balance(&split).is_empty());
    let split_report = eidos_balance(&split);
    assert_eq!(net_multiplicity(&split_report, original_output), Felt::ZERO);
    assert_eq!(
        net_multiplicity(
            &split_report,
            EidosOutMsg {
                chain_head_id: Felt::ONE,
                compression_id: Felt::ONE,
                digest,
            }
            .encode(&challenges),
        ),
        -Felt::ONE,
    );
}

#[test]
fn joining_valid_fresh_cycles_changes_their_boundary_relations() {
    let block_a = core::array::from_fn(|idx| 10 + idx as u32);
    let block_b = core::array::from_fn(|idx| 100 + idx as u32);
    let cv_a = core::array::from_fn(|idx| 1_000 + idx as u32);
    let first = generate_felt_trace_block_with_cycle_id(block_a, cv_a, 0);
    let first_digest: [Felt; 4] = core::array::from_fn(|idx| {
        first.rows[EIDOS_COMPRESSION_CYCLE_LEN - 1][footer_digest_col(idx)]
    });
    let second = generate_felt_trace_block_with_cycle_id(block_b, unpack_felts(&first_digest), 1);
    let mut separate = parent_matrix_from_core(&two_cycle_matrix(&first, &second));
    set_cycle_metadata(&mut separate, 0, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO);
    set_cycle_metadata(&mut separate, 1, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ONE);
    crate::prover::tests::check_local(EidosCompressionAir, &separate);

    let second_digest = cycle_digest(&separate, 1);
    let challenges = lookup_challenges();
    let separate_output = EidosOutMsg {
        chain_head_id: Felt::ONE,
        compression_id: Felt::ONE,
        digest: second_digest,
    }
    .encode(&challenges);
    assert_eq!(net_multiplicity(&eidos_balance(&separate), separate_output), -Felt::ONE);

    // The second fresh chain happens to use the first chain's output as its initial CV. Joining the
    // two cycles is therefore locally valid, but its terminal relation must name span (0, 1), not
    // the original one-cycle span (1, 1).
    let mut joined = separate;
    set_cycle_metadata(&mut joined, 0, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ONE, Felt::ZERO);
    set_cycle_metadata(&mut joined, 1, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ZERO, Felt::ZERO);
    crate::prover::tests::check_local(EidosCompressionAir, &joined);
    assert!(continuation_balance(&joined).is_empty());
    let joined_report = eidos_balance(&joined);
    assert_eq!(net_multiplicity(&joined_report, separate_output), Felt::ZERO);
    assert_eq!(
        net_multiplicity(
            &joined_report,
            EidosOutMsg {
                chain_head_id: Felt::ZERO,
                compression_id: Felt::ONE,
                digest: second_digest,
            }
            .encode(&challenges),
        ),
        -Felt::ONE,
    );
}

#[test]
fn block_init_and_output_relations_fire_at_the_expected_chain_boundaries() {
    let mut requires = EidosRequires::new();
    let chunks = requires.require_absorption(deferred_chunks_frame(2), [block(1), block(11)]);
    requires.require_digest(chunks.digest);
    let compression = generate_trace(requires);
    let fractions = build_lookup_fractions(
        &EidosCompressionAir,
        &compression,
        None,
        &EidosCompressionAir.periodic_columns(),
        &lookup_challenges(),
    );

    let counts = |cycle: usize, row: usize, col: usize| {
        let row = cycle * EIDOS_COMPRESSION_CYCLE_LEN + row;
        fractions.counts()[row * NUM_LOOKUP_COLS + INTERFACE_AUX_BEGIN + col]
    };
    assert_eq!([counts(0, 30, 0), counts(0, 30, 1), counts(0, 30, 2)], [0, 1, 0]);
    assert_eq!([counts(1, 30, 0), counts(1, 30, 1), counts(1, 30, 2)], [0, 0, 1]);
    assert_eq!([counts(0, 31, 0), counts(0, 31, 1), counts(0, 31, 2)], [1, 0, 1]);
    assert_eq!([counts(1, 31, 0), counts(1, 31, 1), counts(1, 31, 2)], [1, 1, 0]);
}

#[test]
#[should_panic(expected = "constraint not satisfied")]
fn native_eidos_compression_core_witness_is_not_a_free_bridge_input() {
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(1)]);
    requires.require_digest(output.digest);
    let mut compression = generate_trace(requires);

    let row = FOOTER_START + 1;
    compression.values[row * NUM_MAIN_COLS + footer_r_col(1, 0)] += Felt::ONE;
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
}

#[test]
fn continuation_lookup_binds_previous_digest_even_with_zero_input_multiplicity() {
    let second_block = block(11);
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(deferred_chunks_frame(2), [block(1), second_block]);
    requires.require_digest(output.digest);
    let mut compression = generate_trace(requires);

    // Replace the second compression with a separately valid native Eidos compression cycle using a
    // forged input CV, and keep its footer metadata self-consistent. The only
    // broken fact is the physical carry from cycle 0's Eidos compression output into cycle 1's
    // Eidos compression input.
    let first_footer = EIDOS_COMPRESSION_CYCLE_LEN - 1;
    let mut forged_cv: [Felt; 4] = core::array::from_fn(|i| {
        compression.values[first_footer * NUM_MAIN_COLS + footer_digest_col(i)]
    });
    forged_cv[0] += Felt::ONE;
    let (block_lo, block_hi) = second_block;
    let mut state = [Felt::ZERO; 12];
    state[..4].copy_from_slice(&block_lo);
    state[4..8].copy_from_slice(&block_hi);
    state[8..].copy_from_slice(&forged_cv);
    let forged = generate_felt_trace_block_with_cycle_id(
        unpack_felts::<16>(&state[..8]),
        unpack_felts::<8>(&forged_cv),
        1,
    );

    for (row, forged_row) in forged.rows.iter().enumerate() {
        let dst = (EIDOS_COMPRESSION_CYCLE_LEN + row) * NUM_MAIN_COLS;
        compression.values[dst..dst + NUM_EIDOS_COMPRESSION_COLS].copy_from_slice(forged_row);
    }

    set_cycle_metadata(
        &mut compression,
        1,
        Felt::ONE,
        Felt::ONE,
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
    );
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
    // Set the continuation's caller multiplicity to zero. Its internal CV link must still
    // consume exactly once and cannot be disabled by the external request count.
    set_cycle_metadata(
        &mut compression,
        1,
        Felt::ZERO,
        Felt::ZERO,
        Felt::ONE,
        Felt::ZERO,
        Felt::ZERO,
    );
    crate::prover::tests::check_local(EidosCompressionAir, &compression);
    let balance = eidos_balance(&compression);
    let encode = |cv: [Felt; 4]| {
        lookup_challenges()
            .encode(INTERNAL_CV_BUS_ID, [Felt::ONE, Felt::ZERO, cv[0], cv[1], cv[2], cv[3]])
    };
    assert_eq!(net_multiplicity(&balance, encode(cycle_digest(&compression, 0))), Felt::ONE);
    assert_eq!(net_multiplicity(&balance, encode(forged_cv)), -Felt::ONE);
}

#[test]
fn initial_cv_lookup_footer_binds_its_two_additional_words() {
    use {
        miden_air_definitions::shared::eidos::footer_cv_word,
        miden_air_definitions::shared::eidos::trace::write_full_felt_footer_cv,
    };
    let mut requires = EidosRequires::new();
    let output = requires.require_absorption(DEFERRED_AND_FRAME, [block(1)]);
    requires.require_digest(output.digest);
    let original = generate_trace(requires);
    for word in 6..8 {
        let mut forged = original.clone();
        let start = (EIDOS_COMPRESSION_CYCLE_LEN - 2) * NUM_MAIN_COLS;
        let mut row: [Felt; NUM_EIDOS_COMPRESSION_COLS] =
            forged.values[start..start + NUM_EIDOS_COMPRESSION_COLS].try_into().unwrap();
        let mut cv =
            core::array::from_fn(|i| footer_cv_word(|col| row[col], i).as_canonical_u64() as u32);
        cv[word] ^= 1;
        // Re-encode all eight words so the six shared prefix bindings remain satisfied.
        write_full_felt_footer_cv(&mut row, cv);
        forged.values[start..start + NUM_EIDOS_COMPRESSION_COLS].copy_from_slice(&row);
        crate::prover::tests::assert_local_rejects(EidosCompressionAir, &forged);
    }
}
