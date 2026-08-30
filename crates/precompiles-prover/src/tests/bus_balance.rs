//! Cross-chiplet bus-balance helpers shared by integration and DAG tests.

use std::{collections::HashMap, fmt::Debug, format, string::String, vec::Vec};

use miden_air::{
    MidenAir,
    logup::{BusId as MidenBusId, MIDEN_MAX_MESSAGE_WIDTH},
    lookup::{
        Challenges, LookupAir,
        debug::{check_trace_balance, trace::DebugTraceBuilder},
    },
};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_lifted_air::LiftedAir;

use crate::{
    composite::extract_band,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir},
    logup::LookupMessage,
    primitives::byte_pair_lut::{BytePairLutAir, NUM_MAIN_COLS as BPL_MAIN_COLS},
    session::{ChipletAir, NUM_CHIPLETS, fixed_ecgroup_msgs, fixed_uintval_msgs},
    transcript::{
        eidos::{
            COL_EIDOS_COMPRESSION_END, EidosCompressionInterfaceAir, EidosCompressionNarrowAir,
        },
        eval::TranscriptEvalAir,
    },
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

/// Fold one chiplet's per-denominator balance into the cross-chiplet accumulator.
///
/// `net[denom] = (multiplicity summed across chiplets, sample message repr for diagnostics)`.
pub(crate) fn fold_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) where
    A: LiftedAir<Felt, QuadFelt>,
    for<'a> A: LookupAir<DebugTraceBuilder<'a>>,
{
    let periodic = air.periodic_columns();
    let report = check_trace_balance(air, main, &periodic, &[], &[], challenges);
    for u in report.unmatched {
        let entry = net.entry(u.denom).or_insert((Felt::ZERO, String::new()));
        entry.0 += u.net_multiplicity;
        if entry.1.is_empty()
            && let Some(c) = u.contributions.first()
        {
            entry.1 = c.msg_repr.clone();
        }
    }
}

/// Fold verifier-side fixed-environment boundary consumes into the accumulator.
pub(crate) fn fold_fixed_boundary_external_balance(
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) {
    fold_fixed_messages(challenges, net, fixed_uintval_msgs());
    fold_fixed_messages(challenges, net, fixed_ecgroup_msgs());
}

fn fold_fixed_messages<M>(
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
    messages: impl IntoIterator<Item = M>,
) where
    M: Debug + LookupMessage<Felt, QuadFelt>,
{
    for msg in messages {
        let entry = net.entry(msg.encode(challenges)).or_insert((Felt::ZERO, String::new()));
        entry.0 += Felt::ONE;
        if entry.1.is_empty() {
            entry.1 = format!("fixed boundary external {msg:?}");
        }
    }
}

/// Net the canonical full session stack, including verifier-side fixed-boundary consumes.
pub(crate) fn session_stack_residual(
    mains: &[&RowMajorMatrix<Felt>; NUM_CHIPLETS],
    replacements: &[(usize, &RowMajorMatrix<Felt>)],
    challenges: &Challenges<QuadFelt>,
) -> Vec<(Felt, String)> {
    let mut net = HashMap::new();
    let miden_challenges = Challenges::new(
        challenges.alpha,
        challenges.beta_powers[1],
        MIDEN_MAX_MESSAGE_WIDTH,
        MidenBusId::COUNT,
    );
    for (idx, air) in ChipletAir::all().into_iter().enumerate() {
        let main = replacements
            .iter()
            .find_map(|(replacement_idx, main)| (*replacement_idx == idx).then_some(*main))
            .unwrap_or(mains[idx]);
        match air {
            ChipletAir::ChunkNodeSponge => {
                fold_balance(&ChunkNodeSpongeAir, main, challenges, &mut net)
            },
            ChipletAir::EidosCompression => {
                fold_balance(&EidosCompressionInterfaceAir, main, challenges, &mut net);
                let eidos_compression = extract_band(main, 0..COL_EIDOS_COMPRESSION_END);
                fold_balance(
                    &EidosCompressionNarrowAir,
                    &eidos_compression,
                    &miden_challenges,
                    &mut net,
                );
            },
            ChipletAir::KeccakRound => fold_balance(&KeccakRoundAir, main, challenges, &mut net),
            ChipletAir::BytePairAnd8 => {
                let bpl = extract_band(main, 0..BPL_MAIN_COLS);
                let and8 = extract_band(main, BPL_MAIN_COLS..main.width);
                fold_balance(&BytePairLutAir, &bpl, challenges, &mut net);
                fold_balance(&MidenAir::And8Lookup, &and8, &miden_challenges, &mut net);
            },
            ChipletAir::TranscriptEval => {
                fold_balance(&TranscriptEvalAir, main, challenges, &mut net)
            },
            ChipletAir::UintStoreMul => fold_balance(&UintStoreMulAir, main, challenges, &mut net),
            ChipletAir::UintAdd => fold_balance(&UintAddAir, main, challenges, &mut net),
            ChipletAir::EcPointStoreGroups => {
                fold_balance(&EcPointStoreGroupsAir, main, challenges, &mut net)
            },
            ChipletAir::EcGroupAdd => fold_balance(&EcGroupAddAir, main, challenges, &mut net),
            ChipletAir::EcMsm => fold_balance(&EcMsmAir, main, challenges, &mut net),
        }
    }
    fold_fixed_boundary_external_balance(challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).collect()
}
