//! Cross-chiplet bus-balance helpers shared by integration and DAG tests.

use std::{collections::HashMap, fmt::Debug};

use miden_air::lookup::{
    Challenges, LookupAir,
    debug::{check_trace_balance, trace::DebugTraceBuilder},
};
use miden_core::{Felt, field::QuadFelt};
use miden_lifted_air::LiftedAir;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::{EcPointStoreAir, add::EcGroupAddAir, groups::EcGroupsAir, msm::EcMsmAir},
    hash::{
        chunk::ChunkAir,
        keccak::{node::KeccakNodeAir, round::KeccakRoundAir, sponge::KeccakSpongeAir},
    },
    logup::LookupMessage,
    primitives::{bitwise64::Bitwise64Air, byte_pair_lut::BytePairLutAir},
    session::{ChipletAir, NUM_CHIPLETS, fixed_ecgroup_msgs, fixed_uintval_msgs},
    transcript::{eval::TranscriptEvalAir, poseidon2::Poseidon2Air},
    uint::{UintStoreAir, add::UintAddAir, mul::UintMulAir},
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
    let combined = crate::tests::combined_lookup_main(air, main);
    let lookup_main = combined.as_ref().unwrap_or(main);
    let report = check_trace_balance(air, lookup_main, &periodic, &[], &[], challenges);
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

pub(crate) fn fold_fixed_group_external_balance(
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) {
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
    for (idx, air) in ChipletAir::all().into_iter().enumerate() {
        let main = replacements
            .iter()
            .find_map(|(replacement_idx, main)| (*replacement_idx == idx).then_some(*main))
            .unwrap_or(mains[idx]);
        match air {
            ChipletAir::Chunk => fold_balance(&ChunkAir, main, challenges, &mut net),
            ChipletAir::Poseidon2 => fold_balance(&Poseidon2Air, main, challenges, &mut net),
            ChipletAir::KeccakRound => fold_balance(&KeccakRoundAir, main, challenges, &mut net),
            ChipletAir::Bitwise64 => fold_balance(&Bitwise64Air, main, challenges, &mut net),
            ChipletAir::BytePairLut => fold_balance(&BytePairLutAir, main, challenges, &mut net),
            ChipletAir::KeccakSponge => fold_balance(&KeccakSpongeAir, main, challenges, &mut net),
            ChipletAir::KeccakNode => fold_balance(&KeccakNodeAir, main, challenges, &mut net),
            ChipletAir::TranscriptEval => {
                fold_balance(&TranscriptEvalAir, main, challenges, &mut net)
            },
            ChipletAir::UintStore => fold_balance(&UintStoreAir, main, challenges, &mut net),
            ChipletAir::UintAdd => fold_balance(&UintAddAir, main, challenges, &mut net),
            ChipletAir::UintMul => fold_balance(&UintMulAir, main, challenges, &mut net),
            ChipletAir::EcGroups => fold_balance(&EcGroupsAir, main, challenges, &mut net),
            ChipletAir::EcPointStore => fold_balance(&EcPointStoreAir, main, challenges, &mut net),
            ChipletAir::EcGroupAdd => fold_balance(&EcGroupAddAir, main, challenges, &mut net),
            ChipletAir::EcMsm => fold_balance(&EcMsmAir, main, challenges, &mut net),
        }
    }
    fold_fixed_boundary_external_balance(challenges, &mut net);
    net.into_values().filter(|(m, _)| *m != Felt::ZERO).collect()
}
