//! Cross-chiplet bus-balance helpers shared by integration and DAG tests.

use std::{collections::HashMap, fmt::Debug, format, string::String, vec::Vec};

use miden_air::lookup::{Challenges, LookupAir, ProverLookupBuilder, build_lookup_fractions};
use miden_core::{
    Felt,
    field::QuadFelt,
    utils::{Matrix, RowMajorMatrix},
};
use miden_lifted_air::{BaseAir, LiftedAir};

use crate::{
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    logup::LookupMessage,
    primitives::byte_pair_lut::BytePairLutAir,
    session::{ChipletAir, NUM_CHIPLETS, fixed_ecgroup_msgs, fixed_uintval_msgs},
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

#[test]
fn hash_airs_preserve_the_deployed_quotient_degree() {
    // Both hash AIRs must fit the existing blowup/folding parameters.
    assert_eq!(crate::tests::log_quotient_degree(&ChunkNodeSpongeAir), 2);
    assert_eq!(crate::tests::log_quotient_degree(&Sha512Air), 2);
}

#[test]
fn sha512_reuses_compression_padding_for_io() {
    // IO needs only sixteen rows per block. It must share both witness and lookup columns
    // with compression instead of adding a mostly empty band to all 4096 rows.
    assert_eq!(Sha512Air.width(), 61);
    assert_eq!(Sha512Air.aux_width(), 18);
    assert_eq!(NUM_CHIPLETS, 12);
    assert_eq!(crate::tests::log_quotient_degree(&Sha512Air), 2);
}

#[test]
fn sha256_reuses_compression_padding_for_io() {
    // IO needs only thirty-two rows per block. It must share both witness and lookup columns
    // with compression instead of adding a mostly empty band to all 4096 rows.
    assert_eq!(Sha256Air.width(), 40);
    assert_eq!(Sha256Air.aux_width(), 11);
    assert_eq!(NUM_CHIPLETS, 12);
    assert_eq!(crate::tests::log_quotient_degree(&Sha256Air), 2);
}

#[test]
fn keccak_only_does_not_pay_for_sha512_block_padding() {
    let mut session = crate::session::Session::new();
    let (_, claim) = session.keccak(b"abc");
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    assert_eq!(traces.mains()[0].height(), 32);
}

#[test]
fn sha256_only_and_sha512_only_sessions_leave_the_other_chiplet_empty() {
    // One block of either SHA must not force the other SHA's chiplet past its metadata period.
    const SHA256: usize = NUM_CHIPLETS - 1;
    const SHA512: usize = NUM_CHIPLETS - 2;
    for (use_sha256, used, empty) in [(true, SHA256, SHA512), (false, SHA512, SHA256)] {
        let mut session = crate::session::Session::new();
        let claim = if use_sha256 {
            session.sha256(b"abc").1
        } else {
            session.sha512(b"abc").1
        };
        let root = session.assert_and_fold([claim]);
        let traces = session.finish(root);
        let mains = traces.mains();
        assert_eq!(mains[used].height(), 4096);
        assert_eq!(mains[empty].height(), 128);
    }
}

#[test]
fn hash_trace_heights_follow_each_hashers_work() {
    // An empty SHA AIR needs only its metadata period. No hash may force another one's column
    // bands to its height, including when Keccak is the larger workload.
    for (
        keccak_len,
        sha512_len,
        sha256_len,
        expected_keccak_height,
        expected_sha512_height,
        expected_sha256_height,
    ) in [
        (3, None, None, 32, 128, 128),
        (136 * 128, Some(3), None, 8192, 4096, 128),
        (3, Some(256), None, 32, 16384, 128),
        (3, None, Some(200), 32, 128, 16384),
        (136 * 128, Some(3), Some(3), 8192, 4096, 4096),
    ] {
        let mut session = crate::session::Session::new();
        let (_, keccak) = session.keccak(&std::vec![0x61; keccak_len]);
        let mut claims = std::vec![keccak];
        if let Some(len) = sha512_len {
            claims.push(session.sha512(&std::vec![0x62; len]).1);
        }
        if let Some(len) = sha256_len {
            claims.push(session.sha256(&std::vec![0x63; len]).1);
        }
        let root = session.assert_and_fold(claims);
        let traces = session.finish(root);
        let mains = traces.mains();
        assert_eq!(mains[0].height(), expected_keccak_height);
        assert_eq!(mains[NUM_CHIPLETS - 2].height(), expected_sha512_height);
        assert_eq!(mains[NUM_CHIPLETS - 1].height(), expected_sha256_height);
    }
}

/// Fold one chiplet's per-denominator balance into the cross-chiplet accumulator.
///
/// `net[denom] = (multiplicity summed across chiplets, sample AIR type for diagnostics)`.
pub(crate) fn fold_balance<A>(
    air: &A,
    main: &RowMajorMatrix<Felt>,
    challenges: &Challenges<QuadFelt>,
    net: &mut HashMap<QuadFelt, (Felt, String)>,
) where
    A: LiftedAir<Felt, QuadFelt> + Sync,
    for<'a> A: LookupAir<ProverLookupBuilder<'a, Felt, QuadFelt>>,
{
    let periodic = air.periodic_columns();
    let preprocessed = air.preprocessed_trace();
    let fractions = build_lookup_fractions(air, main, preprocessed.as_ref(), &periodic, challenges);
    for &(multiplicity, denom) in fractions.fractions() {
        net.entry(denom)
            .or_insert_with(|| (Felt::ZERO, core::any::type_name::<A>().into()))
            .0 += multiplicity;
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
pub(crate) fn session_stack_net(
    mains: &[&RowMajorMatrix<Felt>; NUM_CHIPLETS],
    replacements: &[(usize, &RowMajorMatrix<Felt>)],
    challenges: &Challenges<QuadFelt>,
) -> HashMap<QuadFelt, (Felt, String)> {
    let mut net = HashMap::new();
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
                fold_balance(&EidosCompressionAir, main, challenges, &mut net)
            },
            ChipletAir::KeccakRound => fold_balance(&KeccakRoundAir, main, challenges, &mut net),
            ChipletAir::BytePairLut => fold_balance(&BytePairLutAir, main, challenges, &mut net),
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
            ChipletAir::Sha512 => fold_balance(&Sha512Air, main, challenges, &mut net),
            ChipletAir::Sha256 => fold_balance(&Sha256Air, main, challenges, &mut net),
        }
    }
    fold_fixed_boundary_external_balance(challenges, &mut net);
    net
}

/// Return the nonzero entries from the canonical full session stack balance.
pub(crate) fn session_stack_residual(
    mains: &[&RowMajorMatrix<Felt>; NUM_CHIPLETS],
    replacements: &[(usize, &RowMajorMatrix<Felt>)],
    challenges: &Challenges<QuadFelt>,
) -> Vec<(Felt, String)> {
    session_stack_net(mains, replacements, challenges)
        .into_values()
        .filter(|(m, _)| *m != Felt::ZERO)
        .collect()
}
