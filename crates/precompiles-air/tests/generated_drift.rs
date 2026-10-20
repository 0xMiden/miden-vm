//! Generated PVM evaluators are checked against the concrete handwritten AIRs.
//!
//! Comparing to concrete AIR types keeps the oracle independent of both enum dispatch paths.
//! The shared compiler checks expression structure, assertion order and arbitrary field values.

use miden_constraint_compiler::testing::{
    assert_distinct_captures, assert_evaluations_match, assert_structurally_equivalent,
};
use miden_precompiles_air::{
    ChipletAir, HandwrittenChipletAir,
    ec::{add::EcGroupAddAir, msm::EcMsmAir, point_store_groups::EcPointStoreGroupsAir},
    hash::{
        chunk_node_sponge::ChunkNodeSpongeAir, keccak::round::KeccakRoundAir, sha256::Sha256Air,
        sha512::Sha512Air,
    },
    primitives::byte_pair_lut::BytePairLutAir,
    transcript::{eidos::EidosCompressionAir, eval::TranscriptEvalAir},
    uint::{add::UintAddAir, store_mul::UintStoreMulAir},
};

macro_rules! check_air {
    ($test:ident, $variant:ident, $source:expr) => {
        #[test]
        fn $test() {
            let air = ChipletAir::$variant;
            let handwritten = HandwrittenChipletAir(air.clone());
            assert_distinct_captures(&handwritten, &air);
            assert_structurally_equivalent(&$source, &handwritten);
            assert_structurally_equivalent(&$source, &air);
            assert_evaluations_match(&$source, &air);
        }
    };
}

check_air!(chunk_node_sponge, ChunkNodeSponge, ChunkNodeSpongeAir);
check_air!(eidos_compression, EidosCompression, EidosCompressionAir);
check_air!(keccak_round, KeccakRound, KeccakRoundAir);
check_air!(byte_pair_lut, BytePairLut, BytePairLutAir);
check_air!(transcript_eval, TranscriptEval, TranscriptEvalAir);
check_air!(uint_store_mul, UintStoreMul, UintStoreMulAir);
check_air!(uint_add, UintAdd, UintAddAir);
check_air!(ec_point_store_groups, EcPointStoreGroups, EcPointStoreGroupsAir);
check_air!(ec_group_add, EcGroupAdd, EcGroupAddAir);
check_air!(ec_msm, EcMsm, EcMsmAir);
check_air!(sha512, Sha512, Sha512Air);
check_air!(sha256, Sha256, Sha256Air);
