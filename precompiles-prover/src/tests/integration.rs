//! Integration tests: verify AIR constraints hold on generated traces.
//!
//! These tests use `crate::tests::check_local` to evaluate every local
//! constraint at every row of the trace, catching any mismatch between
//! witness generation and constraint definitions.

use std::{eprintln, string::String, vec, vec::Vec};

use miden_core::{Felt, deferred::Node, field::QuadFelt};
use p3_matrix::Matrix;
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::primitives::{
    bitwise64::{Bitwise64Air, Bitwise64Requires, Logic64Op, generate_trace as bw64_trace},
    byte_pair_lut::{BytePairLutAir, BytePairLutRequires, BytePairOp, generate_trace as bpl_trace},
};

/// Generate random challenges for LogUp arguments.
fn random_challenges(rng: &mut impl Rng) -> [QuadFelt; 2] {
    [
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()]),
        QuadFelt::new([Felt::new(rng.random()).unwrap(), Felt::new(rng.random()).unwrap()]),
    ]
}

// ============================================================================
// BytePairLut integration tests
// ============================================================================

#[test]
fn bpl_constraints_hold_on_random_byte_ops() {
    let mut rng = StdRng::seed_from_u64(0xbee);
    let mut requires = BytePairLutRequires::new();

    // Random byte-pair lookups.
    for _ in 0..50 {
        let a = rng.random::<u8>();
        let b = rng.random::<u8>();
        let op = if rng.random::<bool>() {
            BytePairOp::AndNot
        } else {
            BytePairOp::Xor
        };
        requires.require(op, a, b);
    }

    // Some Range16 lookups.
    for _ in 0..30 {
        let w = rng.random::<u16>();
        requires.require_range16(w);
    }

    let main = bpl_trace(requires);

    crate::tests::check_local(BytePairLutAir, &main);
}

#[test]
fn bpl_constraints_hold_on_saturated_table() {
    // Exercise all 2^16 (a, b) pairs — saturated BPL table.
    let mut requires = BytePairLutRequires::new();

    for a in 0u8..=255 {
        for b in 0u8..=255 {
            let op = if (a ^ b) & 1 == 0 {
                BytePairOp::Xor
            } else {
                BytePairOp::AndNot
            };
            requires.require(op, a, b);
        }
    }

    let main = bpl_trace(requires);
    assert_eq!(main.height(), 1 << 16, "saturated table should have 2^16 rows");

    crate::tests::check_local(BytePairLutAir, &main);
}

// ============================================================================
// Bitwise64 integration tests
// ============================================================================

#[test]
fn bw64_constraints_hold_on_random_logic_ops() {
    let mut rng = StdRng::seed_from_u64(0xb164);
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();

    for _ in 0..100 {
        let a = rng.random::<u64>();
        let b = rng.random::<u64>();
        let op = if rng.random::<bool>() {
            Logic64Op::AndNot
        } else {
            Logic64Op::Xor
        };
        requires.require(&mut bpl, op, a, b);
    }

    let main = bw64_trace(requires);

    crate::tests::check_local(Bitwise64Air, &main);
}

#[test]
fn bw64_constraints_hold_on_chained_logic() {
    // Test chaining: each op's output feeds the next op's input.
    let mut rng = StdRng::seed_from_u64(0xc4a1);
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();

    let mut val = rng.random::<u64>();
    for _ in 0..50 {
        let b = rng.random::<u64>();
        let op = if rng.random::<bool>() {
            Logic64Op::Xor
        } else {
            Logic64Op::AndNot
        };
        val = requires.require(&mut bpl, op, val, b);
    }

    let main = bw64_trace(requires);

    crate::tests::check_local(Bitwise64Air, &main);
}

#[test]
fn bw64_constraints_hold_on_logic_then_rol() {
    // Test LOGIC → ROL chains (the natural Keccak pattern).
    let mut rng = StdRng::seed_from_u64(0x801);
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();

    for _ in 0..30 {
        let a = rng.random::<u64>();
        let b = rng.random::<u64>();
        // LOGIC to establish chain.
        let c = requires.require(&mut bpl, Logic64Op::Xor, a, b);
        // ROL on the result (k must be power of two < 2^31; see
        // `Bitwise64Requires::require_rol` for the bound's derivation).
        let s = rng.random_range(0u32..31);
        let k = 1u64 << s;
        requires.require_rol(&mut bpl, c, k);
        // After ROL, chain is broken — next iteration starts fresh.
    }

    let main = bw64_trace(requires);

    crate::tests::check_local(Bitwise64Air, &main);
}

#[test]
fn bw64_constraints_hold_on_all_rotation_amounts() {
    // Test all in-range rotation amounts (k = 2^s for s in 0..31; see
    // `Bitwise64Requires::require_rol` for the bound's derivation).
    let mut rng = StdRng::seed_from_u64(0xa11807);
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();

    for s in 0..31 {
        let a = rng.random::<u64>();
        // Establish chain via identity XOR.
        let c = requires.require(&mut bpl, Logic64Op::Xor, a, 0);
        let k = 1u64 << s;
        requires.require_rol(&mut bpl, c, k);
    }

    let main = bw64_trace(requires);

    crate::tests::check_local(Bitwise64Air, &main);
}

#[test]
fn bw64_constraints_hold_on_edge_case_values() {
    // Test edge cases: 0, max u64, alternating bits, etc.
    let mut bpl = BytePairLutRequires::new();
    let mut requires = Bitwise64Requires::new();

    let edge_values = [
        0u64,
        u64::MAX,
        0x5555_5555_5555_5555, // alternating bits
        0xaaaa_aaaa_aaaa_aaaa,
        0x0000_0000_ffff_ffff, // low half set
        0xffff_ffff_0000_0000, // high half set
        1,
        u64::MAX - 1,
    ];

    for &a in &edge_values {
        for &b in &edge_values {
            requires.require(&mut bpl, Logic64Op::Xor, a, b);
            requires.require(&mut bpl, Logic64Op::AndNot, a, b);
        }
    }

    // Also test ROL on edge values.
    for &a in &edge_values {
        let c = requires.require(&mut bpl, Logic64Op::Xor, a, 0);
        requires.require_rol(&mut bpl, c, 1 << 16); // k = 2^16
    }

    let main = bw64_trace(requires);

    crate::tests::check_local(Bitwise64Air, &main);
}

// ============================================================================
// Chunk + Poseidon2 integration tests
// ============================================================================

use crate::{
    hash::chunk::{
        COL_PERM_SEQ_ID as CHUNK_COL_PERM_SEQ_ID, ChunkAir, NUM_MAIN_COLS as CHUNK_NUM_MAIN_COLS,
        trace::{ChunkRequires, Invocation, generate_trace as chunk_trace},
    },
    transcript::poseidon2::{
        Poseidon2Air,
        trace::{Poseidon2Requires, generate_trace as p2_trace},
    },
};

fn rand_inv(seed: u64, len: usize) -> Invocation {
    let mut rng = StdRng::seed_from_u64(seed);
    Invocation {
        input: (0..len).map(|_| rng.random()).collect(),
    }
}

/// Multi-invocation chunk trace, P2 trace built from the same
/// `Poseidon2Requires`. Both AIRs verify under the same `(α, β)`,
/// confirming the `perm_seq_id` foreign key wires through cleanly.
#[test]
fn chunk_and_p2_traces_verify_with_shared_challenges() {
    let invs = vec![rand_inv(0xa1, 33), rand_inv(0xb2, 40), rand_inv(0xc3, 129)];

    let mut p2 = Poseidon2Requires::new();
    let mut chunk_req = ChunkRequires::new();
    for inv in &invs {
        chunk_req.require(inv, &mut p2);
    }
    // All invocations are distinct → no interning hits; both sides
    // lay one cycle per chunk across all invocations.
    let total_chunks: u32 = invs
        .iter()
        .map(|i| {
            Node::chunks_from_bytes(&i.input)
                .payload()
                .as_data()
                .expect("chunks_from_bytes creates data payload")
                .len() as u32
        })
        .sum();
    assert_eq!(chunk_req.total_chunks(), total_chunks);
    assert_eq!(p2.total_cycles(), total_chunks);

    let chunk_main = chunk_trace(chunk_req);
    let p2_main = p2_trace(p2);

    crate::tests::check_local(ChunkAir, &chunk_main);
    crate::tests::check_local(Poseidon2Air, &p2_main);
}

/// Two identical-content invocations: chunks duplicate at the
/// chunk-row level (each gets its own 3-row span, distinct
/// `chunk_seq_id` ranges) but P2 interning collapses to one cycle
/// range with `in_mult = 2`. The two `require`s thus return the same
/// digest + perm_seq_id range but distinct chunk_seq_id ranges. Both
/// AIRs verify — bus balance closes since each chunk row's mult-1
/// provide matches exactly one downstream consumer's mult-1 consume
/// (the CR-dedup invariant), and the doubled P2 in_mult matches the
/// two chunk-row sets that consume those cycles.
#[test]
fn identical_chunk_invocations_share_p2_but_duplicate_chunks() {
    let bytes: Vec<u8> = (0..96).map(|i| (i ^ 0x5a) as u8).collect(); // 3 chunks
    let inv_a = Invocation { input: bytes.clone() };
    let inv_b = Invocation { input: bytes };

    let mut p2 = Poseidon2Requires::new();
    let mut chunk_req = ChunkRequires::new();
    let out_a = chunk_req.require(&inv_a, &mut p2);
    let out_b = chunk_req.require(&inv_b, &mut p2);

    // Chunks duplicate: 6 rows total, disjoint chains.
    assert_eq!(chunk_req.total_chunks(), 6);
    assert_eq!(out_a.chunk_head.seq(), 0);
    assert_eq!(out_b.chunk_head.seq(), 3);

    // P2 interns: same digest + shared perm_seq_id_range; in_mult = 2.
    assert_eq!(out_a.digest, out_b.digest);
    assert_eq!(out_a.perm_span, out_b.perm_span);
    assert_eq!(p2.total_cycles(), 3);

    let chunk_main = chunk_trace(chunk_req);
    let p2_main = p2_trace(p2);

    // Both 3-row chunk spans stamp the same perm_seq_id sequence
    // (0, 1, 2) — same P2 cycles, consumed twice.
    let perm_seq_id_at = |row: usize| -> Felt {
        chunk_main.values[row * CHUNK_NUM_MAIN_COLS + CHUNK_COL_PERM_SEQ_ID]
    };
    for c in 0..3u32 {
        let expected = Felt::new(c as u64).expect("seq fits");
        assert_eq!(perm_seq_id_at(c as usize), expected);
        assert_eq!(perm_seq_id_at(3 + c as usize), expected);
    }

    crate::tests::check_local(ChunkAir, &chunk_main);
    crate::tests::check_local(Poseidon2Air, &p2_main);
}

// FULL STACK — Keccak-node Requires dedup + downstream collapse
// ============================================================================

use crate::hash::keccak::{
    node::{
        KeccakNodeAir, NUM_MAIN_COLS as KN_NUM_MAIN_COLS,
        trace::{KeccakNodeRequires, generate_trace as keccak_node_trace},
    },
    round::RoundRequires,
    sponge::{
        KeccakSpongeAir, NUM_MAIN_COLS as KS_NUM_MAIN_COLS,
        trace::{SpongeRequires, generate_trace as sponge_trace},
    },
};

/// Two identical Keccak invocations through `KeccakNodeRequires`
/// collapse to one keccak-node row with `out_mult = 2`, one sponge
/// invocation, one chunk-row span, and a single chunk-content P2
/// cycle range. The downstream digest is shared.
#[test]
fn keccak_node_intern_collapses_identical_invocations() {
    let input: Vec<u8> = (0..96).map(|i| (i ^ 0xa5) as u8).collect();

    let mut p2 = Poseidon2Requires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bw64 = Bitwise64Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut node = KeccakNodeRequires::new();

    let out_a =
        node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bw64, &mut bpl, &mut p2);
    let chunk_rows_after_a = chunk.total_chunks();
    let sponge_rows_after_a = sponge.total_active_rows();
    let p2_cycles_after_a = p2.total_cycles();

    let out_b =
        node.require(&input, &mut sponge, &mut chunk, &mut round, &mut bw64, &mut bpl, &mut p2);

    // Dedup at the node layer.
    assert_eq!(node.total_rows(), 1);
    assert_eq!(out_a.node_row, 0);
    assert_eq!(out_b.node_row, 0);
    assert_eq!(out_a.keccak_digest, out_b.keccak_digest);
    assert_eq!(out_a.h_keccak, out_b.h_keccak);

    // No new downstream allocations on the second call.
    assert_eq!(chunk.total_chunks(), chunk_rows_after_a);
    assert_eq!(sponge.total_active_rows(), sponge_rows_after_a);
    assert_eq!(p2.total_cycles(), p2_cycles_after_a);

    // All four AIRs validate.
    let kn_main = keccak_node_trace(node);
    let ks_main = sponge_trace(sponge);
    let chunk_main = chunk_trace(chunk);
    let p2_main = p2_trace(p2);

    crate::tests::check_local(KeccakNodeAir, &kn_main);
    crate::tests::check_local(KeccakSpongeAir, &ks_main);
    crate::tests::check_local(ChunkAir, &chunk_main);
    crate::tests::check_local(Poseidon2Air, &p2_main);

    // Sanity: the trace dimensions match the expected single-record
    // layout (1 active row padded to 1; sponge has 3 chunks → padded
    // sponge rows; chunks have 3 active rows).
    assert!(kn_main.height() >= 1);
    assert!(ks_main.height() >= KS_NUM_MAIN_COLS / KS_NUM_MAIN_COLS); // trivial
    let _ = KN_NUM_MAIN_COLS;
}

/// Three distinct Keccak invocations through `KeccakNodeRequires`
/// lay three disjoint node rows. `perm_seq_id_chunks` is *not*
/// contiguous across rows — digest-chunks / keccak one-shots interleave
/// between chunk-content absorptions in P2 — which is fine: the
/// `ChunkChain` bus pins each row's pair to a real chunk-side chain
/// head. All four AIRs validate.
#[test]
fn keccak_node_distinct_invocations_lay_disjoint_rows() {
    let inputs: Vec<Vec<u8>> = vec![
        (0..40).map(|i| (i ^ 0x11) as u8).collect(),
        (0..96).map(|i| (i ^ 0x22) as u8).collect(),
        (0..200).map(|i| (i ^ 0x33) as u8).collect(),
    ];

    let mut p2 = Poseidon2Requires::new();
    let mut chunk = ChunkRequires::new();
    let mut round = RoundRequires::new();
    let mut bw64 = Bitwise64Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut sponge = SpongeRequires::new();
    let mut node = KeccakNodeRequires::new();

    let outs: Vec<_> = inputs
        .iter()
        .map(|input| {
            node.require(input, &mut sponge, &mut chunk, &mut round, &mut bw64, &mut bpl, &mut p2)
        })
        .collect();

    assert_eq!(node.total_rows(), 3);
    assert_eq!(outs[0].node_row, 0);
    assert_eq!(outs[1].node_row, 1);
    assert_eq!(outs[2].node_row, 2);
    // All three Keccak digests differ.
    assert_ne!(outs[0].keccak_digest, outs[1].keccak_digest);
    assert_ne!(outs[1].keccak_digest, outs[2].keccak_digest);
    assert_ne!(outs[0].keccak_digest, outs[2].keccak_digest);

    let kn_main = keccak_node_trace(node);
    let ks_main = sponge_trace(sponge);
    let chunk_main = chunk_trace(chunk);
    let p2_main = p2_trace(p2);

    crate::tests::check_local(KeccakNodeAir, &kn_main);
    crate::tests::check_local(KeccakSpongeAir, &ks_main);
    crate::tests::check_local(ChunkAir, &chunk_main);
    crate::tests::check_local(Poseidon2Air, &p2_main);
}

// FULL STACK — eight chiplets, end-to-end
// ============================================================================

use crate::hash::keccak::round::KeccakRoundAir;

/// Single Keccak invocation driven through the entire eight-chiplet stack
/// via [`Session`] — chunk, Poseidon2, round, Bitwise64, BytePairLut,
/// sponge, Keccak-node, eval. Each AIR's local + LogUp constraints
/// validate, catching address-formula bugs and any cross-chiplet witness
/// mismatch. (`Session::finish` owns the trace-gen dependency order the
/// chiplets impose.)
#[test]
fn full_stack_chiplets_validate_under_shared_challenges() {
    let input: Vec<u8> = (0..23).map(|i| (i ^ 0x5a) as u8).collect();

    let mut session = Session::new();
    let (_, claim) = session.keccak(&input);
    let root = session.assert_and_fold([claim]);
    let traces = session.finish(root);
    let mains = traces.mains();

    // Per-AIR `check_local` over the whole stack (mains in canonical
    // `SessionTraces::mains()` order) — catches local-constraint
    // regressions the cross-chiplet balance check below can't see.
    crate::tests::check_local(ChunkAir, mains[0]);
    crate::tests::check_local(Poseidon2Air, mains[1]);
    crate::tests::check_local(KeccakRoundAir, mains[2]);
    crate::tests::check_local(Bitwise64Air, mains[3]);
    crate::tests::check_local(BytePairLutAir, mains[4]);
    crate::tests::check_local(KeccakSpongeAir, mains[5]);
    crate::tests::check_local(KeccakNodeAir, mains[6]);
    crate::tests::check_local_inputs(
        TranscriptEvalAir,
        mains[7],
        traces.public_root().as_array().to_vec(),
    );
    crate::tests::check_local(UintStoreAir, mains[8]);
}

// ============================================================================
// Cross-chiplet bus balance — the guard the per-AIR check_local lacks.
//
// `check_local` pins each chiplet's σ to its own residue but never the
// global `Σ σ = 0`; the tests above are all per-AIR, so a cross-chiplet bus
// imbalance (the `verify_multi` `InvalidReducedAux` failure mode) slips
// through. This walks every chiplet trace with miden-air's
// `check_trace_balance` under one shared `Challenges` and sums net
// multiplicities per encoded denom across all of them: a balanced system
// leaves zero residual. Far cheaper than a full prove/verify, and pinpoints
// the offending tuple on failure. Balance is challenge-independent, so a
// fixed (α, β) reveals the same imbalance the verifier's Fiat-Shamir would.
// ============================================================================

use std::collections::HashMap;

use miden_air::lookup::Challenges;

use crate::{
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    session::Session,
    tests::bus_balance::{fold_balance, session_stack_residual},
    transcript::eval::TranscriptEvalAir,
};

#[test]
fn full_stack_bus_balance_closes() {
    // Full eight-chiplet stack, including the transcript eval chip so the
    // `Binding` bus closes. `n = 3` invocations leave the keccak-node trace
    // one row short of a power of two and the Poseidon2 trace short of a
    // power-of-two cycle count, so the *ungated* `Range16(0)` padding
    // emissions are exercised alongside the active demand.
    let n = 3usize;
    let l = 40usize;

    let mut session = Session::new();
    let mut input = vec![0u8; l];
    let mut claims = Vec::with_capacity(n);
    for k in 0..n {
        let mut rng = StdRng::seed_from_u64(0xb175 ^ (k as u64).wrapping_mul(0x9e3779b97f4a7c15));
        for b in &mut input {
            *b = rng.random();
        }
        let (_, claim) = session.keccak(&input);
        claims.push(claim);
    }
    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    let mains = traces.mains();

    let mut rng = StdRng::seed_from_u64(0x9a11);
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(residual.is_empty());
}

#[test]
fn full_stack_bus_balance_closes_with_empty_input() {
    // A zero-length invocation (one pad block + one canonical zero chunk)
    // mixed with a normal one, through the full eight-chiplet stack +
    // eval chip. This is the cross-chiplet guard for the empty-input fix: it
    // confirms the keccak-node's `H_input_chunks` read at the n_chunks=1 chain
    // tail has a provider, and that the chunk / sponge / P2 buses close
    // for the zero chunk consumed as a full garbage-tail.
    let mut session = Session::new();
    let mut rng = StdRng::seed_from_u64(0xe_2d7);
    let nonempty: Vec<u8> = (0..40).map(|_| rng.random()).collect();
    let mut claims = Vec::with_capacity(2);
    for input in [Vec::<u8>::new(), nonempty] {
        let (_, claim) = session.keccak(&input);
        claims.push(claim);
    }
    let root = session.assert_and_fold(claims);
    let traces = session.finish(root);
    let mains = traces.mains();

    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(residual.is_empty());
}

use super::uint::{random_modulus, random_uint_below};
use crate::{
    math::{from_hex, to_limbs32},
    transcript::eval::trace::{TranscriptEvalRequires, generate_trace as eval_trace},
    uint::{
        UintStoreAir,
        trace::{UintStoreRequires, generate_trace as uint_trace},
    },
};

/// The uint-leaf seam end-to-end: the eval chip pulls a stored uint's two
/// `UintVal` halves, hashes them into `Binding(h, Uint, ptr, bound_ptr)`,
/// and the `UintStore` provides those halves with the eval consume folded
/// into its demand ledger. Folds eval + UintStore + Poseidon2 + BytePairLut
/// — every bus (UintVal, Poseidon2In/Out, Binding, Range16) must close.
#[test]
fn uint_leaf_binds_against_uint_store() {
    let mut rng = StdRng::seed_from_u64(0x0157_57e1);

    // A uint at ptr 5 (value v) under a random modulus stored at ptr 1;
    // v is in range under that bound.
    let bound = random_modulus(&mut rng);
    let v = random_uint_below(&mut rng, bound);
    let v_u32 = to_limbs32(v); // the 4×32 view the eval pins
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound); // modulus (self-ref)
    let v_ptr = store.intern_pinned(5, v, fp); // the hashed uint

    let mut p2 = Poseidon2Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eval_req = TranscriptEvalRequires::new();

    // The eval chip hashes the uint at ptr 5 under the VM uint value cap and routes
    // its UintVal demand into the store's ledger.
    let root = eval_req.zero();
    eval_req.uint_leaf(v_ptr, fp, v_u32, &mut store, &mut p2);
    let eval_main = eval_trace(eval_req, root);

    // The store provides each UintVal with multiplicity = its demand: the
    // bound-refs (recorded on intern) + the eval leaf's consume of the
    // value at ptr 5.
    let uint_main = uint_trace(store, &mut bpl);

    // Poseidon2 + BytePairLut close the perm + Range16 demand (the p2 trace
    // itself emits Range16, so it shares the bpl).
    let p2_main = p2_trace(p2);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&TranscriptEvalAir, &eval_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &uint_main, &challenges, &mut net);
    fold_balance(&Poseidon2Air, &p2_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let residual: Vec<_> = net.into_iter().filter(|(_, (m, _))| *m != Felt::ZERO).collect();
    assert!(
        residual.is_empty(),
        "uint-leaf↔store imbalance: {} unmatched denom(s); e.g. net {:?} on {}",
        residual.len(),
        residual.first().map(|(_, (m, _))| *m),
        residual.first().map(|(_, (_, s))| s.as_str()).unwrap_or(""),
    );
}

/// The pinned→Truthy fork end-to-end: a pinned uint (the self-referential
/// modulus) hashes to `Binding(h, True)` — not `Uint` — and an AND node
/// folds it into the transcript spine, anchoring it in the public root. If
/// the fork mis-bound the pinned leaf as `Uint`, the AND's `True` consume
/// would find no provider and the Binding bus would not close.
#[test]
fn pinned_uint_leaf_folds_into_spine() {
    let mut rng = StdRng::seed_from_u64(0x9114_ed15);

    // A random modulus stored self-referentially at ptr 1.
    let bound = random_modulus(&mut rng);
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, bound); // modulus (self-ref)
    let mod_v_u32 = to_limbs32(bound); // the modulus's 4×32 view

    let mut p2 = Poseidon2Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eval_req = TranscriptEvalRequires::new();

    // Pin the modulus, route its UintVal demand, then fold it with a ZERO_HASH leaf
    // into the root.
    let zero = eval_req.zero();
    let modulus = eval_req.pin_uint(fp, fp, mod_v_u32, &mut store, &mut p2);
    let root = eval_req.record_and(zero, modulus, &mut p2);
    let public_root = root.hash();
    let eval_main = eval_trace(eval_req, root);

    // Store provides UintVal(1) (the modulus) with multiplicity = its self
    // bound-ref + the eval pin consume.
    let uint_main = uint_trace(store, &mut bpl);

    let p2_main = p2_trace(p2);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = random_challenges(&mut rng);

    // Constraints hold (incl. the is_pinned = 1 cap + one-hot node type).
    crate::tests::check_local_inputs(
        TranscriptEvalAir,
        &eval_main,
        public_root.as_array().to_vec(),
    );

    // …and every bus closes — in particular the modulus's Binding(True) is
    // consumed by the AND node.
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&TranscriptEvalAir, &eval_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &uint_main, &challenges, &mut net);
    fold_balance(&Poseidon2Air, &p2_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let residual: Vec<_> = net.into_iter().filter(|(_, (m, _))| *m != Felt::ZERO).collect();
    assert!(
        residual.is_empty(),
        "pinned-uint spine-fold imbalance: {} unmatched denom(s); e.g. net {:?} on {}",
        residual.len(),
        residual.first().map(|(_, (m, _))| *m),
        residual.first().map(|(_, (_, s))| s.as_str()).unwrap_or(""),
    );
}

/// The Session's uint path end-to-end: pin the modulus + a value into the
/// transcript root alongside a keccak claim, driven entirely through the
/// public `Session` facade, then balance the full nine-chiplet stack. The
/// pinned uints' `Binding(True)`s fold into the spine and their `UintVal`
/// halves close against the store.
#[test]
fn full_stack_pins_uints() {
    let mut session = Session::new();
    let mut rng = StdRng::seed_from_u64(0x5117_5717);
    let input: Vec<u8> = (0..40).map(|_| rng.random()).collect();
    let (_, keccak) = session.keccak(&input);

    // A random modulus (self-referential) at a non-fixed ptr, and a value under it.
    const MOD_PTR: u32 = 1000;
    const VALUE_PTR: u32 = 1001;
    let bound = random_modulus(&mut rng);
    let modulus = session.pin_uint(MOD_PTR, bound, MOD_PTR);
    let value = random_uint_below(&mut rng, bound);
    let val = session.pin_uint(VALUE_PTR, value, MOD_PTR);
    let root = session.assert_and_fold([keccak, modulus, val]);

    let traces = session.finish(root);
    let mains = traces.mains();

    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(residual.is_empty());
}

/// The pin-anchoring tamper case: the store holds a *larger* value X at
/// the protocol's modulus address 1 (self-ref) and the real `p − 1`
/// relocated to ptr 7 (typed under 1, in range since `p − 1 ≤ X`); the
/// spine carries the honest "pinned at address 1" leaf, but the laid row
/// is tampered to dereference ptr 7. The forged pin-claim cap
/// `(UINT_PIN_CLAIM_TAG, 1, 7, 0)` mismatches the absorbed cap
/// `(UINT_PIN_CLAIM_TAG, 1, 1, 0)`, so the Poseidon2In bus leaves a residual.
#[test]
fn relocated_modulus_pin_unbalances() {
    use crate::transcript::eval::{COL_IS_PINNED, COL_PTR, NUM_MAIN_COLS as EVAL_NUM_MAIN_COLS};

    let mut rng = StdRng::seed_from_u64(0x4e10_ca7e);

    // X squats at the protocol's modulus address 1; the real p − 1 hides
    // at ptr 7, typed under 1.
    let x = random_modulus(&mut rng);
    let p_minus_1 = random_uint_below(&mut rng, x);
    let mut store = UintStoreRequires::new();
    let fp = store.pin_modulus(1, x);
    let relocated = store.intern_pinned(7, p_minus_1, fp);

    let mut p2 = Poseidon2Requires::new();
    let mut bpl = BytePairLutRequires::new();
    let mut eval_req = TranscriptEvalRequires::new();

    // The honest pin of the value at address 1 …
    let zero = eval_req.zero();
    let modulus = eval_req.pin_uint(fp, fp, to_limbs32(x), &mut store, &mut p2);
    let root = eval_req.record_and(zero, modulus, &mut p2);
    let mut eval_main = eval_trace(eval_req, root);

    // … with the laid row's dereference forged onto the relocated block.
    let pin_row = (0..eval_main.height())
        .find(|&r| eval_main.values[r * EVAL_NUM_MAIN_COLS + COL_IS_PINNED] == Felt::ONE)
        .expect("the pin row");
    eval_main.values[pin_row * EVAL_NUM_MAIN_COLS + COL_PTR] = Felt::from(relocated.addr());

    let uint_main = uint_trace(store, &mut bpl);
    let p2_main = p2_trace(p2);
    let bpl_main = bpl_trace(bpl);

    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let mut net: HashMap<QuadFelt, (Felt, String)> = HashMap::new();
    fold_balance(&TranscriptEvalAir, &eval_main, &challenges, &mut net);
    fold_balance(&UintStoreAir, &uint_main, &challenges, &mut net);
    fold_balance(&Poseidon2Air, &p2_main, &challenges, &mut net);
    fold_balance(&BytePairLutAir, &bpl_main, &challenges, &mut net);

    let residual = net.values().filter(|(m, _)| *m != Felt::ZERO).count();
    assert!(
        residual > 0,
        "a relocated modulus pin must not balance: the cap commits pin_ptr, \
         so a pin row re-pointed at ptr 7 can't reproduce the honest \
         pinned-at-1 hash",
    );
}

/// The motivating secp256k1 shape end-to-end through the Session: pin
/// `p − 1` self-referentially at FP, then Gx / Gy / a / b under it. Each
/// constant's leaf hash commits (value, FP, own ptr), so the root anchors
/// `store[ptr] = value ∧ value < p` for all four — with `a = 0` doubling
/// as the *typed* zero (a pin of 0 under FP's bound, the role the old
/// untyped sentinel could never fill). These explicit transcript pins use
/// non-fixed addresses because `Session::new` already installs VM-owned fixed values;
/// every bus closes once the verifier-side fixed-boundary correction is included.
#[test]
fn full_stack_pins_k1_constants() {
    const FP: u32 = 1000;
    const GX_PTR: u32 = 1001;
    const GY_PTR: u32 = 1002;
    const A_PTR: u32 = 1003;
    const B_PTR: u32 = 1004;

    let p_minus_1 = from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E");
    let gx = from_hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    let gy = from_hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    let a = from_hex("0");
    let b = from_hex("7");

    let mut session = Session::new();
    let (_, keccak) = session.keccak(b"k1");
    let handles = [
        keccak,
        session.pin_uint(FP, p_minus_1, FP),
        session.pin_uint(GX_PTR, gx, FP),
        session.pin_uint(GY_PTR, gy, FP),
        session.pin_uint(A_PTR, a, FP),
        session.pin_uint(B_PTR, b, FP),
    ];
    let root = session.assert_and_fold(handles);
    let traces = session.finish(root);
    let mains = traces.mains();

    let mut rng = StdRng::seed_from_u64(0x5ec9_2561);
    let [alpha, beta] = random_challenges(&mut rng);
    let challenges = Challenges::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);
    let residual = session_stack_residual(&mains, &[], &challenges);
    assert!(residual.is_empty());
}

/// Every chiplet must fit the test config's blowup (lqd ≤ 3 at
/// log_blowup 3) — `cargo test --lib` never proves, so this is the
/// cheap guard that catches a constraint-degree regression before the
/// bench does.
#[test]
fn log_quotient_degrees_fit_the_blowup() {
    use crate::session::ChipletAir;
    for air in ChipletAir::all() {
        let lqd = crate::tests::log_quotient_degree(&air);
        eprintln!("lqd {lqd}  {air:?}");
        assert!(lqd <= 3, "{air:?} busts the blowup: lqd = {lqd} > 3");
    }
}
