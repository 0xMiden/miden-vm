//! Tests for the Binding bus message ([`BindingMsg`]) + [`ValueTag`].
//!
//! Message-encoding invariants: correct bus prefix + β-expansion, the
//! `truth` constructor's tag / ptr pinning, and prefix disjointness from
//! a neighbouring bus.

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};

use crate::{
    logup::{Challenges, LookupMessage},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::{
        binding::{BindingMsg, ValueTag},
        poseidon2::Poseidon2InMsg,
    },
};

#[test]
fn binding_msg_encodes_with_binding_bus_prefix() {
    let alpha = QuadFelt::from_u64(23);
    let beta = QuadFelt::from_u64(29);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let h = [Felt::from(11u32), Felt::from(22u32), Felt::from(33u32), Felt::from(44u32)];
    let ptr = Felt::from(7u32);
    let bound_ptr = Felt::from(9u32);
    let msg = BindingMsg {
        h,
        value_tag: Felt::from(ValueTag::Uint as u8),
        ptr,
        bound_ptr,
    };
    let enc = msg.encode(&challenges);

    // Expected: bus_prefix[Binding] + β⁰·h0 + β¹·h1 + β²·h2 + β³·h3 +
    // β⁴·value_tag + β⁵·ptr + β⁶·bound_ptr.
    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64) * QuadFelt::from_u64((BusId::Binding as u64) + 1);
    let expected = bus_prefix
        + QuadFelt::from(h[0])
        + beta * QuadFelt::from(h[1])
        + beta.square() * QuadFelt::from(h[2])
        + beta.exp_u64(3) * QuadFelt::from(h[3])
        + beta.exp_u64(4) * QuadFelt::from(Felt::from(ValueTag::Uint as u8))
        + beta.exp_u64(5) * QuadFelt::from(ptr)
        + beta.exp_u64(6) * QuadFelt::from(bound_ptr);

    assert_eq!(enc, expected);
}

#[test]
fn binding_truth_sets_true_tag_and_zero_ptr() {
    let alpha = QuadFelt::from_u64(2);
    let beta = QuadFelt::from_u64(3);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    let h = [Felt::from(5u32), Felt::from(6u32), Felt::from(7u32), Felt::from(8u32)];
    // truth() pins value_tag = True (0) and ptr = 0, so the encoding
    // reduces to the bus prefix + the h expansion alone.
    let enc = BindingMsg::truth(h).encode(&challenges);

    let bus_prefix = alpha
        + beta.exp_u64(MAX_MESSAGE_WIDTH as u64) * QuadFelt::from_u64((BusId::Binding as u64) + 1);
    let expected = bus_prefix
        + QuadFelt::from(h[0])
        + beta * QuadFelt::from(h[1])
        + beta.square() * QuadFelt::from(h[2])
        + beta.exp_u64(3) * QuadFelt::from(h[3]);

    assert_eq!(enc, expected);
    assert_eq!(ValueTag::True as u8, 0);
}

#[test]
fn binding_bus_has_disjoint_prefix() {
    let alpha = QuadFelt::from_u64(3);
    let beta = QuadFelt::from_u64(2);
    let challenges = Challenges::<QuadFelt>::new(alpha, beta, MAX_MESSAGE_WIDTH, NUM_BUS_IDS);

    // Identical leading 6-felt payload on Binding vs Poseidon2In, with
    // Binding's 7th slot (bound_ptr) zeroed: they then differ *only* by
    // the bus prefix.
    let p = [
        Felt::from(1u32),
        Felt::from(2u32),
        Felt::from(3u32),
        Felt::from(4u32),
        Felt::from(5u32),
        Felt::from(6u32),
    ];
    let enc_binding = BindingMsg {
        h: [p[0], p[1], p[2], p[3]],
        value_tag: p[4],
        ptr: p[5],
        bound_ptr: Felt::ZERO,
    }
    .encode(&challenges);
    let enc_in = Poseidon2InMsg {
        perm_seq_id: p[0],
        tag: p[1],
        c: [p[2], p[3], p[4], p[5]],
    }
    .encode(&challenges);

    assert_ne!(enc_binding, enc_in);
}
