use miden_core::deferred::{Node as VmNode, TRUE_DIGEST as VM_TRUE_DIGEST};

use crate::{
    deferred::{synthetic_keccak_state, vm_digest_to_p2},
    session::{Session, SessionTraces},
};

fn keccak_session_traces(input: &[u8]) -> SessionTraces {
    let mut session = Session::new();
    let (_, claim) = session.keccak(input);
    let root = session.assert_and_fold([claim]);
    session.finish(root)
}

#[test]
fn synthetic_keccak_deferred_state_reconstructs_root() {
    let input: Vec<u8> = (0u8..33).collect();
    let synthetic = synthetic_keccak_state(&input);

    assert_eq!(synthetic.state.root(), synthetic.vm_root);
    assert_eq!(
        synthetic.vm_root,
        VmNode::and(VM_TRUE_DIGEST, synthetic.assertion_digest).digest(),
    );
    assert_eq!(synthetic.root, vm_digest_to_p2(synthetic.vm_root));
    assert!(synthetic.state.get_node(&synthetic.input_digest).is_some());
    assert!(synthetic.state.get_node(&synthetic.expected_digest).is_some());
    assert!(synthetic.state.get_node(&synthetic.assertion_digest).is_some());
}

#[test]
fn session_public_root_matches_synthetic_deferred_state_for_keccak_inputs() {
    let cases: [(&str, Vec<u8>); 9] = [
        ("empty", Vec::new()),
        ("short", b"abc".to_vec()),
        ("one_chunk_minus_one_limb", vec![0xa5; 31]),
        ("one_chunk", vec![0xa5; 32]),
        ("two_chunks", vec![0xa5; 33]),
        ("keccak_rate_boundary", vec![0xa5; 136]),
        ("post_keccak_rate_boundary", vec![0xa5; 137]),
        ("trailing_zero", b"abc\0".to_vec()),
        ("explicit_padding_zeroes", vec![0, 0, 0, 0, 0]),
    ];

    for (name, input) in cases {
        let synthetic = synthetic_keccak_state(&input);
        let traces = keccak_session_traces(&input);
        assert_eq!(traces.public_root(), synthetic.root, "case {name}");
    }
}

#[test]
fn trailing_zero_input_changes_root() {
    let abc = synthetic_keccak_state(b"abc");
    let abc_zero = synthetic_keccak_state(b"abc\0");

    // Generic chunk nodes are lengthless: these inputs pack to the same single zero-padded chunk.
    // The Keccak assertion tag's `len_bytes` and digest child are what distinguish them.
    assert_eq!(abc.input_digest, abc_zero.input_digest);
    assert_ne!(abc.expected_digest, abc_zero.expected_digest);
    assert_ne!(abc.assertion_digest, abc_zero.assertion_digest);
    assert_ne!(abc.root, abc_zero.root);

    let abc_traces = keccak_session_traces(b"abc");
    let abc_zero_traces = keccak_session_traces(b"abc\0");
    assert_eq!(abc_traces.public_root(), abc.root);
    assert_eq!(abc_zero_traces.public_root(), abc_zero.root);
    assert_ne!(abc_traces.public_root(), abc_zero_traces.public_root());
}

#[test]
fn keccak_deferred_state_root_proves_and_verifies() {
    let input = b"abc";
    let synthetic = synthetic_keccak_state(input);
    let traces = keccak_session_traces(input);
    assert_eq!(traces.public_root(), synthetic.root);

    let proof = traces.prove();
    assert_eq!(proof.public_root(), synthetic.root);
    proof.verify().expect("Keccak deferred-state proof should verify");
}
