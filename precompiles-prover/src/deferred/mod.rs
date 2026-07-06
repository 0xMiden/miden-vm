//! Test-only helpers for checking prover transcript roots against VM deferred state.

use std::sync::Arc;

use miden_core::{
    Felt, ZERO,
    deferred::{DeferredState, Digest, Node, PrecompileRegistry, TRUE_DIGEST},
    utils::bytes_to_packed_u32_elements,
};
use miden_precompiles::Keccak256Precompile;

use crate::{hash::keccak::sponge::trace::keccak_oracle, transcript::poseidon2::P2Digest};

/// A VM synthetic Keccak-only deferred state and the prover-typed view of its root.
#[derive(Debug)]
pub(crate) struct SyntheticKeccakDeferredState {
    pub(crate) state: DeferredState,
    pub(crate) input_digest: Digest,
    pub(crate) expected_digest: Digest,
    pub(crate) assertion_digest: Digest,
    pub(crate) vm_root: Digest,
    pub(crate) root: P2Digest,
}

/// Builds the Keccak-only VM deferred state for `input`:
/// `AND(TRUE_DIGEST, Keccak256Assert(chunks(input), chunks(keccak256(input))))`.
pub(crate) fn synthetic_keccak_state(input: &[u8]) -> SyntheticKeccakDeferredState {
    let registry =
        Arc::new(PrecompileRegistry::new().with_precompile(Keccak256Precompile::default()));
    let mut state = DeferredState::new(registry, usize::MAX)
        .expect("Keccak-only VM deferred state should initialize");

    let input_digest = state
        .register(Node::chunks(pack_input_chunks(input)).expect("input chunks are non-empty"))
        .expect("VM should register input chunks");
    let expected_digest = state
        .register(Node::chunks(keccak_digest_chunks(input)).expect("digest chunks are non-empty"))
        .expect("VM should register expected digest chunks");
    let assertion_digest = state
        .register(Keccak256Precompile::assert_node(
            len_bytes(input),
            input_digest,
            expected_digest,
        ))
        .expect("VM Keccak assertion should evaluate to TRUE");

    let vm_root = state
        .log_statement(assertion_digest)
        .expect("true Keccak assertion should log into the deferred root");
    debug_assert_eq!(vm_root, Node::and(TRUE_DIGEST, assertion_digest).digest());
    debug_assert_eq!(state.root(), vm_root);

    SyntheticKeccakDeferredState {
        state,
        input_digest,
        expected_digest,
        assertion_digest,
        vm_root,
        root: P2Digest::from(vm_root),
    }
}

fn pack_input_chunks(input: &[u8]) -> Vec<[Felt; 8]> {
    let mut felts = bytes_to_packed_u32_elements(input);
    let n_chunks = felts.len().div_ceil(8).max(1);
    felts.resize(n_chunks * 8, ZERO);
    felts.chunks_exact(8).map(|chunk| core::array::from_fn(|i| chunk[i])).collect()
}

fn keccak_digest_chunks(input: &[u8]) -> Vec<[Felt; 8]> {
    // The VM crate re-exports `HashFunction` but not the concrete `Keccak256Hash` spec, so use the
    // prover oracle's u32-limb layout here. The `state.register(assert_node(...))` call above
    // validates these chunks against the VM Keccak precompile before the root is accepted.
    vec![keccak_oracle(input).to_u32s().map(Felt::from_u32)]
}

fn len_bytes(input: &[u8]) -> u32 {
    u32::try_from(input.len()).expect("Keccak MVP inputs fit in a VM u32 length tag")
}
