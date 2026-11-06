use miden_core::{Felt, Word, proof::ExecutionProofCompatibility};
use miden_verifier::Verifier;
use miden_vm::ProgramInfo;

#[path = "../benches/recursive_verify/cache_key.rs"]
mod cache_key;

use cache_key::tx_proof_cache_key;

#[test]
fn verifier_roots_separate_transaction_cache_entries() {
    let program = ProgramInfo::new(Word::default(), Default::default());
    let compatibility = Verifier::proof_compatibility();
    let key = tx_proof_cache_key(&program, &[0, 1], &compatibility);
    let other_root = Word::new([Felt::ONE; 4]);

    for (vm_roots, pvm_roots) in [
        (vec![other_root], compatibility.pvm_verifier_roots().to_vec()),
        (compatibility.vm_verifier_roots().to_vec(), vec![other_root]),
    ] {
        let changed = ExecutionProofCompatibility::new(vm_roots, pvm_roots).unwrap();
        assert_ne!(key, tx_proof_cache_key(&program, &[0, 1], &changed));
    }
    assert_eq!(key, tx_proof_cache_key(&program, &[0, 1], &compatibility));
}
