use miden_assembly::Assembler;
use miden_crypto::merkle::{MerkleTree, NodeIndex, store::MerkleStore};
use miden_processor::{DefaultHost, ExecutionRequest, Felt, StackInputs, WitnessOutput, Word};
use miden_prover::{AdviceInputs, Prover};
use miden_verifier::Verifier;

#[tokio::test(flavor = "current_thread")]
async fn execution_witness_retains_final_advice_and_proves() {
    let mut tree =
        MerkleTree::new([Word::from([1, 2, 3, 4u32]), Word::from([5, 6, 7, 8u32])]).unwrap();
    let old_root = tree.root();
    let new_leaf = Word::from([9, 10, 11, 12u32]);
    let advice_inputs = AdviceInputs::default().with_merkle_store(MerkleStore::from(&tree));
    tree.update_leaf(1, new_leaf).unwrap();
    let stack = [
        Felt::from_u32(1),
        Felt::from_u32(1),
        old_root[0],
        old_root[1],
        old_root[2],
        old_root[3],
        new_leaf[0],
        new_leaf[1],
        new_leaf[2],
        new_leaf[3],
    ];
    let stack_inputs = StackInputs::new(&stack).unwrap();
    let program = Assembler::default()
        .assemble_program(
            "advice",
            "begin
                push.42 mem_store.0
                push.1.0 padw adv.insert_mem dropw drop drop
                mtree_set
            end",
        )
        .unwrap()
        .unwrap_program();

    let request = || ExecutionRequest::new(&program).with_stack_inputs(stack_inputs);
    let sync_result = request()
        .with_advice(advice_inputs.clone())
        .record_witness()
        .run_sync(&mut DefaultHost::default())
        .unwrap();
    let async_result = request()
        .with_advice(advice_inputs)
        .record_witness()
        .run(&mut DefaultHost::default())
        .await
        .unwrap();

    assert_eq!(sync_result.claim, async_result.claim);
    assert_eq!(sync_result.advice, async_result.advice);
    for WitnessOutput { claim, witness, advice } in [sync_result, async_result] {
        assert_eq!(advice.get_mapped_values(&Word::empty()), Some([Felt::from_u32(42)].as_slice()));
        let (_, _, store) = advice.into_parts();
        assert_eq!(store.get_node(tree.root(), NodeIndex::new(1, 1).unwrap()).unwrap(), new_leaf);
        assert_eq!(
            store.get_node(old_root, NodeIndex::new(1, 1).unwrap()).unwrap(),
            Word::from([5, 6, 7, 8u32])
        );
        assert_eq!(claim.stack_inputs(), &stack_inputs);
        let proof = Prover::new().prove_full(witness).unwrap();
        assert!(Verifier::new().verify(&claim, &proof).unwrap().is_complete());
    }
}
