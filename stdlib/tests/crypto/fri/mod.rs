use alloc::collections::BTreeMap;

use miden_utils_testing::{Felt, StarkField, crypto::MerkleStore};

mod channel;

pub(crate) mod verifier_fri_e2f4;
use miden_core::Word;
pub use verifier_fri_e2f4::*;

#[test]
fn fri_fold4_ext2_remainder64() {
    let source = "
        use std::crypto::fri::frie2f4

        begin
            exec.frie2f4::preprocess
            exec.frie2f4::verify
        end
        ";

    let trace_len_e = 14;
    let blowup_exp = 3;
    let depth = trace_len_e + blowup_exp;
    let domain_size = 1 << depth;

    let FriResult {
        partial_trees,
        advice_maps,
        positions,
        alphas,
        commitments,
        remainder,
        num_queries,
    } = fri_prove_verify_fold4_ext2(trace_len_e).unwrap();

    let advice_stack = prepare_advice_stack(
        depth,
        domain_size,
        num_queries,
        positions,
        alphas,
        commitments,
        remainder,
    );

    let advice_map: BTreeMap<Word, Vec<Felt>> = BTreeMap::from_iter(advice_maps);
    let domain_generator = Felt::get_root_of_unity(domain_size.ilog2()).as_int();

    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees {
        store.extend(partial_tree.inner_nodes());
    }
    let test = build_test!(source, &[domain_generator], &advice_stack, store, advice_map.clone());

    test.expect_stack(&[]);
}

#[test]
fn fri_fold4_ext2_remainder128() {
    let source = "
        use std::crypto::fri::frie2f4

        begin
            exec.frie2f4::preprocess
            exec.frie2f4::verify
        end
        ";

    let trace_len_e = 13;
    let blowup_exp = 3;
    let depth = trace_len_e + blowup_exp;
    let domain_size = 1 << depth;

    let FriResult {
        partial_trees,
        advice_maps,
        positions,
        alphas,
        commitments,
        remainder,
        num_queries,
    } = fri_prove_verify_fold4_ext2(trace_len_e).unwrap();

    let advice_stack = prepare_advice_stack(
        depth,
        domain_size,
        num_queries,
        positions,
        alphas,
        commitments,
        remainder,
    );

    let advice_map: BTreeMap<Word, Vec<Felt>> = BTreeMap::from_iter(advice_maps);
    let domain_generator = Felt::get_root_of_unity(domain_size.ilog2()).as_int();

    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees {
        store.extend(partial_tree.inner_nodes());
    }
    let test = build_test!(source, &[domain_generator], &advice_stack, store, advice_map.clone());

    test.expect_stack(&[]);
}

fn prepare_advice_stack(
    depth: usize,
    domain_size: u32,
    num_queries: usize,
    position_eval: Vec<u64>,
    alphas: Vec<u64>,
    com: Vec<u64>,
    remainder: Vec<u64>,
) -> Vec<u64> {
    let mut stack = vec![];
    let remainder_length = remainder.len() / 2;
    let num_layers = (com.len() / 4) - 1;

    stack.push(num_queries as u64);

    stack.extend_from_slice(&position_eval[..]);

    stack.push(num_layers as u64);

    let mut current_domain_size = domain_size as u64;
    let mut current_depth = depth as u64;

    for i in 0..num_layers {
        current_domain_size /= 4;

        stack.extend_from_slice(&com[(4 * i)..(4 * i + 4)]);
        stack.extend_from_slice(&alphas[(4 * i)..(4 * i + 2)]);
        // - 2 is due to the fact that we are folding by 4
        stack.extend_from_slice(&[current_depth - 2, current_domain_size]);
        current_depth -= 2;
    }

    stack.push(remainder_length as u64 / 2);
    for i in 0..remainder_length / 2 {
        let mut remainder_4 = vec![0; 4];
        remainder_4[0] = remainder[4 * i];
        remainder_4[1] = remainder[4 * i + 1];
        remainder_4[2] = remainder[4 * i + 2];
        remainder_4[3] = remainder[4 * i + 3];

        stack.extend_from_slice(&remainder_4);
    }

    stack
}
