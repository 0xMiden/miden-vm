use alloc::collections::BTreeMap;

use miden_utils_testing::{Felt, PrimeField64, crypto::MerkleStore};

mod channel;

pub(crate) mod verifier_fri_e2f4;
use miden_core::Word;
pub use verifier_fri_e2f4::*;

const FRI_PREPROCESS_SOURCE: &str = "
    use miden::core::stark::constants

    const MAX_FRI_QUERIES = 150
    const MAX_FRI_LAYERS = 32
    const MAX_FRI_REMAINDER_WORDS = 64

    proc preprocess
        adv_push
        # => [num_queries, g, ...]
        dup u32gt.0 assert.err=\"number of FRI queries must be nonzero\"
        dup u32lte.MAX_FRI_QUERIES assert.err=\"number of FRI queries exceeds FRI workspace\"

        exec.constants::fri_com_ptr
        # => [layer_ptr, num_queries, g, ...]
        dup.1 mul.4 sub
        # => [query_ptr, num_queries, g, ...]
        dup exec.constants::set_fri_queries_address
        swap
        sub.1
        padw
        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
        #=> [X, x, layer_ptr, g]

        drop
        #=> [X, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, layer_ptr, layer_ptr, g]

        adv_push
        dup u32lte.MAX_FRI_LAYERS assert.err=\"number of FRI layers exceeds FRI workspace\"

        dup push.0 neq
        if.true
            mul.2
            sub.1
            movdn.4
            #=> [X, num_layers, layer_ptr, layer_ptr, g]

            push.1
            while.true
                adv_loadw
                dup.5
                u32wrapping_add.4
                swap.6
                mem_storew_le
                dup.4
                sub.1
                swap.5
                neq.0
            end
            #=> [X, x, remainder_poly_ptr, layer_ptr, g]

            drop
        else
            drop
        end
        #=> [X, remainder_poly_ptr, layer_ptr, g]

        dup.4
        movdn.5
        #=> [X, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        adv_push
        dup u32gt.0 assert.err=\"FRI remainder polynomial must be nonzero\"
        dup u32lte.MAX_FRI_REMAINDER_WORDS assert.err=\"FRI remainder polynomial exceeds FRI workspace\"

        dup mul.2 exec.constants::set_remainder_poly_size

        sub.1
        movdn.4
        #=> [X, len_remainder/2, remainder_poly_ptr, remainder_poly_ptr, layer_ptr, g]

        push.1
        while.true
            adv_loadw
            dup.5
            u32wrapping_add.4
            swap.6
            mem_storew_le
            dup.4
            sub.1
            swap.5
            neq.0
        end
        #=> [X, x, x, remainder_poly_ptr, layer_ptr, g]
        dropw drop drop
        #=> [remainder_poly_ptr, layer_ptr, g]

        exec.constants::set_remainder_poly_address
        drop drop
    end
";

#[test]
fn fri_verify_rejects_empty_query_region() {
    let source = "
        use miden::core::pcs::fri::frie2f4
        use miden::core::stark::constants

        begin
            push.1 exec.constants::set_lde_domain_generator
            push.64 exec.constants::set_remainder_poly_size
            push.4294912800 exec.constants::set_remainder_poly_address
            push.4294912800 exec.constants::set_fri_queries_address
            exec.frie2f4::verify
        end
        ";

    let test = build_test!(source, &[]);
    expect_assert_error_message!(test, contains "fri query region must be non-empty");
}

#[test]
fn fri_fold4_ext2_remainder64() {
    let source = format!(
        "{FRI_PREPROCESS_SOURCE}
        use miden::core::pcs::fri::frie2f4

        begin
            exec.preprocess
            exec.frie2f4::verify
        end
        "
    );

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
    let domain_generator = Felt::get_root_of_unity(domain_size.ilog2()).as_canonical_u64();

    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees {
        store.extend(partial_tree.inner_nodes());
    }
    let test = build_test!(&source, &[domain_generator], &advice_stack, store, advice_map.clone());

    test.expect_stack(&[]);
}

#[test]
fn fri_fold4_ext2_remainder128() {
    let source = format!(
        "{FRI_PREPROCESS_SOURCE}
        use miden::core::pcs::fri::frie2f4

        begin
            exec.preprocess
            exec.frie2f4::verify
        end
        "
    );

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
    let domain_generator = Felt::get_root_of_unity(domain_size.ilog2()).as_canonical_u64();

    let mut store = MerkleStore::new();
    for partial_tree in &partial_trees {
        store.extend(partial_tree.inner_nodes());
    }
    let test = build_test!(&source, &[domain_generator], &advice_stack, store, advice_map.clone());

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
