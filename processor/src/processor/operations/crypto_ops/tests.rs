use alloc::vec::Vec;

use miden_core::{
    Felt, Word, ZERO,
    chiplets::hasher::{STATE_WIDTH, apply_permutation},
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    field::{BasedVectorSpace, QuadFelt},
    mast::MastForest,
    stack::MIN_STACK_DEPTH,
};
use proptest::prelude::*;

use super::{
    op_crypto_stream, op_horner_eval_base, op_horner_eval_ext, op_hperm, op_mpverify, op_mrupdate,
};
use crate::{
    AdviceInputs, ContextId,
    fast::{FastProcessor, NoopTracer, step::NeverStopper},
};

// CONSTANTS
// --------------------------------------------------------------------------------------------

// The memory address where alpha is stored
const ALPHA_ADDR: u64 = 1000;

// HASHING TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_hperm(
        // Input state: 12 elements for the hasher state
        s0 in any::<u64>(),
        s1 in any::<u64>(),
        s2 in any::<u64>(),
        s3 in any::<u64>(),
        s4 in any::<u64>(),
        s5 in any::<u64>(),
        s6 in any::<u64>(),
        s7 in any::<u64>(),
        s8 in any::<u64>(),
        s9 in any::<u64>(),
        s10 in any::<u64>(),
        s11 in any::<u64>(),
        // Additional stack elements (positions 12-15)
        s12 in any::<u64>(),
        s13 in any::<u64>(),
        s14 in any::<u64>(),
        s15 in any::<u64>(),
    ) {
        // Build the initial stack state
        // Stack layout (top first): [s0, s1, s2, ..., s11, s12, s13, s14, s15]
        // FastProcessor::new expects elements in "reverse" order: first element goes to bottom
        let stack_inputs = [
            Felt::new(s15), // position 15 (bottom)
            Felt::new(s14), // position 14
            Felt::new(s13), // position 13
            Felt::new(s12), // position 12
            Felt::new(s11), // position 11
            Felt::new(s10), // position 10
            Felt::new(s9),  // position 9
            Felt::new(s8),  // position 8
            Felt::new(s7),  // position 7
            Felt::new(s6),  // position 6
            Felt::new(s5),  // position 5
            Felt::new(s4),  // position 4
            Felt::new(s3),  // position 3
            Felt::new(s2),  // position 2
            Felt::new(s1),  // position 1
            Felt::new(s0),  // position 0 (top)
        ];
        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Compute expected result
        // The input state is read from stack_top()[4..16]
        // stack_top()[4] = position 11 = s11, stack_top()[15] = position 0 = s0
        // So input_state = [s11, s10, s9, s8, s7, s6, s5, s4, s3, s2, s1, s0]
        let expected_state = {
            let mut expected_state = [
                Felt::new(s11),
                Felt::new(s10),
                Felt::new(s9),
                Felt::new(s8),
                Felt::new(s7),
                Felt::new(s6),
                Felt::new(s5),
                Felt::new(s4),
                Felt::new(s3),
                Felt::new(s2),
                Felt::new(s1),
                Felt::new(s0),
            ];
            apply_permutation(&mut expected_state);

            expected_state
        };

        // Execute the operation
        let _ = op_hperm(&mut processor, &mut tracer);
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Check the result
        let stack = processor.stack_top();

        // The output state is written directly to stack_top()[4..16]
        // output_state[0] -> stack_top()[4], output_state[11] -> stack_top()[15]
        for i in 0..STATE_WIDTH {
            prop_assert_eq!(
                stack[4 + i],
                expected_state[i],
                "mismatch at stack_top()[{}] (expected_state[{}])",
                4 + i,
                i
            );
        }

        // Check that positions 12-15 (stack_top()[0..4]) are NOT affected
        prop_assert_eq!(stack[3], Felt::new(s12), "s12 at position 12");
        prop_assert_eq!(stack[2], Felt::new(s13), "s13 at position 13");
        prop_assert_eq!(stack[1], Felt::new(s14), "s14 at position 14");
        prop_assert_eq!(stack[0], Felt::new(s15), "s15 at position 15");
    }
}

// STREAM CIPHER TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_crypto_stream(
        // Rate (keystream) - top 8 stack elements
        r0 in any::<u64>(),
        r1 in any::<u64>(),
        r2 in any::<u64>(),
        r3 in any::<u64>(),
        r4 in any::<u64>(),
        r5 in any::<u64>(),
        r6 in any::<u64>(),
        r7 in any::<u64>(),
        // Capacity - stack positions 8-11
        c0 in any::<u64>(),
        c1 in any::<u64>(),
        c2 in any::<u64>(),
        c3 in any::<u64>(),
        // Plaintext words (stored in memory)
        p0 in any::<u64>(),
        p1 in any::<u64>(),
        p2 in any::<u64>(),
        p3 in any::<u64>(),
        p4 in any::<u64>(),
        p5 in any::<u64>(),
        p6 in any::<u64>(),
        p7 in any::<u64>(),
    ) {
        // Use fixed addresses for source and destination
        let src_addr: u64 = 1000;
        let dst_addr: u64 = 2000;

        // Build the initial stack state
        // Stack layout (top first): [r7, r6, r5, r4, r3, r2, r1, r0, c3, c2, c1, c0, src_ptr, dst_ptr, 0, 0]
        let stack_inputs = [
            ZERO,                    // position 15 (bottom)
            ZERO,                    // position 14
            Felt::new(dst_addr),     // position 13 (dst_ptr)
            Felt::new(src_addr),     // position 12 (src_ptr)
            Felt::new(c0),           // position 11
            Felt::new(c1),           // position 10
            Felt::new(c2),           // position 9
            Felt::new(c3),           // position 8
            Felt::new(r0),           // position 7
            Felt::new(r1),           // position 6
            Felt::new(r2),           // position 5
            Felt::new(r3),           // position 4
            Felt::new(r4),           // position 3
            Felt::new(r5),           // position 2
            Felt::new(r6),           // position 1
            Felt::new(r7),           // position 0 (top)
        ];
        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Store plaintext in memory at src_addr
        let plaintext_word1: Word = [Felt::new(p0), Felt::new(p1), Felt::new(p2), Felt::new(p3)].into();
        let plaintext_word2: Word = [Felt::new(p4), Felt::new(p5), Felt::new(p6), Felt::new(p7)].into();

        processor.memory.write_word(
            ContextId::root(),
            Felt::new(src_addr),
            processor.clk,
            plaintext_word1,
            &(),
        ).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        processor.memory.write_word(
            ContextId::root(),
            Felt::new(src_addr + 4),
            processor.clk,
            plaintext_word2,
            &(),
        ).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Execute the operation
        let result = op_crypto_stream(&mut processor, &(), &mut tracer);
        prop_assert!(result.is_ok());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Compute expected ciphertext: ciphertext = plaintext + rate
        let expected_cipher1 = [
            Felt::new(p0) + Felt::new(r0),
            Felt::new(p1) + Felt::new(r1),
            Felt::new(p2) + Felt::new(r2),
            Felt::new(p3) + Felt::new(r3),
        ];
        let expected_cipher2 = [
            Felt::new(p4) + Felt::new(r4),
            Felt::new(p5) + Felt::new(r5),
            Felt::new(p6) + Felt::new(r6),
            Felt::new(p7) + Felt::new(r7),
        ];

        // Check that ciphertext was written to destination memory
        let clk = processor.clk;
        let cipher_word1 = processor.memory.read_word(ContextId::root(), Felt::new(dst_addr), clk, &()).unwrap();
        let cipher_word2 = processor.memory.read_word(ContextId::root(), Felt::new(dst_addr + 4), clk, &()).unwrap();

        prop_assert_eq!(cipher_word1[0], expected_cipher1[0], "cipher word1[0]");
        prop_assert_eq!(cipher_word1[1], expected_cipher1[1], "cipher word1[1]");
        prop_assert_eq!(cipher_word1[2], expected_cipher1[2], "cipher word1[2]");
        prop_assert_eq!(cipher_word1[3], expected_cipher1[3], "cipher word1[3]");
        prop_assert_eq!(cipher_word2[0], expected_cipher2[0], "cipher word2[0]");
        prop_assert_eq!(cipher_word2[1], expected_cipher2[1], "cipher word2[1]");
        prop_assert_eq!(cipher_word2[2], expected_cipher2[2], "cipher word2[2]");
        prop_assert_eq!(cipher_word2[3], expected_cipher2[3], "cipher word2[3]");

        // Check stack state
        let stack = processor.stack_top();

        // Stack[0..7] should be updated with ciphertext (in stack order)
        // Word 2 (cipher2) goes to stack[0..3], word 1 (cipher1) goes to stack[4..7]
        prop_assert_eq!(stack[15], expected_cipher2[3], "cipher2[3] at position 0");
        prop_assert_eq!(stack[14], expected_cipher2[2], "cipher2[2] at position 1");
        prop_assert_eq!(stack[13], expected_cipher2[1], "cipher2[1] at position 2");
        prop_assert_eq!(stack[12], expected_cipher2[0], "cipher2[0] at position 3");
        prop_assert_eq!(stack[11], expected_cipher1[3], "cipher1[3] at position 4");
        prop_assert_eq!(stack[10], expected_cipher1[2], "cipher1[2] at position 5");
        prop_assert_eq!(stack[9], expected_cipher1[1], "cipher1[1] at position 6");
        prop_assert_eq!(stack[8], expected_cipher1[0], "cipher1[0] at position 7");

        // Capacity should be unchanged
        prop_assert_eq!(stack[7], Felt::new(c3), "c3 at position 8");
        prop_assert_eq!(stack[6], Felt::new(c2), "c2 at position 9");
        prop_assert_eq!(stack[5], Felt::new(c1), "c1 at position 10");
        prop_assert_eq!(stack[4], Felt::new(c0), "c0 at position 11");

        // Pointers should be incremented by 8
        prop_assert_eq!(stack[3], Felt::new(src_addr + 8), "src_ptr incremented");
        prop_assert_eq!(stack[2], Felt::new(dst_addr + 8), "dst_ptr incremented");
    }
}

// HORNER EVALUATION TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_horner_eval_base(
        // 8 coefficients (c0-c7) - top 8 stack elements
        c0 in any::<u64>(),
        c1 in any::<u64>(),
        c2 in any::<u64>(),
        c3 in any::<u64>(),
        c4 in any::<u64>(),
        c5 in any::<u64>(),
        c6 in any::<u64>(),
        c7 in any::<u64>(),
        // Middle stack elements (8-12)
        s8 in any::<u64>(),
        s9 in any::<u64>(),
        s10 in any::<u64>(),
        s11 in any::<u64>(),
        s12 in any::<u64>(),
        // alpha evaluation point (stored in memory)
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // initial accumulator
        acc_0 in any::<u64>(),
        acc_1 in any::<u64>(),
    ) {
        // Build the initial stack state
        // Stack layout (top first): [c7, c6, c5, c4, c3, c2, c1, c0, s8, s9, s10, s11, s12, alpha_addr, acc1, acc0]
        // Position 0 (top) = c7, position 7 = c0, position 13 = alpha_addr, position 14 = acc1, position 15 = acc0
        //
        // FastProcessor::new expects elements in "reverse" order: first element goes to bottom, last to top.
        // So we pass [acc0, acc1, alpha_addr, s12, s11, s10, s9, s8, c0, c1, c2, c3, c4, c5, c6, c7]
        let stack_inputs = [
            Felt::new(acc_0),       // position 15 (bottom)
            Felt::new(acc_1),       // position 14
            Felt::new(ALPHA_ADDR),  // position 13
            Felt::new(s12),         // position 12
            Felt::new(s11),         // position 11
            Felt::new(s10),         // position 10
            Felt::new(s9),          // position 9
            Felt::new(s8),          // position 8
            Felt::new(c0),          // position 7
            Felt::new(c1),          // position 6
            Felt::new(c2),          // position 5
            Felt::new(c3),          // position 4
            Felt::new(c4),          // position 3
            Felt::new(c5),          // position 2
            Felt::new(c6),          // position 1
            Felt::new(c7),          // position 0 (top)
        ];
        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Store alpha in memory at ALPHA_ADDR
        // Memory format requirement: [alpha_0, alpha_1, 0, 0]
        let alpha_word: Word = [Felt::new(alpha_0), Felt::new(alpha_1), ZERO, ZERO].into();
        processor.memory.write_word(
            ContextId::root(),
            Felt::new(ALPHA_ADDR),
            processor.clk,
            alpha_word,
            &(),
        ).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Execute the operation.
        //
        // Note that we don't check the correctness of the helper registers here, since the
        // `FastProcessor` does not generate them (as they are only relevant in trace generation).
        let result = op_horner_eval_base(&mut processor, &(), &mut tracer);
        prop_assert!(result.is_ok());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Compute expected result
        let alpha = QuadFelt::new_complex(Felt::new(alpha_0), Felt::new(alpha_1));
        let acc_old = QuadFelt::new_complex(Felt::new(acc_0), Felt::new(acc_1));

        let c0_q = QuadFelt::from(Felt::new(c0));
        let c1_q = QuadFelt::from(Felt::new(c1));
        let c2_q = QuadFelt::from(Felt::new(c2));
        let c3_q = QuadFelt::from(Felt::new(c3));
        let c4_q = QuadFelt::from(Felt::new(c4));
        let c5_q = QuadFelt::from(Felt::new(c5));
        let c6_q = QuadFelt::from(Felt::new(c6));
        let c7_q = QuadFelt::from(Felt::new(c7));

        // Level 1: tmp0 = (acc * alpha + c0) * alpha + c1
        let tmp0 = (acc_old * alpha + c0_q) * alpha + c1_q;

        // Level 2: tmp1 = ((tmp0 * alpha + c2) * alpha + c3) * alpha + c4
        let tmp1 = ((tmp0 * alpha + c2_q) * alpha + c3_q) * alpha + c4_q;

        // Level 3: acc' = ((tmp1 * alpha + c5) * alpha + c6) * alpha + c7
        let acc_new = ((tmp1 * alpha + c5_q) * alpha + c6_q) * alpha + c7_q;

        // Check stack state using stack_top()
        // stack_top() returns a slice of 16 elements where index 15 = top, index 0 = bottom
        let stack = processor.stack_top();

        // Check that the top 8 stack elements (coefficients) were NOT affected
        prop_assert_eq!(stack[15], Felt::new(c7), "c7 at position 0 (top)");
        prop_assert_eq!(stack[14], Felt::new(c6), "c6 at position 1");
        prop_assert_eq!(stack[13], Felt::new(c5), "c5 at position 2");
        prop_assert_eq!(stack[12], Felt::new(c4), "c4 at position 3");
        prop_assert_eq!(stack[11], Felt::new(c3), "c3 at position 4");
        prop_assert_eq!(stack[10], Felt::new(c2), "c2 at position 5");
        prop_assert_eq!(stack[9], Felt::new(c1), "c1 at position 6");
        prop_assert_eq!(stack[8], Felt::new(c0), "c0 at position 7");

        // Check that middle stack elements were NOT affected
        prop_assert_eq!(stack[7], Felt::new(s8), "s8 at position 8");
        prop_assert_eq!(stack[6], Felt::new(s9), "s9 at position 9");
        prop_assert_eq!(stack[5], Felt::new(s10), "s10 at position 10");
        prop_assert_eq!(stack[4], Felt::new(s11), "s11 at position 11");
        prop_assert_eq!(stack[3], Felt::new(s12), "s12 at position 12");

        // Check that alpha_addr was NOT affected
        prop_assert_eq!(stack[2], Felt::new(ALPHA_ADDR), "alpha_addr at position 13");

        // Check that the accumulator was updated correctly
        let acc_new_base = acc_new.as_basis_coefficients_slice();
        prop_assert_eq!(stack[1], acc_new_base[1], "acc_high at position 14");
        prop_assert_eq!(stack[0], acc_new_base[0], "acc_low at position 15");
    }

    #[test]
    fn test_op_horner_eval_ext(
        // 4 extension field coefficients (c0-c3), each is 2 base elements
        c0_0 in any::<u64>(),
        c0_1 in any::<u64>(),
        c1_0 in any::<u64>(),
        c1_1 in any::<u64>(),
        c2_0 in any::<u64>(),
        c2_1 in any::<u64>(),
        c3_0 in any::<u64>(),
        c3_1 in any::<u64>(),
        // Middle stack elements (8-12)
        s8 in any::<u64>(),
        s9 in any::<u64>(),
        s10 in any::<u64>(),
        s11 in any::<u64>(),
        s12 in any::<u64>(),
        // alpha evaluation point (stored in memory)
        alpha_0 in any::<u64>(),
        alpha_1 in any::<u64>(),
        // initial accumulator
        acc_0 in any::<u64>(),
        acc_1 in any::<u64>(),
    ) {
        // Build the initial stack state
        // Stack layout from get_coeff_as_quad_ext_elements:
        // Position 0 (top) = c0_1, position 1 = c0_0
        // Position 2 = c1_1, position 3 = c1_0
        // Position 4 = c2_1, position 5 = c2_0
        // Position 6 = c3_1, position 7 = c3_0
        // Position 13 = alpha_addr, position 14 = acc1, position 15 = acc0
        let stack_inputs = [
            Felt::new(acc_0),       // position 15 (bottom)
            Felt::new(acc_1),       // position 14
            Felt::new(ALPHA_ADDR),  // position 13
            Felt::new(s12),         // position 12
            Felt::new(s11),         // position 11
            Felt::new(s10),         // position 10
            Felt::new(s9),          // position 9
            Felt::new(s8),          // position 8
            Felt::new(c3_0),        // position 7
            Felt::new(c3_1),        // position 6
            Felt::new(c2_0),        // position 5
            Felt::new(c2_1),        // position 4
            Felt::new(c1_0),        // position 3
            Felt::new(c1_1),        // position 2
            Felt::new(c0_0),        // position 1
            Felt::new(c0_1),        // position 0 (top)
        ];
        let mut processor = FastProcessor::new(&stack_inputs);
        let mut tracer = NoopTracer;

        // Store alpha in memory at ALPHA_ADDR
        // Memory format requirement: [alpha_0, alpha_1, k0, k1] (k0, k1 are unused but read)
        let alpha_word: Word = [Felt::new(alpha_0), Felt::new(alpha_1), ZERO, ZERO].into();
        processor.memory.write_word(
            ContextId::root(),
            Felt::new(ALPHA_ADDR),
            processor.clk,
            alpha_word,
            &(),
        ).unwrap();
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Execute the operation
        let result = op_horner_eval_ext(&mut processor, &(), &mut tracer);
        prop_assert!(result.is_ok());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Compute expected result
        let alpha = QuadFelt::new_complex(Felt::new(alpha_0), Felt::new(alpha_1));
        let acc_old = QuadFelt::new_complex(Felt::new(acc_0), Felt::new(acc_1));

        let c0 = QuadFelt::new_complex(Felt::new(c0_0), Felt::new(c0_1));
        let c1 = QuadFelt::new_complex(Felt::new(c1_0), Felt::new(c1_1));
        let c2 = QuadFelt::new_complex(Felt::new(c2_0), Felt::new(c2_1));
        let c3 = QuadFelt::new_complex(Felt::new(c3_0), Felt::new(c3_1));

        let coefficients = [c0, c1, c2, c3];

        // acc_tmp = coefficients.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc)
        let acc_tmp = coefficients.iter().rev().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);
        let acc_new = coefficients.iter().rev().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

        // Check stack state using stack_top()
        let stack = processor.stack_top();

        // Check that the top 8 stack elements (coefficients) were NOT affected
        prop_assert_eq!(stack[15], Felt::new(c0_1), "c0_1 at position 0 (top)");
        prop_assert_eq!(stack[14], Felt::new(c0_0), "c0_0 at position 1");
        prop_assert_eq!(stack[13], Felt::new(c1_1), "c1_1 at position 2");
        prop_assert_eq!(stack[12], Felt::new(c1_0), "c1_0 at position 3");
        prop_assert_eq!(stack[11], Felt::new(c2_1), "c2_1 at position 4");
        prop_assert_eq!(stack[10], Felt::new(c2_0), "c2_0 at position 5");
        prop_assert_eq!(stack[9], Felt::new(c3_1), "c3_1 at position 6");
        prop_assert_eq!(stack[8], Felt::new(c3_0), "c3_0 at position 7");

        // Check that middle stack elements were NOT affected
        prop_assert_eq!(stack[7], Felt::new(s8), "s8 at position 8");
        prop_assert_eq!(stack[6], Felt::new(s9), "s9 at position 9");
        prop_assert_eq!(stack[5], Felt::new(s10), "s10 at position 10");
        prop_assert_eq!(stack[4], Felt::new(s11), "s11 at position 11");
        prop_assert_eq!(stack[3], Felt::new(s12), "s12 at position 12");

        // Check that alpha_addr was NOT affected
        prop_assert_eq!(stack[2], Felt::new(ALPHA_ADDR), "alpha_addr at position 13");

        // Check that the accumulator was updated correctly
        let acc_new_base = acc_new.as_basis_coefficients_slice();
        prop_assert_eq!(stack[1], acc_new_base[1], "acc_high at position 14");
        prop_assert_eq!(stack[0], acc_new_base[0], "acc_low at position 15");
    }
}

// MERKLE TREE TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    /// Tests Merkle path verification operation.
    ///
    /// This test creates a Merkle tree with 8 leaves and verifies that the `op_mpverify` operation
    /// correctly verifies the Merkle path for a given node.
    #[test]
    fn test_op_mpverify(
        // 8 leaf values for the Merkle tree
        l0 in any::<u64>(),
        l1 in any::<u64>(),
        l2 in any::<u64>(),
        l3 in any::<u64>(),
        l4 in any::<u64>(),
        l5 in any::<u64>(),
        l6 in any::<u64>(),
        l7 in any::<u64>(),
        // Index of the leaf to verify (0-7)
        leaf_idx in 0u64..8,
    ) {
        // Create leaves from the input values
        let leaves: Vec<Word> = [l0, l1, l2, l3, l4, l5, l6, l7]
            .iter()
            .map(|&v| init_node(v))
            .collect();

        // Create the Merkle tree and store
        let tree = MerkleTree::new(&leaves).unwrap();
        let store = MerkleStore::from(&tree);
        let root = tree.root();
        let node = leaves[leaf_idx as usize];
        let depth = tree.depth() as u64;

        // Create advice inputs with the Merkle store
        let advice_inputs = AdviceInputs::default().with_merkle_store(store);

        // Build the initial stack state
        // Stack layout (top first): [node[3], node[2], node[1], node[0], depth, index, root[3], root[2], root[1], root[0], ...]
        let stack_inputs = [
            ZERO,                  // position 15 (bottom)
            ZERO,                  // position 14
            ZERO,                  // position 13
            ZERO,                  // position 12
            ZERO,                  // position 11
            ZERO,                  // position 10
            root[0],               // position 9
            root[1],               // position 8
            root[2],               // position 7
            root[3],               // position 6
            Felt::new(leaf_idx),   // position 5
            Felt::new(depth),      // position 4
            node[0],               // position 3
            node[1],               // position 2
            node[2],               // position 1
            node[3],               // position 0 (top)
        ];
        let mut processor = FastProcessor::new_with_advice_inputs(&stack_inputs, advice_inputs);
        let mut tracer = NoopTracer;
        let program = MastForest::default();

        // Execute the operation
        let result = op_mpverify(&mut processor, ZERO, &program, &(), &mut tracer);
        prop_assert!(result.is_ok(), "op_mpverify failed: {:?}", result.err());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // The stack should remain unchanged after verification
        let stack = processor.stack_top();

        // Check node value (top of stack)
        prop_assert_eq!(stack[15], node[3], "node[3] at position 0");
        prop_assert_eq!(stack[14], node[2], "node[2] at position 1");
        prop_assert_eq!(stack[13], node[1], "node[1] at position 2");
        prop_assert_eq!(stack[12], node[0], "node[0] at position 3");

        // Check depth and index
        prop_assert_eq!(stack[11], Felt::new(depth), "depth at position 4");
        prop_assert_eq!(stack[10], Felt::new(leaf_idx), "index at position 5");

        // Check root value
        prop_assert_eq!(stack[9], root[3], "root[3] at position 6");
        prop_assert_eq!(stack[8], root[2], "root[2] at position 7");
        prop_assert_eq!(stack[7], root[1], "root[1] at position 8");
        prop_assert_eq!(stack[6], root[0], "root[0] at position 9");
    }

    /// Tests Merkle root update operation.
    ///
    /// This test creates a Merkle tree, updates a leaf node, and verifies that the `op_mrupdate`
    /// operation correctly computes the new root.
    #[test]
    fn test_op_mrupdate(
        // 8 leaf values for the initial Merkle tree
        l0 in any::<u64>(),
        l1 in any::<u64>(),
        l2 in any::<u64>(),
        l3 in any::<u64>(),
        l4 in any::<u64>(),
        l5 in any::<u64>(),
        l6 in any::<u64>(),
        l7 in any::<u64>(),
        // New value for the updated leaf
        new_leaf_value in any::<u64>(),
        // Index of the leaf to update (0-7)
        leaf_idx in 0u64..8,
    ) {
        // Create leaves from the input values
        let leaves: Vec<Word> = [l0, l1, l2, l3, l4, l5, l6, l7]
            .iter()
            .map(|&v| init_node(v))
            .collect();
        let new_leaf = init_node(new_leaf_value);

        // Create the tree with the new leaf
        let mut new_leaves = leaves.clone();
        new_leaves[leaf_idx as usize] = new_leaf;

        // Create both old and new Merkle trees
        let tree = MerkleTree::new(&leaves).unwrap();
        let new_tree = MerkleTree::new(&new_leaves).unwrap();
        let store = MerkleStore::from(&tree);

        let old_root = tree.root();
        let old_node = leaves[leaf_idx as usize];
        let depth = tree.depth() as u64;
        let expected_new_root = new_tree.root();

        // Create advice inputs with the Merkle store
        let advice_inputs = AdviceInputs::default().with_merkle_store(store);

        // Build the initial stack state
        // Stack layout (top first):
        // [old_node[3..0], depth, index, old_root[3..0], new_node[3..0], ...]
        let stack_inputs = [
            ZERO,                     // position 15 (bottom)
            ZERO,                     // position 14
            new_leaf[0],              // position 13
            new_leaf[1],              // position 12
            new_leaf[2],              // position 11
            new_leaf[3],              // position 10
            old_root[0],              // position 9
            old_root[1],              // position 8
            old_root[2],              // position 7
            old_root[3],              // position 6
            Felt::new(leaf_idx),      // position 5
            Felt::new(depth),         // position 4
            old_node[0],              // position 3
            old_node[1],              // position 2
            old_node[2],              // position 1
            old_node[3],              // position 0 (top)
        ];
        let mut processor = FastProcessor::new_with_advice_inputs(&stack_inputs, advice_inputs);
        let mut tracer = NoopTracer;

        // Execute the operation
        let result = op_mrupdate(&mut processor, &(), &mut tracer);
        prop_assert!(result.is_ok(), "op_mrupdate failed: {:?}", result.err());
        let _ = processor.increment_clk(&mut tracer, &NeverStopper);

        // Check the result
        let stack = processor.stack_top();

        // The old node value should be replaced with the new root
        prop_assert_eq!(stack[15], expected_new_root[3], "new_root[3] at position 0");
        prop_assert_eq!(stack[14], expected_new_root[2], "new_root[2] at position 1");
        prop_assert_eq!(stack[13], expected_new_root[1], "new_root[1] at position 2");
        prop_assert_eq!(stack[12], expected_new_root[0], "new_root[0] at position 3");

        // Check depth and index remain unchanged
        prop_assert_eq!(stack[11], Felt::new(depth), "depth at position 4");
        prop_assert_eq!(stack[10], Felt::new(leaf_idx), "index at position 5");

        // Check old root remains unchanged
        prop_assert_eq!(stack[9], old_root[3], "old_root[3] at position 6");
        prop_assert_eq!(stack[8], old_root[2], "old_root[2] at position 7");
        prop_assert_eq!(stack[7], old_root[1], "old_root[1] at position 8");
        prop_assert_eq!(stack[6], old_root[0], "old_root[0] at position 9");

        // Check new leaf remains unchanged
        prop_assert_eq!(stack[5], new_leaf[3], "new_leaf[3] at position 10");
        prop_assert_eq!(stack[4], new_leaf[2], "new_leaf[2] at position 11");
        prop_assert_eq!(stack[3], new_leaf[1], "new_leaf[1] at position 12");
        prop_assert_eq!(stack[2], new_leaf[0], "new_leaf[0] at position 13");

        // make sure both Merkle trees are still in the advice provider
        assert!(processor.advice.has_merkle_root(tree.root()));
        assert!(processor.advice.has_merkle_root(new_tree.root()));
    }
}

/// Tests Merkle tree subtree merge operation.
///
/// This test verifies that the `op_mrupdate` operation can merge a subtree into a larger tree.
/// This is a single deterministic test (not a proptest) since it requires a specific configuration
/// of two trees being merged.
#[test]
fn test_op_mrupdate_merge_subtree() {
    // Init 3 trees:
    // - `a`: the initial 16-leaf tree
    // - `b`: the 4-leaf subtree to merge
    // - `c`: the expected result after merging `b` into `a` at position [4..8]
    let leaves_a: Vec<Word> = (0..16).map(init_node).collect();
    let leaves_b: Vec<Word> = (100..104).map(init_node).collect();

    // Create leaves_c by replacing leaves 4..8 in leaves_a with leaves from leaves_b
    let mut leaves_c = leaves_a.clone();
    leaves_c[4..8].copy_from_slice(&leaves_b);

    let tree_a = MerkleTree::new(&leaves_a).unwrap();
    let tree_b = MerkleTree::new(&leaves_b).unwrap();
    let tree_c = MerkleTree::new(&leaves_c).unwrap();

    // Create a Merkle store with both input trees
    let mut store = MerkleStore::default();
    store.extend(tree_a.inner_nodes());
    store.extend(tree_b.inner_nodes());

    // Set the target coordinates to update indexes 4..8
    // At depth 2, index 1 corresponds to the subtree containing leaves 4..7
    let target_depth = 2_u64;
    let target_index = 1_u64;
    let target_node = tree_b.root(); // This subtree will replace the existing one

    // Get the expected new root and the node being replaced
    let expected_root = tree_c.root();
    let replaced_root = tree_a.root();
    let replaced_node = store
        .get_node(replaced_root, NodeIndex::new(target_depth as u8, target_index).unwrap())
        .unwrap();

    // Create advice inputs
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    // Build the initial stack state
    // Stack layout (top first):
    // [old_node[3..0], depth, index, old_root[3..0], new_node[3..0], ...]
    let stack_inputs = [
        ZERO,                    // position 15 (bottom)
        ZERO,                    // position 14
        target_node[0],          // position 13
        target_node[1],          // position 12
        target_node[2],          // position 11
        target_node[3],          // position 10
        replaced_root[0],        // position 9
        replaced_root[1],        // position 8
        replaced_root[2],        // position 7
        replaced_root[3],        // position 6
        Felt::new(target_index), // position 5
        Felt::new(target_depth), // position 4
        replaced_node[0],        // position 3
        replaced_node[1],        // position 2
        replaced_node[2],        // position 1
        replaced_node[3],        // position 0 (top)
    ];
    let mut processor = FastProcessor::new_with_advice_inputs(&stack_inputs, advice_inputs);
    let mut tracer = NoopTracer;

    // Execute the operation
    let result = op_mrupdate(&mut processor, &(), &mut tracer);
    assert!(result.is_ok(), "op_mrupdate failed: {:?}", result.err());
    let _ = processor.increment_clk(&mut tracer, &NeverStopper);

    // Check the result
    let stack = processor.stack_top();

    // The old node value should be replaced with the expected new root
    assert_eq!(stack[15], expected_root[3], "expected_root[3] at position 0");
    assert_eq!(stack[14], expected_root[2], "expected_root[2] at position 1");
    assert_eq!(stack[13], expected_root[1], "expected_root[1] at position 2");
    assert_eq!(stack[12], expected_root[0], "expected_root[0] at position 3");

    // Check depth and index remain unchanged
    assert_eq!(stack[11], Felt::new(target_depth), "depth at position 4");
    assert_eq!(stack[10], Felt::new(target_index), "index at position 5");

    // Check old root remains unchanged
    assert_eq!(stack[9], replaced_root[3], "replaced_root[3] at position 6");
    assert_eq!(stack[8], replaced_root[2], "replaced_root[2] at position 7");
    assert_eq!(stack[7], replaced_root[1], "replaced_root[1] at position 8");
    assert_eq!(stack[6], replaced_root[0], "replaced_root[0] at position 9");

    // Check target node remains unchanged
    assert_eq!(stack[5], target_node[3], "target_node[3] at position 10");
    assert_eq!(stack[4], target_node[2], "target_node[2] at position 11");
    assert_eq!(stack[3], target_node[1], "target_node[1] at position 12");
    assert_eq!(stack[2], target_node[0], "target_node[0] at position 13");

    // assert the expected root now exists in the advice provider
    assert!(processor.advice.has_merkle_root(expected_root));
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Creates a Word from a u64 value (used for Merkle tree leaves).
fn init_node(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO].into()
}

/// Builds an expected stack state from the given values.
///
/// The values are provided in "stack order" (top of stack first), and the result is a Vec<Felt>
/// that can be compared with `processor.stack_top()`, where the top of the stack is at the
/// **last** index.
#[allow(dead_code)]
fn build_expected(values: &[u64]) -> Vec<Felt> {
    let mut expected = vec![ZERO; MIN_STACK_DEPTH];
    for (i, &value) in values.iter().enumerate() {
        // In the result, top of stack is at index 15, second at 14, etc.
        expected[15 - i] = Felt::new(value);
    }
    expected
}
