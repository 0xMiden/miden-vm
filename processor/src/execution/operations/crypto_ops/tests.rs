use alloc::vec::Vec;

use miden_core::{
    Felt, ONE, Word, ZERO,
    chiplets::{
        blakeg,
        hasher::{Hasher, compress_state},
    },
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    field::{BasedVectorSpace, QuadFelt},
    program::StackInputs,
};
use proptest::prelude::*;

use super::{
    op_aead_stream, op_bcompress, op_horner_eval_base, op_horner_eval_ext, op_mpverify, op_mrupdate,
};
use crate::{
    AdviceInputs, ContextId,
    fast::{FastProcessor, NoopTracer},
    processor::{Processor, SystemInterface},
};

// CONSTANTS
// --------------------------------------------------------------------------------------------

// The memory address where alpha is stored
const ALPHA_ADDR: u64 = 1000;

// HASHING TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_bcompress(
        // Input state: 12 elements for the hasher state (positions 0-11)
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
        let stack_inputs = [
            felt(s0),  // position 0 (top)
            felt(s1),  // position 1
            felt(s2),  // position 2
            felt(s3),  // position 3
            felt(s4),  // position 4
            felt(s5),  // position 5
            felt(s6),  // position 6
            felt(s7),  // position 7
            felt(s8),  // position 8
            felt(s9),  // position 9
            felt(s10), // position 10
            felt(s11), // position 11
            felt(s12), // position 12
            felt(s13), // position 13
            felt(s14), // position 14
            felt(s15), // position 15 (bottom)
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        let mut tracer = NoopTracer;

        // Compute expected result
        // input_state[i] = stack.get(i)
        // So input_state = [s0, s1, s2, ..., s11]
        let expected_state = {
            let mut expected_state = [
                felt(s0),
                felt(s1),
                felt(s2),
                felt(s3),
                felt(s4),
                felt(s5),
                felt(s6),
                felt(s7),
                felt(s8),
                felt(s9),
                felt(s10),
                felt(s11),
            ];
            compress_state(&mut expected_state);

            expected_state
        };

        // Execute the operation
        let _ = op_bcompress(&mut processor, &mut tracer);
        processor.system_mut().increment_clock();

        // Check the result
        let stack = processor.stack_top();

        // bcompress preserves the 8-felt block and writes the digest into the CV word.
        for i in 0..8 {
            prop_assert_eq!(stack[15 - i], stack_inputs[i], "block mismatch at position {}", i);
        }
        for (j, i) in Hasher::DIGEST_RANGE.enumerate() {
            prop_assert_eq!(stack[15 - (8 + j)], expected_state[i], "CV mismatch at lane {}", j);
        }

        // Check that positions 12-15 are NOT affected
        prop_assert_eq!(stack[3], felt(s12), "s12 at position 12");
        prop_assert_eq!(stack[2], felt(s13), "s13 at position 13");
        prop_assert_eq!(stack[1], felt(s14), "s14 at position 14");
        prop_assert_eq!(stack[0], felt(s15), "s15 at position 15");
    }
}

// STREAM CIPHER TESTS
// --------------------------------------------------------------------------------------------

proptest! {
    #[test]
    fn test_op_aead_stream(
        k0 in any::<u64>(),
        k1 in any::<u64>(),
        k2 in any::<u64>(),
        k3 in any::<u64>(),
        counter in any::<u64>(),
        remaining in 1_u64..1000,
        tail0 in any::<u64>(),
        tail1 in any::<u64>(),
        tail2 in any::<u64>(),
        tail3 in any::<u64>(),
        tail4 in any::<u64>(),
        tail5 in any::<u64>(),
        tail6 in any::<u64>(),
        tail7 in any::<u64>(),
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

        // Stack layout: [K_CTR(4), counter, src_ptr, dst_ptr, remaining, tail(8)].
        let stack_inputs = [
            felt(k0),
            felt(k1),
            felt(k2),
            felt(k3),
            felt(counter),
            felt(src_addr),
            felt(dst_addr),
            felt(remaining),
            felt(tail0),
            felt(tail1),
            felt(tail2),
            felt(tail3),
            felt(tail4),
            felt(tail5),
            felt(tail6),
            felt(tail7),
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        let mut tracer = NoopTracer;

        // Store plaintext in memory at src_addr
        let plaintext_word1: Word = [felt(p0), felt(p1), felt(p2), felt(p3)].into();
        let plaintext_word2: Word = [felt(p4), felt(p5), felt(p6), felt(p7)].into();

        let clk = processor.clock();
        processor.memory_mut().write_word(
            ContextId::root(),
            felt(src_addr),
            clk,
            plaintext_word1,
        ).unwrap();
        processor.system_mut().increment_clock();

        let clk = processor.clock();
        processor.memory_mut().write_word(
            ContextId::root(),
            felt(src_addr + 4),
            clk,
            plaintext_word2,
        ).unwrap();
        processor.system_mut().increment_clock();

        let input_state = [
            felt(counter),
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            felt(k0),
            felt(k1),
            felt(k2),
            felt(k3),
        ];
        let keystream = blakeg::compress_raw_xof_lanes(&input_state);
        let plaintext = [plaintext_word1, plaintext_word2];
        let expected_ciphertext: [Felt; 16] = core::array::from_fn(|i| {
            let (lo, hi) = blakeg::unpack(plaintext[i / 8][(i % 8) / 2]);
            let p = if i % 2 == 0 { lo } else { hi };
            Felt::from_u32(p ^ keystream[i])
        });

        let result = op_aead_stream(&mut processor, &mut tracer);
        prop_assert!(result.is_ok());
        processor.system_mut().increment_clock();

        let clk = processor.clock();
        for word_idx in 0..4 {
            let actual = processor
                .memory_mut()
                .read_word(
                    ContextId::root(),
                    felt(dst_addr + 4 * word_idx as u64),
                    clk,
                )
                .unwrap();
            for lane in 0..4 {
                prop_assert_eq!(
                    actual[lane],
                    expected_ciphertext[4 * word_idx + lane],
                    "cipher word {} lane {}",
                    word_idx,
                    lane,
                );
            }
        }

        let stack = processor.stack_top();

        prop_assert_eq!(stack[15], felt(k0), "K_CTR[0]");
        prop_assert_eq!(stack[14], felt(k1), "K_CTR[1]");
        prop_assert_eq!(stack[13], felt(k2), "K_CTR[2]");
        prop_assert_eq!(stack[12], felt(k3), "K_CTR[3]");
        prop_assert_eq!(stack[11], felt(counter) + ONE, "counter");
        prop_assert_eq!(stack[10], felt(src_addr + 8), "src_ptr");
        prop_assert_eq!(stack[9], felt(dst_addr + 16), "dst_ptr");
        prop_assert_eq!(stack[8], felt(remaining) - ONE, "remaining");
        for i in 0..8 {
            prop_assert_eq!(stack[7 - i], stack_inputs[8 + i], "tail lane {}", i);
        }
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
        // Build the initial stack state (low index coefficient at lower position)
        // Stack layout (top first): [c0, c1, c2, c3, c4, c5, c6, c7, s8, s9, s10, s11, s12, alpha_addr, acc0, acc1]
        // Position 0 (top) = c0, position 7 = c7, position 13 = alpha_addr, position 14 = acc0, position 15 = acc1
        let stack_inputs = [
            felt(c0),          // position 0 (top)
            felt(c1),          // position 1
            felt(c2),          // position 2
            felt(c3),          // position 3
            felt(c4),          // position 4
            felt(c5),          // position 5
            felt(c6),          // position 6
            felt(c7),          // position 7
            felt(s8),          // position 8
            felt(s9),          // position 9
            felt(s10),         // position 10
            felt(s11),         // position 11
            felt(s12),         // position 12
            felt(ALPHA_ADDR),  // position 13
            felt(acc_0),       // position 14 (acc low)
            felt(acc_1),       // position 15 (bottom, acc high)
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        let mut tracer = NoopTracer;

        // Store alpha in memory at ALPHA_ADDR
        // Memory format requirement: [alpha_0, alpha_1, 0, 0]
        let alpha_word: Word = [felt(alpha_0), felt(alpha_1), ZERO, ZERO].into();
        let clk = processor.clock();
        processor.memory_mut().write_word(
            ContextId::root(),
            felt(ALPHA_ADDR),
            clk,
            alpha_word,
        ).unwrap();
        processor.system_mut().increment_clock();

        // Execute the operation.
        //
        // Note that we don't check the correctness of the helper registers here, since the
        // `FastProcessor` does not generate them (as they are only relevant in trace generation).
        let result = op_horner_eval_base(&mut processor, &mut tracer);
        prop_assert!(result.is_ok());
        processor.system_mut().increment_clock();

        // Compute expected result
        let alpha = QuadFelt::new([felt(alpha_0), felt(alpha_1)]);
        let acc_old = QuadFelt::new([felt(acc_0), felt(acc_1)]);

        let c0_q = QuadFelt::from(felt(c0));
        let c1_q = QuadFelt::from(felt(c1));
        let c2_q = QuadFelt::from(felt(c2));
        let c3_q = QuadFelt::from(felt(c3));
        let c4_q = QuadFelt::from(felt(c4));
        let c5_q = QuadFelt::from(felt(c5));
        let c6_q = QuadFelt::from(felt(c6));
        let c7_q = QuadFelt::from(felt(c7));

        // Horner evaluation: P(α) = c0*α⁷ + c1*α⁶ + c2*α⁵ + c3*α⁴ + c4*α³ + c5*α² + c6*α + c7
        // c0 (at stack position 0) has highest degree, c7 (at stack position 7) is constant term
        // Level 1: tmp0 = (acc * α + c₀) * α + c₁
        let tmp0 = (acc_old * alpha + c0_q) * alpha + c1_q;

        // Level 2: tmp1 = ((tmp0 * α + c₂) * α + c₃) * α + c₄
        let tmp1 = ((tmp0 * alpha + c2_q) * alpha + c3_q) * alpha + c4_q;

        // Level 3: acc' = ((tmp1 * α + c₅) * α + c₆) * α + c₇
        let acc_new = ((tmp1 * alpha + c5_q) * alpha + c6_q) * alpha + c7_q;

        // Check stack state using stack_top()
        // stack_top() returns a slice of 16 elements where index 15 = top, index 0 = bottom
        let stack = processor.stack_top();

        // Check that the top 8 stack elements (coefficients) were NOT affected (LE: c0 at top)
        prop_assert_eq!(stack[15], felt(c0), "c0 at position 0 (top)");
        prop_assert_eq!(stack[14], felt(c1), "c1 at position 1");
        prop_assert_eq!(stack[13], felt(c2), "c2 at position 2");
        prop_assert_eq!(stack[12], felt(c3), "c3 at position 3");
        prop_assert_eq!(stack[11], felt(c4), "c4 at position 4");
        prop_assert_eq!(stack[10], felt(c5), "c5 at position 5");
        prop_assert_eq!(stack[9], felt(c6), "c6 at position 6");
        prop_assert_eq!(stack[8], felt(c7), "c7 at position 7");

        // Check that middle stack elements were NOT affected
        prop_assert_eq!(stack[7], felt(s8), "s8 at position 8");
        prop_assert_eq!(stack[6], felt(s9), "s9 at position 9");
        prop_assert_eq!(stack[5], felt(s10), "s10 at position 10");
        prop_assert_eq!(stack[4], felt(s11), "s11 at position 11");
        prop_assert_eq!(stack[3], felt(s12), "s12 at position 12");

        // Check that alpha_addr was NOT affected
        prop_assert_eq!(stack[2], felt(ALPHA_ADDR), "alpha_addr at position 13");

        // Check that the accumulator was updated correctly (LE: low at lower position)
        let acc_new_base: &[Felt] = acc_new.as_basis_coefficients_slice();
        prop_assert_eq!(stack[1], acc_new_base[0], "acc_low at position 14");
        prop_assert_eq!(stack[0], acc_new_base[1], "acc_high at position 15");
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
        // Build the initial stack state (low coefficient at lower position)
        // Stack layout for extension field coefficients:
        // Position 0 (top) = c0_0 (low), position 1 = c0_1 (high)
        // Position 2 = c1_0 (low), position 3 = c1_1 (high)
        // Position 4 = c2_0 (low), position 5 = c2_1 (high)
        // Position 6 = c3_0 (low), position 7 = c3_1 (high)
        // Position 13 = alpha_addr, position 14 = acc0 (low), position 15 = acc1 (high)
        let stack_inputs = [
            felt(c0_0),        // position 0 (top, c0 low)
            felt(c0_1),        // position 1 (c0 high)
            felt(c1_0),        // position 2 (c1 low)
            felt(c1_1),        // position 3 (c1 high)
            felt(c2_0),        // position 4 (c2 low)
            felt(c2_1),        // position 5 (c2 high)
            felt(c3_0),        // position 6 (c3 low)
            felt(c3_1),        // position 7 (c3 high)
            felt(s8),          // position 8
            felt(s9),          // position 9
            felt(s10),         // position 10
            felt(s11),         // position 11
            felt(s12),         // position 12
            felt(ALPHA_ADDR),  // position 13
            felt(acc_0),       // position 14 (low)
            felt(acc_1),       // position 15 (bottom, high)
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap());
        let mut tracer = NoopTracer;

        // Store alpha in memory at ALPHA_ADDR
        // Memory format requirement: [alpha_0, alpha_1, k0, k1] (k0, k1 are unused but read)
        let alpha_word: Word = [felt(alpha_0), felt(alpha_1), ZERO, ZERO].into();
        let clk = processor.clock();
        processor.memory_mut().write_word(
            ContextId::root(),
            felt(ALPHA_ADDR),
            clk,
            alpha_word,
        ).unwrap();
        processor.system_mut().increment_clock();

        // Execute the operation
        let result = op_horner_eval_ext(&mut processor, &mut tracer);
        prop_assert!(result.is_ok());
        processor.system_mut().increment_clock();

        // Compute expected result
        let alpha = QuadFelt::new([felt(alpha_0), felt(alpha_1)]);
        let acc_old = QuadFelt::new([felt(acc_0), felt(acc_1)]);

        let c0 = QuadFelt::new([felt(c0_0), felt(c0_1)]);
        let c1 = QuadFelt::new([felt(c1_0), felt(c1_1)]);
        let c2 = QuadFelt::new([felt(c2_0), felt(c2_1)]);
        let c3 = QuadFelt::new([felt(c3_0), felt(c3_1)]);

        let coefficients = [c0, c1, c2, c3];

        // Horner evaluation: P(α) = c0*α³ + c1*α² + c2*α + c3
        // c0 (at stack positions 0,1) has highest degree, c3 (at stack positions 6,7) is constant term
        // acc_tmp = coef.iter().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc)
        let acc_tmp = coefficients.iter().take(2).fold(acc_old, |acc, coef| *coef + alpha * acc);
        let acc_new = coefficients.iter().skip(2).fold(acc_tmp, |acc, coef| *coef + alpha * acc);

        // Check stack state using stack_top()
        let stack = processor.stack_top();

        // Check that the top 8 stack elements (coefficients) were NOT affected (LE: low at lower position)
        prop_assert_eq!(stack[15], felt(c0_0), "c0_0 at position 0 (top, low)");
        prop_assert_eq!(stack[14], felt(c0_1), "c0_1 at position 1 (high)");
        prop_assert_eq!(stack[13], felt(c1_0), "c1_0 at position 2 (low)");
        prop_assert_eq!(stack[12], felt(c1_1), "c1_1 at position 3 (high)");
        prop_assert_eq!(stack[11], felt(c2_0), "c2_0 at position 4 (low)");
        prop_assert_eq!(stack[10], felt(c2_1), "c2_1 at position 5 (high)");
        prop_assert_eq!(stack[9], felt(c3_0), "c3_0 at position 6 (low)");
        prop_assert_eq!(stack[8], felt(c3_1), "c3_1 at position 7 (high)");

        // Check that middle stack elements were NOT affected
        prop_assert_eq!(stack[7], felt(s8), "s8 at position 8");
        prop_assert_eq!(stack[6], felt(s9), "s9 at position 9");
        prop_assert_eq!(stack[5], felt(s10), "s10 at position 10");
        prop_assert_eq!(stack[4], felt(s11), "s11 at position 11");
        prop_assert_eq!(stack[3], felt(s12), "s12 at position 12");

        // Check that alpha_addr was NOT affected
        prop_assert_eq!(stack[2], felt(ALPHA_ADDR), "alpha_addr at position 13");

        // Check that the accumulator was updated correctly (LE: low at lower position)
        let acc_new_base: &[Felt] = acc_new.as_basis_coefficients_slice();
        prop_assert_eq!(stack[1], acc_new_base[0], "acc_low at position 14");
        prop_assert_eq!(stack[0], acc_new_base[1], "acc_high at position 15");
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
        // word[0] at lowest position (closest to top)
        // Stack layout (top first): [node[0], node[1], node[2], node[3], depth, index, root[0], root[1], root[2], root[3], ...]
        let stack_inputs = [
            node[0],               // position 0 (top, node[0])
            node[1],               // position 1
            node[2],               // position 2
            node[3],               // position 3 (node[3])
            felt(depth),      // position 4
            felt(leaf_idx),   // position 5
            root[0],               // position 6 (root[0])
            root[1],               // position 7
            root[2],               // position 8
            root[3],               // position 9 (root[3])
            ZERO,                  // position 10
            ZERO,                  // position 11
            ZERO,                  // position 12
            ZERO,                  // position 13
            ZERO,                  // position 14
            ZERO,                  // position 15 (bottom)
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap())
            .with_advice(advice_inputs).expect("advice inputs should fit advice map limits");
        let mut tracer = NoopTracer;
        // Execute the operation
        let result = op_mpverify(&mut processor, ZERO, &mut tracer);
        prop_assert!(result.is_ok(), "op_mpverify failed: {:?}", result.err());
        processor.system_mut().increment_clock();

        // The stack should remain unchanged after verification
        let stack = processor.stack_top();

        // Check node value (top of stack) - LE: node[0] at position 0 (stack[15])
        prop_assert_eq!(stack[15], node[0], "node[0] at position 0");
        prop_assert_eq!(stack[14], node[1], "node[1] at position 1");
        prop_assert_eq!(stack[13], node[2], "node[2] at position 2");
        prop_assert_eq!(stack[12], node[3], "node[3] at position 3");

        // Check depth and index
        prop_assert_eq!(stack[11], felt(depth), "depth at position 4");
        prop_assert_eq!(stack[10], felt(leaf_idx), "index at position 5");

        // Check root value - LE: root[0] at position 6 (stack[9])
        prop_assert_eq!(stack[9], root[0], "root[0] at position 6");
        prop_assert_eq!(stack[8], root[1], "root[1] at position 7");
        prop_assert_eq!(stack[7], root[2], "root[2] at position 8");
        prop_assert_eq!(stack[6], root[3], "root[3] at position 9");
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
        // word[0] at lowest position (closest to top)
        // Stack layout (top first):
        // [old_node[0..3], depth, index, old_root[0..3], new_node[0..3], ...]
        let stack_inputs = [
            old_node[0],              // position 0 (top, old_node[0])
            old_node[1],              // position 1
            old_node[2],              // position 2
            old_node[3],              // position 3 (old_node[3])
            felt(depth),         // position 4
            felt(leaf_idx),      // position 5
            old_root[0],              // position 6 (old_root[0])
            old_root[1],              // position 7
            old_root[2],              // position 8
            old_root[3],              // position 9 (old_root[3])
            new_leaf[0],              // position 10 (new_leaf[0])
            new_leaf[1],              // position 11
            new_leaf[2],              // position 12
            new_leaf[3],              // position 13 (new_leaf[3])
            ZERO,                     // position 14
            ZERO,                     // position 15 (bottom)
        ];
        let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap())
            .with_advice(advice_inputs).expect("advice inputs should fit advice map limits");
        let mut tracer = NoopTracer;

        // Execute the operation
        let result = op_mrupdate(&mut processor, &mut tracer);
        prop_assert!(result.is_ok(), "op_mrupdate failed: {:?}", result.err());
        processor.system_mut().increment_clock();

        // Check the result
        let stack = processor.stack_top();

        // The old node value should be replaced with the new root (LE: [0] at position 0)
        prop_assert_eq!(stack[15], expected_new_root[0], "new_root[0] at position 0");
        prop_assert_eq!(stack[14], expected_new_root[1], "new_root[1] at position 1");
        prop_assert_eq!(stack[13], expected_new_root[2], "new_root[2] at position 2");
        prop_assert_eq!(stack[12], expected_new_root[3], "new_root[3] at position 3");

        // Check depth and index remain unchanged
        prop_assert_eq!(stack[11], felt(depth), "depth at position 4");
        prop_assert_eq!(stack[10], felt(leaf_idx), "index at position 5");

        // Check old root remains unchanged (LE: [0] at position 6)
        prop_assert_eq!(stack[9], old_root[0], "old_root[0] at position 6");
        prop_assert_eq!(stack[8], old_root[1], "old_root[1] at position 7");
        prop_assert_eq!(stack[7], old_root[2], "old_root[2] at position 8");
        prop_assert_eq!(stack[6], old_root[3], "old_root[3] at position 9");

        // Check new leaf remains unchanged (LE: [0] at position 10)
        prop_assert_eq!(stack[5], new_leaf[0], "new_leaf[0] at position 10");
        prop_assert_eq!(stack[4], new_leaf[1], "new_leaf[1] at position 11");
        prop_assert_eq!(stack[3], new_leaf[2], "new_leaf[2] at position 12");
        prop_assert_eq!(stack[2], new_leaf[3], "new_leaf[3] at position 13");

        // make sure both Merkle trees are still in the advice provider
        assert!(processor.advice_provider().has_merkle_root(tree.root()));
        assert!(processor.advice_provider().has_merkle_root(new_tree.root()));
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
    // word[0] at lowest position (closest to top)
    // Stack layout (top first):
    // [old_node[0..3], depth, index, old_root[0..3], new_node[0..3], ...]
    let stack_inputs = [
        replaced_node[0],   // position 0 (top, replaced_node[0])
        replaced_node[1],   // position 1
        replaced_node[2],   // position 2
        replaced_node[3],   // position 3 (replaced_node[3])
        felt(target_depth), // position 4
        felt(target_index), // position 5
        replaced_root[0],   // position 6 (replaced_root[0])
        replaced_root[1],   // position 7
        replaced_root[2],   // position 8
        replaced_root[3],   // position 9 (replaced_root[3])
        target_node[0],     // position 10 (target_node[0])
        target_node[1],     // position 11
        target_node[2],     // position 12
        target_node[3],     // position 13 (target_node[3])
        ZERO,               // position 14
        ZERO,               // position 15 (bottom)
    ];
    let mut processor = FastProcessor::new(StackInputs::new(&stack_inputs).unwrap())
        .with_advice(advice_inputs)
        .expect("advice inputs should fit advice map limits");
    let mut tracer = NoopTracer;

    // Execute the operation
    let result = op_mrupdate(&mut processor, &mut tracer);
    assert!(result.is_ok(), "op_mrupdate failed: {:?}", result.err());
    processor.system_mut().increment_clock();

    // Check the result
    let stack = processor.stack_top();

    // The old node value should be replaced with the expected new root (LE: [0] at position 0)
    assert_eq!(stack[15], expected_root[0], "expected_root[0] at position 0");
    assert_eq!(stack[14], expected_root[1], "expected_root[1] at position 1");
    assert_eq!(stack[13], expected_root[2], "expected_root[2] at position 2");
    assert_eq!(stack[12], expected_root[3], "expected_root[3] at position 3");

    // Check depth and index remain unchanged
    assert_eq!(stack[11], felt(target_depth), "depth at position 4");
    assert_eq!(stack[10], felt(target_index), "index at position 5");

    // Check old root remains unchanged (LE: [0] at position 6)
    assert_eq!(stack[9], replaced_root[0], "replaced_root[0] at position 6");
    assert_eq!(stack[8], replaced_root[1], "replaced_root[1] at position 7");
    assert_eq!(stack[7], replaced_root[2], "replaced_root[2] at position 8");
    assert_eq!(stack[6], replaced_root[3], "replaced_root[3] at position 9");

    // Check target node remains unchanged (LE: [0] at position 10)
    assert_eq!(stack[5], target_node[0], "target_node[0] at position 10");
    assert_eq!(stack[4], target_node[1], "target_node[1] at position 11");
    assert_eq!(stack[3], target_node[2], "target_node[2] at position 12");
    assert_eq!(stack[2], target_node[3], "target_node[3] at position 13");

    // assert the expected root now exists in the advice provider
    assert!(processor.advice_provider().has_merkle_root(expected_root));
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

/// Creates a canonical Felt from an arbitrary u64 value.
fn felt(value: u64) -> Felt {
    Felt::new_unchecked(value % Felt::ORDER)
}

/// Creates a Word from a u64 value (used for Merkle tree leaves).
fn init_node(value: u64) -> Word {
    [felt(value), ZERO, ZERO, ZERO].into()
}
