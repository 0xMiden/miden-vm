use std::array;

use miden_core::{Felt, crypto::hash::Digest, utils::string_to_event_id};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};
use miden_stdlib::handlers::keccak::{KECCAK_EVENT_ID, pack_digest_u32};

// Test constants
// ================================================================================================

/// Memory address for storing test input data
const INPUT_MEMORY_ADDR: u32 = 128; // Word-aligned for memory operations

/// Event ID for debug/validation events
const DEBUG_EVENT_ID: &str = "miden::debug";

/// Event ID for memory validation
const MEMORY_CHECK_EVENT_ID: &str = "miden::memory_check";

#[test]
fn test_keccak_handler() {
    // Simple program that pushes preimage directly and calls our event
    const INPUT_U32: [u32; 4] = [1, 2, 3, u32::MAX];

    let source = format!(
        r#"
        begin
            push.{INPUT_U32:?}
            
            # Write the 4 u32 values to memory at INPUT_ADDR
            push.{INPUT_MEMORY_ADDR}
            mem_storew
            dropw
            
            # Set up stack for event: [ptr, len=16]
            push.16.{INPUT_MEMORY_ADDR}

            emit.event("{KECCAK_EVENT_ID}")

            drop drop
            emit.event("{DEBUG_EVENT_ID}")
        end
    "#
    );

    let mut test = build_debug_test!(source, &[]);

    // Comprehensive handler to validate the keccak event handler functionality
    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), |process: &ProcessState| {
        // 1. CHECK MEMORY: Verify ptr_in contains INPUT_U32
        let ctx = process.ctx();
        let memory_felt: Vec<Felt> = (INPUT_MEMORY_ADDR
            ..INPUT_MEMORY_ADDR + INPUT_U32.len() as u32)
            .map(|addr| process.get_mem_value(ctx, addr).unwrap())
            .collect();

        let input_felt: [Felt; 4] = INPUT_U32.map(Felt::from);
        assert_eq!(memory_felt, input_felt, "preimage stored in memory is not equal to input");

        // 2. CHECK ADVICE STACK: Verify advice contains keccak hash as 8 u32 values
        //    (stored in reverse)
        let hash_advice: Vec<Felt> =
            process.advice_provider().stack().iter().copied().rev().collect();

        let hash_expected: [Felt; 8] = {
            let input_u8: Vec<u8> = INPUT_U32.into_iter().flat_map(u32::to_le_bytes).collect();
            let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();
            pack_digest_u32(hash_u8).map(Felt::from)
        };

        assert_eq!(
            &hash_advice, &hash_expected,
            "advice stack should contain correct keccak hash as u32 values",
        );

        // 3. CHECK ADVICE MAP: Verify commitment->witness mapping exists

        // Calculate the expected commitment key (same logic as in event handler)
        let calldata_commitment = Rpo256::merge(&[
            Rpo256::hash_elements(&input_felt),    // Commitment to preimage
            Rpo256::hash_elements(&hash_expected), // Commitment to hash
        ]);

        // Verify the advice map contains our witness under this commitment
        let input_advice_map = process
            .advice_provider()
            .get_mapped_values(&calldata_commitment)
            .expect("no entry stored with call data commitment as key");

        assert_eq!(
            input_advice_map, input_felt,
            "stored witness in advice map should match original preimage",
        );

        Ok(vec![])
    });

    test.execute().unwrap();
}

#[test]
fn test_keccak_masm_wrapper() {
    let source = format!(
        r#"
        use.std::crypto::hashes::keccak_precompile
        use.std::sys

        # => [ptr, len]
        #    Advice: [b_1, ..., b_len]
        begin
            # Compute ptr_end = ptr + len
            dup.1 dup.1 add dup.1
            # => [ptr_curr, ptr_end, ptr, len]

            dup.1 dup.1 neq
            # Stack: [ptr_end != ptr_in, ptr_curr, ptr_end, ptr, len]

            # write the top n elements from the advice stack
            # to the memory region [ptr..ptr+len)
            while.true                  # [ptr_curr, ptr_end,   ptr,      len    ]
                adv_push.1              # [byte,     ptr_curr,  ptr_end,  ...    ]
                dup.1                   # [ptr_curr, bytes,     ptr_curr, ptr_end, ...]
                mem_store               # [ptr_curr, ptr_end,   ...]
                add.1 dup.1 dup.1 neq   # [(ptr_end!=ptr_next), ptr_next, ptr_end, ..]
            end                         # [ptr_end,  ptr_end,   ptr,      len    ]
            drop drop
            # => [ptr, len]

            # Save the arguments for the testing handler
            dup.1 dup.1
            # => [ptr, len, ptr, len]
            exec.keccak_precompile::keccak256_precompile
            # => [C, keccak_hi, keccak_lo, ptr, len]
            
            # Emit event to validate the resulting hash on the stack
            emit.event("{MEMORY_CHECK_EVENT_ID}")

            exec.sys::truncate_stack
        end
    "#
    );

    // Memory validation handler - checks that hash was written correctly to output memory
    fn check_memory_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        // [event_id, C, keccak_hi, keccak_lo, ptr, len, ...]
        let commitment = process.get_stack_word(1);
        // keccak hash stored in reverse order at indices [5..11]
        let hash_stack_felt: [Felt; 8] = array::from_fn(|i| process.get_stack_item(12 - i));
        let ptr = process.get_stack_item(13).as_int() as u32;
        let len = process.get_stack_item(14).as_int() as usize;
        let len_u32 = len.div_ceil(4) as u32;

        assert!(process.advice_provider().stack().is_empty(), "advice stack non-empty");

        let ctx = process.ctx();
        let input_felt: Vec<Felt> = (ptr..ptr + len_u32)
            .map(|addr| process.get_mem_value(ctx, addr).unwrap())
            .collect();
        let input_commitment = Rpo256::hash_elements(&input_felt);

        let hash_commitment = {
            // unpack the inputs from u32 to -> [u8; 4]
            let input_u32: Vec<u32> = input_felt.iter().map(|felt| felt.as_int() as u32).collect();
            let mut input_u8: Vec<u8> =
                input_u32.iter().copied().flat_map(|value| value.to_le_bytes()).collect();
            for to_drop in &input_u8[len..] {
                assert_eq!(*to_drop, 0, "padding bytes should be zero");
            }
            input_u8.truncate(len);

            // compute expected keccak digest
            let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();
            let hash_felt: [Felt; 8] = pack_digest_u32(hash_u8).map(Felt::from);

            // ensure the digests match
            assert_eq!(&hash_stack_felt, &hash_felt, "output hash does not match");
            // commit to digest
            Rpo256::hash_elements(&hash_felt)
        };

        // RPO( [RPO(input), RPO(keccak(input)) ]
        let expected_commitment = Rpo256::merge(&[input_commitment, hash_commitment]);

        assert_eq!(commitment, expected_commitment, "invalid commitment on stack");

        let input_advice = process.advice_provider().get_mapped_values(&commitment).unwrap();
        assert_eq!(input_advice, input_felt);

        Ok(vec![])
    }

    // check multiple sizes of preimages
    let preimages: Vec<Vec<u32>> = vec![
        vec![0],
        vec![0, 1],
        vec![0; 32],
        (0..32).collect(),
        (0..255).collect(),
        (34..1234).map(|x| (x % 254) as u32).collect(),
    ];

    for preimage in preimages {
        // Setup stack: [ptr_in, len] and advice: preimage[..]
        let stack_inputs = [preimage.len() as u64, INPUT_MEMORY_ADDR as u64];
        let advice_inputs: Vec<_> = preimage.into_iter().map(u64::from).collect();

        let mut test = build_debug_test!(source.clone(), &stack_inputs, &advice_inputs);
        test.add_event_handler(string_to_event_id(MEMORY_CHECK_EVENT_ID), check_memory_handler);

        test.execute().unwrap();
    }
}
