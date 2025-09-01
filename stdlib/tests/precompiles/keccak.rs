use miden_core::{Felt, crypto::hash::Digest, utils::string_to_event_id};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};
use miden_stdlib::precompiles::keccak::KECCAK_EVENT_ID;

// Test constants
// ================================================================================================

/// Memory address for storing test input data
const INPUT_MEMORY_ADDR: u32 = 128; // Word-aligned for memory operations

/// Memory address for storing keccak hash output
const OUTPUT_MEMORY_ADDR: u32 = 32; // Word-aligned for memory operations

/// Event ID for debug/validation events
const DEBUG_EVENT_ID: &str = "miden::debug";

/// Event ID for memory validation
const MEMORY_CHECK_EVENT_ID: &str = "miden::memory_check";

/// Expected hash output length in bytes
const KECCAK_HASH_SIZE: u32 = 32;

#[test]
fn test_keccak_event_handler_directly() {
    // Simple program that pushes preimage directly and calls our event
    const PREIMAGE: [u8; 4] = [1, 2, 3, 4];
    let source = format!(
        r#"
        begin
            push.{PREIMAGE:?}
            
            # Write the 4 bytes to memory at INPUT_ADDR
            push.{INPUT_MEMORY_ADDR}
            mem_storew
            dropw
            
            # Set up stack for event: [ptr, len=4]
            push.4.{INPUT_MEMORY_ADDR}

            emit.event("{KECCAK_EVENT_ID}")

            drop drop
            emit.event("{DEBUG_EVENT_ID}")
        end
    "#
    );

    let mut test = build_debug_test!(source, &[]);

    // Comprehensive handler to validate the keccak event handler functionality
    test.add_event_handler(string_to_event_id(DEBUG_EVENT_ID), |process: &ProcessState| {
        // 1. CHECK MEMORY: Verify ptr_in contains PREIMAGE
        let ctx = process.ctx();
        let memory_data: Vec<Felt> = (INPUT_MEMORY_ADDR..INPUT_MEMORY_ADDR + PREIMAGE.len() as u32)
            .map(|addr| process.get_mem_value(ctx, addr).unwrap())
            .collect();

        let memory_bytes: Vec<u8> = memory_data.iter().map(|felt| felt.as_int() as u8).collect();

        assert_eq!(memory_bytes, PREIMAGE, "preimage stored in memory is not equal to PREIMAGE");

        // 2. CHECK ADVICE STACK: Verify advice contains keccak hash (it is stored in reverse)
        let hash_from_advice: Vec<u8> = process
            .advice_provider()
            .stack()
            .iter()
            .rev()
            .map(|felt| felt.as_int() as u8)
            .collect();

        // Hash is stored in reverse order on advice stack
        let expected_hash = Keccak256::hash(&PREIMAGE).as_bytes();

        assert_eq!(
            hash_from_advice.as_slice(),
            &expected_hash,
            "advice stack should contain correct keccak hash",
        );

        // 3. CHECK ADVICE MAP: Verify commitment->witness mapping exists
        let expected_hash_felt = expected_hash.map(Felt::from);
        let witness = PREIMAGE.map(Felt::from);

        // Calculate the expected commitment key (same logic as in event handler)
        let calldata_commitment = Rpo256::merge(&[
            Rpo256::hash_elements(&witness),            // Commitment to preimage
            Rpo256::hash_elements(&expected_hash_felt), // Commitment to hash
        ]);

        // Verify the advice map contains our witness under this commitment
        let advice_map_witness = process
            .advice_provider()
            .get_mapped_values(&calldata_commitment)
            .expect("no entry stored with call data commitment as key");

        assert_eq!(
            advice_map_witness, witness,
            "Stored witness in advice map should match original preimage",
        );

        Ok(vec![])
    });

    test.execute().unwrap();
}

#[test]
fn test_keccak_precompile_masm_wrapper() {
    let source = format!(
        r#"
        use.std::crypto::hashes::keccak_precompile
        use.std::sys

        begin
            # start:
            # Stack: [ptr_in, n, ptr_out]
            # Advice: [b_1, ..., b_n]

            # Compute ptr_end = ptr_in + n
            dup.1 dup.1 add dup.1
            # Stack: [ptr_curr, ptr_end, ptr_in, n, ptr_out]

            dup.1 dup.1 neq
            # Stack: [ptr_end != ptr_in, ptr_curr, ptr_end, ptr_in, n, ptr_out]

            while.true                  # [ptr_curr, ptr_end,    ptr_in,     n, ptr_out]
                adv_push.1              # [byte,     ptr_curr,   ptr_end,    ...]
                dup.1                   # [ptr_curr, bytes,      ptr_curr,   ptr_end, ...]
                mem_store               # [ptr_curr, ptr_end,    ...]
                add.1 dup.1 dup.1 neq   # [(ptr_end!=ptr_next),  ptr_next, ptr_end, ..]
            end
            drop drop
            dup.2 dup.2 dup.2
            # Stack: [ptr_in, n, ptr_out, ptr_in, n, ptr_out]
            # mem[ptr_in..ptr_in+n] = [b_1, ..., b_n]

            # Call keccak wrapper: keccak256_precompile(ptr_in, len, ptr_out)
            exec.keccak_precompile::keccak256_precompile
            # stack: [C, ptr_in, n, ptr_out]
            
            # Emit event to validate the hash was written correctly to memory
            swapw
            # stack: [ptr_in, n, ptr_out, 0, C]
            emit.event("{MEMORY_CHECK_EVENT_ID}")

            exec.sys::truncate_stack
        end
    "#
    );

    // Memory validation handler - checks that hash was written correctly to output memory
    fn check_memory_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        let [ptr_in, len, ptr_out] = [1, 2, 3].map(|i| process.get_stack_item(i).as_int() as u32);

        // Validate the output address matches our constant
        assert_eq!(ptr_out, OUTPUT_MEMORY_ADDR, "output pointers should be equal");

        assert!(process.advice_provider().stack().is_empty(), "advice stack non-empty");

        let ctx = process.ctx();
        let preimage_felt = (ptr_in..ptr_in + len)
            .map(|addr| process.get_mem_value(ctx, addr).unwrap())
            .collect::<Vec<_>>();
        let preimage_byte =
            preimage_felt.iter().map(|felt| felt.as_int() as u8).collect::<Vec<_>>();
        let preimage_commitment = Rpo256::hash_elements(&preimage_felt);

        let keccak_commitment = {
            // compute expected keccak digest
            let keccak_hash_byte = Keccak256::hash(&preimage_byte);

            // convert to Felt
            let keccak_hash_felt =
                keccak_hash_byte.iter().copied().map(Felt::from).collect::<Vec<_>>();

            // get the digest computed by the handler from memory
            let keccak_hash_felt_mem = (ptr_out..ptr_out + KECCAK_HASH_SIZE)
                .map(|addr| process.get_mem_value(ctx, addr).unwrap())
                .collect::<Vec<_>>();
            // ensure the digests match
            assert_eq!(keccak_hash_felt, keccak_hash_felt_mem, "output hash does not match");
            // commit to digest
            Rpo256::hash_elements(&keccak_hash_felt)
        };

        // RPO( [RPO(preimage), RPO(keccak(preimage)) ]
        let commitment = process.get_stack_word(5);
        let expected_commitment = Rpo256::merge(&[preimage_commitment, keccak_commitment]);

        assert_eq!(commitment, expected_commitment, "invalid commitment on stack");

        Ok(vec![])
    }

    // check multiple sizes of preimages
    let preimages: Vec<Vec<u8>> = vec![
        vec![0],
        vec![0, 1],
        vec![0; 32],
        (0..32).collect(),
        (0..255).collect(),
        (34..1234).map(|x| (x % 254) as u8).collect(),
    ];

    for preimage in preimages {
        // Setup stack: [ptr_in, len, ptr_out] and advice: preimage[..]
        let stack_inputs =
            [OUTPUT_MEMORY_ADDR as u64, preimage.len() as u64, INPUT_MEMORY_ADDR as u64];
        let advice_inputs: Vec<_> = preimage.iter().copied().map(u64::from).collect();

        let mut test = build_debug_test!(source.clone(), &stack_inputs, &advice_inputs);
        test.add_event_handler(string_to_event_id(MEMORY_CHECK_EVENT_ID), check_memory_handler);

        test.execute().unwrap();
    }
}
