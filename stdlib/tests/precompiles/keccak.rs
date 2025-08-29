use miden_core::{Felt, FieldElement, utils::string_to_event_id};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};
use miden_stdlib::precompiles::{KECCAK_EVENT_ID, push_keccak};

// Test constants
// ================================================================================================

/// Memory address for storing test input data
const INPUT_MEMORY_ADDR: u32 = 100;

/// Memory address for storing keccak hash output
const OUTPUT_MEMORY_ADDR: u32 = 200;

/// Event ID for debug/validation events
const DEBUG_EVENT_ID: &str = "miden::debug";

/// Event ID for memory validation
const MEMORY_CHECK_EVENT_ID: &str = "miden::memory_check";

/// Event ID for system precompile recording
const SYSTEM_RECORD_EVENT_ID: &str = "system::record_precompile";

/// Expected hash output length in bytes
const KECCAK_HASH_SIZE: u64 = 32;

#[test]
fn test_keccak_event_handler_directly() {
    // Compute event ID at runtime
    let event_keccak_precompile = string_to_event_id(KECCAK_EVENT_ID);

    // Simple program that sets up memory and calls our event
    let source = format!(
        r#"
        const.INPUT_ADDR={INPUT_MEMORY_ADDR}
        const.INPUT_LEN=4
        
        begin
            # Write the 4 stack input elements to memory at INPUT_ADDR
            push.INPUT_ADDR
            mem_storew
            dropw
            
            # Set up stack for event: [ptr, len]
            push.INPUT_LEN     # len (4 bytes)
            push.INPUT_ADDR    # ptr (where data is stored)

            emit.event("{KECCAK_EVENT_ID}")

            drop drop
            emit.event("{DEBUG_EVENT_ID}")
        end
    "#
    );

    const PREIMAGE: [u8; 4] = [1, 2, 3, 4];

    let stack_inputs = PREIMAGE.map(u64::from);
    let mut test = build_debug_test!(source, &stack_inputs);
    test.add_event_handler(event_keccak_precompile, push_keccak);

    // Use a custom handler to ensure the advice stack contains the expected hash.
    let event_check_state = string_to_event_id(DEBUG_EVENT_ID);
    let check_advice = |process: &ProcessState| {
        let hash: Vec<u8> = process
            .advice_provider()
            .stack()
            .iter()
            .map(|felt| felt.as_int() as u8)
            .collect();

        // hash is stored in reverse order
        let hash_rev: Vec<_> = hash.iter().copied().rev().collect();
        let expected_hash = Keccak256::hash(&PREIMAGE);
        assert_eq!(
            hash_rev.as_slice(),
            expected_hash.as_ref(),
            "Advice stack should contain keccak hash but got {} bytes, expected {} bytes",
            hash_rev.len(),
            KECCAK_HASH_SIZE
        );

        let expected_hash_felt: Vec<Felt> = expected_hash.iter().copied().map(Felt::from).collect();

        // Check advice map contains the witness (preimage)
        // The event handler should have added an entry with commitment -> witness mapping

        // Reconstruct the witness as field elements (same as in the event handler)
        let witness: Vec<Felt> = PREIMAGE.iter().copied().map(Felt::from).collect();

        // Calculate the expected commitment key (same logic as in event handler)
        let calldata_commitment = Rpo256::merge(&[
            Rpo256::hash_elements(&witness),            // Commitment to pre-image
            Rpo256::hash_elements(&expected_hash_felt), // Commitment to hash
        ]);

        // Check that the advice map contains our witness under this commitment
        let advice_map_entry = process.advice_provider().get_mapped_values(&calldata_commitment);
        assert!(
            advice_map_entry.is_some(),
            "Advice map should contain witness under commitment key: {}",
            calldata_commitment
        );

        let stored_witness = advice_map_entry.unwrap();
        assert_eq!(
            stored_witness,
            witness,
            "Stored witness should match original preimage: expected {} felts, got {} felts",
            witness.len(),
            stored_witness.len()
        );
        Ok(vec![])
    };
    test.add_event_handler(event_check_state, check_advice);

    test.execute().unwrap();
}

#[test]
fn test_keccak_precompile_masm_wrapper() {
    // Test the full MASM wrapper function that calls the event handler
    // and outputs the commitment to the calldata on the stack

    let event_keccak_precompile = string_to_event_id(KECCAK_EVENT_ID);
    let event_system_record = string_to_event_id(SYSTEM_RECORD_EVENT_ID);
    let event_memory_check = string_to_event_id(MEMORY_CHECK_EVENT_ID);

    const PREIMAGE: [u8; 5] = [5, 6, 7, 8, 9];
    const PREIMAGE_LEN: usize = PREIMAGE.len();

    let source = format!(
        r#"
        use.std::crypto::hashes::keccak_precompile
        use.std::sys
        
        const.INPUT_ADDR={INPUT_MEMORY_ADDR}
        const.OUTPUT_ADDR={OUTPUT_MEMORY_ADDR}
        const.INPUT_LEN={PREIMAGE_LEN}

        begin
            # Write test data [5, 6, 7, 8] to memory at INPUT_ADDR
            push.INPUT_ADDR
            mem_storew
            dropw
            
            # Call keccak wrapper: keccak256_precompile(ptr_in, len, ptr_out)
            # This will output the commitment to the calldata on the stack
            push.OUTPUT_ADDR    # ptr_out - where to write 32-byte hash
            push.INPUT_LEN      # len - 4 bytes to hash
            push.INPUT_ADDR     # ptr_in - where input data is stored

            exec.keccak_precompile::keccak256_precompile
            
            # Emit event to validate the hash was written correctly to memory
            push.OUTPUT_ADDR    # ptr where hash should be written
            emit.event("{MEMORY_CHECK_EVENT_ID}")

            exec.sys::truncate_stack
        end
    "#
    );

    // Memory validation handler - checks that hash was written correctly to output memory
    fn check_memory_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {

        let ptr_out = process.get_stack_item(1).as_int(); // ptr_out from stack

        // Validate the output address matches our constant
        assert_eq!(
            ptr_out, OUTPUT_MEMORY_ADDR as u64,
            "Output address should be {} but got {}",
            OUTPUT_MEMORY_ADDR, ptr_out
        );

        // Read the hash bytes from memory starting at ptr_out
        let mut actual_hash = Vec::new();
        let ctx = process.ctx();
        for addr in ptr_out..ptr_out + KECCAK_HASH_SIZE {
            let memory_value = process
                .get_mem_value(ctx, addr as u32)
                .ok_or_else(|| format!("Failed to read memory at address {}", addr))?;
            actual_hash.push(memory_value.as_int() as u8);
        }

        // Compare with expected keccak hash
        let expected_hash = Keccak256::hash(&PREIMAGE);
        assert_eq!(
            actual_hash.len(),
            KECCAK_HASH_SIZE as usize,
            "Expected {} hash bytes, got {}",
            KECCAK_HASH_SIZE,
            actual_hash.len()
        );
        assert_eq!(
            actual_hash.as_slice(),
            expected_hash.as_ref(),
            "Hash not written correctly to memory at address {}",
            ptr_out
        );

        // Validate that the commitment exists in the advice map
        let commitment = process.get_stack_word(2);
        let witness = process
            .advice_provider()
            .get_mapped_values(&commitment)
            .ok_or("Commitment should exist in advice map")?;

        assert_eq!(
            witness.len(),
            PREIMAGE.len(),
            "Witness should have {} elements, got {}",
            PREIMAGE.len(),
            witness.len()
        );

        let witness_bytes: Vec<_> = witness.iter().map(|felt| felt.as_int() as u8).collect();
        assert_eq!(
            &witness_bytes, &PREIMAGE,
            "Witness stored in advice map does not match. expected:\n{:?}\ngot:\n{:?}",
            PREIMAGE, witness_bytes
        );

        Ok(vec![])
    }

    // System recording handler - validates precompile call data structure
    fn system_record_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        // Should receive: [event_id, precompile_type, commitment_word0, commitment_word1,
        //                  commitment_word2, commitment_word3, ...]
        let precompile_type = process.get_stack_item(1).as_int();
        let commitment_word = [
            process.get_stack_item(2),
            process.get_stack_item(3),
            process.get_stack_item(4),
            process.get_stack_item(5),
        ];

        // Validate that we received proper precompile type
        assert_ne!(
            precompile_type, 0,
            "System record should receive non-zero precompile type, got {}",
            precompile_type
        );

        // Validate that commitment data is present (non-zero)
        let commitment_is_zero = commitment_word.iter().all(|&felt| felt == FieldElement::ZERO);
        assert!(!commitment_is_zero, "System record should receive non-zero commitment data");

        Ok(vec![])
    }

    let stack_inputs = PREIMAGE.map(u64::from);
    let mut test = build_debug_test!(source, &stack_inputs);

    // Add all event handlers
    test.add_event_handler(event_keccak_precompile, push_keccak);
    test.add_event_handler(event_system_record, system_record_handler);
    test.add_event_handler(event_memory_check, check_memory_handler);

    test.execute().unwrap();
}
