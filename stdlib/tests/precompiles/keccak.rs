use miden_core::{Felt, utils::string_to_event_id};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};
use miden_stdlib::precompiles::{KECCAK_EVENT_ID, push_keccak};

#[test]
fn test_keccak_event_handler_directly() {
    // Compute event ID at runtime
    let event_keccak_precompile = string_to_event_id(KECCAK_EVENT_ID);

    // Simple program that sets up memory and calls our event
    let source = r#"
        begin
            # Write the 4 stack input elements to memory
            push.100
            mem_storew
            dropw
            
            # Set up stack for event: [ptr, len]
            push.4       # len (4 bytes for "test")
            push.100     # ptr (where "test" is stored)

            emit.event("miden_stdlib::hash::keccak")

            drop drop
            emit.event("miden::debug")
        end
    "#;

    const PREIMAGE: [u8; 4] = [1, 2, 3, 4];

    let stack_inputs = PREIMAGE.map(u64::from);
    let mut test = build_debug_test!(source, &stack_inputs);
    test.add_event_handler(event_keccak_precompile, push_keccak);

    // Use a custom handler to ensure the advice stack contains the expected hash.
    let event_check_state = string_to_event_id("miden::debug");
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
            "Advice stack should contain keccak hash"
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
            "Advice map should contain witness under commitment key"
        );

        let stored_witness = advice_map_entry.unwrap();
        assert_eq!(stored_witness, witness, "Stored witness should match original preimage");
        Ok(vec![])
    };
    test.add_event_handler(event_check_state, check_advice);

    test.execute().unwrap();
}

#[test]
fn test_keccak_precompile_masm_wrapper() {
    // Test the full MASM wrapper function that calls the event handler
    // and writes the hash to output memory

    let event_keccak_precompile = string_to_event_id(KECCAK_EVENT_ID);
    let event_system_record = string_to_event_id("system::record_precompile");
    let event_memory_check = string_to_event_id("miden::memory_check");

    let source = r#"
        use.std::crypto::hashes::keccak_precompile
        use.std::sys

        begin
            # Write test data [5, 6, 7, 8] to memory address 100
            push.100
            mem_storew
            dropw
            
            # Call keccak wrapper: keccak256_precompile(ptr_in=100, len=4, ptr_out=200)
            push.200    # ptr_out - where to write 32-byte hash
            push.4      # len - 4 bytes to hash
            push.100    # ptr_in - where input data is stored

            exec.keccak_precompile::keccak256_precompile
            debug.stack
            # Emit event to check the hash was written correctly to memory at ptr_out=200
            push.200    # ptr where hash should be written
            emit.event("miden::memory_check")

            exec.sys::truncate_stack
        end
    "#;

    const PREIMAGE: [u8; 4] = [5, 6, 7, 8];

    // Memory validation handler - checks that hash was written correctly to output memory
    fn check_memory_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        let ptr_out = process.get_stack_item(1).as_int(); // ptr_out from stack

        println!("stack: {:?}", process.get_stack_state());
        // println!("advice: {:?}", process.advice_provider());
        // Read 32 bytes from memory starting at ptr_out
        let mut actual_hash = Vec::new();
        let ctx = process.ctx();
        for addr in ptr_out..ptr_out + 32 {
            let memory_value = process.get_mem_value(ctx, addr as u32).unwrap();
            actual_hash.push(memory_value.as_int() as u8);
        }

        // Compare with expected keccak hash
        let expected_hash = Keccak256::hash(&PREIMAGE);
        assert_eq!(
            actual_hash.as_slice(),
            expected_hash.as_ref(),
            "Hash not written correctly to memory at address {ptr_out} (expected bytes in reverse order)",
        );

        let commitment = process.get_stack_word(2);
        process.advice_provider().get_mapped_values(&commitment).unwrap();
        Ok(vec![])
    }

    // Mock system recording handler - should receive precompile call data
    fn system_record_handler(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
        // Should receive: [event_id, precompile_type, commitment_word0, commitment_word1,
        //                  commitment_word2, commitment_word3, ...]
        let precompile_type = process.get_stack_item(1).as_int();
        let _commitment_word = [
            process.get_stack_item(2),
            process.get_stack_item(3),
            process.get_stack_item(4),
            process.get_stack_item(5),
        ];

        // Basic validation that we received some commitment data
        assert_ne!(precompile_type, 0, "System record should receive precompile type");
        // Note: Full commitment validation would be more complex

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
