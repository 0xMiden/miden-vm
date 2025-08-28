use miden_core::utils::string_to_event_id;
use miden_crypto::hash::keccak::Keccak256;
use miden_processor::ProcessState;
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
            push.100     # ptr (where "test" is stored)
            push.4       # len (4 bytes for "test")

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

        let expected_hash = Keccak256::hash(&PREIMAGE);
        assert_eq!(hash.as_slice(), expected_hash.as_ref());
        Ok(vec![])
    };
    test.add_event_handler(event_check_state, check_advice);

    test.execute().unwrap();
}
