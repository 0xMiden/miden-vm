use alloc::{sync::Arc, vec, vec::Vec};

use miden_core::{AdviceMap, Felt};
use miden_crypto::{Word, hash::rpo::Rpo256};
use miden_processor::{AdviceMutation, ProcessState};

use crate::precompiles::read_memory;

pub const KECCAK_EVENT_ID: &str = "miden_stdlib::hash::keccak";

pub fn push_keccak(process: &ProcessState) -> Result<Vec<AdviceMutation>, ()> {
    // start at 1 since 0 holds the event id "
    let ptr = process.get_stack_item(1).as_int();
    let len = process.get_stack_item(2).as_int();

    // Attempt to collect the field elements between `prt` and `ptr+len`.
    let witness = read_memory(process, ptr, len)?;

    // Try to convert to bytes
    let preimage = witness
        .iter()
        .map(|felt| u8::try_from(felt.as_int()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ())?;
    // Resulting Keccak hash of the preimage
    let keccak_hash = miden_crypto::hash::keccak::Keccak256::hash(&preimage);
    let advice_stack_extension =
        AdviceMutation::extend_stack(keccak_hash.iter().map(|byte| Felt::from(*byte)));

    // Commiment to precompile call
    // Rpo(
    //     Rpo(preimage),
    //     Rpo(Keccak(preimage))
    // )
    let calldata_commitment = Rpo256::merge(&[
        Rpo256::hash_elements(&witness), // Commitment to pre-image
        Rpo256::hash(&keccak_hash),      // Commitment to hash
    ]);

    // store the calldata in the advice map to be recovered later on by the prover
    let entry: (Word, Arc<Felt>) = (calldata_commitment, witness.into());
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([entry]));

    Ok(vec![advice_stack_extension, advice_map_extension])
}

pub fn call_keccak(process: &ProcessState) {
    // input stack
    let ptr_in;
    let len;
    let prt_out;

    let witness_sponge;
    // stream data from ptr, and absorb into sponge, 2 words at a time
    // finalize absorb
    let witness_commitment = witness_sponge.finalize; // Rpo(preimage)

    // emit event calling this precompile which pushes the
    // stack [ptr, len]
    emit.event("miden_stdlib::hash::keccak");
    // advice: [kecack_hash] as bytes

    let hash_commitment;
    // stream kecack_hash from advice, and write to memory at ptr out, while absorbing into hash_commitment sponge

    // now merge both witness_commitment and hash_commitment
    // and get call_data commitment
    let call_data_commitment = rpo_merge(witness_commitment, hash_commitment);
    
    // for now, let's assume there is an event "system::record_precompile"
    // stack: [ event("miden_stdlib::hash::keccak"), call_data_commitment]
    emit.event("system::record_precompile")

    // output stack can be whatever, 
}
