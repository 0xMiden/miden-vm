#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    utils::Deserializable,
    merkle::{MerklePath, PartialMerkleTree},
};

fuzz_target!(|data: &[u8]| {
    // Test MerklePath deserialization
    let _ = MerklePath::read_from_bytes(data);

    // Test Vec<MerklePath>
    let _ = Vec::<MerklePath>::read_from_bytes(data);

    // Test PartialMerkleTree deserialization
    let _ = PartialMerkleTree::read_from_bytes(data);

    // Test Vec<PartialMerkleTree>
    let _ = Vec::<PartialMerkleTree>::read_from_bytes(data);

    // Test Option<MerklePath>
    let _ = Option::<MerklePath>::read_from_bytes(data);

    // Test arrays of Merkle structures
    let _ = <[MerklePath; 1]>::read_from_bytes(data);
    let _ = <[MerklePath; 2]>::read_from_bytes(data);
});
