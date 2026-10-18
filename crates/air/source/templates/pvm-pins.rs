// Explicit accepted PVM generation inputs; deliberate review required before updates.
use miden_core::{Felt, Word};
pub const GENERATED_BY: &str = "cargo run -p miden-precompiles-verifier --release \
     --features constants-tools --bin pvm-constants-regen -- --write";

pub const PVM_PROTOCOL_ID: u64 = 4;

pub const PVM_RELATION_DIGEST: [u64; 4] = [
    5618632176883261929,
    5091169848121332946,
    9110857118546866548,
    100418585322354598,
];

pub const PVM_ACE_CIRCUIT_DIGEST: [u64; 4] = [
    2255028588524991477,
    8088146176287763667,
    1935595524963351362,
    5560235558590875651,
];

pub const PVM_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];

pub const PVM_CIRCUIT_SHAPE: (usize, usize, usize) = (2520, 13000, 14232);

pub fn relation_digest_for_circuit(circuit_digest: &Word) -> [Felt; 4] {
    miden_stark::config::relation_digest(PVM_PROTOCOL_ID, circuit_digest)
}
