// Explicit accepted generation inputs; update only after deliberate pin review.
use miden_core::Felt;
use miden_stark::config::RelationDigest;

pub const RELATION_DIGEST: RelationDigest = [
    Felt::new_unchecked(9098509505774412735),
    Felt::new_unchecked(4737936789760532215),
    Felt::new_unchecked(1438664865551243811),
    Felt::new_unchecked(7897993217034479822),
];

pub const ACE_CIRCUIT_DIGEST: [Felt; 4] = [
    Felt::new_unchecked(9122225125595333314),
    Felt::new_unchecked(4575736417990392984),
    Felt::new_unchecked(5414688566126692380),
    Felt::new_unchecked(7406482881221041553),
];

pub const BLAKE3_PREPROCESSED_COMMITMENT: [u8; 32] = [
    237, 165, 181, 150, 170, 183, 11, 117, 116, 34, 106, 27, 89, 68, 113, 212, 124, 97, 90, 201,
    199, 30, 220, 145, 185, 5, 104, 155, 67, 55, 138, 126,
];

pub const RPO_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(1822154764201048239),
    Felt::new_unchecked(10652700666966391447),
    Felt::new_unchecked(5380745592975976632),
    Felt::new_unchecked(9394895238760322928),
];

pub const RPX_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(7794497219439565839),
    Felt::new_unchecked(12108238022531853786),
    Felt::new_unchecked(3575474959316559657),
    Felt::new_unchecked(10734344851506324095),
];

pub const EIDOS_PREPROCESSED_COMMITMENT: [u64; 4] = [
    1070440981155119101,
    2022626773377316756,
    6941685244114430330,
    5172579525468662096,
];

pub const POSEIDON2_PREPROCESSED_COMMITMENT: [Felt; 4] = [
    Felt::new_unchecked(1918020177704289460),
    Felt::new_unchecked(13338901298221777084),
    Felt::new_unchecked(7643362476706389016),
    Felt::new_unchecked(12789699880434201102),
];

pub const KECCAK_PREPROCESSED_COMMITMENT: [u64; 4] = [
    8953595915908445159,
    18286975921588085812,
    1662605580119539545,
    8308041584975270064,
];
