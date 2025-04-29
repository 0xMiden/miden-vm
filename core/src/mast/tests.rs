use alloc::vec::Vec;

use miden_crypto::{Felt, PrimeCharacteristicRing, hash::rpo::RpoDigest};
use proptest::prelude::*;
use rand_utils::prng_array;
use winter_utils::{Deserializable, Serializable};

use crate::{Kernel, ProgramInfo, Word, chiplets::hasher, mast::DynNode};

#[test]
fn dyn_hash_is_correct() {
    let expected_constant = hasher::merge_in_domain(
        &[RpoDigest::default(), RpoDigest::default()],
        DynNode::dyn_domain(),
    );
    assert_eq!(expected_constant, DynNode::new_dyn().digest());
}

proptest! {
    #[test]
    fn arbitrary_program_info_serialization_works(
        kernel_count in prop::num::u8::ANY,
        ref seed in any::<[u8; 32]>()
    ) {
        let program_hash = digest_from_seed(*seed);
        let kernel: Vec<RpoDigest> = (0..kernel_count)
            .scan(*seed, |seed, _| {
                *seed = prng_array(*seed);
                Some(digest_from_seed(*seed))
            })
            .collect();
        let kernel = Kernel::new(&kernel).unwrap();
        let program_info = ProgramInfo::new(program_hash, kernel);
        let bytes = program_info.to_bytes();
        let deser = ProgramInfo::read_from_bytes(&bytes).unwrap();
        assert_eq!(program_info, deser);
    }
}

// HELPER FUNCTIONS
// --------------------------------------------------------------------------------------------

fn digest_from_seed(seed: [u8; 32]) -> RpoDigest {
    let mut digest = Word::default();
    digest.iter_mut().enumerate().for_each(|(i, d)| {
        *d = <[u8; 8]>::try_from(&seed[i * 8..(i + 1) * 8])
            .map(u64::from_le_bytes)
            .map(Felt::from_u64)
            .unwrap()
    });
    digest.into()
}
