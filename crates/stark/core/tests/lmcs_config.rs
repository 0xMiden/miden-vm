//! External-crate construction of the public LMCS configurations.
//!
//! `LmcsConfig` and `HidingLmcsConfig` are public types, so downstream crates
//! must be able to construct them through their public constructors.

use miden_crypto::hash::stateful::StatefulSponge;
use miden_stark::lmcs::{config::LmcsConfig, hiding_config::HidingLmcsConfig};
use p3_field::Field;
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::TruncatedPermutation;
use rand::{SeedableRng, rngs::SmallRng};

type PackedFelt = <Goldilocks as Field>::Packing;
type Perm = Poseidon2Goldilocks<12>;
type Sponge = StatefulSponge<Perm, 12, 8, 4>;
type Compress = TruncatedPermutation<Perm, 2, 4, 12>;

#[test]
fn constructs_public_lmcs_configs_from_external_crate() {
    let mut rng = SmallRng::seed_from_u64(7);
    let perm = Perm::new_from_rng_128(&mut rng);
    let sponge = Sponge::new(perm.clone());
    let compress = Compress::new(perm);
    let _: LmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, 12, 4> =
        LmcsConfig::new(sponge, compress);

    let mut rng = SmallRng::seed_from_u64(8);
    let perm = Perm::new_from_rng_128(&mut rng);
    let sponge = Sponge::new(perm.clone());
    let compress = Compress::new(perm);
    let _: HidingLmcsConfig<PackedFelt, PackedFelt, Sponge, Compress, SmallRng, 12, 4, 4> =
        HidingLmcsConfig::new(sponge, compress, rng);
}
