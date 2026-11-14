//! Pure node encodings used by the joint degree/identity source walk.
//!
//! The versioned internal identity excludes sharing, diagnostics and cached degrees. Child order,
//! namespaces, addresses and assertion classes/order are significant. These are not protocol pins.

use alloc::vec::Vec;

use miden_crypto::hash::blake::Blake3_256;
use p3_field::Field;

use super::AirSpec;

/// Frame an authored expression node independently of its allocation and degree caches.
pub(crate) fn expression(node: &[u8]) -> [u8; 32] {
    let mut encoded = Encoding::new(1);
    encoded.bytes(node);
    encoded.finish()
}

pub(crate) fn field_bytes<F: Field>(value: F) -> Vec<u8> {
    let bytes: Vec<_> = value.into_bytes().into_iter().collect();
    assert_eq!(bytes.len(), F::NUM_BYTES, "field encoding byte width");
    bytes
}

pub(crate) fn relation<F: Field>(
    spec: &AirSpec<'_, F>,
    assertions: &[(bool, [u8; 32])],
) -> [u8; 32] {
    let mut encoded = Encoding::new(0);
    encoded.bytes(&F::order().to_bytes_le());
    encoded.count(F::NUM_BYTES);
    for count in [
        spec.main_width,
        spec.aux_width,
        spec.num_public_values,
        spec.num_challenges,
        spec.num_exports,
    ] {
        encoded.count(count);
    }
    match spec.preprocessed {
        None => encoded.0.push(0),
        Some(shape) => {
            encoded.0.push(1);
            encoded.count(shape.width);
            encoded.0.push(shape.log_height);
        },
    }
    encoded.count(spec.periodic_columns.len());
    for column in spec.periodic_columns.iter() {
        encoded.count(column.len());
        for &value in column {
            encoded.field(value);
        }
    }
    encoded.count(assertions.len());
    for &(extension, hash) in assertions {
        encoded.0.push(u8::from(extension));
        encoded.0.extend_from_slice(&hash);
    }
    encoded.finish()
}

struct Encoding(Vec<u8>);

impl Encoding {
    fn new(tag: u8) -> Self {
        let mut bytes = b"miden-native-air-structure-v1\0".to_vec();
        bytes.push(tag);
        Self(bytes)
    }

    fn count(&mut self, value: usize) {
        let value = u64::try_from(value).expect("supported hosts have at most 64-bit indices");
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.count(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    fn field<F: Field>(&mut self, value: F) {
        let start = self.0.len();
        self.0.extend(value.into_bytes());
        assert_eq!(self.0.len() - start, F::NUM_BYTES, "field encoding byte width");
    }

    fn finish(self) -> [u8; 32] {
        Blake3_256::hash(&self.0).into()
    }
}
