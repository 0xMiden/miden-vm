//! Pure node encodings used by the joint degree/identity source walk.
//!
//! The versioned internal identity excludes sharing, diagnostics and cached degrees. Child order,
//! namespaces, addresses and assertion classes/order are significant. These are not protocol pins.

use alloc::vec::Vec;

use miden_crypto::hash::blake::Blake3_256;
use p3_field::{ExtensionField, Field};

use super::{
    AirSpec,
    symbolic::{AuxInput, BaseInput, BaseLeaf},
};

#[derive(Clone, Copy)]
pub(crate) enum ArithmeticOp {
    Add,
    Sub,
    Mul,
    Neg,
}

pub(crate) fn base_leaf<F: Field>(leaf: &BaseLeaf<F>) -> [u8; 32] {
    let mut encoded = Encoding::new(1);
    match leaf {
        BaseLeaf::Input(input) => match input {
            BaseInput::Main { offset, index } | BaseInput::Preprocessed { offset, index } => {
                encoded.0.push(u8::from(matches!(input, BaseInput::Preprocessed { .. })));
                encoded.0.push(offset.index() as u8);
                encoded.count(*index);
            },
            BaseInput::Public(index) => {
                encoded.0.push(2);
                encoded.count(*index);
            },
            BaseInput::Periodic(index) => {
                encoded.0.push(3);
                encoded.count(*index);
            },
        },
        BaseLeaf::IsFirstRow => encoded.0.push(4),
        BaseLeaf::IsLastRow => encoded.0.push(5),
        BaseLeaf::IsTransition => encoded.0.push(6),
        BaseLeaf::Constant(value) => {
            encoded.0.push(7);
            encoded.field(*value);
        },
    }
    encoded.finish()
}

pub(crate) fn lifted_base(base: [u8; 32]) -> [u8; 32] {
    let mut encoded = Encoding::new(16);
    encoded.0.push(0);
    encoded.0.extend_from_slice(&base);
    encoded.finish()
}

pub(crate) fn aux_input(input: AuxInput) -> [u8; 32] {
    let mut encoded = Encoding::new(16);
    match input {
        AuxInput::Trace { offset, index } => {
            encoded.0.push(1);
            encoded.0.push(offset.index() as u8);
            encoded.count(index);
        },
        AuxInput::Challenge(index) => {
            encoded.0.push(2);
            encoded.count(index);
        },
        AuxInput::Export(index) => {
            encoded.0.push(3);
            encoded.count(index);
        },
    }
    encoded.finish()
}

pub(crate) fn ext_constant<F: Field, EF: ExtensionField<F>>(value: EF) -> [u8; 32] {
    if value.is_in_basefield() {
        return lifted_base(base_leaf(&BaseLeaf::Constant(value.as_basis_coefficients_slice()[0])));
    }
    let mut encoded = Encoding::new(16);
    encoded.0.push(4);
    encoded.count(EF::DIMENSION);
    for &coefficient in value.as_basis_coefficients_slice() {
        encoded.field(coefficient);
    }
    encoded.finish()
}

pub(crate) fn operation(
    extension: bool,
    op: ArithmeticOp,
    x: [u8; 32],
    y: Option<[u8; 32]>,
) -> [u8; 32] {
    let tag = match (extension, op) {
        (false, ArithmeticOp::Add) => 2,
        (false, ArithmeticOp::Sub) => 3,
        (false, ArithmeticOp::Mul) => 4,
        (false, ArithmeticOp::Neg) => 5,
        (true, ArithmeticOp::Add) => 17,
        (true, ArithmeticOp::Sub) => 18,
        (true, ArithmeticOp::Mul) => 19,
        (true, ArithmeticOp::Neg) => 20,
    };
    let mut encoded = Encoding::new(tag);
    encoded.0.extend_from_slice(&x);
    if let Some(y) = y {
        encoded.0.extend_from_slice(&y);
    }
    encoded.finish()
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
