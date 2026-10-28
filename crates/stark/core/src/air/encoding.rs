//! The default multi-AIR statement transcript schema.

use p3_challenger::CanObserve;
use p3_field::Field;

/// Static dimensions of the default statement and its instance-shape suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatementEncoding {
    pub num_public_values: usize,
    pub max_aux_inputs: usize,
    pub num_aux_inputs: usize,
    pub num_airs: usize,
}

impl StatementEncoding {
    pub const fn statement_len(self) -> usize {
        3 + self.num_public_values + self.num_aux_inputs
    }

    /// Statement values followed by the instance count and one height per instance.
    pub const fn shape_len(self) -> usize {
        self.statement_len() + 1 + self.num_airs
    }

    /// Emit the default binding in protocol order.
    #[inline]
    pub fn observe<F: Field, C: CanObserve<F>>(
        self,
        challenger: &mut C,
        air_inputs: impl Iterator<Item = F>,
        aux_inputs: &[F],
    ) {
        debug_assert_eq!(aux_inputs.len(), self.num_aux_inputs, "auxiliary input count");
        challenger.observe(F::from_usize(self.num_public_values));
        let mut count = 0;
        for value in air_inputs {
            challenger.observe(value);
            count += 1;
        }
        debug_assert_eq!(count, self.num_public_values, "public value count");
        challenger.observe(F::from_usize(self.max_aux_inputs));
        challenger.observe(F::from_usize(self.num_aux_inputs));
        for &value in aux_inputs {
            challenger.observe(value);
        }
    }
}
