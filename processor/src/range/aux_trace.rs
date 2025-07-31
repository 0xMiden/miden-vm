use alloc::{collections::BTreeMap, vec::Vec};

use miden_air::{
    RowIndex,
    trace::{
        main_trace::MainTrace,
        range::{M_COL_IDX, V_COL_IDX},
    },
};
use miden_core::ZERO;

use super::{Felt, FieldElement, NUM_RAND_ROWS, uninit_vector};

// AUXILIARY TRACE BUILDER
// ================================================================================================

/// Describes how to construct the execution trace of columns related to the range checker in the
/// auxiliary segment of the trace. These are used in multiset checks.
#[derive(Debug)]
pub struct AuxTraceBuilder {
    /// A list of the unique values for which range checks are performed.
    lookup_values: Vec<u16>,
    /// Range check lookups performed by all user operations, grouped and sorted by the clock cycle
    /// at which they are requested.
    cycle_lookups: BTreeMap<RowIndex, Vec<u16>>,
    // The index of the first row of Range Checker's trace when the padded rows end and values to
    // be range checked start.
    values_start: usize,
}

impl AuxTraceBuilder {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------
    pub fn new(
        lookup_values: Vec<u16>,
        cycle_lookups: BTreeMap<RowIndex, Vec<u16>>,
        values_start: usize,
    ) -> Self {
        Self {
            lookup_values,
            cycle_lookups,
            values_start,
        }
    }

    // AUX COLUMN BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Builds and returns range checker auxiliary trace columns. Currently this consists of one
    /// column:
    /// - `b_range`: ensures that the range checks performed by the Range Checker match those
    ///   requested by the Stack and Memory processors.
    pub fn build_aux_columns<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> Vec<Vec<E>> {
        let b_range = self.build_aux_col_b_range(main_trace, rand_elements);
        vec![b_range]
    }

    /// Builds the execution trace of the range check `b_range` column which ensure that the range
    /// check lookups performed by user operations match those executed by the Range Checker.
    fn build_aux_col_b_range<E: FieldElement<BaseField = Felt>>(
        &self,
        main_trace: &MainTrace,
        rand_elements: &[E],
    ) -> Vec<E> {
        // run batch inversion on the lookup values
        let divisors = get_divisors(&self.lookup_values, rand_elements[0]);

        // allocate memory for the running sum column and set the initial value to ZERO
        let mut b_range = unsafe { uninit_vector(main_trace.num_rows()) };
        b_range[0] = E::ZERO;

        // keep track of the last updated row in the `b_range` running sum column. `b_range` is
        // filled with result values that are added to the next row after the operation's execution.
        let mut b_range_idx = 0_usize;

        // the first half of the trace only includes values from the operations.
        for (clk, range_checks) in
            self.cycle_lookups.range(RowIndex::from(0)..RowIndex::from(self.values_start))
        {
            let clk: usize = (*clk).into();

            // if we skipped some cycles since the last update was processed, values in the last
            // updated row should be copied over until the current cycle.
            if b_range_idx < clk {
                let last_value = b_range[b_range_idx];
                b_range[(b_range_idx + 1)..=clk].fill(last_value);
            }

            // move the column pointer to the next row.
            b_range_idx = clk + 1;

            b_range[b_range_idx] = b_range[clk];
            // include the operation lookups
            for lookup in range_checks.iter() {
                let value = divisors.get(lookup).expect("invalid lookup value {}");
                b_range[b_range_idx] -= *value;
            }
        }

        // if we skipped some cycles since the last update was processed, values in the last
        // updated row should by copied over until the current cycle.
        if b_range_idx < self.values_start {
            let last_value = b_range[b_range_idx];
            b_range[(b_range_idx + 1)..=self.values_start].fill(last_value);
        }

        // after the padded section of the range checker table, include the lookup value specified
        // by the range checker into the running sum at each step, and remove lookups from user ops
        // at any step where user ops were executed.
        for (row_idx, (multiplicity, lookup)) in main_trace
            .get_column(M_COL_IDX)
            .iter()
            .zip(main_trace.get_column(V_COL_IDX).iter())
            .enumerate()
            .take(main_trace.num_rows() - NUM_RAND_ROWS)
            .skip(self.values_start)
        {
            b_range_idx = row_idx + 1;

            if *multiplicity != ZERO {
                // add the value in the range checker: multiplicity / (alpha + lookup)
                let value = divisors.get(&(lookup.as_int() as u16)).expect("invalid lookup value");
                b_range[b_range_idx] = b_range[row_idx] + value.mul_base(*multiplicity);
            } else {
                b_range[b_range_idx] = b_range[row_idx];
            }

            // subtract the range checks requested by operations
            if let Some(range_checks) = self.cycle_lookups.get(&(row_idx as u32).into()) {
                for lookup in range_checks.iter() {
                    let value = divisors.get(lookup).expect("invalid lookup value");
                    b_range[b_range_idx] -= *value;
                }
            }
        }

        // at this point, all range checks from user operations and the range checker should be
        // matched - so, the last value must be ZERO;
        assert_eq!(b_range[b_range_idx], E::ZERO);

        if b_range_idx < b_range.len() - 1 {
            b_range[(b_range_idx + 1)..].fill(E::ZERO);
        }

        b_range
    }
}

/// Runs batch inversion on all range check lookup values and returns a map which maps each value
/// to the divisor used for including it in the LogUp lookup. In other words, the map contains
/// mappings of x to 1/(alpha + x).
fn get_divisors<E: FieldElement<BaseField = Felt>>(
    lookup_values: &[u16],
    alpha: E,
) -> BTreeMap<u16, E> {
    // run batch inversion on the lookup values
    let mut values = unsafe { uninit_vector(lookup_values.len()) };
    let mut inv_values = unsafe { uninit_vector(lookup_values.len()) };
    let mut log_values = BTreeMap::new();

    let mut acc = E::ONE;
    for (i, (value, inv_value)) in values.iter_mut().zip(inv_values.iter_mut()).enumerate() {
        *inv_value = acc;
        *value = alpha + E::from(lookup_values[i]);
        acc *= *value;
    }

    // invert the accumulated product
    acc = acc.inv();

    // multiply the accumulated product by the original values to compute the inverses, then
    // build a map of inverses for the lookup values
    for i in (0..lookup_values.len()).rev() {
        inv_values[i] *= acc;
        acc *= values[i];
        log_values.insert(lookup_values[i], inv_values[i]);
    }

    log_values
}
