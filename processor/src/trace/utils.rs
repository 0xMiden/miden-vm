use alloc::{string::ToString, vec::Vec};
use core::{mem::MaybeUninit, slice};

use miden_air::trace::{MAX_MESSAGE_WIDTH, MainTrace};

use super::chiplets::Chiplets;
use crate::{
    Felt, RowIndex,
    debug::BusDebugger,
    field::ExtensionField,
    utils::{assume_init_vec, uninit_vector},
};
#[cfg(test)]
use crate::{operation::Operation, utils::ToElements};

// TRACE FRAGMENT
// ================================================================================================

/// TODO: add docs
pub struct TraceFragment<'a> {
    data: Vec<&'a mut [Felt]>,
    num_rows: usize,
}

impl<'a> TraceFragment<'a> {
    /// Creates a new [TraceFragment] with the expected number of columns and rows.
    ///
    /// The memory needed to hold the trace fragment data is not allocated during construction.
    pub fn new(num_columns: usize, num_rows: usize) -> Self {
        TraceFragment {
            data: Vec::with_capacity(num_columns),
            num_rows,
        }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the number of columns in this execution trace fragment.
    pub fn width(&self) -> usize {
        self.data.len()
    }

    /// Returns the number of rows in this execution trace fragment.
    pub fn len(&self) -> usize {
        self.num_rows
    }

    // DATA MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Updates a single cell in this fragment with provided value.
    #[inline(always)]
    pub fn set(&mut self, row_idx: RowIndex, col_idx: usize, value: Felt) {
        self.data[col_idx][row_idx] = value;
    }

    /// Returns a mutable iterator to the columns of this fragment.
    pub fn columns(&mut self) -> slice::IterMut<'_, &'a mut [Felt]> {
        self.data.iter_mut()
    }

    /// Adds a new column to this fragment by pushing a mutable slice with the first `self.len()`
    /// elements of the provided column.
    ///
    /// Returns the rest of the provided column as a separate mutable slice.
    pub fn push_column_slice(&mut self, column: &'a mut [Felt]) -> &'a mut [Felt] {
        let (column_fragment, rest) = column.split_at_mut(self.num_rows);
        self.data.push(column_fragment);
        rest
    }

    // TEST METHODS
    // --------------------------------------------------------------------------------------------

    #[cfg(test)]
    pub fn trace_to_fragment(trace: &'a mut [Vec<Felt>]) -> Self {
        assert!(!trace.is_empty(), "expected trace to have at least one column");
        let mut data = Vec::new();
        for column in trace.iter_mut() {
            data.push(column.as_mut_slice());
        }

        let num_rows = data[0].len();
        Self { data, num_rows }
    }
}

// TRACE LENGTH SUMMARY
// ================================================================================================

/// Contains the data about lengths of the trace parts.
///
/// - `main_trace_len` contains the length of the main trace.
/// - `range_trace_len` contains the length of the range checker trace.
/// - `chiplets_trace_len` contains the trace lengths of the all chiplets (hash, bitwise, memory,
///   kernel ROM)
#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct TraceLenSummary {
    main_trace_len: usize,
    range_trace_len: usize,
    chiplets_trace_len: ChipletsLengths,
}

impl TraceLenSummary {
    pub fn new(
        main_trace_len: usize,
        range_trace_len: usize,
        chiplets_trace_len: ChipletsLengths,
    ) -> Self {
        TraceLenSummary {
            main_trace_len,
            range_trace_len,
            chiplets_trace_len,
        }
    }

    /// Returns length of the main trace.
    pub fn main_trace_len(&self) -> usize {
        self.main_trace_len
    }

    /// Returns length of the range checker trace.
    pub fn range_trace_len(&self) -> usize {
        self.range_trace_len
    }

    /// Returns [ChipletsLengths] which contains trace lengths of all chilplets.
    pub fn chiplets_trace_len(&self) -> ChipletsLengths {
        self.chiplets_trace_len
    }

    /// Returns the maximum of all component lengths.
    pub fn trace_len(&self) -> usize {
        self.range_trace_len
            .max(self.main_trace_len)
            .max(self.chiplets_trace_len.trace_len())
    }

    /// Returns `trace_len` rounded up to the next power of two.
    pub fn padded_trace_len(&self) -> usize {
        self.trace_len().next_power_of_two()
    }

    /// Returns the percent (0 - 100) of the steps that were added to the trace to pad it to the
    /// next power of tow.
    pub fn padding_percentage(&self) -> usize {
        (self.padded_trace_len() - self.trace_len()) * 100 / self.padded_trace_len()
    }
}

// CHIPLET LENGTHS
// ================================================================================================

/// Contains trace lengths of all chilplets: hash, bitwise, memory and kernel ROM trace
/// lengths.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChipletsLengths {
    hash_chiplet_len: usize,
    bitwise_chiplet_len: usize,
    memory_chiplet_len: usize,
    kernel_rom_len: usize,
}

impl ChipletsLengths {
    pub fn new(chiplets: &Chiplets) -> Self {
        ChipletsLengths {
            hash_chiplet_len: chiplets.bitwise_start().into(),
            bitwise_chiplet_len: chiplets.memory_start() - chiplets.bitwise_start(),
            memory_chiplet_len: chiplets.kernel_rom_start() - chiplets.memory_start(),
            kernel_rom_len: chiplets.padding_start() - chiplets.kernel_rom_start(),
        }
    }

    pub fn from_parts(
        hash_len: usize,
        bitwise_len: usize,
        memory_len: usize,
        kernel_len: usize,
    ) -> Self {
        ChipletsLengths {
            hash_chiplet_len: hash_len,
            bitwise_chiplet_len: bitwise_len,
            memory_chiplet_len: memory_len,
            kernel_rom_len: kernel_len,
        }
    }

    /// Returns the length of the hash chiplet trace
    pub fn hash_chiplet_len(&self) -> usize {
        self.hash_chiplet_len
    }

    /// Returns the length of the bitwise trace
    pub fn bitwise_chiplet_len(&self) -> usize {
        self.bitwise_chiplet_len
    }

    /// Returns the length of the memory trace
    pub fn memory_chiplet_len(&self) -> usize {
        self.memory_chiplet_len
    }

    /// Returns the length of the kernel ROM trace
    pub fn kernel_rom_len(&self) -> usize {
        self.kernel_rom_len
    }

    /// Returns the length of the trace required to accommodate chiplet components and 1
    /// mandatory padding row required for ensuring sufficient trace length for auxiliary connector
    /// columns that rely on the memory chiplet.
    pub fn trace_len(&self) -> usize {
        self.hash_chiplet_len()
            + self.bitwise_chiplet_len()
            + self.memory_chiplet_len()
            + self.kernel_rom_len()
            + 1
    }
}

// AUXILIARY COLUMN BUILDER
// ================================================================================================

/// Defines a builder responsible for building a single column in an auxiliary segment of the
/// execution trace.
pub(crate) trait AuxColumnBuilder<E: ExtensionField<Felt>> {
    // REQUIRED METHODS
    // --------------------------------------------------------------------------------------------

    fn get_requests_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E;

    fn get_responses_at(
        &self,
        main_trace: &MainTrace,
        challenges: &Challenges<E>,
        row: RowIndex,
        debugger: &mut BusDebugger<E>,
    ) -> E;

    // PROVIDED METHODS
    // --------------------------------------------------------------------------------------------

    fn init_requests(
        &self,
        _main_trace: &MainTrace,
        _challenges: &Challenges<E>,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        E::ONE
    }

    fn init_responses(
        &self,
        _main_trace: &MainTrace,
        _challenges: &Challenges<E>,
        _debugger: &mut BusDebugger<E>,
    ) -> E {
        E::ONE
    }

    /// Builds the chiplets bus auxiliary trace column.
    fn build_aux_column(&self, main_trace: &MainTrace, challenges: &Challenges<E>) -> Vec<E> {
        let mut bus_debugger = BusDebugger::new("chiplets bus".to_string());

        let mut requests: Vec<MaybeUninit<E>> = uninit_vector(main_trace.num_rows());
        let init_req = self.init_requests(main_trace, challenges, &mut bus_debugger);
        requests[0].write(init_req);

        let mut responses_prod: Vec<MaybeUninit<E>> = uninit_vector(main_trace.num_rows());
        let mut prev_prod = self.init_responses(main_trace, challenges, &mut bus_debugger);
        responses_prod[0].write(prev_prod);

        let mut requests_running_prod = init_req;

        // Product of all requests to be inverted, used to compute inverses of requests.
        for row_idx in 0..main_trace.num_rows() - 1 {
            let row = row_idx.into();

            let response = self.get_responses_at(main_trace, challenges, row, &mut bus_debugger);
            prev_prod *= response;
            responses_prod[row_idx + 1].write(prev_prod);

            let request = self.get_requests_at(main_trace, challenges, row, &mut bus_debugger);
            requests[row_idx + 1].write(request);
            requests_running_prod *= request;
        }

        // all elements are now initialized
        let requests = unsafe { assume_init_vec(requests) };
        let mut result_aux_column = unsafe { assume_init_vec(responses_prod) };

        // Use batch-inversion method to compute running product of `response[i]/request[i]`.
        let mut requests_running_divisor = requests_running_prod.inverse();
        for i in (0..main_trace.num_rows()).rev() {
            result_aux_column[i] *= requests_running_divisor;
            requests_running_divisor *= requests[i];
        }

        #[cfg(any(test, feature = "bus-debugger"))]
        assert!(bus_debugger.is_empty(), "{bus_debugger}");

        result_aux_column
    }
}

// AUX CHALLENGES
// ================================================================================================

/// Encodes multiset/LogUp contributions as **alpha + <beta, message>**
///
/// Structure:
/// - `alpha`: randomness base (alpha)
/// - `beta_powers`: powers of beta [beta^0, beta^1, beta^2, ..., beta^(MAX_MESSAGE_WIDTH-2)]
///
/// The challenges are derived from permutation randomness:
/// - `alpha = challenges[0]`
/// - `beta  = challenges[1]`
///
/// This structure is shared with the AIR's `Challenges<AB, N>` for constraint evaluation.
pub(crate) struct Challenges<E: ExtensionField<Felt>> {
    pub(crate) alpha: E,
    pub(crate) beta_powers: [E; MAX_MESSAGE_WIDTH - 1],
}

impl<E: ExtensionField<Felt>> Challenges<E> {
    pub fn new(challenges: &[E]) -> Self {
        debug_assert!(challenges.len() >= 2, "need at least alpha and beta");
        let alpha = challenges[0];
        let beta = challenges[1];

        let mut beta_powers = core::array::from_fn(|_| E::ONE);
        // beta_powers[0] = E::ONE  (beta^0) — already set by from_fn
        for i in 1..beta_powers.len() {
            beta_powers[i] = beta_powers[i - 1] * beta;
        }
        Self { alpha, beta_powers }
    }

    /// Encodes as **alpha + <beta, message>** with K consecutive elements.
    #[inline(always)]
    pub fn encode<const K: usize>(&self, elems: [Felt; K]) -> E {
        const { assert!(K < MAX_MESSAGE_WIDTH, "Message length exceeds beta_powers capacity") };
        let mut acc = self.alpha;
        for (i, &elem) in elems.iter().enumerate() {
            acc += self.beta_powers[i] * elem;
        }
        acc
    }

    /// Encodes as **alpha + <beta, message>** using a layout array and separate values.
    ///
    /// `layout[i]` gives the beta-power position for `values[i]`.
    #[inline(always)]
    pub fn encode_sparse<const K: usize>(&self, layout: [usize; K], values: [Felt; K]) -> E {
        let mut acc = self.alpha;
        for i in 0..K {
            let idx = layout[i];
            debug_assert!(
                idx < self.beta_powers.len(),
                "encode_sparse index {} exceeds beta_powers length ({})",
                idx,
                self.beta_powers.len()
            );
            acc += self.beta_powers[idx] * values[i];
        }
        acc
    }
}

// U32 HELPERS
// ================================================================================================

/// Splits an element into two 16 bit integer limbs. It assumes that the field element contains a
/// valid 32-bit integer value.
pub(crate) fn split_element_u32_into_u16(value: Felt) -> (Felt, Felt) {
    let (hi, lo) = split_u32_into_u16(value.as_canonical_u64());
    (Felt::new(hi as u64), Felt::new(lo as u64))
}

/// Splits a u64 integer assumed to contain a 32-bit value into two u16 integers.
///
/// # Errors
/// Fails in debug mode if the provided value is not a 32-bit value.
pub(crate) fn split_u32_into_u16(value: u64) -> (u16, u16) {
    const U32MAX: u64 = u32::MAX as u64;
    debug_assert!(value <= U32MAX, "not a 32-bit value");

    let lo = value as u16;
    let hi = (value >> 16) as u16;

    (hi, lo)
}

// TEST HELPERS
// ================================================================================================

#[cfg(test)]
pub fn build_span_with_respan_ops() -> (Vec<Operation>, Vec<Felt>) {
    let iv = [1, 3, 5, 7, 9, 11, 13, 15, 17].to_elements();
    let ops = vec![
        Operation::Push(iv[0]),
        Operation::Push(iv[1]),
        Operation::Push(iv[2]),
        Operation::Push(iv[3]),
        Operation::Push(iv[4]),
        Operation::Push(iv[5]),
        Operation::Push(iv[6]),
        // next batch
        Operation::Push(iv[7]),
        Operation::Push(iv[8]),
        Operation::Add,
        // drops to make sure stack overflow is empty on exit
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
        Operation::Drop,
    ];
    (ops, iv)
}
