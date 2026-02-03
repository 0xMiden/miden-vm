use super::{ColMatrix, Felt, LookupTableRow};

// PROCESSOR RANGE CHECKS
// ================================================================================================

/// A struct containing all the range check lookups requested by user operations at a single clock
/// cycle, grouped by the processor performing the lookup.
#[derive(Debug, Clone)]
pub struct CycleRangeChecks {
    memory: Option<RangeCheckRequest>,
    stack: Option<RangeCheckRequest>,
}

impl CycleRangeChecks {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Creates a new set of cycle range checks from range checks requested by the Memory processor.
    pub fn new_from_memory(values: &[u16; 2]) -> Self {
        Self {
            stack: None,
            memory: Some(RangeCheckRequest::Memory([Felt::from(values[0]), Felt::from(values[1])])),
        }
    }

    /// Creates a new set of cycle range checks from range checks requested by the Stack processor.
    pub fn new_from_stack(values: &[u16; 4]) -> Self {
        Self {
            memory: None,
            stack: Some(RangeCheckRequest::Stack([
                Felt::from(values[0]),
                Felt::from(values[1]),
                Felt::from(values[2]),
                Felt::from(values[3]),
            ])),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Adds a set of range checks requested by memory to an existing set of cycle range checks. It
    /// is assumed that the existing instance does not already contain checks from Memory.
    pub fn add_memory_checks(&mut self, values: &[u16]) {
        debug_assert_eq!(self.memory, None);
        self.memory =
            Some(RangeCheckRequest::Memory([Felt::from(values[0]), Felt::from(values[1])]));
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Reduces all range checks requested at this cycle by the Stack processor to a single field
    /// element in the field specified by E.
    pub fn to_stack_value<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
    ) -> E {
        let mut value = E::ONE;

        if let Some(stack_checks) = &self.stack {
            value *= stack_checks.to_value(main_trace, alphas);
        }

        value
    }

    /// Reduces all range checks requested at this cycle by the Memory processor to a single field
    /// element in the field specified by E.
    fn to_mem_value<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
    ) -> E {
        let mut value = E::ONE;

        if let Some(mem_checks) = &self.memory {
            value = mem_checks.to_value(main_trace, alphas)
        }

        value
    }
}

impl LookupTableRow for CycleRangeChecks {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 1 alpha value. Includes all values included at this cycle from all processors.
    fn to_value<E: ExtensionField<Felt>>(
        &self,
        main_trace: &MainTrace,
        alphas: &[E],
    ) -> E {
        let stack_value = self.to_stack_value(main_trace, alphas);
        let mem_value = self.to_mem_value(main_trace, alphas);

        if stack_value != E::ONE {
            stack_value * mem_value
        } else {
            mem_value
        }
    }
}

/// Range check lookups requested by a processor at a single cycle, carrying the values to be
/// range-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RangeCheckRequest {
    Memory([Felt; 2]),
    Stack([Felt; 4]),
}

impl LookupTableRow for RangeCheckRequest {
    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 1 alpha value.
    fn to_value<E: ExtensionField<Felt>>(
        &self,
        _main_trace: &MainTrace,
        alphas: &[E],
    ) -> E {
        let alpha: E = alphas[0];
        let mut value = E::ONE;

        let values_iter = match self {
            Self::Memory(values) => values.iter(),
            Self::Stack(values) => values.iter(),
        };

        for &rc_value in values_iter {
            value *= alpha + rc_value.into();
        }

        value
    }
}
