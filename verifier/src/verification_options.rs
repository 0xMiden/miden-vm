use crate::PrecompileRegistry;

/// Options used when verifying deferred-state proof wires.
///
/// The selected [`PrecompileRegistry`] is part of the verification policy. A proof whose deferred
/// wire was produced with custom precompiles must be verified with the matching registry.
#[derive(Debug, Clone)]
pub struct VerificationOptions {
    precompile_registry: PrecompileRegistry,
    max_deferred_elements: usize,
}

impl Default for VerificationOptions {
    fn default() -> Self {
        Self {
            precompile_registry: miden_precompiles::registry(),
            max_deferred_elements: Self::DEFAULT_MAX_DEFERRED_ELEMENTS,
        }
    }
}

impl VerificationOptions {
    /// Default maximum approximate number of field elements allowed in deferred state.
    pub const DEFAULT_MAX_DEFERRED_ELEMENTS: usize =
        miden_core::deferred::DEFAULT_MAX_DEFERRED_ELEMENTS;

    /// Creates default verification options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the registry used to decode and evaluate the proof's deferred wire.
    pub fn with_precompile_registry(mut self, precompile_registry: PrecompileRegistry) -> Self {
        self.precompile_registry = precompile_registry;
        self
    }

    /// Sets the maximum approximate number of field elements allowed in deferred state.
    pub fn with_max_deferred_elements(mut self, max_deferred_elements: usize) -> Self {
        self.max_deferred_elements = max_deferred_elements;
        self
    }

    /// Returns the registry used to decode and evaluate the proof's deferred wire.
    pub fn precompile_registry(&self) -> &PrecompileRegistry {
        &self.precompile_registry
    }

    /// Returns the maximum approximate number of field elements allowed in deferred state.
    pub const fn max_deferred_elements(&self) -> usize {
        self.max_deferred_elements
    }

    pub(crate) fn into_parts(self) -> (PrecompileRegistry, usize) {
        (self.precompile_registry, self.max_deferred_elements)
    }

    pub(crate) fn from_parts(
        precompile_registry: PrecompileRegistry,
        max_deferred_elements: usize,
    ) -> Self {
        Self {
            precompile_registry,
            max_deferred_elements,
        }
    }
}
