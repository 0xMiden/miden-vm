// HELPERS
// ================================================================================================

use miden_core::field::QuotientMap;

/// Converts macro advice stack inputs into the typed advice stack representation.
pub trait IntoAdviceStackInput {
    fn into_advice_stack_input(self)
    -> Result<crate::AdviceStack, miden_core::program::InputError>;
}

impl IntoAdviceStackInput for crate::AdviceStack {
    fn into_advice_stack_input(
        self,
    ) -> Result<crate::AdviceStack, miden_core::program::InputError> {
        Ok(self)
    }
}

impl IntoAdviceStackInput for ::alloc::vec::Vec<u64> {
    fn into_advice_stack_input(
        self,
    ) -> Result<crate::AdviceStack, miden_core::program::InputError> {
        advice_stack_from_ints(self)
    }
}

impl IntoAdviceStackInput for &[u64] {
    fn into_advice_stack_input(
        self,
    ) -> Result<crate::AdviceStack, miden_core::program::InputError> {
        advice_stack_from_ints(self.iter().copied())
    }
}

impl<const N: usize> IntoAdviceStackInput for [u64; N] {
    fn into_advice_stack_input(
        self,
    ) -> Result<crate::AdviceStack, miden_core::program::InputError> {
        advice_stack_from_ints(self)
    }
}

impl<T> IntoAdviceStackInput for &T
where
    T: Clone + IntoAdviceStackInput,
{
    fn into_advice_stack_input(
        self,
    ) -> Result<crate::AdviceStack, miden_core::program::InputError> {
        self.clone().into_advice_stack_input()
    }
}

pub fn advice_stack_from<I>(stack: I) -> Result<crate::AdviceStack, miden_core::program::InputError>
where
    I: IntoAdviceStackInput,
{
    stack.into_advice_stack_input()
}

fn advice_stack_from_ints<I>(iter: I) -> Result<crate::AdviceStack, miden_core::program::InputError>
where
    I: IntoIterator<Item = u64>,
{
    let stack = iter
        .into_iter()
        .map(|value| {
            crate::Felt::from_canonical_checked(value)
                .ok_or(miden_core::program::InputError::InvalidStackElement(value))
        })
        .collect::<Result<::alloc::vec::Vec<_>, _>>()?;

    Ok(stack.into())
}

// MACROS TO BUILD TESTS
// ================================================================================================

/// Creates a `Vec<u64>` for stack inputs where the first element will be on top of the stack.
///
/// This macro handles the reversal required by `StackInputs`, which reverses
/// its input internally. With this macro, you can specify stack inputs in intuitive order.
///
/// # Example
///
/// ```ignore
/// // Stack will be [a, b, c, d, ...] with 'a' at position 0 (top)
/// let inputs = stack![a, b, c, d];
/// let test = build_op_test!("some_op", &inputs);
/// ```
///
/// # Word Helper
///
/// To add a Word to the stack with `word[0]` on top, use the `word` helper:
///
/// ```ignore
/// // Stack will be [w[0], w[1], w[2], w[3], ...] with w[0] on top
/// let inputs = stack![word(my_word), other_value];
/// ```
#[macro_export]
macro_rules! stack {
    ($($elem:expr),* $(,)?) => {{
        ::alloc::vec![$($elem as u64),*]
    }};
}

/// Returns a Test struct in non debug mode from a string of one or more operations and any
/// specified stack and advice inputs.
///
/// Parameters are expected in the following order:
/// `source`, `stack_inputs` (optional), `advice_stack` (optional), `merkle_store` (optional)
///
/// * `source`: a string of one or more operations, e.g. "push.1 push.2".
/// * `stack_inputs` (optional): the initial inputs which must be at the top of the stack before
///   executing the `source`. Stack inputs can be provided independently without any advice inputs.
/// * `advice_stack` (optional): the initial advice stack values. When provided, `stack_inputs` and
///   `merkle_store` are also expected.
/// * `merkle_store` (optional): the initial merkle set values. When provided, `stack_inputs` and
///   `advice_stack` are also expected.
#[macro_export]
macro_rules! build_op_test {
    ($op_str:expr) => {{
        let source = format!("
@locals(4)
proc truncate_stack
    loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end

begin {} exec.truncate_stack end",
            $op_str
        );
        $crate::build_test!(&source)
    }};
    ($op_str:expr, $($tail:tt)+) => {{
        let source = format!("
@locals(4)
proc truncate_stack
    loc_storew_be.0 dropw movupw.3
    sdepth neq.16
    while.true
        dropw movupw.3
        sdepth neq.16
    end
    loc_loadw_be.0
end

begin {} exec.truncate_stack end",
            $op_str
        );
        $crate::build_test!(&source, $($tail)+)
    }};
}

/// Returns a Test struct in non debug mode from the provided source string, and any specified
/// stack and advice inputs.
///
/// Parameters are expected in the following order:
/// `source`, `stack_inputs` (optional), `advice_stack` (optional), `merkle_store` (optional)
///
/// * `source`: a well-formed source string.
/// * `stack_inputs` (optional): the initial inputs which must be at the top of the stack before
///   executing the `source`. Stack inputs can be provided independently without any advice inputs.
/// * `advice_stack` (optional): the initial advice stack values. When provided, `stack_inputs` and
///   `merkle_store` are also expected.
/// * `merkle_store` (optional): the initial merkle set values. When provided, `stack_inputs` and
///   `advice_stack` are also expected.
#[macro_export]
macro_rules! build_test {
    ($($params:tt)+) => {{
        $crate::build_test_by_mode!(false, $($params)+)
    }}
}

/// Returns a Test struct in debug mode from the provided source string and any specified stack
/// and advice inputs.
///
/// Parameters are expected in the following order:
/// `source`, `stack_inputs` (optional), `advice_stack` (optional), `merkle_store` (optional)
///
/// * `source`: a well-formed source string.
/// * `stack_inputs` (optional): the initial inputs which must be at the top of the stack before
///   executing the `source`. Stack inputs can be provided independently without any advice inputs.
/// * `advice_stack` (optional): the initial advice stack values. When provided, `stack_inputs` and
///   `merkle_store` are also expected.
/// * `merkle_store` (optional): the initial merkle set values. When provided, `stack_inputs` and
///   `advice_stack` are also expected.
///
/// NOTE: use `miden_core_lib::tests::build_debug_test` to include the core library in the test.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        $crate::build_test_by_mode!(true, $($params)+)
    }}
}

/// Returns a Test struct in the specified debug or non-debug mode using the provided source string
/// and any specified stack and advice inputs.
///
/// Parameters start with a boolean flag, `in_tracing_mode`, specifying whether the test is built in
/// debug or non-debug mode. After that, they match the parameters of `build_test` and
///`build_debug_test` macros.
///
/// This macro is an internal test builder, and is not intended to be called directly from tests.
/// Instead, the build_test and build_debug_test wrappers should be used.
#[macro_export]
macro_rules! build_test_by_mode {
    ($in_tracing_mode:expr, $source:expr) => {{
        let name = format!("test{}", line!());
        let source = $source;
        $crate::Test::new(&name, &source, $in_tracing_mode)
    }};
    ($in_tracing_mode:expr, $source:expr, $stack_inputs:expr) => {{
        use $crate::SourceManager;

        let stack_inputs: ::alloc::vec::Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::stack_inputs_from_ints(stack_inputs);
        let advice_inputs = $crate::AdviceInputs::default();
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load($crate::SourceLanguage::Masm, name.into(), $source.into());

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_tracing_mode: $in_tracing_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    ($in_tracing_mode:expr, $source:expr, $stack_inputs:expr, $advice_stack:expr) => {{
        use $crate::SourceManager;

        let stack_inputs: ::alloc::vec::Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::stack_inputs_from_ints(stack_inputs);
        let advice_stack = $crate::advice_stack_from(&$advice_stack).unwrap();
        let store = $crate::crypto::MerkleStore::new();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_advice_stack(advice_stack)
            .with_merkle_store(store);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load($crate::SourceLanguage::Masm, name.into(), $source.into());

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_tracing_mode: $in_tracing_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    (
        $in_tracing_mode:expr,
        $source:expr,
        $stack_inputs:expr,
        $advice_stack:expr,
        $advice_merkle_store:expr
    ) => {{
        use $crate::SourceManager;

        let stack_inputs: Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::stack_inputs_from_ints(stack_inputs);
        let advice_stack = $crate::advice_stack_from(&$advice_stack).unwrap();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_advice_stack(advice_stack)
            .with_merkle_store($advice_merkle_store);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load($crate::SourceLanguage::Masm, name.into(), $source.into());

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_tracing_mode: $in_tracing_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    (
        $in_tracing_mode:expr,
        $source:expr,
        $stack_inputs:expr,
        $advice_stack:expr,
        $advice_merkle_store:expr,
        $advice_map:expr
    ) => {{
        use $crate::SourceManager;

        let stack_inputs: Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::stack_inputs_from_ints(stack_inputs);
        let advice_stack = $crate::advice_stack_from(&$advice_stack).unwrap();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_advice_stack(advice_stack)
            .with_merkle_store($advice_merkle_store)
            .with_map($advice_map);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load($crate::SourceLanguage::Masm, name.into(), $source.into());

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_tracing_mode: $in_tracing_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::advice_stack_from;
    use crate::{AdviceStack, Felt};

    #[test]
    fn advice_stack_from_accepts_integer_slices() {
        let stack = advice_stack_from([1, 2, 3]).unwrap();

        assert_eq!(
            stack.into_elements(),
            vec![Felt::new_unchecked(1), Felt::new_unchecked(2), Felt::new_unchecked(3)]
        );
    }

    #[test]
    fn advice_stack_from_accepts_typed_advice_stack() {
        let mut stack = AdviceStack::new();
        stack.push_element(Felt::new_unchecked(7));

        let converted = advice_stack_from(stack).unwrap();

        assert_eq!(converted.into_elements(), vec![Felt::new_unchecked(7)]);
    }
}
