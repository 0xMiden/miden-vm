// MACROS TO BUILD TESTS
// ================================================================================================

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
proc.truncate_stack.4
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
proc.truncate_stack.4
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
/// NOTE: use `miden_stdlib::tests::build_debug_test` to include the standard library in the test.
#[macro_export]
macro_rules! build_debug_test {
    ($($params:tt)+) => {{
        $crate::build_test_by_mode!(true, $($params)+)
    }}
}

/// Returns a Test struct in the specified debug or non-debug mode using the provided source string
/// and any specified stack and advice inputs.
///
/// Parameters start with a boolean flag, `in_debug_mode`, specifying whether the test is built in
/// debug or non-debug mode. After that, they match the parameters of `build_test` and
///`build_debug_test` macros.
///
/// This macro is an internal test builder, and is not intended to be called directly from tests.
/// Instead, the build_test and build_debug_test wrappers should be used.
#[macro_export]
macro_rules! build_test_by_mode {
    ($in_debug_mode:expr, $source:expr) => {{
        let name = format!("test{}", line!());
        $crate::Test::new(&name, $source, $in_debug_mode)
    }};
    ($in_debug_mode:expr, $source:expr, $stack_inputs:expr) => {{
        use $crate::SourceManager;

        let stack_inputs: ::alloc::vec::Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::StackInputs::try_from_ints(stack_inputs).unwrap();
        let advice_inputs = $crate::AdviceInputs::default();
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load(
            $crate::SourceLanguage::Masm,
            name.into(),
            ::alloc::string::String::from($source),
        );

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_debug_mode: $in_debug_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    ($in_debug_mode:expr, $source:expr, $stack_inputs:expr, $advice_stack:expr) => {{
        use $crate::SourceManager;

        let stack_inputs: ::alloc::vec::Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::StackInputs::try_from_ints(stack_inputs).unwrap();
        let stack_values: ::alloc::vec::Vec<u64> = $advice_stack.to_vec();
        let store = $crate::crypto::MerkleStore::new();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_stack_values(stack_values)
            .unwrap()
            .with_merkle_store(store);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load(
            $crate::SourceLanguage::Masm,
            name.into(),
            ::alloc::string::String::from($source),
        );

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_debug_mode: $in_debug_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    (
        $in_debug_mode:expr,
        $source:expr,
        $stack_inputs:expr,
        $advice_stack:expr,
        $advice_merkle_store:expr
    ) => {{
        use $crate::SourceManager;

        let stack_inputs: Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::StackInputs::try_from_ints(stack_inputs).unwrap();
        let stack_values: Vec<u64> = $advice_stack.to_vec();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_stack_values(stack_values)
            .unwrap()
            .with_merkle_store($advice_merkle_store);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load(
            $crate::SourceLanguage::Masm,
            name.into(),
            ::alloc::string::String::from($source),
        );

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_debug_mode: $in_debug_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
    (
        $in_debug_mode:expr,
        $source:expr,
        $stack_inputs:expr,
        $advice_stack:expr,
        $advice_merkle_store:expr,
        $advice_map:expr
    ) => {{
        use $crate::SourceManager;

        let stack_inputs: Vec<u64> = $stack_inputs.to_vec();
        let stack_inputs = $crate::StackInputs::try_from_ints(stack_inputs).unwrap();
        let stack_values: Vec<u64> = $advice_stack.to_vec();
        let advice_inputs = $crate::AdviceInputs::default()
            .with_stack_values(stack_values)
            .unwrap()
            .with_merkle_store($advice_merkle_store)
            .with_map($advice_map);
        let name = format!("test{}", line!());
        let source_manager = ::alloc::sync::Arc::new($crate::DefaultSourceManager::default());
        let source = source_manager.load(
            $crate::SourceLanguage::Masm,
            name.into(),
            ::alloc::string::String::from($source),
        );

        $crate::Test {
            source_manager,
            source,
            kernel_source: None,
            stack_inputs,
            advice_inputs,
            in_debug_mode: $in_debug_mode,
            libraries: ::alloc::vec::Vec::default(),
            handlers: ::alloc::vec::Vec::new(),
            add_modules: ::alloc::vec::Vec::default(),
        }
    }};
}
