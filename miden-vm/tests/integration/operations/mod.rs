#[cfg(feature = "testing")]
macro_rules! assert_op_assembler_diagnostic {
    ($test:ident, $message:expr, $source:expr, $marker:expr) => {
        miden_utils_testing::assert_assembler_diagnostic!(
            $test,
            "error: test compilation produced diagnostics",
            "|",
            $message,
            miden_assembly::testing::Pattern::regex(r#"--> test[\d]+:13:[\d]+"#),
            "|",
            "1 |",
            "2 | @locals(4)",
            "3 | proc truncate_stack",
            "4 |     loc_storew_be.0 dropw movupw.3",
            "5 |     sdepth neq.16",
            "6 |     while.true",
            "7 |         dropw movupw.3",
            "8 |         sdepth neq.16",
            "9 |     end",
            "10 |     loc_loadw_be.0",
            "11 | end",
            "12 |",
            $source,
            $marker
        );
    };
}

mod crypto_ops;
mod events;
mod ext2_ops;
mod field_ops;
mod fri_ops;
mod io_ops;
mod stack_ops;
mod sys_ops;
mod u32_ops;
