#[test]
fn validate_inputs_trace_length_upper_bound() {
    let test = build_test!(validate_inputs_source(), &[30, 7, 0]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn validate_inputs_trace_length_lower_bound() {
    let test = build_test!(validate_inputs_source(), &[5, 7, 0]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn validate_inputs_num_queries_upper_bound() {
    let test = build_test!(validate_inputs_source(), &[10, 151, 0]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn validate_inputs_num_queries_lower_bound() {
    let test = build_test!(validate_inputs_source(), &[10, 6, 0]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn validate_inputs_grinding_upper_bound() {
    let test = build_test!(validate_inputs_source(), &[10, 7, 32]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn init_seed_trace_length_too_large_has_message() {
    let source = "
        use miden::core::stark::random_coin
        begin
            push.0 push.0 push.0 push.0 push.7 push.32
            exec.random_coin::init_seed
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test, contains "range check");
}

#[test]
fn generate_aux_randomness_mismatch_has_message() {
    let source = "
        use miden::core::stark::constants
        use miden::core::stark::random_coin
        begin
            push.11.22.33.44 exec.constants::r1_ptr mem_storew_be dropw
            push.99.44.11.22 exec.constants::aux_rand_nd_ptr mem_storew_be dropw
            exec.random_coin::generate_aux_randomness
        end
    ";
    let test = build_test!(source, &[]);
    expect_assert_error_message!(test, contains "comparison");
}

fn validate_inputs_source() -> &'static str {
    "
        use miden::core::stark::utils
        begin
            exec.utils::validate_inputs
        end
    "
}
