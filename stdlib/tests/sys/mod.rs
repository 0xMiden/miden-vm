use miden_test_utils::{MIN_STACK_DEPTH, proptest::prelude::*, rand::rand_vector};

#[test]
fn truncate_stack() {
    let source = "use.std::sys begin repeat.12 push.0 end exec.sys::truncate_stack end";
    let test = build_test!(source, &[16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
    test.expect_stack(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4]);
}

proptest! {
    #[test]
    fn truncate_stack_proptest(test_values in prop::collection::vec(any::<u64>(), MIN_STACK_DEPTH), n in 1_usize..100) {
        let mut push_values = rand_vector::<u64>(n);
        let mut source_vec = vec!["use.std::sys".to_string(), "begin".to_string()];
        for value in push_values.iter() {
            let token = format!("push.{value}");
            source_vec.push(token);
        }
        source_vec.push("exec.sys::truncate_stack".to_string());
        source_vec.push("end".to_string());
        let source = source_vec.join(" ");
        let mut expected_values = test_values.clone();
        expected_values.append(&mut push_values);
        expected_values.reverse();
        expected_values.truncate(MIN_STACK_DEPTH);
        build_test!(&source, &test_values).prop_expect_stack(&expected_values)?;
    }
}
