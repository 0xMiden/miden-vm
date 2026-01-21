use miden_utils_testing::proptest::prelude::*;

proptest! {
    #[test]
    fn overflowing_add(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, ov) = a.overflowing_add(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_add
            end
        ";

        // LE convention: low limb at position 0 (top of stack)
        // StackInputs::try_from_ints puts first array element at position 0
        // Stack: [b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh, ...]
        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[ov as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_add(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_add(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_add
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn overflowing_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, un) = a.overflowing_sub(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_sub
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[un as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_sub(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_sub(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_sub
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn overflowing_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c, ov) = a.overflowing_mul(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_mul
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[ov as u64, c_ll, c_ml, c_mh, c_hh]);
    }

    #[test]
    fn wrapping_mul(a in any::<u128>(), b in any::<u128>()) {
        let (a_hh, a_mh, a_ml, a_ll) = split_u128(a);
        let (b_hh, b_mh, b_ml, b_ll) = split_u128(b);
        let (c_hh, c_mh, c_ml, c_ll) = split_u128(a.wrapping_mul(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_mul
            end
        ";

        build_test!(source, &[b_ll, b_ml, b_mh, b_hh, a_ll, a_ml, a_mh, a_hh])
            .expect_stack(&[c_ll, c_ml, c_mh, c_hh]);
    }
}

fn split_u128(value: u128) -> (u64, u64, u64, u64) {
    (
        (value >> 96) as u64,
        (value >> 64) as u32 as u64,
        (value >> 32) as u32 as u64,
        value as u32 as u64,
    )
}
