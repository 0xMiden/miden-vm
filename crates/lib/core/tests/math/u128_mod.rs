use miden_utils_testing::proptest::prelude::*;

proptest! {
    #[test]
    fn overflowing_add(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (c, ov) = a.overflowing_add(b);
        let (chh, cmh, cml, cll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_add
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[ov as u64, chh, cmh, cml, cll]);
    }

    #[test]
    fn wrapping_add(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (chh, cmh, cml, cll) = split_u128(a.wrapping_add(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_add
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[chh, cmh, cml, cll]);
    }

    #[test]
    fn overflowing_sub(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (c, un) = a.overflowing_sub(b);
        let (chh, cmh, cml, cll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_sub
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[un as u64, chh, cmh, cml, cll]);
    }

    #[test]
    fn wrapping_sub(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (chh, cmh, cml, cll) = split_u128(a.wrapping_sub(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_sub
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[chh, cmh, cml, cll]);
    }

    #[test]
    fn overflowing_mul(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (c, ov) = a.overflowing_mul(b);
        let (chh, cmh, cml, cll) = split_u128(c);

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::overflowing_mul
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[ov as u64, chh, cmh, cml, cll]);
    }

    #[test]
    fn wrapping_mul(a in any::<u128>(), b in any::<u128>()) {
        let (ahh, amh, aml, all) = split_u128(a);
        let (bhh, bmh, bml, bll) = split_u128(b);
        let (chh, cmh, cml, cll) = split_u128(a.wrapping_mul(b));

        let source = "
            use miden::core::math::u128
            begin
                exec.u128::wrapping_mul
            end
        ";

        build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
            .expect_stack(&[chh, cmh, cml, cll]);
    }

    #[test]
    fn div(a in any::<u128>(), b in any::<u128>()) {
        if b == 0 {
            // Skip it for now.
        } else {
            let (ahh, amh, aml, all) = split_u128(a);
            let (bhh, bmh, bml, bll) = split_u128(b);
            let (chh, cmh, cml, cll) = split_u128(a / b);

            let source = "
                use miden::core::math::u128
                begin
                    exec.u128::div
                end
            ";

            build_test!(source, &[all, aml, amh, ahh, bll, bml, bmh, bhh])
                .expect_stack(&[chh, cmh, cml, cll]);
        }
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
