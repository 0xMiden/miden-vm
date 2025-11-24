use std::ops::Add;

use miden_utils_testing::{Felt, FieldElement, push_inputs, rand::rand_array};

use crate::math::ecgfp5::{base_field::Ext5, group::ECExt5};

fn gen_random_private_key() -> [u32; 10] {
    rand_array::<u32, 10>()
}

fn get_generator() -> ECExt5 {
    ECExt5 {
        x: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ),
        y: Ext5::new(
            0xb2ca178ecf4453a1,
            0x3c757788836d3ea4,
            0x48d7f28a26dafd0b,
            0x1e0f15c7fd44c28e,
            0x21fa7ffcc8252211,
        ) * Ext5::from_int(4),
        point_at_infinity: Felt::ZERO,
    }
}

#[test]
fn test_elgamal_keygen() {
    let generator = get_generator();
    let private_key = gen_random_private_key();
    let q1 = generator.scalar_mul(&private_key);

    let mut stack: [u64; 10] =
        private_key.iter().map(|x| *x as u64).collect::<Vec<u64>>().try_into().unwrap();

    let source = "
        use std::crypto::elgamal_ecgfp5
        use std::sys

        begin
            exec.elgamal_ecgfp5::gen_privatekey

            exec.sys::truncate_stack
        end
    ";

    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();
    assert_eq!(strace[0], q1.x.a0);
    assert_eq!(strace[1], q1.x.a1);
    assert_eq!(strace[2], q1.x.a2);
    assert_eq!(strace[3], q1.x.a3);
    assert_eq!(strace[4], q1.x.a4);
    assert_eq!(strace[5], q1.y.a0);
    assert_eq!(strace[6], q1.y.a1);
    assert_eq!(strace[7], q1.y.a2);
    assert_eq!(strace[8], q1.y.a3);
    assert_eq!(strace[9], q1.y.a4);
    assert_eq!(strace[10], q1.point_at_infinity);
}

#[test]
fn test_elgamal_encrypt() {
    //inputs r, M, H
    //r is 10 limbs
    //H and M are both x and y at point inf
    //11*2 inputs
    let private_key = gen_random_private_key();
    let r = gen_random_private_key();

    let generator = get_generator();
    let plaintext_scalar = [
        666904740u32,
        257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let pm = generator.scalar_mul(&plaintext_scalar);

    let ca = generator.scalar_mul(&r);
    let h = generator.scalar_mul(&private_key);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

    let source = "
        use std::crypto::elgamal_ecgfp5
        use std::sys

        begin
            exec.elgamal_ecgfp5::encrypt_ca

            exec.sys::truncate_stack
        end
    ";

    let mut stack = [
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
        r[5] as u64,
        r[6] as u64,
        r[7] as u64,
        r[8] as u64,
        r[9] as u64,
    ];

    stack.reverse();

    let test = build_test!(source, &stack);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], ca.x.a0);
    assert_eq!(strace[1], ca.x.a1);
    assert_eq!(strace[2], ca.x.a2);
    assert_eq!(strace[3], ca.x.a3);
    assert_eq!(strace[4], ca.x.a4);
    assert_eq!(strace[5], ca.y.a0);
    assert_eq!(strace[6], ca.y.a1);
    assert_eq!(strace[7], ca.y.a2);
    assert_eq!(strace[8], ca.y.a3);
    assert_eq!(strace[9], ca.y.a4);
    assert_eq!(strace[10], ca.point_at_infinity);

    let mut stack = [
        h.x.a0.as_int(),
        h.x.a1.as_int(),
        h.x.a2.as_int(),
        h.x.a3.as_int(),
        h.x.a4.as_int(),
        h.y.a0.as_int(),
        h.y.a1.as_int(),
        h.y.a2.as_int(),
        h.y.a3.as_int(),
        h.y.a4.as_int(),
        h.point_at_infinity.as_int(),
        r[0] as u64,
        r[1] as u64,
        r[2] as u64,
        r[3] as u64,
        r[4] as u64,
        r[5] as u64,
        r[6] as u64,
        r[7] as u64,
        r[8] as u64,
        r[9] as u64,
        pm.x.a0.as_int(),
        pm.x.a1.as_int(),
        pm.x.a2.as_int(),
        pm.x.a3.as_int(),
        pm.x.a4.as_int(),
        pm.y.a0.as_int(),
        pm.y.a1.as_int(),
        pm.y.a2.as_int(),
        pm.y.a3.as_int(),
        pm.y.a4.as_int(),
        pm.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let source = format!(
        "
        use std::crypto::elgamal_ecgfp5
        use std::sys

        begin
            {inputs}
            exec.elgamal_ecgfp5::encrypt_cb

            exec.sys::truncate_stack
        end
    ",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], cb.x.a0);
    assert_eq!(strace[1], cb.x.a1);
    assert_eq!(strace[2], cb.x.a2);
    assert_eq!(strace[3], cb.x.a3);
    assert_eq!(strace[4], cb.x.a4);
    assert_eq!(strace[5], cb.y.a0);
    assert_eq!(strace[6], cb.y.a1);
    assert_eq!(strace[7], cb.y.a2);
    assert_eq!(strace[8], cb.y.a3);
    assert_eq!(strace[9], cb.y.a4);
    assert_eq!(strace[10], cb.point_at_infinity);
}

#[test]
fn test_elgamal_remask() {
    // Also known as rerandomisation
    // inputs r, H, Cb, Ca
    // The private key
    let private_key = gen_random_private_key();
    let r = gen_random_private_key();
    let r_prime = gen_random_private_key();

    let generator = get_generator();
    let plaintext_scalar = [
        666904740u32,
        257318652u32,
        4031728122u32,
        3689598853u32,
        703808805u32,
        386793741u32,
        2898811333u32,
        4092670716u32,
        1596344924u32,
        1692681010u32,
    ];

    let pm = generator.scalar_mul(&plaintext_scalar);

    let ca = generator.scalar_mul(&r);
    let h = generator.scalar_mul(&private_key);
    let rh = h.scalar_mul(&r);
    let cb = pm.add(rh);

    // ca and cb are the original plaintext
    let r_prime_g = generator.scalar_mul(&r_prime);
    let r_prime_h = h.scalar_mul(&r_prime);
    let c_prime_a = ca.add(r_prime_g);
    let c_prime_b = cb.add(r_prime_h);

    let mut stack = [
        r_prime[0] as u64,
        r_prime[1] as u64,
        r_prime[2] as u64,
        r_prime[3] as u64,
        r_prime[4] as u64,
        r_prime[5] as u64,
        r_prime[6] as u64,
        r_prime[7] as u64,
        r_prime[8] as u64,
        r_prime[9] as u64,
        ca.x.a0.as_int(),
        ca.x.a1.as_int(),
        ca.x.a2.as_int(),
        ca.x.a3.as_int(),
        ca.x.a4.as_int(),
        ca.y.a0.as_int(),
        ca.y.a1.as_int(),
        ca.y.a2.as_int(),
        ca.y.a3.as_int(),
        ca.y.a4.as_int(),
        ca.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let source = format!(
        "
        use std::crypto::elgamal_ecgfp5
        use std::sys

        begin
            {inputs}
            exec.elgamal_ecgfp5::remask_ca

            exec.sys::truncate_stack
        end
    ",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c_prime_a.x.a0);
    assert_eq!(strace[1], c_prime_a.x.a1);
    assert_eq!(strace[2], c_prime_a.x.a2);
    assert_eq!(strace[3], c_prime_a.x.a3);
    assert_eq!(strace[4], c_prime_a.x.a4);
    assert_eq!(strace[5], c_prime_a.y.a0);
    assert_eq!(strace[6], c_prime_a.y.a1);
    assert_eq!(strace[7], c_prime_a.y.a2);
    assert_eq!(strace[8], c_prime_a.y.a3);
    assert_eq!(strace[9], c_prime_a.y.a4);
    assert_eq!(strace[10], c_prime_a.point_at_infinity);

    let mut stack = [
        h.x.a0.as_int(),
        h.x.a1.as_int(),
        h.x.a2.as_int(),
        h.x.a3.as_int(),
        h.x.a4.as_int(),
        h.y.a0.as_int(),
        h.y.a1.as_int(),
        h.y.a2.as_int(),
        h.y.a3.as_int(),
        h.y.a4.as_int(),
        h.point_at_infinity.as_int(),
        r_prime[0] as u64,
        r_prime[1] as u64,
        r_prime[2] as u64,
        r_prime[3] as u64,
        r_prime[4] as u64,
        r_prime[5] as u64,
        r_prime[6] as u64,
        r_prime[7] as u64,
        r_prime[8] as u64,
        r_prime[9] as u64,
        cb.x.a0.as_int(),
        cb.x.a1.as_int(),
        cb.x.a2.as_int(),
        cb.x.a3.as_int(),
        cb.x.a4.as_int(),
        cb.y.a0.as_int(),
        cb.y.a1.as_int(),
        cb.y.a2.as_int(),
        cb.y.a3.as_int(),
        cb.y.a4.as_int(),
        cb.point_at_infinity.as_int(),
    ];
    stack.reverse();

    let source = format!(
        "
        use std::crypto::elgamal_ecgfp5
        use std::sys

        begin
            {inputs}
            exec.elgamal_ecgfp5::remask_cb

            exec.sys::truncate_stack
        end
    ",
        inputs = push_inputs(&stack)
    );

    let test = build_test!(source, &[]);
    let strace = test.get_last_stack_state();

    assert_eq!(strace[0], c_prime_b.x.a0);
    assert_eq!(strace[1], c_prime_b.x.a1);
    assert_eq!(strace[2], c_prime_b.x.a2);
    assert_eq!(strace[3], c_prime_b.x.a3);
    assert_eq!(strace[4], c_prime_b.x.a4);
    assert_eq!(strace[5], c_prime_b.y.a0);
    assert_eq!(strace[6], c_prime_b.y.a1);
    assert_eq!(strace[7], c_prime_b.y.a2);
    assert_eq!(strace[8], c_prime_b.y.a3);
    assert_eq!(strace[9], c_prime_b.y.a4);
    assert_eq!(strace[10], c_prime_b.point_at_infinity);
}
