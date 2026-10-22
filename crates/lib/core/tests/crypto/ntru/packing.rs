//! Exercise the maintained private helpers without making them part of the library API.

use super::*;

const PRODUCT: u32 = 1536;
const LIFT_M: u32 = 2560;
const LIFT_R: u32 = 3072;
const CIPHERTEXT: u32 = 3584;

fn execute(program: &Program, inputs: &[Felt], advice: AdviceInputs) -> ExecutionOutput {
    FastProcessor::new(StackInputs::new(inputs).unwrap())
        .with_advice(advice)
        .unwrap()
        .execute_sync(program, &mut DefaultHost::default())
        .unwrap()
}

fn helper_program(body: &str) -> Program {
    let module =
        include_str!("../../../asm/crypto/kem/ntru_hps509.masm").replace("pub proc ", "proc ");
    assemble(&format!("{module}\nbegin\n{body}\nend"))
}

fn lift(trit: u64) -> u64 {
    if trit == 2 { 2047 } else { trit }
}

#[test]
fn trit_byte_encoding_covers_every_digit() {
    let program = helper_program(
        "adv_push mem_store.64 push.73.72.64 exec.encode_trits20 repeat.4 movup.4 drop end",
    );
    let cases = (0..20)
        .flat_map(|i| [3u32.pow(i), 2 * 3u32.pow(i)])
        .chain([0, 3u32.pow(20) - 1]);
    for packed in cases {
        let output = execute(&program, &[], private_advice([Felt::from(packed)]));
        let expected = (0..4).fold(0, |word, i| word | ((packed / 243u32.pow(i)) % 243) << (8 * i));
        for (i, value) in [expected, 64, 72, 73].into_iter().enumerate() {
            assert_eq!(output.stack.get_element(i), Some(Felt::from(value)));
        }
        assert_eq!(memory(&output, 64, 1), [Felt::from(packed)]);
    }
}

#[test]
fn lift_table_covers_every_four_trit_word() {
    let guards = [124, 452]
        .map(|address| format!("push.[5,6,7,8] mem_storew_le.{address} dropw"))
        .join("\n");
    let program = helper_program(&format!("{guards}\nexec.prepare_lift_table"));
    let output =
        execute(&program, &[Felt::from(91u32), Felt::from(73u32)], AdviceInputs::default());
    for index in 0..81u32 {
        let trits: [u64; 4] = core::array::from_fn(|j| u64::from(index) / 3u64.pow(j as u32) % 3);
        assert_eq!(memory(&output, 128 + 4 * index, 4), trits.map(|x| Felt::from(lift(x) as u32)));
    }
    for address in [124, 452] {
        assert_eq!(memory(&output, address, 4), [5u32, 6, 7, 8].map(Felt::from));
    }
    assert_eq!(output.stack.get_element(0), Some(Felt::from(91u32)));
    assert_eq!(output.stack.get_element(1), Some(Felt::from(73u32)));
}

#[test]
fn trit_decoding_covers_every_tail_and_each_full_word_digit() {
    for (name, ptr) in [("r", LIFT_R), ("m", LIFT_M)] {
        for count in [8, 20] {
            let guards = [ptr - 4, ptr + count]
                .map(|address| format!("push.[5,6,7,8] mem_storew_le.{address} dropw"))
                .join("\n");
            let program = helper_program(&format!(
                "{guards}\nexec.prepare_lift_table \
                 push.94.93.92.{ptr} adv_push exec.decode_{name}{count} \
                 repeat.4 movup.4 drop end"
            ));
            let limit = 3u64.pow(count);
            let cases: Vec<_> = if count == 8 {
                (0..limit).collect()
            } else {
                (0..count)
                    .flat_map(|i| {
                        let digit = 3u64.pow(i);
                        [digit, 2 * digit, limit - 1 - digit, limit - 1 - 2 * digit]
                    })
                    .chain([0, (limit - 1) / 2, limit - 1])
                    .collect()
            };
            for value in cases {
                let output = execute(&program, &[], private_advice([Felt::from(value as u32)]));
                let lifts: Vec<_> = (0..count).map(|i| lift(value / 3u64.pow(i) % 3)).collect();
                assert_eq!(
                    memory(&output, ptr, count as usize),
                    lifts.iter().map(|&x| Felt::from(x as u32)).collect::<Vec<_>>()
                );
                assert_eq!(memory(&output, ptr - 4, 4), [5u32, 6, 7, 8].map(Felt::from));
                assert_eq!(memory(&output, ptr + count, 4), [5u32, 6, 7, 8].map(Felt::from));
                let sum = 93 + if name == "m" { lifts.iter().sum::<u64>() } else { 0 };
                for (i, x) in [u64::from(ptr + count), 92, sum, 94].into_iter().enumerate() {
                    assert_eq!(output.stack.get_element(i), Some(Felt::from(x as u32)));
                }
            }
            expect_failure(
                &program,
                Word::default(),
                private_advice([Felt::from(limit as u32)]),
                "packed trits",
            );
        }
    }
}

#[test]
fn ciphertext_packing_covers_every_bit_and_tail_padding() {
    for (index, count) in [(0u32, 32usize), (480, 28)] {
        let end = CIPHERTEXT + (11 * count).div_ceil(32) as u32;
        let program = helper_program(&format!(
            "push.33 mem_store.{} push.44 mem_store.{end} \
             push.{} repeat.{count} adv_push dup.1 mem_store add.1 end drop \
             push.73.72.{index}.{CIPHERTEXT} exec.fold_encode{count} repeat.4 movup.4 drop end",
            CIPHERTEXT - 1,
            PRODUCT + index,
        ));
        let cases = (0..count * 11)
            .map(|bit| {
                let mut coefficients = vec![0u32; count];
                coefficients[bit / 11] = 1 << (bit % 11);
                coefficients
            })
            .chain([vec![0; count], vec![2047; count]]);
        for coefficients in cases {
            let output = execute(
                &program,
                &[],
                private_advice(coefficients.iter().copied().map(Felt::from)),
            );
            // Independent bit-by-bit encoding, including zero high bits in the final u32.
            let mut words = vec![0u32; (11 * count).div_ceil(32)];
            for (i, coefficient) in coefficients.iter().enumerate() {
                for bit in 0..11 {
                    let position = 11 * i + bit;
                    words[position / 32] |= ((coefficient >> bit) & 1) << (position % 32);
                }
            }
            assert_eq!(
                memory(&output, CIPHERTEXT, words.len()),
                words.iter().copied().map(Felt::from).collect::<Vec<_>>()
            );
            assert_eq!(
                output.stack.get_element(0),
                Some(Felt::from(CIPHERTEXT + words.len() as u32))
            );
            assert_eq!(output.stack.get_element(1), Some(Felt::from(index + count as u32)));
            assert_eq!(output.stack.get_element(2), Some(Felt::from(72u32)));
            assert_eq!(output.stack.get_element(3), Some(Felt::from(73u32)));
            assert_eq!(memory(&output, CIPHERTEXT - 1, 1), [Felt::from(33u32)]);
            assert_eq!(memory(&output, end, 1), [Felt::from(44u32)]);
        }
    }
}

#[test]
fn folding_uses_the_shifted_upper_word_without_field_wrap() {
    let bounds = [0u64, 1, 2047, 2_132_816_380, 2_132_816_381];
    for i in [0u32, 504] {
        let stores = (PRODUCT + i..PRODUCT + i + 4)
            .chain(PRODUCT + i + 508..PRODUCT + i + 513)
            .chain(LIFT_M + i..LIFT_M + i + 4)
            .map(|address| format!("adv_push mem_store.{address}"))
            .collect::<Vec<_>>()
            .join("\n");
        let program = helper_program(&format!(
            "{stores}\npush.987.654.{i} exec.fold_pack_four repeat.4 movup.4 drop end"
        ));
        for a in 0..bounds.len() {
            for b in 0..bounds.len() {
                for trit in 0..3 {
                    let low: [u64; 4] = core::array::from_fn(|j| bounds[(a + j) % bounds.len()]);
                    let high: [u64; 4] =
                        core::array::from_fn(|j| bounds[(b + 2 * j) % bounds.len()]);
                    let message: [u64; 4] = core::array::from_fn(|j| lift((trit + j as u64) % 3));
                    let advice = low
                        .into_iter()
                        .chain([bounds[(a + b) % bounds.len()]])
                        .chain(high)
                        .chain(message)
                        .map(|x| Felt::new(x).unwrap());
                    let output = execute(&program, &[], private_advice(advice));
                    let packed: u64 =
                        (0..4).map(|j| ((low[j] + high[j] + message[j]) % 2048) << (11 * j)).sum();
                    assert_eq!(output.stack.get_element(0), Some(Felt::new(packed).unwrap()));
                    for (j, x) in [i, 654, 987].into_iter().enumerate() {
                        assert_eq!(output.stack.get_element(1 + j), Some(Felt::from(x)));
                    }
                }
            }
        }
    }
}

#[test]
fn product_challenges_match_the_packed_transcript() {
    use miden_crypto::hash::eidos::{Eidos, domains::NTRU_HPS509_EIDOS};

    let mut rng = ChaCha20Rng::from_seed([49; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let (_, _, advice) = key.public_key().encapsulate_with_advice(&mut rng);
    let advice: Vec<_> = advice.elements().collect();
    // h(512) || product(1024) || packed_r(26) || packed_m(26), without block padding.
    let transcript: Vec<_> = advice[..512]
        .iter()
        .chain(&advice[564..1588])
        .chain(&advice[512..564])
        .copied()
        .collect();
    let mut expected = Eidos::init_chaining_word_with_params(NTRU_HPS509_EIDOS, [4, 1588, 0]);
    for chunk in transcript.chunks(8) {
        let mut block = [Felt::ZERO; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        expected = Eidos::compress(expected, block);
    }
    let program = helper_program("exec.encapsulate_inner");
    let output =
        execute(&program, key.public_key().to_commitment().as_elements(), private_advice(advice));
    // The digest is split into the two Fp2 evaluation points.
    let actual: Vec<_> = memory(&output, 44, 2).into_iter().chain(memory(&output, 84, 2)).collect();
    assert_eq!(actual, expected.as_elements());
}
