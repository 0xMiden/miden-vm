//! Tests for ECDSA secp256k1 precompile.
//!
//! Validates that:
//! - Raw event handlers correctly perform ECDSA verification and populate advice provider
//! - Private implementation helper returns the expected commitment, tag, and result on stack
//! - Both valid and invalid signatures are handled correctly

use miden_core::{
    Felt, Word,
    events::EventName,
    field::PrimeCharacteristicRing,
    precompile::{PrecompileCommitment, PrecompileVerifier},
    serde::{Deserializable, Serializable},
    utils::{IntoBytes, bytes_to_packed_u32_elements},
};
use miden_core_lib::{
    dsa::ecdsa_k256_keccak::sign as ecdsa_sign,
    handlers::ecdsa::{EcdsaPrecompile, EcdsaRequest},
};
use miden_crypto::{dsa::ecdsa_k256_keccak::SigningKey as SecretKey, hash::poseidon2::Poseidon2};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler},
};
use miden_utils_testing::proptest::prelude::*;
use rand::{SeedableRng, rngs::StdRng};

use crate::helpers::masm_store_felts;

// TEST CONSTANTS
// ================================================================================================

const PK_ADDR: u32 = 128;
const DIGEST_ADDR: u32 = 192;
const SIG_ADDR: u32 = 256;

// TESTS PRECOMPILE
// ================================================================================================

#[test]
fn test_ecdsa_verify_cases() {
    // One valid and one invalid (wrong key) request
    let test_cases = vec![
        (generate_valid_signature(), true),
        (generate_invalid_signature_wrong_key(), false),
    ];

    for (request, expected_valid) in test_cases {
        let memory_stores = generate_memory_store_masm(&request);

        let source = format!(
            "
                use miden::core::crypto::dsa::ecdsa_k256_keccak
                use miden::core::sys

                begin
                    # Store test data in memory
                    {memory_stores}

                    # Call verify: [ptr_pk, ptr_digest, ptr_sig]
                    push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                    exec.ecdsa_k256_keccak::verify_prehash
                    # => [result, ...]

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(source, &[]);
        let (output, _) = test.execute_for_output().unwrap();

        // Assert result
        let result = output.stack.get_element(0).unwrap();
        assert_eq!(result, Felt::from_bool(expected_valid));

        // Verify the precompile request was logged with the right event ID
        let deferred = output.advice.precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1);
        assert_eq!(deferred[0], request.as_precompile_request());
    }
}

#[test]
fn test_ecdsa_verify_impl_commitment() {
    // One valid and one invalid (wrong key) request
    let test_cases = vec![
        (generate_valid_signature(), true),
        (generate_invalid_signature_wrong_key(), false),
    ];
    for (request, expected_valid) in test_cases {
        // Verify tag/commitment once on a valid request
        let memory_stores = generate_memory_store_masm(&request);

        let source = private_proc_harness(
            include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
            format!(
                "
                    # Store test data in memory
                    {memory_stores}

                    # Call verify_impl: [ptr_pk, ptr_digest, ptr_sig]
                    push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                    exec.verify_prehash_impl
                    # => [COMM, TAG, result, ...]

                    exec.sys::truncate_stack
                ",
            ),
        );

        let test = build_debug_test!(source, &[]);
        let (output, _) = test.execute_for_output().unwrap();
        let stack = output.stack;

        // Verify stack layout: [COMM (0-3), TAG (4-7), result (at position 8), ...]
        // TAG = [event_id, result, 0, 0] where TAG[1]=result is at position 5
        // Use get_stack_word to match LE stack convention
        let commitment = stack.get_word(0).unwrap();
        let tag = stack.get_word(4).unwrap();
        // Commitment and tag must match verifier output
        let precompile_commitment = PrecompileCommitment::new(tag, commitment);
        let verifier_commitment =
            EcdsaPrecompile.verify(&request.to_bytes()).expect("verifier should succeed");
        assert_eq!(
            precompile_commitment, verifier_commitment,
            "commitment on stack should match verifier output"
        );

        // Verify result - TAG[1] is at position 5 (TAG is at positions 4-7)
        let result = stack.get_element(5).unwrap();
        assert_eq!(
            result,
            Felt::from_bool(expected_valid),
            "result does not match expected validity"
        );

        let deferred = output.advice.precompile_requests().to_vec();
        assert_eq!(deferred.len(), 1, "expected a single deferred request");
        assert_eq!(deferred[0], request.as_precompile_request());

        let advice_stack = output.advice.stack();
        assert!(advice_stack.is_empty(), "advice stack should be empty after verify_impl");
    }
}

// TESTS SIGN+VERIFY
// ================================================================================================

const EVENT_ECDSA_SIG_TO_STACK: EventName = EventName::new("test::ecdsa::sig_to_stack");

struct EcdsaSignatureHandler {
    secret_key_bytes: Vec<u8>,
}

impl EcdsaSignatureHandler {
    fn new(secret_key: &SecretKey) -> Self {
        Self { secret_key_bytes: secret_key.to_bytes() }
    }
}

impl EventHandler for EcdsaSignatureHandler {
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        // Stack: [event_id, pk_commitment(1-4), message(5-8), ...]
        let provided_pk_commitment = process.get_stack_word(1);
        let secret_key =
            SecretKey::read_from_bytes(&self.secret_key_bytes).expect("invalid test secret key");
        let pk_commitment = {
            let pk = secret_key.public_key();
            let pk_felts = bytes_to_packed_u32_elements(&pk.to_bytes());
            Poseidon2::hash_elements(&pk_felts)
        };
        assert_eq!(
            provided_pk_commitment, pk_commitment,
            "public key commitment mismatch: expected {pk_commitment:?}, got {provided_pk_commitment:?}"
        );

        // Message starts at position 5 (after event_id + pk_commitment)
        let message = process.get_stack_word(5);
        let calldata = ecdsa_sign(&secret_key, message);

        // Use extend_stack to make elements available in order: pk first, then sig
        Ok(vec![AdviceMutation::extend_stack(calldata)])
    }
}

#[test]
fn test_ecdsa_verify_bis_wrapper() {
    let mut rng = StdRng::seed_from_u64(19260817);
    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();
    let message = Word::from([
        Felt::new_unchecked(11),
        Felt::new_unchecked(22),
        Felt::new_unchecked(33),
        Felt::new_unchecked(44),
    ]);

    let pk_commitment = {
        let pk_felts = bytes_to_packed_u32_elements(&public_key.to_bytes());
        Poseidon2::hash_elements(&pk_felts)
    };

    let source = format!(
        "
        use miden::core::crypto::dsa::ecdsa_k256_keccak

        begin
            push.{message}
            push.{pk_commitment}
            emit.event(\"{EVENT_ECDSA_SIG_TO_STACK}\")
            exec.ecdsa_k256_keccak::verify
        end
        ",
    );

    let test = build_debug_test!(&source)
        .with_event_handler(EVENT_ECDSA_SIG_TO_STACK, EcdsaSignatureHandler::new(&secret_key));

    test.expect_stack(&[]);
}

// TEST DATA GENERATION
// ================================================================================================

/// Generates a valid signature using deterministic seed
fn generate_valid_signature() -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();

    // Use a simple deterministic digest
    let digest = [1u8; 32];
    let sig = secret_key.sign_prehash(digest);

    EcdsaRequest::new(pk, digest, sig)
}

/// Generates an invalid signature by signing with a different key
fn generate_invalid_signature_wrong_key() -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key1 = SecretKey::with_rng(&mut rng);
    let pk = secret_key1.public_key();

    // Create a different key for signing
    let mut rng2 = StdRng::seed_from_u64(123);
    let secret_key2 = SecretKey::with_rng(&mut rng2);

    let digest = [1u8; 32];
    let sig = secret_key2.sign_prehash(digest);

    EcdsaRequest::new(pk, digest, sig)
}

// MASM GENERATION HELPERS
// ================================================================================================

/// Generates MASM code to store test data (pk, digest, sig) into memory as packed u32 values.
///
/// Memory layout:
/// - Public key: PK_ADDR (33 bytes)
/// - Digest: DIGEST_ADDR (32 bytes)
/// - Signature: SIG_ADDR (65 bytes)
fn generate_memory_store_masm(request: &EcdsaRequest) -> String {
    let pk_words = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_elements(request.digest());
    let sig_words = bytes_to_packed_u32_elements(&request.sig().to_bytes());

    [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ")
}

fn private_proc_harness(module_source: &str, body: impl AsRef<str>) -> String {
    format!("{}\n\nbegin\n{}\nend", module_source.replace("pub proc", "proc"), body.as_ref())
}

// NATIVE-PATH HELPER TESTS
// ================================================================================================
// Byte-shuffling: packed u32-LE-byte calldata -> u32-LE-limb integers for f_k1/k1_scalar/k1_point.

#[test]
fn byte_rev_u32_known_values() {
    // (input, expected_byte_reversed)
    let cases: [(u32, u32); 6] = [
        (0x0000_0000, 0x0000_0000),
        (0xffff_ffff, 0xffff_ffff),
        (0xaabb_ccdd, 0xddcc_bbaa),
        (0x0000_0001, 0x0100_0000),
        (0x12345678, 0x78563412),
        (0xdead_beef, 0xefbe_adde),
    ];
    for (input, expected) in cases {
        let source = private_proc_harness(
            include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
            format!(
                "
                push.{input}
                exec._byte_rev_u32
                push.{expected}
                assert_eq.err=\"byte_rev_u32 mismatch\"
                "
            ),
        );
        build_test!(&source, &[]).execute().unwrap();
    }
}

#[test]
fn parse_be_u256_secp256k1_n() {
    // The secp256k1 group order n encoded as 32 big-endian bytes:
    //   FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE
    //   BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 41
    //
    // Packed as 8 u32-LE felts (each felt = u32::from_le_bytes(4 consecutive bytes)).
    // Expected u32 LE integer limbs (low to high) are byte_rev of felt[7..0]:
    //   0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
    //   0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF.
    let module_with_wrapper = format!(
        "{}\n\n@locals(24)\nproc test_wrapper_parse_be_u256
            # Stack at entry: [packed[0], packed[1], ..., packed[7], ...] with packed[0] on top.
            # Store to mem[0..8] (word-aligned).
            loc_store.0
            loc_store.1
            loc_store.2
            loc_store.3
            loc_store.4
            loc_store.5
            loc_store.6
            loc_store.7

            # _parse_be_u256(dest=locaddr.16, src=locaddr.0); stack [dest, src].
            # Both addresses must be word-aligned (multiples of 4).
            locaddr.0  locaddr.16
            exec._parse_be_u256

            # Read mem[16..24] back, in reverse order so limb 0 ends on top.
            loc_load.23
            loc_load.22
            loc_load.21
            loc_load.20
            loc_load.19
            loc_load.18
            loc_load.17
            loc_load.16
        end",
        include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
    );
    let source = private_proc_harness(
        &module_with_wrapper,
        "
            # Push packed felts so packed[0] (= 0xFFFFFFFF) ends on top.
            # Push order is deepest-first: packed[7], packed[6], ..., packed[0].
            push.0x414136D0  push.0x8C5ED2BF  push.0x3BA048AF  push.0xE6DCAEBA
            push.0xFEFFFFFF  push.0xFFFFFFFF  push.0xFFFFFFFF  push.0xFFFFFFFF

            exec.test_wrapper_parse_be_u256

            # Assert top word = [limb0, limb1, limb2, limb3] = [0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6].
            # push.A.B.C.D leaves stack with D on top, A at depth 3.
            push.0xBAAEDCE6.0xAF48A03B.0xBFD25E8C.0xD0364141
            assert_eqw.err=\"limbs 0-3 mismatch\"

            # Assert next word = [limb4..7] = [0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF].
            push.0xFFFFFFFF.0xFFFFFFFF.0xFFFFFFFF.0xFFFFFFFE
            assert_eqw.err=\"limbs 4-7 mismatch\"
        ",
    );
    build_test!(&source, &[]).execute().unwrap();
}

#[test]
fn parse_sig_known_values() {
    // Synthetic signature with all bytes distinct so any byte-shuffling bug shows up.
    //   r bytes (BE): 01 02 03 ... 20
    //   s bytes (BE): 21 22 23 ... 40
    //   v byte: 1B
    //
    // Expected r limbs (low to high):
    //   0x1D1E1F20, 0x191A1B1C, 0x15161718, 0x11121314,
    //   0x0D0E0F10, 0x090A0B0C, 0x05060708, 0x01020304
    //
    // Expected s limbs:
    //   0x3D3E3F40, 0x393A3B3C, 0x35363738, 0x31323334,
    //   0x2D2E2F30, 0x292A2B2C, 0x25262728, 0x21222324
    let module_with_wrapper = format!(
        "{}\n\n@locals(40)\nproc test_wrapper_parse_sig
            # Lay out the 17 packed sig felts at mem[0..17].
            push.0x04030201 loc_store.0
            push.0x08070605 loc_store.1
            push.0x0C0B0A09 loc_store.2
            push.0x100F0E0D loc_store.3
            push.0x14131211 loc_store.4
            push.0x18171615 loc_store.5
            push.0x1C1B1A19 loc_store.6
            push.0x201F1E1D loc_store.7
            push.0x24232221 loc_store.8
            push.0x28272625 loc_store.9
            push.0x2C2B2A29 loc_store.10
            push.0x302F2E2D loc_store.11
            push.0x34333231 loc_store.12
            push.0x38373635 loc_store.13
            push.0x3C3B3A39 loc_store.14
            push.0x403F3E3D loc_store.15
            push.0x00000001 loc_store.16   # sig[16] = v (0x01) || zero padding; valid

            # _parse_sig(dest_r=locaddr.20, dest_s=locaddr.28, sig_ptr=locaddr.0).
            # Stack convention: [dest_r_addr, dest_s_addr, sig_ptr, ...] with dest_r on top.
            # _parse_sig now also returns a `flag` (1 iff sig[16] < 4); assert it.
            locaddr.0  locaddr.28  locaddr.20
            exec._parse_sig
            assert.err=\"_parse_sig flag\"

            # Read s (mem[28..36]) reverse so s[0] is on top of its 8.
            loc_load.35  loc_load.34  loc_load.33  loc_load.32
            loc_load.31  loc_load.30  loc_load.29  loc_load.28

            # Read r (mem[20..28]) reverse so r[0] is on top.
            loc_load.27  loc_load.26  loc_load.25  loc_load.24
            loc_load.23  loc_load.22  loc_load.21  loc_load.20
        end",
        include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
    );
    let source = private_proc_harness(
        &module_with_wrapper,
        "
            exec.test_wrapper_parse_sig

            # Top word = r[0..3]. Push expected so they end on top in matching order.
            push.0x11121314.0x15161718.0x191A1B1C.0x1D1E1F20  assert_eqw.err=\"r[0..3]\"
            push.0x01020304.0x05060708.0x090A0B0C.0x0D0E0F10  assert_eqw.err=\"r[4..7]\"
            push.0x31323334.0x35363738.0x393A3B3C.0x3D3E3F40  assert_eqw.err=\"s[0..3]\"
            push.0x21222324.0x25262728.0x292A2B2C.0x2D2E2F30  assert_eqw.err=\"s[4..7]\"
        ",
    );
    build_test!(&source, &[]).execute().unwrap();
}

/// Helper: render a `_parse_compressed_pk` test wrapper. The 9 packed pk felts are pushed via
/// `push` instructions (we can't pass them via `&operands` because of the 16-felt cap), then
/// laid out at `locaddr.0..locaddr.9`. After the proc call we read mem[20..28] (x as integer
/// limbs), mem[30] (parity), and the returned flag, leaving them on the operand stack with
/// flag on top.
fn parse_compressed_pk_source(felt0: u32, asserts: &str) -> String {
    // The test below uses a fixed Gx for the rest of the bytes; only felt[0] (the byte
    // containing the prefix) varies between cases.
    let module_with_wrapper = format!(
        "{}\n\n@locals(40)\nproc test_wrapper_parse_pk
            push.{felt0:#x}    loc_store.0
            push.0xBBDCF97E    loc_store.1
            push.0x62A055AC    loc_store.2
            push.0x0B87CE95    loc_store.3
            push.0xFC9B0207    loc_store.4
            push.0x28CE2DDB    loc_store.5
            push.0x81F259D9    loc_store.6
            push.0x17F8165B    loc_store.7
            push.0x00000098    loc_store.8

            # _parse_compressed_pk(dest_x=locaddr.20, dest_parity=locaddr.30, pk_ptr=locaddr.0).
            locaddr.0  locaddr.30  locaddr.20
            exec._parse_compressed_pk
            # Stack now: [flag, ...]. Stash flag in mem[31] for retrieval below.
            loc_store.31

            # Load mem[30] (parity), mem[20..28] (x limbs in reverse so x[0] on top), and mem[31] (flag).
            loc_load.31  loc_load.30
            loc_load.27  loc_load.26  loc_load.25  loc_load.24
            loc_load.23  loc_load.22  loc_load.21  loc_load.20
            # Stack now (top -> bottom): x[0], x[1], ..., x[7], parity, flag.
        end",
        include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
    );
    private_proc_harness(
        &module_with_wrapper,
        format!(
            "
                exec.test_wrapper_parse_pk
                {asserts}
            "
        ),
    )
}

#[test]
fn parse_compressed_pk_even_parity() {
    // Valid pk with prefix 0x02 (y is even). felt[0] = u32_le(0x02, 0x79, 0xBE, 0x66) = 0x66BE7902.
    // Expected: x = Gx integer limbs, parity = 0, flag = 1.
    let asserts = "
        push.0x029BFCDB.0x2DCE28D9.0x59F2815B.0x16F81798  assert_eqw.err=\"x[0..3]\"
        push.0x79BE667E.0xF9DCBBAC.0x55A06295.0xCE870B07  assert_eqw.err=\"x[4..7]\"
        push.0  assert_eq.err=\"parity\"
        push.1  assert_eq.err=\"flag\"
    ";
    let source = parse_compressed_pk_source(0x66be7902, asserts);
    build_test!(&source, &[]).execute().unwrap();
}

#[test]
fn parse_compressed_pk_odd_parity() {
    // Valid pk with prefix 0x03 (y is odd). felt[0] = u32_le(0x03, 0x79, 0xBE, 0x66) = 0x66BE7903.
    // x is the same Gx; only parity changes.
    let asserts = "
        push.0x029BFCDB.0x2DCE28D9.0x59F2815B.0x16F81798  assert_eqw.err=\"x[0..3]\"
        push.0x79BE667E.0xF9DCBBAC.0x55A06295.0xCE870B07  assert_eqw.err=\"x[4..7]\"
        push.1  assert_eq.err=\"parity\"
        push.1  assert_eq.err=\"flag\"
    ";
    let source = parse_compressed_pk_source(0x66be7903, asserts);
    build_test!(&source, &[]).execute().unwrap();
}

// NATIVE-PATH END-TO-END TESTS
// ================================================================================================

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn ecdsa_verify_prehash_native_cycles() {
    use miden_processor::ContextId;

    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);

    // Measure the cost of `verify_prehash_native` for a valid signature. The proc runs every
    // check unconditionally (validity is accumulated as a multiplicative flag), so an invalid
    // signature would cost roughly the same; we measure the valid case for simplicity.
    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                clk
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash_native
                # => [result, t0, ...]
                clk                                          # [t1, result, t0, ...]
                movup.2 sub                                  # [t1 - t0, result, ...]
                push.5000 mem_store                          # mem[5000] = cycle delta
                push.5001 mem_store                          # mem[5001] = result
                exec.sys::truncate_stack
            end
        ",
    );

    let test = build_debug_test!(&source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    let result = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5001))
        .unwrap()
        .as_canonical_u64();
    assert_eq!(result, 1, "verify_prehash_native should accept the valid signature");
    eprintln!("verify_prehash_native cycles (valid sig): {cycles}");
}

/// Assert that `verify_prehash_native` returns the expected 0/1 result for the given
/// (possibly-malformed) pk/digest/sig byte triple, and that the proc completes without
/// trapping. Used by the adversarial tests below to exercise the no-trap contract.
fn assert_native_verify(
    pk_bytes: &[u8],
    digest: &[u8; 32],
    sig_bytes: &[u8],
    expected_result: u64,
) {
    assert_eq!(pk_bytes.len(), 33, "pk must be 33 bytes");
    assert_eq!(sig_bytes.len(), 65, "sig must be 65 bytes");
    let pk_words = bytes_to_packed_u32_elements(pk_bytes);
    let digest_words = bytes_to_packed_u32_elements(digest);
    let sig_words = bytes_to_packed_u32_elements(sig_bytes);

    let memory_stores = [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ");

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash_native

                exec.sys::truncate_stack
            end
        ",
    );

    let test = build_debug_test!(&source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::new_unchecked(expected_result),
        "verify_prehash_native expected {expected_result}, got {result}",
    );
}

#[test]
fn ecdsa_verify_prehash_native_malformed_pk_prefix_returns_zero() {
    // Take a valid signature and replace the pk's prefix byte with 0x04 (the SEC1
    // uncompressed-key prefix; not valid for our compressed-only path). The proc must
    // return 0 without trapping.
    let request = generate_valid_signature();
    let mut pk_bytes = request.pk().to_bytes();
    pk_bytes[0] = 0x04;
    assert_native_verify(&pk_bytes, request.digest(), &request.sig().to_bytes(), 0);
}

#[test]
fn ecdsa_verify_prehash_native_zero_r_returns_zero() {
    // r = 0 is forbidden by ECDSA. The proc must catch it and return 0 without trapping.
    let request = generate_valid_signature();
    let mut sig_bytes = request.sig().to_bytes();
    for b in &mut sig_bytes[0..32] {
        *b = 0;
    }
    assert_native_verify(&request.pk().to_bytes(), request.digest(), &sig_bytes, 0);
}

#[test]
fn ecdsa_verify_prehash_native_zero_s_returns_zero() {
    // s = 0 is forbidden (and would trap `k1_scalar::inv` if not substituted).
    let request = generate_valid_signature();
    let mut sig_bytes = request.sig().to_bytes();
    for b in &mut sig_bytes[32..64] {
        *b = 0;
    }
    assert_native_verify(&request.pk().to_bytes(), request.digest(), &sig_bytes, 0);
}

#[test]
fn ecdsa_verify_prehash_native_invalid_v_returns_zero() {
    // The native path validates that sig[64] (v) is in {0, 1, 2, 3} to match the precompile
    // path's `Signature::read_from_bytes` constraint. v = 0x1B is the legacy Ethereum
    // recovery byte and exceeds 3; both paths must reject.
    let request = generate_valid_signature();
    let mut sig_bytes = request.sig().to_bytes();
    sig_bytes[64] = 0x1b;
    assert_native_verify(&request.pk().to_bytes(), request.digest(), &sig_bytes, 0);
}

#[test]
fn ecdsa_verify_prehash_native_nonzero_sig_padding_returns_zero() {
    // sig[16] (the 17th packed felt) must hold [v, 0, 0, 0] in LE byte order. A nonzero
    // upper byte is a malformed calldata that the precompile path rejects via
    // `read_memory_packed_u32`'s padding check; the native path's `sig[16] u32lt.4` check
    // covers it. Bypass `bytes_to_packed_u32_elements` to construct the exact malformed felt.
    let request = generate_valid_signature();
    let pk_words = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_elements(request.digest());
    let mut sig_words = bytes_to_packed_u32_elements(&request.sig().to_bytes());
    // v = 0 (low byte) but byte 3 nonzero. sig[16] = 0x01000000 (= 16777216) > 4, fails.
    sig_words[16] = Felt::new_unchecked(0x0100_0000);

    let memory_stores = [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ");
    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash_native
                exec.sys::truncate_stack
            end
        ",
    );
    let test = build_debug_test!(&source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::new_unchecked(0),
        "verify_prehash_native must reject nonzero sig[16] padding bytes",
    );
}

#[test]
fn ecdsa_verify_prehash_native_nonzero_pk_padding_returns_zero() {
    // pk[8] (the 9th packed felt) must hold [last_byte_of_x, 0, 0, 0]. A nonzero upper byte
    // is the same class of malformed calldata as the sig[16] case above; the native path's
    // `pk[8] u32lt.256` check inside `_parse_compressed_pk` covers it.
    let request = generate_valid_signature();
    let mut pk_words = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_elements(request.digest());
    let sig_words = bytes_to_packed_u32_elements(&request.sig().to_bytes());
    // Keep the low byte (last byte of x) intact, set byte 1 to nonzero. pk[8] >= 256, fails.
    let low_byte = pk_words[8].as_canonical_u64() & 0xff;
    pk_words[8] = Felt::new_unchecked(low_byte | 0x0000_0100);

    let memory_stores = [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ");
    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}
                push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                exec.ecdsa_k256_keccak::verify_prehash_native
                exec.sys::truncate_stack
            end
        ",
    );
    let test = build_debug_test!(&source, &[]);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::new_unchecked(0),
        "verify_prehash_native must reject nonzero pk[8] padding bytes",
    );
}

#[test]
fn ecdsa_verify_prehash_native_pk_x_equal_p_returns_zero() {
    // x = p_k1 violates the canonical-range check (x must be < p). Substitution to a safe
    // value should keep the proc from trapping; the validity flag should be 0.
    let request = generate_valid_signature();
    let mut pk_bytes = request.pk().to_bytes();
    // Set x to p_k1 in big-endian: 0xFFFFFFFF...FFFFFFFEFFFFFC2F
    pk_bytes[1..29].fill(0xff);
    pk_bytes[29] = 0xfe;
    pk_bytes[30] = 0xff;
    pk_bytes[31] = 0xfc;
    pk_bytes[32] = 0x2f;
    assert_native_verify(&pk_bytes, request.digest(), &request.sig().to_bytes(), 0);
}

#[test]
fn ecdsa_verify_prehash_native_valid_and_invalid() {
    // Two cases: a valid signature (expected result = 1) and a signature signed with the
    // wrong key (expected result = 0). Reuses the calldata-prep helpers from the precompile
    // test path so we exercise the *same* byte format the precompile interface uses.
    let cases = vec![
        (generate_valid_signature(), true),
        (generate_invalid_signature_wrong_key(), false),
    ];

    for (request, expected_valid) in cases {
        let memory_stores = generate_memory_store_masm(&request);
        let source = format!(
            "
                use miden::core::crypto::dsa::ecdsa_k256_keccak
                use miden::core::sys

                begin
                    {memory_stores}

                    push.{SIG_ADDR}.{DIGEST_ADDR}.{PK_ADDR}
                    exec.ecdsa_k256_keccak::verify_prehash_native
                    # => [result, ...]

                    exec.sys::truncate_stack
                end
            ",
        );

        let test = build_debug_test!(&source, &[]);
        let (output, _) = test.execute_for_output().unwrap();
        let result = output.stack.get_element(0).unwrap();
        assert_eq!(
            result,
            Felt::from_bool(expected_valid),
            "verify_prehash_native expected {expected_valid} for this case, got {result}",
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Low-count integration property test for the native ECDSA verifier: random key + digest
    /// must verify, while a one-bit mutation in the digest/signature/public key must reject.
    #[test]
    fn ecdsa_verify_prehash_native_sign_verify_proptest(
        seed in any::<u64>(),
        digest in prop::array::uniform32(any::<u8>()),
        corrupt_target in 0u8..3,
        flip_idx in 0usize..64,
    ) {
        let mut rng = StdRng::seed_from_u64(seed);
        let secret_key = SecretKey::with_rng(&mut rng);
        let pk = secret_key.public_key();
        let sig = secret_key.sign_prehash(digest);
        let request = EcdsaRequest::new(pk, digest, sig);

        assert_native_verify(
            &request.pk().to_bytes(),
            request.digest(),
            &request.sig().to_bytes(),
            1,
        );

        let mut pk_bytes = request.pk().to_bytes();
        let mut wrong_digest = *request.digest();
        let mut sig_bytes = request.sig().to_bytes();
        match corrupt_target {
            0 => wrong_digest[flip_idx % 32] ^= 1,
            // Mutate r/s only. The recovery id is validated for well-formedness but is not used by
            // the ECDSA equation checked by `verify_prehash_native`.
            1 => sig_bytes[flip_idx] ^= 1,
            // Keep the compressed-key prefix well-formed and mutate x.
            2 => pk_bytes[1 + (flip_idx % 32)] ^= 1,
            _ => unreachable!("corrupt_target is generated in 0..3"),
        }
        assert_native_verify(&pk_bytes, &wrong_digest, &sig_bytes, 0);
    }
}

/// secp256k1 base prime as 8 u32 LE limbs (low to high). Duplicated from `tests/math/u256_mod`
/// to avoid a cross-test-tree import; the values are checked against the canonical handler
/// constant by the modmul tests anyway.
const SECP_P_LIMBS: [u32; 8] = [
    0xffff_fc2f,
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];

const SECP_GX_LIMBS: [u32; 8] = [
    0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e,
];

const SECP_GY_LIMBS: [u32; 8] = [
    0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77,
];

/// `p_k1 - Gy` as 8 u32 LE limbs (= the y of -G).
fn neg_gy_limbs() -> [u32; 8] {
    use num::bigint::BigUint;
    let p = BigUint::from_slice(&SECP_P_LIMBS);
    let gy = BigUint::from_slice(&SECP_GY_LIMBS);
    let neg = &p - &gy;
    let digits = neg.to_u32_digits();
    let mut out = [0u32; 8];
    for (i, &d) in digits.iter().enumerate().take(8) {
        out[i] = d;
    }
    out
}

/// Build a `_decompress_no_trap` test wrapper. Pushes x and parity, calls the helper, then
/// leaves `[flag, X (8), Y (8), inf_word (4), ...]` on the stack.
fn decompress_no_trap_source(x_limbs: &[u32; 8], parity: u8, asserts: &str) -> String {
    let pushes_x = (0..8)
        .rev()
        .map(|i| format!("push.{:#x}", x_limbs[i]))
        .collect::<Vec<_>>()
        .join(" ");

    let module_with_wrapper = format!(
        "{}\n\n@locals(40)\nproc test_wrapper_decompress_no_trap
            # Stack at entry: [x[0], x[1], ..., x[7], parity, ...] with x[0] on top.
            loc_storew_le.0  dropw                       # mem[0..4] = x[0..4]
            loc_storew_le.4  dropw                       # mem[4..8] = x[4..8]
            loc_store.8                                  # mem[8] = parity

            # _decompress_no_trap(dest_pt=locaddr.12, x_addr=locaddr.0, parity_addr=locaddr.8).
            locaddr.8  locaddr.0  locaddr.12
            exec._decompress_no_trap
            loc_store.32                                 # stash flag at mem[32]

            # Read mem[12..32] in reverse address order so X[0..4] ends on top.
            padw loc_loadw_le.28
            padw loc_loadw_le.24
            padw loc_loadw_le.20
            padw loc_loadw_le.16
            padw loc_loadw_le.12

            # Push flag on top.
            loc_load.32
        end",
        include_str!("../../asm/crypto/dsa/ecdsa_k256_keccak.masm"),
    );

    private_proc_harness(
        &module_with_wrapper,
        format!(
            "
                # Push parity first (deepest), then x[7..0] -> stack [x[0..7], parity].
                push.{parity}
                {pushes_x}
                exec.test_wrapper_decompress_no_trap
                {asserts}
            "
        ),
    )
}

#[test]
fn decompress_no_trap_g_even_parity() {
    let asserts = format!(
        "
        push.1  assert_eq.err=\"flag should be 1\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"X[0..3]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"X[4..7]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"Y[0..3]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"Y[4..7]\"
        push.0.0.0.0  assert_eqw.err=\"inf_flag\"
        ",
        SECP_GX_LIMBS[3],
        SECP_GX_LIMBS[2],
        SECP_GX_LIMBS[1],
        SECP_GX_LIMBS[0],
        SECP_GX_LIMBS[7],
        SECP_GX_LIMBS[6],
        SECP_GX_LIMBS[5],
        SECP_GX_LIMBS[4],
        SECP_GY_LIMBS[3],
        SECP_GY_LIMBS[2],
        SECP_GY_LIMBS[1],
        SECP_GY_LIMBS[0],
        SECP_GY_LIMBS[7],
        SECP_GY_LIMBS[6],
        SECP_GY_LIMBS[5],
        SECP_GY_LIMBS[4],
    );
    let source = decompress_no_trap_source(&SECP_GX_LIMBS, 0, &asserts);
    build_test!(&source, &[]).execute().unwrap();
}

#[test]
fn decompress_no_trap_g_odd_parity_yields_neg_g() {
    let neg_gy = neg_gy_limbs();
    let asserts = format!(
        "
        push.1  assert_eq.err=\"flag should be 1\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"X[0..3]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"X[4..7]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"Y[0..3]\"
        push.{:#x}.{:#x}.{:#x}.{:#x}  assert_eqw.err=\"Y[4..7]\"
        push.0.0.0.0  assert_eqw.err=\"inf_flag\"
        ",
        SECP_GX_LIMBS[3],
        SECP_GX_LIMBS[2],
        SECP_GX_LIMBS[1],
        SECP_GX_LIMBS[0],
        SECP_GX_LIMBS[7],
        SECP_GX_LIMBS[6],
        SECP_GX_LIMBS[5],
        SECP_GX_LIMBS[4],
        neg_gy[3],
        neg_gy[2],
        neg_gy[1],
        neg_gy[0],
        neg_gy[7],
        neg_gy[6],
        neg_gy[5],
        neg_gy[4],
    );
    let source = decompress_no_trap_source(&SECP_GX_LIMBS, 1, &asserts);
    build_test!(&source, &[]).execute().unwrap();
}

#[test]
fn decompress_no_trap_off_curve_x_yields_flag_zero_and_identity() {
    // x = 0 is canonical (< p) and provably NOT a curve x-coordinate: the curve equation
    // requires y² ≡ 7 mod p, but 7 is a quadratic non-residue mod p_k1 (verifiable via
    // quadratic reciprocity: p_k1 ≡ 1 mod 7, so (7|p_k1) = -(p_k1|7) = -(1|7) = -1).
    // The other decompression checks (X < p, parity, Y < p, Y mod 2 == parity) still
    // pass; only the y² == x³+7 check fails. The proc must:
    //   (1) flag = 0;
    //   (2) is_infinity slot = 1 (per the post-decompress identity-substitution fix; this
    //       is the load-bearing piece that keeps `verify_glv_hinted`'s MSM safe when the
    //       caller-supplied PK doesn't decompress).
    let x_limbs = [0u32; 8];
    let asserts = "
        push.0  assert_eq.err=\"flag should be 0 for off-curve x\"
        # Drop X (2 words) and Y (2 words); only the inf_word remains underneath.
        dropw  dropw  dropw  dropw
        # is_infinity is at the LOW slot of the inf_word, which lands on top of the stack
        # after `loc_loadw_le`. push.0.0.0.1 puts 1 on TOP, matching the expected layout
        # `[is_infinity = 1, pad, pad, pad]`.
        push.0.0.0.1  assert_eqw.err=\"inf_flag should be 1 for off-curve x\"
    ";
    let source = decompress_no_trap_source(&x_limbs, 0, asserts);
    build_test!(&source, &[]).execute().unwrap();
}

#[test]
fn parse_compressed_pk_invalid_prefix_yields_zero_flag() {
    // Prefix 0x04 (uncompressed-key prefix) is invalid for our compressed-only path.
    // felt[0] = u32_le(0x04, 0x79, 0xBE, 0x66) = 0x66BE7904. Expected flag = 0.
    let asserts = "
        # We only check the flag here; x and parity values for an invalid prefix are
        # unspecified and must be ignored when flag = 0.
        # Drop x[0..7] and parity to leave only the flag on top.
        dropw  dropw  drop
        push.0  assert_eq.err=\"flag should be 0\"
    ";
    let source = parse_compressed_pk_source(0x66be7904, asserts);
    build_test!(&source, &[]).execute().unwrap();
}

// VERIFY_PREHASH_NATIVE_PRECOMP -- Merkle-committed comb-table verifier
// ================================================================================================

/// Decompress a 33-byte SEC1 compressed secp256k1 public key into its affine `(x, y)` BigUint
/// coordinates. Uses `y = (x^3 + 7)^((p+1)/4) mod p`, valid because `p == 3 (mod 4)`.
fn decompress_pk_to_xy(pk_bytes: &[u8]) -> (num::BigUint, num::BigUint) {
    use num::BigUint;
    assert_eq!(pk_bytes.len(), 33, "compressed pk must be 33 bytes");
    let prefix = pk_bytes[0];
    assert!(prefix == 0x02 || prefix == 0x03, "compressed pk prefix must be 0x02 or 0x03");

    let p = BigUint::from_slice(&SECP_P_LIMBS);
    let x = BigUint::from_bytes_be(&pk_bytes[1..33]);
    let rhs = (x.modpow(&BigUint::from(3u32), &p) + BigUint::from(7u32)) % &p;
    let exp = (&p + BigUint::from(1u32)) / BigUint::from(4u32);
    let y_candidate = rhs.modpow(&exp, &p);

    let want_odd = prefix == 0x03;
    let candidate_odd = (&y_candidate % BigUint::from(2u32)) == BigUint::from(1u32);
    let y = if want_odd == candidate_odd {
        y_candidate
    } else {
        &p - y_candidate
    };
    (x, y)
}

/// Witness bundle for `verify_prehash_native_precomp` under the Merkle-committed table
/// design. Holds:
///   - `pk_aug`: 4-felt augmented public-key commitment.
///   - `pk_aug_value`: 16-felt advice-map value at key `pk_aug`, defined as `compressed_PK_9 ||
///     zeros_3 || merkle_root_4`.
///   - `precomputed_pk`: reusable per-key comb-table cache; per-signature advice and Merkle paths
///     are selected from it.
///   - `u_1`, `u_2`: ECDSA scalars derived from `(digest, sig)`, used to select the per-window
///     table entries.
struct PrecompWitness {
    pk_aug: [Felt; 4],
    pk_aug_value: Vec<Felt>,
    precomputed_pk: miden_core_lib::handlers::comb_k1::PrecomputedK1PubKey,
    u_1: num::BigUint,
    u_2: num::BigUint,
}

/// Compute `pk_aug` (= `Poseidon2::hash_elements(compressed_PK || zeros || merkle_root)`),
/// the per-public-key comb-table cache, and the scalars `(u_1, u_2)` the verifier derives
/// from this signature.
fn precomp_witness(request: &EcdsaRequest) -> PrecompWitness {
    use miden_core::crypto::hash::Poseidon2;
    use miden_core_lib::handlers::comb_k1::{AffinePoint, PrecomputedK1PubKey};
    use num::BigUint;

    let pk_bytes = request.pk().to_bytes();
    let (q_x, q_y) = decompress_pk_to_xy(&pk_bytes);
    let g = AffinePoint {
        x: BigUint::from_slice(&SECP_GX_LIMBS),
        y: BigUint::from_slice(&SECP_GY_LIMBS),
        is_infinity: false,
    };
    let q = AffinePoint { x: q_x, y: q_y, is_infinity: false };
    let precomputed_pk = PrecomputedK1PubKey::new(&g, &q);
    let merkle_root = precomputed_pk.merkle_root();

    let pk_felts = bytes_to_packed_u32_elements(&pk_bytes);
    assert_eq!(pk_felts.len(), 9);
    let mut pk_aug_value: Vec<Felt> = Vec::with_capacity(16);
    pk_aug_value.extend_from_slice(&pk_felts);
    pk_aug_value.extend([Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    pk_aug_value.extend_from_slice(&merkle_root);
    let pk_aug: [Felt; 4] = *Poseidon2::hash_elements(&pk_aug_value);

    let (u_1, u_2) = derive_u1_u2(request);
    PrecompWitness {
        pk_aug,
        pk_aug_value,
        precomputed_pk,
        u_1,
        u_2,
    }
}

/// Rust derivation of `(u_1, u_2)` from the signed request, mirroring the VM
/// computation in `ecdsa_k256_keccak::verify_prehash_native_precomp`:
///     e      = digest mod n
///     s_inv  = s^-1 mod n
///     u_1    = e * s_inv mod n
///     u_2    = r * s_inv mod n
fn derive_u1_u2(request: &EcdsaRequest) -> (num::BigUint, num::BigUint) {
    use num::BigUint;
    let n = BigUint::from_slice(&secp256k1_scalar_order());
    let r = BigUint::from_bytes_be(request.sig().r());
    let s = BigUint::from_bytes_be(request.sig().s());
    let e = BigUint::from_bytes_be(request.digest()) % &n;
    let s_inv = s.modpow(&(&n - 2u32), &n);
    let u_1 = (&e * &s_inv) % &n;
    let u_2 = (&r * &s_inv) % &n;
    (u_1, u_2)
}

/// Local copy of the secp256k1 scalar order as 8 u32 LE limbs (low to high). Mirrors the
/// `_push_n_k1` constant in the MASM-side ECDSA proc.
fn secp256k1_scalar_order() -> [u32; 8] {
    [
        0xd036_4141,
        0xbfd2_5e8c,
        0xaf48_a03b,
        0xbaae_dce6,
        0xffff_fffe,
        0xffff_ffff,
        0xffff_ffff,
        0xffff_ffff,
    ]
}

/// Build a populated `AdviceInputs` for the precomp-path tests.
fn precomp_advice_inputs(witness: &PrecompWitness) -> miden_core::advice::AdviceInputs {
    use miden_core::{Word, advice::AdviceInputs};

    let (entry_advice, store) =
        witness.precomputed_pk.advice_for_windows(&witness.u_1, &witness.u_2);

    AdviceInputs::default()
        .with_map([(Word::new(witness.pk_aug), witness.pk_aug_value.clone())])
        .with_stack(entry_advice)
        .with_merkle_store(store)
}

/// Render the MASM literal that pushes a 4-felt word so it lands on the operand stack with
/// `word[0]` on top.
fn push_word_inline(word: &[Felt; 4]) -> String {
    format!(
        "push.{}.{}.{}.{}",
        word[3].as_canonical_u64(),
        word[2].as_canonical_u64(),
        word[1].as_canonical_u64(),
        word[0].as_canonical_u64(),
    )
}

// PRECOMP-PATH HAPPY PATH
// ================================================================================================

/// An unmodified witness produced by `precomp_witness` must verify to 1.
#[test]
fn ecdsa_verify_prehash_native_precomp_valid_signature_returns_one() {
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(result, Felt::ONE, "honest precomp witness must verify to 1 (got {:?})", result);
}

// PRECOMP-PATH CYCLES BENCHMARK
// ================================================================================================

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn ecdsa_verify_prehash_native_precomp_cycles() {
    use miden_processor::ContextId;

    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                clk
                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                # => [result, t0, ...]
                clk                                          # [t1, result, t0, ...]
                movup.2 sub                                  # [t1 - t0, result, ...]
                push.5000 mem_store                          # mem[5000] = cycle delta
                push.5001 mem_store                          # mem[5001] = result
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    let result = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5001))
        .unwrap()
        .as_canonical_u64();
    assert_eq!(result, 1, "verify_prehash_native_precomp should accept the valid signature");
    eprintln!("verify_prehash_native_precomp cycles (valid sig): {cycles}");
}

#[test]
#[ignore = "benchmark; run with --ignored to print trace lengths"]
fn ecdsa_verify_prehash_native_precomp_trace_lengths() {
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}
                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let trace = test.execute().unwrap();
    let summary = trace.trace_len_summary();
    let chiplets = summary.chiplets_trace_len();

    eprintln!("verify_prehash_native_precomp trace lengths (valid sig):");
    eprintln!("  main trace          : {}", summary.main_trace_len());
    eprintln!("  range checker trace : {}", summary.range_trace_len());
    eprintln!("  chiplets trace total: {}", chiplets.trace_len());
    eprintln!("    hash chiplet      : {}", chiplets.hash_chiplet_len());
    eprintln!("    bitwise chiplet   : {}", chiplets.bitwise_chiplet_len());
    eprintln!("    memory chiplet    : {}", chiplets.memory_chiplet_len());
    eprintln!("    ACE chiplet       : {}", chiplets.ace_chiplet_len());
    eprintln!("    kernel ROM        : {}", chiplets.kernel_rom_len());
    eprintln!("  max(main, range, chiplets): {}", summary.trace_len());
    eprintln!("  padded (next power of 2)  : {}", summary.padded_trace_len());
    eprintln!("  padding                   : {}%", summary.padding_percentage());
}

// PRECOMP-PATH SOUNDNESS REGRESSIONS
// ================================================================================================

/// A tampered `pk_aug` -- one that doesn't match the honest `Poseidon2(compressed_PK ||
/// zeros || h_T)` -- must cause verification to return 0 without trapping. The advice-map
/// entries are honest; the caller-supplied commitment is not.
#[test]
fn ecdsa_verify_prehash_native_precomp_rejects_tampered_pk_aug() {
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let witness = precomp_witness(&request);

    let mut pk_aug_tampered = witness.pk_aug;
    pk_aug_tampered[0] = Felt::new_unchecked(witness.pk_aug[0].as_canonical_u64() ^ 1);
    let pk_aug_push = push_word_inline(&pk_aug_tampered);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(result, Felt::ZERO, "tampered pk_aug must be rejected (returned {:?})", result);
}

/// A caller-supplied `pk_aug` that is missing from the advice map must return 0 without
/// letting `_parse_compressed_pk` read uninitialized local scratch.
#[test]
fn ecdsa_verify_prehash_native_precomp_missing_pk_aug_advice_returns_zero() {
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    // Honest witness for digest + sig, but pass a pk_aug key that is not inserted into
    // the advice map. This forces the `adv.has_mapkey == 0` branch.
    let unregistered_pk_aug = [
        Felt::new_unchecked(0xdeadbeef),
        Felt::new_unchecked(0xcafebabe),
        Felt::new_unchecked(0xfeedface),
        Felt::new_unchecked(0x12345678),
    ];
    let pk_aug_push = push_word_inline(&unregistered_pk_aug);
    let witness = precomp_witness(&request);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ZERO,
        "missing pk_aug map key must return 0 without trapping (got {:?})",
        result
    );
}

/// A host that publishes a tampered `pk_aug` advice-map entry (one whose stored values
/// don't hash to the caller-supplied `pk_aug`) must cause verification to return 0
/// without trapping. Same gating as the previous test, but the inconsistency is on the
/// witness side rather than on the public-input side.
#[test]
fn ecdsa_verify_prehash_native_precomp_rejects_tampered_advice_witness() {
    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let mut witness = precomp_witness(&request);

    // Flip one bit in compressed_PK in the advice-map value. The caller still supplies the
    // honest pk_aug, so the VM hash check catches the mismatch.
    witness.pk_aug_value[0] = Felt::new_unchecked(witness.pk_aug_value[0].as_canonical_u64() ^ 1);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ZERO,
        "tampered advice witness must be rejected (returned {:?})",
        result
    );
}

/// A witness whose 3 pad felts in the augmented-PK preimage are non-zero must be
/// rejected, even when the hash binding is internally consistent (i.e. `pk_aug` is
/// recomputed from the tampered preimage). This pins the proc's contract to the literal
/// shape `compressed_PK_9 || 0,0,0 || merkle_root_4` rather than "any 16-felt preimage
/// that hashes to pk_aug".
#[test]
fn ecdsa_verify_prehash_native_precomp_rejects_nonzero_preimage_pad() {
    use miden_core::crypto::hash::Poseidon2;

    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let mut witness = precomp_witness(&request);

    // Flip one pad felt; recompute pk_aug from the modified preimage so the hash binding
    // check still passes. Only the new pad-zero check should reject this.
    witness.pk_aug_value[9] = Felt::ONE;
    witness.pk_aug = *Poseidon2::hash_elements(&witness.pk_aug_value);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ZERO,
        "non-zero preimage pad must be rejected (returned {:?})",
        result
    );
}

/// A selected table entry must match its Merkle opening. Tampering the advice-stack entry
/// while keeping the root and path unchanged must trap in `mtree_verify`.
#[test]
fn ecdsa_verify_prehash_native_precomp_traps_on_tampered_merkle_entry() {
    use miden_core::{Word, advice::AdviceInputs};

    let request = generate_valid_signature();
    let memory_stores = generate_memory_store_masm(&request);
    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    // Build the honest entry advice, then flip one bit in the very first felt of the
    // first window's entry. `mtree_verify` at window 0 will see a hash that doesn't
    // match the leaf at that window's `(u_1, u_2)`-derived index under the bound root.
    let mut entry_advice =
        witness.precomputed_pk.entries_in_window_order(&witness.u_1, &witness.u_2);
    let original = entry_advice[0].as_canonical_u64();
    entry_advice[0] = Felt::new_unchecked(original ^ 1);

    let store = witness.precomputed_pk.merkle_store_for_windows(&witness.u_1, &witness.u_2);
    let advice = AdviceInputs::default()
        .with_map([(Word::new(witness.pk_aug), witness.pk_aug_value.clone())])
        .with_stack(entry_advice)
        .with_merkle_store(store);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = advice;
    let result = test.execute_for_output();
    assert!(
        result.is_err(),
        "tampered merkle entry must trap; got Ok with stack {:?}",
        result.ok().map(|(o, _)| o.stack.get_element(0)),
    );
}

/// Mirror of `ecdsa_verify_prehash_native_invalid_v_returns_zero` for the precomp path.
/// The `_parse_sig`-derived validity flag must be ANDed into the running flag so a
/// malformed `v` byte rejects even when the ECDSA equation passes.
#[test]
fn ecdsa_verify_prehash_native_precomp_invalid_v_returns_zero() {
    // `pk_aug` is computed from (compressed_PK, root) only; the sig has no effect on the
    // witness. Build witness from the honest request and store tampered sig bytes to
    // memory, the same shape as the native-path counterpart.
    let request = generate_valid_signature();
    let mut sig_bytes = request.sig().to_bytes();
    sig_bytes[64] = 0x1b;
    let memory_stores =
        generate_memory_store_masm_raw(&request.pk().to_bytes(), request.digest(), &sig_bytes);
    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(result, Felt::ZERO, "invalid v must be rejected (returned {:?})", result);
}

/// Mirror of `ecdsa_verify_prehash_native_nonzero_sig_padding_returns_zero` for the
/// precomp path. The `_parse_sig` validity flag covers padding bytes too; without the
/// gating fix the malformed felt could still produce a `1` result.
#[test]
fn ecdsa_verify_prehash_native_precomp_nonzero_sig_padding_returns_zero() {
    let request = generate_valid_signature();
    let pk_words = bytes_to_packed_u32_elements(&request.pk().to_bytes());
    let digest_words = bytes_to_packed_u32_elements(request.digest());
    let mut sig_words = bytes_to_packed_u32_elements(&request.sig().to_bytes());
    // v = 0 (low byte) but byte 3 nonzero. sig[16] = 0x01000000 = 16,777,216 > 4, fails.
    sig_words[16] = Felt::new_unchecked(0x0100_0000);

    let memory_stores = [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ");

    let witness = precomp_witness(&request);
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ZERO,
        "nonzero sig padding must be rejected (returned {:?})",
        result
    );
}

/// Helper used by the invalid-v test: same shape as `generate_memory_store_masm` but
/// takes raw bytes (not an `EcdsaRequest`) so we can store a sig that wouldn't survive
/// `Signature::read_from_bytes`.
fn generate_memory_store_masm_raw(pk_bytes: &[u8], digest: &[u8], sig_bytes: &[u8]) -> String {
    let pk_words = bytes_to_packed_u32_elements(pk_bytes);
    let digest_words = bytes_to_packed_u32_elements(digest);
    let sig_words = bytes_to_packed_u32_elements(sig_bytes);

    [
        masm_store_felts(&pk_words, PK_ADDR),
        masm_store_felts(&digest_words, DIGEST_ADDR),
        masm_store_felts(&sig_words, SIG_ADDR),
    ]
    .join(" ")
}

/// Documents the table-root precondition of `verify_prehash_native_precomp`.
///
/// The proc checks that `pk_aug` opens to `(compressed_PK, merkle_root)`, but it does not
/// recompute the table root from `compressed_PK`. If `pk_aug` itself is chosen for
/// `(Q, root(Q'))`, the proc verifies against the table committed by `root(Q')`.
#[test]
fn ecdsa_verify_prehash_native_precomp_does_not_rebuild_comb_root() {
    use miden_core::crypto::hash::Poseidon2;
    use miden_core_lib::handlers::comb_k1::{AffinePoint, PrecomputedK1PubKey};
    use num::BigUint;

    // Honest signer Q'. The sig + digest must verify against Q', which is what the table
    // is built for, so the VM ECDSA equation check passes.
    let actual = generate_valid_signature();

    // Decoy public key Q (different seed). `compressed_PK` in pk_aug binds Q, but the
    // table root binds Q'.
    let decoy = {
        let mut rng = StdRng::seed_from_u64(123);
        let sk = SecretKey::with_rng(&mut rng);
        let pk = sk.public_key();
        let digest = [1u8; 32];
        let sig = sk.sign_prehash(digest);
        EcdsaRequest::new(pk, digest, sig)
    };

    // Build the witness "by hand": compressed_PK from decoy, root from actual.
    let g = AffinePoint {
        x: BigUint::from_slice(&SECP_GX_LIMBS),
        y: BigUint::from_slice(&SECP_GY_LIMBS),
        is_infinity: false,
    };
    let (q_actual_x, q_actual_y) = decompress_pk_to_xy(&actual.pk().to_bytes());
    let q_actual = AffinePoint {
        x: q_actual_x,
        y: q_actual_y,
        is_infinity: false,
    };
    let precomputed_pk = PrecomputedK1PubKey::new(&g, &q_actual);
    let merkle_root = precomputed_pk.merkle_root();

    let decoy_pk_felts = bytes_to_packed_u32_elements(&decoy.pk().to_bytes());
    let mut pk_aug_value: Vec<Felt> = Vec::with_capacity(16);
    pk_aug_value.extend_from_slice(&decoy_pk_felts);
    pk_aug_value.extend([Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    pk_aug_value.extend_from_slice(&merkle_root);
    let pk_aug: [Felt; 4] = *Poseidon2::hash_elements(&pk_aug_value);
    let (u_1, u_2) = derive_u1_u2(&actual);

    let witness = PrecompWitness {
        pk_aug,
        pk_aug_value,
        precomputed_pk,
        u_1,
        u_2,
    };

    // Memory layout: caller publishes decoy's compressed_PK and the actual sig/digest.
    let memory_stores = generate_memory_store_masm_raw(
        &decoy.pk().to_bytes(),
        actual.digest(),
        &actual.sig().to_bytes(),
    );
    let pk_aug_push = push_word_inline(&witness.pk_aug);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {memory_stores}

                push.{SIG_ADDR}.{DIGEST_ADDR}  {pk_aug_push}
                exec.ecdsa_k256_keccak::verify_prehash_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = precomp_advice_inputs(&witness);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ONE,
        "expected valid result because the proc does not rebuild the comb root (got {:?})",
        result
    );
}

// VERIFY_KECCAK_NATIVE_PRECOMP (wrapper that adds the Keccak-256 prologue)
// ================================================================================================

/// Generate a valid request whose digest is `Keccak-256(msg_word.into_bytes())`. The 32-byte
/// encoding matches the `word::store_word_u32s_le` layout the wrapper produces in memory.
fn generate_valid_keccak_signature(msg_word: &[Felt; 4]) -> EcdsaRequest {
    let mut rng = StdRng::seed_from_u64(42);
    let secret_key = SecretKey::with_rng(&mut rng);
    let pk = secret_key.public_key();

    let msg_bytes = msg_word.into_bytes();
    let digest = miden_core_lib::keccak256_native::reference::keccak256(&msg_bytes);
    let sig = secret_key.sign_prehash(digest);

    EcdsaRequest::new(pk, digest, sig)
}

/// Build the combined advice stack for the wrapper test: 17 SIG felts (consumed by the wrapper)
/// followed by the comb-window entries (consumed by the inner `verify_prehash_native_precomp`).
fn keccak_precomp_advice_inputs(
    witness: &PrecompWitness,
    sig_felts: &[Felt],
) -> miden_core::advice::AdviceInputs {
    use miden_core::advice::AdviceInputs;

    let (entry_advice, store) =
        witness.precomputed_pk.advice_for_windows(&witness.u_1, &witness.u_2);
    let mut combined = Vec::with_capacity(sig_felts.len() + entry_advice.len());
    combined.extend_from_slice(sig_felts);
    combined.extend(entry_advice);

    AdviceInputs::default()
        .with_map([(Word::new(witness.pk_aug), witness.pk_aug_value.clone())])
        .with_stack(combined)
        .with_merkle_store(store)
}

#[test]
fn ecdsa_verify_keccak_native_precomp_valid_signature_returns_one() {
    let msg_word = [
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(0x7edc_ba98_7654_3210),
        Felt::new_unchecked(0x0ead_beef_cafe_babe),
        Felt::new_unchecked(0x0000_1111_2222_3333),
    ];
    let request = generate_valid_keccak_signature(&msg_word);
    let witness = precomp_witness(&request);
    let sig_felts = bytes_to_packed_u32_elements(&request.sig().to_bytes());

    let pk_aug_push = push_word_inline(&witness.pk_aug);
    let msg_push = push_word_inline(&msg_word);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {pk_aug_push}
                {msg_push}
                exec.ecdsa_k256_keccak::verify_keccak_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = keccak_precomp_advice_inputs(&witness, &sig_felts);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ONE,
        "verify_keccak_native_precomp should accept the valid signature (got {:?})",
        result,
    );
}

#[test]
fn ecdsa_verify_keccak_native_precomp_wrong_message_returns_zero() {
    let signed_msg_word = [
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(0x7edc_ba98_7654_3210),
        Felt::new_unchecked(0x0ead_beef_cafe_babe),
        Felt::new_unchecked(0x0000_1111_2222_3333),
    ];
    let wrong_msg_word = [
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(0x7edc_ba98_7654_3210),
        Felt::new_unchecked(0x0ead_beef_cafe_babe),
        Felt::new_unchecked(0x0000_1111_2222_3334),
    ];

    let signed_request = generate_valid_keccak_signature(&signed_msg_word);
    let wrong_digest =
        miden_core_lib::keccak256_native::reference::keccak256(&wrong_msg_word.into_bytes());
    let wrong_request =
        EcdsaRequest::new(signed_request.pk().clone(), wrong_digest, signed_request.sig().clone());
    let witness = precomp_witness(&wrong_request);
    let sig_felts = bytes_to_packed_u32_elements(&signed_request.sig().to_bytes());

    let pk_aug_push = push_word_inline(&witness.pk_aug);
    let msg_push = push_word_inline(&wrong_msg_word);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {pk_aug_push}
                {msg_push}
                exec.ecdsa_k256_keccak::verify_keccak_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = keccak_precomp_advice_inputs(&witness, &sig_felts);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(
        result,
        Felt::ZERO,
        "signature for a different Keccak message must be rejected (got {:?})",
        result,
    );
}

// Deterministic KAT for `verify_keccak_native_precomp`. The private key is the EIP-155 example
// key (`0x46..46`). The message, compressed public key, digest, and signature are pinned as hex
// constants so changes in encoding, Keccak, or deterministic signing trip before the wrapper is
// called.
const KAT_PRIVKEY_HEX: &str = "4646464646464646464646464646464646464646464646464646464646464646";
const KAT_PK_COMPRESSED_HEX: &str =
    "024bc2a31265153f07e70e0bab08724e6b85e217f8cd628ceb62974247bb493382";
const KAT_MSG_BYTES_HEX: &str = "0123456789abcdef7edcba98765432100eadbeefcafebabe0000111122223333";
const KAT_DIGEST_HEX: &str = "63ea3777a99f01e8ad5b8941ba675e860028b01012667548d8fad93a6a0a9568";
const KAT_SIG_HEX: &str = "f19dd943619c26f8db980d29e724009921eec38065c099b6056ca0c79cf33ef7\
     260255db93eb1ab4ac06f008cb6b0cc21f56e07542dea7dcffb8ade3bf1f2c5c\
     01";

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

#[test]
fn ecdsa_verify_keccak_native_precomp_kat() {
    let privkey_bytes = hex_decode(KAT_PRIVKEY_HEX);
    let secret_key =
        SecretKey::read_from_bytes(&privkey_bytes).expect("KAT privkey must deserialize");

    let pk = secret_key.public_key();
    assert_eq!(
        hex_encode(&pk.to_bytes()),
        KAT_PK_COMPRESSED_HEX,
        "KAT public key mismatch -- update KAT_PK_COMPRESSED_HEX",
    );

    let msg_bytes: [u8; 32] =
        hex_decode(KAT_MSG_BYTES_HEX).try_into().expect("KAT message must be 32 bytes");
    let digest = miden_core_lib::keccak256_native::reference::keccak256(&msg_bytes);
    assert_eq!(
        hex_encode(&digest),
        KAT_DIGEST_HEX,
        "KAT digest mismatch -- update KAT_DIGEST_HEX",
    );

    let sig = secret_key.sign_prehash(digest);
    assert_eq!(
        hex_encode(&sig.to_bytes()),
        KAT_SIG_HEX,
        "KAT signature mismatch -- update KAT_SIG_HEX",
    );

    let msg_word = bytes_to_msg_word(&msg_bytes);
    let request = EcdsaRequest::new(pk, digest, sig);
    let witness = precomp_witness(&request);
    let sig_felts = bytes_to_packed_u32_elements(&request.sig().to_bytes());

    let pk_aug_push = push_word_inline(&witness.pk_aug);
    let msg_push = push_word_inline(&msg_word);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                {pk_aug_push}
                {msg_push}
                exec.ecdsa_k256_keccak::verify_keccak_native_precomp
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = keccak_precomp_advice_inputs(&witness, &sig_felts);
    let (output, _) = test.execute_for_output().unwrap();
    let result = output.stack.get_element(0).unwrap();
    assert_eq!(result, Felt::ONE, "KAT signature must verify (got {:?})", result);
}

/// Inverse of `[Felt; 4]::into_bytes()`: read 4 felts back from a 32-byte little-endian encoding.
fn bytes_to_msg_word(bytes: &[u8; 32]) -> [Felt; 4] {
    let mut word = [Felt::ZERO; 4];
    for (i, felt) in word.iter_mut().enumerate() {
        let v = u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        *felt = Felt::new_unchecked(v);
    }
    word
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[test]
#[ignore = "benchmark; run with --ignored to print cycle count"]
fn ecdsa_verify_keccak_native_precomp_cycles() {
    use miden_processor::ContextId;

    let msg_word = [
        Felt::new_unchecked(0x0123_4567_89ab_cdef),
        Felt::new_unchecked(0x7edc_ba98_7654_3210),
        Felt::new_unchecked(0x0ead_beef_cafe_babe),
        Felt::new_unchecked(0x0000_1111_2222_3333),
    ];
    let request = generate_valid_keccak_signature(&msg_word);
    let witness = precomp_witness(&request);
    let sig_felts = bytes_to_packed_u32_elements(&request.sig().to_bytes());

    let pk_aug_push = push_word_inline(&witness.pk_aug);
    let msg_push = push_word_inline(&msg_word);

    let source = format!(
        "
            use miden::core::crypto::dsa::ecdsa_k256_keccak
            use miden::core::sys

            begin
                clk
                {pk_aug_push}
                {msg_push}
                exec.ecdsa_k256_keccak::verify_keccak_native_precomp
                # => [result, t0, ...]
                clk                                          # [t1, result, t0, ...]
                movup.2 sub                                  # [t1 - t0, result, ...]
                push.5000 mem_store                          # mem[5000] = cycle delta
                push.5001 mem_store                          # mem[5001] = result
                exec.sys::truncate_stack
            end
        ",
    );

    let mut test = build_debug_test!(&source, &[]);
    test.advice_inputs = keccak_precomp_advice_inputs(&witness, &sig_felts);
    let (output, _) = test.execute_for_output().unwrap();
    let cycles = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5000))
        .unwrap()
        .as_canonical_u64();
    let result = output
        .memory
        .read_element(ContextId::root(), Felt::from_u32(5001))
        .unwrap()
        .as_canonical_u64();
    assert_eq!(result, 1, "verify_keccak_native_precomp should accept the valid signature");
    eprintln!("verify_keccak_native_precomp cycles (valid sig): {cycles}");
}
