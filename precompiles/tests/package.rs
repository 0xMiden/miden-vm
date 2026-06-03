//! Focused smoke tests for the `miden-precompiles` package and its `PrecompilesLibrary` wrapper.

use miden_assembly::{Assembler, Linkage};
use miden_core::{
    Felt, Word,
    serde::{Deserializable, Serializable},
    utils::bytes_to_packed_u32_elements,
};
use miden_crypto::{
    dsa::{
        ecdsa_k256_keccak::SigningKey as EcdsaSigningKey,
        eddsa_25519_sha512::SigningKey as EddsaSigningKey,
    },
    hash::{keccak::Keccak256, sha2::Sha512},
};
use miden_mast_package::Package;
use miden_precompiles::{PrecompilesLibrary, registry};
use miden_processor::{
    DefaultHost, ExecutionOptions, ExecutionOutput, FastProcessor, StackInputs,
    advice::AdviceInputs,
};

/// Memory address the e2e tests pass as the digest output pointer.
const OUT_PTR: u32 = 0;

/// The embedded `.masp` is a valid, deserializable package.
#[test]
fn package_deserializes() {
    assert!(!PrecompilesLibrary::SERIALIZED.is_empty());
    Package::read_from_bytes(PrecompilesLibrary::SERIALIZED)
        .expect("embedded miden-precompiles.masp should deserialize");
}

/// The expected procedures are exported under the `miden::precompiles` namespace.
#[test]
fn exports_expected_paths() {
    let package = PrecompilesLibrary::default().package();
    assert!(
        package.get_procedure_root_by_path("::miden::precompiles::smoke").is_some(),
        "smoke procedure should be exported",
    );
    assert!(
        package
            .get_procedure_root_by_path("::miden::precompiles::sys::register_expr")
            .is_some(),
        "duplicated deferred sys helper should be exported",
    );
}

/// The keccak256 wrappers are exported under `miden::precompiles::crypto::hashes::keccak256`.
#[test]
fn exports_keccak_paths() {
    let package = PrecompilesLibrary::default().package();
    for path in [
        "::miden::precompiles::crypto::hashes::keccak256::hash",
        "::miden::precompiles::crypto::hashes::keccak256::hash_bytes",
        "::miden::precompiles::crypto::hashes::keccak256::merge",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "keccak256 procedure should be exported: {path}",
        );
    }
}

/// The sha512 wrappers are exported under `miden::precompiles::crypto::hashes::sha512`.
#[test]
fn exports_sha512_paths() {
    let package = PrecompilesLibrary::default().package();
    for path in [
        "::miden::precompiles::crypto::hashes::sha512::hash",
        "::miden::precompiles::crypto::hashes::sha512::hash_bytes",
        "::miden::precompiles::crypto::hashes::sha512::merge",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "sha512 procedure should be exported: {path}",
        );
    }
}

/// The signature `verify_prehash` wrappers are exported under
/// `miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}`.
#[test]
fn exports_dsa_paths() {
    let package = PrecompilesLibrary::default().package();
    for path in [
        "::miden::precompiles::crypto::dsa::ecdsa_k256_keccak::verify_prehash",
        "::miden::precompiles::crypto::dsa::eddsa_ed25519::verify_prehash",
    ] {
        assert!(
            package.get_procedure_root_by_path(path).is_some(),
            "signature procedure should be exported: {path}",
        );
    }
}

/// A program can be dynamically linked and assembled against the package.
#[test]
fn links_against_program() {
    let library = PrecompilesLibrary::default();
    let source = "begin exec.::miden::precompiles::smoke end";
    Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program("smoke", source)
        .expect("failed to assemble a program against miden-precompiles");
}

/// A host can load the library via `DefaultHost::with_library`.
#[test]
fn host_loads_library() {
    DefaultHost::default()
        .with_library(&PrecompilesLibrary::default())
        .expect("failed to load PrecompilesLibrary into the host");
}

/// End-to-end: a program calling `keccak256::hash` runs on a real processor with the precompile
/// registry installed on the processor and returns the expected digest.
#[test]
fn keccak_hash_executes_end_to_end() {
    let library = PrecompilesLibrary::default();

    // 256-bit input, u32-packed-LE into 8 felts. The `hash` contract is `[out_ptr, INPUT_U32[8]]`,
    // so seed the stack with `out_ptr` on top followed by the input felts.
    let input: Vec<u8> = (0u8..32).collect();
    let mut stack = vec![Felt::from_u32(OUT_PTR)];
    stack.extend(bytes_to_packed_u32_elements(&input));

    let source = "begin exec.::miden::precompiles::crypto::hashes::keccak256::hash end";
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program("keccak", source)
        .expect("failed to assemble keccak program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&library)
        .expect("failed to load PrecompilesLibrary into the host");

    let output = FastProcessor::new_with_options(
        StackInputs::new(&stack).expect("stack inputs"),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(registry())
    .expect("failed to register miden-precompiles")
    .execute_sync(&program, &mut host)
    .expect("keccak execution must succeed");

    let expected = keccak_digest_felts(&input);
    assert_eq!(
        read_digest(&output, OUT_PTR, 8),
        expected.to_vec(),
        "digest at out_ptr must match Keccak256(input)",
    );
}

/// Compute Keccak256 of `input`, unpacked into 8 u32-packed-LE felts — the layout the MASM wrapper
/// writes to `out_ptr`.
fn keccak_digest_felts(input: &[u8]) -> [Felt; 8] {
    let hash: [u8; 32] = Keccak256::hash(input).into();
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&hash[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

/// End-to-end: `sha512::hash` runs on a real processor and writes the 512-bit digest (16 felts) to
/// the caller-provided `out_ptr`.
#[test]
fn sha512_hash_executes_end_to_end() {
    let library = PrecompilesLibrary::default();

    // 256-bit input; `hash` contract is `[out_ptr, INPUT_U32[8]]`.
    let input: Vec<u8> = (0u8..32).collect();
    let mut stack = vec![Felt::from_u32(OUT_PTR)];
    stack.extend(bytes_to_packed_u32_elements(&input));

    let source = "begin exec.::miden::precompiles::crypto::hashes::sha512::hash end";
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program("sha512", source)
        .expect("failed to assemble sha512 program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&library)
        .expect("failed to load PrecompilesLibrary into the host");

    let output = FastProcessor::new_with_options(
        StackInputs::new(&stack).expect("stack inputs"),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(registry())
    .expect("failed to register miden-precompiles")
    .execute_sync(&program, &mut host)
    .expect("sha512 execution must succeed");

    let expected = sha512_digest_felts(&input);
    assert_eq!(
        read_digest(&output, OUT_PTR, 16),
        expected.to_vec(),
        "digest at out_ptr must match Sha512(input)",
    );
}

/// Compute SHA-512 of `input`, unpacked into 16 u32-packed-LE felts — the layout the MASM wrapper
/// writes to `out_ptr`.
fn sha512_digest_felts(input: &[u8]) -> [Felt; 16] {
    let hash: [u8; 64] = Sha512::hash(input).into();
    core::array::from_fn(|i| {
        let mut limb = [0u8; 4];
        limb.copy_from_slice(&hash[i * 4..(i + 1) * 4]);
        Felt::from_u32(u32::from_le_bytes(limb))
    })
}

/// Reads `n_felts` consecutive memory elements at `ptr` (context 0) — the digest a wrapper wrote.
fn read_digest(output: &ExecutionOutput, ptr: u32, n_felts: u32) -> Vec<Felt> {
    let ctx = 0u32.into();
    (0..n_felts)
        .map(|i| {
            output
                .memory
                .read_element(ctx, Felt::from_u32(ptr + i))
                .expect("digest element")
        })
        .collect()
}

// SIGNATURE PRECOMPILES
// ================================================================================================

/// Word-aligned address the signature e2e tests pack the 40-felt verify buffer into.
const BUF_ADDR: u32 = 128;

/// End-to-end: a valid ECDSA signature registered through `verify_prehash` executes successfully
/// (the predicate evaluates to TRUE during `register_data`). Surfacing the logged statement through
/// the deferred root belongs to the proof-wire layer.
#[test]
fn ecdsa_verify_prehash_executes_end_to_end() {
    let sk = EcdsaSigningKey::new();
    let digest = [7u8; 32];
    let buf = ecdsa_buffer_felts(
        &sk.public_key().to_bytes(),
        &digest,
        &sk.sign_prehash(digest).to_bytes(),
    );

    run_verify_prehash("ecdsa_k256_keccak", &buf)
        .expect("valid ECDSA signature must verify end-to-end");
}

/// End-to-end: a tampered ECDSA signature traps during `sys::register_data`'s eager evaluation.
#[test]
fn ecdsa_verify_prehash_traps_on_invalid_signature() {
    let sk = EcdsaSigningKey::new();
    let digest = [7u8; 32];
    let mut sig = sk.sign_prehash(digest).to_bytes();
    sig[0] ^= 0xff;
    let buf = ecdsa_buffer_felts(&sk.public_key().to_bytes(), &digest, &sig);

    assert!(
        run_verify_prehash("ecdsa_k256_keccak", &buf).is_err(),
        "invalid ECDSA signature must trap execution",
    );
}

/// End-to-end: a valid Ed25519 signature registered through `verify_prehash` executes successfully
/// (the predicate evaluates to TRUE during `register_data`).
#[test]
fn eddsa_verify_prehash_executes_end_to_end() {
    let sk = EddsaSigningKey::new();
    let pk = sk.public_key();
    let message =
        Word::new([Felt::from_u32(11), Felt::from_u32(22), Felt::from_u32(33), Felt::from_u32(44)]);
    let sig = sk.sign(message);
    let k_digest = pk.compute_challenge_k(message, &sig);
    let buf = eddsa_buffer_felts(&pk.to_bytes(), &k_digest, &sig.to_bytes());

    run_verify_prehash("eddsa_ed25519", &buf)
        .expect("valid Ed25519 signature must verify end-to-end");
}

/// End-to-end: a tampered Ed25519 signature traps during `sys::register_data`'s eager evaluation.
#[test]
fn eddsa_verify_prehash_traps_on_invalid_signature() {
    let sk = EddsaSigningKey::new();
    let pk = sk.public_key();
    let message =
        Word::new([Felt::from_u32(11), Felt::from_u32(22), Felt::from_u32(33), Felt::from_u32(44)]);
    let sig = sk.sign(message);
    let k_digest = pk.compute_challenge_k(message, &sig);
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[0] ^= 0xff;
    let buf = eddsa_buffer_felts(&pk.to_bytes(), &k_digest, &sig_bytes);

    assert!(
        run_verify_prehash("eddsa_ed25519", &buf).is_err(),
        "invalid Ed25519 signature must trap execution",
    );
}

/// Packs a `(pk, digest, sig)` ECDSA triple into the precompile's tightly-packed 40-felt buffer.
fn ecdsa_buffer_felts(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> Vec<Felt> {
    assert_eq!(pk.len(), 33);
    assert_eq!(sig.len(), 65);
    let mut buf = vec![0u8; 160];
    buf[0..33].copy_from_slice(pk);
    buf[33..65].copy_from_slice(digest);
    buf[65..130].copy_from_slice(sig);
    bytes_to_packed_u32_elements(&buf)
}

/// Packs a `(pk, k_digest, sig)` Ed25519 triple into the precompile's 40-felt buffer (no padding).
fn eddsa_buffer_felts(pk: &[u8], k_digest: &[u8; 64], sig: &[u8]) -> Vec<Felt> {
    assert_eq!(pk.len(), 32);
    assert_eq!(sig.len(), 64);
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(pk);
    buf.extend_from_slice(k_digest);
    buf.extend_from_slice(sig);
    bytes_to_packed_u32_elements(&buf)
}

/// Generates MASM that stores `felts` sequentially in memory starting at `base_addr`.
fn masm_store_felts(felts: &[Felt], base_addr: u32) -> String {
    felts
        .iter()
        .enumerate()
        .map(|(i, felt)| {
            format!("push.{} push.{} mem_store", felt.as_canonical_u64(), base_addr + i as u32)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Assembles and executes a program that stores `buf_felts` at [`BUF_ADDR`] and calls
/// `crypto::dsa::{module}::verify_prehash`, with the crate registry installed on the processor.
fn run_verify_prehash(
    module: &str,
    buf_felts: &[Felt],
) -> Result<ExecutionOutput, miden_processor::ExecutionError> {
    let library = PrecompilesLibrary::default();
    let stores = masm_store_felts(buf_felts, BUF_ADDR);
    let source = format!(
        r#"
            use miden::precompiles::crypto::dsa::{module}
            begin
                {stores}
                push.{BUF_ADDR}
                exec.{module}::verify_prehash
            end
        "#,
    );
    let program = Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program(module, &source)
        .expect("failed to assemble signature program")
        .unwrap_program();

    let mut host = DefaultHost::default()
        .with_library(&library)
        .expect("failed to load PrecompilesLibrary into the host");

    FastProcessor::new_with_options(
        StackInputs::default(),
        AdviceInputs::default(),
        ExecutionOptions::default(),
    )
    .expect("processor construction")
    .with_deferred_precompiles(registry())
    .expect("failed to register miden-precompiles")
    .execute_sync(&program, &mut host)
}
