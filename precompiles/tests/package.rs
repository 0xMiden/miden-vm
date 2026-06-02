//! Focused smoke tests for the `miden-precompiles` package and its `PrecompilesLibrary` wrapper.

use miden_assembly::{Assembler, Linkage};
use miden_core::{Felt, serde::Deserializable, utils::bytes_to_packed_u32_elements};
use miden_crypto::hash::{keccak::Keccak256, sha2::Sha512};
use miden_mast_package::Package;
use miden_precompiles::PrecompilesLibrary;
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
/// registry installed (via `with_library`) and returns the expected digest.
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
