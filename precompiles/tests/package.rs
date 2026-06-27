//! Focused smoke tests for the `miden-precompiles` package and its `PrecompilesLibrary` wrapper.

use miden_assembly::{Assembler, Linkage};
use miden_core::serde::Deserializable;
use miden_mast_package::Package;
use miden_precompiles::PrecompilesLibrary;
use miden_processor::DefaultHost;

/// The embedded `.masp` is a valid, deserializable package.
#[test]
fn package_deserializes() {
    assert!(!PrecompilesLibrary::SERIALIZED.is_empty());
    Package::read_from_bytes(PrecompilesLibrary::SERIALIZED)
        .expect("embedded miden-precompiles.masp should deserialize");
}

/// A representative program can be dynamically linked and assembled against the package.
#[test]
fn links_against_program() {
    let library = PrecompilesLibrary::default();
    let source = "begin exec.::miden::precompiles::math::u256::push_zero_digest dropw end";
    Assembler::default()
        .with_package(library.package(), Linkage::Dynamic)
        .expect("failed to link miden-precompiles")
        .assemble_program("precompiles_link", source)
        .expect("failed to assemble a program against miden-precompiles");
}

/// A host can load the library via `DefaultHost::with_library`.
#[test]
fn host_loads_library() {
    DefaultHost::default()
        .with_library(&PrecompilesLibrary::default())
        .expect("failed to load PrecompilesLibrary into the host");
}
