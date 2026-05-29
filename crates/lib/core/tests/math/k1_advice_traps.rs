//! Adversarial-advice regression tests for the secp256k1-related procs that pull witness
//! values from the host advice stack: `f_k1::inv` / `f_k1::inv_unsafe`,
//! `k1_scalar::inv` / `k1_scalar::inv_unsafe`, `k1_scalar::verify_glv_split`,
//! `k1_point::decompress`, and `k1_point::decompress_no_trap`.
//!
//! Convention: invalid caller-controlled inputs to a no-trap proc set its returned flag to 0;
//! malformed advice is treated as an inconsistent witness and traps. The canonical `inv`
//! wrappers also trap on non-canonical inverse hints; `inv_unsafe` only promises u32-valid limbs.

use alloc::vec::Vec;

use miden_core::Felt;
use miden_core_lib::{
    CoreLibrary,
    handlers::{
        glv_split_k1::{GLV_SPLIT_K1_EVENT_NAME, handle_glv_split_k1},
        k1_point_decompress::{K1_POINT_DECOMPRESS_EVENT_NAME, handle_k1_point_decompress},
        secp256k1_constants::{SECP256K1_BASE_PRIME_U32, SECP256K1_SCALAR_PRIME_U32},
        u256_inv_k1::{
            U256_INV_K1_BASE_EVENT_NAME, U256_INV_K1_SCALAR_EVENT_NAME, handle_u256_inv_k1_base,
            handle_u256_inv_k1_scalar,
        },
    },
};
use miden_processor::{
    ProcessorState,
    advice::AdviceMutation,
    event::{EventError, EventHandler, EventName},
};
use miden_utils_testing::Test;

// ----- handler scaffolding ------------------------------------------------------------------

/// Wraps a production handler and applies one of a few tamper modes to the felts the
/// handler pushed onto the advice stack before returning them.
#[derive(Clone, Copy)]
enum Tamper {
    /// Overwrite advice[index] with `value`. Used to inject non-u32 felts (e.g. 1u64 << 32).
    Set { index: usize, value: u64 },
    /// Add `addend` to the first 8 advice felts with carry propagation. Used to make hinted
    /// inverses non-canonical by returning `inv + p` (or `inv + n`).
    AddU256 { addend: [u32; 8] },
}

struct TamperHandler<F>
where
    F: Fn(&ProcessorState) -> Result<Vec<AdviceMutation>, EventError> + Send + Sync + 'static,
{
    inner: F,
    tamper: Tamper,
}

impl<F> EventHandler for TamperHandler<F>
where
    F: Fn(&ProcessorState) -> Result<Vec<AdviceMutation>, EventError> + Send + Sync + 'static,
{
    fn on_event(&self, process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
        let mut muts = (self.inner)(process)?;
        for m in &mut muts {
            if let AdviceMutation::ExtendStack { values } = m {
                match self.tamper {
                    Tamper::Set { index, value } => {
                        values[index] = Felt::new(value).expect("tamper value must fit in Felt");
                    },
                    Tamper::AddU256 { addend } => {
                        let mut carry: u64 = 0;
                        for (i, &limb) in addend.iter().enumerate() {
                            let v = values[i].as_canonical_u64() as u32;
                            let sum = v as u64 + limb as u64 + carry;
                            values[i] = Felt::from_u32(sum as u32);
                            carry = sum >> 32;
                        }
                    },
                }
            }
        }
        Ok(muts)
    }
}

/// Build a test from a MASM source string with one production handler replaced by a tampering
/// wrapper. All other core-lib handlers are forwarded unchanged.
fn build_tampered_test<F>(source: &str, event: EventName, inner: F, tamper: Tamper) -> Test
where
    F: Fn(&ProcessorState) -> Result<Vec<AdviceMutation>, EventError> + Send + Sync + 'static,
{
    let core_lib = CoreLibrary::default();
    let mut handlers = core_lib.handlers();
    handlers.retain(|(name, _)| name != &event);

    miden_utils_testing::build_debug_test!(source, &[])
        .with_library(core_lib.package())
        .with_event_handlers(handlers)
        .with_event_handler(event, TamperHandler { inner, tamper })
}

// ----- f_k1::inv / inv_unsafe ---------------------------------------------------------------

const INV_BASE_SOURCE: &str = "
    use miden::core::math::f_k1
    use miden::core::sys

    begin
        # inv(1) = 1; small input keeps the AddU256 tamper safely inside 8 limbs.
        push.0.0.0.0  push.0.0.0.1
        exec.f_k1::inv
        exec.sys::truncate_stack
    end
";

const INV_UNSAFE_BASE_SOURCE: &str = "
    use miden::core::math::f_k1
    use miden::core::sys

    begin
        push.0.0.0.0  push.0.0.0.1
        exec.f_k1::inv_unsafe
        exec.sys::truncate_stack
    end
";

#[test]
fn f_k1_inv_unsafe_traps_on_non_u32_advice() {
    let test = build_tampered_test(
        INV_UNSAFE_BASE_SOURCE,
        U256_INV_K1_BASE_EVENT_NAME,
        handle_u256_inv_k1_base,
        Tamper::Set { index: 0, value: 1u64 << 32 },
    );
    test.execute().expect_err("non-u32 inv advice must trap at u32assertw");
}

#[test]
fn f_k1_inv_unsafe_accepts_non_canonical_advice() {
    let test = build_tampered_test(
        INV_UNSAFE_BASE_SOURCE,
        U256_INV_K1_BASE_EVENT_NAME,
        handle_u256_inv_k1_base,
        Tamper::AddU256 { addend: SECP256K1_BASE_PRIME_U32 },
    );
    test.execute().expect("u32-valid inv + p advice is allowed by inv_unsafe");
}

#[test]
fn f_k1_inv_traps_on_non_canonical_advice() {
    // honest inv(1) = 1, so the tampered advice is p + 1: u32-valid per limb, satisfies the
    // modmul check, but fails the canonical `inv < p` assert at the end of `f_k1::inv`.
    let test = build_tampered_test(
        INV_BASE_SOURCE,
        U256_INV_K1_BASE_EVENT_NAME,
        handle_u256_inv_k1_base,
        Tamper::AddU256 { addend: SECP256K1_BASE_PRIME_U32 },
    );
    test.execute()
        .expect_err("non-canonical inv (inv + p) must trap at the canonical bound check");
}

// ----- k1_scalar::inv / inv_unsafe ----------------------------------------------------------

const INV_SCALAR_SOURCE: &str = "
    use miden::core::math::k1_scalar
    use miden::core::sys

    begin
        push.0.0.0.0  push.0.0.0.1
        exec.k1_scalar::inv
        exec.sys::truncate_stack
    end
";

const INV_UNSAFE_SCALAR_SOURCE: &str = "
    use miden::core::math::k1_scalar
    use miden::core::sys

    begin
        push.0.0.0.0  push.0.0.0.1
        exec.k1_scalar::inv_unsafe
        exec.sys::truncate_stack
    end
";

#[test]
fn k1_scalar_inv_unsafe_traps_on_non_u32_advice() {
    let test = build_tampered_test(
        INV_UNSAFE_SCALAR_SOURCE,
        U256_INV_K1_SCALAR_EVENT_NAME,
        handle_u256_inv_k1_scalar,
        Tamper::Set { index: 0, value: 1u64 << 32 },
    );
    test.execute().expect_err("non-u32 inv advice must trap at u32assertw");
}

#[test]
fn k1_scalar_inv_unsafe_accepts_non_canonical_advice() {
    let test = build_tampered_test(
        INV_UNSAFE_SCALAR_SOURCE,
        U256_INV_K1_SCALAR_EVENT_NAME,
        handle_u256_inv_k1_scalar,
        Tamper::AddU256 { addend: SECP256K1_SCALAR_PRIME_U32 },
    );
    test.execute().expect("u32-valid inv + n advice is allowed by inv_unsafe");
}

#[test]
fn k1_scalar_inv_traps_on_non_canonical_advice() {
    let test = build_tampered_test(
        INV_SCALAR_SOURCE,
        U256_INV_K1_SCALAR_EVENT_NAME,
        handle_u256_inv_k1_scalar,
        Tamper::AddU256 { addend: SECP256K1_SCALAR_PRIME_U32 },
    );
    test.execute()
        .expect_err("non-canonical scalar inv (inv + n) must trap at the canonical bound check");
}

// ----- k1_scalar::verify_glv_split ----------------------------------------------------------

/// Drives `verify_glv_split` on a small u256 scalar. The production handler computes the
/// honest split; the TamperHandler corrupts one advice felt before it's returned.
const GLV_SPLIT_SOURCE: &str = "
    use miden::core::math::k1_scalar
    use miden::core::sys

    @locals(32)
    proc test_glv
        # Save k = 12345 (small u256) to mem[0..8].
        push.0.0.0.0  loc_storew_le.4  dropw
        push.0.0.0.12345  loc_storew_le.0  dropw

        # Stack convention: [out_addr, k_addr, ...].
        locaddr.16  locaddr.0
        exec.k1_scalar::verify_glv_split
    end

    begin
        exec.test_glv
        exec.sys::truncate_stack
    end
";

#[test]
fn k1_scalar_verify_glv_split_traps_on_non_u32_advice() {
    // Index 0 = low limb of |k_a|. Setting it to 2^32 trips the boundary u32assertw.
    let test = build_tampered_test(
        GLV_SPLIT_SOURCE,
        GLV_SPLIT_K1_EVENT_NAME,
        handle_glv_split_k1,
        Tamper::Set { index: 0, value: 1u64 << 32 },
    );
    test.execute().expect_err("non-u32 GLV split advice must trap at u32assertw");
}

// ----- k1_point::decompress / decompress_no_trap --------------------------------------------

/// Compressed encoding of the secp256k1 generator G: (X = G.x, parity = G.y & 1).
/// G.y is odd (parity = 1).
const G_X_LIMBS: [u32; 8] = [
    0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e,
];

/// Builds a MASM source that drops valid `(X, parity)` for the generator at the given locals
/// and invokes one of the decompress procs.
fn decompress_source(proc: &str) -> String {
    let [x0, x1, x2, x3, x4, x5, x6, x7] = G_X_LIMBS;
    format!(
        "
        use miden::core::math::k1_point
        use miden::core::sys

        @locals(32)
        proc test_decompress
            # Save X to mem[0..8] (word-aligned).
            push.{x3}.{x2}.{x1}.{x0}     loc_storew_le.0  dropw
            push.{x7}.{x6}.{x5}.{x4}     loc_storew_le.4  dropw
            # Parity (G.y is odd) at mem[8].
            push.1                       loc_store.8

            # Stack: [out_addr, x_addr, parity_addr, ...]
            locaddr.8  locaddr.0  locaddr.12
            exec.k1_point::{proc}
        end

        begin
            exec.test_decompress
            exec.sys::truncate_stack
        end"
    )
}

#[test]
fn k1_point_decompress_traps_on_non_u32_y_advice() {
    let source = decompress_source("decompress");
    let test = build_tampered_test(
        &source,
        K1_POINT_DECOMPRESS_EVENT_NAME,
        handle_k1_point_decompress,
        Tamper::Set { index: 0, value: 1u64 << 32 },
    );
    test.execute()
        .expect_err("non-u32 Y advice must trap at u32assertw in decompress");
}

#[test]
fn k1_point_decompress_no_trap_traps_on_non_u32_y_advice() {
    // The no-trap guarantee covers caller-controlled (X, parity) only; malformed advice is
    // an inconsistent witness and still traps at u32assertw.
    let source = decompress_source("decompress_no_trap");
    let test = build_tampered_test(
        &source,
        K1_POINT_DECOMPRESS_EVENT_NAME,
        handle_k1_point_decompress,
        Tamper::Set { index: 0, value: 1u64 << 32 },
    );
    test.execute().expect_err(
        "non-u32 Y advice must trap at u32assertw in decompress_no_trap; the no-trap \
         guarantee covers caller-controlled (X, parity), not advice",
    );
}
