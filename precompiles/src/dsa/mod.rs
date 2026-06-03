//! Digital-signature deferred precompiles.
//!
//! Each signature is a self-contained [`Precompile`] with a single `verify` predicate over a
//! fixed 5-chunk (40-felt) data buffer: the caller packs the verification calldata
//! (`pk || digest || sig`) into the buffer, registers it as the precompile's `verify` node, and
//! folds the node digest into the deferred root. Evaluation runs the byte-level signature check
//! and the predicate succeeds by evaluating to [`Node::TRUE`].
//!
//! The matching MASM `verify_prehash` wrappers live under
//! `::miden::precompiles::crypto::dsa::{ecdsa_k256_keccak,eddsa_ed25519}`.
//!
//! ## Calldata binding
//!
//! The `verify` predicate attests only that `sig` is valid for `pk` over `digest`; it does not
//! constrain *which* public key or message those are. `verify_prehash` derives the node digest in
//! circuit from the buffer in VM memory, so the deferred root commits to the exact
//! `pk || digest || sig` bytes the program placed there — but a caller that needs to tie `pk` to a
//! known signer, or `digest` to a specific message, must establish those bindings itself (commit
//! `pk` and hash the message in circuit, as the higher-level `verify` wrappers do). For EdDSA this
//! is essential: the precompile uses `verify_with_unchecked_k`, which checks the group equation
//! against the supplied `k_digest = SHA-512(R || A || message)` without recomputing it, so an
//! unbound `k_digest` proves nothing about any message.
//!
//! [`Precompile`]: miden_core::deferred::Precompile
//! [`Node::TRUE`]: miden_core::deferred::Node::TRUE

pub mod ecdsa_k256_keccak;
pub mod eddsa_ed25519;
