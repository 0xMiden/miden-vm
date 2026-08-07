//! Conjectured soundness estimation for the Miden lifted-STARK protocol.
//!
//! A proof's security is not a property of the parameter preset alone: the lookup and out-of-domain
//! rounds degrade with trace height, so the same parameters grade differently for different
//! executions. This crate computes that grade from the protocol parameters, the instance shape, and
//! the AIR shape — all of which the verifier already has, and all of which the Fiat-Shamir
//! transcript already binds.
//!
//! Entry point: [`conjectured::security_report`].
//!
//! # Fixed point
//!
//! Every quantity is `−log2(error)` in 16-fractional-bit fixed point. The MASM recursive verifier
//! grades proofs with these same formulas and has no floating-point arithmetic, so the
//! representation is a requirement rather than an optimization. Rounding is always toward
//! understating security.
//!
//! # Scope
//!
//! Conjectured bounds only. Proven bounds for this parameter class are far lower, and
//! <https://eprint.iacr.org/2025/2010> recommends publishing them; anything derived from this crate
//! must be labeled conjectured wherever it is published.
//!
//! # References
//! - ethSTARK ([2021/582](https://eprint.iacr.org/2021/582))
//! - Proximity gaps for Reed-Solomon codes ([2020/654](https://eprint.iacr.org/2020/654))
//! - LogUp ([2022/1530](https://eprint.iacr.org/2022/1530))
//! - On the security of STARKs with FRI ([2024/1553](https://eprint.iacr.org/2024/1553))
//! - Distances of random words ([2025/2010](https://eprint.iacr.org/2025/2010))

#![no_std]

pub mod conjectured;
pub mod fixed;
pub mod report;
pub mod shape;

pub use conjectured::security_report;
pub use report::{SecurityReport, SecurityTerm};
pub use shape::{AirShape, InstanceShape, LookupShape, ProtocolParams};
