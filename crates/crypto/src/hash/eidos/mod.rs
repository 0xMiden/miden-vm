//! The Eidos hash construction and its underlying compression function.
//!
//! [`Eidos`](crate::hash::eidos::Eidos) exposes a framed hash construction and a raw compression
//! operation. Complete-hash methods apply domain and length binding, framing, and padding.
//! [`Eidos::compress`](crate::hash::eidos::Eidos::compress) compresses one complete block under a
//! caller-supplied chaining value and adds no framing.
//!
//! Eidos compression produces four canonical Goldilocks field elements. These outputs form the
//! next chaining value and give an approximately 128-bit generic collision-resistance bound when
//! Eidos is modeled as a random oracle.

mod challenger;
mod compression;
mod construction;
pub mod domain;
pub mod domains;
pub mod encoding;
mod finalizer;
mod frame;
mod framing;
mod lmcs;
mod primitive;

#[cfg(test)]
mod tests;

pub use challenger::{EidosChallenger, MidenEidosChallenger};
pub use construction::Eidos;
pub use domain::{
    ByteString, Custom, DELEGATED_VERSIONING, DomainDescriptor, DomainEncoding, DomainNamespace,
    DomainTag, DomainVersion, EidosDomain, EidosDomainRegistry, EidosEncoding, FeltSequence,
    NAMESPACE_REGISTRY, Transcript, namespace, render_masm_constants,
};
#[doc(hidden)]
pub use finalizer::FINALIZER_MATRIX;
pub use frame::EidosFrame;
pub use lmcs::{EidosLmcs, config as lmcs_config};

/// Number of Felts in one Eidos message block.
pub const BLOCK_LEN: usize = 8;

/// Number of Felts in an Eidos digest.
pub const DIGEST_WIDTH: usize = 4;

/// Number of independent Eidos inputs in one logical packed batch.
///
/// The logical width is fixed across targets. Backends with narrower SIMD registers process the
/// batch in independent sub-batches. Callers should fill tails by repeating a real lane and
/// discard the duplicate outputs.
pub const PACKED_LANES: usize = primitive::PACKED_LANES;

/// One packed base-field element, with one independent value per logical packed lane.
pub type PackedFelt = [crate::Felt; PACKED_LANES];

/// Lane-oriented chaining value retained between packed compression calls.
///
/// Packing into field elements is reserved for API boundaries.
type PackedU32ChainingValue = [[u32; PACKED_LANES]; 8];

/// One packed Eidos chaining value, with one independent CV per logical packed lane.
///
/// Raw compression accepts arbitrary canonical field elements here.
pub type PackedChainingValue = [PackedFelt; DIGEST_WIDTH];

/// One packed Eidos digest, with one independent digest per logical packed lane.
pub type PackedDigest = PackedChainingValue;

/// One packed Eidos message block, with one independent block per logical packed lane.
pub type PackedBlock = [PackedFelt; BLOCK_LEN];
