//! Lookup interactions grouped by operation across Core and Chiplets columns.
//!
//! [`super::main_air`] and [`super::chiplet_air`] fix column order. Each column emitter opens
//! its own group and declares its degree and per-row fraction bound; these modules supply the
//! operation-specific gates, messages, and batches at those call sites.

pub(super) mod aead_stream;
pub(super) mod merkle;
