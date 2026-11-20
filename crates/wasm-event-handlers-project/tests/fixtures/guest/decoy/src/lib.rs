//! The only default member of the fixture guest workspace, and never the handler module.
//!
//! A `cargo build` that selects no package builds this crate and not the guest library next to it,
//! which is what the plugin's explicit `--package` selection must prevent.

#![no_std]
