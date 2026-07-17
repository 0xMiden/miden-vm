//! Common benchmark configuration and utilities for systematic benchmarking.
//!
//! This module provides standardized configuration and helper functions
//! to ensure consistent benchmarking across all benchmark modules.
//!
//! # Organization
//!
//! All benchmark modules follow this structure:
//! 1. Configuration setup (using common helpers)
//! 2. Input data generation functions (following naming convention)
//! 3. Benchmark functions (following naming convention)
//! 4. Group definition and main export
//!
//! # Naming Conventions
//!
//! ## Benchmark Functions
//! - `hash_<algorithm>_<operation>_<data_type>` (e.g., `hash_rpo256_single_byte`,
//!   `hash_rpo256_sequential_felt`)
//! - `merkle_<structure>_<operation>_<parameter>` (e.g., `merkle_smt_update_sparse`,
//!   `merkle_mmr_proof_generation`)
//!
//! ## Input Generation Functions  
//! - `generate_<data_type>_<size>` (e.g., `generate_byte_array_896` for 896 bytes)
//! - `generate_<data_type>_random_<size>` (e.g., `generate_byte_array_random_1024` for 1KB)
//!
//! ## Configuration Functions
//! - `setup_<benchmark_group>_config()` (e.g., `setup_hash_benchmarks_config()`)
//!
//! # Adding New Benchmarks
//!
//! To add a new benchmark module:
//! 1. Create `benches/<category>_all.rs` (e.g., `benches/hash_all.rs`)
//! 2. Import `common::*`
//! 3. Follow the naming conventions
//! 4. Use the provided configuration helpers
//! 5. Export the benchmark group

#![allow(dead_code)] // benchmark use doesn't count as "usage" for linting

pub mod config;
pub mod data;
pub mod macros;
