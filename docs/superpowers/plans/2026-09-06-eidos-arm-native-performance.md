# Eidos ARM Native Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add correct, runtime-dispatched NEON, SVE, and SVE2 Eidos compression paths and reduce ARM-side framing overhead.

**Architecture:** The portable Rust schedule remains the oracle. AArch64 C kernels expose pointer-only ABIs, query SVE vector length inside each call, and are selected once in `std`; `no_std` uses compile-time selection. Private count-aware and sequential interfaces let callers avoid empty lanes and repeated setup.

**Tech Stack:** Rust, C11, Arm ACLE NEON/SVE/SVE2 intrinsics, Cargo `cc`, Criterion.

**Spec:** `docs/superpowers/specs/2026-09-06-eidos-arm-native-performance-design.md`

## Global Constraints

- Keep `PACKED_LANES == 16` and preserve the portable fallback.
- Preserve raw CV/XOF semantics, digest odd-lane masking, Eidos framing, and exact-length binding.
- Do not cache SVE vector length; it can differ by Linux thread.
- `std` selects ARM tiers at runtime; `no_std` selects only compile-time-enabled tiers.
- Each optimization is a standalone commit and retains tests that compare it with the portable oracle.
- Hardware speedup claims require Graviton measurements; local assembly inspection is only a code-shape check.

---

### Task 1: ARM dispatch boundary and C build

**Files:**
- Modify: `crates/crypto/build.rs`
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Create: `crates/crypto/arch/arm64-eidos/eidos_arm.h`
- Create: `crates/crypto/arch/arm64-eidos/dispatch_stubs.c`

**Interfaces:**
- Produces: `ArmTier::{Neon,Sve,Sve2}`, cached `detect_arm_tier()`, and pointer ABI declarations for raw, packed, counted, and PoW kernels.

- [ ] Add an AArch64-only test hook that reports the selected tier; first verify it cannot compile because the dispatch API is absent.
- [ ] Compile ARM kernel objects in every AArch64 `std` build with per-file `-march` flags; retain target-feature-gated builds for `no_std`.
- [ ] Implement cached `std::arch::is_aarch64_feature_detected!` selection with `sve2 > sve > neon` precedence and compile-time `no_std` selection.
- [ ] Cross-check generic, `+sve`, and `+sve2` C objects with Clang and run existing Eidos tests.
- [ ] Commit as `perf(crypto): add runtime ARM dispatch for Eidos`.

### Task 2: Direct packed SVE and SVE2 compression

**Files:**
- Create: `crates/crypto/arch/arm64-eidos/eidos_sve.c`
- Create: `crates/crypto/arch/arm64-eidos/eidos_sve2.c`
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Test: `crates/crypto/src/hash/eidos/primitive.rs`

**Interfaces:**
- Produces: `eidos_compress16_sve(cv, block, out, active_lanes)` and `eidos_compress16_sve2(...)` over word-major `[8][16]`, `[16][16]`, and `[8][16]` buffers.

- [ ] Add oracle tests for active lane counts 1 through 16; first verify the absent counted API fails compilation.
- [ ] Implement an SVE loop using `svcntw()` and `svwhilelt_b32()` for each lane window, direct word-major loads/stores, interleaved G chains, and short message-vector lifetimes.
- [ ] Implement the same schedule for SVE2 with each XOR/rotate expressed as `svxar_n_u32`; inactive lanes must never be loaded or stored.
- [ ] Compile both sources to assembly and verify SVE2 emits `xar`; run the portable/native equivalence suite on the host.
- [ ] Commit SVE and SVE2 separately as `perf(crypto): add packed SVE compression for Eidos` and `perf(crypto): fuse Eidos SVE2 xor rotations`.

### Task 3: Row-wise single-block ARM compression

**Files:**
- Create: `crates/crypto/arch/arm64-eidos/eidos_neon.c`
- Modify: `crates/crypto/arch/arm64-eidos/eidos_sve2.c`
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Test: `crates/crypto/src/hash/eidos/primitive.rs`

**Interfaces:**
- Produces: `eidos_compress_raw_neon`, `eidos_compress_xof_neon`, `eidos_compress_raw_sve2`, and `eidos_compress_xof_sve2`.

- [ ] Extend the 10,000-input scalar-oracle test so AArch64 dispatch exercises raw and XOF paths; verify the new symbols are initially absent.
- [ ] Port the row-wise four-register schedule, including diagonal lane permutations, to NEON; implement rotate-eight with `vqtbl1q_u8` and keep rotate-sixteen as `vrev32q_u16`.
- [ ] Add an SVE2 row-wise variant predicated to four u32 lanes and fuse XOR/rotate through `XAR`.
- [ ] Inspect assembly for table rotation and `xar`, compile all objects, and run Eidos tests.
- [ ] Commit as `perf(crypto): add row-wise ARM compression for Eidos`.

### Task 4: Count-aware adapters and partial batches

**Files:**
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Modify: `crates/crypto/src/hash/eidos/compression.rs`
- Modify: `crates/crypto/src/hash/eidos/encoding.rs`
- Modify: `crates/crypto/src/hash/eidos/lmcs.rs`
- Test: `crates/crypto/src/hash/eidos/{primitive.rs,compression.rs,lmcs.rs}`

**Interfaces:**
- Produces: `compress_packed_native_counted(cv, block, active_lanes)` with `1..=16` validation and counted packed-u64/felt adapters.

- [ ] Add tests whose inactive lanes are poison values and verify only the active prefix affects returned active lanes; first verify the counted APIs are absent.
- [ ] Route full batches without temporary sub-arrays and partial batches through ARM predication or the smallest scalar/NEON fallback.
- [ ] Add ARM adapters that split packed u64 inputs and pack masked outputs within the architecture call; retain canonicalization for arbitrary Felt input.
- [ ] Use active counts at LMCS/Merkle tail call sites that expose them; preserve the full-batch public API.
- [ ] Run adapter, LMCS, and Eidos suites and commit as `perf(crypto): avoid empty ARM Eidos lanes`.

### Task 5: Sequential and fixed-shape hashing

**Files:**
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Modify: `crates/crypto/src/hash/eidos/compression.rs`
- Modify: `crates/crypto/src/hash/eidos/construction.rs`
- Test: `crates/crypto/src/hash/eidos/construction.rs`

**Interfaces:**
- Produces: private `compress_blocks(cv, blocks)` and a one-block `compress_digest_pair` preparation path.

- [ ] Add literal-vector tests covering zero, one, two, and partial final blocks plus merge/domain equivalence; verify the absent multi-block API fails compilation.
- [ ] Keep CV inside one dispatched architecture call across encoded blocks and apply odd-word masking after every compression.
- [ ] Route byte/u64/felt sequential hashing through the multi-block entry only when inputs are already materialized contiguously; retain iterator validation and padding in Rust.
- [ ] Hoist the fixed merge initialization and direct two-digest encoding without defining a second construction.
- [ ] Run construction and full Eidos suites and commit as `perf(crypto): batch sequential Eidos blocks on ARM`.

### Task 6: Specialized packed PoW grinding

**Files:**
- Modify: `crates/crypto/src/hash/eidos/challenger.rs`
- Modify: `crates/crypto/src/hash/eidos/primitive/blake3_schedule.rs`
- Modify: `crates/crypto/arch/arm64-eidos/eidos_neon.c`
- Modify: `crates/crypto/arch/arm64-eidos/eidos_sve.c`
- Modify: `crates/crypto/arch/arm64-eidos/eidos_sve2.c`
- Test: `crates/crypto/src/hash/eidos/challenger.rs`

**Interfaces:**
- Produces: `check_witness_batch(cv, buffer, buffer_len, base, count, mask) -> u16` with one- and two-compression handling.

- [ ] Add tests for every buffer length, tail counts 1 through 16, and masks 0/1/8/24; verify the absent batch API fails compilation.
- [ ] Hoist invariant CV/block/tag preparation out of the Rayon candidate closure and generate consecutive witness lanes without challenger clones.
- [ ] Return only the accepted-lane bit mask and keep final scalar `check_witness` validation.
- [ ] Run challenger and Eidos suites and commit as `perf(crypto): specialize Eidos grinding on ARM`.

### Task 7: ARM benchmark and verification campaign

**Files:**
- Modify: `crates/crypto/benches/hash.rs`
- Modify: `crates/crypto/benches/README.md`
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Produces benchmark groups for raw/XOF, merge, sequential lengths, packed counts 1/2/4/8/16, and PoW candidate throughput.

- [ ] Add Criterion cases that call the real public or `pub(crate)` adapters and report elements/candidates per second.
- [ ] Add AArch64 compile jobs for generic, SVE, and SVE2 configurations and commands for Graviton3/4 runs.
- [ ] Run formatting, Clippy, Eidos tests, benchmark compilation, generic AArch64 build, and standalone assembly checks.
- [ ] Commit as `bench(crypto): cover Eidos ARM acceleration`.
