# Eidos ARM Native Performance Design

## Goal

Bring the native Eidos improvements on `robin/eidos-native-perf` to AArch64, with dedicated
implementations for the NEON baseline, Graviton3's 256-bit SVE, and Graviton4/5's 128-bit SVE2.
The optimized paths must remain byte-for-byte equivalent to the portable compression schedule and
must retain the crate's `no_std` behavior.

## Scope

The work covers every actionable ARM recommendation from the accepted investigation:

- runtime selection between NEON, SVE, and SVE2 in `std` builds;
- compile-time selection in `no_std` builds;
- an SVE packed backend that uses the active vector length without assuming it is process-global;
- an SVE2 packed backend that fuses XOR and rotate with `XAR`;
- row-wise single-block NEON and SVE2 compression;
- direct logical-batch access that removes materialized four- and eight-lane sub-batches;
- ARM-specific packed `u64`/`Felt` input and output adapters;
- reduced message-vector lifetimes and interleaved independent G chains;
- a one-instruction NEON byte permutation for rotate-right-by-eight where generated code confirms
  the intended instruction;
- a PoW kernel that hoists invariant preparation and returns only its lane acceptance mask;
- multi-block sequential entry points that retain a chaining value across a call;
- count-aware packed entry points for partially occupied Merkle/LMCS batches;
- narrow fixed-shape preparation for merge and PoW inputs when the existing caller contracts make
  the constants explicit;
- ARM benchmark coverage for raw, framed, packed, PoW, and partial-batch operations.

Reducing rounds, changing Eidos framing, changing digest masking, and changing the public logical
packed width are outside scope.

## Architecture

The portable Rust schedule remains the reference implementation. Architecture kernels live below
`crates/crypto/arch/arm64-eidos/` and expose pointer-and-count C ABIs. C ACLE intrinsics are used for
SVE because Rust's scalable-vector intrinsics are not stable. The NEON single-block path may use
Rust intrinsics when this keeps the implementation smaller; its API remains behind the same
internal dispatch boundary.

`std` builds compile all three AArch64 tiers and select a function table once from AArch64 feature
detection. Selection distinguishes latency-oriented single compression from throughput-oriented
packed compression. `no_std` builds compile and select only tiers enabled by target features,
falling back to NEON, which is part of the AArch64 baseline used by this crate.

SVE kernels query their vector length on every call and iterate over the fixed logical 16-lane
batch with predicates. No Rust type contains an SVE-sized value and no cached process-wide lane
count is used. Thus Linux's per-thread SVE vector-length setting cannot invalidate dispatch or
memory bounds. The same kernel processes eight candidates per iteration on Graviton3 and four on
Graviton4/5.

SVE2 represents each `rotate_right(x ^ y, r)` as one `svxar_n_u32` operation. The SVE1 backend uses
XOR plus the best generated rotate sequence. Both packed kernels keep state word-major: one vector
contains the same word from independent compressions. The row-wise kernels instead keep four words
of one compression in a vector and permute lanes for diagonal rounds.

## Data movement

Architecture entry points consume the existing logical 16-lane arrays directly. Each kernel loads
the current lane window from `word * 16 + lane_offset`, avoiding temporary sub-batch arrays and
copy-back loops. Count-aware calls predicate or bound the final window and never read inactive
lanes.

The packed-u64 path supplies fused adapters that split eight 64-bit values into the sixteen u32
message words expected by Eidos and pack the eight output u32 words back into four masked u64
words. Arbitrary `Felt` inputs remain canonicalized. Callers that already hold canonical integers
may use an internal contract-specific adapter, documented at the call site.

Sequential multi-block calls retain the raw chaining value inside the architecture kernel. Digest
masking is applied after every compression, because the masked output is the chaining value of the
next block. Framing and padding continue to be decided by Rust.

## Specialized paths

PoW grinding prepares the invariant CV, fixed buffer words, tag, and mask once. The architecture
kernel receives a base nonce and candidate count, generates lane values, performs the required one
or two compressions, and returns an acceptance bit mask. Rust still verifies the selected witness
with the scalar challenger before returning it.

LMCS/Merkle callers pass their active lane count to a private packed compressor. Full batches take
the regular fast path; partial batches avoid manufacturing sixteen meaningful inputs. Existing
scalar fallback behavior remains available for counts where it benchmarks faster.

Merge specialization consists only of hoisting values fixed by the established one-block framing
contract. It must call the same compression output fold and mask as the generic path. No separate
cryptographic construction is introduced.

## Testing

Every architecture entry point is checked against the portable scalar implementation over fixed
vectors, random CVs and blocks, zero and maximum words, and lane counts 1 through 16. Raw CV, XOF,
masked digest, framed multi-block hashing, merge, and both PoW buffer cases are covered.

Cross-compilation checks build generic AArch64, `+sve`, and `+sve2` configurations, with and without
`std`. Generated assembly checks assert that the SVE2 G primitive contains `xar` and that the NEON
rotate-eight primitive contains the intended byte permutation. These checks establish code shape;
they do not substitute for hardware correctness tests.

Benchmarks report raw single-block latency, packed throughput for active counts 1/2/4/8/16,
short/long `hash_elements`, merge, and PoW candidates per second. Graviton3 and Graviton4 results
are required before removing a fallback or claiming a performance improvement.

## Delivery

Changes are split into reviewable commits: tests and dispatch boundary; SVE packed kernel; SVE2
packed kernel; single-block kernels; adapters and partial batches; PoW and sequential
specializations; benchmarks and documentation. Each commit preserves the portable fallback and
passes the relevant native and cross-compilation checks.
