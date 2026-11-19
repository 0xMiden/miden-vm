# Independently specified base observation v1

This is a new observation format authored from the public interfaces at fixed base
`614c9f3608e6cc0a80397e8aa60315558f3069f7`. It is not the unspecified historical
`native-air-reference-v1` hash encoding. No old observer source, migrated code or
old generated output was consulted. The associated observer is
`../../native_air_reference.rs`; it observes authored definitions, never a
generated evaluator. No observer/test execution or numerical snapshot capture
has been performed while introducing this contract.

## Frozen data usage

`reference.txt` and `coverage.txt` are byte-for-byte supplied handoff data.
`PROVENANCE.md` retains the supplied attribution with an authored31 interface-adapter note;
README.md records original and current provenance-file hashes separately. Historical
producer/observer revisions are attribution only, not permission to inspect those objects.
The original transfer manifest verifies supplied bytes, not historical reproducibility or
base equivalence.

Read-only comparisons use these explicit fields from `reference.txt`:

- The 4 VM and 12 precompile named entries, with their whole ordered registry
  sequence compared against the ordered frozen section headers.
- `shape`, including main/preprocessed/aux/public/challenge/export dimensions and
  optional preprocessing log height; `periods`; per-class assertion counts.
- Protocol ID when supplied; independently rebuilt ACE commitment and circuit
  dimensions; relation digest computed with the existing base protocol encoder.
- Rebuilt fixed-table commitments for the three existing canonical hash configs.
- PVM raw widths in canonical order, with auxiliary widths expressed in base
  coordinates, and quotient chunk count from the existing base degree helper.

`next.txt` supplies the explicit fields changed by the upstream VM decoder update. A
comparison looks up those fields in `next.txt` first and uses `reference.txt` for
all other expectations. Its `base=` line identifies the upstream revision.

The comparison does **not** claim to reproduce opaque `periodic`, `preprocessed`,
`ordered-classes-degrees`, `ordered-values`, `aux` or `ace-stream` hashes. Their
complete preimage framing is missing. Historical sample Horner values and aux
exports are not compared: the full historic Horner/aux input recipe has not been
independently established. The synthetic coverage relation's body is missing;
its seven records remain data only. Neither unknown hash framing nor missing
coverage equations may be recovered from archived Rust/patches. Keep unsupported
fields unchanged; do not regenerate them from reconstructed code.

## Inputs and order for new v1 observations

1. Iterate authored VM `AIRS`, then authored `ChipletAir::all()`. Section names
   are `vm/<file_token>` then `pvm/<file_token>`. No proof-order sorting occurs.
2. The first observer captures each source through the allowed-base compiler `ir::capture`.
   The current native interface adapter uses `ir::capture_native`; this changes the API entrypoint,
   not the defined observation recipe. Record raw degrees with `testing::constraint_degrees`.
   Merge per-class roots and degrees by their global emission ordinals, requiring exactly the dense range
   `0..base_count+ext_count`. Keep repeated and zero-gated roots. Global class is
   0 for base and 1 for extension. No optimization/generated evaluator supplies
   the observation.
3. For each seed in this exact order, use base `testing::eval_graph`:
   `243f6a8885a308d3`, `13198a2e03707344`, `a4093822299f31d0`,
   `082efa98ec4e6c89`. Its leaf mapping/mixer at the fixed base is part of this
   version: main tags1/2; public3; periodic4; first5/last6/transition7;
   auxiliary8/9; challenges10; exports11; preprocessed12/13; field constants
   retain their values. Base leaves reduce `mix(seed,tag,index,0)` to Felt;
   extension leaves use coefficients with final index0 then1. This deliberately
   assigns selectors and limbs arbitrary field values, not valid trace values.
   Forward Horner is `acc = acc * alpha + value`, initially zero, with QuadFelt
   `alpha=[17,19]`; all emissions participate in global order. This new alpha
   choice does not establish the historical recipe.
4. Periodic definitions are taken in source order, storing each native period
   once. Preprocessed values use the source's actual optional matrix, row-major.
5. Auxiliary sample height is the maximum of2, maximum native period and fixed
   table height when present. Main and public cells are zero; statement-level
   auxiliary inputs are empty. Challenge i has coefficients `[2*i+2,2*i+3]`.
   Use the existing source auxiliary constructor with the already materialized
   optional preprocessing. Record its whole row-major result and exports in
   their returned order. These are deterministic constructor samples, **not**
   claims that all-zero main rows satisfy each AIR or cover every witness branch.
6. Build VM and PVM recursive ACE circuits through their authored compiler
   functions, not embedded/generated artifacts. Use their existing protocol IDs,
   `relation_digest` encoder and default PCS parameter factories. For fixed
   setup, construct a source-only MultiAir with zero public values at every
   declared public-input index, empty statement auxiliary inputs, and the
   canonical source instance list. Use the existing Blake3/Eidos/Keccak configs;
   Eidos domain is `miden_core::program::domain::STARK_TRANSCRIPT`.

## Binary framing of new digest fields

Every digest is BLAKE3-256 over the ASCII bytes
`native-air-base-observation-v1`, one zero byte, its ASCII tag, one zero byte,
then the payload below. Counts, dimensions, ordinals, degrees and seeds are
checked `u64`, little-endian. Every base-field element is its canonical u64,
little-endian; QuadFelt stores basis coefficient0 then coefficient1. Class and
option-presence flags are single bytes. No Rust Debug encoding is hashed.

| Tag | Payload, in exact order |
|---|---|
| `periodic` | column count; for each column: length followed by all base values |
| `fixed` | presence byte; if1: width, height, all base values row-major |
| `layout` | assertion count; for each global assertion: ordinal, class, raw degree |
| `values` | seed, assertion count; for each global assertion: ordinal, class, extension value (base values lifted with coefficient1=0) |
| `aux` | width, height, all extension values row-major |
| `exports` | value count, then extension values |
| `ace` | READ-input count, EVAL-gate count, stream length, then all base instruction elements in existing ACE stream order |

Text begins `native-air-base-observation-v1`, then exact fixed base and
`alpha=[17, 19]`. AIR section metadata uses the explicit historical field spelling
for the comparable fields. Sample lines are `sample-v1=seed=<seed> ordered-values-v1=<digest> horner=<array>`.
New hashes have a `-v1` suffix and lowercase `0x` plus
64 hex digits. Seeds have `0x` plus16 lowercase hex digits. Protocol sections
contain protocol ID, relation/ACE/setup commitments, circuit shape and a new
`ace-stream-v1` digest. Decimal arrays/tuples use Rust's standard list/tuple
Debug spacing, which affects text only, never hash preimages. Each record has
one LF terminator; one blank line precedes each section.

## Baseline and execution gate

The observer is read-only: it has no fixture overwrite or environment-controlled
regeneration mode. The ignored recording target prints the newly framed report;
it never writes an expected result. A reproducible baseline must be captured
from the first independently authored observer commit
`aae9815060a1f558d89969215333b050d29bc5af`, the signed publication of original local commit
`881521641a737e7f656a156ebd6dff440aaf81c4`. Its production sources remain at the fixed
base. Capture requires explicit execution authorization and required power checks.
Record that exact commit ID, toolchain and lock hash alongside the snapshot.
Do not capture an expected baseline from later equation/kernel changes.

Until that is authorized, no new numerical expected bytes exist. The metadata
and explicit identity comparisons are authored but unexecuted. Their acceptance
must not be reported as proof of all equations, every input namespace, witness
branches, transcript sampling order or arbitrary-assignment stream equality.
