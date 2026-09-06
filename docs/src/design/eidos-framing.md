---
title: "Eidos framing and domain registry"
sidebar_position: 3
---

# Eidos framing and domain registry

Eidos binds a numeric domain tag and three domain-defined parameters into its initial chaining
value. Domain tags are allocated rather than derived by hashing names. Rust APIs carry the domain
as a type, and downstream MASM constants can be generated from the same declarations.

This document specifies Eidos framing and the domain-registry contract.

## Construction overview

Every registered Eidos construction defines a domain tag, the meaning of its three parameters,
and a block-encoding rule. Hashing then follows the same outer flow:

```text
(tag, [param0, param1, param2]) --init--> CV_0
logical input                         --encode and pad--> block_0, ..., block_n
CV_{i + 1} = compress(CV_i, block_i)
digest = pack(CV_{n + 1})
```

The tag and parameters are inputs to initialization, not the chaining value itself. Initialization
interleaves those four `u32` values with four fixed IV words to form `CV_0`. The domain's encoding
rule determines the physical blocks and how the logical length is represented.

For example, the generic byte-string hash of `"abc"` is:

```text
tag       = GENERIC_BYTE_STRING = 0x00000301
params    = [3, 0, 0]                     # three input bytes
CV_0      = init(tag, params)
block_0   = [0x00636261, 0, ..., 0]       # 16 little-endian u32 words
CV_1      = compress(CV_0, block_0)
digest    = pack(CV_1)
```

The final block is zero-padded, while `params[0] = 3` binds the unpadded byte length. Consequently,
`"abc"`, `"abc\0"`, and the same physical block under another domain start from different initial
chaining values.

## Initial chaining value

Let `IV` be the eight 32-bit words of the BLAKE3 initialization vector and let
`pack(low, high) = low + 2^32 * high`. Define four packed base field elements:

```text
BASE0 = pack(0, IV[1] & 0x7fff_ffff) = 4280581857092829184
BASE1 = pack(0, IV[3] & 0x7fff_ffff) = 2688637132020383744
BASE2 = pack(0, IV[5] & 0x7fff_ffff) = 1947077364412317696
BASE3 = pack(0, IV[7] & 0x7fff_ffff) = 6620516959492505600
```

For a domain tag and three parameters, Eidos initializes:

```text
CV = [
    BASE0 + tag,
    BASE1 + param0,
    BASE2 + param1,
    BASE3 + param2,
]
```

Equivalently, unpacking the four field elements into eight 32-bit lanes gives:

```text
[
    tag,    fixed0,
    param0, fixed1,
    param1, fixed2,
    param2, fixed3,
]
```

The tag and each parameter may use the complete `u32` range. Each fixed high lane is below
`2^31`, so the largest packed value is:

```text
(2^31 - 1) * 2^32 + (2^32 - 1) = 2^63 - 1
```

This is below the Goldilocks modulus `2^64 - 2^32 + 1`. The additions therefore place each input
directly in the low half of one Felt without a carry or runtime bit manipulation.

## Domain-tag hierarchy

A registered tag is a 32-bit `8/16/8` value:

```text
 31            24 23                         8 7             0
+----------------+-----------------------------+---------------+
|  namespace: 8  |       local id: 16          |  version: 8   |
+----------------+-----------------------------+---------------+

tag = (namespace << 24) | (local_id << 8) | version
```

The central registry records which owner controls each namespace. That owner maintains a sorted
local registry and coordinates assignments inside it. The code checks one registry declaration for
the correct namespace and unique tags, but allocation across repositories remains a governance
rule. The `(namespace, local_id) = (0, 0)` pair is reserved, so the all-zero tag is never
registrable. A nonzero namespace may allocate owner-local ID zero.

| Namespace | Owner | Responsibility |
| ---: | --- | --- |
| `0x00` | `miden-crypto` | Cryptographic constructions implemented by `miden-crypto` |
| `0x01` | `miden-vm` | VM, proof-system, and precompile constructions |
| `0x02` | `miden-protocol` | Protocol commitments and transaction constructions |
| `0x10` | Miden ecosystem | Reserved for a centrally maintained ecosystem registry; not for ad hoc allocation |

Unlisted namespace values remain unallocated. Adding one requires an update to the central
namespace registry in `miden-crypto`; it is not a local convention.

Values in the reserved `(namespace, local_id) = (0, 0)` region are not domain tags. The all-zero
tuple initializes Merkle inner-node compression. MAST control nodes place an opcode in the tag
lane, bind `param0 = 8`, and leave the other parameters zero. Registered tags are at least `0x100`,
so neither VM-internal framing family can overlap a registry allocation.

### Versioning

Version bytes `1..=255` identify numbered construction versions. Version byte `0` is the named
`DELEGATED_VERSIONING` marker:

```text
numbered:  tag = pack(namespace, local_id, version)  where version != 0
delegated: tag = pack(namespace, local_id, 0); the authenticated payload carries the version
```

For a delegated domain, zero is not the object version. It says that the authenticated payload
carries the version according to the domain's registered schema. The schema must fix the version's
location and encoding. The Eidos encoding family and compression schedule also remain fixed;
changing any of these requires a new registered tag.

The protocol decides which embedded object versions it accepts. Unknown versions must be rejected.
A local ID uses either delegated versioning or numbered versions, never both. This keeps one
canonical versioning policy for each construction family.

## Typed registries

`DomainTag` stores the numeric `8/16/8` value. An `EidosDomain` implementation also records the
construction's name and encoding family:

- `FeltSequence` for the standard exact-length Felt schedule;
- `ByteString` for the standard exact-length byte schedule;
- `Transcript` for the Fiat-Shamir transcript seed schedule;
- `Custom` for a construction with its own fixed or stateful schedule.

For domains declared with the registry macro, this distinction is part of the Rust API. A
`ByteString` domain, for example, cannot be passed to `Eidos::hash_elements_in_domain`. Registry
owners remain responsible for their numeric assignments and should not implement `EidosDomain`
manually.

Each owner declares its local registry once with `eidos_domain_registry!`:

```rust
use miden_crypto::{
    eidos_domain_registry,
    hash::eidos::{DomainVersion, FeltSequence, namespace},
};

eidos_domain_registry! {
    pub registry ProtocolEidosDomains {
        namespace: namespace::MIDEN_PROTOCOL;
        domains: {
            pub ACCOUNT_COMMITMENT: AccountCommitmentDomain {
                local_id: 0x0001,
                version: DomainVersion::numbered(1),
                encoding: FeltSequence,
                description: "Miden account commitment.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0",
            }
        }
    }
}
```

The macro emits typed zero-sized values, structured descriptors, and compile-time checks within
that declaration: tags must be sorted, unique, inside the declared namespace, and use one
versioning policy per local ID. It cannot detect an independent registry that wrongly claims the
same namespace. `render_masm_constants` renders the declarations as MASM constants; downstream
generators should use this output rather than copying numeric tags by hand.

Dynamic boundaries may recover an `EidosFrame` from an initial chaining word. This checks the
fixed IV lanes and the canonical `u32` representation of the domain and parameters, but not registry
membership or domain semantics. The dynamic consumer must resolve the domain in the owner's
registry, then validate the parameters and payload.

## Standard Felt and byte schedules

The ordinary one-shot APIs use two different registered domains:

```text
hash_elements(elements):
    tag    = GENERIC_FELT_SEQUENCE
    param0 = number of Felts
    param1 = 0
    param2 = 0

hash(bytes):
    tag    = GENERIC_BYTE_STRING
    param0 = number of bytes
    param1 = 0
    param2 = 0
```

Each schedule binds the complete logical length, compresses every complete block, and zero-fills a
single partial final block. Empty input compresses one all-zero physical block. A non-empty exact
multiple of the block width does not append another block.

The logical length must fit in the `u32` parameter lane. The one-shot Rust APIs panic when a byte
length or flattened Felt length exceeds that limit. Flattening a slice of extension-field elements
also panics if the length calculation overflows `usize`.

Domain-specific Felt and byte constructions declare their own typed domains. Bytes are therefore
an encoding family, not one global numeric range: a protocol can register several `ByteString`
domains inside its namespace without colliding with its `FeltSequence` domains.

The two generic domains give the ordinary library APIs stable constructions. A protocol-visible
commitment with its own meaning should register a semantic domain instead of treating
`GENERIC_FELT_SEQUENCE` or `GENERIC_BYTE_STRING` as a shared namespace for unrelated objects.

The `CryptographicHasher<u64, _>` implementations are representation adapters for the generic
Felt construction. Canonical Goldilocks `u64` encodings match the corresponding `Felt` inputs
exactly. The adapter deliberately splits any other `u64` into its two 32-bit limbs without field
reduction for its low-level consumers; those extra inputs do not define another registered
construction or alter the typed `FeltSequence` API.

## Reserved Merkle inner-node construction

Merkle inner-node compression is the only unregistered Eidos construction. It uses the all-zero
framing tuple and exactly one 8-Felt block:

```text
MerkleInner(left, right):
    tag    = 0
    param0 = 0
    param1 = 0
    param2 = 0
    block  = left_digest || right_digest
```

"All zero" refers to the four injected lanes. The actual initial chaining word is
`[BASE0, BASE1, BASE2, BASE3]`, not the literal zero word.

This construction is reserved exclusively for Merkle inner nodes so that the VM's Merkle-path
operations have one fixed initialization. Structured leaves bind their own meaning before they
enter the tree, and callers bind the role of a root where it is consumed. In particular:

```text
Eidos::merge([left, right]) != Eidos::hash_elements(left || right)
```

The right-hand side uses the registered generic Felt tag and binds length eight. The VM's `hmerge`
instruction and `eidos::hash_two_words` procedure implement that generic hash. Merkle code uses
`Eidos::merge`, or obtains its reserved initial word from
`Eidos::merkle_node_init_chaining_word` when compression is scheduled by a separate engine.

## Custom schedules

A numbered tag identifies the complete grammar of a construction: parameter meanings, payload
encoding, compression schedule, and output extraction. A delegated tag identifies the same fixed
hash schedule plus the stable rule used to find the object version in its payload. The three
parameter lanes do not have global names; their interpretation belongs to the registered domain.

### Deferred-node framing

A non-TRUE deferred node stores this frame:

```text
FRAME = [domain_tag, param0, param1, param2]
```

For `b` complete payload blocks, its digest is:

```text
CV_0 = init(domain_tag, [param0, param1, param2])
CV_{i + 1} = compress(CV_i, payload_block_i)
digest = CV_b
```

Every frame value is a canonical `u32`. The domain defines the meaning of all three parameters and
must validate them against the payload. There is no framework-wide length parameter. Every
compression consumes payload; there is no terminal framing block. Framework AND and CHUNKS nodes
use the registered `DEFERRED_AND` and `DEFERRED_CHUNKS` domains. The TRUE node is a sentinel and is
not hashed.

When the PVM proves a multi-block deferred digest, the semantic owner provides `EidosInit` at the
physical chain head, `EidosBlock` for each compression, and the terminal
`EidosOut(head, tail, digest)` relation. Including both endpoints in the terminal relation binds the
digest to the same physical chain the owner initialized. The owner derives the tail from its
domain's payload grammar; the generic Eidos controller consumes all three relations, proves
contiguous chaining, and propagates the head identity.

LMCS is an example. Leaf hashing has its own `Custom` domain because it absorbs matrix rows in
commitment order, padding each row independently to eight Felts. Its first parameter binds the sum
of those padded widths, including the independently padded salt when present. The verifier still
supplies the row boundaries and widths fixed by its LMCS configuration; the total length does not
replace that shape check. LMCS internal nodes use the reserved Merkle construction above. The tag
is part of the canonical `EidosLmcs` configuration, not something callers choose per matrix. A
different leaf schedule needs its own registered domain and matching hasher.

The Fiat-Shamir challenger also uses a dedicated schedule. `transcript_init_cv(domain)` creates the
standard framed initial CV with the registered transcript tag and three zero parameters. The
relation digest is then absorbed as the first transcript block. Scalar observations are buffered
in groups of eight and full buffers are compressed immediately. Sampling zero-pads the pending
buffer, adds `1 + pending_len` to the fourth CV element in the Goldilocks field, and compresses it.
The four resulting CV elements are returned in order. Each additional output word adds `9` in the
same field and compresses `[counter, 0, ..., 0]`, starting at counter one. A new observation
discards unused output elements and resets the counter while preserving the current CV.
Finalization also discards unread output elements and returns a freshly generated word. One
uninterrupted squeezing phase can produce `2^32` words: one with counter zero and one for each
nonzero `u32` counter. Requesting another word panics. VM transcript domains belong in the
`miden-vm` namespace, not the `miden-crypto` local registry.

Falcon hash-to-point, AEAD key derivation, and random-coin output generation similarly use named
custom domains whose schemas define their fixed block and output schedules.

## `miden-crypto` local registry

The declarations in `hash::eidos::domains` are normative and are the source for this table and
generated MASM constants.

| Local ID | Version | Rust domain | Encoding |
| ---: | ---: | --- | --- |
| `0x0001` | 1 | `SMT_BUCKET_LEAF` | `Custom` |
| `0x0002` | 1 | `MMR_PEAKS` | `Custom` |
| `0x0003` | 1 | `GENERIC_BYTE_STRING` | `ByteString` |
| `0x0004` | 1 | `FALCON_HASH_TO_POINT` | `Custom` |
| `0x0005` | 1 | `FALCON_PUBLIC_KEY` | `FeltSequence` |
| `0x0006` | 1 | `AEAD_CTR_KEY` | `Custom` |
| `0x0007` | 1 | `AEAD_MAC_KEY` | `Custom` |
| `0x0008` | 1 | `RANDOM_COIN_STATE` | `FeltSequence` |
| `0x0009` | 1 | `RANDOM_COIN_OUTPUT` | `Custom` |
| `0x000a` | 1 | `GENERIC_FELT_SEQUENCE` | `FeltSequence` |
| `0x000b` | 1 | `LMCS_LEAF` | `Custom` |

## `miden-vm` local registry

The declarations in `core::program::domain` are normative and are the source for this table.

| Local ID | Version | Rust domain | Encoding |
| ---: | ---: | --- | --- |
| `0x0000` | 1 | `KERNEL_COMMITMENT` | `FeltSequence` |
| `0x0001` | 1 | `EXECUTION_CLAIM` | `FeltSequence` |
| `0x0002` | 1 | `PROOF_REQUEST` | `FeltSequence` |
| `0x0003` | 1 | `DEFERRED_AND` | `Custom` |
| `0x0004` | 1 | `DEFERRED_CHUNKS` | `Custom` |
| `0x0005` | 1 | `STARK_TRANSCRIPT` | `Transcript` |
| `0x0006` | 1 | `KECCAK256_PRECOMPILE` | `Custom` |
| `0x0007` | 1 | `UINT256_PRECOMPILE` | `Custom` |
| `0x0008` | 1 | `CURVE_PRECOMPILE` | `Custom` |
| `0x0009` | 1 | `PVM_UINT_PIN_CLAIM` | `Custom` |
| `0x000a` | 1 | `FALCON_PRODUCT_CHECK` | `FeltSequence` |

Numeric assignments are consensus-visible. Changing a numbered construction's encoding, parameter
schema, or schedule requires a new version. A delegated construction may evolve the payload grammar
through its embedded object version, but changing its version envelope or hash schedule requires a
new tag. Either change invalidates every digest that depends on the construction.
