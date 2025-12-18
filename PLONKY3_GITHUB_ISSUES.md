# GitHub Issues for 0xMiden/Plonky3

This file contains issues ready to be created on https://github.com/0xMiden/Plonky3

---

## Issue 1: Implement Security Level Estimator

**Title:** `Implement security level estimator for STARK proofs`

**Labels:** `enhancement`

**Body:**

## Problem

The `ExecutionProof::security_level()` method currently returns a hardcoded value of 96 bits. We need a proper security estimator that calculates the actual conjectured security level based on proof parameters.

## Background

The previous Winterfell implementation calculated security level based on:
- Proof parameters (FRI folding factor, number of queries, blowup factor)
- Hash function collision resistance
- Field size and extension degree

## Proposed Solution

Implement a `security_level()` function that computes the conjectured security based on:
- `num_queries` - number of FRI query repetitions
- `log_blowup` - blowup factor
- `proof_of_work_bits` - grinding parameter
- Hash function collision resistance

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472

---

## Issue 2: Add Blake3_192 Support

**Title:** `Add CryptographicHasher<u8, [u8; 24]> trait impl for Blake3`

**Labels:** `enhancement`

**Body:**

## Problem

Blake3_192 (192-bit / 24-byte output) is not supported because Plonky3 lacks the `CryptographicHasher<u8, [u8; 24]>` trait implementation. Currently, Blake3_192 falls back to using Blake3_256 configuration.

## Current Workaround

```rust
HashFunction::Blake3_192 => {
    // Falls back to 256-bit config
    let config = create_blake3_256_config();
}
```

## Proposed Solution

1. Add `CryptographicHasher<u8, [u8; 24]>` impl for `Blake3` in `p3-blake3`
2. Create type aliases for 192-bit Merkle tree and compression function
3. Export a `create_blake3_192_config()` factory function

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472

---

## Issue 3: Remove winter-utils Dependency from p3-goldilocks

**Title:** `Remove winter-utils dependency from p3-goldilocks`

**Labels:** `cleanup`, `dependencies`

**Body:**

## Problem

The `p3-goldilocks` crate still depends on `winter-utils v0.13.1`, which is the only remaining Winterfell dependency in the Miden ecosystem after the Plonky3 migration.

## Dependency Chain

```
winter-utils v0.13.1
└── p3-goldilocks (0xMiden/Plonky3)
    └── miden-crypto
        └── miden-vm (all crates)
```

## Proposed Solution

1. Identify what `winter-utils` is used for in `p3-goldilocks`
2. Replace with native implementations or equivalent utilities
3. Remove the dependency

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472

---

## Issue 4: Rename miden-prover and miden-air Crates

**Title:** Rename `miden-prover` and `miden-air` to avoid conflicts with `miden-vm`

**Labels:** `breaking-change`, `naming`

**Body:**

## Problem

The `0xMiden/Plonky3` fork contains crates named `miden-prover` and `miden-air`, which conflict with the crate names used in `miden-vm`. This causes:
- Ambiguous package errors when running cargo commands
- Confusion about which crate is which
- Potential dependency resolution issues

## Proposed Solution

Rename the crates to make it clear they are Plonky3-specific:
- `miden-prover` → `miden-prover-p3`
- `miden-air` → `miden-air-p3`

Alternative naming:
- `miden-prover` → `p3-miden-prover`
- `miden-air` → `p3-miden-air`

## Rationale

1. Avoids name collision with `miden-vm/prover` and `miden-vm/air`
2. Makes it clear these are Plonky3-specific implementations
3. Follows common naming conventions for framework-specific adapters

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472

---

## Issue 5: FRI Verification Fails with Octary Folding

**Title:** FRI verification fails with `log_folding_factor > 1`

**Labels:** `bug`, `fri`

**Body:**

## Problem

Using `log_folding_factor: 3` (octary folding, fold by 8 each round) in FRI parameters causes `RootMismatch` errors during proof verification. All configs are currently forced to use `log_folding_factor: 1` (binary folding) as a workaround.

## Steps to Reproduce

1. Create a STARK config with `log_folding_factor: 3` in `FriParameters`
2. Generate a proof
3. Attempt to verify → `RootMismatch` error

## Current Workaround

```rust
let fri_config = FriParameters {
    log_blowup: 3,
    log_final_poly_len: 7,
    num_queries: 27,
    proof_of_work_bits: 16,
    mmcs: challenge_mmcs,
    log_folding_factor: 1, // Forced to binary folding
};
```

## Impact

- Larger proof sizes (more FRI rounds with binary folding)
- Slower verification (more rounds to process)

## Expected Behavior

FRI should work correctly with any valid `log_folding_factor` value (1, 2, 3, etc.).

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472

---

## Issue 6: Add ProvingOptions and AcceptableOptions for Proof Serialization

**Title:** `Add ProvingOptions serialization and AcceptableOptions validation`

**Labels:** `enhancement`, `api`

**Body:**

## Problem

Currently, when serializing/deserializing proofs, the verifier has no way to know which STARK configuration (FRI parameters, etc.) was used during proving. The proof stores only the hash function, but the full config includes:

- `log_blowup` (blowup factor)
- `log_final_poly_len` (final polynomial degree)
- `num_queries` (FRI query repetitions)
- `proof_of_work_bits` (grinding parameter)
- `log_folding_factor` (folding strategy)

This creates several issues:

1. **No forward/backward compatibility** - If config parameters change between versions, old proofs silently fail to verify
2. **No security policy enforcement** - Verifier can't reject proofs generated with unacceptable security levels
3. **Hardcoded config reconstruction** - Verifier must assume the proof was generated with specific hardcoded parameters

In Winterfell, `ProvingOptions` and `AcceptableOptions` provided this functionality.

## Proposed Solution

### ProvingOptions with named constants

```rust
/// Parameters specifying how STARK proofs are generated.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProvingOptions {
    pub hash_fn: HashFunction,
    pub num_queries: usize,
    pub log_blowup: usize,
    pub log_final_poly_len: usize,
    pub proof_of_work_bits: usize,
    pub log_folding_factor: usize,
}

impl ProvingOptions {
    /// Standard proof parameters for 96-bit conjectured security.
    pub const REGULAR_96_BITS: Self = Self {
        hash_fn: HashFunction::Blake3_256,
        num_queries: 27,
        log_blowup: 3,
        log_final_poly_len: 7,
        proof_of_work_bits: 16,
        log_folding_factor: 1,
    };

    /// Standard proof parameters for 128-bit conjectured security.
    pub const REGULAR_128_BITS: Self = Self {
        hash_fn: HashFunction::Rpo256,
        num_queries: 27,
        log_blowup: 4,
        log_final_poly_len: 7,
        proof_of_work_bits: 21,
        log_folding_factor: 1,
    };

    /// Proof parameters for 96-bit security in recursive context.
    pub const RECURSIVE_96_BITS: Self = Self { ... };

    /// Proof parameters for 128-bit security in recursive context.
    pub const RECURSIVE_128_BITS: Self = Self { ... };

    /// Computes the conjectured security level for these options.
    pub fn security_level(&self) -> u32 { ... }

    /// Reconstructs a StarkConfig from these options.
    pub fn to_stark_config(&self) -> impl StarkGenericConfig { ... }
}
```

### AcceptableOptions for verification

```rust
pub struct AcceptableOptions {
    min_security_level: u32,
    acceptable_hash_fns: HashSet<HashFunction>,
    // Or more granular constraints if needed:
    // min_num_queries: usize,
    // min_log_blowup: usize,
}

impl AcceptableOptions {
    pub fn with_96_bit_security() -> Self {
        Self {
            min_security_level: 96,
            acceptable_hash_fns: HashSet::from([
                HashFunction::Blake3_256,
                HashFunction::Keccak,
                // ...
            ]),
        }
    }

    pub fn with_128_bit_security() -> Self { ... }

    pub fn is_acceptable(&self, opts: &ProvingOptions) -> bool {
        opts.security_level() >= self.min_security_level
            && self.acceptable_hash_fns.contains(&opts.hash_fn)
    }
}
```

### Proof serialization

```rust
pub struct ExecutionProof {
    pub proof: Vec<u8>,
    pub options: ProvingOptions,  // replaces hash_fn field
    pub precompile_requests: Vec<PrecompileRequest>,
    pub precompile_transcript_digest: PrecompileTranscriptDigest,
}
```

### Verification flow

```rust
pub fn verify(
    proof: ExecutionProof,
    acceptable: &AcceptableOptions,
) -> Result<u32, VerificationError> {
    if !acceptable.is_acceptable(&proof.options) {
        return Err(VerificationError::UnacceptableOptions);
    }

    let config = proof.options.to_stark_config();
    // verify with config...

    Ok(proof.options.security_level())
}
```

## Why This Approach

1. **Flexible** - Can define new parameter sets without changing an enum
2. **Self-documenting** - Parameters are explicit, not hidden behind an opaque ID
3. **Custom configs** - Users can create custom parameter combinations if needed
4. **Familiar** - Follows the existing Winterfell pattern
5. **Policy enforcement** - Verifiers can specify minimum security requirements via ranges

## Related

Part of the Plonky3 migration for miden-vm: https://github.com/0xMiden/miden-vm/pull/2472
