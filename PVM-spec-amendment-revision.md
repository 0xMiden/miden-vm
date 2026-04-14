## Section 1 — Unified diff

```diff
--- a/discussion-3005-comment-1.md  (original)
+++ b/discussion-3005-comment-1.md  (revised, Miden-native layout)
@@ -1,6 +1,8 @@
 # Transcript Evaluation AIR Specification
  
 **Version:** 0 (initial)
+
+*Layout amendment: sponge state reordered to Miden-native `[RATE, CAPACITY]` convention (see §3). No cryptographic change; pure relabeling.*
  
 ---
  
@@ -10,7 +12,7 @@
  
 The design is organized around a single **eval chip** that recursively resolves commitment hashes into typed values, dispatching to auxiliary chips for arithmetic, group operations, Keccak hashing, and chunk management. All inter-chip communication uses LogUp bus arguments over fixed-width tuples.
  
-The hash function is **RPO** (Rescue Prime Optimized), permutation width **12**, capacity **4**, rate **8**. All hash outputs are 4 field elements extracted from capacity positions `[0..4]` after permutation.
+The hash function is **RPO** (Rescue Prime Optimized), permutation width **12**, capacity **4**, rate **8**. The state layout is Miden-native: rate at `state[0..8]`, capacity at `state[8..12]`. All hash outputs are the 4 field elements of the first rate word extracted from positions `[0..4]` after permutation — Miden's standard `DIGEST_RANGE` (= `RATE0'`).
  
 **ZERO_HASH** = `[0, 0, 0, 0]` is the trivial base case, evaluating to `Value::True`.
  
@@ -65,16 +67,16 @@
  
 ## 3. Hash preimage layout
  
-Every node in the transcript tree is committed via RPO over a 12-felt preimage:
+Every node in the transcript tree is committed via RPO over a 12-felt preimage. The state uses Miden's native `[RATE, CAPACITY]` ordering, so a Miden hasher chiplet call can consume the preimage directly without any felt reshuffling:
  
 ```
-index:  0        1        2        3        4 ........ 11
-        tag_id   param_a  param_b  version  val[8]
-        ──────── capacity ────────────────   ── rate ──
+index:  0 ................ 7        8        9        10       11
+        val[8]                      tag_id   param_a  param_b  version
+        ────── rate ──────          ─────────── capacity ─────────────
 ```
  
-- `version` (position 3): fixed constant `CURRENT_VERSION`. The eval chip rejects any node where the version does not match. This enables future spec upgrades: bumping the version invalidates all prior proofs.
-- `val[8]` (positions 4–11): for most tags, this is `lhs_hash[4] || rhs_hash[4]`. For KeccakDigestLeaf, it is the 8-felt digest.
-- The hash output is `RPO(preimage)[0..4]`.
+- `val[8]` (positions 0–7, the rate): for most tags, this is `lhs_hash[4] || rhs_hash[4]`. For KeccakDigestLeaf, it is the 8-felt digest.
+- `tag_id`, `param_a`, `param_b` (positions 8, 9, 10, in the capacity): node-shape discriminators (see §4).
+- `version` (position 11): fixed constant `CURRENT_VERSION`. The eval chip rejects any node where the version does not match. This enables future spec upgrades: bumping the version invalidates all prior proofs.
+- The hash output is `RPO(preimage)[0..4]` — the first rate word post-permutation, which is Miden's `DIGEST_RANGE` convention.
  
 ---
  
@@ -93,7 +95,7 @@
 | 6 | `group_ty` | `op` (0–2) | GroupBinOp |
 | 7 | `len_bytes` | 0 | Keccak |
  
-**Tag 1 (Chunk)** is reserved for chunk sponge initialization. The initial sponge capacity is `(1, 0, 0, CURRENT_VERSION)`. This tag never appears as a node in the eval chip.
+**Tag 1 (Chunk)** is reserved for chunk sponge initialization. Under the Miden-native layout the initial capacity lives at `state[8..12]` and is set to `state[8] = 1` (tag), `state[9] = 0`, `state[10] = 0`, `state[11] = CURRENT_VERSION`. This tag never appears as a node in the eval chip.
  
 ### Parameter constraints
  
@@ -298,10 +300,10 @@
 ### 7.2 Hash (width 16)
  
 ```
-digest[4]  cap[4]  val[8]
+digest[4]  val[8]  cap[4]
 ```
  
-One-shot node hashing. Semantics: `RPO(cap[4] || val[8])` has capacity output `digest[4]`.
+One-shot node hashing. Semantics: `RPO(val[8] || cap[4])` has `DIGEST_RANGE` output `digest[4]`, where `val[8]` is the input rate at `state[0..8]`, `cap[4]` is the input capacity at `state[8..12]`, and `digest[4]` is `state[0..4]` post-permutation (the first rate word = Miden's `DIGEST_RANGE`). The bus tuple width is 16 felts.
  
 Provider: permutation chip. Consumer: eval chip.
  
@@ -308,10 +310,10 @@
 ### 7.3 Absorb (width 16)
  
 ```
-cap[4]  cap_prev[4]  val[8]
+cap[4]  val[8]  cap_prev[4]
 ```
  
-Sponge chaining. Semantics: `RPO(cap_prev[4] || val[8])` has capacity output `cap[4]`.
+Sponge chaining. Semantics: `RPO(val[8] || cap_prev[4])` has `CAPACITY_RANGE` output `cap[4]`, where `val[8]` is the rate input at `state[0..8]`, and `cap_prev` / `cap` both live at `state[8..12]` (the capacity slot). The bus tuple width is 16 felts.
  
 Provider: permutation chip. Consumer: chunk chip.
  
@@ -380,7 +382,7 @@
  
 ### 8.1 Permutation chip
  
-Computes `RPO(state) → output` for width-12 inputs. Provides Hash and Absorb tuples. The permutation chip has no semantic awareness of tags, versions, or parameter validity — it is purely the algebraic permutation.
+Computes `RPO(state) → output` for width-12 inputs in Miden-native `[RATE, CAPACITY]` order (rate at `state[0..8]`, capacity at `state[8..12]`). Provides Hash and Absorb tuples. Because the state layout matches Miden's hasher chiplet verbatim, a PVM implementer can copy the Poseidon2/RPO round-constraint structure directly from `air/src/constraints/chiplets/hasher*`. The permutation chip has no semantic awareness of tags, versions, or parameter validity — it is purely the algebraic permutation.
  
 ### 8.2 Field chip
  
@@ -402,9 +404,9 @@
  
 Manages the sponge construction for chunk data. Given a sequence of N chunks:
  
-1. Initializes sponge capacity: `(1, 0, 0, CURRENT_VERSION)` — tag 1 is the Chunk domain separator
+1. Initializes capacity at `state[8..12]` to `(1, 0, 0, CURRENT_VERSION)` — tag 1 is the Chunk domain separator
 2. For each chunk `i ∈ 0..N`: absorbs 8 felts via the Absorb bus
-3. Extracts digest = final `cap[0..4]`
+3. Extracts digest = final `state[0..4]` post-permutation (the first rate word, matching Miden's `DIGEST_RANGE`)
  
 The chunk chip allocates a `ptr` for each chunks object. This is the same `ptr` that appears in the KeccakDigest and Chunks bindings and in KeccakEval — it is the shared identifier that ties the digest to its input data (see §6.7).
```

## Section 2 — Changelog

- **Header (under "Version: 0 (initial)")**: added a one-line italicized amendment note flagging that the spec has been relabeled to Miden-native `[RATE, CAPACITY]` ordering. Needed so a reader of the published comment immediately sees this is a layout amendment and not an unrelated revision.
- **§1 Overview, hash-function paragraph**: "extracted from capacity positions `[0..4]` after permutation" → explicit statement that rate lives at `state[0..8]` and capacity at `state[8..12]`, and that the digest is the first rate word post-permutation (Miden's `DIGEST_RANGE` = `RATE0'`). Needed because the whole premise of the amendment is that positions `[0..4]` are the *rate*, not the capacity.
- **§3 Hash preimage layout, intro sentence**: added "The state uses Miden's native `[RATE, CAPACITY]` ordering, so a Miden hasher chiplet call can consume the preimage directly without any felt reshuffling" — states the design intent up front, right next to the diagram it governs.
- **§3 ASCII diagram**: flipped so `val[8]` occupies indices 0..7 (labeled `rate`) and `[tag_id, param_a, param_b, version]` occupies indices 8..11 (labeled `capacity`). This is the core relabeling of felt positions.
- **§3 bullets**: reordered so rate comes first; `val[8]` now cited as "positions 0–7, the rate"; added a new bullet listing `tag_id/param_a/param_b` at positions 8–10; `version` moved from "position 3" to "position 11". Bullet about `RPO(preimage)[0..4]` expanded to say the formula is unchanged but the prose now calls it "the first rate word post-permutation, which is Miden's `DIGEST_RANGE` convention."
- **§4 Tag 1 (Chunk) note**: "The initial sponge capacity is `(1, 0, 0, CURRENT_VERSION)`" → explicit "Under the Miden-native layout the initial capacity lives at `state[8..12]` and is set to `state[8] = 1` (tag), `state[9] = 0`, `state[10] = 0`, `state[11] = CURRENT_VERSION`." The 4 felts of the IV are unchanged; only their state positions are called out.
- **§7.2 Hash bus, tuple diagram**: column order flipped from `digest[4] cap[4] val[8]` to `digest[4] val[8] cap[4]` to match the Miden-native input ordering (rate first, capacity last). Width stays 16.
- **§7.2 Hash bus, semantics sentence**: `RPO(cap[4] || val[8]) has capacity output digest[4]` → `RPO(val[8] || cap[4]) has DIGEST_RANGE output digest[4]`, with an explicit gloss of which state slice each tuple lives in and a restatement that the bus tuple width is 16.
- **§7.3 Absorb bus, tuple diagram**: column order flipped from `cap[4] cap_prev[4] val[8]` to `cap[4] val[8] cap_prev[4]` for consistency with §7.2. Width stays 16.
- **§7.3 Absorb bus, semantics sentence**: `RPO(cap_prev[4] || val[8]) has capacity output cap[4]` → `RPO(val[8] || cap_prev[4]) has CAPACITY_RANGE output cap[4]`, naming `state[8..12]` as the capacity slot. Width gloss restated.
- **§8.1 Permutation chip**: added an explicit sentence that the state is in Miden-native `[RATE, CAPACITY]` order with rate at `state[0..8]` and capacity at `state[8..12]`, and a pointer to `air/src/constraints/chiplets/hasher*` for direct round-constraint reuse. Needed so a PVM implementer knows they can copy Miden's hasher constraint code structurally.
- **§8.4 Chunk chip step 1**: "Initializes sponge capacity: `(1, 0, 0, CURRENT_VERSION)`" → "Initializes capacity at `state[8..12]` to `(1, 0, 0, CURRENT_VERSION)`". Clarifies the position of the IV without changing its contents.
- **§8.4 Chunk chip step 3**: "Extracts digest = final `cap[0..4]`" → "Extracts digest = final `state[0..4]` post-permutation (the first rate word, matching Miden's `DIGEST_RANGE`)". Under the old layout `cap[0..4]` was positions 0..3; under Miden-native those positions are now the first rate word, so the phrase `cap[0..4]` would be ambiguous / wrong.

Unchanged (by design): all tag IDs, value variants, parameter semantics, bus widths, the eval-chip dispatch logic in §6, the `RPO(preimage)[0..4]` formula itself, §7.1/§7.4–§7.9 bus definitions, §8.2/§8.3/§8.5 chip descriptions, the §9 bus summary table, and the `ZERO_HASH` base case. The pure-relabeling property is preserved: every felt at a semantic position in the original appears at the same semantic position in the revision; only the state *index* labels change.

## Section 3 — Full revised comment (for copy-paste)

# Transcript Evaluation AIR Specification
 
**Version:** 0 (initial)

*Layout amendment: sponge state reordered to Miden-native `[RATE, CAPACITY]` convention (see §3). No cryptographic change; pure relabeling.*
 
---
 
## 1. Overview
 
This document specifies an Algebraic Intermediate Representation (AIR) for verifying cryptographic transcripts. The system proves that a transcript—a tree of commitments to field elements, group elements, Keccak digests, and assertions—evaluates correctly under a fixed set of algebraic and hashing rules.
 
The design is organized around a single **eval chip** that recursively resolves commitment hashes into typed values, dispatching to auxiliary chips for arithmetic, group operations, Keccak hashing, and chunk management. All inter-chip communication uses LogUp bus arguments over fixed-width tuples.
 
The hash function is **RPO** (Rescue Prime Optimized), permutation width **12**, capacity **4**, rate **8**. The state layout is Miden-native: rate at `state[0..8]`, capacity at `state[8..12]`. All hash outputs are the 4 field elements of the first rate word extracted from positions `[0..4]` after permutation — Miden's standard `DIGEST_RANGE` (= `RATE0'`).
 
**ZERO_HASH** = `[0, 0, 0, 0]` is the trivial base case, evaluating to `Value::True`.
 
---
 
## 2. Type system
 
### 2.1 Field types
 
Both curves share the same prime field Fp. There are no extension fields in this system. The four field types exist to enforce semantic separation between base and scalar field roles for each curve.
 
| `field_ty` | Semantics |
|------------|-----------|
| 0 | base field, curve A |
| 1 | scalar field, curve A |
| 2 | base field, curve B |
| 3 | scalar field, curve B |
 
### 2.2 Field element encoding
 
The field chip stores each field element as a sequence of u16 limbs in little-endian order. The field chip internally range-checks each limb to `[0, 2^16)` and verifies that the overall value is canonical in the field (i.e., less than the field modulus).
 
When providing a FieldLookup, the field chip constructs the 8-felt `val[8]` representation by linearly combining adjacent pairs of u16 limbs into u32 values: `val[i] = limb[2i] + limb[2i+1] * 2^16`. This u32-LE encoding matches the preimage layout, so the 8 rate felts in a FieldLeaf node are exactly the u32-LE representation of the field element.
 
When providing values to the FieldEval relation (arithmetic operations), the field chip provides the raw u16 limbs directly. This gives the field operation chip access to the fine-grained limb structure needed for carrying and overflow handling during addition, subtraction, and multiplication.
 
### 2.3 Group types
 
| `group_ty` | Curve | `base_field_ty(group_ty)` |
|------------|-------|---------------------------|
| 0 | curve A | 0 |
| 1 | curve B | 2 |
 
Group elements are represented in affine coordinates `(x, y)` where both coordinates are base-field elements. The point at infinity is encoded as `(0, 0)`; the group chip handles identity cases internally.
 
The function `base_field_ty(group_ty)` is a fixed map used by the GroupCreate arm and must be a named constant in the AIR.
 
### 2.3 Value variants
 
The eval chip produces and consumes **bindings** that associate a 4-felt hash with a typed value:
 
| `value_tag` | Name | Payload |
|-------------|------|---------|
| 0 | True | (none) |
| 1 | Field | `field_ty`, `ptr` |
| 2 | Group | `group_ty`, `ptr` |
| 3 | KeccakDigest | `ptr` |
| 4 | Chunks | `n_chunks`, `ptr` |
 
Pointers are opaque felt-valued identifiers owned by the respective chip. Pointer equality implies value equality: the chips must enforce canonical pointer assignment.
 
---
 
## 3. Hash preimage layout
 
Every node in the transcript tree is committed via RPO over a 12-felt preimage. The state uses Miden's native `[RATE, CAPACITY]` ordering, so a Miden hasher chiplet call can consume the preimage directly without any felt reshuffling:
 
```
index:  0 ................ 7        8        9        10       11
        val[8]                      tag_id   param_a  param_b  version
        ────── rate ──────          ─────────── capacity ─────────────
```
 
- `val[8]` (positions 0–7, the rate): for most tags, this is `lhs_hash[4] || rhs_hash[4]`. For KeccakDigestLeaf, it is the 8-felt digest.
- `tag_id`, `param_a`, `param_b` (positions 8, 9, 10, in the capacity): node-shape discriminators (see §4).
- `version` (position 11): fixed constant `CURRENT_VERSION`. The eval chip rejects any node where the version does not match. This enables future spec upgrades: bumping the version invalidates all prior proofs.
- The hash output is `RPO(preimage)[0..4]` — the first rate word post-permutation, which is Miden's `DIGEST_RANGE` convention.
 
---
 
## 4. Tag enumeration
 
| `tag_id` | `param_a` | `param_b` | Name |
|----------|-----------|-----------|------|
| 0 | 0 | 0 | Transcript |
| 1 | 0 | 0 | Chunk |
| 2 | `field_ty` | 0 | FieldLeaf |
| 3 | 0 | 0 | KeccakDigestLeaf |
| 4 | `field_ty` | `op` (0–3) | FieldBinOp |
| 5 | `group_ty` | 0 | GroupCreate |
| 6 | `group_ty` | `op` (0–2) | GroupBinOp |
| 7 | `len_bytes` | 0 | Keccak |
 
**Tag 1 (Chunk)** is reserved for chunk sponge initialization. Under the Miden-native layout the initial capacity lives at `state[8..12]` and is set to `state[8] = 1` (tag), `state[9] = 0`, `state[10] = 0`, `state[11] = CURRENT_VERSION`. This tag never appears as a node in the eval chip.
 
### Parameter constraints
 
The eval chip enforces these for each tag:
 
- Tags 0, 1, 3: `param_a = 0`, `param_b = 0`
- Tags 2, 7: `param_b = 0`
- Tag 4: `param_b ∈ {0, 1, 2, 3}`
- Tag 5: `param_b = 0`
- Tag 6: `param_b ∈ {0, 1, 2}`
 
---
 
## 5. Operations
 
### 5.1 Field operations
 
| `op` | Name | Semantics |
|------|------|-----------|
| 0 | Add | `out = lhs + rhs` |
| 1 | Sub | `out = lhs - rhs` |
| 2 | Mul | `out = lhs * rhs` |
| 3 | Eq | `assert lhs_ptr == rhs_ptr` (pointer equality) |
 
There is no division primitive. To prove `a / b = c`, the transcript compiler emits `b * c = a` and witnesses `c`.
 
### 5.2 Group operations
 
| `op` | Name | Semantics |
|------|------|-----------|
| 0 | Add | elliptic curve addition |
| 1 | Sub | elliptic curve subtraction |
| 2 | Eq | `assert lhs_ptr == rhs_ptr` (pointer equality) |
 
There is no scalar multiplication primitive. The transcript compiler unrolls it into repeated group additions.
 
---
 
## 6. Eval chip logic
 
The eval chip takes a hash and resolves it into a binding. The entry point is the transcript root hash.
 
```
fn eval(hash: Hash) {
    if hash == ZERO_HASH {
        provide!(Binding { hash, value: True })
        return
    }
 
    let Node { tag, lhs, rhs } = resolve_hash(hash)   // Hash bus
 
    dispatch on tag...
}
```
 
### 6.1 Transcript (tag 0)
 
```
Tag::Transcript
 
require Binding(lhs, True)
require Binding(rhs, True)
provide Binding(hash, True)
```
 
Evaluating a transcript root recursively walks backward through the assertion chain until it reaches `ZERO_HASH`.
 
- `rhs` must be an assertion-like object, i.e. something that evaluates to `True`.
- `lhs` is the previous transcript prefix, which is either another assertion/transcript object returning `True`, or `ZERO_HASH` as the trivial base case.
 
The lhs and rhs are symmetric: canonical ordering of assertions is a compiler concern, not a verifier concern. A vacuous transcript (both children `ZERO_HASH`) is valid.
 
### 6.2 FieldLeaf (tag 2)
 
```
Tag::FieldLeaf { field_ty }
 
witness ptr
 
// Provided by the field table.
// Looks up the field object represented by this leaf opening.
require FieldLookup(field_ty, val[8], ptr)
 
provide Binding(hash, Field(field_ty, ptr))
```
 
The 8 rate felts from the node preimage are the u32-LE encoding of the field element (see §2.2). The field chip looks up the field object represented by this leaf opening and returns a canonical pointer.
 
### 6.3 KeccakDigestLeaf (tag 3)
 
```
Tag::KeccakDigestLeaf
 
witness ptr
provide Binding(hash, KeccakDigest(ptr))
```
 
This leaf binds the commitment `hash` to a Keccak digest object. The 8 rate felts in the preimage are the digest itself (8 u32-LE values = 256 bits).
 
The actual hashing semantics are not enforced here — they live in the Keccak arm (tag 7) via `KeccakEval`. This arm only witnesses the chip-owned digest pointer and binds this commitment to that digest object. The pointer `ptr` is the same identifier that the chunk chip uses when it provides the corresponding `Chunks` binding; this shared pointer is what ties the digest to a specific sequence of input chunks (see §6.7).
 
### 6.4 FieldBinOp (tag 4)
 
```
Tag::FieldBinOp { field_ty, op }
 
witness lhs_ptr, rhs_ptr
require Binding(lhs, Field(field_ty, lhs_ptr))
require Binding(rhs, Field(field_ty, rhs_ptr))
 
if op ∈ {Add, Sub, Mul}:
    witness out_ptr
    // Provided by the field table.
    require FieldEval(op, field_ty, lhs_ptr, rhs_ptr, out_ptr)
    provide Binding(hash, Field(field_ty, out_ptr))
 
if op == Eq:
    assert lhs_ptr == rhs_ptr
    provide Binding(hash, True)
```
 
For arithmetic operations, the field chip provides the evaluation. For equality, the prover must supply the same pointer for both operands; soundness relies on the field chip's canonical pointer assignment.
 
### 6.5 GroupCreate (tag 5)
 
```
Tag::GroupCreate { group_ty }
 
let base_ty = base_field_ty(group_ty)
witness x_ptr, y_ptr, group_ptr
require Binding(lhs, Field(base_ty, x_ptr))
require Binding(rhs, Field(base_ty, y_ptr))
// Provided by the group table.
// Binds coordinate field objects to a group object.
require GroupLookup(group_ty, x_ptr, y_ptr, group_ptr)
provide Binding(hash, Group(group_ty, group_ptr))
```
 
The group chip binds coordinate field objects to a group object and enforces that the point is on the curve.
 
### 6.6 GroupBinOp (tag 6)
 
```
Tag::GroupBinOp { group_ty, op }
 
witness lhs_ptr, rhs_ptr
require Binding(lhs, Group(group_ty, lhs_ptr))
require Binding(rhs, Group(group_ty, rhs_ptr))
 
if op ∈ {Add, Sub}:
    witness out_ptr
    // Provided by the group table.
    require GroupEval(op, group_ty, lhs_ptr, rhs_ptr, out_ptr)
    provide Binding(hash, Group(group_ty, out_ptr))
 
if op == Eq:
    assert lhs_ptr == rhs_ptr
    provide Binding(hash, True)
```
 
### 6.7 Keccak (tag 7)
 
```
Tag::Keccak { len_bytes }
 
witness ptr, n_chunks
require Binding(lhs, KeccakDigest(ptr))
require Binding(rhs, Chunks(ptr, n_chunks))
 
// Provided by the Keccak chip.
// Checks that hashing exactly `len_bytes` bytes from the chunks object
// identified by `ptr` yields the digest object identified by that same `ptr`.
require KeccakEval(ptr, len_bytes)
 
provide Binding(hash, True)
```
 
The critical mechanism here is the **shared pointer** between the digest and the chunks. Both the `KeccakDigest` binding (provided by a KeccakDigestLeaf node, §6.3) and the `Chunks` binding (provided by the chunk chip, §8.4) use the same `ptr`. This is what forces the digest to correspond to a specific sequence of input chunks: the Keccak chip, given `ptr`, can look up both the digest value and the chunk data under that pointer, and verify that hashing the chunks actually produces the digest.
 
The Keccak chip owns the relationship between digests and chunks. The eval chip's role is only to require that the three pieces (digest binding, chunks binding, and Keccak verification) all agree on the same `ptr`.
 
---
 
## 7. Bus relations
 
All inter-chip communication is via LogUp arguments over fixed-width tuples. Each relation has exactly one provider side and one consumer side, except Binding where the eval chip is both.
 
### 7.1 Binding (width 7)
 
```
              h[4]   value_tag  aux        ptr
 
True:         h[4]   0          0          0
Field:        h[4]   1          field_ty   ptr
Group:        h[4]   2          group_ty   ptr
KeccakDigest: h[4]   3          0          ptr
Chunks:       h[4]   4          n_chunks   ptr
```
 
Unused positions are constrained to zero. The bus must balance: every provided tuple has a matching consumed tuple.
 
Provider: eval chip (`provide!`). Consumer: eval chip (`require!`).
 
### 7.2 Hash (width 16)
 
```
digest[4]  val[8]  cap[4]
```
 
One-shot node hashing. Semantics: `RPO(val[8] || cap[4])` has `DIGEST_RANGE` output `digest[4]`, where `val[8]` is the input rate at `state[0..8]`, `cap[4]` is the input capacity at `state[8..12]`, and `digest[4]` is `state[0..4]` post-permutation (the first rate word = Miden's `DIGEST_RANGE`). The bus tuple width is 16 felts.
 
Provider: permutation chip. Consumer: eval chip.
 
### 7.3 Absorb (width 16)
 
```
cap[4]  val[8]  cap_prev[4]
```
 
Sponge chaining. Semantics: `RPO(val[8] || cap_prev[4])` has `CAPACITY_RANGE` output `cap[4]`, where `val[8]` is the rate input at `state[0..8]`, and `cap_prev` / `cap` both live at `state[8..12]` (the capacity slot). The bus tuple width is 16 felts.
 
Provider: permutation chip. Consumer: chunk chip.
 
Hash and Absorb are the same permutation computation with different framing.
 
### 7.4 FieldLookup (width 10)
 
```
field_ty  val[8]  out_ptr
```
 
`val[8]` is the u32-LE encoding of the field element, constructed by the field chip from pairs of u16 limbs (see §2.2).
 
Provider: field chip. Consumer: eval chip (FieldLeaf arm).
 
### 7.5 FieldEval (width 5)
 
```
op  field_ty  lhs_ptr  rhs_ptr  out_ptr
```
 
`op ∈ {0, 1, 2}` (Add, Sub, Mul). Eq is not dispatched to the field chip.
 
Provider: field chip. Consumer: eval chip (FieldBinOp arithmetic arm).
 
### 7.6 GroupLookup (width 4)
 
```
group_ty  x_ptr  y_ptr  group_ptr
```
 
Provider: group chip. Consumer: eval chip (GroupCreate arm).
 
### 7.7 GroupEval (width 5)
 
```
op  group_ty  lhs_ptr  rhs_ptr  out_ptr
```
 
`op ∈ {0, 1}` (Add, Sub). Eq is not dispatched to the group chip.
 
Provider: group chip. Consumer: eval chip (GroupBinOp arithmetic arm).
 
### 7.8 KeccakEval (width 2)
 
```
ptr  len_bytes
```
 
Provider: Keccak chip. Consumer: eval chip (Keccak arm).
 
### 7.9 ChunkVal (width 9)
 
```
chunk_ptr  val[8]
```
 
Where `chunk_ptr = base_ptr + i` for chunk index `i`.
 
Provider: chunk chip. Consumer: Keccak chip.
 
---
 
## 8. Auxiliary chips
 
### 8.1 Permutation chip
 
Computes `RPO(state) → output` for width-12 inputs in Miden-native `[RATE, CAPACITY]` order (rate at `state[0..8]`, capacity at `state[8..12]`). Provides Hash and Absorb tuples. Because the state layout matches Miden's hasher chiplet verbatim, a PVM implementer can copy the Poseidon2/RPO round-constraint structure directly from `air/src/constraints/chiplets/hasher*`. The permutation chip has no semantic awareness of tags, versions, or parameter validity — it is purely the algebraic permutation.
 
### 8.2 Field chip
 
Owns a table of field elements indexed by `(field_ty, ptr)`. Each element is stored as u16 limbs in little-endian order. The field chip:
 
- Range-checks each u16 limb to `[0, 2^16)`
- Verifies the value is canonical (less than the field modulus)
- Provides FieldLookup by combining pairs of u16 limbs into u32 values to match the preimage encoding: `val[i] = limb[2i] + limb[2i+1] * 2^16`
- Provides FieldEval using the raw u16 limbs for arithmetic
 
Must enforce canonical pointer assignment: distinct values get distinct pointers, equal values get the same pointer. This is the foundation of the Eq operation's soundness.
 
### 8.3 Group chip
 
Owns a table of group elements indexed by `(group_ty, ptr)`. Provides GroupLookup and GroupEval. GroupLookup enforces that the point is on the curve. Handles the point at infinity `(0, 0)` as the identity element. Must enforce canonical pointer assignment.
 
### 8.4 Chunk chip
 
Manages the sponge construction for chunk data. Given a sequence of N chunks:
 
1. Initializes capacity at `state[8..12]` to `(1, 0, 0, CURRENT_VERSION)` — tag 1 is the Chunk domain separator
2. For each chunk `i ∈ 0..N`: absorbs 8 felts via the Absorb bus
3. Extracts digest = final `state[0..4]` post-permutation (the first rate word, matching Miden's `DIGEST_RANGE`)
 
The chunk chip allocates a `ptr` for each chunks object. This is the same `ptr` that appears in the KeccakDigest and Chunks bindings and in KeccakEval — it is the shared identifier that ties the digest to its input data (see §6.7).
 
Provides Binding with `Value::Chunks { n_chunks, ptr }` onto the Binding bus, and ChunkVal for each `(base_ptr + i, val[8])`.
 
### 8.5 Keccak chip
 
Verifies that Keccak-256 applied to `len_bytes` bytes from a chunks object yields the associated digest. The Keccak chip ties together three pieces of data under a single `ptr`:
 
- The **digest**: 8 u32-LE felts representing the 256-bit Keccak output. These are the values committed in the KeccakDigestLeaf preimage (the 8 rate felts).
- The **input chunks**: a sequence of `n_chunks` chunks, each containing 8 u32-LE felts (32 bytes). These are accessed via ChunkVal lookups from the chunk chip.
- The **length**: `len_bytes`, which comes from the Keccak tag's `param_a`.
 
The chip consumes ChunkVal tuples from the chunk chip to read the input data, computes the Keccak-256 hash, and verifies it matches the digest. It provides KeccakEval tuples to confirm the result.
 
Encoding: each chunk of 8 felts represents 32 bytes as 8 little-endian u32 values, one per felt. The Keccak chip enforces:
 
- Each felt value lies in `[0, 2^32)`
- `n_chunks = ⌈len_bytes / 32⌉`
- Trailing bytes past `len_bytes` in the last chunk are zero (upper bytes of the boundary felt are masked, subsequent felts in that chunk are exactly zero)
- The 8-felt digest is also canonical u32-LE
 
---
 
## 9. Bus summary
 
| Relation | Width | Provider | Consumer |
|----------|-------|----------|----------|
| Binding | 7 | eval chip | eval chip |
| Hash | 16 | permutation chip | eval chip |
| Absorb | 16 | permutation chip | chunk chip |
| FieldLookup | 10 | field chip | eval chip |
| FieldEval | 5 | field chip | eval chip |
| GroupLookup | 4 | group chip | eval chip |
| GroupEval | 5 | group chip | eval chip |
| KeccakEval | 2 | Keccak chip | eval chip |
| ChunkVal | 9 | chunk chip | Keccak chip |
 
9 buses. Binding is the only self-referential bus.
