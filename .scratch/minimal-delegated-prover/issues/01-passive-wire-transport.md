# 01 — Replace hydrated proof transport with passive wire

**What to build:** Starting cleanly from baseline `12fee12d24b2d7a894e030723d5ef25087e73394`, make a deferred execution proof an infallibly encodable, registry-free transport artifact containing passive canonical wire. A caller can decode the proof without a registry and explicitly hydrate its wire through the sole bundled-registry façade function to obtain a semantically valid singleton precompile witness.

**Blocked by:** None — can start immediately.

**Status:** resolved

- [ ] Begin from the exact fetched baseline `12fee12d24b2d7a894e030723d5ef25087e73394`; do not copy, cherry-pick, patch forward, or incrementally clean the detached prototype ending at `4b42edb73`.
- [ ] Represent deferred execution proofs as `ExecutionProof::Deferred { vm, precompile: DeferredStateWire }` while retaining `Complete { vm, precompile: Option<PrecompileProof> }` and the public variants.
- [ ] Make `ExecutionProof::to_bytes` infallible and `ExecutionProof::read_from_bytes(&[u8])` registry-free.
- [ ] Add `precompile_witness_from_wire(&DeferredStateWire)` as the sole public hydration helper; it uses the bundled registry, rehydrates and semantically validates the wire, and returns a singleton witness.
- [ ] Delete witness byte transport, registry-aware execution-proof decoding, the redundant façade decoder, and transport errors made obsolete by infallible encoding.
- [ ] Derive Serde directly for `StarkProof`, `VmProof`, `PrecompileProof`, `WireEntry`, and `DeferredStateWire`; delete the custom Serde visitors they replace.
- [ ] Keep generic Serde round trips representation-preserving without claiming that generic Serde decoding is allocation-bounded.
- [ ] Preserve early canonical-decoder checks for `MAX_STARK_PROOF_BYTES`, `MAX_PRECOMPILE_ROOTS`, and `MAX_DEFERRED_ELEMENTS` before allocating declared payloads or collections.
- [ ] Preserve correct canonical minimum sizes: 2-byte `StarkProof`, 34-byte `VmProof`, 35-byte singleton `PrecompileProof`, and successful exact-budget decoding of a 71-byte vector containing two singleton precompile proofs.
- [ ] Make deferred-wire entries private, reduce `WireEntry` to crate plumbing, and stop re-exporting it as a public construction interface.
- [ ] Canonical and Serde round trips cover all proof and wire artifacts; canonical decoders reject oversized declarations before allocation; hydration accepts bundled-registry wires and rejects malformed or semantically invalid wires.
- [ ] Do not add a transport abstraction, registry provider, hydration service, intermediate transport type, helper module, dependency, feature flag, or compatibility wrapper.
- [ ] Delete replaced implementation in this ticket. Do not leave the old transport or hydration path for a later cleanup ticket.
- [ ] Record an incremental and cumulative simplification ledger against `12fee12d2`: production Rust/MASM additions and deletions separately from tests/docs, public symbols added and removed, concepts and validity seams added and removed, and retained hidden plumbing with concrete callers.
- [ ] The cumulative production Rust/MASM delta is strictly net-negative, the public interface is smaller, and every production addition directly replaces more old implementation. Otherwise stop and report the blocker rather than adding complexity.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

Implemented passive deferred-proof transport from baseline `12fee12d2` by replacing hydrated witness storage with `DeferredStateWire`, deleting witness byte transport and registry-aware proof decoding, deriving Serde directly, privatizing wire construction plumbing, and adding the sole bundled-registry hydration façade. Existing canonical wire hydration and state conversion logic were reused; no new abstraction or error layer was added.

Simplification at ticket close: 16 tracked files changed with 245 additions and 1,313 deletions before commit (net −1,068 raw lines). The largest deletion was the custom wire Serde visitor hierarchy. Public transport errors, witness codecs, the façade decoder, witness access, and public `WireEntry` construction disappeared.

Validation was intentionally narrow:

- `cargo check -p miden-vm --all-targets --features concurrent,executable,internal,testing` passed.
- Ten focused `miden-core` canonical transport, Serde representation, minimum-size, framing, and early declaration-limit tests passed.

Proof-generating lifecycle tests were deferred until tickets 02–03 stabilize their behavior.
