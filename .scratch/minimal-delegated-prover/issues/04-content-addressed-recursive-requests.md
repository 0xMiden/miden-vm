# 04 — Restore content-addressed recursive proof requests

**What to build:** Restore the existing recursive request contract so the claim commitment and verifier identity derive a proof request key, the proof stream is registered under that key, the VM fetches it through the advice map, and `verify_vm_proof` verifies it without an erroneous 40-value proof-stream copy.

**Blocked by:** 01 — Replace hydrated proof transport with passive wire.

**Status:** resolved

- [ ] Restore and use `generate_request_inputs` for the production recursive request flow.
- [ ] Package recursive inputs through `CLAIM_COMMITMENT → proof_request_key → adv.push_mapval → verify_vm_proof`.
- [ ] Leave the proof stream unchanged in the request package, store the claim preimage separately under its commitment, and store kernel procedure digests under the kernel commitment.
- [ ] Remove the stale 40-value advice copy; `verify_vm_proof` authenticates and materializes the claim preimage itself.
- [ ] Recursive verification selects the VM proof component and returns the authenticated outstanding deferred root; it does not recursively verify or settle a precompile proof.
- [ ] Native and MASM request-key derivation agree, map lookup retrieves the registered package, and claim substitution fails.
- [ ] The equal-heights and hash-heavy divergent-heights recursive proof-request regressions pass through the coherent content-addressed request contract.
- [ ] Delete stale direct-call packaging logic wherever it conflicts with the request contract; do not preserve two production request ABIs.
- [ ] Do not add a packaging abstraction, request service, transport trait, new recursive interface, dependency, feature flag, or compatibility wrapper.
- [ ] Record incremental and cumulative production Rust/MASM deltas, public-symbol changes, concept changes, and validity-seam changes against `12fee12d2`.
- [ ] This ticket should be a small net deletion. The cumulative production delta must remain strictly net-negative; otherwise stop and report the blocker instead of reorganizing the recursive verifier.
- [x] Do not push, modify PR #3437, post replies, or resolve/minimize review threads.

## Answer

Production request packaging and MASM verification were already correct. The stale integration helper mixed request packaging with the obsolete direct-advice ABI, copying the first 40 proof values to dead claim memory.

Reused the existing `generate_request_inputs` and canonical request flow:

`CLAIM_COMMITMENT → procref(verify_vm_proof) → build_proof_request_key → adv.push_mapval → verify_vm_proof`.

Deleted the local 40-value copy procedure and did not add any request abstraction, helper, ABI, or production code.

Ticket delta: one integration file changed with 7 additions and 30 deletions. Both required recursive regressions passed together under one eight-thread Rayon pool and one nextest test thread. No additional proof-generating request suites were run.
