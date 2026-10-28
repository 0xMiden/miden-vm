The Eidos VM fixture executes `begin push.5 push.8 add drop end`, assembled with the source name
`advice_fixture`, an empty kernel, and zero stack inputs and outputs. The `.bin` file is a canonical
serialized `VmProof`, including its authenticated precompile root. The `.program` file is the
canonical serialized program root used to reconstruct its execution claim.

The advice regression verifies this proof natively and checks the digest of the complete packaged
advice. It runs without the prover feature.

To regenerate into a separate directory:

```sh
MIDEN_VM_FIXTURE_OUTPUT_DIR=/tmp/miden-vm-advice-fixture cargo nextest run --locked \
  --cargo-profile test-dev -p miden-vm-stark --features concurrent,prover \
  --run-ignored only -E 'test(regenerate_vm_advice_fixture)'
```

Review the output before replacing these files. Regeneration uses one Rayon worker so proof-of-work
selection is deterministic.
