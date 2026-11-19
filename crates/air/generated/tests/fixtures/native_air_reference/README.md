# AIR compatibility fixtures

The active tests in [native_air_reference.rs](../../native_air_reference.rs) compare the ordered
VM and PVM AIR registries, declared dimensions, period lengths, and assertion counts. They also
rebuild the recursive ACE circuits and fixed setup commitments from the authored AIRs and check
explicit protocol identities, PVM raw widths, and quotient allocation.

`reference.txt` is the byte-for-byte historical handoff attributed to source revision
`b87fa2b33acdc908b66be77c3bcf252858214a7d` and observer revision
`092a6a9834216e51c795a194a282f3b0ddd96faf`. Its SHA-256 is
`2ffa5cda0fec36c05d4e1e5a6ba88df3533043065d2bf0bce739d0aae90f7581`.
The file also records the historical lockfile hash. The active tests compare explicit fields.
Opaque hashes and sample observations lack independent framing or inputs, so witness behavior,
polynomial equivalence, and Fiat–Shamir call order require separate validation.

`next.txt` overrides the VM Core assertion count and VM protocol identity fields with values
pinned at upstream revision `38b8e6ea819ff856f90b8f7d8c00ffcc3c66ca72` after decoder PR #4239.
