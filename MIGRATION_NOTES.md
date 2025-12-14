# Plonky3 Migration Notes

## Scope
- Branch: `al-migrate-p3-ver2` (based off `next`).
- Reference branch: `al-e2e-p3-integration-backup-2025-12-13` for Plonky3-specific code only.

## Key Principles
- Do **not** bring back the old winterfell dependencies.
- Primary areas to port from the backup branch:
  1. Prover/verifier integration (Plonky3-based).
  2. AIR builder / constraint changes compatible with Plonky3.
  3. Auxiliary trace building logic.
- Everything else comes from `next` unless an API change is required for Plonky3.
- Temporarily set `NUM_RANDOM_ROWS = 0` (will be removed later once Plonky3 prover is fully wired).

## Dependency Layout
- `miden-crypto` from Git (branch `al-e2e-plonky3`).
- All `p3-*` crates from `https://github.com/0xMiden/Plonky3` branch `zz/migrate-plonky3`.
- No `winter-*` crates anywhere in the workspace.

## Migration Steps
1. Root manifests updated: remove winter deps, add Plonky3 deps.
2. Crate manifests cleaned:
   - `miden-core`, `processor`, `air`, `prover`, `verifier`, `test-utils`, etc. no longer reference `winter-*`.
3. Code porting order:
   1. `miden-core` (mast, utils, event IDs, etc.).
   2. `air` constraints + AIR builder traits.
   3. Processor aux trace builders + Plonky3-compatible trace adapters.
   4. Prover & verifier wiring against Plonky3.
4. Use `al-e2e-p3-integration-backup-2025-12-13` as reference only for the Plonky3-specific sections; otherwise stick to `next` logic.

## Misc
- Keep this file updated if new constraints arise.
- Once Plonky3 prover/verifier fully working, delete or archive these notes.

## Additional Guidance
- Field arithmetic must use the Plonky3 traits (`p3_field`’s `Field`, `ExtensionField`, etc.) as done in `al-e2e-p3-integration-backup-2025-12-13`; do not reintroduce `winter_math::` / ``.
- Regularly compare against `next` and keep code identical unless a deviation is required for the Plonky3 migration; document any intentional differences.
