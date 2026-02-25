//! Input layout definitions for ACE circuit evaluation.
//!
//! The layout mirrors the MASM verifier READ section: values are stored as
//! extension-field elements in point-major order (all openings at `zeta`
//! followed by all openings at `g * zeta`). Auxiliary trace and quotient
//! chunk openings are provided as base-field coordinates and merged into
//! extension elements inside the ACE circuit.
//!
//! All offsets and widths in this module are measured in extension-field (EF)
//! elements. One EF element occupies two base-field elements.
//!
//! Besides the AIR constraints themselves, the ACE circuit computes:
//! - Randomness expansion from `(alpha, beta)` into the full challenge vector `[alpha, 1, beta,
//!   beta^2, ...]`.
//! - Auxiliary/quotient coordinate merges to recover extension-field values.
//! - Periodic column evaluations from `z_k`.
//! - Selector polynomial evaluations and vanishing inverses.
//! - Lagrange-kernel weights and shifts for quotient chunk recomposition.
//! - Constraint folding with the composition challenge and final root check.
//!
//! The current "stark vars" block is sufficient to derive both selector
//! polynomials and the Lagrange-kernel weights used in quotient chunk
//! recomposition:
//! - Selector evaluations:
//!   - `inv_vanishing = 1 / (z^N - 1)`
//!   - `is_first = (z^N - 1) * inv(z - 1)`
//!   - `is_last  = (z^N - 1) * inv(z - g^{-1})`
//!   - `is_transition = z - g^{-1}`
//! - Lagrange kernel inputs:
//!   - `s0 = offset^N` and `g = subgroup_gen^N` define the shifts `s_i = s0 * g^i`.
//!   - `weight0 = 1 / (k * s0^{k-1})` gives barycentric weights `weight_i = weight0 * g^i` for the
//!     chunk recomposition kernel.
//! - `z_k` is used to evaluate periodic columns inside the circuit.
//!
//! Layout order (both Native and Masm):
//! 1) public_values
//! 2) randomness (direct or expanded alpha/beta)
//! 3) main_curr
//! 4) aux_curr
//! 5) quotient_curr
//! 6) main_next
//! 7) aux_next
//! 8) quotient_next
//! 9) aux_bus_boundary
//! 10) stark_vars
//!
//! Notes:
//! - `quotient_next` is included in the READ layout and is mapped via
//!   `InputKey::QuotientChunkCoord` with `offset = 1`.
//! - `stark_vars` reserves at least 14 EF slots for the canonical verifier inputs. Extra slots are
//!   left available for future aux inputs.

mod keys;
mod plan;
mod policy;

pub use keys::InputKey;
pub(crate) use keys::InputKeyMapper;
pub use plan::{InputCounts, InputLayout};
pub(crate) use plan::{InputRegion, LayoutRegions, StarkVarIndices};
