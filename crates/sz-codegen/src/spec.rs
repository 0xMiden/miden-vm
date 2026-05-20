//! Spec types describing the Schwartz-Zippel relation used by the modular-multiplication
//! verifiers.
//!
//! The model is deliberately flat. A [`LinearRelation`] is a static description of:
//!  - the polynomials involved (inputs, witnesses, constants, carry), with where they come from and
//!    how they are stored,
//!  - the polynomial identity that the verifier checks at a Fiat-Shamir-derived extension-field
//!    point,
//!  - any auxiliary checks beyond the identity (e.g., `c < p`, top carry coefficients are zero),
//!  - which polynomials the proc exposes back on the operand stack as the result.
//!
//! Realized instances: u256 `modmul_k1_base` and `modmul_k1_scalar`. The data model is generic
//! enough to describe the product, linear, constant, and signed-carry pieces of this modmul
//! family, but the emitter intentionally assumes the modmul verifier shape rather than trying
//! to be a general-purpose polynomial-identity compiler.

/// A polynomial appearing in the identity. The identity is always evaluated over u16 limbs
/// (W = 2^16); that is the only limb size for which the convolution stays inside the felt
/// field. Storage and operand-stack form may differ from u16 (see [`Storage`]).
#[derive(Clone, Copy, Debug)]
pub struct Poly {
    /// Identifier used in the identity equation and the emitted MASM (e.g. `"a"`, `"c"`,
    /// `"e_pos"`).
    pub name: &'static str,
    /// Where the polynomial's coefficients come from.
    pub role: PolyRole,
    /// Number of u16 coefficients in the polynomial as it enters the identity check. For inputs
    /// a, b in the k1 modmul specs this is 16 (8 u32 limbs split into 16 u16). For the carry
    /// polynomials it is 32 (with the top two coefficients of both signed halves enforced zero
    /// via [`AuxCheck::LimbIsZero`]).
    pub u16_coeff_count: usize,
    /// On-disk storage and load pattern for this polynomial.
    pub storage: Storage,
}

/// Where a polynomial's coefficients come from.
#[derive(Clone, Copy, Debug)]
pub enum PolyRole {
    /// Read from the operand stack at emit time; the host sees the coefficients via the event
    /// handler's `ProcessorState::get_stack_item`.
    OperandStack {
        /// Stack depth of the first limb. Subsequent limbs at increasing depth.
        depth_start: usize,
    },
    /// Provided by the host on the advice stack, then absorbed into memory + the FS hash via
    /// `adv_pipe`. Each landed felt is range-checked as u32.
    Witness,
    /// Compile-time constant baked into the emitted MASM as immediate `push.<u16>` sequences;
    /// no advice traffic.
    Constant {
        /// u16 limbs in little-endian order (limb 0 = least-significant).
        u16_limbs: &'static [u16],
    },
}

/// Memory and load conventions for a polynomial's coefficients.
#[derive(Clone, Copy, Debug)]
pub enum Storage {
    /// One felt per u16 coefficient. For advice-backed witness polynomials, each landed felt
    /// is range-checked as u32 by `adv_pipe`. Constant polynomials of this storage are baked
    /// into the emitted MASM as u16 immediates and need no runtime check. Per-witness
    /// soundness arguments (e.g., why non-canonical u32 coefficients are accepted) live with
    /// the concrete modmul specs, not here.
    PerU16,
    /// One felt per u32 limb, packing two adjacent u16 limbs per felt. The emitter inserts a
    /// `u32divmod.65536` split when the polynomial is evaluated at alpha via `horner_eval_base`.
    PerU32,
}

/// The polynomial identity the verifier checks. All terms are in the quadratic extension of the
/// Miden base field; the identity is `sum(products) + sum(linears) - (W - alpha) *
/// (carry.pos(alpha) - carry.neg(alpha)) = 0`.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// Quadratic terms: `sign * Pa(alpha) * Pb(alpha)`. Modmul has `[+ a*b, - q*p]`.
    pub products: &'static [Product],
    /// Linear terms: `sign * P(alpha)`. Modmul has `[- c]`.
    pub linears: &'static [Linear],
    /// The signed carry term `(W - alpha) * (pos(alpha) - neg(alpha))`; `multiplier` is the
    /// limb base (W = 2^16).
    pub carry: CarryTerm,
}

#[derive(Clone, Copy, Debug)]
pub struct Product {
    pub sign: Sign,
    pub lhs: PolyRef,
    pub rhs: PolyRef,
}

#[derive(Clone, Copy, Debug)]
pub struct Linear {
    pub sign: Sign,
    pub poly: PolyRef,
}

#[derive(Clone, Copy, Debug)]
pub struct CarryTerm {
    /// Non-negative carry polynomial. The verified signed carry is `pos - neg`, contributing
    /// `(W - x) * (pos(x) - neg(x))` to the RHS of the identity.
    pub pos: PolyRef,
    /// Second non-negative carry polynomial. Splitting the signed carry into two non-negative
    /// halves keeps each component u32-bounded; required for modular arithmetic where the
    /// natural recurrence can yield negative carries.
    pub neg: PolyRef,
    /// The limb base. Equal to 2^16 for the u16-limb SZ family.
    pub multiplier: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sign {
    Plus,
    Minus,
}

/// Reference to a polynomial by name. Resolved against [`LinearRelation::polys`] at emit time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyRef(pub &'static str);

/// Auxiliary check beyond the polynomial identity itself. These cover invariants the SZ identity
/// doesn't capture by itself (or for which an explicit assertion gives unconditional rather than
/// probabilistic enforcement).
#[derive(Clone, Copy, Debug)]
pub enum AuxCheck {
    /// Assert `poly[index] == 0`.
    LimbIsZero { poly: PolyRef, index: usize },
    /// Assert `lhs(W) < rhs(W)` interpreting both polynomials as integers in W-base.
    LessThan { lhs: PolyRef, rhs: PolyRef },
}

/// Specifies how a polynomial is exposed back on the operand stack as the proc's result.
#[derive(Clone, Copy, Debug)]
pub struct Output {
    pub poly: PolyRef,
    pub form: OutputForm,
}

#[derive(Clone, Copy, Debug)]
pub enum OutputForm {
    /// Recombine adjacent u16 coefficients into u32 limbs and push them onto the operand stack.
    /// The emitter inserts `u32assert2` as it emits the recombined limbs; the polynomial's
    /// `u16_coeff_count` must be even.
    U32Limbs,
}

/// Static description of an SZ modmul verifier relation. The emitter consumes one of these and
/// produces a fully-specialized MASM proc; per-instance cost differences come from spec-level
/// differences (different constants, polys, terms, or aux checks) rather than runtime branching
/// in the emitted code.
#[derive(Clone, Copy, Debug)]
pub struct LinearRelation {
    /// Generated proc name (e.g., `"modmul_k1_base"`).
    pub name: &'static str,
    /// MASM signature emitted on the `pub proc` line, e.g.
    /// `"(b: u256, a: u256) -> u256"` for `modmul_k1_base`. Kept as a literal string because
    /// MASM type syntax isn't trivially derivable from `polys` and `expose`.
    pub signature: &'static str,
    /// All polynomials referenced by `identity`, `aux_checks`, or `expose`. Order is significant
    /// for memory layout: polys are laid out in this order starting after the FS-challenge slots.
    pub polys: &'static [Poly],
    pub identity: Identity,
    pub aux_checks: &'static [AuxCheck],
    pub expose: &'static [Output],
}
