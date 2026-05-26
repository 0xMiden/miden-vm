//! Spec types describing the Schwartz-Zippel relation used by the modular-multiplication
//! verifiers.
//!
//! The model is deliberately flat. A [`LinearRelation`] is a static description of:
//!  - the polynomials involved (inputs, witnesses, constants, carry), with where they come from and
//!    how they are stored,
//!  - the polynomial identity that the verifier checks at a Fiat-Shamir-derived extension-field
//!    point,
//!  - any auxiliary checks beyond the identity (e.g., `c < modulus`, top carry coefficients are
//!    zero),
//!  - which polynomials the proc exposes back on the operand stack as the result.
//!
//! Realized instances: u256 `modmul_k1_base` and `modmul_k1_scalar`. The data model is generic
//! enough to describe the product, linear, constant, and signed-carry pieces of this modmul
//! family, but the emitter intentionally assumes the modmul verifier shape rather than trying
//! to be a general-purpose polynomial-identity compiler.

/// A polynomial appearing in the identity. The current specs use u16 limbs (`W = 2^16`);
/// this keeps the convolution bounds below the felt modulus while preserving a compact
/// representation. Storage and operand-stack form may differ from u16 (see [`Storage`]).
#[derive(Clone, Copy, Debug)]
pub struct Poly {
    /// Identifier used in the identity equation and the emitted MASM (e.g. `"a"`, `"c"`,
    /// `"e_shifted"`).
    pub name: &'static str,
    /// Where the polynomial's coefficients come from.
    pub role: PolyRole,
    /// Number of u16 coefficients as the polynomial enters the identity check. Inputs `a, b`
    /// declare 16 (8 u32 limbs split into 16 u16); the carry polynomial declares 32.
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
    /// Fixed modulus supplied by the spec. The emitter expects exactly one `Constant`; it is
    /// advice-loaded and pinned together with [`PolyRole::FixedU32Vector`] (if any) against a
    /// single combined Poseidon2 digest before use.
    Constant {
        /// u16 limbs in little-endian order (limb 0 = least-significant).
        u16_limbs: &'static [u16],
    },
    /// Fixed u32-valued vector supplied by the spec. Absorbed via advice as the second phase of
    /// the fixed-statement prefix (after the modulus) and pinned with it under a single combined
    /// Poseidon2 digest. Used for the carry-shift offset polynomial.
    FixedU32Vector {
        /// Coefficients in low-to-high order: `u32_values[0]` is the constant term,
        /// `u32_values[len-1]` is the highest-degree coefficient. The verifier absorbs them
        /// high-first via the reversed-advice convention shared by all polys in the family.
        u32_values: &'static [u32],
    },
}

/// Memory and load conventions for a polynomial's coefficients.
#[derive(Clone, Copy, Debug)]
pub enum Storage {
    /// One felt per u16 coefficient. For advice-backed witness polynomials, each landed felt
    /// is range-checked as u32 by `adv_pipe`. Per-witness soundness arguments (e.g., why
    /// non-canonical u32 coefficients are accepted) live with the concrete modmul specs, not here.
    PerU16,
    /// One felt per u32 limb, packing two adjacent u16 limbs per felt. The emitter inserts a
    /// `u32divmod.65536` split when the polynomial is evaluated at alpha via `horner_eval_base`.
    PerU32,
}

/// The polynomial identity the verifier checks. All terms are in the quadratic extension of the
/// Miden base field; the identity is `sum(products) + sum(linears) - (W - alpha) *
/// (carry.shifted(alpha) - carry.offset(alpha)) = 0`.
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    /// Quadratic terms: `sign * Pa(alpha) * Pb(alpha)`. Modmul has `[+ a*b, - q*modulus]`.
    pub products: &'static [Product],
    /// Linear terms: `sign * P(alpha)`. Modmul has `[- c]`.
    pub linears: &'static [Linear],
    /// The signed-carry term `(W - alpha) * (shifted(alpha) - offset(alpha))`.
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
    /// Host-shifted signed carry polynomial. Each coefficient is `signed_carry + shift` where
    /// `shift` is the constant value carried by every coefficient of [`Self::offset`]; the shift
    /// keeps every landed coefficient a valid u32.
    pub shifted: PolyRef,
    /// Fixed offset polynomial whose coefficients all equal the host-side shift scalar (`2^31`
    /// for the k1 modmul specs). Pinned alongside the modulus in the fixed-statement prefix.
    pub offset: PolyRef,
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
    /// Assert `poly[index] == value` (as a base-field felt). The shifted carry's top two
    /// coefficients use this to pin their unwritten-and-shifted value (`shift`, e.g. `2^31`).
    LimbEquals { poly: PolyRef, index: usize, value: u32 },
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
