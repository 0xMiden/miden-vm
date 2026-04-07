//! On-chain implementation of [`crate::Felt`].

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
/// A `Felt` represented as an on-chain felt.
pub struct Felt {
    /// The backing type is `f32` which will be treated as a felt by the compiler.
    /// We're basically hijacking the Wasm `f32` type and treat as felt.
    pub inner: f32,
    // We cannot define this type as `Felt(f32)` since there is no struct tuple support in WIT.
    // For the type remapping to work the bindings are expecting the remapped type to be the
    // same shape as the one generated from WIT.
    //
    // In WIT it's defined as
    // ```wit
    // record felt {
    //   inner: f32,
    // }
    //```
    // see sdk/base-macros/wit/miden.wit so we have to define it like that here.
}

unsafe extern "C" {
    #[link_name = "intrinsics::felt::from_u64_unchecked"]
    pub(crate) fn extern_from_u64_unchecked(value: u64) -> Felt;

    #[link_name = "intrinsics::felt::from_u32"]
    pub(crate) fn extern_from_u32(value: u32) -> Felt;

    #[link_name = "intrinsics::felt::as_u64"]
    pub(crate) fn extern_as_u64(felt: Felt) -> u64;

    #[link_name = "intrinsics::felt::sub"]
    pub(crate) fn extern_sub(a: Felt, b: Felt) -> Felt;

    #[link_name = "intrinsics::felt::mul"]
    pub(crate) fn extern_mul(a: Felt, b: Felt) -> Felt;

    #[link_name = "intrinsics::felt::div"]
    pub(crate) fn extern_div(a: Felt, b: Felt) -> Felt;

    #[link_name = "intrinsics::felt::neg"]
    pub(crate) fn extern_neg(a: Felt) -> Felt;

    #[link_name = "intrinsics::felt::inv"]
    pub(crate) fn extern_inv(a: Felt) -> Felt;

    #[link_name = "intrinsics::felt::pow2"]
    pub(crate) fn extern_pow2(a: Felt) -> Felt;

    #[link_name = "intrinsics::felt::exp"]
    pub(crate) fn extern_exp(a: Felt, b: Felt) -> Felt;

    #[link_name = "intrinsics::felt::eq"]
    pub(crate) fn extern_eq(a: Felt, b: Felt) -> i32;

    #[link_name = "intrinsics::felt::gt"]
    pub(crate) fn extern_gt(a: Felt, b: Felt) -> i32;

    #[link_name = "intrinsics::felt::lt"]
    pub(crate) fn extern_lt(a: Felt, b: Felt) -> i32;

    #[link_name = "intrinsics::felt::ge"]
    pub(crate) fn extern_ge(a: Felt, b: Felt) -> i32;

    #[link_name = "intrinsics::felt::le"]
    pub(crate) fn extern_le(a: Felt, b: Felt) -> i32;

    #[link_name = "intrinsics::felt::is_odd"]
    pub(crate) fn extern_is_odd(a: Felt) -> i32;

    #[link_name = "intrinsics::felt::add"]
    pub(crate) fn extern_add(a: Felt, b: Felt) -> Felt;
}

impl Felt {
    /// The field modulus, `2^64 - 2^32 + 1`.
    pub const ORDER_U64: u64 = 0xffff_ffff_0000_0001;

    /// Alias for [`Self::ORDER_U64`], matching the native API surface.
    pub const ORDER: u64 = Self::ORDER_U64;

    /// Field element representing zero.
    pub const ZERO: Self = Self { inner: f32::from_bits(0) };

    /// Field element representing one.
    pub const ONE: Self = Self { inner: f32::from_bits(1) };

    /// Field element representing two.
    pub const TWO: Self = Self { inner: f32::from_bits(2) };

    /// Constructs a new field element from the provided `value`.
    ///
    /// # Errors
    ///
    /// - [`FeltFromIntError`] if the provided `value` is not a valid input.
    pub fn new(value: u64) -> Result<Self, FeltFromIntError> {
        Felt::from_canonical_checked(value).ok_or(FeltFromIntError(value))
    }

    /// Creates a new field element from any `u64` without performing reduction.
    ///
    /// Any `u64` value is accepted. No validation is performed; the value is passed directly
    /// to the VM intrinsic.
    #[inline(always)]
    pub fn new_unchecked(value: u64) -> Self {
        unsafe { extern_from_u64_unchecked(value) }
    }

    #[inline(always)]
    pub fn from_canonical_checked(int: u64) -> Option<Self> {
        (int < Self::ORDER_U64).then(|| Self::new_unchecked(int))
    }

    #[inline(always)]
    pub fn from_u8(int: u8) -> Self {
        int.into()
    }

    #[inline(always)]
    pub fn from_u16(int: u16) -> Self {
        int.into()
    }

    /// Creates a new field element from any `u32`.
    pub fn from_u32(value: u32) -> Self {
        unsafe { extern_from_u32(value) }
    }

    /// Returns the representative of this felt in canonical form in the range `[0, ORDER_U64)`.
    #[inline(always)]
    pub fn as_canonical_u64(&self) -> u64 {
        unsafe { extern_as_u64(*self) }
    }

    /// Constant-time equivalent of `as_canonical_u64()` for wasm targets.
    ///
    /// On wasm, the host implementation is the only source of truth for canonicalization, and we
    /// cannot reproduce its constant-time behavior locally.
    #[inline(always)]
    pub fn as_canonical_u64_ct(&self) -> u64 {
        self.as_canonical_u64()
    }

    /// Returns true if this felt is odd.
    #[inline(always)]
    pub fn is_odd(&self) -> bool {
        unsafe { extern_is_odd(*self) != 0 }
    }

    /// Returns true if this felt is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    /// Returns the multiplicative inverse of this felt.
    ///
    /// # Panics
    /// Panics if `self` is zero.
    #[inline(always)]
    pub fn inv(&self) -> Self {
        debug_assert!(!self.is_zero(), "attempted to invert zero");
        unsafe { extern_inv(*self) }
    }

    /// Returns `Some(self.inv())` if `self` is non-zero, and `None` otherwise.
    #[inline(always)]
    pub fn try_inverse(&self) -> Option<Self> {
        (!self.is_zero()).then(|| self.inv())
    }

    /// Returns `2 * self`.
    #[inline(always)]
    pub fn double(&self) -> Self {
        *self + *self
    }

    /// Returns `self^2`.
    #[inline(always)]
    pub fn square(&self) -> Self {
        unsafe { extern_pow2(*self) }
    }

    /// Computes `self^power`.
    #[inline(always)]
    pub fn exp(&self, power: Self) -> Self {
        unsafe { extern_exp(*self, power) }
    }
}

impl From<Felt> for u64 {
    fn from(felt: Felt) -> u64 {
        felt.as_canonical_u64()
    }
}

impl From<u32> for Felt {
    fn from(value: u32) -> Self {
        unsafe { extern_from_u32(value) }
    }
}

impl From<u16> for Felt {
    fn from(value: u16) -> Self {
        Self::from(value as u32)
    }
}

impl From<u8> for Felt {
    fn from(value: u8) -> Self {
        Self::from(value as u32)
    }
}

#[cfg(target_pointer_width = "32")]
impl From<usize> for Felt {
    fn from(value: usize) -> Self {
        Self::from(value as u32)
    }
}

impl TryFrom<u64> for Felt {
    type Error = FeltFromIntError;

    fn try_from(int: u64) -> Result<Felt, Self::Error> {
        Felt::new(int)
    }
}

impl core::ops::Add for Felt {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Self) -> Self {
        unsafe { extern_add(self, other) }
    }
}

impl core::ops::AddAssign for Felt {
    #[inline(always)]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl core::ops::Sub for Felt {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Self) -> Self {
        unsafe { extern_sub(self, other) }
    }
}

impl core::ops::SubAssign for Felt {
    #[inline(always)]
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl core::ops::Mul for Felt {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        unsafe { extern_mul(self, other) }
    }
}

impl core::ops::MulAssign for Felt {
    #[inline(always)]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl core::ops::Div for Felt {
    type Output = Self;

    #[inline(always)]
    fn div(self, other: Self) -> Self {
        unsafe { extern_div(self, other) }
    }
}

impl core::ops::DivAssign for Felt {
    #[inline(always)]
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl core::ops::Neg for Felt {
    type Output = Self;

    #[inline(always)]
    fn neg(self) -> Self {
        unsafe { extern_neg(self) }
    }
}

impl PartialEq for Felt {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        unsafe { extern_eq(*self, *other) == 1 }
    }
}

impl Eq for Felt {}

impl PartialOrd for Felt {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }

    #[inline(always)]
    fn gt(&self, other: &Self) -> bool {
        unsafe { extern_gt(*self, *other) != 0 }
    }

    #[inline(always)]
    fn ge(&self, other: &Self) -> bool {
        unsafe { extern_ge(*self, *other) != 0 }
    }

    #[inline(always)]
    fn lt(&self, other: &Self) -> bool {
        unsafe { extern_lt(*self, *other) != 0 }
    }

    #[inline(always)]
    fn le(&self, other: &Self) -> bool {
        unsafe { extern_le(*self, *other) != 0 }
    }
}

impl Ord for Felt {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        if self.lt(other) {
            core::cmp::Ordering::Less
        } else if self.gt(other) {
            core::cmp::Ordering::Greater
        } else {
            core::cmp::Ordering::Equal
        }
    }
}

// Note: public `assert` helpers live in `sdk/field/src/lib.rs` to preserve their stable paths in
// emitted WASM and expected-file tests.

impl core::fmt::Display for Felt {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.as_canonical_u64(), f)
    }
}

impl core::hash::Hash for Felt {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.as_canonical_u64(), state);
    }
}

// ERRORS
// ================================================================================================

#[derive(Debug, thiserror::Error)]
#[error("integer {0} is equal to or exceeds the felt modulus {modulus}", modulus = Felt::ORDER)]
pub struct FeltFromIntError(u64);

impl FeltFromIntError {
    /// Returns the integer for which the conversion failed.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
