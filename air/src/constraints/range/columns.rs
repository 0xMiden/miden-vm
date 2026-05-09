/// Range check columns in the main execution trace (2 columns).
#[repr(C)]
pub struct RangeCols<T> {
    /// Multiplicity: how many times this value is range-checked.
    pub multiplicity: T,
    /// The value being range-checked.
    pub value: T,
}
