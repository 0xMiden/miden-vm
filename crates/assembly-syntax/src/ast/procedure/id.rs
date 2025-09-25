/// Represents the index of a procedure within a single module.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ProcedureIndex(u16);

impl ProcedureIndex {
    pub fn new(id: usize) -> Self {
        Self(id.try_into().expect("invalid procedure index: too many procedures"))
    }

    pub const fn const_new(id: u16) -> Self {
        Self(id)
    }

    #[inline(always)]
    pub const fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl core::fmt::Display for ProcedureIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", &self.as_usize())
    }
}
