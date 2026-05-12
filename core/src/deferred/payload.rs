use crate::Felt;

/// 8-felt body of a [`super::Node`]. For a leaf, this is the value data; for a binary op, the
/// first 4 felts are the lhs child digest and the last 4 are the rhs child digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Payload(pub [Felt; 8]);

impl Payload {
    pub const fn new(felts: [Felt; 8]) -> Self {
        Self(felts)
    }

    pub fn as_felts(&self) -> &[Felt; 8] {
        &self.0
    }
}
