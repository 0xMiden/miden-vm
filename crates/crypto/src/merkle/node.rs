use super::Word;

/// Representation of a node with two children used for iterating over containers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(test, derive(PartialOrd, Ord))]
pub struct InnerNodeInfo {
    pub value: Word,
    pub left: Word,
    pub right: Word,
}
