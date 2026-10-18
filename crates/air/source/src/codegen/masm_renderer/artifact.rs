//! Complete generated source artifacts and their write ownership.

use std::string::String;

/// Whether ordinary generation may replace a tracked artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactOwnership {
    Managed,
    ProtectedCheckOnly,
}

/// A complete UTF-8 output, including its final newline.
///
/// Consumers compare every byte for both ownership classes. A protected output
/// is never replaced by ordinary generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenderedArtifact {
    pub relative_path: String,
    pub body: String,
    pub ownership: ArtifactOwnership,
}
