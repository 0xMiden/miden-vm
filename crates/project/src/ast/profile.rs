#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use alloc::sync::Arc;

use crate::{Metadata, SourceId, Span};

use super::parsing::SetSourceId;

/// Represents configuration options for a specific build profile, e.g. `release`
#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Profile {
    /// The name of another profile that this profile inherits from
    pub inherits: Option<Span<Arc<str>>>,
    /// The name of this profile, e.g. `release`
    #[cfg_attr(feature = "serde", serde(default, skip))]
    pub name: Span<Arc<str>>,
    /// Whether to emit debugging information for this profile
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub debug: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", rename = "trim-paths")
    )]
    pub trim_paths: Option<bool>,
    #[cfg_attr(
        feature = "serde",
        serde(default, flatten, skip_serializing_if = "Metadata::is_empty")
    )]
    pub metadata: Metadata,
}

impl SetSourceId for Profile {
    fn set_source_id(&mut self, source_id: SourceId) {
        self.metadata.set_source_id(source_id);
    }
}

#[cfg(feature = "serde")]
pub use self::serialization::deserialize_profiles_table;

#[cfg(feature = "serde")]
mod serialization {
    use alloc::{sync::Arc, vec::Vec};

    use miden_assembly_syntax::debuginfo::Span;
    use serde::de::{MapAccess, Visitor};

    use super::Profile;

    struct ProfileMapVisitor;

    impl<'de> Visitor<'de> for ProfileMapVisitor {
        type Value = Vec<Profile>;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("a profile map")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut profiles = Self::Value::default();

            while let Some((key, mut value)) = access.next_entry::<Span<Arc<str>>, Profile>()? {
                value.name = key;

                if let Some(prev) =
                    profiles.iter_mut().find(|p| p.name.inner() == value.name.inner())
                {
                    *prev = value;
                }
            }

            Ok(profiles)
        }
    }

    pub fn deserialize_profiles_table<'de, D>(deserializer: D) -> Result<Vec<Profile>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(ProfileMapVisitor)
    }
}
