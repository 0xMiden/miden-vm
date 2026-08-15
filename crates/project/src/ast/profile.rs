use alloc::sync::Arc;

#[cfg(feature = "serde")]
use serde::Serialize;

use crate::{AstMetadata, TomlSpan};

/// Represents configuration options for a specific build profile, e.g. `release`
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Profile {
    /// The name of another profile that this profile inherits from
    pub inherits: Option<TomlSpan<Arc<str>>>,
    /// The name of this profile, e.g. `release`
    #[cfg_attr(feature = "serde", serde(default = "default_profile_name", skip))]
    pub name: TomlSpan<Arc<str>>,
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
        serde(default, flatten, skip_serializing_if = "crate::Map::is_empty")
    )]
    pub metadata: AstMetadata,
}

fn default_profile_name() -> TomlSpan<Arc<str>> {
    TomlSpan::new(0..0, Arc::from(""))
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            inherits: None,
            name: default_profile_name(),
            debug: None,
            trim_paths: None,
            metadata: Default::default(),
        }
    }
}

#[cfg(feature = "serde")]
pub(super) mod serialization {
    use alloc::{sync::Arc, vec::Vec};

    use serde::{
        Deserialize, Deserializer,
        de::{Error, MapAccess, Visitor},
    };

    use super::Profile;
    use crate::{AstMetadata, TomlSpan};

    impl<'de> Deserialize<'de> for Profile {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct ProfileVisitor;

            impl<'de> Visitor<'de> for ProfileVisitor {
                type Value = Profile;

                fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    formatter.write_str("a build profile")
                }

                fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
                where
                    M: MapAccess<'de>,
                {
                    let mut inherits = None;
                    let mut debug = None;
                    let mut trim_paths = None;
                    let mut metadata = AstMetadata::default();
                    while let Some(key) = access.next_key::<TomlSpan<Arc<str>>>()? {
                        match key.get_ref().as_ref() {
                            "inherits" => {
                                set_once(&mut inherits, access.next_value()?, "inherits")?
                            },
                            "debug" => set_once(&mut debug, access.next_value()?, "debug")?,
                            "trim-paths" => {
                                set_once(&mut trim_paths, access.next_value()?, "trim-paths")?
                            },
                            _ => {
                                let value = access.next_value()?;
                                metadata.insert(key, value);
                            },
                        }
                    }

                    Ok(Profile {
                        inherits,
                        name: super::default_profile_name(),
                        debug,
                        trim_paths,
                        metadata,
                    })
                }
            }

            deserializer.deserialize_map(ProfileVisitor)
        }
    }

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

            while let Some((key, mut value)) = access.next_entry::<TomlSpan<Arc<str>>, Profile>()? {
                value.name = key;

                if let Some(prev) =
                    profiles.iter_mut().find(|p| p.name.get_ref() == value.name.get_ref())
                {
                    *prev = value;
                } else {
                    profiles.push(value);
                }
            }

            Ok(profiles)
        }
    }

    pub fn serialize<S>(profiles: &[Profile], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer
            .collect_map(profiles.iter().map(|profile| (profile.name.get_ref().clone(), profile)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Profile>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ProfileMapVisitor)
    }

    fn set_once<T, E>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E>
    where
        E: Error,
    {
        if slot.replace(value).is_some() {
            Err(E::duplicate_field(field))
        } else {
            Ok(())
        }
    }
}
