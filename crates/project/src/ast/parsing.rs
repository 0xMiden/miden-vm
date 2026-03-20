use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};

use miden_assembly_syntax::{
    Report,
    debuginfo::{SourceFile, SourceId, SourceSpan, Span, Uri},
};

/// This type is used to represent package information which may be inherited within a workspace.
#[derive(Debug, Clone)]
pub enum MaybeInherit<T> {
    /// We were given a concrete value, i.e. the value is not inherited
    Value(T),
    /// The value is inherited from the parent workspace
    Inherit,
}

impl<T> MaybeInherit<T> {
    #[track_caller]
    pub fn unwrap_value(&self) -> &T {
        match self {
            Self::Value(value) => value,
            Self::Inherit => panic!("attempted to unwrap value of inherited property"),
        }
    }
}

#[cfg(feature = "serde")]
mod maybe_inherit {
    use alloc::string::String;
    use core::{fmt, marker::PhantomData};

    use serde::{
        Deserialize,
        de::{self, IntoDeserializer, MapAccess, Visitor},
    };

    use super::MaybeInherit;

    impl<'de, T> serde::Deserialize<'de> for MaybeInherit<T>
    where
        T: serde::Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct MaybeInheritVisitor<T>(PhantomData<T>);

            impl<'de, T> Visitor<'de> for MaybeInheritVisitor<T>
            where
                T: Deserialize<'de>,
            {
                type Value = MaybeInherit<T>;

                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str(
                        "a string value, a boolean, or a map of the form { workspace = true }",
                    )
                }

                fn visit_bool<E>(self, workspace: bool) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if workspace {
                        Ok(MaybeInherit::Inherit)
                    } else {
                        Err(E::custom("the 'workspace' field may only be set to 'true'"))
                    }
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    T::deserialize(value.into_deserializer()).map(MaybeInherit::Value)
                }

                fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    T::deserialize(value.into_deserializer()).map(MaybeInherit::Value)
                }

                fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
                where
                    A: MapAccess<'de>,
                {
                    let mut workspace = None;
                    while let Some(key) = map.next_key::<String>()? {
                        match key.as_str() {
                            "workspace" => {
                                if workspace.is_some() {
                                    return Err(de::Error::duplicate_field("workspace"));
                                }
                                workspace = Some(map.next_value::<bool>()?);
                            },
                            _ => return Err(de::Error::unknown_field(&key, &["workspace"])),
                        }
                    }

                    match workspace {
                        Some(true) => Ok(MaybeInherit::Inherit),
                        Some(false) => Err(de::Error::custom(
                            "the 'workspace' field may only be set to 'true'",
                        )),
                        None => Err(de::Error::missing_field("workspace")),
                    }
                }
            }

            deserializer.deserialize_any(MaybeInheritVisitor(PhantomData))
        }
    }

    impl<T> serde::Serialize for MaybeInherit<T>
    where
        T: serde::Serialize,
    {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            match self {
                Self::Value(value) => value.serialize(serializer),
                Self::Inherit => true.serialize(serializer),
            }
        }
    }
}

/// This trait is implemented for all types which have source spans with an associated [SourceId].
///
/// After parsing via `serde`, it is necessary for us to post-process such spans to attach the
/// `SourceId` to the span, otherwise the spans only contain the byte range, which is insufficient
/// for reporting purposes.
///
/// NOTE: In the future, we may want to define this as part of a as-yet-to-be-defined `SpannedMut`
/// trait which would provide APIs to not only set the `SourceId`, but also the `SourceSpan` itself,
/// but it isn't clear if that is actually needed at the moment, so to keep things simple, we're
/// keeping this crate-local.
///
/// This is an internal trait.
pub(crate) trait SetSourceId {
    fn set_source_id(&mut self, source_id: SourceId);
}

impl<T: SetSourceId> SetSourceId for Span<T> {
    fn set_source_id(&mut self, source_id: SourceId) {
        Span::set_source_id(self, source_id);
        <T as SetSourceId>::set_source_id(self, source_id);
    }
}

impl SetSourceId for SourceSpan {
    fn set_source_id(&mut self, source_id: SourceId) {
        SourceSpan::set_source_id(self, source_id);
    }
}

impl SetSourceId for String {
    #[inline(always)]
    fn set_source_id(&mut self, _source_id: SourceId) {}
}

impl SetSourceId for toml::Value {
    #[inline(always)]
    fn set_source_id(&mut self, _source_id: SourceId) {}
}

impl SetSourceId for crate::SemVer {
    #[inline(always)]
    fn set_source_id(&mut self, _source_id: SourceId) {}
}

impl SetSourceId for crate::VersionRequirement {
    fn set_source_id(&mut self, source_id: SourceId) {
        match self {
            crate::VersionRequirement::Semantic(version) => version.set_source_id(source_id),
            crate::VersionRequirement::Digest(digest) => digest.set_source_id(source_id),
            crate::VersionRequirement::Exact(_) => {},
        }
    }
}

impl SetSourceId for Uri {
    #[inline(always)]
    fn set_source_id(&mut self, _source_id: SourceId) {}
}

impl<T: ?Sized> SetSourceId for Arc<T> {
    fn set_source_id(&mut self, _source_id: SourceId) {}
}

impl<T: ?Sized + SetSourceId> SetSourceId for Box<T> {
    fn set_source_id(&mut self, source_id: SourceId) {
        <T as SetSourceId>::set_source_id(self, source_id)
    }
}
impl<T: SetSourceId> SetSourceId for Vec<T> {
    fn set_source_id(&mut self, source_id: SourceId) {
        for value in self.iter_mut() {
            value.set_source_id(source_id);
        }
    }
}

impl<K: SetSourceId + Ord, V: SetSourceId> SetSourceId for BTreeMap<K, V> {
    fn set_source_id(&mut self, source_id: SourceId) {
        let map = core::mem::take(self);
        for (mut key, mut value) in map {
            key.set_source_id(source_id);
            value.set_source_id(source_id);
            self.insert(key, value);
        }
    }
}

/// This trait is implemented for all types for which we have additional semantic validation rules
/// we wish to check after parsing from source, which cannot be easily represented (or represented
/// at all) in Rust/`serde` type system (and thus enforced during the actual parsing).
///
/// This is an internal trait.
pub(crate) trait Validate {
    #[allow(unused_variables)]
    fn validate(&self, source: Arc<SourceFile>) -> Result<(), Report> {
        Ok(())
    }
}
