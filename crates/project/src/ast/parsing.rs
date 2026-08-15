#[cfg(feature = "std")]
use miden_diagnostics::Span;
use miden_diagnostics::{
    Diagnostic, DiagnosticCollector, PushResult, SourceId, SourceKey, SourceSpan, TextRange,
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

    impl<'de, T> Deserialize<'de> for MaybeInherit<T>
    where
        T: Deserialize<'de>,
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

/// Converts the source-local byte range produced by TOML into a canonical diagnostic span.
pub(crate) fn source_span(source_id: SourceId, range: core::ops::Range<usize>) -> SourceSpan {
    let range = TextRange::try_from_usize(range.start, range.end)
        .expect("TOML input was registered as a valid diagnostic source");
    SourceSpan::new(SourceKey::Session(source_id), None, range)
}

/// Lowers a TOML parsing span into the canonical span type used by the project model.
#[cfg(feature = "std")]
pub(crate) fn lower_span<T>(source_id: SourceId, value: toml::Spanned<T>) -> Span<T> {
    let span = source_span(source_id, value.span());
    Span::new(span, value.into_inner())
}

#[cfg(feature = "std")]
pub(crate) fn lower_metadata(
    source_id: SourceId,
    metadata: &crate::AstMetadata,
) -> crate::Metadata {
    metadata
        .iter()
        .map(|(key, value)| {
            (lower_span(source_id, key.clone()), lower_span(source_id, value.clone()))
        })
        .collect()
}

#[cfg(feature = "std")]
pub(crate) fn lower_metadata_set(
    source_id: SourceId,
    metadata: &crate::AstMetadataSet,
) -> crate::MetadataSet {
    metadata
        .iter()
        .map(|(key, values)| {
            (lower_span(source_id, key.clone()), lower_metadata(source_id, values))
        })
        .collect()
}

/// Context shared by semantic validation and AST lowering.
pub(crate) struct ValidationContext<'a> {
    source_id: SourceId,
    diagnostics: &'a mut DiagnosticCollector,
}

impl<'a> ValidationContext<'a> {
    pub(crate) fn new(source_id: SourceId, diagnostics: &'a mut DiagnosticCollector) -> Self {
        Self { source_id, diagnostics }
    }

    pub(crate) const fn source_id(&self) -> SourceId {
        self.source_id
    }

    pub(crate) fn span<T>(&self, value: &toml::Spanned<T>) -> SourceSpan {
        source_span(self.source_id, value.span())
    }

    #[cfg(feature = "std")]
    pub(crate) fn span_in<T>(&self, source_id: SourceId, value: &toml::Spanned<T>) -> SourceSpan {
        source_span(source_id, value.span())
    }

    #[cfg(feature = "std")]
    pub(crate) fn lower<T>(&self, value: toml::Spanned<T>) -> Span<T> {
        lower_span(self.source_id, value)
    }

    pub(crate) fn add<D>(&mut self, diagnostic: D) -> PushResult
    where
        D: Diagnostic + Send + Sync + 'static,
    {
        self.diagnostics.add(diagnostic)
    }

    #[cfg(feature = "std")]
    pub(crate) fn error_count(&self) -> usize {
        self.diagnostics.counts().errors()
    }
}
