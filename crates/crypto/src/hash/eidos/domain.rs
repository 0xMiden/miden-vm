//! Typed Eidos domains and registry support.
//!
//! Registered Eidos tags use an 8/16/8 hierarchy:
//!
//! ```text
//!  31            24 23                         8 7             0
//! +----------------+-----------------------------+---------------+
//! |  namespace: 8  |       local id: 16          |  version: 8   |
//! +----------------+-----------------------------+---------------+
//! ```
//!
//! A namespace is allocated centrally. Its owner maintains a local registry and is responsible for
//! assigning each local ID under exactly one versioning policy. Versions `1..=255` identify a
//! numbered construction. Version `0` delegates versioning to the authenticated payload and may
//! not coexist with numbered versions of the same local ID.
//!
//! The all-zero tag is deliberately not registrable. Together with three zero parameters, it is
//! reserved for the fixed, one-block Merkle inner-node compression exposed by
//! [`super::Eidos::merge`].

use alloc::string::String;
use core::fmt::{self, Write};

use crate::Felt;

/// One centrally allocated 8-bit Eidos namespace.
///
/// Add namespaces to [`namespace`] and [`NAMESPACE_REGISTRY`] in `miden-crypto`. Downstream
/// registries select one of those values rather than constructing their own.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainNamespace(u8);

impl DomainNamespace {
    const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the numeric namespace prefix.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    const fn from_allocated_u8(value: u8) -> Option<Self> {
        let mut index = 0;
        while index < NAMESPACE_REGISTRY.len() {
            let namespace = NAMESPACE_REGISTRY[index].namespace;
            if namespace.as_u8() == value {
                return Some(namespace);
            }
            index += 1;
        }
        None
    }
}

/// Centrally allocated Eidos namespaces.
pub mod namespace {
    use super::DomainNamespace;

    /// Domains maintained by `miden-crypto`.
    pub const MIDEN_CRYPTO: DomainNamespace = DomainNamespace::new(0x00);

    /// Domains maintained by `miden-vm`.
    pub const MIDEN_VM: DomainNamespace = DomainNamespace::new(0x01);

    /// Domains maintained by the Miden protocol repository.
    pub const MIDEN_PROTOCOL: DomainNamespace = DomainNamespace::new(0x02);

    /// Reserved for a centrally maintained ecosystem registry, not ad hoc allocation.
    pub const MIDEN_ECOSYSTEM: DomainNamespace = DomainNamespace::new(0x10);
}

/// Metadata for one centrally allocated namespace.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NamespaceDescriptor {
    /// Human-readable namespace name.
    pub name: &'static str,
    /// Numeric namespace prefix.
    pub namespace: DomainNamespace,
    /// Repository responsible for the namespace's local registry.
    pub maintainer: &'static str,
}

/// The central Eidos namespace registry.
///
/// Entries are sorted by numeric prefix. Gaps remain unallocated until they are assigned here.
pub const NAMESPACE_REGISTRY: &[NamespaceDescriptor] = &[
    NamespaceDescriptor {
        name: "Miden cryptographic primitives",
        namespace: namespace::MIDEN_CRYPTO,
        maintainer: "https://github.com/0xMiden/miden-vm/tree/next/crates/crypto",
    },
    NamespaceDescriptor {
        name: "Miden VM",
        namespace: namespace::MIDEN_VM,
        maintainer: "https://github.com/0xMiden/miden-vm",
    },
    NamespaceDescriptor {
        name: "Miden protocol",
        namespace: namespace::MIDEN_PROTOCOL,
        maintainer: "https://github.com/0xMiden/protocol",
    },
    NamespaceDescriptor {
        name: "Miden ecosystem",
        namespace: namespace::MIDEN_ECOSYSTEM,
        maintainer: "https://github.com/0xMiden",
    },
];

const _: () = assert_namespaces_are_sorted_and_unique(NAMESPACE_REGISTRY);

const fn assert_namespaces_are_sorted_and_unique(entries: &[NamespaceDescriptor]) {
    let mut index = 1;
    while index < entries.len() {
        assert!(
            entries[index - 1].namespace.as_u8() < entries[index].namespace.as_u8(),
            "Eidos namespace allocations must be sorted and unique"
        );
        index += 1;
    }
}

/// The versioning policy encoded in an Eidos domain tag.
///
/// Numbered versions identify a specific construction. [`DELEGATED_VERSIONING`] means that the
/// registered payload schema carries the object version instead.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainVersion(u8);

impl DomainVersion {
    /// Constructs a numbered domain version.
    ///
    /// # Panics
    ///
    /// Panics if `version` is zero. Use [`DELEGATED_VERSIONING`] for payload-defined versioning.
    pub const fn numbered(version: u8) -> Self {
        assert!(version != 0, "numbered Eidos domain versions start at 1");
        Self(version)
    }

    /// Returns the encoded version byte.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns true when the authenticated payload carries the object version.
    pub const fn is_delegated(self) -> bool {
        self.0 == 0
    }

    const fn from_tag_byte(version: u8) -> Self {
        Self(version)
    }
}

/// Domain-version marker for constructions whose authenticated payload carries the object
/// version.
pub const DELEGATED_VERSIONING: DomainVersion = DomainVersion(0);

/// A structurally valid 32-bit Eidos domain tag.
///
/// The tag packs `(namespace, local_id, version)` as `8/16/8` bits. The namespace and local ID
/// cannot both be zero. A tag becomes registered only when its namespace owner includes it in an
/// [`EidosDomainRegistry`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DomainTag(u32);

impl DomainTag {
    /// Constructs a structurally valid tag in `namespace`.
    ///
    /// # Panics
    ///
    /// Panics if both the namespace and local ID are zero.
    pub const fn new(namespace: DomainNamespace, local_id: u16, version: DomainVersion) -> Self {
        assert!(
            namespace.as_u8() != 0 || local_id != 0,
            "the namespace and local ID cannot both be zero"
        );
        Self(((namespace.as_u8() as u32) << 24) | ((local_id as u32) << 8) | version.as_u8() as u32)
    }

    /// Parses the structural representation of a tag.
    ///
    /// This rejects the reserved `(namespace, local_id) = (0, 0)` pair and requires a centrally
    /// allocated namespace. It does not establish that the owner has declared the complete tag in
    /// its local registry.
    pub const fn from_u32(value: u32) -> Option<Self> {
        let version = value as u8;
        let namespace_byte = (value >> 24) as u8;
        let local_id = ((value >> 8) & 0xffff) as u16;
        if namespace_byte == 0 && local_id == 0 {
            return None;
        }

        let namespace = match DomainNamespace::from_allocated_u8(namespace_byte) {
            Some(namespace) => namespace,
            None => return None,
        };
        Some(Self::new(namespace, local_id, DomainVersion::from_tag_byte(version)))
    }

    /// Returns the complete `namespace || local_id || version` tag.
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Returns the tag's namespace.
    pub const fn namespace(self) -> DomainNamespace {
        DomainNamespace::new((self.0 >> 24) as u8)
    }

    /// Returns the tag's owner-local ID.
    pub const fn local_id(self) -> u16 {
        ((self.0 >> 8) & 0xffff) as u16
    }

    /// Returns the tag's versioning policy.
    pub const fn version(self) -> DomainVersion {
        DomainVersion::from_tag_byte(self.0 as u8)
    }

    /// Returns true when the authenticated payload carries the object version.
    pub const fn uses_delegated_versioning(self) -> bool {
        self.version().is_delegated()
    }

    /// Encodes this tag as a canonical Miden field element.
    pub const fn as_felt(self) -> Felt {
        Felt::new_unchecked(self.0 as u64)
    }
}

impl fmt::Display for DomainTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

/// Coarse input encoding recorded for a registered Eidos construction.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum DomainEncoding {
    /// Exact-length sequence of Goldilocks field elements.
    FeltSequence,
    /// Exact-length byte string encoded into 64-byte Eidos blocks.
    ByteString,
    /// Stateful Fiat-Shamir transcript construction.
    Transcript,
    /// A construction with a registry-defined fixed or custom schedule.
    Custom,
}

/// Type-level description of an Eidos input encoding.
pub trait EidosEncoding: 'static {
    /// Runtime metadata written into registry descriptors.
    const KIND: DomainEncoding;
}

/// Type marker for the standard exact-length Felt-sequence construction.
#[derive(Debug)]
pub enum FeltSequence {}

impl EidosEncoding for FeltSequence {
    const KIND: DomainEncoding = DomainEncoding::FeltSequence;
}

/// Type marker for the standard exact-length byte-string construction.
#[derive(Debug)]
pub enum ByteString {}

impl EidosEncoding for ByteString {
    const KIND: DomainEncoding = DomainEncoding::ByteString;
}

/// Type marker for the Eidos Fiat-Shamir transcript seed construction.
#[derive(Debug)]
pub enum Transcript {}

impl EidosEncoding for Transcript {
    const KIND: DomainEncoding = DomainEncoding::Transcript;
}

/// Type marker for a domain-specific Eidos schedule.
#[derive(Debug)]
pub enum Custom {}

impl EidosEncoding for Custom {
    const KIND: DomainEncoding = DomainEncoding::Custom;
}

/// A typed, registered Eidos construction domain.
///
/// Implementations must preserve the numeric assignment and encoding declared by the namespace
/// owner. Use [`crate::eidos_domain_registry!`] rather than implementing this trait manually. The
/// associated encoding prevents a byte-string domain from being passed to Felt-sequence hashing,
/// and vice versa.
pub trait EidosDomain: Copy + 'static {
    /// Input encoding and schedule family accepted by typed hash APIs.
    type Encoding: EidosEncoding;

    /// Stable symbolic name used by generated constants and diagnostics.
    const NAME: &'static str;

    /// Registered numeric tag.
    const TAG: DomainTag;
}

/// Structured metadata for one registered Eidos domain.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct DomainDescriptor {
    /// Stable symbolic name.
    pub name: &'static str,
    /// Registered numeric tag.
    pub tag: DomainTag,
    /// Standard encoding family, or [`DomainEncoding::Custom`].
    pub encoding: DomainEncoding,
    /// Short human-readable purpose.
    pub description: &'static str,
    /// Normative interpretation of the three Eidos parameter lanes and payload schedule.
    pub schema: &'static str,
}

/// One owner-maintained registry inside a centrally allocated namespace.
pub trait EidosDomainRegistry {
    /// Namespace owned by this registry.
    const NAMESPACE: DomainNamespace;

    /// Sorted domain declarations maintained by this registry.
    const DOMAINS: &'static [DomainDescriptor];

    /// Returns the declaration for `tag`, if it belongs to this registry.
    fn resolve(tag: DomainTag) -> Option<&'static DomainDescriptor> {
        if tag.namespace() != Self::NAMESPACE {
            return None;
        }

        Self::DOMAINS.iter().find(|domain| domain.tag == tag)
    }
}

/// Validates one owner-local registry at compile time.
///
/// This function is public because the exported registry macro expands in downstream crates.
#[doc(hidden)]
pub const fn assert_domain_registry(namespace: DomainNamespace, entries: &[DomainDescriptor]) {
    let mut index = 0;
    while index < entries.len() {
        assert!(
            entries[index].tag.namespace().as_u8() == namespace.as_u8(),
            "Eidos domain belongs to the wrong namespace"
        );

        if index != 0 {
            let previous = entries[index - 1].tag;
            let current = entries[index].tag;
            assert!(
                previous.as_u32() < current.as_u32(),
                "Eidos domains must be sorted and unique"
            );
            assert!(
                previous.local_id() != current.local_id()
                    || (!previous.uses_delegated_versioning()
                        && !current.uses_delegated_versioning()),
                "delegated and numbered Eidos versions cannot share a local ID"
            );
        }
        index += 1;
    }
}

/// Renders one registry as MASM constants from the same declarations used by Rust.
///
/// The generated names are the Rust constant names and the values are complete 32-bit tags.
pub fn render_masm_constants<R: EidosDomainRegistry>() -> String {
    let mut output = String::new();
    writeln!(
        output,
        "# Generated Eidos domain tags for namespace 0x{:02x}.",
        R::NAMESPACE.as_u8()
    )
    .expect("writing to a String cannot fail");
    for domain in R::DOMAINS {
        writeln!(output, "const {} = 0x{:08x}", domain.name, domain.tag.as_u32())
            .expect("writing to a String cannot fail");
    }
    output
}

/// Declares every Eidos domain owned by one namespace.
///
/// The macro emits typed zero-sized domain values, a structured registry, and compile-time checks
/// within that declaration. A repository should invoke it once for its allocated namespace.
#[macro_export]
macro_rules! eidos_domain_registry {
    (
        $(#[$registry_meta:meta])*
        $registry_vis:vis registry $registry:ident {
            namespace: $namespace:path;
            domains: {
                $(
                    $(#[$domain_meta:meta])*
                    $domain_vis:vis $domain_const:ident : $domain_type:ident {
                        local_id: $local_id:expr,
                        version: $version:expr,
                        encoding: $encoding:ty,
                        description: $description:literal,
                        schema: $schema:literal $(,)?
                    }
                )+
            }
        }
    ) => {
        $(#[$registry_meta])*
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        $registry_vis struct $registry;

        $(
            $(#[$domain_meta])*
            #[doc = $description]
            #[derive(Debug, Copy, Clone, Eq, PartialEq)]
            $domain_vis struct $domain_type;

            $(#[$domain_meta])*
            #[doc = $description]
            $domain_vis const $domain_const: $domain_type = $domain_type;

            impl $crate::hash::eidos::domain::EidosDomain for $domain_type {
                type Encoding = $encoding;

                const NAME: &'static str = stringify!($domain_const);
                const TAG: $crate::hash::eidos::domain::DomainTag =
                    $crate::hash::eidos::domain::DomainTag::new(
                        $namespace,
                        $local_id,
                        $version,
                    );
            }
        )+

        impl $registry {
            /// Returns this registry's structured domain declarations.
            pub const fn domains() -> &'static [$crate::hash::eidos::domain::DomainDescriptor] {
                <Self as $crate::hash::eidos::domain::EidosDomainRegistry>::DOMAINS
            }

            /// Returns the declaration for `tag`, if it belongs to this registry.
            pub fn resolve(
                tag: $crate::hash::eidos::domain::DomainTag,
            ) -> Option<&'static $crate::hash::eidos::domain::DomainDescriptor> {
                <Self as $crate::hash::eidos::domain::EidosDomainRegistry>::resolve(tag)
            }
        }

        impl $crate::hash::eidos::domain::EidosDomainRegistry for $registry {
            const NAMESPACE: $crate::hash::eidos::domain::DomainNamespace = $namespace;
            const DOMAINS: &'static [$crate::hash::eidos::domain::DomainDescriptor] = &[
                $(
                    $crate::hash::eidos::domain::DomainDescriptor {
                        name: stringify!($domain_const),
                        tag: <$domain_type as $crate::hash::eidos::domain::EidosDomain>::TAG,
                        encoding: <$encoding as $crate::hash::eidos::domain::EidosEncoding>::KIND,
                        description: $description,
                        schema: $schema,
                    },
                )+
            ];
        }

        const _: () = $crate::hash::eidos::domain::assert_domain_registry(
            $namespace,
            <$registry as $crate::hash::eidos::domain::EidosDomainRegistry>::DOMAINS,
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn test_descriptor(local_id: u16, version: DomainVersion) -> DomainDescriptor {
        DomainDescriptor {
            name: "TEST",
            tag: DomainTag::new(namespace::MIDEN_PROTOCOL, local_id, version),
            encoding: DomainEncoding::Custom,
            description: "test",
            schema: "test",
        }
    }

    #[test]
    fn domain_tag_uses_the_8_16_8_layout() {
        let tag = DomainTag::new(namespace::MIDEN_PROTOCOL, 0x1234, DomainVersion::numbered(0x56));
        assert_eq!(tag.as_u32(), 0x0212_3456);
        assert_eq!(tag.namespace(), namespace::MIDEN_PROTOCOL);
        assert_eq!(tag.local_id(), 0x1234);
        assert_eq!(tag.version(), DomainVersion::numbered(0x56));
        assert!(!tag.uses_delegated_versioning());
        assert_eq!(tag.as_felt().as_canonical_u64(), 0x0212_3456);
    }

    #[test]
    #[should_panic(expected = "numbered Eidos domain versions start at 1")]
    fn numbered_version_zero_requires_the_delegated_marker() {
        let _ = DomainVersion::numbered(0);
    }

    #[test]
    fn delegated_versioning_uses_version_byte_zero() {
        let tag = DomainTag::new(namespace::MIDEN_PROTOCOL, 1, DELEGATED_VERSIONING);
        assert_eq!(tag.as_u32(), 0x0200_0100);
        assert_eq!(tag.version(), DELEGATED_VERSIONING);
        assert!(tag.uses_delegated_versioning());
    }

    #[test]
    #[should_panic(expected = "delegated and numbered Eidos versions cannot share a local ID")]
    fn registry_rejects_mixed_versioning_policies_for_one_local_id() {
        let entries = [
            test_descriptor(1, DELEGATED_VERSIONING),
            test_descriptor(1, DomainVersion::numbered(1)),
        ];

        assert_domain_registry(namespace::MIDEN_PROTOCOL, &entries);
    }

    #[test]
    fn registry_allows_multiple_numbered_versions_for_one_local_id() {
        let entries = [
            test_descriptor(1, DomainVersion::numbered(1)),
            test_descriptor(1, DomainVersion::numbered(2)),
        ];

        assert_domain_registry(namespace::MIDEN_PROTOCOL, &entries);
    }

    #[test]
    #[should_panic(expected = "the namespace and local ID cannot both be zero")]
    fn zero_namespace_and_local_id_are_not_registrable() {
        let _ = DomainTag::new(namespace::MIDEN_CRYPTO, 0, DomainVersion::numbered(1));
    }

    #[test]
    #[should_panic(expected = "the namespace and local ID cannot both be zero")]
    fn zero_namespace_and_local_id_are_not_registrable_with_delegated_versioning() {
        let _ = DomainTag::new(namespace::MIDEN_CRYPTO, 0, DELEGATED_VERSIONING);
    }

    #[test]
    fn owner_local_zero_is_valid_outside_namespace_zero() {
        let tag = DomainTag::new(namespace::MIDEN_VM, 0, DomainVersion::numbered(1));
        assert_eq!(tag.as_u32(), 0x0100_0001);
    }

    #[test]
    fn parsing_checks_structure_but_leaves_local_membership_to_the_owner() {
        let registered =
            DomainTag::new(namespace::MIDEN_PROTOCOL, 0x1234, DomainVersion::numbered(7));
        assert_eq!(DomainTag::from_u32(registered.as_u32()), Some(registered));

        // This is structurally valid even though this test does not declare it in the protocol
        // registry. Dynamic consumers perform that second, context-specific check.
        assert_eq!(
            DomainTag::from_u32(0x02ff_ff01),
            Some(DomainTag::new(namespace::MIDEN_PROTOCOL, 0xffff, DomainVersion::numbered(1),)),
        );
        assert_eq!(
            DomainTag::from_u32(0x0100_0100),
            Some(DomainTag::new(namespace::MIDEN_VM, 1, DELEGATED_VERSIONING)),
        );

        assert_eq!(DomainTag::from_u32(0), None);
        assert_eq!(DomainTag::from_u32(1), None);
        assert_eq!(DomainTag::from_u32(0x0300_0001), None);
    }

    #[test]
    fn masm_constants_come_from_registry_declarations() {
        let rendered = render_masm_constants::<super::super::domains::MidenCryptoDomainRegistry>();
        assert!(rendered.contains("const GENERIC_FELT_SEQUENCE = 0x00000a01"));
        assert!(rendered.contains("const GENERIC_BYTE_STRING = 0x00000301"));
    }
}
