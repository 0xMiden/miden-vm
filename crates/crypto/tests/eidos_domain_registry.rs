use miden_crypto::{
    Felt, eidos_domain_registry,
    hash::eidos::{
        DELEGATED_VERSIONING, DomainEncoding, DomainTag, DomainVersion, Eidos, EidosDomain,
        EidosDomainRegistry, FeltSequence, namespace, render_masm_constants,
    },
};

eidos_domain_registry! {
    /// Test registry owned by a downstream crate.
    pub registry DownstreamDomains {
        namespace: namespace::MIDEN_PROTOCOL;
        domains: {
            pub TEST_VERSIONED_COMMITMENT: TestVersionedCommitmentDomain {
                local_id: 0x1234,
                version: DELEGATED_VERSIONING,
                encoding: FeltSequence,
                description: "Downstream delegated-versioning test.",
                schema: "first Felt is the object version; remaining Felts are the versioned payload",
            }
            pub TEST_COMMITMENT: TestCommitmentDomain {
                local_id: 0x1235,
                version: DomainVersion::numbered(7),
                encoding: FeltSequence,
                description: "Downstream registry macro test.",
                schema: "param0 = number of Felts; param1 = 0; param2 = 0",
            }
        }
    }
}

#[test]
fn downstream_registry_drives_rust_and_masm_from_one_declaration() {
    assert_eq!(
        TestCommitmentDomain::TAG,
        DomainTag::new(namespace::MIDEN_PROTOCOL, 0x1235, DomainVersion::numbered(7)),
    );

    let descriptor = DownstreamDomains::DOMAINS[1];
    assert_eq!(descriptor.tag, TestCommitmentDomain::TAG);
    assert_eq!(descriptor.encoding, DomainEncoding::FeltSequence);
    assert_eq!(DownstreamDomains::resolve(descriptor.tag), Some(&descriptor));
    assert_eq!(
        DownstreamDomains::resolve(DomainTag::new(
            namespace::MIDEN_PROTOCOL,
            0xffff,
            DomainVersion::numbered(1),
        )),
        None,
    );
    assert_eq!(
        DownstreamDomains::resolve(DomainTag::new(
            namespace::MIDEN_CRYPTO,
            1,
            DomainVersion::numbered(1),
        )),
        None,
    );
    assert_eq!(
        render_masm_constants::<DownstreamDomains>(),
        "# Generated Eidos domain tags for namespace 0x02.\n\
         const TEST_VERSIONED_COMMITMENT = 0x02123400\n\
         const TEST_COMMITMENT = 0x02123507\n",
    );

    let values = [Felt::new_unchecked(1), Felt::new_unchecked(2)];
    assert_eq!(
        Eidos::hash_elements_in_domain(&values, TEST_COMMITMENT),
        Eidos::hash_elements_in_domain(&values, TestCommitmentDomain),
    );
}

#[test]
fn downstream_registry_supports_delegated_versioning() {
    let tag = TestVersionedCommitmentDomain::TAG;
    assert_eq!(tag.as_u32(), 0x0212_3400);
    assert!(tag.uses_delegated_versioning());
    assert_ne!(
        Eidos::init_chaining_word_with_tag(tag, [0; 3]),
        Eidos::merkle_node_init_chaining_word(),
    );

    let version_one = [Felt::new_unchecked(1), Felt::new_unchecked(42)];
    let version_two = [Felt::new_unchecked(2), Felt::new_unchecked(42)];
    assert_ne!(
        Eidos::hash_elements_in_domain(&version_one, TEST_VERSIONED_COMMITMENT),
        Eidos::hash_elements_in_domain(&version_two, TEST_VERSIONED_COMMITMENT),
    );
}
