use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};

use miden_core::{
    Felt,
    deferred::{
        DeferredError, Digest, Node, Precompile, PrecompileWitness, PrecompileWitnessEntry,
        TRUE_DIGEST, Tag, fold_deferred_root,
    },
};
use miden_precompiles::{CurvePrecompile, Keccak256Precompile, UintDomain, UintPrecompile};
use miden_precompiles_verifier::verify_deferred;
use rand::{RngExt, SeedableRng, rngs::StdRng};

use crate::{
    HashFunction, SessionInputError, WitnessLocation,
    deferred::session::{ImportLimits, import_witnesses, session_from_witnesses},
    hash::keccak::sponge::trace::keccak_oracle,
};

/// Raw committed test graphs, with no runtime evaluator. The shared fixture also supports the
/// pre-existing arithmetic/MSM cases, and permits false claims to reach the importer boundary.
#[derive(Debug)]
pub(super) struct WitnessFixture {
    nodes: BTreeMap<Digest, Node>,
    root: Digest,
}

impl WitnessFixture {
    pub(super) fn new() -> Self {
        Self {
            nodes: UintPrecompile
                .init()
                .into_iter()
                .chain(CurvePrecompile.init())
                .map(|node| (node.digest(), node))
                .collect(),
            root: TRUE_DIGEST,
        }
    }

    pub(super) fn register(&mut self, node: Node) -> Result<Digest, DeferredError> {
        let digest = node.digest();
        if self.nodes.get(&digest).is_some_and(|previous| *previous != node) {
            return Err(DeferredError::ConflictingNode);
        }
        self.nodes.insert(digest, node);
        Ok(digest)
    }

    pub(super) fn log_statement(&mut self, claim: Digest) -> Result<Digest, DeferredError> {
        self.root = self.register(Node::and(self.root, claim))?;
        Ok(self.root)
    }

    pub(super) fn root(&self) -> Digest {
        self.root
    }

    pub(super) fn get_node(&self, digest: &Digest) -> Option<&Node> {
        self.nodes.get(digest)
    }

    pub(super) fn witness(&self) -> PrecompileWitness {
        self.open(self.root)
    }

    fn open(&self, root: Digest) -> PrecompileWitness {
        let mut indices = BTreeMap::from([(TRUE_DIGEST, 0u32)]);
        let mut entries = Vec::new();
        let mut work = vec![(root, false)];
        while let Some((digest, emit)) = work.pop() {
            if indices.contains_key(&digest) {
                continue;
            }
            let node = &self.nodes[&digest];
            let tag = node.tag();
            let children = if let Ok((lhs, rhs)) = node.payload().as_join() {
                vec![(lhs, rhs)]
            } else {
                node.payload().as_pair_list().unwrap_or_default()
            };
            if !emit {
                work.push((digest, true));
                for &(lhs, rhs) in children.iter().rev() {
                    work.push((rhs, false));
                    work.push((lhs, false));
                }
                continue;
            }
            let entry = if let Ok(chunks) = node.payload().as_data() {
                PrecompileWitnessEntry::Data { tag, chunks: chunks.to_vec() }
            } else if let Ok((lhs, rhs)) = node.payload().as_join() {
                PrecompileWitnessEntry::Join {
                    tag,
                    lhs: indices[&lhs],
                    rhs: indices[&rhs],
                }
            } else {
                PrecompileWitnessEntry::PairList {
                    tag,
                    pairs: children.iter().map(|(lhs, rhs)| (indices[lhs], indices[rhs])).collect(),
                }
            };
            entries.push(entry);
            indices.insert(digest, entries.len() as u32);
        }
        let witness = PrecompileWitness::from_entries(entries).unwrap();
        assert_eq!(witness.root_unchecked(), root);
        witness
    }
}

fn uint(fixture: &mut WitnessFixture, domain: UintDomain, value: u32) -> Digest {
    fixture
        .register(UintPrecompile::value_node(domain, [value, 0, 0, 0, 0, 0, 0, 0]))
        .unwrap()
}

fn uint_eq(fixture: &mut WitnessFixture, a: Digest, b: Digest) -> Digest {
    fixture
        .register(Node::join(UintPrecompile::op_tag(UintPrecompile::EQ_OP_ID), a, b).unwrap())
        .unwrap()
}

fn keccak(fixture: &mut WitnessFixture, input: &[u8]) -> Digest {
    let preimage = fixture.register(Node::chunks_from_bytes(input)).unwrap();
    let expected = fixture
        .register(Node::chunks(vec![keccak_oracle(input).to_u32s().map(Felt::from_u32)]).unwrap())
        .unwrap();
    fixture
        .register(Keccak256Precompile::assert_node(input.len() as u32, preimage, expected))
        .unwrap()
}

fn shared_witnesses() -> (PrecompileWitness, PrecompileWitness) {
    let mut fixture = WitnessFixture::new();
    let value = uint(&mut fixture, UintDomain::U256, 17);
    let eq = uint_eq(&mut fixture, value, value);
    let hash = keccak(&mut fixture, b"shared prefix");
    let shared = fixture.register(Node::and(eq, hash)).unwrap();
    fixture.log_statement(shared).unwrap();
    let a = fixture.witness();
    fixture.log_statement(eq).unwrap();
    (a, fixture.witness())
}

#[test]
fn compute_root_evaluates_arithmetic_and_hash_claims() {
    let registry = Arc::new(miden_precompiles::registry());
    let (a, b) = shared_witnesses();
    for witness in [a, b] {
        assert_eq!(witness.compute_root(registry.clone()).unwrap(), witness.root_unchecked());
    }
    let mut fixture = WitnessFixture::new();
    let one = uint(&mut fixture, UintDomain::U256, 1);
    let two = uint(&mut fixture, UintDomain::U256, 2);
    let false_eq = uint_eq(&mut fixture, one, two);
    let chunks = fixture.register(Node::chunks_from_bytes(b"abc")).unwrap();
    let false_hash = fixture.register(Keccak256Precompile::assert_node(3, chunks, chunks)).unwrap();
    for claim in [false_eq, false_hash] {
        let root = fixture.register(Node::and(TRUE_DIGEST, claim)).unwrap();
        let error = fixture.open(root).compute_root(registry.clone()).unwrap_err();
        assert!(matches!(error.root(), miden_core::deferred::PrecompileError::AssertionFailed));
    }
}

#[test]
fn ordered_repeated_batches_prove_and_verify() {
    let (a, b) = shared_witnesses();
    for inputs in [vec![a.clone(), b.clone(), a.clone()], vec![b.clone(), a.clone(), a.clone()]] {
        let roots: Vec<_> = inputs.iter().map(PrecompileWitness::root_unchecked).collect();
        let root = roots.iter().copied().reduce(fold_deferred_root).unwrap();
        let proof = crate::prove_precompiles(inputs, HashFunction::Blake3_256).unwrap();
        assert_eq!(proof.roots, roots);
        verify_deferred(&proof.proof, root).unwrap();
        assert!(verify_deferred(&proof.proof, TRUE_DIGEST).is_err());
    }
    assert_ne!(
        fold_deferred_root(a.root_unchecked(), b.root_unchecked()),
        fold_deferred_root(b.root_unchecked(), a.root_unchecked())
    );
}

#[test]
fn shared_subgraphs_keep_local_indices_and_binding_uses() {
    let (a, b) = shared_witnesses();
    // The same uint assertion is an internal child in A and a later statement in B. It also
    // appears as a direct transcript root here, covering roots already used as operands.
    let mut fixture = WitnessFixture::new();
    let value = uint(&mut fixture, UintDomain::U256, 17);
    let eq = uint_eq(&mut fixture, value, value);
    let root = fixture.open(eq);
    session_from_witnesses(vec![a.clone(), b, a, root]).unwrap().finish().check();
}

#[test]
fn randomized_shared_arithmetic_preserves_assertion_uses() {
    let mut rng = StdRng::seed_from_u64(0x0da6_3811);
    for _ in 0..4 {
        let mut fixture = WitnessFixture::new();
        let mut values: Vec<_> = (0..4)
            .map(|_| {
                let value = rng.random_range(1..32);
                (uint(&mut fixture, UintDomain::U256, value), value)
            })
            .collect();
        let mut assertions = vec![TRUE_DIGEST];
        let mut inputs = Vec::new();
        for step in 0..12 {
            let (lhs, a) = values[rng.random_range(0..values.len())];
            let (rhs, b) = values[rng.random_range(0..values.len())];
            // Small additions keep the independent u32 oracle exact while reusing prior nodes.
            let sum = fixture
                .register(
                    Node::join(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), lhs, rhs)
                        .unwrap(),
                )
                .unwrap();
            let expected = uint(&mut fixture, UintDomain::U256, a + b);
            let eq = uint_eq(&mut fixture, sum, expected);
            let shared = assertions[rng.random_range(0..assertions.len())];
            let assertion = fixture.register(Node::and(eq, shared)).unwrap();
            fixture.log_statement(assertion).unwrap();
            values.push((sum, a + b));
            assertions.push(assertion);
            if step % 4 == 3 {
                inputs.push(fixture.witness());
            }
        }
        inputs.insert(1, inputs[2].clone());
        inputs.push(inputs[0].clone());
        session_from_witnesses(inputs).unwrap().finish().check();
    }
}

#[test]
fn exponentially_shared_graph_is_imported_without_expansion() {
    let mut fixture = WitnessFixture::new();
    let mut root = TRUE_DIGEST;
    for _ in 0..2048 {
        root = fixture.register(Node::and(root, root)).unwrap();
    }
    let witness = fixture.open(root);
    let traces = session_from_witnesses(vec![witness.clone(), witness]).unwrap().finish();
    traces.check();
}

#[test]
fn malformed_semantics_are_located_before_session_operations() {
    let mut fixture = WitnessFixture::new();
    let one = uint(&mut fixture, UintDomain::U256, 1);
    let two = uint(&mut fixture, UintDomain::U256, 2);
    let field_one = uint(&mut fixture, UintDomain::K1Base, 1);
    let false_eq = uint_eq(&mut fixture, one, two);
    let wrong_domain = fixture
        .register(
            Node::join(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), one, field_one).unwrap(),
        )
        .unwrap();
    let bad_limb = fixture
        .register(
            Node::value(
                UintPrecompile::value_tag(UintDomain::U256),
                [Felt::new_unchecked(u32::MAX as u64 + 1); 8],
            )
            .unwrap(),
        )
        .unwrap();
    let unknown = fixture
        .register(
            Node::value(
                Tag::precompile(Felt::from_u32(77), [Felt::ZERO; 3]).unwrap(),
                [Felt::ZERO; 8],
            )
            .unwrap(),
        )
        .unwrap();
    let wrong_shape = fixture
        .register(
            Node::value(UintPrecompile::op_tag(UintPrecompile::ADD_OP_ID), [Felt::ZERO; 8])
                .unwrap(),
        )
        .unwrap();
    let off_curve = fixture
        .register(CurvePrecompile::affine_node_from_digests(
            miden_precompiles::CurveId::Secp256k1,
            field_one,
            field_one,
        ))
        .unwrap();
    let modulus = fixture
        .register(
            Node::value(
                UintPrecompile::value_tag(UintDomain::K1Base),
                miden_precompiles::K1Base::MODULUS.map(Felt::from_u32),
            )
            .unwrap(),
        )
        .unwrap();
    let above_modulus = fixture
        .register(
            Node::value(
                UintPrecompile::value_tag(UintDomain::K1Base),
                [Felt::from_u32(u32::MAX); 8],
            )
            .unwrap(),
        )
        .unwrap();
    let curve = miden_precompiles::CurveId::Secp256k1;
    let incomplete_infinity = fixture
        .register(CurvePrecompile::affine_node_from_digests(curve, TRUE_DIGEST, field_one))
        .unwrap();
    let wrong_coordinate_domain = fixture
        .register(CurvePrecompile::affine_node_from_digests(curve, one, one))
        .unwrap();
    let generator = fixture.register(CurvePrecompile::generator_node(curve)).unwrap();
    let identity = fixture.register(CurvePrecompile::identity_node(curve)).unwrap();
    let false_point_eq = fixture
        .register(
            Node::join(CurvePrecompile::op_tag(CurvePrecompile::EQ_OP_ID), generator, identity)
                .unwrap(),
        )
        .unwrap();
    let wrong_scalar_domain = fixture
        .register(
            Node::try_pair_list(CurvePrecompile::msm_tag(), vec![(generator, field_one)]).unwrap(),
        )
        .unwrap();
    let chunks = fixture.register(Node::chunks_from_bytes(b"abc")).unwrap();
    let false_hash = fixture.register(Keccak256Precompile::assert_node(3, chunks, chunks)).unwrap();
    // All remain structurally valid: hash length and byte packing are importer semantics.
    let short_hash_input =
        fixture.register(Keccak256Precompile::assert_node(33, chunks, chunks)).unwrap();
    let nonzero_hash_padding =
        fixture.register(Keccak256Precompile::assert_node(2, chunks, chunks)).unwrap();
    let wide_chunks = fixture
        .register(Node::chunks(vec![[Felt::new(u32::MAX as u64 + 1).unwrap(); 8]]).unwrap())
        .unwrap();
    let wide_hash_limb = fixture
        .register(Keccak256Precompile::assert_node(32, wide_chunks, chunks))
        .unwrap();
    let long_chunks = fixture.register(Node::chunks_from_bytes(&[0; 64])).unwrap();
    let long_hash_output = fixture
        .register(Keccak256Precompile::assert_node(3, chunks, long_chunks))
        .unwrap();
    let (valid, _) = shared_witnesses();
    for root in [
        false_eq,
        wrong_domain,
        bad_limb,
        unknown,
        wrong_shape,
        off_curve,
        false_hash,
        modulus,
        above_modulus,
        incomplete_infinity,
        wrong_coordinate_domain,
        false_point_eq,
        wrong_scalar_domain,
    ] {
        let error = session_from_witnesses(vec![valid.clone(), fixture.open(root)]).err().unwrap();
        assert!(
            matches!(
                error,
                SessionInputError::Invalid {
                    location: WitnessLocation::Entry { witness: 1, .. },
                    ..
                }
            ),
            "{error}"
        );
    }
    for (root, expected_reason) in [
        (short_hash_input, "malformed hash input chunks"),
        (nonzero_hash_padding, "malformed hash input chunks"),
        (wide_hash_limb, "malformed hash input chunks"),
        (long_hash_output, "malformed expected hash chunks"),
    ] {
        let error = session_from_witnesses(vec![valid.clone(), fixture.open(root)]).err().unwrap();
        assert!(
            matches!(
                error,
                SessionInputError::Invalid {
                    location: WitnessLocation::Entry { witness: 1, .. },
                    reason,
                } if reason == expected_reason
            ),
            "{error}"
        );
    }
    let hash = keccak(&mut fixture, b"abc");
    for root in [one, chunks, hash] {
        let error = session_from_witnesses(vec![fixture.open(root)]).err().unwrap();
        assert!(
            matches!(
                error,
                SessionInputError::Invalid {
                    location: WitnessLocation::Root { witness: 0 },
                    ..
                }
            ),
            "{error}"
        );
    }
}

#[test]
fn batch_limits_count_repeated_inputs_and_shared_hash_demand() {
    let (a, _) = shared_witnesses();
    assert!(matches!(session_from_witnesses(Vec::new()), Err(SessionInputError::Empty)));
    let entries_cost: usize = a
        .entries()
        .iter()
        .map(|entry| match entry {
            PrecompileWitnessEntry::Data { chunks, .. } => 4 + 8 * chunks.len(),
            PrecompileWitnessEntry::Join { .. } => 12,
            PrecompileWitnessEntry::PairList { pairs, .. } => 4 + 8 * pairs.len(),
        })
        .sum();
    let singleton_cost = entries_cost;
    let exact = ImportLimits {
        elements: singleton_cost,
        ..ImportLimits::default()
    };
    assert!(import_witnesses(vec![a.clone()], exact).is_ok());
    for limits in [
        ImportLimits { roots: 1, ..ImportLimits::default() },
        exact,
        ImportLimits {
            hash_bytes: b"shared prefix".len(),
            ..ImportLimits::default()
        },
    ] {
        assert!(matches!(
            import_witnesses(vec![a.clone(), a.clone()], limits),
            Err(SessionInputError::Limit { .. })
        ));
    }
    let exact_batch = ImportLimits {
        elements: 2 * singleton_cost + 12,
        hash_bytes: 2 * b"shared prefix".len(),
        ..ImportLimits::default()
    };
    assert!(import_witnesses(vec![a.clone(), a], exact_batch).is_ok());
}

#[test]
fn distinct_hash_claims_count_shared_payload_demand() {
    let mut fixture = WitnessFixture::new();
    // These lengths share one zero-padded input chunk but commit to distinct hash claims.
    for length in [1, 7, 31] {
        let hash = keccak(&mut fixture, &[0; 32][..length]);
        fixture.log_statement(hash).unwrap();
    }
    let witness = fixture.witness();
    let demand = 1 + 7 + 31;
    assert!(matches!(
        import_witnesses(
            vec![witness.clone()],
            ImportLimits {
                hash_bytes: demand - 1,
                ..ImportLimits::default()
            },
        ),
        Err(SessionInputError::Limit {
            location: WitnessLocation::Entry { witness: 0, .. },
            resource: "hash input bytes",
        })
    ));
    import_witnesses(
        vec![witness],
        ImportLimits {
            hash_bytes: demand,
            ..ImportLimits::default()
        },
    )
    .unwrap()
    .finish()
    .check();
}

#[test]
fn shared_commitment_cannot_change_payload_shape() {
    use miden_precompiles::CurveId;

    let mut fixture = WitnessFixture::new();
    let scalar = uint(&mut fixture, UintDomain::K1Scalar, 1);
    let generator = fixture.register(CurvePrecompile::generator_node(CurveId::Secp256k1)).unwrap();
    let msm = fixture
        .register(
            Node::try_pair_list(CurvePrecompile::msm_tag(), vec![(generator, scalar)]).unwrap(),
        )
        .unwrap();
    let eq = fixture
        .register(
            Node::join(CurvePrecompile::op_tag(CurvePrecompile::EQ_OP_ID), msm, generator).unwrap(),
        )
        .unwrap();
    fixture.log_statement(eq).unwrap();
    let valid = fixture.witness();
    let mut entries = valid.entries().to_vec();
    let changed = entries
        .iter()
        .position(|entry| matches!(entry, PrecompileWitnessEntry::PairList { .. }))
        .unwrap();
    let PrecompileWitnessEntry::PairList { tag, pairs } = &entries[changed] else {
        unreachable!()
    };
    let (lhs, rhs) = pairs[0];
    entries[changed] = PrecompileWitnessEntry::Join { tag: *tag, lhs, rhs };
    let malformed = PrecompileWitness::from_entries(entries).unwrap();
    assert_eq!(
        valid.root_unchecked(),
        malformed.root_unchecked(),
        "payload bytes commit identically"
    );
    let registry = Arc::new(miden_precompiles::registry());
    assert_eq!(valid.compute_root(registry.clone()).unwrap(), valid.root_unchecked());
    assert!(malformed.compute_root(registry).is_err());
    let error = session_from_witnesses(vec![valid, malformed]).err().unwrap();
    assert!(matches!(error, SessionInputError::Invalid {
        location: WitnessLocation::Entry { witness: 1, entry },
        reason: "conflicting definition for a shared commitment",
    } if entry == changed + 1));
}

#[test]
fn fallback_msm_limits_apply_across_distinct_claims() {
    use miden_precompiles::CurveId;

    let mut fixture = WitnessFixture::new();
    let generator = fixture.register(CurvePrecompile::generator_node(CurveId::Secp256k1)).unwrap();
    let zero = uint(&mut fixture, UintDomain::K1Scalar, 0);
    let mut inputs = Vec::new();
    for count in [1, 2] {
        let msm = fixture
            .register(
                Node::try_pair_list(CurvePrecompile::msm_tag(), vec![(generator, zero); count])
                    .unwrap(),
            )
            .unwrap();
        let identity =
            fixture.register(CurvePrecompile::identity_node(CurveId::Secp256k1)).unwrap();
        let eq = fixture
            .register(
                Node::join(CurvePrecompile::op_tag(CurvePrecompile::EQ_OP_ID), msm, identity)
                    .unwrap(),
            )
            .unwrap();
        inputs.push(fixture.open(eq));
    }
    let per_claim = ImportLimits {
        fallback_terms_per_node: 1,
        ..ImportLimits::default()
    };
    assert!(matches!(
        import_witnesses(vec![inputs[1].clone()], per_claim),
        Err(SessionInputError::Limit { .. })
    ));
    let aggregate = ImportLimits {
        fallback_terms: 2,
        ..ImportLimits::default()
    };
    assert!(matches!(
        import_witnesses(inputs.clone(), aggregate),
        Err(SessionInputError::Limit {
            location: WitnessLocation::Entry { witness: 1, .. },
            ..
        })
    ));
    // Repeated roots reuse the lowering, although their input scan and binding uses still count.
    import_witnesses(vec![inputs[1].clone(), inputs[1].clone()], aggregate)
        .unwrap()
        .finish()
        .check();
    import_witnesses(
        inputs,
        ImportLimits {
            fallback_terms: 3,
            ..ImportLimits::default()
        },
    )
    .unwrap()
    .finish()
    .check();
}
