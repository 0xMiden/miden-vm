//! Run with `make bench benchmark=merkle_witness` from the repository root.
//! Sizes are binary bytes, before CLI hex encoding (which doubles payload bytes). All full
//! transports include leaf preimages. `paths_only` is diagnostic, not a complete witness.
//! Expanded bytes are logical node triples plus map keys/values, not allocator overhead or RSS.

use std::{collections::BTreeMap, hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use miden_crypto::{
    Felt, Word,
    merkle::{
        smt::{PartialSmt, Smt, SmtProof, SmtWitness},
        store::MerkleStore,
    },
    utils::{Deserializable, Serializable},
};

type StorePayload = (MerkleStore, BTreeMap<Word, Vec<Felt>>);
type Proofs = Vec<(Word, Vec<SmtProof>)>;
const MAX_NODES: usize = 16 * 1024 * 1024 / 96;

fn key(position: u64) -> Word {
    Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(position),
    ])
}

fn tree(positions: impl IntoIterator<Item = u64>) -> Smt {
    Smt::with_entries(positions.into_iter().map(|p| (key(p), Word::from([4, 5, 6, 7u32])))).unwrap()
}

fn openings(tree: &Smt, positions: impl IntoIterator<Item = u64>) -> (Word, Vec<SmtProof>) {
    (tree.root(), positions.into_iter().map(|p| tree.open(&key(p))).collect())
}

fn cases() -> Vec<(&'static str, Proofs)> {
    let step = u64::MAX / 257;
    let clustered = tree(0..256);
    let spread = tree((0..256).map(|i| i * step));
    let mut updated = clustered.clone();
    updated.insert(key(17), Word::from([8, 9, 10, 11u32])).unwrap();
    vec![
        ("empty", vec![openings(&Smt::default(), [31])]),
        ("single", vec![openings(&tree([7]), [7])]),
        ("sparse_opening", vec![openings(&spread, [17 * step])]),
        ("clustered_256", vec![openings(&clustered, 0..256)]),
        ("spread_256", vec![openings(&spread, (0..256).map(|i| i * step))]),
        ("exclusion_256", vec![openings(&spread, (0..256).map(|i| i * step + 1))]),
        (
            "two_roots",
            vec![openings(&clustered, 0..256), openings(&spread, (0..256).map(|i| i * step))],
        ),
        ("two_versions", vec![openings(&clustered, 0..256), openings(&updated, 0..256)]),
    ]
}

fn expand_partials(trees: &[PartialSmt]) -> StorePayload {
    let store = trees.iter().flat_map(PartialSmt::inner_nodes).collect();
    let leaves = trees
        .iter()
        .flat_map(PartialSmt::leaves)
        .map(|(_, leaf)| (leaf.hash(), leaf.to_elements().collect()))
        .collect();
    (store, leaves)
}

fn expand_proofs(groups: Proofs) -> StorePayload {
    let mut store = MerkleStore::default();
    let mut leaves = BTreeMap::new();
    for (root, proofs) in groups {
        for proof in proofs {
            assert_eq!(proof.compute_root(), root);
            store.extend(proof.authenticated_nodes());
            // Empty leaves have no preimage to supply, matching PartialSmt's implicit empties.
            if proof.leaf().num_entries() > 0 {
                leaves.insert(proof.leaf().hash(), proof.leaf().to_elements().collect());
            }
        }
    }
    (store, leaves)
}

fn merkle_witness(c: &mut Criterion) {
    for (name, proofs) in cases() {
        let partials: Vec<_> = proofs
            .iter()
            .map(|(_, proofs)| PartialSmt::from_proofs(proofs.clone()).unwrap())
            .collect();
        let witnesses: Vec<_> = partials.iter().map(SmtWitness::from).collect();
        let payload = expand_partials(&partials);
        let store_bytes = payload.to_bytes();
        let proof_bytes = proofs.to_bytes();
        let partial_bytes = partials.to_bytes();
        let witness_bytes = witnesses.to_bytes();
        let paths_only: usize =
            proofs.iter().flat_map(|(_, p)| p).map(|p| p.path().to_bytes().len()).sum();
        let expanded_bytes = payload.0.num_internal_nodes() * 96
            + payload.1.values().map(|v| 32 + v.len() * 8).sum::<usize>();
        eprintln!(
            "witness_size case={name} store_only={} store_with_leaves={} independent_proofs={} partial_smt={} smt_witness={} paths_only={paths_only} expanded_nodes={} expanded_logical_bytes={expanded_bytes} reconstruction_limit={MAX_NODES}",
            payload.0.to_bytes().len(),
            store_bytes.len(),
            proof_bytes.len(),
            partial_bytes.len(),
            witness_bytes.len(),
            payload.0.num_internal_nodes()
        );

        // Validate every transport against the same full payload outside the timed loops.
        assert_eq!(expand_proofs(proofs.clone()), payload);
        assert_eq!(
            expand_partials(&Vec::<PartialSmt>::read_from_bytes(&partial_bytes).unwrap()),
            payload
        );
        let reconstructed: Vec<_> = Vec::<SmtWitness>::read_from_bytes(&witness_bytes)
            .unwrap()
            .into_iter()
            .map(|w| w.into_partial_smt(MAX_NODES).unwrap())
            .collect();
        assert_eq!(expand_partials(&reconstructed), payload);

        let mut group = c.benchmark_group(name);
        group
            .sample_size(10)
            .warm_up_time(Duration::from_millis(200))
            .measurement_time(Duration::from_secs(1));
        group.bench_function("encode_store", |b| b.iter(|| black_box(&payload).to_bytes()));
        group.bench_function("decode_store", |b| {
            b.iter(|| {
                StorePayload::read_from_bytes_with_budget(
                    black_box(&store_bytes),
                    store_bytes.len(),
                )
                .unwrap()
            })
        });
        group.bench_function("encode_proofs", |b| b.iter(|| black_box(&proofs).to_bytes()));
        group.bench_function("decode_proofs_to_store", |b| {
            b.iter(|| {
                expand_proofs(
                    Proofs::read_from_bytes_with_budget(black_box(&proof_bytes), proof_bytes.len())
                        .unwrap(),
                )
            })
        });
        group.bench_function("encode_partial_smt", |b| b.iter(|| black_box(&partials).to_bytes()));
        group.bench_function("decode_partial_smt_to_store", |b| {
            b.iter(|| {
                expand_partials(
                    &Vec::<PartialSmt>::read_from_bytes_with_budget(
                        black_box(&partial_bytes),
                        partial_bytes.len(),
                    )
                    .unwrap(),
                )
            })
        });
        group.bench_function("encode_smt_witness", |b| b.iter(|| black_box(&witnesses).to_bytes()));
        group.bench_function("build_smt_witness", |b| {
            b.iter(|| black_box(&partials).iter().map(SmtWitness::from).collect::<Vec<_>>())
        });
        group.bench_function("decode_smt_witness_to_store", |b| {
            b.iter(|| {
                let partials: Vec<_> = Vec::<SmtWitness>::read_from_bytes_with_budget(
                    black_box(&witness_bytes),
                    witness_bytes.len(),
                )
                .unwrap()
                .into_iter()
                .map(|w| w.into_partial_smt(MAX_NODES).unwrap())
                .collect();
                expand_partials(&partials)
            })
        });
        group.finish();
    }
}

criterion_group!(benches, merkle_witness);
criterion_main!(benches);
