#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{merkle::smt::Smt, Felt, Word, ONE};

struct FuzzInput {
    entries: Vec<(Word, Word)>,
    updates: Vec<(Word, Word)>,
}

impl FuzzInput {
    fn from_bytes(data: &[u8]) -> Self {
        let split_percentage = data.first().map_or(50, |byte| 20 + usize::from(byte % 60));
        let split_index = (data.len() * split_percentage) / 100;
        let (construction_data, update_data) = data.split_at(split_index);

        let entries = Self::parse_entries(construction_data);
        let updates = Self::parse_entries(update_data);

        Self { entries, updates }
    }

    fn parse_entries(data: &[u8]) -> Vec<(Word, Word)> {
        let mut entries = Vec::new();
        let num_entries = data.len() / 40; // Each entry is 40 bytes

        for chunk in data.chunks_exact(40).take(num_entries) {
            let key = Word::new([
                Felt::new_unchecked(u64::from_le_bytes(chunk[0..8].try_into().unwrap())),
                Felt::new_unchecked(u64::from_le_bytes(chunk[8..16].try_into().unwrap())),
                Felt::new_unchecked(u64::from_le_bytes(chunk[16..24].try_into().unwrap())),
                Felt::new_unchecked(u64::from_le_bytes(chunk[24..32].try_into().unwrap())),
            ]);
            let value = [
                ONE,
                ONE,
                ONE,
                Felt::new_unchecked(u64::from_le_bytes(chunk[32..40].try_into().unwrap())),
            ]
            .into();
            entries.push((key, value));
        }

        // Sort entries by key to ensure deterministic processing order between
        // sequential and concurrent implementations.
        entries.sort_by_key(|(key, _)| *key);

        entries
    }
}

fuzz_target!(|data: &[u8]| {
    let fuzz_input = FuzzInput::from_bytes(data);
    run_fuzz_smt(fuzz_input);
});

fn run_fuzz_smt(fuzz_input: FuzzInput) {
    let sequential_result = Smt::fuzz_with_entries_sequential(fuzz_input.entries.clone());
    let parallel_result = Smt::with_entries(fuzz_input.entries);

    match (sequential_result, parallel_result) {
        (Ok(sequential_smt), Ok(parallel_smt)) => {
            assert_eq!(sequential_smt.root(), parallel_smt.root(), "Mismatch in SMT roots!");

            let sequential_mutations =
                sequential_smt.fuzz_compute_mutations_sequential(fuzz_input.updates.clone());
            let parallel_mutations = parallel_smt.compute_mutations(fuzz_input.updates);

            match (sequential_mutations, parallel_mutations) {
                (Ok(sequential_mutations), Ok(parallel_mutations)) => {
                    assert_eq!(
                        sequential_mutations.root(),
                        parallel_mutations.root(),
                        "Mismatch in mutation results!"
                    );
                    assert_eq!(
                        sequential_mutations.node_mutations(),
                        parallel_mutations.node_mutations(),
                        "Node mutations mismatch!"
                    );
                    assert_eq!(
                        sequential_mutations.new_pairs(),
                        parallel_mutations.new_pairs(),
                        "New pairs mismatch!"
                    );
                },
                (Err(e1), Err(e2)) => {
                    assert_eq!(format!("{:?}", e1), format!("{:?}", e2), "Different errors returned");
                },
                (Ok(_), Err(e)) => panic!("Sequential succeeded but parallel failed with: {:?}", e),
                (Err(e), Ok(_)) => panic!("Parallel succeeded but sequential failed with: {:?}", e),
            }
        },
        (Err(e1), Err(e2)) => {
            assert_eq!(format!("{:?}", e1), format!("{:?}", e2), "Different errors returned");
        },
        (Ok(_), Err(e)) => panic!("Sequential succeeded but parallel failed with: {:?}", e),
        (Err(e), Ok(_)) => panic!("Parallel succeeded but sequential failed with: {:?}", e),
    }
}
