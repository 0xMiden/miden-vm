use miden_core::{Felt, Word};

use super::*;

fn word(values: [u32; 4]) -> Word {
    Word::from(values.map(Felt::from))
}

/// V5 snapshot written by `ReplaySnapshot::write_to_file` for `begin push.1 push.2 add drop end`.
#[test]
fn replay_snapshot_v5_fixture_round_trips() {
    let bytes = include_bytes!("../../../tests/fixtures/replay-v5.bin");
    let restored = ReplaySnapshot::read_from_bytes(bytes).unwrap();
    assert_eq!(bytes[SNAPSHOT_MAGIC.len()], 5);
    assert_eq!(
        restored.package.commitment(),
        Word::try_from("0xcc93b23806c34d65dba8528d9dd3c25d8696e7d28a9a947fab48cc2effc6b36c")
            .unwrap(),
    );
    assert_eq!(
        restored.stack_inputs,
        StackInputs::new(&[Felt::from(42u32), Felt::from(43u32)]).unwrap(),
    );
    assert_eq!(
        restored.advice_inputs,
        AdviceInputs::default().with_stack([Felt::from(99u32)].into_iter().collect()),
    );
    assert_eq!(
        restored.options,
        ExecutionOptions::new(Some(100_000), 32, 1024)
            .unwrap()
            .with_max_advice_size_bytes(256)
            .with_max_hash_len_bytes(512)
            .with_max_num_continuations(128)
            .with_max_memory_elements(1024)
            .with_max_stack_depth(128)
            .unwrap(),
    );
    assert_eq!(restored.mast_forests.len(), 1);
    assert_eq!(
        restored.mast_forests[0].mast_forest().commitment(),
        restored.package.mast_forest_commitment(),
    );
    assert_eq!(restored.event_log.len(), 3);
    assert_eq!(restored.event_log[1].len(), 0, "empty event batch must survive");
    match restored.event_log[0].as_slice() {
        [AdviceMutation::ExtendStack { stack }] => {
            assert_eq!(
                stack.iter().copied().collect::<Vec<_>>(),
                [Felt::from(7u32), Felt::from(8u32)],
            );
        },
        _ => panic!("unexpected first event batch"),
    }
    match restored.event_log[2].as_slice() {
        [AdviceMutation::ExtendMerkleStore { inner_nodes }] => {
            assert_eq!(inner_nodes.len(), 1);
            assert_eq!(inner_nodes[0].value, word([1, 2, 3, 4]));
            assert_eq!(inner_nodes[0].left, word([5, 6, 7, 8]));
            assert_eq!(inner_nodes[0].right, word([9, 10, 11, 12]));
        },
        _ => panic!("unexpected merkle-store event batch"),
    }
    assert_eq!(restored.to_bytes().unwrap().as_slice(), bytes);
}

/// A file that does not start with the snapshot magic is rejected.
#[test]
fn replay_snapshot_rejects_bad_magic() {
    let err = ReplaySnapshot::read_from_bytes(b"not a snapshot at all really");
    assert!(err.is_err(), "expected deserialization to fail on bad magic");
}

/// Unsupported policies must be rejected before an existing snapshot file is overwritten.
#[cfg(feature = "std")]
#[test]
fn replay_snapshot_rejects_custom_precompile_limits() {
    use miden_assembly::{Assembler, DefaultSourceManager};
    use miden_core::deferred::PrecompileLimits;

    let package = Assembler::new(Arc::new(DefaultSourceManager::default()))
        .assemble_program("program", "begin nop end")
        .map(Arc::<Package>::from)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot");
    let original = b"existing snapshot";
    std::fs::write(&path, original).unwrap();

    for options in [
        ExecutionOptions::default().with_execution_precompile_limits(PrecompileLimits::new(0)),
        ExecutionOptions::default().with_verification_precompile_limits(PrecompileLimits::new(0)),
    ] {
        let snapshot = ReplaySnapshot {
            package: package.clone(),
            stack_inputs: StackInputs::default(),
            advice_inputs: AdviceInputs::default(),
            options,
            mast_forests: vec![],
            event_log: vec![],
        };
        assert_eq!(
            snapshot.to_bytes().unwrap_err(),
            ReplaySnapshotEncodeError::UnsupportedPrecompileLimits,
        );
        let mut bytes = b"prefix".to_vec();
        assert!(snapshot.write_into(&mut bytes).is_err());
        assert_eq!(bytes, b"prefix");
        let error = snapshot.write_to_file(&path).expect_err("custom limits must not be lost");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

/// Older snapshots may contain incompatible package formats and opcode semantics.
#[test]
fn replay_snapshot_rejects_unsupported_versions() {
    for version in [SNAPSHOT_VERSION - 1, SNAPSHOT_VERSION + 1] {
        let mut bytes = SNAPSHOT_MAGIC.to_vec();
        bytes.push(version);
        let Err(err) = ReplaySnapshot::read_from_bytes(&bytes) else {
            panic!("expected deserialization to reject snapshot version {version}");
        };
        assert!(err.to_string().contains("unsupported replay snapshot version"));
    }
}
