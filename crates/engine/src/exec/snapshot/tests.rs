use miden_assembly::{Assembler, DefaultSourceManager};
use miden_core::{Felt, Word, crypto::merkle::InnerNodeInfo};

use super::*;

fn word(values: [u32; 4]) -> Word {
    Word::from(values.map(Felt::from))
}

/// A snapshot round-trips through bytes: program, inputs, forests, and the event log — across
/// the AdviceMutation variant shapes that carry simple payloads — survive intact.
#[test]
fn replay_snapshot_round_trips() {
    let source_manager = Arc::new(DefaultSourceManager::default());
    let program = Assembler::new(source_manager)
        .assemble_program("program", "begin push.1 push.2 add drop end")
        .map(Arc::<Package>::from)
        .expect("failed to assemble test program");
    let forest = LoadedMastForest::with_package_debug_info(
        program.mast_forest().clone(),
        program.debug_info(),
    );

    let event_log = vec![
        vec![AdviceMutation::extend_advice_stack(
            [Felt::from(7u32), Felt::from(8u32)].into_iter().collect(),
        )],
        vec![],
        vec![AdviceMutation::extend_merkle_store([InnerNodeInfo {
            value: word([1, 2, 3, 4]),
            left: word([5, 6, 7, 8]),
            right: word([9, 10, 11, 12]),
        }])],
    ];

    let snapshot = ReplaySnapshot {
        package: program.clone(),
        stack_inputs: StackInputs::new(&[Felt::from(42u32), Felt::from(43u32)]).unwrap(),
        advice_inputs: AdviceInputs::default()
            .with_stack([Felt::from(99u32)].into_iter().collect()),
        options: ExecutionOptions::new(Some(100_000), 32, 1024)
            .unwrap()
            .with_max_advice_size_bytes(256)
            .with_max_hash_len_bytes(512)
            .with_overlapped_trace_build(false)
            .with_max_num_continuations(128)
            .with_max_memory_elements(1024)
            .with_max_stack_depth(128)
            .unwrap(),
        mast_forests: vec![forest],
        event_log,
    };

    let restored = ReplaySnapshot::read_from_bytes(&snapshot.to_bytes().unwrap())
        .expect("snapshot failed to deserialize");

    assert_eq!(restored.package.commitment(), snapshot.package.commitment());
    assert_eq!(restored.stack_inputs, snapshot.stack_inputs);
    assert_eq!(restored.advice_inputs, snapshot.advice_inputs);
    assert_eq!(restored.options, snapshot.options);
    assert_eq!(restored.mast_forests.len(), 1);
    assert_eq!(restored.event_log.len(), 3);
    assert_eq!(restored.event_log[1].len(), 0, "empty event batch must survive");
    match restored.event_log[0].as_slice() {
        [AdviceMutation::ExtendStack { stack }] => {
            assert_eq!(
                stack.iter().copied().collect::<Vec<_>>(),
                [Felt::from(7u32), Felt::from(8u32)],
            );
        }
        _ => panic!("unexpected first event batch"),
    }
    match restored.event_log[2].as_slice() {
        [AdviceMutation::ExtendMerkleStore { inner_nodes }] => {
            assert_eq!(inner_nodes.len(), 1);
            assert_eq!(inner_nodes[0].value, word([1, 2, 3, 4]));
            assert_eq!(inner_nodes[0].right, word([9, 10, 11, 12]));
        }
        _ => panic!("unexpected merkle-store event batch"),
    }
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
fn replay_snapshot_rejects_previous_version() {
    let mut bytes = SNAPSHOT_MAGIC.to_vec();
    bytes.push(SNAPSHOT_VERSION - 1);

    let Err(err) = ReplaySnapshot::read_from_bytes(&bytes) else {
        panic!("expected deserialization to reject a snapshot from a previous version");
    };
    assert!(err.to_string().contains("unsupported replay snapshot version"));
}
