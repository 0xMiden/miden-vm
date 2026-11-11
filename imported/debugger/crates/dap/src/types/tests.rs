use super::*;

#[allow(unused)]
#[test]
fn test_checksum_algorithm_serde() {
    let sha = ChecksumAlgorithm::SHA256;
    let sha_ser = serde_json::to_value(sha).unwrap();
    assert_eq!("SHA256", sha_ser);
    let sha_deser: ChecksumAlgorithm = serde_json::from_value(sha_ser).unwrap();
    assert!(matches!(ChecksumAlgorithm::SHA256, sha_deser));

    let ts = ChecksumAlgorithm::Timestamp;
    let ts_ser = serde_json::to_value(&ts).unwrap();
    assert_eq!("timestamp", ts_ser);
    #[allow(unused)]
    let ts_deser: ChecksumAlgorithm = serde_json::from_value(ts_ser).unwrap();
    assert!(matches!(ChecksumAlgorithm::Timestamp, ts_deser));
}

#[allow(unused)]
#[test]
fn test_invalidated_areas_serde() {
    let str = "string".to_string();
    let untagged = InvalidatedAreas::String(str.clone());
    let untagged_ser = serde_json::to_value(untagged).unwrap();
    assert_eq!(str, untagged_ser);
    let untagged_deser: InvalidatedAreas = serde_json::from_value(untagged_ser).unwrap();
    assert!(matches!(InvalidatedAreas::String(str), untagged_deser));
}

#[cfg(feature = "integration_testing")]
#[test]
fn stack_frame_dummy_supports_arc_str_name() {
    use fake::Fake as _;

    let _: StackFrame = fake::Faker.fake();
}

#[cfg(feature = "integration_testing")]
#[test]
fn source_dummy_generates_leaf_sources() {
    use fake::Fake as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..64 {
        let source: Source = fake::Faker.fake_with_rng(&mut rng);
        assert!(source.sources.is_none());
    }
}

#[cfg(feature = "integration_testing")]
#[test]
fn exception_details_dummy_generates_leaf_exceptions() {
    use fake::Fake as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0);
    for _ in 0..64 {
        let details: ExceptionDetails = fake::Faker.fake_with_rng(&mut rng);
        assert!(details.inner_exception.is_none());
    }
}
