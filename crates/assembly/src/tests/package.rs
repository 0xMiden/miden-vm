use crate::serde::Serializable;
use crate::package::Package;
use {
    proptest::prelude::*,
    proptest::test_runner::Config,
    proptest::test_runner::TestRunner,
};

// PACKAGE SERIALIZATION AND DESERIALIZATION
// ================================================================================================

#[test]
fn package_serialization_roundtrip() {
    // since the test is quite expensive, 128 cases should be enough to cover all edge cases
    // (default is 256)
    let cases = 128;
    TestRunner::new(Config::with_cases(cases))
        .run(&any::<Package>(), move |package| {
            let bytes = package.to_bytes();
            let deserialized = Package::read_from_bytes_trusted(&bytes).unwrap();
            prop_assert_eq!(package, deserialized);
            Ok(())
        })
        .unwrap_or_else(|err| {
            panic!("{err}");
        });
}
