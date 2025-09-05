use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Unit;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Newtype(u64);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Person {
    name: String,
    age: u32,
    email: Option<String>,
    #[serde(skip)]
    address: Option<String>,
    #[serde(skip_serializing_if = "Metadata::is_empty")]
    metadata: Metadata,
    _unit: Unit,
    _newtype: Newtype,
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
struct Metadata {
    metadata: BTreeMap<String, String>,
}
impl Metadata {
    #[inline]
    fn new(entries: impl IntoIterator<Item = (String, String)>) -> Self {
        Self { metadata: BTreeMap::from_iter(entries) }
    }

    pub fn is_empty(&self) -> bool {
        self.metadata.is_empty()
    }
}

#[test]
fn test_roundtrip_all() {
    let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
    let person = Person {
        name: "Alice".to_string(),
        age: 30,
        email: Some("alice@example.com".to_string()),
        address: None,
        metadata: Metadata::new([
            ("key".to_string(), "value".to_string()),
            ("a".to_string(), "b".to_string()),
        ]),
        _unit: Unit,
        _newtype: Newtype(101),
    };

    let bytes = to_bytes(&person).unwrap();
    let decoded: Person = from_bytes(&bytes).unwrap();

    assert_eq!(person, decoded);
}

#[test]
fn test_roundtrip_with_skipped_field() {
    let _ = env_logger::Builder::from_env("MIDEN_LOG").format_timestamp(None).try_init();
    let person = Person {
        name: "Alice".to_string(),
        age: 30,
        email: None,
        address: None,
        metadata: Default::default(),
        _unit: Unit,
        _newtype: Newtype(101),
    };

    let bytes = to_bytes(&person).unwrap();
    let decoded: Person = from_bytes(&bytes).unwrap();

    assert_eq!(person, decoded);
}
