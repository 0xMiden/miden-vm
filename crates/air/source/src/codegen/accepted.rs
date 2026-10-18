//! Explicit accepted identity inputs for delivery; rendering never accepts new pins.

use std::{format, fs, path::Path, string::String};

use miden_core::Felt;
use serde_json::Value;

const ACCEPTED_PATH: &str = "crates/air/generated/protocol/accepted.json";

pub(super) struct AcceptedIdentities {
    vm: RelationIdentity,
    precompile: RelationIdentity,
}

struct RelationIdentity {
    circuit: [u64; 4],
    relation: [u64; 4],
}

pub(super) fn load(root: &Path) -> Result<AcceptedIdentities, String> {
    let path = root.join(ACCEPTED_PATH);
    let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let json: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    parse(&json).map_err(|error| format!("{}: {error}", path.display()))
}

fn parse(json: &Value) -> Result<AcceptedIdentities, String> {
    if json["accepted_schema"].as_u64() != Some(1) {
        return Err("expected accepted_schema 1".into());
    }
    Ok(AcceptedIdentities {
        vm: relation(&json["relations"]["vm"], 1)?,
        precompile: relation(&json["relations"]["precompile"], 4)?,
    })
}

fn relation(json: &Value, protocol: u64) -> Result<RelationIdentity, String> {
    if json["protocol_id"].as_u64() != Some(protocol) {
        return Err(format!("unsupported accepted protocol id; expected {protocol}"));
    }
    Ok(RelationIdentity {
        circuit: word(&json["accepted_circuit_digest"])?,
        relation: word(&json["accepted_relation_digest"])?,
    })
}

fn word(json: &Value) -> Result<[u64; 4], String> {
    let limbs = json
        .as_array()
        .filter(|values| values.len() == 4)
        .ok_or("accepted digest must contain four canonical field integers")?;
    let mut word = [0; 4];
    for (slot, value) in word.iter_mut().zip(limbs) {
        *slot = value.as_u64().ok_or("accepted digest must contain u64 integers")?;
        Felt::new(*slot).map_err(|_| "accepted digest contains a noncanonical field integer")?;
    }
    Ok(word)
}

impl AcceptedIdentities {
    pub(super) fn check(
        &self,
        name: &str,
        circuit: [u64; 4],
        relation: [u64; 4],
    ) -> Result<(), String> {
        let accepted = match name {
            "vm" => &self.vm,
            "precompile" => &self.precompile,
            _ => return Err(format!("unknown accepted relation {name}")),
        };
        if accepted.circuit != circuit || accepted.relation != relation {
            return Err(format!(
                "{name} candidate identity differs from explicit accepted inputs; no pins accepted and no outputs written"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fixture() -> Value {
        json!({"accepted_schema": 1, "relations": {
            "vm": {"protocol_id": 1, "accepted_circuit_digest": [1,2,3,4], "accepted_relation_digest": [5,6,7,8]},
            "precompile": {"protocol_id": 4, "accepted_circuit_digest": [9,10,11,12], "accepted_relation_digest": [13,14,15,16]}
        }})
    }

    #[test]
    fn rejects_candidate_and_malformed_acceptance_inputs() {
        let input = fixture();
        let accepted = parse(&input).unwrap();
        accepted.check("vm", [1, 2, 3, 4], [5, 6, 7, 8]).unwrap();
        assert!(accepted.check("vm", [1, 2, 3, 9], [5, 6, 7, 8]).is_err());
        for invalid in [Value::Null, json!([1, 2, 3]), json!([1, 2, 3, u64::MAX])] {
            let mut input = fixture();
            input["relations"]["vm"]["accepted_circuit_digest"] = invalid;
            assert!(parse(&input).is_err());
        }
        let mut input = fixture();
        input["accepted_schema"] = json!(2);
        assert!(parse(&input).is_err());
    }
}
