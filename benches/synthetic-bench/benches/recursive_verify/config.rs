//! Environment-derived configuration and benchmark compositions.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use miden_vm::{HashFunction, Prover};

const DEFAULT_PROOF_COUNTS: [usize; 5] = [3, 4, 5, 6, 7];

#[derive(Clone, Copy)]
pub(super) struct ProofComposition {
    mvm: usize,
}

impl ProofComposition {
    pub(super) const fn mvm_count(self) -> usize {
        self.mvm
    }

    pub(super) const fn pvm_count(self) -> usize {
        1
    }

    pub(super) fn label(self) -> String {
        format!("{} mvm + 1 pvm ({} ecdsa)", self.mvm, self.mvm)
    }

    pub(super) fn machine_fields(self) -> String {
        format!(
            "mvm_proofs={} pvm_proofs=1 pvm_ecdsas={} pvm_keccaks={}",
            self.mvm, self.mvm, self.mvm
        )
    }
}

pub(super) struct BenchConfig {
    compositions: Vec<ProofComposition>,
    tx_proof_cache_dir: PathBuf,
    pvm_proof_cache_dir: PathBuf,
    write_recursive_masm: bool,
    base_stack_values: Vec<u64>,
    hash_lde_blocks: bool,
}

impl BenchConfig {
    pub(super) fn from_env() -> Self {
        let hash_lde_blocks = match std::env::var("RECURSION_HASH_LDE_BLOCKS") {
            Ok(value) if value == "0" => false,
            Ok(value) if value == "1" => true,
            Err(std::env::VarError::NotPresent) => false,
            _ => panic!("RECURSION_HASH_LDE_BLOCKS must be 0 or 1"),
        };
        println!("BENCH_RECURSION_CONFIG hash_lde_blocks={}", u8::from(hash_lde_blocks));
        let base_stack_values = stack_values_from_env("RECURSION_BENCH_STACK", "0,1");
        assert!(!base_stack_values.is_empty(), "RECURSION_BENCH_STACK must contain a value");
        let cache_root = env_path("CARGO_TARGET_DIR")
            .unwrap_or_else(|| workspace_root().join("target"))
            .join("recursive-bench-cache");
        Self {
            compositions: proof_counts_from_env(&DEFAULT_PROOF_COUNTS)
                .into_iter()
                .map(|mvm| ProofComposition { mvm })
                .collect(),
            tx_proof_cache_dir: cache_path_from_env(
                "RECURSION_BENCH_TX_PROOF_CACHE_DIR",
                cache_root.join("tx"),
            ),
            pvm_proof_cache_dir: cache_path_from_env(
                "RECURSION_BENCH_PVM_PROOF_CACHE_DIR",
                cache_root.join("pvm"),
            ),
            write_recursive_masm: std::env::var_os("RECURSION_MASM_WRITE").is_some(),
            base_stack_values,
            hash_lde_blocks,
        }
    }

    pub(super) fn outer_prover(&self) -> Prover {
        Prover::new()
            .with_hash_fn(HashFunction::Eidos)
            .with_hash_lde_blocks(self.hash_lde_blocks)
    }

    pub(super) fn compositions(&self) -> &[ProofComposition] {
        &self.compositions
    }

    pub(super) fn tx_proof_cache_dir(&self) -> &Path {
        &self.tx_proof_cache_dir
    }

    pub(super) fn pvm_proof_cache_dir(&self) -> &Path {
        &self.pvm_proof_cache_dir
    }

    pub(super) fn write_recursive_masm(&self) -> bool {
        self.write_recursive_masm
    }

    pub(super) fn stack_values_for_proof(&self, proof_index: usize) -> Vec<u64> {
        let mut values = self.base_stack_values.clone();
        values[0] = values[0]
            .checked_add(proof_index as u64)
            .expect("recursive proof input overflow");
        values
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn cache_path_from_env(name: &str, default: PathBuf) -> PathBuf {
    env_path(name).map_or(default, |path| {
        if path.is_absolute() {
            path
        } else {
            workspace_root().join(path)
        }
    })
}

pub(super) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn proof_counts_from_env(default: &[usize]) -> Vec<usize> {
    let Some(raw) = std::env::var("RECURSION_PROOF_COUNTS").ok().filter(|s| !s.trim().is_empty())
    else {
        return default.to_vec();
    };

    let mut counts = Vec::new();
    let mut seen = HashSet::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let value = entry.parse::<usize>().expect("RECURSION_PROOF_COUNTS entries must be usize");
        assert!((3..=7).contains(&value), "RECURSION_PROOF_COUNTS must be between 3 and 7");
        assert!(seen.insert(value), "duplicate RECURSION_PROOF_COUNTS entry: {value}");
        counts.push(value);
    }

    assert!(!counts.is_empty(), "RECURSION_PROOF_COUNTS did not select any proof counts");
    counts
}

fn stack_values_from_env(name: &str, default: &str) -> Vec<u64> {
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    if raw.trim().is_empty() {
        return Vec::new();
    }

    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u64>().unwrap_or_else(|_| panic!("{name} entries must be u64")))
        .collect()
}

pub(super) fn env_usize(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().unwrap_or_else(|_| panic!("{name} must be a usize"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}

pub(super) fn env_usize_allow_zero(name: &str, default: usize) -> usize {
    match std::env::var(name) {
        Ok(raw) => raw.parse::<usize>().unwrap_or_else(|_| panic!("{name} must be a usize")),
        Err(_) => default,
    }
}

pub(super) fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<u64>().unwrap_or_else(|_| panic!("{name} must be a u64"));
            assert!(value > 0, "{name} must be greater than zero");
            value
        },
        Err(_) => default,
    }
}
