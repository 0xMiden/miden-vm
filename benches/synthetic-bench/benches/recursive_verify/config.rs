//! Environment-derived configuration and benchmark compositions.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use miden_vm::HashFunction;

const DEFAULT_PROOF_COUNTS: [usize; 7] = [2, 3, 4, 5, 6, 7, 8];
const PVM_PROOF_COUNT: usize = 1;

#[derive(Clone, Copy)]
pub(super) struct ProofComposition {
    mvm: usize,
    pvm: usize,
}

impl ProofComposition {
    pub(super) const fn mvm(proof_count: usize) -> Self {
        Self { mvm: proof_count, pvm: 0 }
    }

    const fn mixed(mvm_proof_count: usize) -> Self {
        Self {
            mvm: mvm_proof_count,
            pvm: PVM_PROOF_COUNT,
        }
    }

    pub(super) const fn mvm_count(self) -> usize {
        self.mvm
    }

    pub(super) const fn pvm_count(self) -> usize {
        self.pvm
    }

    pub(super) const fn is_mixed(self) -> bool {
        self.pvm != 0
    }

    pub(super) fn label(self) -> String {
        if self.is_mixed() {
            format!("{} mvm + {} pvm", self.mvm, self.pvm)
        } else {
            format!("{} proofs", self.mvm)
        }
    }

    pub(super) fn machine_fields(self) -> String {
        if self.is_mixed() {
            format!("mvm_proofs={} pvm_proofs={}", self.mvm, self.pvm)
        } else {
            format!("proofs={}", self.mvm)
        }
    }
}

const PVM_COMPARISON_COMPOSITIONS: [ProofComposition; 4] = [
    ProofComposition::mixed(4),
    ProofComposition::mvm(7),
    ProofComposition::mixed(5),
    ProofComposition::mvm(8),
];

pub(super) struct BenchConfig {
    outer_hash_fn: HashFunction,
    compositions: Vec<ProofComposition>,
    tx_masm_path: PathBuf,
    tx_proof_cache_dir: Option<PathBuf>,
    pvm_proof_cache_dir: Option<PathBuf>,
    write_recursive_masm: bool,
    base_stack_values: Vec<u64>,
}

impl BenchConfig {
    pub(super) fn from_env() -> Option<Self> {
        let tx_masm_path = env_path("RECURSION_BENCH_MASM")?;
        let tx_masm_path = resolve_masm_path(tx_masm_path);
        let hash_name =
            std::env::var("RECURSION_BENCH_HASH").unwrap_or_else(|_| "poseidon2".to_string());
        let outer_hash_fn = HashFunction::try_from(hash_name.as_str())
            .unwrap_or_else(|_| panic!("unsupported RECURSION_BENCH_HASH={hash_name:?}"));
        let base_stack_values = stack_values_from_env("RECURSION_BENCH_STACK", "0,1");
        let pvm_comparison = std::env::var_os("RECURSION_PVM_COMPARISON").is_some();
        assert!(
            !base_stack_values.is_empty(),
            "RECURSION_BENCH_STACK must contain at least one value"
        );

        let compositions = if pvm_comparison {
            assert!(
                std::env::var_os("RECURSION_PROOF_COUNTS").is_none(),
                "RECURSION_PROOF_COUNTS cannot be combined with RECURSION_PVM_COMPARISON"
            );
            PVM_COMPARISON_COMPOSITIONS.to_vec()
        } else {
            proof_counts_from_env(&DEFAULT_PROOF_COUNTS)
                .into_iter()
                .map(ProofComposition::mvm)
                .collect()
        };

        Some(Self {
            outer_hash_fn,
            compositions,
            tx_masm_path,
            tx_proof_cache_dir: cache_path_from_env("RECURSION_BENCH_TX_PROOF_CACHE_DIR"),
            pvm_proof_cache_dir: cache_path_from_env("RECURSION_BENCH_PVM_PROOF_CACHE_DIR"),
            write_recursive_masm: std::env::var_os("RECURSION_MASM_WRITE").is_some(),
            base_stack_values,
        })
    }

    pub(super) const fn outer_hash_fn(&self) -> HashFunction {
        self.outer_hash_fn
    }

    pub(super) fn compositions(&self) -> &[ProofComposition] {
        &self.compositions
    }

    pub(super) fn tx_masm_path(&self) -> &Path {
        &self.tx_masm_path
    }

    pub(super) fn tx_proof_cache_dir(&self) -> Option<&Path> {
        self.tx_proof_cache_dir.as_deref()
    }

    pub(super) fn pvm_proof_cache_dir(&self) -> Option<&Path> {
        self.pvm_proof_cache_dir.as_deref()
    }

    pub(super) const fn write_recursive_masm(&self) -> bool {
        self.write_recursive_masm
    }

    pub(super) fn stack_values_for_proof(&self, proof_index: usize) -> Vec<u64> {
        let mut values = self.base_stack_values.clone();
        values[0] = values[0]
            .checked_add(proof_index as u64)
            .expect("distinct stack input overflow");
        values
    }

    pub(super) fn requires_pvm(&self) -> bool {
        self.compositions.iter().copied().any(ProofComposition::is_mixed)
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn cache_path_from_env(name: &str) -> Option<PathBuf> {
    env_path(name).map(|path| {
        if path.is_absolute() {
            path
        } else {
            workspace_root().join(path)
        }
    })
}

fn resolve_masm_path(path: PathBuf) -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = workspace_root();
    let requested = path.display().to_string();

    let candidates = if path.is_absolute() {
        vec![path]
    } else {
        vec![path.clone(), manifest_dir.join(&path), workspace_root.join(&path)]
    };

    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("RECURSION_BENCH_MASM must point to a MASM file: {requested}"))
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
        assert!(value > 0, "RECURSION_PROOF_COUNTS entries must be non-zero");
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
