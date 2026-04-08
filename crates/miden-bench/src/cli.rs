//! Command-line interface types and parsing.

use std::{fmt, str::FromStr};

use clap::{Parser, ValueEnum};

const DEFAULT_NUM_QUERIES: usize = 100;
const DEFAULT_POW_BITS: usize = 16;

pub(crate) const DEFAULT_MIDEN_WIDTH: usize = 51;
pub(crate) const DEFAULT_MIDEN_AUX_COLS: usize = 8;

/// Prove and verify a set of AIR instances with the lifted or batch STARK prover.
///
/// Prints a configuration summary, proof size, and total time.
/// Pass -v for the full hierarchical tracing tree.
///
/// Trace spec format:  `AIR:LOG_HEIGHT[:WIDTH[:AUX_COLS]]`
///
/// Available AIR types (with short aliases):
///
///   keccak (k)     Keccak-f(1600) permutation, 24 rows/hash
///   poseidon2 (p)  Poseidon2 permutation (Goldilocks), 1 row/hash
///   blake3 (b)     Blake3 compression, 1 row/hash
///   miden (m)      Dummy degree-9 constraint (Miden VM shape)
///
/// WIDTH and AUX_COLS only apply to `miden` (defaults: 51, 8).
///
/// Examples:
///
///   bench                                             # default: blake3:15 keccak:18 poseidon2:19
///   bench keccak:15 keccak:18 keccak:19               # 3x Keccak at different heights
///   bench -v keccak:15                                 # full tracing tree
///   bench miden:18:51 miden:19:20                      # two Miden-shaped traces (auto blowup=3)
///   bench -m batch keccak:15 keccak:18 keccak:19       # batch-STARK comparison
///   bench -H keccak keccak:15                          # use Keccak hash for commitments
///   bench -H blake3 keccak:15                          # use BLAKE3 (32B) hash for commitments
///   bench -H blake3-192 keccak:15                      # use BLAKE3-192 (24B) hash for commitments
///   bench --log-blowup 2 --num-queries 50 keccak:18    # override PCS parameters
#[derive(Parser)]
#[command(name = "bench", verbatim_doc_comment)]
pub(crate) struct Cli {
    /// Trace specs (`AIR:LOG_HEIGHT[:WIDTH[:AUX_COLS]]`).
    ///
    /// When omitted, defaults to: blake3:15 keccak:18 poseidon2:19
    #[arg(value_name = "TRACE")]
    pub(crate) traces: Vec<TraceSpec>,

    /// Prover backend: `lifted` (LMCS-based) or `batch` (Plonky3 batch-STARK).
    #[arg(long, short = 'm', value_enum, default_value_t = Mode::Lifted)]
    pub(crate) mode: Mode,

    /// Hash function for the commitment scheme.
    ///
    /// Only applies to lifted mode; batch mode always uses poseidon2.
    #[arg(long, short = 'H', value_enum, default_value_t = HashFn::Poseidon2)]
    pub(crate) hash: HashFn,

    /// Print the full hierarchical tracing tree (default: summary only).
    ///
    /// RUST_LOG overrides this when set.
    #[arg(long, short = 'v')]
    pub(crate) verbose: bool,

    /// RNG seed for reproducible trace generation.
    #[arg(long, short = 's', default_value_t = 1)]
    pub(crate) seed: u64,

    /// Skip proof verification (prover-only profiling).
    #[arg(long)]
    pub(crate) no_verify: bool,

    // ── PCS Parameters ──────────────────────────────────────────────────
    /// Log₂ blowup factor for the LDE domain extension.
    ///
    /// Auto-detected when omitted: 1 for hash-only workloads, 3 when any
    /// `miden` trace is present (degree-9 constraints need more blowup).
    #[arg(long, help_heading = "PCS Parameters")]
    pub(crate) log_blowup: Option<u8>,

    /// Number of FRI query repetitions (higher = more soundness).
    #[arg(long, default_value_t = DEFAULT_NUM_QUERIES, help_heading = "PCS Parameters")]
    pub(crate) num_queries: usize,

    /// Proof-of-work grinding bits for the DEEP challenge (lifted mode only).
    #[arg(long, default_value_t = DEFAULT_POW_BITS, help_heading = "PCS Parameters")]
    pub(crate) deep_pow_bits: usize,

    /// Log₂ FRI folding arity (1, 2, or 3 for fold-by-2/4/8).
    #[arg(long, default_value_t = 2, help_heading = "PCS Parameters")]
    pub(crate) log_folding_arity: u8,

    /// Log₂ final polynomial degree bound.
    #[arg(long, default_value_t = 0, help_heading = "PCS Parameters")]
    pub(crate) log_final_degree: u8,

    /// Proof-of-work grinding bits per FRI folding round.
    #[arg(long, default_value_t = 0, help_heading = "PCS Parameters")]
    pub(crate) folding_pow_bits: usize,

    /// Proof-of-work grinding bits before query index sampling.
    #[arg(long, default_value_t = 0, help_heading = "PCS Parameters")]
    pub(crate) query_pow_bits: usize,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Mode {
    Lifted,
    Batch,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum HashFn {
    Poseidon2,
    Keccak,
    Blake3,
    #[value(name = "blake3-192")]
    Blake3_192,
}

impl fmt::Display for HashFn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashFn::Poseidon2 => write!(f, "poseidon2"),
            HashFn::Keccak => write!(f, "keccak"),
            HashFn::Blake3 => write!(f, "blake3"),
            HashFn::Blake3_192 => write!(f, "blake3-192"),
        }
    }
}

// ─── Trace spec parsing ──────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct TraceSpec {
    pub(crate) air_type: AirType,
    pub(crate) log_height: u8,
    /// Main trace width (miden only).
    pub(crate) width: usize,
    /// Extension-field auxiliary columns (miden only).
    pub(crate) num_aux_cols: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AirType {
    Keccak,
    Poseidon2,
    Blake3,
    Miden,
}

impl fmt::Display for AirType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keccak => write!(f, "keccak"),
            Self::Poseidon2 => write!(f, "poseidon2"),
            Self::Blake3 => write!(f, "blake3"),
            Self::Miden => write!(f, "miden"),
        }
    }
}

impl FromStr for TraceSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 2 {
            return Err(format!("expected <air>:<log_height>[:<width>[:<aux_cols>]], got '{s}'"));
        }

        let air_type = match parts[0] {
            "keccak" | "k" => AirType::Keccak,
            "poseidon2" | "p" => AirType::Poseidon2,
            "blake3" | "b" => AirType::Blake3,
            "miden" | "m" => AirType::Miden,
            other => return Err(format!("unknown AIR type '{other}'")),
        };

        let log_height: u8 =
            parts[1].parse().map_err(|_| format!("invalid log_height '{}'", parts[1]))?;

        let width = if parts.len() > 2 {
            parts[2].parse().map_err(|_| format!("invalid width '{}'", parts[2]))?
        } else {
            DEFAULT_MIDEN_WIDTH
        };

        let num_aux_cols = if parts.len() > 3 {
            parts[3].parse().map_err(|_| format!("invalid aux_cols '{}'", parts[3]))?
        } else {
            DEFAULT_MIDEN_AUX_COLS
        };

        if air_type == AirType::Miden && width < 9 {
            return Err("miden width must be at least 9".to_string());
        }

        Ok(Self {
            air_type,
            log_height,
            width,
            num_aux_cols,
        })
    }
}
