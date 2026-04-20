//! Shared test harness for LogUp-based aux-trace assertions.
//!
//! Wraps the prover-path LogUp collection pipeline (`build_lookup_fractions` + `accumulate`)
//! behind a small struct so each restored test under `processor/src/trace/tests/` can simply
//! call `LookupHarness::new(&trace)` and then assert per-row deltas and per-column terminals
//! against hand-constructed `LookupMessage` instances.

use alloc::vec::Vec;

use miden_air::{
    LOGUP_AUX_TRACE_WIDTH, LiftedAir, ProcessorAir,
    lookup::{
        BusId, Challenges, LookupMessage, MIDEN_MAX_MESSAGE_WIDTH, MidenLookupAir, accumulate,
        build_lookup_fractions,
    },
};
use miden_core::{
    field::{Field, PrimeCharacteristicRing, QuadFelt},
    utils::Matrix,
};
use miden_utils_testing::rand::rand_array;

use super::{ExecutionTrace, Felt};

// AUX COLUMN LAYOUT
// ================================================================================================

/// Aggregator column indices for [`MidenLookupAir`], mirroring the `eval` order
/// `[M1, M_2+5, M3, M4, C1, C2, C3]` (4 main-trace + 3 chiplet-trace = 7 columns).
/// Keeping these constants here (rather than importing from `air/`) makes any future bus
/// re-shuffle in the AIR a visible compile-time change.
#[allow(dead_code)]
pub(super) mod aux_col {
    /// M1 — `BUS_BLOCK_STACK_TABLE` + `BUS_RANGE_CHECK` (range-table response side).
    pub const BLOCK_STACK_AND_RANGE_TABLE: usize = 0;
    /// M_2+5 — `BUS_BLOCK_HASH_TABLE` + `BUS_OP_GROUP_TABLE`.
    pub const BLOCK_HASH_AND_OP_GROUP: usize = 1;
    /// M3 — `BUS_CHIPLETS` (requests from the decoder / stack side).
    pub const CHIPLET_REQUESTS: usize = 2;
    /// M4 — `BUS_STACK_OVERFLOW_TABLE`.
    pub const STACK_OVERFLOW: usize = 3;
    /// C1 — `BUS_CHIPLETS` (responses from the chiplet side).
    pub const CHIPLET_RESPONSES: usize = 4;
    /// C2 — `BUS_CHIPLETS` (hash-kernel) + `BUS_SIBLING_TABLE`.
    pub const HASH_KERNEL_AND_SIBLING: usize = 5;
    /// C3 — `BUS_ACE_WIRING` + `BUS_HASHER_PERM_LINK` (both ride the shared v_wiring column).
    pub const V_WIRING: usize = 6;
}

// LOOKUP HARNESS
// ================================================================================================

/// Per-test view over the `accumulate`-built aux trace for a given [`ExecutionTrace`].
///
/// Owns the 7-column `(num_rows + 1) × 7` accumulator matrix and the randomised
/// [`Challenges`] used to encode expected messages. Tests call [`Self::delta`] to
/// query per-row deltas on a specific aggregator column and [`Self::fraction`] to encode
/// expected `LookupMessage`s into their matching `1 / denom` contributions.
pub(super) struct LookupHarness {
    /// Flat row-major `(num_rows + 1) * 7` buffer; row `0` is all-zero, row `r + 1` holds the
    /// running sum after main-trace row `r`.
    aux_values: Vec<QuadFelt>,
    /// Number of main-trace rows (= `aux.height() - 1`).
    num_rows: usize,
    /// Column stride (always 7, but stored to avoid a magic number in `delta` / `terminal`).
    num_cols: usize,
    /// Challenges used to encode all expected messages. Also exposed for callers that need to
    /// reach into `bus_prefix` / `beta_powers` directly.
    pub challenges: Challenges<QuadFelt>,
}

#[allow(dead_code)]
impl LookupHarness {
    /// Build a harness for the given execution trace.
    ///
    /// Runs the real prover LogUp collection path end-to-end:
    /// 1. Extracts the main trace as a row-major matrix.
    /// 2. Lifts periodic columns via `LiftedAir::<Felt, QuadFelt>::periodic_columns`.
    /// 3. Draws random `(alpha, beta)` challenges in `QuadFelt`.
    /// 4. Calls `build_lookup_fractions(&MidenLookupAir, ...)` + `accumulate`.
    pub fn new(trace: &ExecutionTrace) -> Self {
        let main_trace = trace.main_trace().to_row_major();
        let public_vals = trace.to_public_values();
        let periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir);

        // `QuadFelt` itself doesn't implement `Randomizable`, so draw 4 base-field elements
        // and pair them into (alpha, beta). Same scheme used by `tests/lookup.rs`.
        let raw = rand_array::<Felt, 4>();
        let alpha = QuadFelt::new([raw[0], raw[1]]);
        let beta = QuadFelt::new([raw[2], raw[3]]);
        let air = MidenLookupAir;
        let challenges =
            Challenges::<QuadFelt>::new(alpha, beta, MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

        let fractions =
            build_lookup_fractions(&air, &main_trace, &periodic, &public_vals, &challenges);
        let rs_cols: &[usize] = &[0, 4];
        let frac_map: &[&[usize]] = &[&[1, 2, 3], &[5, 6]];
        let aux = accumulate(&fractions, rs_cols, frac_map);

        let num_cols = aux.width();
        let num_rows = aux.height() - 1;
        assert_eq!(
            num_cols, LOGUP_AUX_TRACE_WIDTH,
            "MidenLookupAir must produce exactly LOGUP_AUX_TRACE_WIDTH aux columns",
        );
        assert_eq!(
            num_rows,
            trace.main_trace().num_rows(),
            "aux height should be main trace length + 1",
        );

        Self {
            aux_values: aux.values,
            num_rows,
            num_cols,
            challenges,
        }
    }

    /// Number of main-trace rows covered by this harness.
    pub fn num_rows(&self) -> usize {
        self.num_rows
    }

    /// Running-sum value on column `col` at aux row `r` (where `r ∈ 0..=num_rows`).
    ///
    /// Row `0` is the initial condition (`QuadFelt::ZERO` for every column); row `num_rows`
    /// is the terminal value used for closure checks.
    pub fn aux(&self, col: usize, r: usize) -> QuadFelt {
        debug_assert!(col < self.num_cols);
        debug_assert!(r <= self.num_rows);
        self.aux_values[r * self.num_cols + col]
    }

    /// Per-row delta `aux[r + 1][col] - aux[r][col]` for main-trace row `r`.
    ///
    /// This is the contribution made by row `r` to the running sum on column `col`. Tests
    /// compare this against the sum of encoded expected messages for that row (via
    /// [`Self::fraction`] or direct `LookupMessage::encode` + `try_inverse`).
    pub fn delta(&self, col: usize, r: usize) -> QuadFelt {
        debug_assert!(r < self.num_rows);
        self.aux(col, r + 1) - self.aux(col, r)
    }

    /// Terminal value on column `col` — the running sum after every row has been applied.
    /// Balanced buses should close to `QuadFelt::ZERO`; the log-precompile transcript bus
    /// closes to a public-values-dependent non-zero value.
    pub fn terminal(&self, col: usize) -> QuadFelt {
        self.aux(col, self.num_rows)
    }

    /// Encode a `LookupMessage` against this harness's challenges and return its
    /// `1 / denominator` contribution. Panics if the encoded denominator is zero (that
    /// indicates a bug in the expected-message construction, not a test failure).
    pub fn fraction<M>(&self, msg: &M) -> QuadFelt
    where
        M: LookupMessage<Felt, QuadFelt>,
    {
        let denom = msg.encode(&self.challenges);
        denom.try_inverse().expect("encoded message denominator must be non-zero")
    }

    /// Sum of `+1 / denom` for every message in `msgs`. Matches a group of "add" interactions
    /// on a single bus column during one row.
    pub fn add_fractions<'a, M, I>(&self, msgs: I) -> QuadFelt
    where
        M: LookupMessage<Felt, QuadFelt> + 'a,
        I: IntoIterator<Item = &'a M>,
    {
        let mut acc = QuadFelt::ZERO;
        for m in msgs {
            acc += self.fraction(m);
        }
        acc
    }

    /// Sum of `-1 / denom` for every message in `msgs`. Matches a group of "remove"
    /// interactions on a single bus column during one row.
    pub fn remove_fractions<'a, M, I>(&self, msgs: I) -> QuadFelt
    where
        M: LookupMessage<Felt, QuadFelt> + 'a,
        I: IntoIterator<Item = &'a M>,
    {
        -self.add_fractions(msgs)
    }
}
