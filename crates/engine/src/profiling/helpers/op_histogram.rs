use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt::Write;

use miden_core::{Felt, operations::Operation};

/// A histogram of executed operations weighted by cycles per operation.
///
/// At each cycle, [`OpHistogram::record`] records the current operation. If `opX` takes 4 cycles
/// and was executed twice, its count will be 8.
pub struct OpHistogram {
    total_cycles: u128,
    counts: [u64; 256],
}

impl Default for OpHistogram {
    fn default() -> Self {
        Self {
            total_cycles: 0,
            counts: [0; 256],
        }
    }
}

impl OpHistogram {
    /// Records `op` as executed for one cycle.
    pub fn record(&mut self, op: Operation) {
        self.total_cycles += 1;
        // `op.op_code` returns u8 which can safely be used as index here
        self.counts[usize::from(op.op_code())] += 1;
    }

    /// Total number of recorded cycles.
    pub fn total_cycles(&self) -> u128 {
        self.total_cycles
    }

    /// Counts per operation, sorted in descending order by count.
    ///
    /// Only operations with a non-zero count are included.
    pub fn sorted_counts(&self) -> SortedCounts {
        let mut counts: SortedCounts = ALL_OPERATIONS
            .iter()
            .map(|&op| (op, self.counts[usize::from(op.op_code())]))
            .filter(|&(_, count)| count > 0)
            .collect();
        // Sort by count descending; break ties by opcode for a stable order.
        counts.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.op_code().cmp(&b.0.op_code())));
        counts
    }

    /// Renders the histogram as a report.
    pub fn report(&self) -> String {
        const OP_COL_WIDTH: usize = 16;
        const SHARE_COL_WIDTH: usize = 7;

        let total = self.total_cycles;
        let mut report = String::new();

        // Every row is laid out in three columns (op | share | count) with fixed widths so the
        // output stays aligned.
        writeln!(
            report,
            "{:<col1$} {:>col2$} {}",
            "total_cycles",
            "100%",
            total,
            col1 = OP_COL_WIDTH,
            col2 = SHARE_COL_WIDTH,
        )
        .unwrap();

        for (op, count) in self.sorted_counts() {
            let share = 100.0 * (count as f64) / (total as f64);
            // Any payload on the reconstructed `Operation` is just a meaningless placeholder, so
            // remove it. The report then only contains `push` instead of `push(0)`, for example.
            let label = op.to_string();
            let label = label.split('(').next().unwrap();
            writeln!(
                report,
                "{:<col1$} {:>col2$} {}",
                label,
                format!("{share:.2}%"),
                count,
                col1 = OP_COL_WIDTH,
                col2 = SHARE_COL_WIDTH,
            )
            .unwrap();
        }
        report
    }
}

/// Counts per operation, sorted in descending order by count.
pub type SortedCounts = Vec<(Operation, u64)>;

/// Every basic-block [`Operation`] variant, with placeholder payloads (`Felt::ZERO`) for the
/// value-carrying variants. Used to map the `counts` array back into typed operations for
/// reporting.
///
/// A unit test ensures that this list contains *all* relevant operations from `miden-core`.
const ALL_OPERATIONS: &[Operation] = &[
    Operation::Noop,
    Operation::Assert(Felt::ZERO),
    Operation::SDepth,
    Operation::Caller,
    Operation::Clk,
    Operation::Emit,
    Operation::Add,
    Operation::Neg,
    Operation::Mul,
    Operation::Inv,
    Operation::Incr,
    Operation::And,
    Operation::Or,
    Operation::Not,
    Operation::Eq,
    Operation::Eqz,
    Operation::Expacc,
    Operation::Ext2Mul,
    Operation::U32split,
    Operation::U32add,
    Operation::U32add3,
    Operation::U32sub,
    Operation::U32mul,
    Operation::U32madd,
    Operation::U32div,
    Operation::U32and,
    Operation::U32xor,
    Operation::U32assert2(Felt::ZERO),
    Operation::Pad,
    Operation::Drop,
    Operation::Dup0,
    Operation::Dup1,
    Operation::Dup2,
    Operation::Dup3,
    Operation::Dup4,
    Operation::Dup5,
    Operation::Dup6,
    Operation::Dup7,
    Operation::Dup9,
    Operation::Dup11,
    Operation::Dup13,
    Operation::Dup15,
    Operation::Swap,
    Operation::SwapW,
    Operation::SwapW2,
    Operation::SwapW3,
    Operation::SwapDW,
    Operation::MovUp2,
    Operation::MovUp3,
    Operation::MovUp4,
    Operation::MovUp5,
    Operation::MovUp6,
    Operation::MovUp7,
    Operation::MovUp8,
    Operation::MovDn2,
    Operation::MovDn3,
    Operation::MovDn4,
    Operation::MovDn5,
    Operation::MovDn6,
    Operation::MovDn7,
    Operation::MovDn8,
    Operation::CSwap,
    Operation::CSwapW,
    Operation::Push(Felt::ZERO),
    Operation::AdvPop,
    Operation::AdvPopW,
    Operation::MLoadW,
    Operation::MStoreW,
    Operation::MLoad,
    Operation::MStore,
    Operation::MStream,
    Operation::Pipe,
    Operation::CryptoStream,
    Operation::Compress,
    Operation::MpVerify(Felt::ZERO),
    Operation::MrUpdate,
    Operation::FriE2F4,
    Operation::HornerBase,
    Operation::HornerExt,
    Operation::EvalCircuit,
    Operation::LogDeferred,
];

#[cfg(test)]
mod tests;
