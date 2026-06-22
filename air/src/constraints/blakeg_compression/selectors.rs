//! Periodic-column selectors and gating expressions.
//!
//! All gating selectors used by the BlakeG constraints are exposed via named
//! methods on [`Selectors`].

use core::marker::PhantomData;

use miden_core::Felt;
use miden_crypto::stark::air::LiftedAirBuilder;

use super::periodic;

/// Bundles the periodic columns that drive BlakeG row-type gating and SIGMA indexing.
///
/// Constructed by copying the relevant slice out of `builder.periodic_values()`
/// (each `PeriodicVar` is `Copy`). This keeps the struct independent from the
/// builder while avoiding a heap allocation for every quotient-row evaluation.
pub struct Selectors<AB: LiftedAirBuilder<F = Felt>> {
    periodic: [AB::PeriodicVar; periodic::NUM_BLAKEG_PERIODIC_COLUMNS],
    _phantom: PhantomData<AB>,
}

impl<AB: LiftedAirBuilder<F = Felt>> Selectors<AB> {
    /// Construct a [`Selectors`] from the AIR builder's periodic-values slice.
    ///
    /// `offset` is the starting index of the BlakeG periodic columns within
    /// the slice (in the standalone BlakeG AIR this is `0`; in a fused AIR
    /// it would be the offset of the BlakeG periodic block).
    pub fn new(periodic: &[AB::PeriodicVar], offset: usize) -> Self {
        let end = offset + periodic::NUM_BLAKEG_PERIODIC_COLUMNS;
        let periodic = &periodic[offset..end];
        Self {
            periodic: core::array::from_fn(|idx| periodic[idx]),
            _phantom: PhantomData,
        }
    }

    #[inline]
    fn read(&self, idx: usize) -> AB::Expr {
        Into::<AB::Expr>::into(self.periodic[idx])
    }

    // --- single-row-type selectors -----------------------------------------

    /// 1 on A_col and A_diag rows, 0 elsewhere.
    pub fn is_a(&self) -> AB::Expr {
        self.read(periodic::P_IS_A)
    }

    /// 1 on B_col and B_diag rows, 0 elsewhere.
    pub fn is_b(&self) -> AB::Expr {
        self.read(periodic::P_IS_B)
    }

    /// 1 on C_col and C_diag rows, 0 elsewhere.
    pub fn is_c(&self) -> AB::Expr {
        self.read(periodic::P_IS_C)
    }

    /// 1 on D_col and D_diag rows, 0 elsewhere.
    pub fn is_d(&self) -> AB::Expr {
        self.read(periodic::P_IS_D)
    }

    /// 1 on rows 4..7 of each round (the diagonal half-round).
    pub fn is_diag(&self) -> AB::Expr {
        self.read(periodic::P_IS_DIAG_HALF)
    }

    /// 1 on row 0 only (the very first computation row of an invocation).
    pub fn is_first_comp(&self) -> AB::Expr {
        self.read(periodic::P_IS_FIRST_COMP)
    }

    /// 1 on row 1 only (the first B row of an invocation).
    pub fn is_first_b(&self) -> AB::Expr {
        self.read(periodic::P_IS_FIRST_B)
    }

    /// 1 on rows 56..59 (any footer row).
    pub fn is_footer(&self) -> AB::Expr {
        self.read(periodic::P_IS_FOOTER)
    }

    /// 1 on `F_t` only (`t` in `0..4`).
    pub fn is_f(&self, t: usize) -> AB::Expr {
        debug_assert!(t < 4, "footer index must be in 0..4");
        let id = match t {
            0 => periodic::P_IS_F0,
            1 => periodic::P_IS_F1,
            2 => periodic::P_IS_F2,
            3 => periodic::P_IS_F3,
            _ => unreachable!(),
        };
        self.read(id)
    }

    /// 1 on row 62 (input interface I).
    pub fn is_iface_in(&self) -> AB::Expr {
        self.read(periodic::P_IS_IFACE_IN)
    }

    /// 1 on row 60 (message row M0; carries m[0..7]).
    pub fn is_msg_row0(&self) -> AB::Expr {
        self.read(periodic::P_IS_MSG_ROW0)
    }

    /// 1 on row 61 (message row M1; carries m[8..15]).
    pub fn is_msg_row1(&self) -> AB::Expr {
        self.read(periodic::P_IS_MSG_ROW1)
    }

    /// 1 on either M0 or M1 (rows 60-61). Convenience sum for callers that
    /// gate on "any message row" without caring which half.
    pub fn is_msg_row(&self) -> AB::Expr {
        self.is_msg_row0() + self.is_msg_row1()
    }

    /// Expected BlakeG message-word index for lane `g` on A/C rows.
    pub fn sigma_msg_index(&self, g: usize) -> AB::Expr {
        debug_assert!(g < 4, "G lane index must be in 0..4");
        let idx = match g {
            0 => periodic::P_SIGMA_MSG_0,
            1 => periodic::P_SIGMA_MSG_1,
            2 => periodic::P_SIGMA_MSG_2,
            3 => periodic::P_SIGMA_MSG_3,
            _ => unreachable!(),
        };
        self.read(idx)
    }

    // --- compound selectors / gates ----------------------------------------

    /// `is_a + is_c`: 1 on any A or C row.
    /// A and C rows share the local slot layout, so most A/C constraints
    /// share this gate.
    pub fn is_ac(&self) -> AB::Expr {
        self.is_a() + self.is_c()
    }

    /// `is_b + is_d`: 1 on any B or D row.
    pub fn is_bd(&self) -> AB::Expr {
        self.is_b() + self.is_d()
    }

    /// A->B transition gate. A rows never occur at the final computation row.
    pub fn gate_a_b(&self) -> AB::Expr {
        self.is_a()
    }

    /// B->C transition gate. B rows never occur at the final computation row.
    pub fn gate_b_c(&self) -> AB::Expr {
        self.is_b()
    }

    /// C->D transition gate. C rows never occur at the final computation row.
    pub fn gate_c_d(&self) -> AB::Expr {
        self.is_c()
    }

    /// Gate for D rows that forward into the next A row.
    pub fn gate_d_to_next_a(&self) -> AB::Expr {
        self.read(periodic::P_GATE_D_TO_NEXT_A)
    }

    /// Gate for the very last computation row (row 55). Fires only there.
    /// Used to bind the final working state into F0's `W[0..15]` columns.
    pub fn gate_last_d(&self) -> AB::Expr {
        self.read(periodic::P_GATE_LAST_D)
    }
}
