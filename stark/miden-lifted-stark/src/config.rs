//! STARK configuration trait and generic implementation.
//!
//! [`StarkConfig`] bundles the LMCS, DFT, and challenger as associated types.
//! The base field `F` and extension field `EF` are generic parameters so that
//! functions using `SC: StarkConfig<F, EF>` can refer to `F` and `EF` directly
//! instead of going through `SC::F` / `SC::EF`.
//!
//! [`GenericStarkConfig`] provides a ready-made implementation for tests and
//! examples. Production integrations can implement `StarkConfig` on their own
//! concrete struct.

use core::marker::PhantomData;

use miden_stark_transcript::TranscriptChallenger;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, TwoAdicField};
use p3_matrix::{bitrev::BitReversibleMatrix, dense::RowMajorMatrix};

use crate::{lmcs::Lmcs, pcs::params::PcsParams};

/// Lifted STARK configuration.
///
/// `F` and `EF` are generic parameters rather than associated types so that
/// functions bounded by `SC: StarkConfig<F, EF>` can refer to them directly.
/// Bounds on `F` and `EF` are declared once here and inherited by every user.
pub trait StarkConfig<F: TwoAdicField, EF: ExtensionField<F>>: Clone {
    /// LMCS (Merkle commitment scheme).
    type Lmcs: Lmcs<F = F>;
    /// DFT for LDE computation.
    ///
    /// Its evaluations must bit-reverse to an owned [`RowMajorMatrix`] so committed LDEs are
    /// stored in a single concrete layout (e.g. `Radix2DitParallel`).
    type Dft: TwoAdicSubgroupDft<F, Evaluations: BitReversibleMatrix<F, BitRev = RowMajorMatrix<F>>>;
    /// Fiat-Shamir challenger.
    type Challenger: TranscriptChallenger<F, <Self::Lmcs as Lmcs>::Commitment>;

    /// PCS parameters (DEEP + FRI settings).
    fn pcs(&self) -> &PcsParams;
    /// LMCS instance for commitments.
    fn lmcs(&self) -> &Self::Lmcs;
    /// DFT implementation for LDE computation.
    fn dft(&self) -> &Self::Dft;
    /// Create a fresh challenger for a new proof/verification.
    fn challenger(&self) -> Self::Challenger;
}

/// Generic [`StarkConfig`] implementation.
///
/// Stores the PCS parameters, LMCS, DFT, and a challenger prototype
/// (cloned for each proof/verification). Use this for tests and examples;
/// production code can implement `StarkConfig` on a custom struct.
pub struct GenericStarkConfig<F, EF, L, Dft, Ch> {
    pub pcs: PcsParams,
    pub lmcs: L,
    pub dft: Dft,
    pub challenger: Ch,
    _phantom: PhantomData<fn() -> (F, EF)>,
}

impl<F, EF, L, Dft, Ch> GenericStarkConfig<F, EF, L, Dft, Ch> {
    pub fn new(pcs: PcsParams, lmcs: L, dft: Dft, challenger: Ch) -> Self {
        Self {
            pcs,
            lmcs,
            dft,
            challenger,
            _phantom: PhantomData,
        }
    }
}

// Manual Clone: avoids requiring F: Clone, EF: Clone.
impl<F, EF, L: Clone, Dft: Clone, Ch: Clone> Clone for GenericStarkConfig<F, EF, L, Dft, Ch> {
    fn clone(&self) -> Self {
        Self {
            pcs: self.pcs,
            lmcs: self.lmcs.clone(),
            dft: self.dft.clone(),
            challenger: self.challenger.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<F, EF, L, Dft, Ch> StarkConfig<F, EF> for GenericStarkConfig<F, EF, L, Dft, Ch>
where
    F: TwoAdicField,
    EF: ExtensionField<F>,
    L: Lmcs<F = F>,
    Dft: TwoAdicSubgroupDft<F, Evaluations: BitReversibleMatrix<F, BitRev = RowMajorMatrix<F>>>
        + Clone,
    Ch: TranscriptChallenger<F, L::Commitment>,
{
    type Lmcs = L;
    type Dft = Dft;
    type Challenger = Ch;

    fn pcs(&self) -> &PcsParams {
        &self.pcs
    }

    fn lmcs(&self) -> &L {
        &self.lmcs
    }

    fn dft(&self) -> &Dft {
        &self.dft
    }

    fn challenger(&self) -> Ch {
        self.challenger.clone()
    }
}
