//! Shape declarations that do not construct fixed matrices or witnesses.

use alloc::{borrow::Cow, vec::Vec};

use p3_field::Field;
use thiserror::Error;

/// Declared shape of a fixed preprocessed matrix.
///
/// Setup checks this declaration against the actual matrix before committing it. The main trace
/// must have the same native height. Declaring a shape does not allocate the matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreprocessedSpec {
    pub width: usize,
    pub log_height: u8,
}

/// Immutable configuration of one authored AIR relation.
///
/// Periodic definitions may be borrowed from the source. Analysis can take an owned copy with
/// [`Self::into_owned`], without invoking a fixed-table factory or witness construction. Zero
/// auxiliary width is representable here even when a particular proof engine requires auxiliaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirSpec<'a, F: Field> {
    pub main_width: usize,
    pub aux_width: usize,
    pub num_public_values: usize,
    pub num_challenges: usize,
    pub num_exports: usize,
    pub preprocessed: Option<PreprocessedSpec>,
    pub periodic_columns: Cow<'a, [Vec<F>]>,
}

/// Invalid source metadata, detected before allocating symbolic inputs.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SpecError {
    #[error("an AIR must have at least one main column")]
    EmptyMain,
    #[error("invalid preprocessed shape: width {width}, log height {log_height}")]
    Preprocessed { width: usize, log_height: u8 },
    #[error("periodic column {column} has non-power-of-two or zero length {length}")]
    Periodic { column: usize, length: usize },
    #[error("AIR shape overflows host indexing for {0}")]
    Overflow(&'static str),
}

impl<F: Field> AirSpec<'_, F> {
    pub fn into_owned(self) -> AirSpec<'static, F> {
        AirSpec {
            main_width: self.main_width,
            aux_width: self.aux_width,
            num_public_values: self.num_public_values,
            num_challenges: self.num_challenges,
            num_exports: self.num_exports,
            preprocessed: self.preprocessed,
            periodic_columns: Cow::Owned(self.periodic_columns.into_owned()),
        }
    }

    pub fn preprocessed_width(&self) -> usize {
        self.preprocessed.map_or(0, |shape| shape.width)
    }

    /// The maximum period, or zero when this relation has no periodic columns.
    ///
    /// Call [`Self::validate`] before using this as a valid period or height lower bound.
    pub fn max_periodic_length(&self) -> usize {
        self.periodic_columns.iter().map(Vec::len).max().unwrap_or(0)
    }

    /// Validate host-representable shape and periodic definitions without constructing data.
    ///
    /// This does not promise allocation success or establish field two-adicity, PCS compatibility,
    /// actual trace-height divisibility, or the presence and shape of a factory's returned matrix.
    /// Those conditions must be checked where the concrete height and setup are known.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.main_width == 0 {
            return Err(SpecError::EmptyMain);
        }
        if let Some(shape) = self.preprocessed {
            if shape.width == 0
                || shape.log_height == 0
                || u32::from(shape.log_height) >= usize::BITS
            {
                return Err(SpecError::Preprocessed {
                    width: shape.width,
                    log_height: shape.log_height,
                });
            }
            let height = 1usize << shape.log_height;
            shape.width.checked_mul(height).ok_or(SpecError::Overflow("fixed matrix"))?;
        }
        for (column, values) in self.periodic_columns.iter().enumerate() {
            if !values.len().is_power_of_two() {
                return Err(SpecError::Periodic { column, length: values.len() });
            }
        }
        self.max_periodic_length()
            .checked_mul(self.periodic_columns.len())
            .ok_or(SpecError::Overflow("expanded periodic columns"))?;

        // Capture uses two rows in every trace namespace and one value for each uniform input.
        let rows = self
            .main_width
            .checked_add(self.preprocessed_width())
            .and_then(|n| n.checked_add(self.aux_width))
            .and_then(|n| n.checked_mul(2))
            .ok_or(SpecError::Overflow("symbolic trace rows"))?;
        [
            self.num_public_values,
            self.num_challenges,
            self.num_exports,
            self.periodic_columns.len(),
            3,
        ]
        .into_iter()
        .try_fold(rows, |n, count| n.checked_add(count))
        .ok_or(SpecError::Overflow("symbolic inputs"))?;
        Ok(())
    }
}
