//! Typed selector accessors for the 32-row BlakeG layout.

use core::array;

use super::periodic::{
    NUM_PERIODIC_COLUMNS, P_IS_AB, P_IS_CD, P_IS_DIAG, P_IS_F0, P_IS_F1, P_IS_F2, P_IS_F3,
    P_IS_FIRST_FUSED, P_IS_FOOTER, P_IS_LAST_FUSED, P_SIGMA_MSG_0, P_SIGMA_MSG_1, P_SIGMA_MSG_2,
    P_SIGMA_MSG_3,
};

#[derive(Clone, Debug)]
pub struct BlakeGSelectors<T> {
    columns: [T; NUM_PERIODIC_COLUMNS],
}

impl<T: Clone> BlakeGSelectors<T> {
    pub fn new(periodic_values: &[T], offset: usize) -> Self {
        assert!(
            periodic_values.len() >= offset + NUM_PERIODIC_COLUMNS,
            "not enough periodic values for 32-row BlakeG selectors",
        );
        Self {
            columns: array::from_fn(|idx| periodic_values[offset + idx].clone()),
        }
    }

    pub fn is_ab(&self) -> T {
        self.read(P_IS_AB)
    }

    pub fn is_cd(&self) -> T {
        self.read(P_IS_CD)
    }

    pub fn is_diag(&self) -> T {
        self.read(P_IS_DIAG)
    }

    pub fn is_first_fused(&self) -> T {
        self.read(P_IS_FIRST_FUSED)
    }

    pub fn is_last_fused(&self) -> T {
        self.read(P_IS_LAST_FUSED)
    }

    pub fn is_footer(&self) -> T {
        self.read(P_IS_FOOTER)
    }

    pub fn is_footer_row(&self, footer: usize) -> T {
        match footer {
            0 => self.read(P_IS_F0),
            1 => self.read(P_IS_F1),
            2 => self.read(P_IS_F2),
            3 => self.read(P_IS_F3),
            _ => panic!("footer selector index out of bounds"),
        }
    }

    pub fn sigma_msg_index(&self, lane: usize) -> T {
        match lane {
            0 => self.read(P_SIGMA_MSG_0),
            1 => self.read(P_SIGMA_MSG_1),
            2 => self.read(P_SIGMA_MSG_2),
            3 => self.read(P_SIGMA_MSG_3),
            _ => panic!("sigma lane index out of bounds"),
        }
    }

    fn read(&self, column: usize) -> T {
        self.columns[column].clone()
    }
}
