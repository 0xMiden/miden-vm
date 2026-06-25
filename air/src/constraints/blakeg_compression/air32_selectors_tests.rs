use alloc::vec::Vec;

use miden_core::Felt;

use super::air32_layout::*;
use super::air32_periodic::*;
use super::air32_selectors::Air32Selectors;

fn row_values(columns: &[Vec<Felt>], row: usize) -> Vec<Felt> {
    columns.iter().map(|column| column[row]).collect()
}

#[test]
fn selectors_read_periodic_row_values() {
    let columns = get_air32_periodic_column_values();
    let footer_cols = [P_IS_F0, P_IS_F1, P_IS_F2, P_IS_F3];

    for row in 0..BLOCK_PERIOD {
        let values = row_values(&columns, row);
        let selectors = Air32Selectors::new(&values, 0);

        assert_eq!(selectors.is_ab(), values[P_IS_AB]);
        assert_eq!(selectors.is_cd(), values[P_IS_CD]);
        assert_eq!(selectors.is_diag(), values[P_IS_DIAG]);
        assert_eq!(selectors.is_first_fused(), values[P_IS_FIRST_FUSED]);
        assert_eq!(selectors.is_last_fused(), values[P_IS_LAST_FUSED]);
        assert_eq!(selectors.is_footer(), values[P_IS_FOOTER]);

        for footer in 0..FOOTER_ROWS {
            assert_eq!(selectors.is_footer_row(footer), values[footer_cols[footer]]);
        }
        for lane in 0..NUM_G {
            assert_eq!(selectors.sigma_msg_index(lane), values[P_SIGMA_MSG_0 + lane]);
        }
    }
}

#[test]
fn selectors_support_nonzero_periodic_offset() {
    let columns = get_air32_periodic_column_values();
    let mut values = vec![Felt::ZERO, Felt::ZERO];
    values.extend(row_values(&columns, 0));

    let selectors = Air32Selectors::new(&values, 2);

    assert_eq!(selectors.is_ab(), Felt::ONE);
    assert_eq!(selectors.is_cd(), Felt::ZERO);
    assert_eq!(selectors.is_first_fused(), Felt::ONE);
    assert_eq!(selectors.sigma_msg_index(0), columns[P_SIGMA_MSG_0][0]);
}
