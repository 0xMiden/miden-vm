use super::{layout::*, periodic::*};

#[test]
fn periodic_columns_have_32_row_period() {
    let columns = get_periodic_column_values();

    assert_eq!(columns.len(), NUM_PERIODIC_COLUMNS);
    assert!(columns.iter().all(|column| column.len() == BLOCK_PERIOD));
}

#[test]
fn fused_row_selectors_match_row_kinds() {
    let columns = get_periodic_column_values();

    for (row, &is_ab) in columns[P_IS_AB].iter().enumerate() {
        let is_cd = columns[P_IS_CD][row];
        let is_diag = columns[P_IS_DIAG][row];
        let is_footer = columns[P_IS_FOOTER][row];

        match row_kind(row) {
            RowKind::Ab => {
                assert_eq!(is_ab.as_canonical_u64(), 1);
                assert_eq!(is_cd.as_canonical_u64(), 0);
                assert_eq!(is_diag.as_canonical_u64(), 0);
                assert_eq!(is_footer.as_canonical_u64(), 0);
            },
            RowKind::Cd => {
                assert_eq!(is_ab.as_canonical_u64(), 0);
                assert_eq!(is_cd.as_canonical_u64(), 1);
                assert_eq!(is_diag.as_canonical_u64(), 0);
                assert_eq!(is_footer.as_canonical_u64(), 0);
            },
            RowKind::AbDiag => {
                assert_eq!(is_ab.as_canonical_u64(), 1);
                assert_eq!(is_cd.as_canonical_u64(), 0);
                assert_eq!(is_diag.as_canonical_u64(), 1);
                assert_eq!(is_footer.as_canonical_u64(), 0);
            },
            RowKind::CdDiag => {
                assert_eq!(is_ab.as_canonical_u64(), 0);
                assert_eq!(is_cd.as_canonical_u64(), 1);
                assert_eq!(is_diag.as_canonical_u64(), 1);
                assert_eq!(is_footer.as_canonical_u64(), 0);
            },
            RowKind::Footer(_) => {
                assert_eq!(is_ab.as_canonical_u64(), 0);
                assert_eq!(is_cd.as_canonical_u64(), 0);
                assert_eq!(is_diag.as_canonical_u64(), 0);
                assert_eq!(is_footer.as_canonical_u64(), 1);
            },
        }
    }
}

#[test]
fn first_and_last_fused_selectors_are_singletons() {
    let columns = get_periodic_column_values();

    assert_eq!(
        columns[P_IS_FIRST_FUSED].iter().filter(|&&v| v.as_canonical_u64() == 1).count(),
        1
    );
    assert_eq!(
        columns[P_IS_LAST_FUSED].iter().filter(|&&v| v.as_canonical_u64() == 1).count(),
        1
    );
    assert_eq!(columns[P_IS_FIRST_FUSED][0].as_canonical_u64(), 1);
    assert_eq!(columns[P_IS_LAST_FUSED][FUSED_G_ROWS - 1].as_canonical_u64(), 1);
}

#[test]
fn footer_selectors_are_disjoint_and_cover_footer_rows() {
    let columns = get_periodic_column_values();
    let footer_cols = [P_IS_F0, P_IS_F1, P_IS_F2, P_IS_F3];

    for (row, _) in columns[P_IS_FOOTER].iter().enumerate() {
        let total: u64 = footer_cols.iter().map(|&col| columns[col][row].as_canonical_u64()).sum();
        let expected = usize::from(row >= FOOTER_START) as u64;
        assert_eq!(total, expected, "row {row}");
        assert_eq!(columns[P_IS_FOOTER][row].as_canonical_u64(), expected, "row {row}");
    }
}
