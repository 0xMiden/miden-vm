//! Shared helpers for the miden-core fuzz targets.

use miden_core::mast::MastNodeId;

/// Root selection for the generator-driven oracle in `mast_forest_wire_view_new`: `k` in
/// 0..=node_ids.len(), distinct node ids in first-occurrence order over `data[1..]`, padded
/// deterministically. The count check precedes each push so k == 0 yields an EMPTY root list
/// even with trailing bytes (the former push-then-check ordering produced
/// one root for supposedly rootless forests).
pub fn select_roots(data: &[u8], node_ids: &[MastNodeId], k: usize) -> Vec<MastNodeId> {
    let mut roots = Vec::new();
    if k == 0 {
        return roots;
    }
    for byte in data.iter().skip(1) {
        let id = node_ids[usize::from(*byte) % node_ids.len()];
        if !roots.contains(&id) {
            roots.push(id);
        }
        if roots.len() == k {
            break;
        }
    }
    while roots.len() < k {
        let id = node_ids
            .iter()
            .copied()
            .find(|id| !roots.contains(id))
            .expect("5 nodes provide enough distinct ids for k <= 5");
        roots.push(id);
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::select_roots;
    use miden_core::mast::MastNodeId;

    /// BEHAVIORAL REGRESSION : zero-count inputs produce EMPTY root
    /// lists even with trailing bytes — the former push-then-check ordering produced one
    /// root for supposedly rootless forests. The fuzz bins set `test = false`, so this
    /// lives in the lib target where `cargo test` actually compiles it.
    #[test]
    fn zero_count_is_rootless_even_with_trailing_bytes() {
        let ids: Vec<MastNodeId> = (0..5).map(MastNodeId::new_unchecked).collect();
        for data in [&[0u8, 1][..], &[0u8, 1, 2, 3, 4][..], &[][..], &[0u8][..]] {
            let roots = select_roots(data, &ids, 0);
            assert!(
                roots.is_empty(),
                "k=0 must be rootless regardless of trailing bytes (data {data:?})"
            );
        }
        // EXACT-SEQUENCE ORACLE : length-only checks accept a selector
        // that always returns the first k nodes, which would silently remove root-order
        // variation (and the serialization oracle captures expectations AFTER selection, so
        // it cannot catch it either). The documented selection: data[0] is the count,
        // data[1..] map to node ids (byte % 5) deduped in first-occurrence order, padded
        // with the lowest unused ids when input is insufficient.
        let select = |count: u8, rest: &[u8]| -> Vec<MastNodeId> {
            let mut data = vec![count];
            data.extend_from_slice(rest);
            select_roots(&data, &ids, usize::from(count) % 6)
        };
        // First-occurrence order preserved (NOT sorted): 3 then 1.
        assert_eq!(select(2, &[3, 1]), vec![ids[3], ids[1]]);
        // Duplicates skipped, padding appends the lowest unused id.
        assert_eq!(select(2, &[1, 1, 1]), vec![ids[1], ids[0]]);
        // Insufficient input: pure deterministic padding in id order.
        assert_eq!(select(2, &[]), vec![ids[0], ids[1]]);
        // The [1, 1] case: count byte 1 -> k=1, data[1] = 1 selects ids[1]. (Fuzz input
        // [0, 1] is the count-0 rootless case covered above.)
        assert_eq!(select(1, &[1]), vec![ids[1]]);
        // Count byte maps mod 6: count 7 -> k = 1.
        assert_eq!(select(7, &[2]), vec![ids[2]]);
    }
}
