use crate::vm::MidenAir;

/// Supported AIRs in instance order.
///
/// This order is used for per-AIR inputs and breaks proof-order ties when trace heights are equal.
pub const AIRS: [MidenAir; miden_air_definitions::vm::MIDEN_AIR_COUNT] = {
    let mut airs = [MidenAir::CORE; miden_air_definitions::vm::MIDEN_AIR_COUNT];
    let mut i = 0;
    while i < airs.len() {
        airs[i] = MidenAir(miden_air_definitions::vm::AIRS[i]);
        i += 1;
    }
    airs
};

pub const MIDEN_AIR_COUNT: usize = AIRS.len();

#[cfg(test)]
mod tests {
    use super::*;

    /// `AIRS` fixes proof-order tie-breaks and the relation digest. Pin it independently of
    /// `instance_index`; intentional changes require regenerated protocol constants and a
    /// breaking changelog entry.
    #[test]
    fn air_instance_order_is_protocol_pinned() {
        const PINNED: [MidenAir; MIDEN_AIR_COUNT] = [
            MidenAir::CORE,
            MidenAir::CHIPLETS,
            MidenAir::EIDOS_COMPRESSION,
            MidenAir::AND8_LOOKUP,
        ];
        assert_eq!(
            AIRS, PINNED,
            "AIRS instance order moved; regenerate protocol constants for an intentional change"
        );
        for (index, air) in AIRS.iter().copied().enumerate() {
            assert_eq!(air.instance_index(), index);
        }
    }
}
