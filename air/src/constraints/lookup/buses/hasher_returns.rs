//! Final hasher digest-return bus interactions.
//!
//! A single-row controller operation can emit an operation-init response and a final digest return
//! on the same row. Init responses stay in the shared chiplet-responses column; this column carries
//! the final digest return so the response column keeps its single-denominator hasher shape.

use crate::{
    constraints::{
        lookup::{
            chiplet_air::{ChipletBusContext, ChipletLookupBuilder},
            messages::HasherMsg,
        },
        utils::BoolNot,
    },
    lookup::{Deg, LookupColumn, LookupGroup},
};

/// Upper bound on fractions this emitter pushes into its column per row.
pub(in crate::constraints::lookup) const MAX_INTERACTIONS_PER_ROW: usize = 1;

/// Emit final hasher digest responses.
pub(in crate::constraints::lookup) fn emit_hasher_returns<LB>(
    builder: &mut LB,
    ctx: &ChipletBusContext<LB>,
) where
    LB: ChipletLookupBuilder,
{
    let local = ctx.local;
    let ctrl = local.controller();

    let controller_flag = ctx.chiplet_active.controller.clone();
    let merkle_or_padding: LB::Expr = local.controller_merkle_or_padding().into();
    let ctrl_s0: LB::Expr = ctrl.s0.into();
    let op_final: LB::Expr = local.controller_op_final().into();
    let hash_return = controller_flag * merkle_or_padding.clone().not() * op_final.clone();
    // The controller skeleton makes `merkle_or_padding * s0` zero off controller rows. Keeping
    // this gate narrow avoids a higher-degree controller-selector factor.
    let merkle_return = merkle_or_padding * ctrl_s0 * op_final;

    let addr: LB::Expr = local.chip_clk.into();
    let hash_digest = ctrl.hash_digest();
    let merkle_digest = ctrl.merkle_digest();

    builder.next_column(
        |col| {
            col.group(
                "hasher_returns",
                |g| {
                    g.add(
                        "hash_return",
                        hash_return,
                        || HasherMsg::return_hash(addr.clone(), hash_digest.map(LB::Expr::from)),
                        Deg { v: 3, u: 4 },
                    );
                    g.add(
                        "merkle_return",
                        merkle_return,
                        || HasherMsg::return_hash(addr.clone(), merkle_digest.map(LB::Expr::from)),
                        Deg { v: 3, u: 4 },
                    );
                },
                Deg { v: 3, u: 4 },
            );
        },
        Deg { v: 3, u: 4 },
    );
}
