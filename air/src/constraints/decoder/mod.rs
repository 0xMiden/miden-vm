pub mod bus;

use miden_crypto::stark::air::MidenAirBuilder;
use miden_core::field::PrimeCharacteristicRing;

use crate::MainTraceRow;

pub fn enforce_main_decoder_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_decoder_boundary_constraints(builder, local);
    enforce_general_constraints(builder, local, next);
    enforce_basic_block_constraints(builder, local, next);
    enforce_op_flags_bits_constraints(builder, local, next);
}


fn enforce_decoder_boundary_constraints<AB>(builder: &mut AB, local: &MainTraceRow<AB::Var>)
where
    AB: MidenAirBuilder,
{
    builder.when_first_row().assert_zero(local.decoder[16].clone().into());
}

fn enforce_general_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero((local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * local.decoder[1].clone().into()) * (local.stack[0].clone().into() * local.stack[0].clone().into() - local.stack[0].clone().into()));
    builder.assert_zero(local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) * local.decoder[12].clone().into());
    builder.assert_zero(local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) * local.decoder[13].clone().into());
    builder.assert_zero(local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) * local.decoder[14].clone().into());
    builder.assert_zero(local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) * local.decoder[15].clone().into());
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * (local.stack[0].clone().into() - AB::Expr::ONE));
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * (local.decoder[12].clone().into() - AB::Expr::ONE));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (next.decoder[0].clone().into() - (local.decoder[0].clone().into() + AB::Expr::from_u64(8))));
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[13].clone().into() * local.stack[0].clone().into());
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * next.decoder[3].clone().into() * (next.decoder[8].clone().into() - local.decoder[8].clone().into()));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * next.decoder[3].clone().into() * (next.decoder[9].clone().into() - local.decoder[9].clone().into()));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * next.decoder[3].clone().into() * (next.decoder[10].clone().into() - local.decoder[10].clone().into()));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * next.decoder[3].clone().into() * (next.decoder[11].clone().into() - local.decoder[11].clone().into()));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * next.decoder[3].clone().into() * (next.decoder[12].clone().into() - local.decoder[12].clone().into()));
    builder.when_transition().assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - next.decoder[23].clone().into() * next.decoder[5].clone().into() * next.decoder[4].clone().into() * next.decoder[3].clone().into()));
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * local.decoder[0].clone().into());
    builder.assert_zero(local.decoder[1].clone().into() * local.decoder[1].clone().into() - local.decoder[1].clone().into());
    builder.assert_zero(local.decoder[2].clone().into() * local.decoder[2].clone().into() - local.decoder[2].clone().into());
    builder.assert_zero(local.decoder[3].clone().into() * local.decoder[3].clone().into() - local.decoder[3].clone().into());
    builder.assert_zero(local.decoder[4].clone().into() * local.decoder[4].clone().into() - local.decoder[4].clone().into());
    builder.assert_zero(local.decoder[5].clone().into() * local.decoder[5].clone().into() - local.decoder[5].clone().into());
    builder.assert_zero(local.decoder[6].clone().into() * local.decoder[6].clone().into() - local.decoder[6].clone().into());
    builder.assert_zero(local.decoder[7].clone().into() * local.decoder[7].clone().into() - local.decoder[7].clone().into());
    builder.assert_zero(local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() + local.decoder[23].clone().into() * local.decoder[5].clone().into() + local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * local.decoder[3].clone().into() * (AB::Expr::ONE - local.decoder[2].clone().into()) * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) - (AB::Expr::ONE - local.decoder[16].clone().into()));
}

fn enforce_basic_block_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
        builder.assert_zero(local.decoder[16].clone().into() * local.decoder[16].clone().into() - local.decoder[16].clone().into());
        builder.when_transition().assert_zero((local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into())) * (next.decoder[16].clone().into() - AB::Expr::ONE));
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * (next.decoder[0].clone().into() - local.decoder[0].clone().into()));
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * (local.decoder[17].clone().into() - next.decoder[17].clone().into()) * (local.decoder[17].clone().into() - next.decoder[17].clone().into() - AB::Expr::ONE));
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * (local.decoder[17].clone().into() - next.decoder[17].clone().into()) * (AB::Expr::ONE - local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[2].clone().into() * local.decoder[1].clone().into()) * local.decoder[8].clone().into());
        builder.when_transition().assert_zero((local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[2].clone().into() * local.decoder[1].clone().into()) * (local.decoder[17].clone().into() - next.decoder[17].clone().into() - AB::Expr::ONE));
        builder.when_transition().assert_zero((local.decoder[17].clone().into() - next.decoder[17].clone().into()) * (next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * (AB::Expr::ONE - next.decoder[3].clone().into()) + next.decoder[23].clone().into() * next.decoder[5].clone().into() * next.decoder[4].clone().into() * (AB::Expr::ONE - next.decoder[3].clone().into())));
        builder.assert_zero(local.decoder[23].clone().into() * local.decoder[5].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[17].clone().into());
        builder.when_transition().assert_zero((local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) + local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[2].clone().into() * local.decoder[1].clone().into() + local.decoder[16].clone().into() * next.decoder[16].clone().into() * (AB::Expr::ONE - (local.decoder[17].clone().into() - next.decoder[17].clone().into()))) * (local.decoder[8].clone().into() - (next.decoder[8].clone().into() * AB::Expr::from_u64(128) + next.decoder[1].clone().into() + next.decoder[2].clone().into().double() + AB::Expr::from_u64(4) * next.decoder[3].clone().into() + AB::Expr::from_u64(8) * next.decoder[4].clone().into() + AB::Expr::from_u64(16) * next.decoder[5].clone().into() + AB::Expr::from_u64(32) * next.decoder[6].clone().into() + AB::Expr::from_u64(64) * next.decoder[7].clone().into())));
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * (next.decoder[23].clone().into() * next.decoder[5].clone().into() * (AB::Expr::ONE - next.decoder[4].clone().into()) * (AB::Expr::ONE - next.decoder[3].clone().into()) + next.decoder[23].clone().into() * next.decoder[5].clone().into() * next.decoder[4].clone().into() * (AB::Expr::ONE - next.decoder[3].clone().into())) * local.decoder[8].clone().into());
        builder.when_transition().assert_zero((local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into())) * next.decoder[18].clone().into());
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * (local.decoder[17].clone().into() - next.decoder[17].clone().into() - local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[2].clone().into() * local.decoder[1].clone().into()) * next.decoder[18].clone().into());
        builder.when_transition().assert_zero(local.decoder[16].clone().into() * next.decoder[16].clone().into() * (AB::Expr::ONE - (local.decoder[17].clone().into() - next.decoder[17].clone().into() - local.decoder[22].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) * local.decoder[2].clone().into() * local.decoder[1].clone().into())) * (next.decoder[18].clone().into() - local.decoder[18].clone().into() - AB::Expr::ONE));
        builder.assert_zero(local.decoder[18].clone().into() * (local.decoder[18].clone().into() - AB::Expr::ONE) * (local.decoder[18].clone().into() - AB::Expr::from_u64(2)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(3)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(4)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(5)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(6)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(7)) * (local.decoder[18].clone().into() - AB::Expr::from_u64(8)));

}

fn enforce_op_batch_flags_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
        builder.assert_zero(local.decoder[19].clone().into() * local.decoder[19].clone().into() - local.decoder[19].clone().into());
        builder.assert_zero(local.decoder[20].clone().into() * local.decoder[20].clone().into() - local.decoder[20].clone().into());
        builder.assert_zero(local.decoder[21].clone().into() * local.decoder[21].clone().into() - local.decoder[21].clone().into());
        builder.assert_zero(local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()) - ((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * (AB::Expr::ONE - local.decoder[21].clone().into()) + local.decoder[19].clone().into()));
        builder.assert_zero((AB::Expr::ONE - (local.decoder[22].clone().into() * (AB::Expr::ONE - local.decoder[4].clone().into()) * local.decoder[3].clone().into() * local.decoder[2].clone().into() * (AB::Expr::ONE - local.decoder[1].clone().into()) + local.decoder[23].clone().into() * local.decoder[5].clone().into() * local.decoder[4].clone().into() * (AB::Expr::ONE - local.decoder[3].clone().into()))) * (local.decoder[19].clone().into() + local.decoder[20].clone().into() + local.decoder[21].clone().into()));
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * (AB::Expr::ONE - local.decoder[21].clone().into())) * local.decoder[12].clone().into());
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * (AB::Expr::ONE - local.decoder[21].clone().into())) * local.decoder[13].clone().into());
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * (AB::Expr::ONE - local.decoder[21].clone().into())) * local.decoder[14].clone().into());
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * (AB::Expr::ONE - local.decoder[21].clone().into())) * local.decoder[15].clone().into());
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into()) * local.decoder[10].clone().into());
        builder.assert_zero(((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() + (AB::Expr::ONE - local.decoder[19].clone().into()) * (AB::Expr::ONE - local.decoder[20].clone().into()) * local.decoder[21].clone().into()) * local.decoder[11].clone().into());
        builder.assert_zero((AB::Expr::ONE - local.decoder[19].clone().into()) * local.decoder[20].clone().into() * local.decoder[21].clone().into() * local.decoder[9].clone().into());

}

fn enforce_op_flags_bits_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    enforce_u32_bit_constraints(builder, local, next);
    enforce_high_degree_bit_constraints(builder, local, next);
    enforce_very_high_degree_bit_constraints(builder, local, next);
}

fn enforce_u32_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero(local.decoder[7].clone().into() * (AB::Expr::ONE - local.decoder[6].clone().into()) * (AB::Expr::ONE - local.decoder[5].clone().into()) * local.decoder[1].clone().into());
}

fn enforce_high_degree_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero(local.decoder[22].clone().into() - local.decoder[7].clone().into() * (AB::Expr::ONE - local.decoder[6].clone().into()) * local.decoder[5].clone().into());
}

fn enforce_very_high_degree_bit_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero(local.decoder[23].clone().into() - local.decoder[7].clone().into() * local.decoder[6].clone().into());
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[1].clone().into());
    builder.assert_zero(local.decoder[23].clone().into() * local.decoder[2].clone().into());
}
