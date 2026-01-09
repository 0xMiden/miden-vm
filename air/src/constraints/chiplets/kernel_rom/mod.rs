use miden_core::field::PrimeCharacteristicRing;
use miden_crypto::stark::air::MidenAirBuilder;

use crate::MainTraceRow;

pub fn enforce_kernel_rom_chiplet_constraints<AB>(
    builder: &mut AB,
    local: &MainTraceRow<AB::Var>,
    next: &MainTraceRow<AB::Var>,
) where
    AB: MidenAirBuilder,
{
    builder.assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * local.chiplets[3].clone().into() * (AB::Expr::ONE - local.chiplets[4].clone().into()) * (local.chiplets[5].clone().into() * local.chiplets[5].clone().into() - local.chiplets[5].clone().into()));
    builder.when_transition().assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * local.chiplets[3].clone().into() * (AB::Expr::ONE - local.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[5].clone().into()) * (next.chiplets[6].clone().into() - local.chiplets[6].clone().into()));
    builder.when_transition().assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * local.chiplets[3].clone().into() * (AB::Expr::ONE - local.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[5].clone().into()) * (next.chiplets[7].clone().into() - local.chiplets[7].clone().into()));
    builder.when_transition().assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * local.chiplets[3].clone().into() * (AB::Expr::ONE - local.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[5].clone().into()) * (next.chiplets[8].clone().into() - local.chiplets[8].clone().into()));
    builder.when_transition().assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * local.chiplets[3].clone().into() * (AB::Expr::ONE - local.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[4].clone().into()) * (AB::Expr::ONE - next.chiplets[5].clone().into()) * (next.chiplets[9].clone().into() - local.chiplets[9].clone().into()));
    builder.when_transition().assert_zero(local.chiplets[0].clone().into() * local.chiplets[1].clone().into() * local.chiplets[2].clone().into() * (AB::Expr::ONE - local.chiplets[3].clone().into()) * next.chiplets[3].clone().into() * (next.chiplets[5].clone().into() - AB::Expr::ONE));
}
