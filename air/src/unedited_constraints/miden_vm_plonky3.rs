use alloc::vec::Vec;
use miden_core::{field::{ExtensionField, Field, PrimeCharacteristicRing}, utils::Matrix};
use miden_crypto::stark::air::{MidenAir, MidenAirBuilder};

// FIXME: Current trace is 71 (system: 6, padding: 0), generated constraints trace is width 80 (system: 8, padding: 7)
pub const MAIN_WIDTH: usize = 71; // 80

pub struct MidenVM;

impl<F, EF> MidenAir<F, EF> for MidenVM
where F: Field,
      EF: ExtensionField<F>,
{
    fn width(&self) -> usize {
        MAIN_WIDTH
    }

    fn eval<AB>(&self, builder: &mut AB)
    where AB: MidenAirBuilder<F = F>,
    {
        let main = builder.main();
        let (main_current, main_next) = (main.row_slice(0).unwrap(), main.row_slice(1).unwrap());

        // System clock starts at 0
        builder.when_first_row().assert_zero(main_current[0].clone().into());

        // System clock transition constraint - Ensure clock increments by 1 each step
        builder.when_transition().assert_zero(main_next[0].clone().into() - (main_current[0].clone().into() + AB::Expr::ONE));
        
        // Chiplet selectors binary constraints - Ensure all selectors are valid binary values
        builder.assert_zero(main_current[51].clone().into() * main_current[51].clone().into() - main_current[51].clone().into());
        builder.assert_zero(main_current[51].clone().into() * (main_current[52].clone().into() * main_current[52].clone().into() - main_current[52].clone().into()));
        builder.assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * (main_current[53].clone().into() * main_current[53].clone().into() - main_current[53].clone().into()));
        builder.assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * main_current[53].clone().into() * (main_current[54].clone().into() * main_current[54].clone().into() - main_current[54].clone().into()));
        builder.assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * main_current[53].clone().into() * main_current[54].clone().into() * (main_current[55].clone().into() * main_current[55].clone().into() - main_current[55].clone().into()));
        
        // Chiplet selectors stability constraints - Prevent deactivation (forbids 1→0 transitions)
        builder.when_transition().assert_zero(main_current[51].clone().into() * (main_next[51].clone().into() - main_current[51].clone().into()));
        builder.when_transition().assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * (main_next[52].clone().into() - main_current[52].clone().into()));
        builder.when_transition().assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * main_current[53].clone().into() * (main_next[53].clone().into() - main_current[53].clone().into()));
        builder.when_transition().assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * main_current[53].clone().into() * main_current[54].clone().into() * (main_next[54].clone().into() - main_current[54].clone().into()));
        builder.when_transition().assert_zero(main_current[51].clone().into() * main_current[52].clone().into() * main_current[53].clone().into() * main_current[54].clone().into() * main_current[55].clone().into() * (main_next[55].clone().into() - main_current[55].clone().into()));
    }
}
