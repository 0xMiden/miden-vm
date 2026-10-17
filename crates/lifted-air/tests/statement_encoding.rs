//! The default statement binding's transcript order and lengths.

use miden_field::Felt;
use miden_lifted_air::StatementEncoding;
use p3_challenger::CanObserve;

#[test]
fn statement_encoding_preserves_exact_lengths_and_field_order() {
    #[derive(Default)]
    struct Recorder(Vec<Felt>);
    impl CanObserve<Felt> for Recorder {
        fn observe(&mut self, value: Felt) {
            self.0.push(value);
        }
    }
    let encoding = StatementEncoding {
        num_public_values: 2,
        max_aux_inputs: 4,
        num_aux_inputs: 1,
        num_airs: 3,
    };
    let mut recorder = Recorder::default();
    encoding.observe(&mut recorder, &[Felt::from(11u32), Felt::from(12u32)], &[Felt::from(21u32)]);
    assert_eq!(recorder.0, [2u32, 11, 12, 4, 1, 21].map(Felt::from));
    assert_eq!(encoding.statement_len(), 6);
    assert_eq!(encoding.shape_len(), 10);
}
