OOD constraint evaluation for the RPO signature AIR via ACE circuit.<br /><br />Uses a standalone circuit (not ace-codegen) that checks:<br />root = acc - Q_recon * vanishing = 0<br /><br />where acc is the Horner-folded constraint accumulator and Q_recon is the<br />power-sum quotient reconstruction from flattened base-field coords.<br /><br /># Input layout (56 EF slots = 112 base felts = 28 words)<br /><br />Slots 0-3:    pk[0..3]              (base field as EF)<br />Slots 4-11:   witness_z[0..7]       (EF)<br />Slots 12-19:  witness_gz[0..7]      (EF)<br />Slots 20-49:  quotient_z_coords     (30 base-field-as-EF, 15 chunks * 2 coords)<br />Slot 50:      alpha                 (EF)<br />Slot 51:      z^N                   (EF)<br />Slot 52:      z_k = z               (EF)<br />Slot 53:      is_first              (EF)<br />Slot 54:      is_last               (EF)<br />Slot 55:      is_transition         (EF)<br />


## miden::core::sig::ood_check
| Procedure | Description |
| ----------- | ------------- |
| verify_constraints_at_ood | Verify OOD evaluations satisfy the RPO AIR constraints.<br /><br />Stack transition:<br />Input:  [...]<br />Output: [...]<br /> |
| populate_and_setup_only | Populate the READ section and compute STARK vars without evaluating the<br />circuit. Useful when debugging memory layout/setup only.<br /> |
