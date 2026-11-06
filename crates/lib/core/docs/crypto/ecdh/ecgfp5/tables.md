Merkle openings for the paired-point multiplication tables.<br /><br />The caller hashes the twenty ordered roots into the public-key commitment before reading<br />entries. For ordinary-key agreement that commitment is the fixed generator commitment;<br />for preprocessed agreement it is the recipient's input.<br /><br />Each opened entry is written directly into arithmetic's two term slots:<br />offset  0: [Gx0, Gx1, Gx2, Gx3]       offset  4: [Gy0, Gy1, Gy2, Gy3]<br />offset  8: [Qx0, Qx1, Qx2, Qx3]       offset 12: [Qy0, Qy1, Qy2, Qy3]<br />offset 16: [Gx4, Gy4, Qx4, Qy4]       offset 20: [is_identity, 0, 0, 0]<br /><br />Zero digits are skipped, so the entries used by agreement have is_identity = 0.<br />


## miden::core::crypto::ecdh::ecgfp5::tables
| Procedure | Description |
| ----------- | ------------- |
| read_entry | Reads T_window[digit] from advice and checks its path against the corresponding window root.<br /><br />Input:  [digit, window, ...]<br />Advice: [entry(24), ...], with the Merkle path in the advice provider<br />Output: [window, ...]<br /><br />Requires 0 < digit < 2^16 and window < 20. Reads the root at ROOTS_PTR + 4*window and<br />writes the packed entry at arithmetic::TERMS_PTR.<br /> |
