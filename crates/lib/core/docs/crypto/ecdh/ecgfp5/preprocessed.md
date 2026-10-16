Agreement from a preprocessed public key.<br /><br />For generator G and recipient point Q, table i contains<br />T_i[d] = (d * 2^(16*i) * G, d * 2^(16*i) * Q).<br />The public-key commitment binds the twenty table roots.<br /><br />For scalar r and prime subgroup order n, check 0 < r < n and read r = sum_i d_i * 2^(16*i).<br />Authenticate the selected entries and sum their two points.<br />Zero digits are skipped; the first nonzero entry initializes both sums.<br /><br />Finally, check the R and S encodings and recover Q from table zero, digit one.<br />


## miden::core::crypto::ecdh::ecgfp5::preprocessed
| Procedure | Description |
| ----------- | ------------- |
| agree_inner | Computes R and S from the preprocessed public key and returns the recipient point Q.<br />Internal procedure; use `ecgfp5::agree_preprocessed` for key agreement.<br /><br />Input:  [public_key(4), pad(12)]<br />Output: [R(5), S(5), Q(5), scratch(1)]<br />Advice: scalar, table entries, slopes, and encodings from `PreparedPublicKey::advise`.<br /><br />Called in a fresh memory context by `agree_preprocessed`. Uses the scalar digits, table roots,<br />and point workspace defined in the shared helper modules.<br /><br />Invocation: call<br /> |
