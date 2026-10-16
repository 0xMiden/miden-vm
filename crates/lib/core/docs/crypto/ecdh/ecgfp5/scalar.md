Scalar validation for EcGFp5 agreement.<br /><br />The private scalar r is supplied as ten little-endian u32 limbs. Check 0 < r < n,<br />where n is the prime subgroup order, then store twenty little-endian radix-2^16 digits.<br />


## miden::core::crypto::ecdh::ecgfp5::scalar
| Procedure | Description |
| ----------- | ------------- |
| prepare | Reads r, checks 0 < r < n, and writes its twenty 16-bit digits.<br /><br />Input:  [...]<br />Advice: [r0, ..., r9, ...], with u32 limbs in little-endian order<br />Output: [...]<br /><br />Writes mem[DIGITS_PTR .. DIGITS_PTR+20) = [d0, ..., d19].<br /> |
