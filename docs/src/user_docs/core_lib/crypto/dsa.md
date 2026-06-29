---
title: "Digital Signatures"
sidebar_position: 1
---

# Digital signatures

Namespace `miden::core::crypto::dsa` contains core-library signature procedures.

## Poseidon2 Falcon512

Module `miden::core::crypto::dsa::falcon512_poseidon2` contains procedures for verifying
`Poseidon2 Falcon512` signatures. These signatures differ from standard Falcon signatures in that
instead of using the `SHAKE256` hash function in the hash-to-point algorithm, they use `Poseidon2`.
This makes the signature more efficient to verify in the Miden VM.

The module exposes the following procedures:

| Procedure | Description |
| --------- | ----------- |
| `verify` | Verifies a signature against a public key and a message. The procedure gets the hash of the public key and the hash of the message via the operand stack. The signature is expected to be provided via the advice provider.<br /><br />The signature is valid if and only if the procedure returns.<br /><br />Stack inputs: `[PK, MSG, ...]`<br />Advice stack inputs: `[SIGNATURE]`<br />Outputs: `[...]`<br /><br />Where `PK` is the hash of the public key and `MSG` is the hash of the message, and `SIGNATURE` is the signature being verified. Both hashes are expected to be computed using the `Poseidon2` hash function. |
