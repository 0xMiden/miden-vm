# Miden prover service

This crate runs a persistent gRPC service that accepts serialized `ExecutionWitness`
values and returns serialized `ExecutionProof` values. Every successful response
contains a complete proof from `Prover::prove_full`, including a precompile STARK
when the execution has native precompile work. Generated Tonic client and server
bindings are available in `protocol`.

## Build and start

The build requires Protocol Buffers compiler `protoc` on `PATH`. Install the
`protobuf-compiler` package on Debian or Ubuntu, or `protobuf` on macOS with
Homebrew. Bindings are generated from `proto/prover.proto`.

Build both binaries from the workspace root:

```sh
cargo build --profile optimized -p miden-prover-service --bins
```

The ordinary binary uses bounded decoding for externally supplied witnesses.
The following example chooses 8 MiB witness and proof limits, a 60 second deadline,
and 32 GiB modeled memory budgets for each prover. Choose limits for your workload
and available memory before deploying.

```sh
./target/optimized/miden-prover-service \
  --max-witness-bytes 8388608 \
  --max-proof-bytes 8388608 \
  --request-timeout-ms 60000 \
  --vm-memory-bytes 34359738368 \
  --precompile-memory-bytes 34359738368
```

The listener defaults to `127.0.0.1:50051` and capacity defaults to one. Override
them with `--listen` and `--capacity`. Capacity counts active and queued proofs.
Each instance has exactly one worker and keeps queued witnesses serialized.
All byte, timeout, and memory options above are required and must be nonzero.
Size validation includes protobuf framing before a listener starts.

Use `miden-prover-service-trusted` with the same resource options for witnesses
from trusted producers. Restrict access to that endpoint accordingly. Each binary
constructs its corresponding Rust service type. Both are built together, and
`cargo run -p miden-prover-service` defaults to the untrusted binary. Neither binary
accepts a runtime trust selector.

The trusted reader preserves its documented acceptance of trailing bytes. The
untrusted reader rejects trailing bytes without retrying the trusted reader.
Both readers enforce their witness wire version, and both service types apply
the same configured prover limits. Bounded decoding does not authenticate sparse
replay against a source forest commitment. A caller must verify the proof against
its independently chosen execution claim.

## Resource policy

The default precompile work limits come from
`miden_precompiles::default_verification_precompile_limits()`. Optional overrides
retain every canonical limit that the operator does not replace:

```sh
--precompile-max-elements 1048576 \
--precompile-work-limit hash:128:262144:131072 \
--precompile-work-limit msm:32:128:16
```

Each work override has the form `CLASS:COUNT:TOTAL_SIZE:ITEM_SIZE`. Classes are
`hash`, `uint`, `curve`, and `msm`. Hash sizes count input bytes, MSM sizes count
terms, and uint and non-MSM curve operations each have size one. Repeating a class
is an error. Zero is a valid restrictive work limit, for example
`--precompile-work-limit hash:0:0:0` denies hash work. Structural limits count
deferred field elements.

The VM memory budget models prover allocations and excludes some allocations and
cached preprocessing. Precompile preparation happens before the precompile
prover's memory check. Witness decoding and transport buffers also consume memory.
The service bounds concurrent proof ingress before protobuf decoding and retains
that allowance through response delivery, including bytes buffered by HTTP/2.
It applies separate witness-field and response-proof limits. Health has its own
allowance equal to capacity, with 1 KiB message limits. Health watches occupy a
health slot until closed, and proof traffic cannot consume those slots. These
controls do not impose a total
RSS ceiling or an open-connection limit. Apply deployment limits when a hard
process bound is required. Running two instances permits two active proofs and
requires memory for both instances.

The request timeout covers request decoding, queue wait, and waiting for a proof
response. A started synchronous proof cannot be interrupted. Its worker and
admission slot remain held until the actual proof job exits, even after a client
disconnects or times out. An oversized generated proof is rejected after proving.
Buffered response bytes must drain within one configured request timeout. If they
remain blocked, the service closes that connection and releases capacity when its
buffers are discarded. Idle health watches stay open while no bytes are buffered.

SIGINT and SIGTERM request graceful shutdown on Unix. Other platforms use Ctrl-C.
Shutdown stops admission, cancels queued requests, and joins active proof work.
Health watches report not serving and end. Connections receive one configured
request timeout to drain before closure. Shutdown can still wait indefinitely for
a stuck synchronous prover. A hard proving deadline requires process isolation.

The listener uses plaintext HTTP/2 and has no authentication layer. Keep the
default loopback address or provide access controls and TLS through your
deployment. `RUST_LOG` controls tracing and defaults to `info` when absent. Invalid
filters or non-Unicode values fail startup. Logs and application errors omit
witness contents and private replay values.

## Rust instances

`ProvingService::new(config)` constructs `ProvingService<Untrusted>`.
`ProvingService::<Trusted>::new_trusted(config)` explicitly constructs the trusted
type. `ServerConfig` contains only resource settings. A sealed policy trait
prevents callers from adding an unchecked decoder policy.

Each instance owns independent admission and shutdown state. Both types can run
in the same process on different listeners. `serve()` binds the configured address.
Use `serve_with_listener(listener)` for an already bound Tokio listener and retain
a clone to call `shutdown().await`. Await the serving future as well to join its
network connections. Listener failures return an error after proof work is joined.

## Client

The generated `protocol::prover_service_client::ProverServiceClient` works with
either service type. The service accepts protocol version 1 with `ExecutionWitness`
wire version 2 and returns `ExecutionProof` format 2. These version numbers are
independent. The server owns the accepted input policy and proving configuration.
Each RPC accepts exactly one gRPC request message. Extra messages and trailing
data are rejected before proving. The aggregate upload is bounded by its message
limit plus the five-byte gRPC header, including fragmented HTTP/2 uploads.

This function submits a witness and verifies the returned proof against a claim
chosen by the caller. Its client limits match the 8 MiB server example above.
The extra bytes allow for protobuf framing. The caller supplies the expected
claim independently of the proving service.

```rust
use std::time::Duration;

use miden_core::{program::ExecutionClaim, proof::ExecutionProof, serde::Serializable};
use miden_processor::ExecutionWitness;
use miden_prover_service::{
    PROTOCOL_VERSION,
    protocol::{ProveRequest, prover_service_client::ProverServiceClient},
};
use miden_verifier::Verifier;

async fn prove_and_verify(
    witness: &ExecutionWitness,
    expected_claim: &ExecutionClaim,
) -> Result<ExecutionProof, Box<dyn std::error::Error + Send + Sync>> {
    let mut client = tokio::time::timeout(
        Duration::from_secs(10),
        ProverServiceClient::connect("http://127.0.0.1:50051"),
    ).await??
        .max_encoding_message_size((8 << 20) + 12)
        .max_decoding_message_size((8 << 20) + 6);
    let response = tokio::time::timeout(
        Duration::from_secs(60),
        client.prove(ProveRequest {
            protocol_version: PROTOCOL_VERSION,
            execution_witness: witness.to_bytes(),
        }),
    ).await??.into_inner();
    let proof = ExecutionProof::read_from_bytes(&response.execution_proof)?;
    let outcome = Verifier::new().verify(expected_claim, &proof)?;
    if !outcome.is_complete() {
        return Err(std::io::Error::other("incomplete execution proof").into());
    }
    Ok(proof)
}
```

Application failures carry a protobuf `ErrorDetail` in `tonic::Status::details()`.
Decode it with `prost::Message` and branch on its `ErrorCode`. Error text can change.
Transport failures and client cancellations may have only a standard gRPC status.
The protocol assigns the following stable application codes:

| Code | gRPC status | Meaning |
| --- | --- | --- |
| `UNSUPPORTED_VERSION` | `INVALID_ARGUMENT` | Unsupported service protocol version |
| `INVALID_WITNESS` | `INVALID_ARGUMENT` | Empty, malformed, or invalid execution witness |
| `REQUEST_TOO_LARGE` | `RESOURCE_EXHAUSTED` | Transport or witness-field size limit |
| `QUEUE_FULL` | `RESOURCE_EXHAUSTED` | Ingress or proof capacity exhausted |
| `PROVER_LIMIT_EXCEEDED` | `RESOURCE_EXHAUSTED` | VM or precompile memory/work limit |
| `RESPONSE_TOO_LARGE` | `RESOURCE_EXHAUSTED` | Generated proof exceeds its byte limit |
| `DEADLINE_EXCEEDED` | `DEADLINE_EXCEEDED` | Request timed out before a response |
| `CANCELLED` | `CANCELLED` | Request cancelled |
| `SHUTTING_DOWN` | `UNAVAILABLE` | Service stopped admission |
| `PROVING_FAILED` | `INTERNAL` | Proof generation failed |
| `INTERNAL` | `INTERNAL` | Worker panic or unexpected failure |

Standard health reporting is available through `grpc.health.v1.Health` for the
empty service name and `miden.prover.v1.ProverService`.

Run `make test-prover-service` from the workspace root for library and binary
integration tests. The crate owns its network and protobuf dependencies, and
existing VM libraries retain their independent `no_std` builds.

The binary tests also serve as deployment smoke tests for the documented startup
options. They run both executables as child processes and verify complete proofs
over gRPC. Under active proof load, SIGINT and SIGTERM stop queued requests and
close health watches while the active proof finishes before successful exit.
Debug logging reports admission and proof-job start/finish without witness data.
The ordinary workspace test target runs these tests. `test-fast` excludes CLI
tests, so pair it with `make test-prover-service` when checking this behavior.
