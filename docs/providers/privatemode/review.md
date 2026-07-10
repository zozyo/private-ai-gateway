# Privatemode provider review

Audit date: 2026-05-26 UTC. Provider behavior was rechecked against
Privatemode v1.48 and the live manifest on 2026-07-09; the gateway supervision
contract was reviewed on 2026-07-10.

Provider: [Privatemode](https://www.privatemode.ai/) by Edgeless Systems.
TCB source: [`edgelesssys/privatemode-public`](https://github.com/edgelesssys/privatemode-public).
Attestation framework: [`edgelesssys/contrast`](https://github.com/edgelesssys/contrast).

## Verdict

**Acceptable with conditions.** Privatemode has one of the strongest engineering
postures in the surveyed provider set. Its full encryption lifecycle was
reproduced against production: the client proxy verified the Coordinator,
obtained the attested Mesh CA, exchanged an inference secret, encrypted a live
chat request, decrypted the response, and streamed successfully. The public API
rejected a plaintext request.

Admission conditions:

- Pin a reviewed manifest digest instead of trusting automatic CDN updates.
- Pin the official proxy executable digest inside the gateway's attested
  workload.
- Let the gateway launch the exact pinned executable and manifest from sealed
  memory files. Do not attach an externally managed proxy.
- Require the gateway's pinned ephemeral TLS channel to the supervised child.
- Expose only the gateway listener from the workload network. Version 1.48 of
  the official proxy has no listen-address flag and opens its ephemeral port on
  the network namespace's wildcard address.
- Treat the proxy as part of the TCB: the gateway verifies its manifest binding
  but does not possess the provider E2EE secret.

## Verified trust chain

The observed chain was:

```text
SEV-SNP or TDX hardware evidence
  -> Contrast reference values in the pinned manifest
    -> Coordinator policy admitted
      -> attested Coordinator supplies Mesh CA
        -> Secret Service authenticates under that Mesh CA
          -> inference secret released only to admitted workers
            -> official proxy encrypts request bodies to those workers
```

The manifest pins workload policies and hardware reference values. During the
original audit it included strict SNP guest policy and chip allowlists, TDX
measurements/platform identities, minimum TCB versions, and separate policies
for the Coordinator, Secret Service, and model workloads. The 2026-07-09 live
manifest still contained exactly one Coordinator policy, SNP and TDX reference
profiles, and one seed-share owner key.

Privatemode's model workers place decryption in an inference-proxy sidecar
inside the confidential VM. Plaintext is then passed locally to the model
server. The public edge sees encrypted bodies and routes them to workers.

## Criteria status

Passed:

- Workload identity is measured and admitted under Contrast policy.
- The inference secret is released through an attested Mesh-CA chain.
- CPU-TEE and GPU confidential-computing checks gate worker activation.
- Model workloads and deployment images are published in the TCB source.
- Builds are reproducible and releases are versioned.
- The public endpoint rejects unencrypted inference traffic.
- OpenAI-compatible chat, streaming, embeddings, models, and other documented
  surfaces are mediated by the official proxy.

Open or conditional:

- The manifest publication channel has no detached signature. In automatic
  mode the initial trust seed is CDN TLS. The gateway adapter closes this gap
  operationally by requiring an explicit SHA-256 manifest pin and supervised
  static-manifest mode.
- The observed manifest has one RSA seed-share owner key. Public ownership,
  recovery procedure, rotation policy, and quorum expectations should be
  documented.
- Privatemode does not expose a per-worker TLS SPKI or public E2EE key for the
  gateway to pin directly. Its binding is transitive through the manifest,
  attested Coordinator/Mesh CA, and secret-release protocol.
- The exact served worker is not named in a per-request signed receipt. ACI
  records the selected model and verified router-scoped manifest session.

## Live observations from the original audit

- The official proxy completed attestation and became ready in roughly ten
  seconds.
- A live chat request and an SSE streaming request succeeded over the encrypted
  path.
- A direct plaintext request to the public API returned HTTP 400 with the
  `privatemode-encrypted: false` signal.
- Streaming latency was stable in the sampled runs: time to first byte was
  approximately 0.24 seconds across the tested models, with low run-to-run
  throughput variance. These figures are operational observations, not
  security guarantees.

## Adapter validation

The supervisor integration tests exercise the security boundary directly. A
proxy fixture implementing the official command-line and credential timing
contract rejects any API key in its arguments, reads its executable inputs
through inherited descriptors, and serves only pinned TLS. The test mutates
the source binary and manifest after supervisor construction, verifies that the
sealed copies are used, forces the child to exit and restart, and consumes a
slow stream after all other supervisor references are dropped. A full gateway
test also verifies that the receipt records the manifest, Coordinator policy,
proxy executable, and ephemeral TLS-certificate digests.

On 2026-07-10 the final supervisor was also exercised end to end against the
production service with a real API key and the official v1.48.0 binary. The
gateway executed the pinned binary from sealed memory, supplied the pinned
manifest through the inherited descriptor, authenticated the fresh child over
its ephemeral pinned TLS channel, and completed the live SNP Coordinator
verification and secret exchange. A chat request returned HTTP 200 through the
gateway, and its signed receipt matched the configured manifest and binary
digests while recording the Coordinator-policy and child-certificate digests.
Redacted artifacts are retained at
`/tmp/private-ai-gateway-live-e2e/20260710-195532-privatemode-supervised` on the
test host.

## Adapter decision

The gateway does not reimplement Contrast or copy only its quote checks. Its
first-class `privatemode` upstream owns an official-proxy child from executable
verification through process lifetime. The verifier and forwarding backend
share that supervisor. Receipts bind the exact manifest and Coordinator policy,
the exact proxy executable, and the pinned TLS identity of the child that
carried the request. See [verification.md](verification.md) for the enforced
contract.
