# Privatemode provider review

Audit date: 2026-05-26 UTC. Provider behavior was rechecked against
Privatemode v1.48 and the live manifest on 2026-07-09. The gateway adapter was
changed to the measured co-deployment boundary on 2026-07-13.

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
- Pin the official proxy OCI image by digest in the same measured dstack
  Compose as the gateway.
- Mount the same reviewed manifest into both services and repeat its digest and
  proxy image digest in static gateway policy.
- Require every mutable Privatemode route to use the statically pinned internal
  service origin.
- Disable HTTP redirects for proxy readiness and forwarding requests.
- Bind the accepted credential digest in measured static policy and require a
  coordinated gateway/proxy redeploy to change it, matching the proxy's
  first-credential ownership semantics.
- Expose only the gateway listener from the workload network. Version 1.48 of
  the official proxy has no listen-address flag and opens its configured port on
  the network namespace's wildcard address.
- Override the proxy's availability-oriented NVIDIA OCSP defaults: reject
  unknown status and use no revoked-certificate grace period.
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
  operationally by requiring an explicit SHA-256 manifest pin and measured
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

The adapter tests run a persistent HTTP service at the same boundary as the
Compose sidecar. They verify that manifest bytes are checked and retained at
static-policy construction, an authenticated model-list probe gates verified
events, bearer authentication reaches inference, buffered and streaming
forwards require the exact receipt binding, and receipts record the manifest,
Coordinator policy, proxy image digest, and internal origin. Config tests reject
legacy deployment fields in mutable upstream config, and deployment tests pin
the official image while ensuring its port is not published.

The earlier child-supervisor prototype was exercised end to end against the
production service on 2026-07-10 with a real API key and the official v1.48.0
binary. That established compatibility with the live Contrast verification,
secret exchange, chat, and receipt path, but its process-management boundary is
no longer part of the adapter. A live run of the replacement Compose boundary
must accompany its deployment review.

## Adapter decision

The gateway does not reimplement Contrast or copy only its quote checks. dstack
owns the official proxy lifecycle as a separate service in the same measured
Compose. The gateway verifier and forwarding backend share immutable static
policy for that service. Receipts bind the exact manifest and Coordinator
policy, official proxy image digest, and internal origin that carried the
request. See [verification.md](verification.md) for the enforced contract.
