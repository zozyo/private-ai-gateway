# Privatemode — supervised delegated attestation

- **TEE:** AMD SEV-SNP or Intel TDX + NVIDIA Confidential Computing
- **Session binding:** `manifest_sha256`, including the Coordinator policy,
  exact proxy executable, and supervised TLS channel
- **Verifier:** gateway-owned supervisor running the official
  `privatemode-proxy`
- **Transport:** pinned TLS on loopback to the proxy; Privatemode E2EE from the
  proxy to model workers
- **Audit:** see [review.md](review.md)

## Why the proxy is part of the binding

Privatemode deliberately couples verification and encryption. The official
proxy verifies the Contrast Coordinator against a manifest, obtains the Mesh
CA, and exchanges an inference secret with the Secret Service. Only workloads
admitted under the same manifest receive that secret. The proxy then encrypts
inference requests and decrypts responses.

Reimplementing only a quote check would not bind gateway traffic to the secret
released by that protocol. The gateway therefore runs the official proxy as a
child inside its attested workload and treats the child as part of the channel
TCB.

## Supervised generation

The gateway, rather than an operator or sidecar manager, owns every proxy
generation:

1. At config load, it reads the configured proxy executable and manifest,
   verifies both SHA-256 pins, and validates that the manifest has exactly one
   Coordinator policy.
2. It copies both files into sealed Linux memory files. Later changes to the
   source paths cannot affect the generation.
3. It creates an ephemeral self-signed TLS certificate and key and seals those
   in memory files too.
4. It executes the binary through `/proc/self/fd`, passing only the manifest,
   TLS-file descriptors, and a reserved loopback port. The child starts with an
   empty environment and no API key in its arguments or environment.
5. Over a client that trusts only the generated certificate and never uses an
   HTTP proxy, the gateway sends the bearer credential on the child's first
   `/v1/models` request. A fresh official proxy cannot return success until it
   has completed Contrast verification and secret exchange.
6. Only after that request returns a valid models response can verification or
   inference succeed.

If the child exits, the next operation starts a fresh child from the same
sealed executable and manifest and performs the credential exchange again.
Replacing the upstream config creates a new generation. In-flight streaming
responses retain their old supervisor until the response body finishes, so a
config replacement cannot silently move a stream between generations.

This implementation is Linux-specific because sealed memory files and
`/proc/self/fd` execution are part of the security contract.

Privatemode-proxy v1.48 opens its selected port on the network namespace's
wildcard address; it has no listen-address flag. The gateway connects only to
the loopback address and authenticates the child by certificate, but the
workload network must expose only the gateway's public listener. Do not publish
or permit untrusted same-network access to the child's ephemeral ports.

## Configuration

Download and review both official artifacts, then calculate their digests:

```bash
sha256sum /run/privatemode/manifest.json
sha256sum /usr/local/bin/privatemode-proxy
```

Configure the gateway to supervise them:

```json
[
  {
    "name": "privatemode",
    "provider": "privatemode",
    "base_url": "supervised://privatemode-proxy",
    "models": {
      "gpt-oss-120b-private": "gpt-oss-120b"
    },
    "bearer_token": "<privatemode-api-key>",
    "privatemode_manifest_path": "/run/privatemode/manifest.json",
    "privatemode_manifest_sha256": "<64-lowercase-hex-characters>",
    "privatemode_proxy_binary_path": "/usr/local/bin/privatemode-proxy",
    "privatemode_proxy_binary_sha256": "<64-lowercase-hex-characters>"
  }
]
```

Both paths must be absolute. `base_url` is a required logical identifier, not a
network endpoint. Any other value is rejected. Operators must not launch a
separate proxy for this upstream, and container/VM ingress must expose only the
gateway port.

## Session binding

The verifier emits one binding:

```json
{
  "type": "manifest_sha256",
  "provider": "privatemode",
  "manifest_sha256": "...",
  "coordinator_policy_hash": "...",
  "proxy_binary_sha256": "...",
  "proxy_tls_certificate_sha256": "..."
}
```

The first three digests bind the provider policy and the exact implementation
that executed it. The TLS-certificate digest binds forwarding to that specific
child generation. The backend accepts only a verified Privatemode event with
exactly this binding, checks all four values against its shared supervisor, and
uses a client pinned to the same loopback certificate.

The event's `url_origin` is the generation's actual ephemeral
`https://127.0.0.1:<port>` origin. Its verifier id is
`privatemode-proxy/supervised-contrast/v1`. The raw pinned manifest is retained
as verification evidence.

## Failure behavior

The route fails closed when the binary or manifest is missing, malformed, or
does not match its digest; the manifest does not contain exactly one
Coordinator policy; the child cannot start; its pinned TLS endpoint does not
become ready; the authenticated models request fails; the child exits during
an operation; or the verified binding differs from the supervisor generation.

The gateway never falls back to the public Privatemode API, an externally
managed proxy, plaintext loopback, or a newly read version of either source
file.

## Updates

A manifest or proxy-binary change alters the channel TCB. Review the new
artifact, calculate a new digest, and intentionally replace the upstream
configuration. That replacement creates a distinct TLS certificate and
attested session; it does not mutate an existing generation.

## Sources

- [Privatemode attestation overview](https://docs.privatemode.ai/architecture/attestation/overview/)
- [Privatemode proxy configuration](https://docs.privatemode.ai/api/proxy-configuration/)
- [Privatemode TCB source](https://github.com/edgelesssys/privatemode-public)
- [Contrast source](https://github.com/edgelesssys/contrast)
