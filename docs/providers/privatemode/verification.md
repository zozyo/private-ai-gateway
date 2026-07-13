# Privatemode — co-deployed delegated attestation

- **TEE:** AMD SEV-SNP or Intel TDX + NVIDIA Confidential Computing
- **Session binding:** `manifest_image_sha256`: reviewed Contrast manifest, Coordinator policy, and
  official proxy OCI image digest
- **Verifier:** official `privatemode-proxy` co-deployed in the gateway's
  measured dstack Compose
- **Transport:** private Compose HTTP to the proxy; Privatemode full-body E2EE
  from the proxy to model workers
- **Audit:** see [review.md](review.md)

## Trust boundary

Privatemode deliberately couples verification and encryption. The official
proxy verifies the Contrast Coordinator against a manifest, obtains the Mesh
CA, exchanges an inference secret with the Secret Service, and uses that secret
to encrypt inference bodies. Reimplementing only the quote check would not bind
gateway traffic to the secret released by that protocol.

The gateway therefore delegates this protocol to the official proxy, but it
does not run the proxy as a child process. dstack launches the gateway and proxy
as separate services in one measured Compose workload. That measurement binds
the proxy image digest, its command, the manifest mount, and the private network
topology. The proxy port is not published.
Its workspace is an unpersisted `tmpfs`, so a service restart cannot silently
reuse credential or Contrast state from an earlier container generation.
The proxy is launched with `--nvidiaOCSPAllowUnknown=false` and
`--nvidiaOCSPRevokedGracePeriod=0`; unknown or revoked NVIDIA certificate
status therefore fails closed instead of using the availability-oriented
upstream defaults.

The gateway's static config separately pins:

- the internal proxy origin;
- the exact manifest path and SHA-256 digest;
- the SHA-256 digest of the one accepted API credential;
- the official proxy OCI image digest recorded in the Compose file.

These fields cannot be changed through `PUT /v1/admin/upstreams`. A dynamic
Privatemode route is accepted only when its `base_url` exactly matches the
static origin and its `bearer_token` matches the static credential digest. This
prevents an admin-config update from redirecting plaintext to a different proxy
or diverging from credential state retained by that proxy.

## Verification and forwarding

At startup, the gateway reads the mounted manifest, verifies its digest, and
requires exactly one Coordinator policy. When a route is verified, the gateway
sends an authenticated `GET /v1/models` to the pinned internal origin using a
client that ignores HTTP proxy environment variables. A fresh official proxy
cannot return a successful model list until it has completed Contrast
verification and inference-secret exchange for that credential. The client
also rejects redirects, so neither the readiness credential nor a forwarded
prompt can be redirected away from the pinned internal origin. Readiness has an
end-to-end request deadline and rejects model-list bodies over 1 MiB, including
chunked responses without a declared length.

The verifier emits a verified event only after this probe returns a JSON model
list. The forwarding backend accepts only that exact manifest/image binding,
then sends OpenAI-compatible requests to the same internal origin. The proxy
performs Privatemode full-body encryption and response decryption.

Plain HTTP is intentional at this hop. It is not a remote trust channel: both
endpoints and their private network are inside the same attested dstack
workload. Adding a self-signed TLS layer would encrypt the same in-workload hop
without independently authenticating the measured service. The security
requirements are instead that the proxy remains in the measured Compose and
its port is never published.

## Configuration

Use [`deploy/compose.privatemode.yaml`](../../../deploy/compose.privatemode.yaml)
and set the reviewed manifest file and digest before deployment:

```bash
export PRIVATE_AI_GATEWAY_REPO_COMMIT=<audited-commit>
export PRIVATE_AI_GATEWAY_ADMIN_TOKEN=<admin-token>
export PRIVATE_AI_GATEWAY_ADMIN_TOKEN_SHA256="$(printf %s "$PRIVATE_AI_GATEWAY_ADMIN_TOKEN" | sha256sum | cut -d' ' -f1)"
export PRIVATE_AI_GATEWAY_INFERENCE_TOKEN=<long-random-client-token>
export PRIVATE_AI_GATEWAY_INFERENCE_TOKEN_SHA256="$(printf %s "$PRIVATE_AI_GATEWAY_INFERENCE_TOKEN" | sha256sum | cut -d' ' -f1)"
export PRIVATEMODE_API_KEY=<privatemode-api-key>
export PRIVATEMODE_MANIFEST_PATH=/absolute/path/to/exact-reviewed-manifest.json
export PRIVATEMODE_CREDENTIAL_SHA256="$(printf %s "$PRIVATEMODE_API_KEY" | sha256sum | cut -d' ' -f1)"

deploy/render-privatemode-compose.sh /tmp/private-ai-gateway-privatemode.json
phala-h4xuser deploy -n private-ai-gateway \
  -c /tmp/private-ai-gateway-privatemode.json \
  -e PRIVATE_AI_GATEWAY_ADMIN_TOKEN="$PRIVATE_AI_GATEWAY_ADMIN_TOKEN" \
  -e PRIVATEMODE_API_KEY="$PRIVATEMODE_API_KEY"
```

Rendering makes the exact manifest bytes and non-secret pins part of the
measured Compose. The renderer verifies that inline serialization preserves the
manifest file's SHA-256, including its whitespace and final newline.
The admin and Privatemode secrets remain outside it and enter only through the
encrypted deployment environment. Compose mounts the Privatemode key as a
secret file for the official proxy's `--apiKey @<file>` interface. Their
measured SHA-256 policies prevent an untrusted host from substituting
credentials it knows. The downstream inference token never enters the
deployment: only its digest is measured, and clients present the token as a
Bearer credential on every inference request.

The measured static gateway config has this shape:

```json
{
  "inference_token_sha256": "<sha256-of-high-entropy-client-bearer>",
  "privatemode_proxy": {
    "base_url": "http://privatemode-proxy:8080",
    "manifest_path": "/run/privatemode/manifest.json",
    "manifest_sha256": "<64-lowercase-hex-characters>",
    "credential_sha256": "<sha256-of-privatemode-api-key>",
    "proxy_image_digest": "sha256:ff900b263a51a437633d15da809e7893a31fa4b1f4acfa4e526c075682d84307"
  }
}
```

Configure the mutable route, including its API credential, after boot:

```json
[
  {
    "name": "privatemode",
    "provider": "privatemode",
    "base_url": "http://privatemode-proxy:8080",
    "models": {
      "gpt-oss-120b-private": "gpt-oss-120b"
    },
    "bearer_token": "<privatemode-api-key>"
  }
]
```

One co-deployed proxy supports one gateway upstream entry. Put all models that
share its credential in that entry. The official proxy loads one credential
from its Compose secret file at startup. The gateway accepts only a
`bearer_token` matching the static measured `credential_sha256`, including after
route removal or a gateway-only restart. To rotate the key, remove the route,
change the measured credential digest, redeploy both the gateway and proxy,
then add the route with the new credential. If distinct credentials are
required, deploy distinct measured proxy services rather than pointing multiple
entries at one service.

## Session binding

The verifier emits one binding:

```json
{
  "type": "manifest_image_sha256",
  "provider": "privatemode",
  "manifest_sha256": "...",
  "coordinator_policy_hash": "...",
  "proxy_image_digest": "sha256:..."
}
```

The event's `url_origin` is the pinned internal service origin. Its verifier id
is `privatemode-proxy/co-deployed-contrast/v1`. The exact manifest bytes are
retained as verification evidence.

## Failure behavior

The route fails closed when static proxy policy is absent; the route origin
differs from the static origin; the manifest is missing, malformed, or has the
wrong digest; the manifest does not contain exactly one Coordinator policy;
the proxy image digest is malformed; the authenticated model-list probe fails;
or the verified receipt binding differs from the active deployment.

There is no fallback to the public Privatemode API, an operator-supplied remote
proxy, an HTTP redirect, or an HTTP proxy from the process environment. Proxy
error bodies are not exposed in public verification failures. Container
restart and lifecycle policy belong to Compose.

## Updates

A manifest or proxy-image change alters the channel TCB. Review both changes,
update the manifest digest and image digest in the measured static deployment,
and redeploy. A dynamic upstream-config replacement cannot mutate these pins.

## Sources

- [Privatemode attestation overview](https://docs.privatemode.ai/architecture/attestation/overview/)
- [Privatemode proxy configuration](https://docs.privatemode.ai/api/proxy-configuration/)
- [Privatemode TCB source](https://github.com/edgelesssys/privatemode-public)
- [Contrast source](https://github.com/edgelesssys/contrast)
