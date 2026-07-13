//! Per-provider upstream verifiers that wrap the external bridge, plus the
//! origin/name routing verifier that dispatches to them.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;

use super::external::ExternalProviderVerifier;
#[cfg(test)]
use super::external::ProviderVerifierConfigError;
use crate::aci::receipt::{ChannelBinding, UpstreamVerifiedEvent, VerificationResult};
use crate::aci::upstream::{ChutesSessionStore, PrivatemodeProxyDeployment, UpstreamError};
use crate::aggregator::service::{UpstreamVerificationRequest, UpstreamVerifier};
use crate::aggregator::upstream_config::UpstreamProvider;

const MAX_PRIVATEMODE_MODELS_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ChutesProviderVerifier {
    verifier: ExternalProviderVerifier,
}

impl ChutesProviderVerifier {
    pub fn new(timeout_seconds: u64) -> Self {
        Self::new_with_cache(timeout_seconds, 0)
    }

    pub fn new_with_cache(timeout_seconds: u64, cache_ttl_seconds: u64) -> Self {
        Self {
            verifier: ExternalProviderVerifier::private_inference(
                "chutes",
                UpstreamProvider::Chutes.attestation_scope(),
                timeout_seconds,
                cache_ttl_seconds,
            ),
        }
    }

    pub fn new_with_cache_and_session_store(
        timeout_seconds: u64,
        cache_ttl_seconds: u64,
        session_store: Arc<ChutesSessionStore>,
    ) -> Self {
        Self {
            verifier: ExternalProviderVerifier::private_inference(
                "chutes",
                UpstreamProvider::Chutes.attestation_scope(),
                timeout_seconds,
                cache_ttl_seconds,
            )
            .with_chutes_session_store(session_store),
        }
    }

    pub fn with_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.verifier = self.verifier.with_option("chutes_api_key", api_key);
        self
    }

    pub fn with_e2ee_api_base(mut self, api_base: impl Into<String>) -> Self {
        self.verifier = self.verifier.with_option("chutes_e2ee_api_base", api_base);
        self
    }

    pub fn with_chute_ids(mut self, chute_ids: BTreeMap<String, String>) -> Self {
        for (model_id, chute_id) in chute_ids {
            self.verifier = self
                .verifier
                .with_option(format!("chutes_chute_id:{model_id}"), chute_id);
        }
        self
    }

    pub fn with_discovery_rounds(mut self, rounds: u64) -> Self {
        self.verifier = self
            .verifier
            .with_option("chutes_e2ee_discovery_rounds", rounds.to_string());
        self
    }

    pub fn with_discovery_interval_seconds(mut self, seconds: u64) -> Self {
        self.verifier = self.verifier.with_option(
            "chutes_e2ee_discovery_interval_seconds",
            seconds.to_string(),
        );
        self
    }

    #[cfg(test)]
    pub(super) fn with_command(
        command: Vec<String>,
        timeout_seconds: u64,
    ) -> Result<Self, ProviderVerifierConfigError> {
        Ok(Self {
            verifier: ExternalProviderVerifier::with_command(
                "chutes",
                UpstreamProvider::Chutes.attestation_scope(),
                command,
                timeout_seconds,
            )?,
        })
    }

    #[cfg(test)]
    pub(super) fn with_command_and_session_store(
        command: Vec<String>,
        timeout_seconds: u64,
        session_store: Arc<ChutesSessionStore>,
    ) -> Result<Self, ProviderVerifierConfigError> {
        Ok(Self {
            verifier: ExternalProviderVerifier::with_command(
                "chutes",
                UpstreamProvider::Chutes.attestation_scope(),
                command,
                timeout_seconds,
            )?
            .with_chutes_session_store(session_store),
        })
    }
}

#[async_trait]
impl UpstreamVerifier for ChutesProviderVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.verify(request).await
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.refresh(request).await
    }

    fn invalidate(&self, request: &UpstreamVerificationRequest) {
        self.verifier.invalidate(request);
    }
}

#[derive(Debug, Clone)]
pub struct TinfoilProviderVerifier {
    verifier: ExternalProviderVerifier,
}

impl TinfoilProviderVerifier {
    pub fn new(timeout_seconds: u64) -> Self {
        Self::new_with_cache(timeout_seconds, 0)
    }

    pub fn new_with_cache(timeout_seconds: u64, cache_ttl_seconds: u64) -> Self {
        Self {
            verifier: ExternalProviderVerifier::private_inference(
                "tinfoil",
                UpstreamProvider::Tinfoil.attestation_scope(),
                timeout_seconds,
                cache_ttl_seconds,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_command(
        command: Vec<String>,
        timeout_seconds: u64,
    ) -> Result<Self, ProviderVerifierConfigError> {
        Ok(Self {
            verifier: ExternalProviderVerifier::with_command(
                "tinfoil",
                UpstreamProvider::Tinfoil.attestation_scope(),
                command,
                timeout_seconds,
            )?,
        })
    }
}

#[async_trait]
impl UpstreamVerifier for TinfoilProviderVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.verify(request).await
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.refresh(request).await
    }

    fn invalidate(&self, request: &UpstreamVerificationRequest) {
        self.verifier.invalidate(request);
    }
}

#[derive(Debug, Clone)]
pub struct NearAiProviderVerifier {
    verifier: ExternalProviderVerifier,
}

impl NearAiProviderVerifier {
    pub fn new(timeout_seconds: u64) -> Self {
        Self::new_with_cache(timeout_seconds, 0)
    }

    pub fn new_with_cache(timeout_seconds: u64, cache_ttl_seconds: u64) -> Self {
        Self {
            verifier: ExternalProviderVerifier::private_inference(
                "near-ai",
                UpstreamProvider::NearAi.attestation_scope(),
                timeout_seconds,
                cache_ttl_seconds,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_command(
        command: Vec<String>,
        timeout_seconds: u64,
    ) -> Result<Self, ProviderVerifierConfigError> {
        Ok(Self {
            verifier: ExternalProviderVerifier::with_command(
                "near-ai",
                UpstreamProvider::NearAi.attestation_scope(),
                command,
                timeout_seconds,
            )?,
        })
    }
}

#[async_trait]
impl UpstreamVerifier for NearAiProviderVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.verify(request).await
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.refresh(request).await
    }

    fn invalidate(&self, request: &UpstreamVerificationRequest) {
        self.verifier.invalidate(request);
    }
}

/// Verifier for the exact official Privatemode proxy deployment measured with
/// the gateway. A successful authenticated model-list request proves that the
/// proxy completed Contrast verification and inference-secret exchange.
#[derive(Debug, Clone)]
pub struct PrivatemodeProviderVerifier {
    deployment: Arc<PrivatemodeProxyDeployment>,
    bearer_token: String,
    client: reqwest::Client,
}

impl PrivatemodeProviderVerifier {
    pub fn new(
        deployment: Arc<PrivatemodeProxyDeployment>,
        bearer_token: impl Into<String>,
        connect_timeout_seconds: u64,
        request_timeout_seconds: u64,
    ) -> Result<Self, UpstreamError> {
        let bearer_token = bearer_token.into();
        if bearer_token.trim().is_empty() {
            return Err(UpstreamError::Transport(
                "Privatemode requires a bearer token for attested secret exchange".to_string(),
            ));
        }
        if !deployment.accepts_credential(&bearer_token) {
            return Err(UpstreamError::Transport(
                "Privatemode bearer token does not match static credential_sha256 policy"
                    .to_string(),
            ));
        }
        let client =
            deployment.readiness_client(connect_timeout_seconds, request_timeout_seconds)?;
        Ok(Self {
            deployment,
            bearer_token,
            client,
        })
    }

    async fn verify_deployment(
        &self,
        request: UpstreamVerificationRequest,
    ) -> UpstreamVerifiedEvent {
        if let Err(err) = self.probe().await {
            return UpstreamVerifiedEvent {
                upstream_name: request.upstream_name,
                provider_type: Some("privatemode".to_string()),
                model_id: request.model_id,
                url_origin: Some(self.deployment.base_url().to_string()),
                verifier_id: "privatemode-proxy/co-deployed-contrast/v1".to_string(),
                result: VerificationResult::Failed,
                required: request.required,
                reason: Some(err.to_string()),
                ..Default::default()
            };
        }
        UpstreamVerifiedEvent {
            upstream_name: request.upstream_name,
            provider_type: Some("privatemode".to_string()),
            model_id: request.model_id,
            url_origin: Some(self.deployment.base_url().to_string()),
            verifier_id: "privatemode-proxy/co-deployed-contrast/v1".to_string(),
            result: VerificationResult::Verified,
            required: request.required,
            evidence: Some(self.deployment.manifest_evidence()),
            channel_bindings: vec![ChannelBinding::ManifestImageSha256 {
                provider: "privatemode".to_string(),
                manifest_sha256: self.deployment.manifest_sha256().to_string(),
                coordinator_policy_hash: self.deployment.coordinator_policy_hash().to_string(),
                proxy_image_digest: self.deployment.proxy_image_digest().to_string(),
            }],
            provider_claims: Some(serde_json::json!({
                "trust_boundary": "attested-compose-privatemode-proxy",
                "proxy_image_digest": self.deployment.proxy_image_digest(),
                "manifest_sha256": self.deployment.manifest_sha256(),
                "coordinator_policy_hash": self.deployment.coordinator_policy_hash(),
                "request_encryption": "privatemode-oae",
            })),
            reason: None,
        }
    }

    async fn probe(&self) -> Result<(), UpstreamError> {
        let response = self
            .client
            .get(format!("{}/v1/models", self.deployment.base_url()))
            .header("accept", "application/json")
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .map_err(|err| {
                UpstreamError::Transport(format!("Privatemode proxy probe failed: {err}"))
            })?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(UpstreamError::Transport(format!(
                "Privatemode proxy attestation probe returned {status}"
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PRIVATEMODE_MODELS_RESPONSE_BYTES as u64)
        {
            return Err(UpstreamError::Transport(format!(
                "Privatemode proxy readiness response exceeds {MAX_PRIVATEMODE_MODELS_RESPONSE_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|err| {
                UpstreamError::Transport(format!("Privatemode proxy readiness body failed: {err}"))
            })?;
            let next_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
                UpstreamError::Transport(
                    "Privatemode proxy readiness response length overflowed".to_string(),
                )
            })?;
            if next_len > MAX_PRIVATEMODE_MODELS_RESPONSE_BYTES {
                return Err(UpstreamError::Transport(format!(
                    "Privatemode proxy readiness response exceeds {MAX_PRIVATEMODE_MODELS_RESPONSE_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let payload: serde_json::Value = serde_json::from_slice(&body).map_err(|err| {
            UpstreamError::Transport(format!(
                "Privatemode proxy readiness returned invalid JSON: {err}"
            ))
        })?;
        if !payload.get("data").is_some_and(serde_json::Value::is_array) {
            return Err(UpstreamError::Transport(
                "Privatemode proxy readiness returned an invalid model list".to_string(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl UpstreamVerifier for PrivatemodeProviderVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verify_deployment(request).await
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verify_deployment(request).await
    }

    fn invalidate(&self, _request: &UpstreamVerificationRequest) {}
}

/// Verifier for `PhalaDirect` upstreams: a Phala dstack-vllm-proxy attestation
/// endpoint reached directly (per model). The external bridge fetches the
/// `version=2` attestation report, verifies the dstack TDX quote, GPU evidence,
/// and the report_data binding (signing address + nonce + custom-domain TLS
/// SPKI), and returns a `tls_spki_sha256` channel binding the
/// [`OpenAICompatibleBackend`] pins on the forward connection.
///
/// (Named "direct" because it is expected to be superseded by an ACI-compatible
/// server; see [`AciServiceUpstreamVerifier`].)
#[derive(Debug, Clone)]
pub struct PhalaDirectProviderVerifier {
    verifier: ExternalProviderVerifier,
}

impl PhalaDirectProviderVerifier {
    pub fn new(timeout_seconds: u64) -> Self {
        Self::new_with_cache(timeout_seconds, 0)
    }

    pub fn new_with_cache(timeout_seconds: u64, cache_ttl_seconds: u64) -> Self {
        Self {
            verifier: ExternalProviderVerifier::private_inference(
                "phala-direct",
                UpstreamProvider::PhalaDirect.attestation_scope(),
                timeout_seconds,
                cache_ttl_seconds,
            ),
        }
    }

    /// Bearer token sent on the attestation report request (the proxy's
    /// `/v1/attestation/report` endpoint requires authorization).
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.verifier = self
            .verifier
            .with_option("phala_direct_bearer_token", token);
        self
    }

    #[cfg(test)]
    pub(super) fn with_command(
        command: Vec<String>,
        timeout_seconds: u64,
    ) -> Result<Self, ProviderVerifierConfigError> {
        Ok(Self {
            verifier: ExternalProviderVerifier::with_command(
                "phala-direct",
                UpstreamProvider::PhalaDirect.attestation_scope(),
                command,
                timeout_seconds,
            )?,
        })
    }
}

#[async_trait]
impl UpstreamVerifier for PhalaDirectProviderVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.verify(request).await
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        self.verifier.refresh(request).await
    }

    fn invalidate(&self, request: &UpstreamVerificationRequest) {
        self.verifier.invalidate(request);
    }
}

pub struct RoutingUpstreamVerifier {
    by_origin: HashMap<String, Arc<dyn UpstreamVerifier>>,
    by_name: HashMap<String, Arc<dyn UpstreamVerifier>>,
}

impl RoutingUpstreamVerifier {
    pub fn new() -> Self {
        Self {
            by_origin: HashMap::new(),
            by_name: HashMap::new(),
        }
    }

    pub fn add_origin(
        mut self,
        origin: impl Into<String>,
        verifier: Arc<dyn UpstreamVerifier>,
    ) -> Self {
        self.by_origin.insert(origin.into(), verifier);
        self
    }

    pub fn add_name(
        mut self,
        name: impl Into<String>,
        verifier: Arc<dyn UpstreamVerifier>,
    ) -> Self {
        self.by_name.insert(name.into(), verifier);
        self
    }
}

impl Default for RoutingUpstreamVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UpstreamVerifier for RoutingUpstreamVerifier {
    async fn verify(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        // A selected route name is more specific than its origin. Several
        // routes can intentionally share one router origin while using
        // different provider policy or credentials (notably Privatemode).
        if let Some(verifier) = self.by_name.get(&request.upstream_name) {
            return verifier.verify(request).await;
        }
        if let Some(origin) = request.url_origin.as_ref() {
            if let Some(verifier) = self.by_origin.get(origin) {
                return verifier.verify(request).await;
            }
        }
        UpstreamVerifiedEvent {
            upstream_name: request.upstream_name,
            model_id: request.model_id,
            url_origin: request.url_origin,
            verifier_id: "routing-upstream-verifier/v1".to_string(),
            result: VerificationResult::Failed,
            required: request.required,
            reason: Some("no verifier configured for selected upstream".to_string()),
            ..Default::default()
        }
    }

    async fn refresh(&self, request: UpstreamVerificationRequest) -> UpstreamVerifiedEvent {
        if let Some(verifier) = self.by_name.get(&request.upstream_name) {
            return verifier.refresh(request).await;
        }
        if let Some(origin) = request.url_origin.as_ref() {
            if let Some(verifier) = self.by_origin.get(origin) {
                return verifier.refresh(request).await;
            }
        }
        UpstreamVerifiedEvent {
            upstream_name: request.upstream_name,
            model_id: request.model_id,
            url_origin: request.url_origin,
            verifier_id: "routing-upstream-verifier/v1".to_string(),
            result: VerificationResult::Failed,
            required: request.required,
            reason: Some("no verifier configured for selected upstream".to_string()),
            ..Default::default()
        }
    }

    fn invalidate(&self, request: &UpstreamVerificationRequest) {
        if let Some(verifier) = self.by_name.get(&request.upstream_name) {
            verifier.invalidate(request);
            return;
        }
        if let Some(origin) = request.url_origin.as_ref() {
            if let Some(verifier) = self.by_origin.get(origin) {
                verifier.invalidate(request);
            }
        }
    }
}
