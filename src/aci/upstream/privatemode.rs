//! Privatemode transport through a gateway-supervised official proxy.
//!
//! The supervisor binds exact proxy executable bytes, immutable Contrast
//! manifest bytes, and an ephemeral TLS identity into one child generation.
//! This backend accepts only the receipt binding for that generation and sends
//! plaintext exclusively over its pinned loopback TLS channel.

use std::sync::Arc;

use async_trait::async_trait;
use futures_util::StreamExt;

use super::{
    OpenAICompatibleBackend, PreparedUpstreamRequest, PrivatemodeProxySupervisor, UpstreamBackend,
    UpstreamError, UpstreamRequest, UpstreamResponse, UpstreamStreamResponse,
};
use crate::aci::receipt::{ChannelBinding, UpstreamVerifiedEvent, VerificationResult};

const PROVIDER: &str = "privatemode";

#[derive(Debug, thiserror::Error)]
pub enum PrivatemodeBackendConfigError {
    #[error("invalid Privatemode backend: {0}")]
    Backend(String),
}

pub struct PrivatemodeProviderBackend {
    inner: OpenAICompatibleBackend,
    supervisor: Arc<PrivatemodeProxySupervisor>,
}

impl PrivatemodeProviderBackend {
    pub fn new_with_timeouts(
        supervisor: Arc<PrivatemodeProxySupervisor>,
        connect_timeout_seconds: u64,
        read_timeout_seconds: u64,
    ) -> Result<Self, PrivatemodeBackendConfigError> {
        let inner = OpenAICompatibleBackend::new_with_timeouts(
            supervisor.base_url(),
            connect_timeout_seconds,
            read_timeout_seconds,
        )
        .map_err(|e| PrivatemodeBackendConfigError::Backend(e.to_string()))?
        .with_client(supervisor.client())
        .with_bearer_token(supervisor.bearer_token().to_string());
        Ok(Self { inner, supervisor })
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.inner = self.inner.with_name(name);
        self
    }

    fn enforce_proxy_binding(&self, event: &UpstreamVerifiedEvent) -> Result<(), UpstreamError> {
        if event.result != VerificationResult::Verified {
            return Err(binding_mismatch(
                "Privatemode forwarding requires a verified event",
            ));
        }
        if event.provider_type.as_deref() != Some(PROVIDER) {
            return Err(binding_mismatch(format!(
                "verification provider {:?} is not {PROVIDER:?}",
                event.provider_type
            )));
        }
        if event.url_origin.as_deref() != self.url_origin() {
            return Err(binding_mismatch(format!(
                "verified proxy origin {:?} does not match supervised child {:?}",
                event.url_origin,
                self.url_origin()
            )));
        }
        let [ChannelBinding::ManifestSha256 {
            provider,
            manifest_sha256,
            coordinator_policy_hash,
            proxy_binary_sha256,
            proxy_tls_certificate_sha256,
        }] = event.channel_bindings.as_slice()
        else {
            return Err(binding_mismatch(
                "Privatemode verification must produce exactly one manifest_sha256 binding",
            ));
        };
        if provider != PROVIDER
            || manifest_sha256 != self.supervisor.manifest_sha256()
            || coordinator_policy_hash != self.supervisor.coordinator_policy_hash()
            || proxy_binary_sha256 != self.supervisor.binary_sha256()
            || proxy_tls_certificate_sha256 != self.supervisor.tls_certificate_sha256()
        {
            return Err(binding_mismatch(
                "Privatemode event does not match the active supervised proxy generation",
            ));
        }
        Ok(())
    }

    async fn admit(&self, event: &UpstreamVerifiedEvent) -> Result<(), UpstreamError> {
        self.enforce_proxy_binding(event)?;
        self.supervisor.ensure_ready().await
    }
}

#[async_trait]
impl UpstreamBackend for PrivatemodeProviderBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn url_origin(&self) -> Option<&str> {
        self.inner.url_origin()
    }

    fn prepare(&self, req: UpstreamRequest) -> Result<PreparedUpstreamRequest, UpstreamError> {
        self.inner.prepare(req)
    }

    async fn forward(&self, _req: UpstreamRequest) -> Result<UpstreamResponse, UpstreamError> {
        Err(verification_required())
    }

    async fn forward_prepared(
        &self,
        _req: PreparedUpstreamRequest,
    ) -> Result<UpstreamResponse, UpstreamError> {
        Err(verification_required())
    }

    async fn forward_verified_prepared(
        &self,
        req: PreparedUpstreamRequest,
        event: &UpstreamVerifiedEvent,
    ) -> Result<UpstreamResponse, UpstreamError> {
        self.admit(event).await?;
        self.inner.forward_prepared(req).await
    }

    async fn models(&self) -> Result<UpstreamResponse, UpstreamError> {
        self.supervisor.ensure_ready().await?;
        self.inner.models().await
    }

    async fn forward_stream(
        &self,
        _req: UpstreamRequest,
    ) -> Result<UpstreamStreamResponse, UpstreamError> {
        Err(verification_required())
    }

    async fn forward_stream_prepared(
        &self,
        _req: PreparedUpstreamRequest,
    ) -> Result<UpstreamStreamResponse, UpstreamError> {
        Err(verification_required())
    }

    async fn forward_stream_verified_prepared(
        &self,
        req: PreparedUpstreamRequest,
        event: &UpstreamVerifiedEvent,
    ) -> Result<UpstreamStreamResponse, UpstreamError> {
        self.admit(event).await?;
        let mut response = self.inner.forward_stream_prepared(req).await?;
        // A dynamic config replacement drops the old backend immediately after
        // this method returns. Keep its supervised child alive until the caller
        // consumes or drops the response stream.
        let supervisor = self.supervisor.clone();
        response.body = Box::pin(response.body.map(move |item| {
            let _generation_guard = &supervisor;
            item
        }));
        Ok(response)
    }
}

fn binding_mismatch(message: impl Into<String>) -> UpstreamError {
    UpstreamError::ChannelBindingMismatch(message.into())
}

fn verification_required() -> UpstreamError {
    UpstreamError::ChannelBindingMismatch(
        "Privatemode forwarding requires an active supervised proxy binding".to_string(),
    )
}
