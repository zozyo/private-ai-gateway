//! Lifecycle and channel binding for the official `privatemode-proxy` child.
//!
//! The proxy does not expose its active Contrast manifest. To bind the secret it
//! establishes to an ACI session, the gateway owns the complete process launch:
//! exact executable bytes, exact immutable manifest bytes, and a one-generation
//! TLS identity are sealed in anonymous Linux files and inherited only by the
//! child. A fresh child receives its first API credential over that pinned TLS
//! channel; the official proxy synchronously performs Contrast verification and
//! secret exchange before that request can return successfully.

use std::fmt;
use std::fs::{DirBuilder, File};
use std::io::{Seek, SeekFrom, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustix::fs::{fchmod, fcntl_add_seals, memfd_create, MemfdFlags, Mode, SealFlags};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

use super::tls::pinned_certificate_client_no_proxy;
use super::UpstreamError;

const LOOPBACK_HOST: &str = "127.0.0.1";

#[derive(Debug, thiserror::Error)]
pub enum PrivatemodeSupervisorConfigError {
    #[error("Privatemode proxy binary path must be absolute")]
    RelativeBinaryPath,
    #[error("failed to read Privatemode proxy binary {path}: {source}")]
    ReadBinary {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid Privatemode proxy binary SHA-256 digest: {0}")]
    InvalidBinaryDigest(String),
    #[error(
        "Privatemode proxy binary digest {actual} does not match configured digest {expected}"
    )]
    BinaryDigestMismatch { actual: String, expected: String },
    #[error("Privatemode manifest path must be absolute")]
    RelativeManifestPath,
    #[error("failed to read Privatemode manifest {path}: {source}")]
    ReadManifest {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid Privatemode manifest SHA-256 digest: {0}")]
    InvalidManifestDigest(String),
    #[error("Privatemode manifest digest {actual} does not match configured digest {expected}")]
    ManifestDigestMismatch { actual: String, expected: String },
    #[error("invalid Privatemode manifest: {0}")]
    InvalidManifest(String),
    #[error("Privatemode requires a bearer token so a fresh proxy can complete secret exchange")]
    MissingBearerToken,
    #[error("failed to create sealed Privatemode process material: {0}")]
    SealedMaterial(String),
    #[error("failed to generate Privatemode child TLS identity: {0}")]
    TlsIdentity(String),
    #[error("failed to reserve Privatemode child port: {0}")]
    ReservePort(std::io::Error),
    #[error("failed to create Privatemode child workspace {path}: {source}")]
    CreateWorkspace {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to build Privatemode child TLS client: {0}")]
    TlsClient(String),
}

struct ProxyState {
    child: Option<Child>,
    reservation: Option<TcpListener>,
    ready: bool,
}

/// One config generation of a gateway-owned official Privatemode proxy.
pub struct PrivatemodeProxySupervisor {
    binary_fd: OwnedFd,
    manifest_fd: OwnedFd,
    tls_cert_fd: OwnedFd,
    tls_key_fd: OwnedFd,
    binary_sha256: String,
    manifest: Vec<u8>,
    manifest_sha256: String,
    coordinator_policy_hash: String,
    tls_certificate_sha256: String,
    bearer_token: String,
    base_url: String,
    port: u16,
    workspace: PathBuf,
    client: reqwest::Client,
    readiness_timeout: Duration,
    state: tokio::sync::Mutex<ProxyState>,
}

impl fmt::Debug for PrivatemodeProxySupervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivatemodeProxySupervisor")
            .field("binary_sha256", &self.binary_sha256)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("coordinator_policy_hash", &self.coordinator_policy_hash)
            .field("tls_certificate_sha256", &self.tls_certificate_sha256)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl PrivatemodeProxySupervisor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binary_path: impl AsRef<Path>,
        accepted_binary_sha256: impl AsRef<str>,
        manifest_path: impl AsRef<Path>,
        accepted_manifest_sha256: impl AsRef<str>,
        bearer_token: impl Into<String>,
        connect_timeout_seconds: u64,
        read_timeout_seconds: u64,
        readiness_timeout_seconds: u64,
    ) -> Result<Self, PrivatemodeSupervisorConfigError> {
        let binary_path = binary_path.as_ref();
        if !binary_path.is_absolute() {
            return Err(PrivatemodeSupervisorConfigError::RelativeBinaryPath);
        }
        let binary = std::fs::read(binary_path).map_err(|source| {
            PrivatemodeSupervisorConfigError::ReadBinary {
                path: binary_path.display().to_string(),
                source,
            }
        })?;
        let accepted_binary_sha256 = normalize_sha256_hex(accepted_binary_sha256.as_ref())
            .map_err(PrivatemodeSupervisorConfigError::InvalidBinaryDigest)?;
        let binary_sha256 = sha256_hex(&binary);
        if binary_sha256 != accepted_binary_sha256 {
            return Err(PrivatemodeSupervisorConfigError::BinaryDigestMismatch {
                actual: binary_sha256,
                expected: accepted_binary_sha256,
            });
        }

        let manifest_path = manifest_path.as_ref();
        if !manifest_path.is_absolute() {
            return Err(PrivatemodeSupervisorConfigError::RelativeManifestPath);
        }
        let manifest = std::fs::read(manifest_path).map_err(|source| {
            PrivatemodeSupervisorConfigError::ReadManifest {
                path: manifest_path.display().to_string(),
                source,
            }
        })?;
        let accepted_manifest_sha256 = normalize_sha256_hex(accepted_manifest_sha256.as_ref())
            .map_err(PrivatemodeSupervisorConfigError::InvalidManifestDigest)?;
        let manifest_sha256 = sha256_hex(&manifest);
        if manifest_sha256 != accepted_manifest_sha256 {
            return Err(PrivatemodeSupervisorConfigError::ManifestDigestMismatch {
                actual: manifest_sha256,
                expected: accepted_manifest_sha256,
            });
        }
        let coordinator_policy_hash = coordinator_policy_hash(&manifest)
            .map_err(PrivatemodeSupervisorConfigError::InvalidManifest)?;

        let bearer_token = bearer_token.into();
        if bearer_token.trim().is_empty() {
            return Err(PrivatemodeSupervisorConfigError::MissingBearerToken);
        }

        let binary_fd = sealed_memfd("privatemode-proxy", &binary, true)?;
        let manifest_fd = sealed_memfd("privatemode-manifest", &manifest, false)?;
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed([LOOPBACK_HOST.to_string()])
                .map_err(|e| PrivatemodeSupervisorConfigError::TlsIdentity(e.to_string()))?;
        let certificate_der = cert.der();
        let tls_certificate_sha256 = sha256_hex(certificate_der.as_ref());
        let tls_cert_fd = sealed_memfd("privatemode-tls-cert", cert.pem().as_bytes(), false)?;
        let tls_key_fd = sealed_memfd(
            "privatemode-tls-key",
            signing_key.serialize_pem().as_bytes(),
            false,
        )?;

        let reservation = TcpListener::bind((LOOPBACK_HOST, 0))
            .map_err(PrivatemodeSupervisorConfigError::ReservePort)?;
        let port = reservation
            .local_addr()
            .map_err(PrivatemodeSupervisorConfigError::ReservePort)?
            .port();
        let base_url = format!("https://{LOOPBACK_HOST}:{port}");
        let client = pinned_certificate_client_no_proxy(
            tls_certificate_sha256.clone(),
            connect_timeout_seconds,
            read_timeout_seconds,
        )
        .map_err(|e| PrivatemodeSupervisorConfigError::TlsClient(e.to_string()))?;

        let workspace = create_private_workspace()?;
        Ok(Self {
            binary_fd,
            manifest_fd,
            tls_cert_fd,
            tls_key_fd,
            binary_sha256: accepted_binary_sha256,
            manifest,
            manifest_sha256: accepted_manifest_sha256,
            coordinator_policy_hash,
            tls_certificate_sha256,
            bearer_token,
            base_url,
            port,
            workspace,
            client,
            readiness_timeout: Duration::from_secs(readiness_timeout_seconds),
            state: tokio::sync::Mutex::new(ProxyState {
                child: None,
                reservation: Some(reservation),
                ready: false,
            }),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    pub(crate) fn bearer_token(&self) -> &str {
        &self.bearer_token
    }

    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn manifest_evidence(&self) -> Value {
        serde_json::json!({
            "digest": format!("sha256:{}", self.manifest_sha256),
            "data": format!(
                "data:application/json;base64,{}",
                BASE64.encode(&self.manifest)
            ),
        })
    }

    pub fn coordinator_policy_hash(&self) -> &str {
        &self.coordinator_policy_hash
    }

    pub fn tls_certificate_sha256(&self) -> &str {
        &self.tls_certificate_sha256
    }

    /// Ensure an exact child generation has completed Contrast verification and
    /// inference-secret exchange before the caller admits or forwards traffic.
    pub async fn ensure_ready(&self) -> Result<(), UpstreamError> {
        let mut state = self.state.lock().await;
        let was_ready = state.ready;
        if let Some(child) = state.child.as_mut() {
            match child.try_wait() {
                Ok(None) if was_ready => return Ok(()),
                Ok(None) => {
                    child.start_kill().map_err(|e| {
                        UpstreamError::Transport(format!(
                            "failed to stop unready Privatemode proxy child: {e}"
                        ))
                    })?;
                    let _ = child.wait().await;
                    state.child = None;
                }
                Ok(Some(status)) => {
                    state.child = None;
                    state.ready = false;
                    tracing::warn!(%status, "supervised Privatemode proxy exited; restarting");
                }
                Err(err) => {
                    return Err(UpstreamError::Transport(format!(
                        "failed to inspect Privatemode proxy child: {err}"
                    )));
                }
            }
        }

        self.spawn(&mut state)?;
        let result = self.wait_until_ready(&mut state).await;
        if result.is_err() {
            if let Some(child) = state.child.as_mut() {
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
            state.child = None;
            state.ready = false;
        }
        result
    }

    fn spawn(&self, state: &mut ProxyState) -> Result<(), UpstreamError> {
        // The reserved listener prevents another process from claiming this
        // generation's endpoint before launch. TLS pinning authenticates the
        // endpoint after the reservation is released for the child to bind.
        drop(state.reservation.take());

        // Contrast keeps credentials in its workspace. A restarted process
        // must not inherit a prior child's credential cache: its first
        // authenticated request is what establishes this child's attestation
        // and inference-secret state. There cannot be a live child here.
        std::fs::remove_dir_all(&self.workspace).map_err(|e| {
            UpstreamError::Transport(format!(
                "failed to clear Privatemode proxy workspace {}: {e}",
                self.workspace.display()
            ))
        })?;
        let mut workspace = DirBuilder::new();
        workspace.mode(0o700);
        workspace.create(&self.workspace).map_err(|e| {
            UpstreamError::Transport(format!(
                "failed to recreate Privatemode proxy workspace {}: {e}",
                self.workspace.display()
            ))
        })?;

        let binary_fd = self.binary_fd.as_raw_fd();
        let manifest_fd = self.manifest_fd.as_raw_fd();
        let tls_cert_fd = self.tls_cert_fd.as_raw_fd();
        let tls_key_fd = self.tls_key_fd.as_raw_fd();
        let inherited_fds = [binary_fd, manifest_fd, tls_cert_fd, tls_key_fd];
        let mut command = Command::new(format!("/proc/self/fd/{binary_fd}"));
        command
            .args([
                "--manifestPath",
                &format!("/proc/self/fd/{manifest_fd}"),
                "--tlsCertPath",
                &format!("/proc/self/fd/{tls_cert_fd}"),
                "--tlsKeyPath",
                &format!("/proc/self/fd/{tls_key_fd}"),
                "--port",
                &self.port.to_string(),
                "--workspace",
                &self.workspace.display().to_string(),
            ])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        // SAFETY: `fcntl(F_SETFD)` is async-signal-safe. All strings and command
        // allocations are prepared before fork; the closure only clears CLOEXEC
        // on the four sealed descriptors intended for this exact child.
        unsafe {
            command.as_std_mut().pre_exec(move || {
                for fd in inherited_fds {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|e| {
            UpstreamError::Transport(format!("failed to spawn Privatemode proxy child: {e}"))
        })?;
        state.child = Some(child);
        state.ready = false;
        Ok(())
    }

    async fn wait_until_ready(&self, state: &mut ProxyState) -> Result<(), UpstreamError> {
        let started = Instant::now();
        loop {
            if let Some(child) = state.child.as_mut() {
                if let Some(status) = child.try_wait().map_err(|e| {
                    UpstreamError::Transport(format!(
                        "failed to inspect Privatemode proxy child: {e}"
                    ))
                })? {
                    return Err(UpstreamError::Transport(format!(
                        "Privatemode proxy exited before completing attestation: {status}"
                    )));
                }
            }
            let elapsed = started.elapsed();
            let Some(remaining) = self.readiness_timeout.checked_sub(elapsed) else {
                return Err(UpstreamError::Transport(format!(
                    "Privatemode proxy did not complete attestation within {}s",
                    self.readiness_timeout.as_secs()
                )));
            };
            let probe = self
                .client
                .get(format!("{}/v1/models", self.base_url))
                .header("accept", "application/json")
                .bearer_auth(&self.bearer_token)
                .send();
            match tokio::time::timeout(remaining, probe).await {
                Ok(Ok(response)) if response.status().is_success() => {
                    let payload: Value = response.json().await.map_err(|e| {
                        UpstreamError::Transport(format!(
                            "Privatemode proxy readiness returned invalid JSON: {e}"
                        ))
                    })?;
                    if !payload.get("data").is_some_and(Value::is_array) {
                        return Err(UpstreamError::Transport(
                            "Privatemode proxy readiness returned an invalid model list"
                                .to_string(),
                        ));
                    }
                    state.ready = true;
                    return Ok(());
                }
                Ok(Ok(response)) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    return Err(UpstreamError::Transport(format!(
                        "Privatemode proxy attestation probe returned {status}: {}",
                        truncate(&body, 512)
                    )));
                }
                Ok(Err(_)) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(_) => {
                    return Err(UpstreamError::Transport(format!(
                        "Privatemode proxy did not complete attestation within {}s",
                        self.readiness_timeout.as_secs()
                    )));
                }
            }
        }
    }
}

impl Drop for PrivatemodeProxySupervisor {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.try_lock() {
            if let Some(child) = state.child.as_mut() {
                let _ = child.start_kill();
            }
        }
        let _ = std::fs::remove_dir_all(&self.workspace);
    }
}

fn sealed_memfd(
    name: &str,
    bytes: &[u8],
    executable: bool,
) -> Result<OwnedFd, PrivatemodeSupervisorConfigError> {
    let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
        .map_err(|e| PrivatemodeSupervisorConfigError::SealedMaterial(e.to_string()))?;
    if executable {
        fchmod(&fd, Mode::RUSR | Mode::WUSR | Mode::XUSR)
            .map_err(|e| PrivatemodeSupervisorConfigError::SealedMaterial(e.to_string()))?;
    }
    let mut file = File::from(fd);
    file.write_all(bytes)
        .and_then(|_| file.seek(SeekFrom::Start(0)).map(|_| ()))
        .map_err(|e| PrivatemodeSupervisorConfigError::SealedMaterial(e.to_string()))?;
    fcntl_add_seals(
        &file,
        SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE | SealFlags::SEAL,
    )
    .map_err(|e| PrivatemodeSupervisorConfigError::SealedMaterial(e.to_string()))?;
    Ok(file.into())
}

fn create_private_workspace() -> Result<PathBuf, PrivatemodeSupervisorConfigError> {
    for _ in 0..16 {
        let path = std::env::temp_dir().join(format!(
            "private-ai-gateway-privatemode-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(PrivatemodeSupervisorConfigError::CreateWorkspace {
                    path: path.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(PrivatemodeSupervisorConfigError::CreateWorkspace {
        path: std::env::temp_dir().display().to_string(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique workspace",
        ),
    })
}

fn normalize_sha256_hex(value: &str) -> Result<String, String> {
    let value = value.trim().strip_prefix("sha256:").unwrap_or(value.trim());
    let bytes = hex::decode(value).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    Ok(hex::encode(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn coordinator_policy_hash(manifest: &[u8]) -> Result<String, String> {
    let manifest: Value = serde_json::from_slice(manifest)
        .map_err(|e| format!("invalid Privatemode manifest JSON: {e}"))?;
    let policies = manifest
        .get("Policies")
        .and_then(Value::as_object)
        .ok_or_else(|| "Privatemode manifest is missing Policies".to_string())?;
    let coordinator_policies = policies
        .iter()
        .filter(|(_, policy)| policy.get("Role").and_then(Value::as_str) == Some("coordinator"))
        .map(|(hash, _)| normalize_sha256_hex(hash))
        .collect::<Result<Vec<_>, _>>()?;
    match coordinator_policies.as_slice() {
        [hash] => Ok(hash.clone()),
        policies => Err(format!(
            "Privatemode manifest must contain exactly one Coordinator policy, found {}",
            policies.len()
        )),
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}
