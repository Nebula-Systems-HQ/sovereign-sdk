use std::time::Duration;

#[cfg(feature = "unix-client")]
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyClientConfig {
    /// Static key configuration (no external fetching).
    ///
    /// Currently supports symmetric AES-256-GCM only. For future asymmetric encryption
    /// support (HPKE with Kyber KEM for forced inclusion transactions), an algorithm type
    /// will be added to InternalKey and keys will be delivered via the Unix socket key
    /// service with type metadata. See PR2_REVIEW_PLAN.md "Asymmetric Encryption Roadmap".
    Static {
        /// Hex-encoded AES-256-GCM encryption key (must be exactly 32 bytes / 64 hex chars)
        encryption_key: String,
    },

    /// Unix socket key client
    #[cfg(feature = "unix-client")]
    UnixSocket {
        /// Path to the Unix socket
        socket_path: PathBuf,
        /// Timeout for key server requests (in seconds)
        #[serde(default = "default_key_server_timeout")]
        timeout: u64,
        /// Maximum number of retry attempts
        #[serde(default = "default_max_retries")]
        max_retries: u32,
        /// Retry backoff base delay (in milliseconds)
        #[serde(default = "default_retry_delay_ms")]
        retry_delay_ms: u64,
        /// Optional initial key to start with (hex-encoded)
        initial_key: Option<String>,
    },
}

#[cfg(feature = "unix-client")]
fn default_key_server_timeout() -> u64 {
    30 // 30 seconds
}

#[cfg(feature = "unix-client")]
fn default_max_retries() -> u32 {
    3
}

#[cfg(feature = "unix-client")]
fn default_retry_delay_ms() -> u64 {
    1000 // 1 second
}

impl std::fmt::Debug for KeyClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyClientConfig::Static { .. } => f
                .debug_struct("Static")
                .field("encryption_key", &"[REDACTED]")
                .finish(),
            #[cfg(feature = "unix-client")]
            KeyClientConfig::UnixSocket {
                socket_path,
                timeout,
                max_retries,
                retry_delay_ms,
                initial_key,
            } => f
                .debug_struct("UnixSocket")
                .field("socket_path", socket_path)
                .field("timeout", timeout)
                .field("max_retries", max_retries)
                .field("retry_delay_ms", retry_delay_ms)
                .field(
                    "initial_key",
                    &initial_key.as_ref().map(|_| "[REDACTED]"),
                )
                .finish(),
        }
    }
}

impl KeyClientConfig {
    pub fn timeout_duration(&self) -> Option<Duration> {
        match self {
            KeyClientConfig::Static { .. } => None,
            #[cfg(feature = "unix-client")]
            KeyClientConfig::UnixSocket { timeout, .. } => Some(Duration::from_secs(*timeout)),
        }
    }

    pub fn retry_delay_duration(&self) -> Option<Duration> {
        match self {
            KeyClientConfig::Static { .. } => None,
            #[cfg(feature = "unix-client")]
            KeyClientConfig::UnixSocket { retry_delay_ms, .. } => {
                Some(Duration::from_millis(*retry_delay_ms))
            }
        }
    }

    pub fn max_retries(&self) -> u32 {
        match self {
            KeyClientConfig::Static { .. } => 0,
            #[cfg(feature = "unix-client")]
            KeyClientConfig::UnixSocket { max_retries, .. } => *max_retries,
        }
    }
}
