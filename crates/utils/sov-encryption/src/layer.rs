use std::collections::VecDeque;
#[cfg(feature = "unix-client")]
use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use secrecy::zeroize::Zeroize;
use secrecy::{ExposeSecret, SecretBox};

#[cfg(feature = "unix-client")]
use futures::StreamExt;
use serde::{Deserialize, Serialize};
#[cfg(feature = "unix-client")]
use tokio::net::{UnixListener, UnixStream};
#[cfg(feature = "unix-client")]
use tokio_util::codec::{FramedRead, LengthDelimitedCodec};
#[cfg(feature = "unix-client")]
use tracing::error;
use tracing::{debug, info, warn};

#[cfg(feature = "aes-encryption")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
#[cfg(feature = "aes-encryption")]
use rand::{rngs::OsRng, RngCore};

use crate::{config::KeyClientConfig, error::EncryptionError};

#[cfg(feature = "aes-encryption")]
const AES_256_KEY_SIZE: usize = 32;
#[cfg(feature = "aes-encryption")]
const AES_GCM_NONCE_SIZE: usize = 12;
#[cfg(feature = "aes-encryption")]
const AES_GCM_TAG_SIZE: usize = 16;

/// Key format from the key service (matches your service exactly).
/// Implements Drop to zeroize key_data, ensuring key material is securely
/// wiped from memory even on unexpected drop paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub id: String,
    pub key_data: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub slot_number: u64,
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        self.key_data.zeroize();
    }
}

/// Internal key format used by the encryption layer.
/// Key material is wrapped in Arc<SecretBox> so that cloning shares the same
/// protected memory rather than copying raw key bytes through an intermediate Vec.
/// SecretBox provides:
/// - Zeroize on drop (securely wiped from memory)
/// - No accidental logging (Debug shows [REDACTED])
#[derive(Clone)]
pub struct InternalKey {
    pub id: String,
    pub material: Arc<SecretBox<Vec<u8>>>,
}

impl std::fmt::Debug for InternalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalKey")
            .field("id", &self.id)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyUpdate {
    NewKey(EncryptionKey),
}

/// Number of old keys to keep as a buffer when pruning after decryption.
/// Example: with buffer_size=2 and keys [A, B, C, D], decrypting with D removes A → [B, C, D]
const KEY_PRUNE_BUFFER_SIZE: usize = 2;

#[derive(Clone)]
pub struct KeyCache {
    // Queue of keys in arrival order (oldest first, newest last)
    // Each entry is (slot, key) where slot is the slot number the key is valid from
    key_queue: Arc<RwLock<VecDeque<(u64, InternalKey)>>>,
}

impl KeyCache {
    pub fn new() -> Self {
        Self {
            key_queue: Arc::new(RwLock::new(VecDeque::new())),
        }
    }

    /// For ENCRYPTION: Find key by slot logic with fallback to most recent.
    /// Returns the newest key where key_slot <= batch_slot, or the most recent key as fallback.
    pub fn get_key_for_slot(&self, slot_number: u64) -> Option<InternalKey> {
        let queue = self.key_queue.read();

        // Primary: find newest key where slot <= batch_slot
        for (slot, key) in queue.iter().rev() {
            if *slot <= slot_number {
                debug!(
                    "🔑 Found key '{}' (slot {}) for batch slot {}",
                    key.id, slot, slot_number
                );
                return Some(key.clone());
            }
        }

        // Fallback: use the most recent key (all keys have slots > batch_slot)
        if let Some((slot, key)) = queue.back() {
            debug!(
                "🔑 FALLBACK: No key with slot <= {}, using most recent '{}' (slot {})",
                slot_number, key.id, slot
            );
            return Some(key.clone());
        }

        debug!("🔑 NO KEY: No keys available");
        None
    }

    /// For DECRYPTION: Get exact key by ID.
    pub fn get_key_by_id(&self, key_id: &str) -> Option<InternalKey> {
        self.key_queue
            .read()
            .iter()
            .find(|(_, key)| key.id == key_id)
            .map(|(_, key)| key.clone())
    }

    /// Add a new key to the cache.
    pub fn add_key(&self, slot_number: u64, key: InternalKey) {
        info!("🔑 KEY ADDED: '{}' for slot {}", key.id, slot_number);
        let mut queue = self.key_queue.write();
        queue.push_back((slot_number, key));
    }

    /// Prune old keys, keeping a buffer of N keys before the specified key.
    /// Example: with buffer_size=2 and keys [A, B, C, D], pruning at D removes A → [B, C, D]
    pub fn prune_keys_before_id(&self, key_id: &str, buffer_size: usize) {
        let mut queue = self.key_queue.write();

        // Find the position of the key we just used
        let Some(pos) = queue.iter().position(|(_, k)| k.id == key_id) else {
            return;
        };

        // Keep buffer_size keys before the used key, remove older ones
        let remove_count = pos.saturating_sub(buffer_size);
        if remove_count > 0 {
            queue.drain(0..remove_count);
            debug!(
                "Pruned {} old key(s), {} remaining",
                remove_count,
                queue.len()
            );
        }
    }

    /// Get the number of keys currently in the cache
    pub fn len(&self) -> usize {
        self.key_queue.read().len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.key_queue.read().is_empty()
    }
}

impl Default for KeyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Primary encryption interface with slot-based key management
///
/// The listener task (if started) is detached and runs independently.
/// The `KeyCache` is shared via `Arc`, so all clones share the same cache.
#[derive(Clone)]
pub struct EncryptionLayer {
    key_cache: Arc<KeyCache>,
}

impl EncryptionLayer {
    /// Create a new encryption layer from a key client config (preferred)
    ///
    /// The optional `shutdown_receiver` is used to gracefully stop the Unix socket
    /// key listener when the node is shutting down. Pass `None` for static key configs
    /// or when shutdown signaling is not needed.
    pub async fn new(
        key_client_config: KeyClientConfig,
        #[allow(unused_variables)] // Used only with unix-client feature
        shutdown_receiver: Option<tokio::sync::watch::Receiver<()>>,
    ) -> Result<Self, EncryptionError> {
        info!(
            "Creating encryption layer with config: {:?}",
            key_client_config
        );
        let key_cache = Arc::new(KeyCache::new());

        // Handle different key client configurations
        match &key_client_config {
            #[cfg(feature = "unix-client")]
            KeyClientConfig::UnixSocket {
                socket_path,
                initial_key,
                ..
            } => {
                // If an initial key is provided, populate the cache with it
                if let Some(key_hex) = initial_key {
                    let key_bytes = hex::decode(key_hex).map_err(|e| {
                        EncryptionError::InvalidKeyFormat(format!("Invalid hex initial key: {e}"))
                    })?;
                    if key_bytes.len() != 32 {
                        return Err(EncryptionError::InvalidKeyFormat(format!(
                            "Initial key must be 32 bytes, got {}",
                            key_bytes.len()
                        )));
                    }
                    let initial_encryption_key = InternalKey {
                        id: "genesis-key".to_string(),
                        material: Arc::new(SecretBox::new(Box::new(key_bytes))),
                    };
                    key_cache.add_key(0, initial_encryption_key);
                    info!("Initialized unix socket encryption layer with genesis key");
                }

                // Start unix socket listener for key pushes (spawns detached background task)
                Self::spawn_key_listener(key_cache.clone(), socket_path.clone(), shutdown_receiver);
                info!(
                    "Started key listener for unix socket key client at {:?}",
                    socket_path
                );
            }
            KeyClientConfig::Static { encryption_key, .. } => {
                // For static keys, populate the cache immediately
                let key_bytes = hex::decode(encryption_key).map_err(|e| {
                    EncryptionError::InvalidKeyFormat(format!("Invalid hex key: {e}"))
                })?;
                if key_bytes.len() != 32 {
                    return Err(EncryptionError::InvalidKeyFormat(format!(
                        "Static key must be 32 bytes, got {}",
                        key_bytes.len()
                    )));
                }
                if key_bytes.iter().all(|b| *b == 0) {
                    return Err(EncryptionError::InvalidKeyFormat(
                        "Static key must not be all zeros".into(),
                    ));
                }
                let static_key = InternalKey {
                    id: "static-key".to_string(),
                    material: Arc::new(SecretBox::new(Box::new(key_bytes))),
                };
                key_cache.add_key(0, static_key);
                info!("Initialized with static encryption key");
            }
        }

        Ok(Self { key_cache })
    }

    #[cfg(feature = "aes-encryption")]
    fn encrypt_with_key(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {} byte key, got {}",
                AES_256_KEY_SIZE,
                key.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        // Generate a random nonce
        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        debug!("Encrypting {} bytes with AES-256-GCM", plaintext.len());

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {e}"))
        })?;

        // Prepend nonce to ciphertext for storage
        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        debug!(
            "Successfully encrypted to {} bytes (including nonce)",
            result.len()
        );
        Ok(result)
    }

    #[cfg(feature = "aes-encryption")]
    fn decrypt_with_key(
        &self,
        key: &[u8],
        ciphertext_with_nonce: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {} byte key, got {}",
                AES_256_KEY_SIZE,
                key.len()
            )));
        }

        let min_ciphertext_len = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
        if ciphertext_with_nonce.len() < min_ciphertext_len {
            return Err(EncryptionError::InvalidCiphertextFormat(format!(
                "Ciphertext too short: expected at least {} bytes (nonce + auth tag), got {}",
                min_ciphertext_len,
                ciphertext_with_nonce.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        // Extract nonce from the beginning
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_GCM_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        debug!("Decrypting {} bytes with AES-256-GCM", ciphertext.len());

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EncryptionError::DecryptionFailed(format!("AES-GCM decryption failed: {e}"))
        })?;

        debug!("Successfully decrypted to {} bytes", plaintext.len());
        Ok(plaintext)
    }

    /// Start a unix socket listener for pushed keys from the key service.
    ///
    /// This spawns a background task that:
    /// - Binds to the socket with exponential backoff retry (interruptible by shutdown)
    /// - Accepts connections and processes key updates
    /// - On errors, logs and retries (exits on shutdown signal)
    /// - Cleans up the socket file on shutdown
    ///
    /// Errors are surfaced through logging, not return values. The task is designed
    /// to be resilient and recover from transient failures.
    ///
    /// If `shutdown_receiver` is `None`, the listener runs indefinitely.
    ///
    /// This is a static method that spawns a detached background task. The task
    /// runs independently and is not tied to any particular `EncryptionLayer` instance.
    #[cfg(feature = "unix-client")]
    fn spawn_key_listener<P: AsRef<Path> + Send + 'static>(
        cache: Arc<KeyCache>,
        socket_path: P,
        shutdown_receiver: Option<tokio::sync::watch::Receiver<()>>,
    ) {
        tokio::spawn(async move {
            use std::os::unix::fs::PermissionsExt;
            use std::time::Duration;

            const INITIAL_BIND_BACKOFF: Duration = Duration::from_secs(1);
            const MAX_BIND_BACKOFF: Duration = Duration::from_secs(60);

            let mut bind_backoff = INITIAL_BIND_BACKOFF;
            let mut shutdown_rx = shutdown_receiver;

            // Outer loop: bind with exponential backoff
            loop {
                // Check for shutdown before attempting to bind
                if let Some(ref mut rx) = shutdown_rx {
                    if rx.has_changed().unwrap_or(true) {
                        info!("Shutdown signal received before bind, stopping key listener");
                        break;
                    }
                }

                // Remove existing socket file if it exists.
                // Intentionally ignoring errors: the file may not exist, which is fine.
                let _ = std::fs::remove_file(&socket_path);

                let listener = match UnixListener::bind(&socket_path) {
                    Ok(listener) => {
                        // Set restrictive permissions: only owner can read/write (0600)
                        if let Err(e) = std::fs::set_permissions(
                            socket_path.as_ref(),
                            std::fs::Permissions::from_mode(0o600),
                        ) {
                            error!("Failed to set socket permissions: {}", e);
                        }

                        info!(
                            "Key listener bound to {:?} (permissions: 0600)",
                            socket_path.as_ref()
                        );
                        bind_backoff = INITIAL_BIND_BACKOFF; // Reset on success
                        listener
                    }
                    Err(e) => {
                        error!(
                            "Failed to bind key socket {:?}: {}",
                            socket_path.as_ref(),
                            e
                        );

                        // Wait for backoff duration, but allow shutdown to interrupt the sleep
                        if let Some(ref mut rx) = shutdown_rx {
                            tokio::select! {
                                _ = tokio::time::sleep(bind_backoff) => {}
                                _ = rx.changed() => {
                                    info!("Shutdown signal received during bind backoff, stopping key listener");
                                    break;
                                }
                            }
                        } else {
                            warn!("Retrying bind in {:?}...", bind_backoff);
                            tokio::time::sleep(bind_backoff).await;
                        }

                        bind_backoff = (bind_backoff * 2).min(MAX_BIND_BACKOFF);
                        continue;
                    }
                };

                // Inner loop: accept connections
                let shutdown_triggered = loop {
                    if let Some(ref mut rx) = shutdown_rx {
                        tokio::select! {
                            result = listener.accept() => {
                                match result {
                                    Ok((stream, _)) => {
                                        info!("Key service connected");

                                        if let Err(e) = Self::handle_key_connection(stream, cache.clone()).await {
                                            warn!("Key connection ended: {}", e);
                                        }

                                        info!("Key service disconnected, waiting for reconnection...");
                                    }
                                    Err(e) => {
                                        error!("Accept error: {}", e);
                                        warn!("Rebinding socket...");
                                        break false; // Break inner loop to rebind
                                    }
                                }
                            }
                            _ = rx.changed() => {
                                info!("Shutdown signal received, stopping key listener");
                                break true;
                            }
                        }
                    } else {
                        match listener.accept().await {
                            Ok((stream, _)) => {
                                info!("Key service connected");

                                if let Err(e) =
                                    Self::handle_key_connection(stream, cache.clone()).await
                                {
                                    warn!("Key connection ended: {}", e);
                                }

                                info!("Key service disconnected, waiting for reconnection...");
                            }
                            Err(e) => {
                                error!("Accept error: {}", e);
                                warn!("Rebinding socket...");
                                break false; // Break inner loop to rebind
                            }
                        }
                    }
                };

                if shutdown_triggered {
                    break;
                }
            }

            // Clean up socket file on shutdown.
            // Intentionally ignoring errors: the file may already be gone.
            let _ = std::fs::remove_file(&socket_path);
            info!("Key listener shut down, socket cleaned up");
        });
    }

    /// Deserialize the key service message format
    #[cfg(feature = "unix-client")]
    fn deserialize_key_service_message(data: &[u8]) -> Result<KeyUpdate, String> {
        // Try to deserialize directly since the formats should match now
        match bincode::deserialize::<KeyUpdate>(data) {
            Ok(key_update) => {
                debug!("📋 PARSED KEY SERVICE: Successfully deserialized KeyUpdate");
                Ok(key_update)
            }
            Err(e) => Err(format!("Failed to deserialize KeyUpdate: {e}")),
        }
    }

    #[cfg(feature = "unix-client")]
    async fn handle_key_connection(
        stream: UnixStream,
        cache: Arc<KeyCache>,
    ) -> Result<(), EncryptionError> {
        debug!("New unix socket connection established for key updates");

        // Use length-delimited framing for reliable message boundaries
        let mut framed = FramedRead::new(stream, LengthDelimitedCodec::new());

        while let Some(result) = framed.next().await {
            match result {
                Ok(bytes) => {
                    debug!("Received {} bytes on unix socket (framed)", bytes.len());
                    // Key material is intentionally not logged

                    // Try to deserialize the key service bincode format
                    match Self::deserialize_key_service_message(&bytes) {
                        Ok(key_update) => {
                            debug!("Successfully deserialized KeyUpdate message");
                            match key_update {
                                KeyUpdate::NewKey(mut key) => {
                                    debug!(
                                        "Received new encryption key '{}' ({} bytes) for slot {}",
                                        key.id,
                                        key.key_data.len(),
                                        key.slot_number
                                    );

                                    let target_slot = key.slot_number;

                                    // Convert to internal format - take ownership to avoid copy
                                    let key_data = std::mem::take(&mut key.key_data);
                                    let internal_key = InternalKey {
                                        id: std::mem::take(&mut key.id),
                                        material: Arc::new(SecretBox::new(Box::new(key_data))),
                                    };

                                    cache.add_key(target_slot, internal_key);
                                }
                            }
                        }
                        Err(e) => {
                            // Log error but continue processing
                            error!(
                                "❌ Failed to deserialize KeyUpdate message from {} bytes: {}",
                                bytes.len(),
                                e
                            );
                            // Key material is intentionally not logged — only length and error
                            // Continue to next message instead of returning error
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // Transport-level error - break the connection
                    error!("❌ Frame read error on unix socket: {}", e);
                    return Err(EncryptionError::EncryptionFailed(format!(
                        "Frame read error: {e}"
                    )));
                }
            }
        }

        info!("Unix socket connection closed by client");
        debug!("Unix socket key connection handler exiting");
        Ok(())
    }

    /// Debug method to show key status
    pub fn debug_key_status(&self) {
        let queue = self.key_cache.key_queue.read();

        if queue.is_empty() {
            warn!("🔍 KEY STATUS: No keys available");
        } else {
            debug!("Key status: {} keys in queue", queue.len());

            // Show current (newest) key
            if let Some((slot, key)) = queue.back() {
                debug!("Current key: slot {} -> key '{}'", slot, key.id);
            }

            // Show keys in queue (oldest first)
            let display_count = queue.len().min(5);
            debug!("Queue (oldest first):");
            for (slot, key) in queue.iter().take(display_count) {
                debug!("  - Slot {}: key '{}'", slot, key.id);
            }

            if queue.len() > 5 {
                debug!("  ... and {} more keys", queue.len() - 5);
            }
        }
    }

    /// Get the key that would be used for a specific slot (for inspection/debugging)
    /// For actual encryption/decryption, use encrypt_for_slot() or decrypt_with_key_id()
    pub fn get_key_for_slot(&self, slot_number: u64) -> Option<InternalKey> {
        let key = self.key_cache.get_key_for_slot(slot_number);

        if let Some(ref k) = key {
            debug!(
                "🔑 INSPECT: Key '{}' available for slot {}",
                k.id, slot_number
            );
        } else {
            debug!("🔑 INSPECT: No key available for slot {}", slot_number);
        }

        key
    }

    /// Encrypt data for a specific slot.
    /// Returns (encrypted_data, key_id) where key_id identifies which key was used.
    ///
    /// Key selection logic:
    /// 1. Find newest key where key_slot <= batch_slot
    /// 2. Fallback: use the most recent key if all keys have slots > batch_slot
    #[cfg(feature = "aes-encryption")]
    pub fn encrypt_for_slot(
        &self,
        slot_number: u64,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, String), EncryptionError> {
        let key = self
            .key_cache
            .get_key_for_slot(slot_number)
            .ok_or_else(|| {
                EncryptionError::InvalidKeyFormat("No encryption key available".into())
            })?;

        tracing::debug!(
            "Encrypting {} bytes for slot {} with key '{}'",
            plaintext.len(),
            slot_number,
            key.id
        );

        let encrypted = self.encrypt_with_key(key.material.expose_secret(), plaintext)?;
        Ok((encrypted, key.id))
    }

    /// Decrypt data using the specific key ID that was used for encryption.
    /// Falls back to trying all keys if the specified key is not found or fails.
    ///
    /// Automatically prunes old keys after successful decryption, keeping KEY_PRUNE_BUFFER_SIZE
    /// keys as a buffer before the used key.
    #[cfg(feature = "aes-encryption")]
    pub fn decrypt_with_key_id(
        &self,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        // Primary: try the exact key by ID
        if let Some(key) = self.key_cache.get_key_by_id(key_id) {
            match self.decrypt_with_key(key.material.expose_secret(), ciphertext) {
                Ok(plaintext) => {
                    tracing::debug!(
                        "🔓 DECRYPT: Successfully decrypted with key '{}' ({} bytes)",
                        key_id,
                        ciphertext.len()
                    );

                    // Prune old keys, keeping buffer
                    self.key_cache
                        .prune_keys_before_id(key_id, KEY_PRUNE_BUFFER_SIZE);

                    return Ok(plaintext);
                }
                Err(e) => {
                    tracing::warn!(
                        "🔓 Key '{}' found but decryption failed: {}, trying fallback",
                        key_id,
                        e
                    );
                }
            }
        } else {
            tracing::warn!("🔓 Key '{}' not found, trying fallback", key_id);
        }

        // Fallback: brute force try all keys, newest first
        tracing::warn!("🔓 DECRYPT FALLBACK: Trying all available keys");

        let queue = self.key_cache.key_queue.read();
        for (_, key) in queue.iter().rev() {
            if let Ok(plaintext) = self.decrypt_with_key(key.material.expose_secret(), ciphertext) {
                let used_key_id = key.id.clone();
                drop(queue); // Release read lock before pruning

                tracing::warn!("Decryption fallback succeeded with key '{}'", used_key_id);

                // Prune old keys, keeping buffer
                self.key_cache
                    .prune_keys_before_id(&used_key_id, KEY_PRUNE_BUFFER_SIZE);

                return Ok(plaintext);
            }
        }
        drop(queue);

        Err(EncryptionError::DecryptionFailed(
            "No available key could decrypt the data".into(),
        ))
    }

    /// Get a key by its ID (for inspection/debugging)
    pub fn get_key_by_id(&self, key_id: &str) -> Option<InternalKey> {
        self.key_cache.get_key_by_id(key_id)
    }
}

#[cfg(test)]
#[cfg(feature = "aes-encryption")]
mod tests {
    use super::*;

    use secrecy::SecretBox;
    use std::sync::Arc;

    /// Helper: create an InternalKey from raw bytes with a given id.
    fn make_internal_key(id: &str, key_bytes: Vec<u8>) -> InternalKey {
        InternalKey {
            id: id.to_string(),
            material: Arc::new(SecretBox::new(Box::new(key_bytes))),
        }
    }

    /// Helper: create a valid 32-byte test key from a seed byte.
    /// Produces an asymmetric byte pattern to catch endianness bugs.
    fn make_test_key_bytes(seed: u8) -> Vec<u8> {
        (0u8..32)
            .map(|i| i.wrapping_add(seed).wrapping_mul(7).wrapping_add(3))
            .collect()
    }

    /// Helper: create an EncryptionLayer with a single key pre-loaded.
    fn make_layer_with_key(key_id: &str, key_bytes: Vec<u8>) -> EncryptionLayer {
        let cache = Arc::new(KeyCache::new());
        let internal_key = make_internal_key(key_id, key_bytes);
        cache.add_key(0, internal_key);
        EncryptionLayer { key_cache: cache }
    }

    // ===== Encryption/Decryption tests =====

    #[test]
    fn test_round_trip_encrypt_decrypt() {
        let key_bytes = make_test_key_bytes(0xAB);
        let layer = make_layer_with_key("test-key", key_bytes.clone());

        let plaintext = b"Hello, sovereign encryption layer!";
        let encrypted = layer.encrypt_with_key(&key_bytes, plaintext).unwrap();
        let decrypted = layer.decrypt_with_key(&key_bytes, &encrypted).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Decrypted plaintext should match original"
        );
    }

    #[test]
    fn test_wrong_key_fails() {
        let key_a = make_test_key_bytes(0x01);
        let key_b = make_test_key_bytes(0x02);
        let layer = make_layer_with_key("key-a", key_a.clone());

        let plaintext = b"secret data for key A only";
        let encrypted = layer.encrypt_with_key(&key_a, plaintext).unwrap();
        let result = layer.decrypt_with_key(&key_b, &encrypted);

        assert!(
            result.is_err(),
            "Decryption with a different key should fail"
        );
    }

    #[test]
    fn test_corrupted_ciphertext_detected() {
        let key_bytes = make_test_key_bytes(0xCC);
        let layer = make_layer_with_key("test-key", key_bytes.clone());

        let plaintext = b"data that will be tampered with";
        let mut encrypted = layer.encrypt_with_key(&key_bytes, plaintext).unwrap();

        // Flip a byte in the ciphertext portion (after the 12-byte nonce)
        let tamper_index = AES_GCM_NONCE_SIZE + 1;
        encrypted[tamper_index] ^= 0xFF;

        let result = layer.decrypt_with_key(&key_bytes, &encrypted);
        assert!(
            result.is_err(),
            "Decryption of corrupted ciphertext should fail due to authentication tag mismatch"
        );
    }

    #[test]
    fn test_truncated_ciphertext_rejected() {
        let key_bytes = make_test_key_bytes(0xDD);
        let layer = make_layer_with_key("test-key", key_bytes.clone());

        // Minimum valid ciphertext length is AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE = 28 bytes.
        // Pass something shorter.
        let short_ciphertext = vec![0u8; 27];
        let result = layer.decrypt_with_key(&key_bytes, &short_ciphertext);

        assert!(result.is_err(), "Truncated ciphertext should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, EncryptionError::InvalidCiphertextFormat(_)),
            "Error should be InvalidCiphertextFormat, got: {err:?}"
        );
    }

    #[test]
    fn test_empty_plaintext_round_trip() {
        let key_bytes = make_test_key_bytes(0xEE);
        let layer = make_layer_with_key("test-key", key_bytes.clone());

        let plaintext: &[u8] = b"";
        let encrypted = layer.encrypt_with_key(&key_bytes, plaintext).unwrap();
        let decrypted = layer.decrypt_with_key(&key_bytes, &encrypted).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Empty plaintext should round-trip correctly"
        );
    }

    #[test]
    fn test_large_plaintext_round_trip() {
        let key_bytes = make_test_key_bytes(0xFF);
        let layer = make_layer_with_key("test-key", key_bytes.clone());

        // 1 MB of data with a recognizable pattern
        let plaintext: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();

        let encrypted = layer.encrypt_with_key(&key_bytes, &plaintext).unwrap();
        let decrypted = layer.decrypt_with_key(&key_bytes, &encrypted).unwrap();

        assert_eq!(
            decrypted, plaintext,
            "Large plaintext (1 MB) should round-trip correctly"
        );
    }

    // ===== KeyCache tests =====

    #[test]
    fn test_key_cache_add_and_get_by_id() {
        let cache = KeyCache::new();
        let key = make_internal_key("key-alpha", make_test_key_bytes(0x10));
        cache.add_key(500, key);

        let retrieved = cache.get_key_by_id("key-alpha");
        assert!(retrieved.is_some(), "Key should be retrievable by its id");
        assert_eq!(retrieved.unwrap().id, "key-alpha");

        let missing = cache.get_key_by_id("nonexistent");
        assert!(missing.is_none(), "Nonexistent key id should return None");
    }

    #[test]
    fn test_key_cache_get_for_slot() {
        let cache = KeyCache::new();
        // Add keys at different slots: key-1 at slot 100, key-2 at slot 300, key-3 at slot 500
        cache.add_key(100, make_internal_key("key-1", make_test_key_bytes(0x01)));
        cache.add_key(300, make_internal_key("key-2", make_test_key_bytes(0x02)));
        cache.add_key(500, make_internal_key("key-3", make_test_key_bytes(0x03)));

        // Slot 400 should get key-2 (newest key where slot <= 400)
        let key = cache.get_key_for_slot(400).unwrap();
        assert_eq!(
            key.id, "key-2",
            "Slot 400 should select key-2 (slot 300 <= 400, and it is the newest such key)"
        );

        // Slot 600 should get key-3 (newest key where slot <= 600)
        let key = cache.get_key_for_slot(600).unwrap();
        assert_eq!(
            key.id, "key-3",
            "Slot 600 should select key-3 (slot 500 <= 600)"
        );

        // Slot 100 should get key-1 (newest key where slot <= 100)
        let key = cache.get_key_for_slot(100).unwrap();
        assert_eq!(
            key.id, "key-1",
            "Slot 100 should select key-1 (slot 100 <= 100)"
        );

        // Slot 250 should get key-1 (newest key where slot <= 250)
        let key = cache.get_key_for_slot(250).unwrap();
        assert_eq!(
            key.id, "key-1",
            "Slot 250 should select key-1 (slot 100 <= 250, key-2 has slot 300 > 250)"
        );
    }

    #[test]
    fn test_key_cache_get_for_slot_fallback() {
        let cache = KeyCache::new();
        // All keys have slots greater than the requested slot
        cache.add_key(
            1000,
            make_internal_key("key-future-1", make_test_key_bytes(0x11)),
        );
        cache.add_key(
            2000,
            make_internal_key("key-future-2", make_test_key_bytes(0x12)),
        );

        // Request slot 500 — all keys have slot > 500, so fallback to the most recent (back of queue)
        let key = cache.get_key_for_slot(500).unwrap();
        assert_eq!(
            key.id, "key-future-2",
            "When all keys have slots > requested, should fallback to the most recent key"
        );
    }

    #[test]
    fn test_key_cache_prune() {
        let cache = KeyCache::new();
        // Add keys: A, B, C, D, E
        cache.add_key(100, make_internal_key("A", make_test_key_bytes(0x01)));
        cache.add_key(200, make_internal_key("B", make_test_key_bytes(0x02)));
        cache.add_key(300, make_internal_key("C", make_test_key_bytes(0x03)));
        cache.add_key(400, make_internal_key("D", make_test_key_bytes(0x04)));
        cache.add_key(500, make_internal_key("E", make_test_key_bytes(0x05)));

        assert_eq!(cache.len(), 5, "Should start with 5 keys");

        // Prune before "D" with buffer_size=2
        // Position of D is 3. remove_count = 3 - 2 = 1, so remove A.
        // Remaining: [B, C, D, E]
        cache.prune_keys_before_id("D", 2);
        assert_eq!(
            cache.len(),
            4,
            "After pruning at D with buffer=2, should have 4 keys"
        );

        // A should be gone
        assert!(
            cache.get_key_by_id("A").is_none(),
            "Key A should have been pruned"
        );
        // B, C, D, E should remain
        assert!(
            cache.get_key_by_id("B").is_some(),
            "Key B should be retained as buffer"
        );
        assert!(
            cache.get_key_by_id("C").is_some(),
            "Key C should be retained as buffer"
        );
        assert!(
            cache.get_key_by_id("D").is_some(),
            "Key D should still exist"
        );
        assert!(
            cache.get_key_by_id("E").is_some(),
            "Key E should still exist"
        );
    }

    #[test]
    fn test_key_cache_empty() {
        let cache = KeyCache::new();

        assert!(
            cache.get_key_for_slot(100).is_none(),
            "Empty cache should return None for get_key_for_slot"
        );
        assert!(
            cache.get_key_by_id("any").is_none(),
            "Empty cache should return None for get_key_by_id"
        );
        assert!(cache.is_empty(), "New cache should be empty");
        assert_eq!(cache.len(), 0, "New cache should have length 0");
    }

    // ===== Static key validation tests =====

    #[tokio::test]
    async fn test_static_key_wrong_length() {
        // 16 bytes (32 hex chars) instead of 32 bytes (64 hex chars)
        let short_key_hex = "0123456789abcdef0123456789abcdef"; // 16 bytes
        let config = KeyClientConfig::Static {
            encryption_key: short_key_hex.to_string(),
        };
        let result = EncryptionLayer::new(config, None).await;

        match result {
            Err(EncryptionError::InvalidKeyFormat(msg)) => {
                assert!(
                    msg.contains("32 bytes"),
                    "Error message should mention expected key size, got: {msg}"
                );
            }
            Err(other) => panic!("Expected InvalidKeyFormat error, got: {other:?}"),
            Ok(_) => panic!("Key shorter than 32 bytes should be rejected"),
        }
    }

    #[tokio::test]
    async fn test_static_key_all_zeros_rejected() {
        // 32 bytes of zeros = 64 hex zero chars
        let zeros_hex = "0".repeat(64);
        let config = KeyClientConfig::Static {
            encryption_key: zeros_hex,
        };
        let result = EncryptionLayer::new(config, None).await;

        match result {
            Err(EncryptionError::InvalidKeyFormat(msg)) => {
                assert!(
                    msg.contains("all zeros"),
                    "Error message should mention all-zeros rejection, got: {msg}"
                );
            }
            Err(other) => panic!("Expected InvalidKeyFormat error, got: {other:?}"),
            Ok(_) => panic!("All-zeros key should be rejected"),
        }
    }

    #[tokio::test]
    async fn test_static_key_invalid_hex() {
        // "zz" is not valid hex
        let bad_hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let config = KeyClientConfig::Static {
            encryption_key: bad_hex.to_string(),
        };
        let result = EncryptionLayer::new(config, None).await;

        match result {
            Err(EncryptionError::InvalidKeyFormat(msg)) => {
                assert!(
                    msg.contains("hex"),
                    "Error message should mention hex decoding failure, got: {msg}"
                );
            }
            Err(other) => panic!("Expected InvalidKeyFormat error, got: {other:?}"),
            Ok(_) => panic!("Non-hex string should be rejected"),
        }
    }

    #[tokio::test]
    async fn test_static_key_valid() {
        // Generate a valid 32-byte key as hex (asymmetric pattern)
        let key_bytes = make_test_key_bytes(0x42);
        let key_hex = hex::encode(&key_bytes);

        let config = KeyClientConfig::Static {
            encryption_key: key_hex,
        };
        let result = EncryptionLayer::new(config, None).await;

        assert!(
            result.is_ok(),
            "Valid 32-byte hex key should succeed, got error: {:?}",
            result.err()
        );
    }

    // ===== encrypt_for_slot / decrypt_with_key_id tests =====

    #[tokio::test]
    async fn test_encrypt_for_slot_and_decrypt_with_key_id() {
        let key_bytes = make_test_key_bytes(0x42);
        let key_hex = hex::encode(&key_bytes);

        let config = KeyClientConfig::Static {
            encryption_key: key_hex,
        };
        let layer = EncryptionLayer::new(config, None).await.unwrap();

        let plaintext = b"round trip through the public API with slot 1234";
        let slot_number = 1234u64;

        let (encrypted, key_id) = layer.encrypt_for_slot(slot_number, plaintext).unwrap();
        assert_eq!(
            key_id, "static-key",
            "Static config should use key id 'static-key'"
        );

        let decrypted = layer.decrypt_with_key_id(&key_id, &encrypted).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "Decrypted data should match original plaintext"
        );
    }

    #[tokio::test]
    async fn test_decrypt_with_key_id_fallback() {
        // Create layer with first key
        let key_bytes_1 = make_test_key_bytes(0xA1);
        let cache = Arc::new(KeyCache::new());
        let key_1 = make_internal_key("key-1", key_bytes_1.clone());
        cache.add_key(0, key_1);

        let layer = EncryptionLayer {
            key_cache: cache.clone(),
        };

        // Encrypt with key-1
        let plaintext = b"data encrypted with key-1 before key-2 exists";
        let (encrypted, key_id) = layer.encrypt_for_slot(500, plaintext).unwrap();
        assert_eq!(key_id, "key-1");

        // Add a second key
        let key_bytes_2 = make_test_key_bytes(0xB2);
        let key_2 = make_internal_key("key-2", key_bytes_2);
        cache.add_key(1000, key_2);

        // Decrypt using the original key-1 id — should still work by exact id match
        let decrypted = layer.decrypt_with_key_id("key-1", &encrypted).unwrap();
        assert_eq!(
            decrypted, plaintext,
            "Decryption should succeed using the original key id even after a new key was added"
        );
    }
}
