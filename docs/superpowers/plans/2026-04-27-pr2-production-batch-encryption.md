# PR #2 Production Batch Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring PR #2 to a production-ready native full-node feature that encrypts preferred sequencer transaction batches with one configured static AES-256-GCM key, while preserving a small provider boundary for future KMS integration.

**Architecture:** Keep encryption at the preferred-batch boundary: `PreferredBlobSender` encrypts serialized transaction vectors before DA submission, and blob storage decrypts them in the native STF path before normal batch selection/execution. Replace the current socket/key-queue/key-id design with a focused `sov-encryption` crate containing static-key config, a key-provider trait, AES-GCM helpers, redacted key handling, and tests. ZK/prover support remains out of scope; guest STFs keep no encryption layer.

**Tech Stack:** Rust, Borsh, Serde, Schemars, AES-256-GCM via `aes-gcm`, `secrecy` for key material, `cargo nextest`, Sovereign SDK native full-node components.

---

## File Structure

Create:

- `crates/utils/sov-encryption/src/key_provider.rs`  
  Owns `BatchEncryptionKey`, `BatchEncryptionKeyProvider`, and `StaticKeyProvider`.

Modify:

- `crates/utils/sov-encryption/src/config.rs`  
  Replace `KeyClientConfig` with `BatchEncryptionConfig`.
- `crates/utils/sov-encryption/src/layer.rs`  
  Replace queue/socket/key-id logic with single-key encrypt/decrypt.
- `crates/utils/sov-encryption/src/error.rs`  
  Keep focused errors for config, key format, encryption, decryption, and ciphertext format.
- `crates/utils/sov-encryption/src/lib.rs`  
  Export the new provider/config/layer API.
- `crates/utils/sov-encryption/Cargo.toml`  
  Remove socket/rotation dependencies and keep static-key crypto dependencies.
- `Cargo.toml`  
  Keep workspace registration for `sov-encryption`.
- `crates/full-node/full-node-configs/src/runner.rs`  
  Add one root rollup config field for batch encryption.
- `crates/full-node/full-node-configs/src/sequencer.rs`  
  Remove `batch_encryption` from sequencer config.
- `crates/full-node/full-node-configs/Cargo.toml`  
  Depend on `sov-encryption` without Unix socket features.
- `crates/full-node/full-node-configs/src/snapshots/*.snap`  
  Update config snapshots.
- `crates/module-system/module-implementations/sov-blob-storage/src/lib.rs`  
  Replace `encryption_key_id` with `encryption_format_version`.
- `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`  
  Decrypt with the configured single key and route failures through malformed preferred blob handling.
- `crates/module-system/module-implementations/sov-blob-storage/Cargo.toml`  
  Depend on `sov-encryption` without Unix socket features.
- `crates/module-system/sov-modules-stf-blueprint/src/stf_blueprint.rs`  
  Keep optional encryption layer for native STF construction.
- `crates/module-system/sov-modules-stf-blueprint/src/lib.rs`  
  Thread the encryption layer through blob selection while preserving current upstream STF API changes.
- `crates/module-system/sov-modules-stf-blueprint/Cargo.toml`  
  Keep encryption dependency native-compatible and no-default checks passing.
- `crates/module-system/sov-modules-rollup-blueprint/src/native_only/mod.rs`  
  Create one shared encryption layer from root rollup config.
- `crates/module-system/sov-modules-rollup-blueprint/Cargo.toml`  
  Ensure `sov-encryption` is only enabled for native rollup blueprint usage.
- `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`  
  Encrypt with the simplified layer and serialize the encrypted batch wrapper.
- `crates/full-node/sov-sequencer/src/preferred/initialization.rs`  
  Resolve upstream merge conflict, preserve signer checks and new DB cache APIs, and pass the encryption layer into blob sender.
- `crates/full-node/sov-sequencer/src/preferred/mod.rs`  
  Keep `PreferredSequencer::create` accepting the shared encryption layer.
- `crates/full-node/sov-sequencer/Cargo.toml`  
  Depend on `sov-encryption` without Unix socket features.
- `examples/demo-rollup/configs/mock_rollup_config.toml`  
  Add a commented static-key example.
- `examples/demo-rollup/configs/celestia_rollup_config.toml`  
  Add a commented static-key example.
- `docs/superpowers/specs/2026-04-27-pr2-production-batch-encryption-design.md`  
  Reference the final plan during implementation review.

Test:

- `crates/utils/sov-encryption/src/layer.rs`
- `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`
- `crates/full-node/full-node-configs/src/runner.rs`
- `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`
- `crates/full-node/sov-sequencer/tests/integration/preferred_blob_sender.rs`

---

### Task 1: Create an Implementation Branch and Reconcile Current `dev-sync`

**Files:**

- Modify: `.github/workflows/rust.yml.disabled`
- Modify: `Cargo.lock`
- Modify: `crates/full-node/sov-sequencer/src/preferred/initialization.rs`
- Modify: `crates/module-system/sov-modules-stf-blueprint/src/lib.rs`
- Modify: `examples/demo-rollup/provers/risc0/guest-celestia/Cargo.lock`
- Modify: `examples/demo-rollup/provers/sp1/guest-celestia/Cargo.lock`
- Modify: `examples/demo-rollup/provers/sp1/guest-mock/Cargo.lock`

- [ ] **Step 1: Create the implementation branch from the PR head**

```bash
git fetch origin --prune
git switch -c codex/pr2-production-batch-encryption origin/tyson/encrypt-txs
```

Expected: branch `codex/pr2-production-batch-encryption` exists at `origin/tyson/encrypt-txs`.

- [ ] **Step 2: Merge current `dev-sync` and capture conflicts**

```bash
git merge --no-commit --no-ff origin/dev-sync
```

Expected: merge stops with conflicts in:

```text
.github/workflows/rust.yml.disabled
Cargo.lock
crates/full-node/sov-sequencer/src/preferred/initialization.rs
crates/module-system/sov-modules-stf-blueprint/src/lib.rs
examples/demo-rollup/provers/risc0/guest-celestia/Cargo.lock
examples/demo-rollup/provers/sp1/guest-celestia/Cargo.lock
examples/demo-rollup/provers/sp1/guest-mock/Cargo.lock
```

- [ ] **Step 3: Resolve workflow conflict by taking current `dev-sync` workflow state**

```bash
git checkout --theirs .github/workflows/rust.yml.disabled
git add .github/workflows/rust.yml.disabled
```

Expected: workflow conflict is resolved. The production feature does not need PR-specific workflow hacks from the old branch.

- [ ] **Step 4: Resolve `initialization.rs` by preserving both upstream logic and encryption plumbing**

In `crates/full-node/sov-sequencer/src/preferred/initialization.rs`, keep the upstream import:

```rust
use sov_modules_api::capabilities::SequencerRemuneration;
```

and add the encryption import:

```rust
use sov_encryption::EncryptionLayer;
```

Keep the builder signature with the encryption argument immediately before `bind_addr`:

```rust
pub async fn build(
    self,
    state_update_receiver: StateUpdateReceiver<S::Storage>,
    storage_path: &Path,
    ledger_db: LedgerDb,
    api_ledger_db: LedgerDb,
    shutdown_sender: watch::Sender<()>,
    stop_at_rollup_height: Option<RollupHeight>,
    shared_encryption_layer: Option<EncryptionLayer>,
    bind_addr: SocketAddr,
) -> Result<(PreferredSequencer<S, Rt, Da>, Vec<JoinHandle<()>>)> {
```

Preserve the upstream DA signer check after `da_address` is obtained:

```rust
Self::check_runtime_address_match(&latest_state_update, da_address)?;
```

Preserve the upstream completed-blob cache API and add the encryption argument to `PreferredBlobSender::new`:

```rust
let (blob_sender, blob_sender_handle) = PreferredBlobSender::new(
    self.da,
    ledger_db.clone(),
    db_cache.all_proofs_and_completed_blobs().clone(),
    storage_path.into(),
    tx_status_manager.clone(),
    shutdown_sender.clone(),
    Duration::from_secs(config.blob_processing_timeout_secs),
    blobs_sender_channel.clone(),
    seq_role,
    shared_encryption_layer,
)
.await?;
```

- [ ] **Step 5: Resolve `sov-modules-stf-blueprint/src/lib.rs` by preserving upstream STF generic changes**

In `crates/module-system/sov-modules-stf-blueprint/src/lib.rs`, keep the upstream `ApplySlotOutput` type:

```rust
ApplySlotOutput::<S::Da, Self> {
    state_root,
    change_set,
    proof_receipts,
    batch_receipts,
    discarded_blobs,
    witness,
    rollup_height,
}
```

Also keep the upstream block gas limit logic:

```rust
let block_gas_limit = runtime
    .chain_state()
    .block_gas_limit(state.rollup_height_to_access(), !creates_rollup_block);
```

Keep the PR's encryption threading where `get_blobs_for_this_slot` is called:

```rust
let blob_selector_output = self.get_blobs_for_this_slot(
    &mut runtime,
    relevant_blobs,
    &mut kernel,
    cf,
    self.encryption_layer.as_ref(),
);
```

- [ ] **Step 6: Resolve lockfiles by regenerating after code conflicts are resolved**

```bash
cargo generate-lockfile
```

Expected: no conflict markers remain in `Cargo.lock` or guest lockfiles. If guest lockfiles still contain conflict markers, run:

```bash
cargo generate-lockfile --manifest-path examples/demo-rollup/provers/risc0/guest-celestia/Cargo.toml
cargo generate-lockfile --manifest-path examples/demo-rollup/provers/sp1/guest-celestia/Cargo.toml
cargo generate-lockfile --manifest-path examples/demo-rollup/provers/sp1/guest-mock/Cargo.toml
```

- [ ] **Step 7: Verify merge conflict cleanup**

```bash
rg -n '<<<<<<<|=======|>>>>>>>' .
```

Expected: no output.

- [ ] **Step 8: Run a compile smoke check**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-sequencer -p sov-blob-storage -p sov-modules-stf-blueprint --all-features
```

Expected: command exits 0.

- [ ] **Step 9: Commit the conflict resolution**

```bash
git add .github/workflows/rust.yml.disabled Cargo.lock \
  crates/full-node/sov-sequencer/src/preferred/initialization.rs \
  crates/module-system/sov-modules-stf-blueprint/src/lib.rs \
  examples/demo-rollup/provers/risc0/guest-celestia/Cargo.lock \
  examples/demo-rollup/provers/sp1/guest-celestia/Cargo.lock \
  examples/demo-rollup/provers/sp1/guest-mock/Cargo.lock
git commit -m "chore: merge dev-sync into encryption branch"
```

---

### Task 2: Replace Socket/Queue Config With Static Provider Config

**Files:**

- Modify: `crates/utils/sov-encryption/src/config.rs`
- Create: `crates/utils/sov-encryption/src/key_provider.rs`
- Modify: `crates/utils/sov-encryption/src/lib.rs`
- Modify: `crates/utils/sov-encryption/Cargo.toml`
- Test: `crates/utils/sov-encryption/src/key_provider.rs`

- [ ] **Step 1: Add failing static key provider tests**

Create `crates/utils/sov-encryption/src/key_provider.rs` with this test module first, putting minimal production stubs below the tests so this file compiles far enough to expose the expected failures:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn valid_key_hex() -> String {
        (0u8..32).map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn accepts_valid_static_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        assert_eq!(key.expose_for_crypto().len(), 32);
    }

    #[test]
    fn rejects_invalid_hex() {
        let err = BatchEncryptionKey::from_hex("not-hex").unwrap_err();
        assert!(err.to_string().contains("Invalid hex"));
    }

    #[test]
    fn rejects_short_key() {
        let err = BatchEncryptionKey::from_hex("abcd").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn rejects_all_zero_key() {
        let err = BatchEncryptionKey::from_hex(&"00".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("all zeros"));
    }

    #[test]
    fn debug_redacts_key_material() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&valid_key_hex()));
    }

    #[test]
    fn static_provider_returns_active_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        let provider = StaticKeyProvider::new(key.clone());
        assert_eq!(provider.active_key().expose_for_crypto(), key.expose_for_crypto());
    }
}
```

- [ ] **Step 2: Run the tests and verify they fail before implementation**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption key_provider
```

Expected: FAIL because `BatchEncryptionKey` and `StaticKeyProvider` are not fully implemented.

- [ ] **Step 3: Replace `config.rs` with the static config enum**

Replace `crates/utils/sov-encryption/src/config.rs` with:

```rust
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BatchEncryptionConfig {
    /// Static key configuration. The key is a hex-encoded 32-byte AES-256-GCM key.
    Static {
        /// Hex-encoded AES-256-GCM encryption key.
        encryption_key: String,
    },
}

impl std::fmt::Debug for BatchEncryptionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchEncryptionConfig::Static { .. } => f
                .debug_struct("Static")
                .field("encryption_key", &"[REDACTED]")
                .finish(),
        }
    }
}
```

- [ ] **Step 4: Implement `key_provider.rs`**

Replace `crates/utils/sov-encryption/src/key_provider.rs` with:

```rust
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretBox};

use crate::error::EncryptionError;

const AES_256_KEY_SIZE: usize = 32;

#[derive(Clone)]
pub struct BatchEncryptionKey {
    material: Arc<SecretBox<Vec<u8>>>,
}

impl BatchEncryptionKey {
    pub fn from_hex(key_hex: &str) -> Result<Self, EncryptionError> {
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| EncryptionError::InvalidKeyFormat(format!("Invalid hex key: {e}")))?;

        if key_bytes.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Static encryption key must be {AES_256_KEY_SIZE} bytes, got {}",
                key_bytes.len()
            )));
        }

        if key_bytes.iter().all(|byte| *byte == 0) {
            return Err(EncryptionError::InvalidKeyFormat(
                "Static encryption key must not be all zeros".to_string(),
            ));
        }

        Ok(Self {
            material: Arc::new(SecretBox::new(Box::new(key_bytes))),
        })
    }

    pub(crate) fn expose_for_crypto(&self) -> &[u8] {
        self.material.expose_secret()
    }
}

impl std::fmt::Debug for BatchEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchEncryptionKey")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

pub trait BatchEncryptionKeyProvider: Send + Sync + std::fmt::Debug {
    fn active_key(&self) -> BatchEncryptionKey;
}

#[derive(Debug, Clone)]
pub struct StaticKeyProvider {
    key: BatchEncryptionKey,
}

impl StaticKeyProvider {
    pub fn new(key: BatchEncryptionKey) -> Self {
        Self { key }
    }
}

impl BatchEncryptionKeyProvider for StaticKeyProvider {
    fn active_key(&self) -> BatchEncryptionKey {
        self.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_key_hex() -> String {
        (0u8..32).map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn accepts_valid_static_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        assert_eq!(key.expose_for_crypto().len(), 32);
    }

    #[test]
    fn rejects_invalid_hex() {
        let err = BatchEncryptionKey::from_hex("not-hex").unwrap_err();
        assert!(err.to_string().contains("Invalid hex"));
    }

    #[test]
    fn rejects_short_key() {
        let err = BatchEncryptionKey::from_hex("abcd").unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn rejects_all_zero_key() {
        let err = BatchEncryptionKey::from_hex(&"00".repeat(32)).unwrap_err();
        assert!(err.to_string().contains("all zeros"));
    }

    #[test]
    fn debug_redacts_key_material() {
        let key_hex = valid_key_hex();
        let key = BatchEncryptionKey::from_hex(&key_hex).unwrap();
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&key_hex));
    }

    #[test]
    fn static_provider_returns_active_key() {
        let key = BatchEncryptionKey::from_hex(&valid_key_hex()).unwrap();
        let provider = StaticKeyProvider::new(key.clone());
        assert_eq!(provider.active_key().expose_for_crypto(), key.expose_for_crypto());
    }
}
```

- [ ] **Step 5: Export the provider API**

Update `crates/utils/sov-encryption/src/lib.rs`:

```rust
pub mod config;
pub mod error;
pub mod key_provider;
pub mod layer;

pub use config::*;
pub use error::*;
pub use key_provider::*;
pub use layer::*;
```

- [ ] **Step 6: Remove socket-only dependencies and features**

Update `crates/utils/sov-encryption/Cargo.toml` so the dependency section is:

```toml
[features]
default = ["aes-encryption"]
aes-encryption = ["aes-gcm", "rand"]

[dependencies]
aes-gcm = { version = "0.10", default-features = false, features = ["aes", "alloc", "getrandom"], optional = true }
rand = { workspace = true, optional = true }
serde = { workspace = true, features = ["derive"] }
serde_json = { workspace = true }
hex = { workspace = true }
thiserror = { workspace = true }
anyhow = { workspace = true }
schemars = { workspace = true, features = ["derive"] }
tracing = { workspace = true }
secrecy = { version = "0.10", features = ["serde"] }

[dev-dependencies]
tempfile = { workspace = true }
```

Remove `tokio`, `tokio-util`, `futures`, `async-trait`, `bincode`, `bytes`, `parking_lot`, and `chrono` from `sov-encryption` unless another retained code path still uses them after Task 3.

- [ ] **Step 7: Run provider tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption key_provider
```

Expected: provider tests pass.

- [ ] **Step 8: Commit the provider/config boundary**

```bash
git add crates/utils/sov-encryption/src/config.rs \
  crates/utils/sov-encryption/src/key_provider.rs \
  crates/utils/sov-encryption/src/lib.rs \
  crates/utils/sov-encryption/Cargo.toml Cargo.lock
git commit -m "refactor: add static batch encryption provider"
```

---

### Task 3: Simplify `EncryptionLayer` to Single-Key AES-GCM

**Files:**

- Modify: `crates/utils/sov-encryption/src/layer.rs`
- Modify: `crates/utils/sov-encryption/src/error.rs`
- Test: `crates/utils/sov-encryption/src/layer.rs`

- [ ] **Step 1: Replace layer tests with single-key behavior tests**

In `crates/utils/sov-encryption/src/layer.rs`, keep or add tests covering:

```rust
#[cfg(test)]
#[cfg(feature = "aes-encryption")]
mod tests {
    use super::*;
    use crate::BatchEncryptionConfig;

    fn valid_config() -> BatchEncryptionConfig {
        BatchEncryptionConfig::Static {
            encryption_key: (1u8..=32).map(|b| format!("{b:02x}")).collect(),
        }
    }

    fn other_config() -> BatchEncryptionConfig {
        BatchEncryptionConfig::Static {
            encryption_key: (33u8..=64).map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let plaintext = b"preferred batch bytes";
        let encrypted = layer.encrypt(plaintext).unwrap();
        assert_ne!(encrypted, plaintext);
        let decrypted = layer.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_uses_random_nonce() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let plaintext = b"same plaintext";
        let first = layer.encrypt(plaintext).unwrap();
        let second = layer.encrypt(plaintext).unwrap();
        assert_ne!(first, second);
        assert_eq!(layer.decrypt(&first).unwrap(), plaintext);
        assert_eq!(layer.decrypt(&second).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let other_layer = EncryptionLayer::from_config(other_config()).unwrap();
        let encrypted = layer.encrypt(b"secret").unwrap();
        let err = other_layer.decrypt(&encrypted).unwrap_err();
        assert!(err.to_string().contains("AES-GCM decryption failed"));
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let err = layer.decrypt(&[1, 2, 3]).unwrap_err();
        assert!(err.to_string().contains("Ciphertext too short"));
    }

    #[test]
    fn corrupted_ciphertext_is_rejected() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let mut encrypted = layer.encrypt(b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xff;
        assert!(layer.decrypt(&encrypted).is_err());
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let layer = EncryptionLayer::from_config(valid_config()).unwrap();
        let encrypted = layer.encrypt(&[]).unwrap();
        assert_eq!(layer.decrypt(&encrypted).unwrap(), b"");
    }
}
```

- [ ] **Step 2: Run the layer tests and verify failures before simplification**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption layer
```

Expected: FAIL while old slot/key-id APIs still exist and `from_config`, `encrypt`, or `decrypt` are missing.

- [ ] **Step 3: Replace `layer.rs` with the simplified layer**

Replace the production implementation in `crates/utils/sov-encryption/src/layer.rs` with:

```rust
use std::sync::Arc;

#[cfg(feature = "aes-encryption")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
#[cfg(feature = "aes-encryption")]
use rand::{rngs::OsRng, RngCore};

use crate::{
    BatchEncryptionConfig, BatchEncryptionKey, BatchEncryptionKeyProvider, EncryptionError,
    StaticKeyProvider,
};

#[cfg(feature = "aes-encryption")]
const AES_256_KEY_SIZE: usize = 32;
#[cfg(feature = "aes-encryption")]
const AES_GCM_NONCE_SIZE: usize = 12;
#[cfg(feature = "aes-encryption")]
const AES_GCM_TAG_SIZE: usize = 16;

#[derive(Clone, Debug)]
pub struct EncryptionLayer {
    key_provider: Arc<dyn BatchEncryptionKeyProvider>,
}

impl EncryptionLayer {
    pub fn from_config(config: BatchEncryptionConfig) -> Result<Self, EncryptionError> {
        match config {
            BatchEncryptionConfig::Static { encryption_key } => {
                let key = BatchEncryptionKey::from_hex(&encryption_key)?;
                Ok(Self::from_provider(StaticKeyProvider::new(key)))
            }
        }
    }

    pub fn from_provider(provider: impl BatchEncryptionKeyProvider + 'static) -> Self {
        Self {
            key_provider: Arc::new(provider),
        }
    }

    #[cfg(feature = "aes-encryption")]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let key = self.key_provider.active_key();
        let key = key.expose_for_crypto();
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {AES_256_KEY_SIZE} byte key, got {}",
                key.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);

        let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|e| {
            EncryptionError::EncryptionFailed(format!("AES-GCM encryption failed: {e}"))
        })?;

        let mut result = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[cfg(feature = "aes-encryption")]
    pub fn decrypt(&self, ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let min_ciphertext_len = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
        if ciphertext_with_nonce.len() < min_ciphertext_len {
            return Err(EncryptionError::InvalidCiphertextFormat(format!(
                "Ciphertext too short: expected at least {min_ciphertext_len} bytes, got {}",
                ciphertext_with_nonce.len()
            )));
        }

        let key = self.key_provider.active_key();
        let key = key.expose_for_crypto();
        if key.len() != AES_256_KEY_SIZE {
            return Err(EncryptionError::InvalidKeyFormat(format!(
                "Expected {AES_256_KEY_SIZE} byte key, got {}",
                key.len()
            )));
        }

        let cipher_key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(cipher_key);
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(AES_GCM_NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext).map_err(|e| {
            EncryptionError::DecryptionFailed(format!("AES-GCM decryption failed: {e}"))
        })
    }
}
```

Then append the tests from Step 1 at the bottom of the file.

- [ ] **Step 4: Keep focused errors**

Replace `crates/utils/sov-encryption/src/error.rs` with:

```rust
#[derive(thiserror::Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertextFormat(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),
}
```

- [ ] **Step 5: Run encryption tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption --all-features
```

Expected: all `sov-encryption` tests pass.

- [ ] **Step 6: Commit simplified encryption layer**

```bash
git add crates/utils/sov-encryption/src/layer.rs crates/utils/sov-encryption/src/error.rs Cargo.lock
git commit -m "refactor: simplify batch encryption layer"
```

---

### Task 4: Normalize Rollup Config to One Root `batch_encryption` Field

**Files:**

- Modify: `crates/full-node/full-node-configs/src/runner.rs`
- Modify: `crates/full-node/full-node-configs/src/sequencer.rs`
- Modify: `crates/full-node/full-node-configs/Cargo.toml`
- Modify: `crates/full-node/full-node-configs/src/snapshots/*.snap`
- Test: `crates/full-node/full-node-configs/src/runner.rs`

- [ ] **Step 1: Add config parsing tests**

In `crates/full-node/full-node-configs/src/runner.rs`, add this test after `test_correct_config`:

```rust
#[test]
fn test_correct_config_with_static_batch_encryption() {
    let config_s = r#"
        [da]
        connection_string = "sqlite:///tmp/mockda.sqlite?mode=rwc"
        sender_address = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
        [da.block_producing.periodic]
        block_time_ms = 1_000
        [storage]
        path = "/tmp"
        [runner]
        da_polling_interval_ms = 10000
        concurrent_sync_tasks = 18
        [runner.http_config]
        bind_host = "127.0.0.1"
        bind_port = 12346
        public_address = "https://rollup.sovereign.xyz"
        cors = "restrictive"
        [monitoring]
        telegraf_address = "udp://192.168.4.5:8543"
        max_datagram_size = 1024
        max_pending_metrics = 2560
        [proof_manager]
        aggregated_proof_block_jump = 22
        prover_address = "sov1lzkjgdaz08su3yevqu6ceywufl35se9f33kztu5cu2spja5hyyf"
        max_number_of_transitions_in_db = 1025
        max_number_of_transitions_in_memory = 768
        [sequencer]
        blob_processing_timeout_secs = 60
        max_batch_size_bytes = 1048576
        max_concurrent_blobs = 16
        max_allowed_node_distance_behind = 5
        rollup_address = "sov1lzkjgdaz08su3yevqu6ceywufl35se9f33kztu5cu2spja5hyyf"
        [sequencer.standard]
        [batch_encryption]
        type = "static"
        encryption_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "#;

    let config =
        toml::from_str::<RollupConfig<Address, MockDaService, MonitoringConfig>>(config_s)
            .unwrap();

    insta::assert_json_snapshot!(config);
}
```

Also add this invalid old dual-config test:

```rust
#[test]
fn test_sequencer_batch_encryption_is_rejected() {
    let config_s = r#"
        [da]
        connection_string = "sqlite:///tmp/mockda.sqlite?mode=rwc"
        sender_address = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"
        [da.block_producing.periodic]
        block_time_ms = 1_000
        [storage]
        path = "/tmp"
        [runner]
        da_polling_interval_ms = 10000
        concurrent_sync_tasks = 18
        [runner.http_config]
        bind_host = "127.0.0.1"
        bind_port = 12346
        [monitoring]
        telegraf_address = "udp://192.168.4.5:8543"
        max_datagram_size = 1024
        max_pending_metrics = 2560
        [proof_manager]
        aggregated_proof_block_jump = 22
        prover_address = "sov1lzkjgdaz08su3yevqu6ceywufl35se9f33kztu5cu2spja5hyyf"
        max_number_of_transitions_in_db = 1025
        max_number_of_transitions_in_memory = 768
        [sequencer]
        blob_processing_timeout_secs = 60
        max_batch_size_bytes = 1048576
        max_concurrent_blobs = 16
        max_allowed_node_distance_behind = 5
        rollup_address = "sov1lzkjgdaz08su3yevqu6ceywufl35se9f33kztu5cu2spja5hyyf"
        [sequencer.standard]
        [sequencer.batch_encryption]
        type = "static"
        encryption_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    "#;

    let err =
        toml::from_str::<RollupConfig<Address, MockDaService, MonitoringConfig>>(config_s)
            .unwrap_err();

    assert!(err.to_string().contains("unknown field"));
}
```

- [ ] **Step 2: Run config tests and verify the new tests fail**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-full-node-configs
```

Expected: FAIL because root `batch_encryption` does not exist and old sequencer config is still accepted.

- [ ] **Step 3: Update `RollupConfig`**

In `crates/full-node/full-node-configs/src/runner.rs`, remove `StfConfig` and add a root config field after `sequencer`:

```rust
/// Optional preferred batch encryption configuration.
#[serde(default)]
pub batch_encryption: Option<sov_encryption::BatchEncryptionConfig>,
```

The `RollupConfig` struct should contain:

```rust
pub struct RollupConfig<Address: Copy, Da: DaService, M> {
    pub storage: RollupDbConfig,
    pub runner: RunnerConfig,
    pub da: Da::Config,
    pub proof_manager: ProofManagerConfig<Address>,
    pub sequencer: SequencerConfig<Address, SequencerKindConfig<Address>>,
    /// Optional preferred batch encryption configuration.
    #[serde(default)]
    pub batch_encryption: Option<sov_encryption::BatchEncryptionConfig>,
    pub monitoring: M,
}
```

- [ ] **Step 4: Remove `batch_encryption` from `SequencerConfig`**

In `crates/full-node/full-node-configs/src/sequencer.rs`, delete:

```rust
/// Optional batch encryption configuration. When provided, serialized
/// transaction batches will be encrypted before being submitted to the DA layer.
#[serde(default)]
pub batch_encryption: Option<sov_encryption::KeyClientConfig>,
```

Also remove `batch_encryption: self.batch_encryption.clone(),` from `with_seq_config`.

- [ ] **Step 5: Remove Unix socket feature from full-node config dependency**

In `crates/full-node/full-node-configs/Cargo.toml`, use:

```toml
sov-encryption = { workspace = true }
```

- [ ] **Step 6: Update snapshots**

```bash
INSTA_UPDATE=always SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-full-node-configs
```

Expected: tests pass and snapshots include `"batch_encryption": null` at the root for existing config tests. The new static config snapshot redacts only through Rust `Debug`; JSON snapshots will contain the test key because the config struct serializes values.

- [ ] **Step 7: Commit config normalization**

```bash
git add crates/full-node/full-node-configs/src/runner.rs \
  crates/full-node/full-node-configs/src/sequencer.rs \
  crates/full-node/full-node-configs/Cargo.toml \
  crates/full-node/full-node-configs/src/snapshots Cargo.lock
git commit -m "refactor: use root batch encryption config"
```

---

### Task 5: Update Batch Wire Format and Sequencer Encryption

**Files:**

- Modify: `crates/module-system/module-implementations/sov-blob-storage/src/lib.rs`
- Modify: `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`
- Modify: `crates/full-node/sov-sequencer/Cargo.toml`
- Test: `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`

- [ ] **Step 1: Add unit tests for encrypted and unencrypted batch bytes**

At the bottom of `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use std::{num::NonZero, sync::Arc};

    use borsh::BorshDeserialize;
    use sov_blob_sender::new_blob_id;
    use sov_blob_storage::{EncryptedPreferredBatchData, PreferredBatchData};
    use sov_encryption::{BatchEncryptionConfig, EncryptionLayer};
    use sov_modules_api::{FullyBakedTx, TxHash, VisibleSlotNumber};

    use super::{batch_bytes, ReadBatch};

    fn encryption_layer() -> EncryptionLayer {
        EncryptionLayer::from_config(BatchEncryptionConfig::Static {
            encryption_key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
                .to_string(),
        })
        .unwrap()
    }

    fn read_batch() -> ReadBatch {
        ReadBatch {
            sequence_number: 7,
            visible_slot_number_after_increase: VisibleSlotNumber::new_dangerous(10),
            visible_slots_to_advance: NonZero::new(1).unwrap(),
            blob_id: new_blob_id(),
            txs: Arc::new(vec![FullyBakedTx::new(vec![1, 2, 3]), FullyBakedTx::new(vec![4, 5])]),
            tx_hashes: Arc::new(vec![TxHash::new([1; 32]), TxHash::new([2; 32])]),
        }
    }

    #[test]
    fn unencrypted_batch_bytes_decode_as_preferred_batch() {
        let bytes = batch_bytes(read_batch(), None).unwrap();
        let batch = PreferredBatchData::try_from_slice(&bytes).unwrap();
        assert_eq!(batch.sequence_number, 7);
        assert_eq!(batch.data.len(), 2);
    }

    #[test]
    fn encrypted_batch_bytes_hide_plaintext_and_round_trip() {
        let layer = encryption_layer();
        let batch = read_batch();
        let plaintext_txs = borsh::to_vec(&*batch.txs).unwrap();
        let bytes = batch_bytes(batch, Some(&layer)).unwrap();

        assert!(
            !bytes
                .windows(plaintext_txs.len())
                .any(|window| window == plaintext_txs.as_slice()),
            "encrypted blob must not contain serialized plaintext transactions"
        );

        let encrypted = EncryptedPreferredBatchData::try_from_slice(&bytes).unwrap();
        assert_eq!(encrypted.sequence_number, 7);
        assert_eq!(encrypted.encryption_format_version, 1);
        let decrypted = layer.decrypt(&encrypted.encrypted_txs_data).unwrap();
        let txs = Vec::<FullyBakedTx>::try_from_slice(&decrypted).unwrap();
        assert_eq!(txs.len(), 2);
    }
}
```

Use `FullyBakedTx::new`, `TxHash::new`, and `VisibleSlotNumber::new_dangerous`; these constructors compile on the analyzed branch and are already used by nearby sequencer tests.

- [ ] **Step 2: Run the tests and verify failure**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer preferred_blob_sender::tests
```

Expected: FAIL because the encrypted wrapper still uses `encryption_key_id` and the old slot-key API.

- [ ] **Step 3: Update encrypted batch data**

In `crates/module-system/module-implementations/sov-blob-storage/src/lib.rs`, replace `EncryptedPreferredBatchData` with:

```rust
pub const ENCRYPTED_PREFERRED_BATCH_DATA_VERSION: u8 = 1;

#[derive(Debug, PartialEq, Eq, Clone, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct EncryptedPreferredBatchData {
    /// Encryption envelope version.
    pub encryption_format_version: u8,
    /// The sequence number of the batch.
    pub sequence_number: u64,
    /// The encrypted serialized Vec<FullyBakedTx> data. The bytes are nonce || AES-GCM ciphertext.
    pub encrypted_txs_data: Vec<u8>,
    /// The number of visible slots to advance after processing the batch. Minimum 1.
    pub visible_slots_to_advance: NonZero<u8>,
    /// Transaction hashes corresponding to the encrypted transactions.
    pub tx_hashes: Arc<Vec<sov_modules_api::TxHash>>,
}
```

Update `PreferredSequenced for EncryptedPreferredBatchData` to keep returning `self.sequence_number`.

- [ ] **Step 4: Update `batch_bytes`**

In `crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs`, import the version constant:

```rust
use sov_blob_storage::{
    EncryptedPreferredBatchData, PreferredBatchData, PreferredProofData,
    ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
};
```

Replace the encrypted branch of `batch_bytes` with:

```rust
if let Some(encryptor) = encryption_layer {
    let txs_serialized = borsh::to_vec(&*batch.txs)?;
    let encrypted_txs_data = encryptor.encrypt(&txs_serialized)?;

    Ok(
        borsh::to_vec::<EncryptedPreferredBatchData>(&EncryptedPreferredBatchData {
            encryption_format_version: ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
            sequence_number: batch.sequence_number,
            visible_slots_to_advance: batch.visible_slots_to_advance,
            encrypted_txs_data,
            tx_hashes: batch.tx_hashes,
        })?
        .into(),
    )
} else {
    Ok(borsh::to_vec::<PreferredBatchData>(&PreferredBatchData {
        sequence_number: batch.sequence_number,
        visible_slots_to_advance: batch.visible_slots_to_advance,
        data: batch.txs,
    })?
    .into())
}
```

- [ ] **Step 5: Remove Unix socket feature from sequencer dependency**

In `crates/full-node/sov-sequencer/Cargo.toml`, use:

```toml
sov-encryption = { workspace = true }
```

- [ ] **Step 6: Run sequencer batch bytes tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer preferred_blob_sender::tests
```

Expected: tests pass.

- [ ] **Step 7: Commit sequencer batch encryption update**

```bash
git add crates/module-system/module-implementations/sov-blob-storage/src/lib.rs \
  crates/full-node/sov-sequencer/src/preferred/preferred_blob_sender.rs \
  crates/full-node/sov-sequencer/Cargo.toml Cargo.lock
git commit -m "refactor: encrypt batches with static provider"
```

---

### Task 6: Update Native Rollup Wiring to Create One Shared Layer

**Files:**

- Modify: `crates/module-system/sov-modules-rollup-blueprint/src/native_only/mod.rs`
- Modify: `crates/module-system/sov-modules-rollup-blueprint/Cargo.toml`
- Modify: `crates/full-node/sov-sequencer/src/preferred/mod.rs`
- Modify: `crates/full-node/sov-sequencer/src/preferred/initialization.rs`

- [ ] **Step 1: Update shared layer creation**

In `crates/module-system/sov-modules-rollup-blueprint/src/native_only/mod.rs`, replace the current `stf.encryption` and `sequencer.batch_encryption` logic with:

```rust
let shared_encryption_layer = rollup_config
    .batch_encryption
    .clone()
    .map(sov_encryption::EncryptionLayer::from_config)
    .transpose()?;
```

Keep:

```rust
let native_stf = StfBlueprint::new(shared_encryption_layer.clone());
```

and keep passing `shared_encryption_layer.clone()` into `create_sequencer`.

- [ ] **Step 2: Preserve upstream native rollup changes during edit**

Confirm this upstream line still exists:

```rust
let witness_generation = prover_config.as_ref().is_some_and(|c| c.needs_witness());
let mut storage_manager =
    self.create_storage_manager(&rollup_config, witness_generation)?;
```

Confirm calls to `sequencer_additional_apis` still pass `da_address` if current `dev-sync` requires it.

- [ ] **Step 3: Keep sequencer constructor API stable for native wiring**

In `crates/full-node/sov-sequencer/src/preferred/mod.rs`, keep:

```rust
shared_encryption_layer: Option<EncryptionLayer>,
```

in `PreferredSequencer::create`, and keep passing it to `Builder::build`.

In `crates/full-node/sov-sequencer/src/preferred/initialization.rs`, keep:

```rust
shared_encryption_layer: Option<EncryptionLayer>,
```

in `Builder::build`, and keep passing it to `PreferredBlobSender::new`.

- [ ] **Step 4: Remove Unix socket feature from rollup blueprint dependency**

In `crates/module-system/sov-modules-rollup-blueprint/Cargo.toml`, keep `sov-encryption` optional and native-only:

```toml
sov-encryption = { workspace = true, optional = true }
```

Ensure the `native` feature still includes:

```toml
"sov-encryption",
```

- [ ] **Step 5: Compile native wiring**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-rollup-blueprint --features native
```

Expected: command exits 0.

- [ ] **Step 6: Commit native wiring**

```bash
git add crates/module-system/sov-modules-rollup-blueprint/src/native_only/mod.rs \
  crates/module-system/sov-modules-rollup-blueprint/Cargo.toml \
  crates/full-node/sov-sequencer/src/preferred/mod.rs \
  crates/full-node/sov-sequencer/src/preferred/initialization.rs Cargo.lock
git commit -m "refactor: create shared batch encryption layer from rollup config"
```

---

### Task 7: Update Blob Storage Decryption and Malformed Blob Handling

**Files:**

- Modify: `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`
- Modify: `crates/module-system/module-implementations/sov-blob-storage/Cargo.toml`
- Test: `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`

- [ ] **Step 1: Add focused decrypt helper tests**

In the `#[cfg(test)] mod tests` in `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs`, add unit coverage for encrypted wrapper conversion using helper functions that do not need a full kernel state:

```rust
#[test]
fn encrypted_batch_round_trips_to_preferred_batch_data() {
    use borsh::BorshSerialize;
    use sov_encryption::{BatchEncryptionConfig, EncryptionLayer};
    use crate::{EncryptedPreferredBatchData, ENCRYPTED_PREFERRED_BATCH_DATA_VERSION};

    let layer = EncryptionLayer::from_config(BatchEncryptionConfig::Static {
        encryption_key: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            .to_string(),
    })
    .unwrap();

    let txs = std::sync::Arc::new(vec![sov_modules_api::FullyBakedTx::new(vec![1, 2, 3])]);
    let encrypted_txs_data = layer.encrypt(&borsh::to_vec(&*txs).unwrap()).unwrap();
    let encrypted = EncryptedPreferredBatchData {
        encryption_format_version: ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
        sequence_number: 11,
        encrypted_txs_data,
        visible_slots_to_advance: NonZeroU8::new(1).unwrap(),
        tx_hashes: std::sync::Arc::new(vec![]),
    };

    let decrypted_bytes = layer.decrypt(&encrypted.encrypted_txs_data).unwrap();
    let decoded = std::sync::Arc::<Vec<sov_modules_api::FullyBakedTx>>::try_from_slice(
        &decrypted_bytes,
    )
    .unwrap();

    assert_eq!(decoded.len(), 1);
}
```

If `Arc<Vec<FullyBakedTx>>::try_from_slice` does not compile on the rebased branch, use the same type that `PreferredBatchData.data` uses after the rebase and keep the assertion that one transaction is recovered.

- [ ] **Step 2: Run blob-storage tests and verify failure before implementation**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-blob-storage encrypted_batch_round_trips_to_preferred_batch_data
```

Expected: FAIL if `encryption_format_version` or single-key decrypt is not wired yet.

- [ ] **Step 3: Update encrypted batch processing**

In `decrypt_and_deserialize_batch`, replace key-id logging and lookup with version validation plus single-key decrypt:

```rust
if encrypted_batch.encryption_format_version != ENCRYPTED_PREFERRED_BATCH_DATA_VERSION {
    tracing::error!(
        version = encrypted_batch.encryption_format_version,
        expected = ENCRYPTED_PREFERRED_BATCH_DATA_VERSION,
        "STF: Unsupported encrypted preferred batch format version"
    );
    self.sequencer_registry
        .slash_sequencer(&blob.sender(), state);
    return None;
}

let decrypted_txs_bytes = match encryption_layer.decrypt(&encrypted_batch.encrypted_txs_data) {
    Ok(bytes) => bytes,
    Err(e) => {
        tracing::error!(
            error = ?e,
            sequence_number = encrypted_batch.sequence_number,
            "STF: Failed to decrypt preferred batch"
        );
        self.sequencer_registry
            .slash_sequencer(&blob.sender(), state);
        return None;
    }
};
```

Update decrypted transaction deserialization failure to slash the sender:

```rust
let txs = match self.deserialize_transaction_data(&decrypted_txs_bytes, &encrypted_batch) {
    Some(txs) => txs,
    None => {
        self.sequencer_registry
            .slash_sequencer(&blob.sender(), state);
        return None;
    }
};
```

- [ ] **Step 4: Update `deserialize_transaction_data` logs**

Replace references to `encrypted_batch.encryption_key_id` with `encrypted_batch.sequence_number` and the format version:

```rust
tracing::error!(
    sequence_number = encrypted_batch.sequence_number,
    version = encrypted_batch.encryption_format_version,
    error = ?e,
    "STF: Failed to deserialize decrypted preferred batch transactions"
);
```

- [ ] **Step 5: Remove Unix socket feature from blob-storage dependency**

In `crates/module-system/module-implementations/sov-blob-storage/Cargo.toml`, use:

```toml
sov-encryption = { workspace = true }
```

- [ ] **Step 6: Run blob-storage tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-blob-storage
```

Expected: command exits 0.

- [ ] **Step 7: Commit blob storage decryption update**

```bash
git add crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs \
  crates/module-system/module-implementations/sov-blob-storage/Cargo.toml Cargo.lock
git commit -m "fix: route encrypted batch decrypt failures through blob handling"
```

---

### Task 8: Keep STF/ZK Boundaries Explicit and Compilable

**Files:**

- Modify: `crates/module-system/sov-modules-stf-blueprint/src/stf_blueprint.rs`
- Modify: `crates/module-system/sov-modules-stf-blueprint/src/lib.rs`
- Modify: `crates/module-system/sov-modules-stf-blueprint/Cargo.toml`
- Modify: `examples/demo-rollup/provers/risc0/guest-celestia/src/bin/rollup.rs`
- Modify: `examples/demo-rollup/provers/risc0/guest-mock/src/bin/mock_da.rs`
- Modify: `examples/demo-rollup/provers/sp1/guest-celestia/src/main.rs`
- Modify: `examples/demo-rollup/provers/sp1/guest-mock/src/main.rs`

- [ ] **Step 1: Keep guest STFs unencrypted**

Confirm each guest file still calls:

```rust
StfBlueprint::new(None)
```

for:

```text
examples/demo-rollup/provers/risc0/guest-celestia/src/bin/rollup.rs
examples/demo-rollup/provers/risc0/guest-mock/src/bin/mock_da.rs
examples/demo-rollup/provers/sp1/guest-celestia/src/main.rs
examples/demo-rollup/provers/sp1/guest-mock/src/main.rs
```

- [ ] **Step 2: Keep no-default checks passing**

If `sov-modules-stf-blueprint` or `sov-blob-storage` pull in native-only encryption dependencies with no-default features, gate the encryption fields and parameters with the same feature gates already used around native STF paths. Preserve the public constructors:

```rust
pub fn new(encryption_layer: Option<sov_encryption::EncryptionLayer>) -> Self
```

for native builds, and keep guest call sites compiling with `None`.

- [ ] **Step 3: Remove Unix socket feature from STF blueprint dependency**

In `crates/module-system/sov-modules-stf-blueprint/Cargo.toml`, use:

```toml
sov-encryption = { workspace = true }
```

- [ ] **Step 4: Run no-default and targeted all-feature checks**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-stf-blueprint --no-default-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-blob-storage --no-default-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-stf-blueprint -p sov-blob-storage --all-features
```

Expected: all commands exit 0.

- [ ] **Step 5: Commit STF/ZK boundary cleanup**

```bash
git add crates/module-system/sov-modules-stf-blueprint/src/stf_blueprint.rs \
  crates/module-system/sov-modules-stf-blueprint/src/lib.rs \
  crates/module-system/sov-modules-stf-blueprint/Cargo.toml \
  examples/demo-rollup/provers/risc0/guest-celestia/src/bin/rollup.rs \
  examples/demo-rollup/provers/risc0/guest-mock/src/bin/mock_da.rs \
  examples/demo-rollup/provers/sp1/guest-celestia/src/main.rs \
  examples/demo-rollup/provers/sp1/guest-mock/src/main.rs Cargo.lock
git commit -m "docs: keep encrypted batches native only"
```

---

### Task 9: Add Native Integration Coverage for Encrypted Blob Sending

**Files:**

- Modify: `crates/full-node/sov-sequencer/tests/integration/preferred_blob_sender.rs`
- Modify: `crates/full-node/sov-sequencer/tests/integration/utils.rs`
- Modify: `crates/utils/sov-test-utils/src/test_rollup.rs`
- Modify: `crates/utils/sov-test-utils/Cargo.toml`

- [ ] **Step 1: Add a rollup builder encryption hook**

In `crates/utils/sov-test-utils/Cargo.toml`, add:

```toml
sov-encryption = { workspace = true }
```

In `crates/utils/sov-test-utils/src/test_rollup.rs`, add this field to `RollupBuilderConfig<S>`:

```rust
pub batch_encryption: Option<sov_encryption::BatchEncryptionConfig>,
```

In `RollupBuilder::default_config`, initialize it:

```rust
batch_encryption: None,
```

In the `impl<R: FullNodeBlueprint<Native> + Default + 'static> RollupBuilder<R>` block, add:

```rust
pub fn with_batch_encryption_config(
    mut self,
    config: sov_encryption::BatchEncryptionConfig,
) -> Self {
    self.config.batch_encryption = Some(config);
    self
}
```

In `RollupBuilder::rollup_config`, replace:

```rust
batch_encryption: None,
```

with:

```rust
batch_encryption: self.config.batch_encryption.clone(),
```

- [ ] **Step 2: Expose encrypted test rollup construction**

In `crates/full-node/sov-sequencer/tests/integration/utils.rs`, import `BatchEncryptionConfig`:

```rust
use sov_encryption::BatchEncryptionConfig;
```

Move the body of `new_test_rollup` into a sibling helper named `new_test_rollup_with_batch_encryption` that takes one extra final parameter:

```rust
batch_encryption: Option<BatchEncryptionConfig>,
```

Build the existing `RollupBuilder` exactly as today, then apply the optional hook before `start()`:

```rust
let builder = RollupBuilder::<RtAgnosticBlueprint<TestSpec, RT>>::new(
    GenesisSource::CustomParams(genesis_params),
    block_producing_config,
    finalization_blocks,
)
.set_config(|c| {
    c.rollup_prover_config = rollup_prover_config;
    c.automatic_batch_production = automatic_batch_production;
    c.storage = StoragePath::Tmp(dir);
    c.max_batch_size_bytes = max_batch_size_bytes;
    c.blob_processing_timeout_secs = blob_processing_timeout_secs;
    c.stop_at_rollup_height = stop_at_rollup_height;
    if let SequencerKindConfig::Preferred(preferred_sequencer_config) = &mut c.sequencer_config {
        preferred_sequencer_config.batch_execution_time_limit_millis =
            max_batch_execution_time_millis;
    }
    c.max_concurrent_blobs = TEST_MAX_CONCURRENT_BLOBS;
})
.set_da_config(|c| c.sender_address = seq_da_address)
.set_persistent_da()
.with_preferred_seq_min_profit_per_tx(minimum_profit_per_tx)
.with_preferred_seq_recovery_strategy(sov_sequencer::preferred::RecoveryStrategy::TryToSave);

let builder = match batch_encryption {
    Some(config) => builder.with_batch_encryption_config(config),
    None => builder,
};

builder.start().await.unwrap()
```

Keep the existing `new_test_rollup` signature by making it call `new_test_rollup_with_batch_encryption(..., None)`.

- [ ] **Step 3: Add an encrypted rollup helper**

In `crates/full-node/sov-sequencer/tests/integration/preferred_blob_sender.rs`, import the new helper and config:

```rust
use sov_encryption::BatchEncryptionConfig;
use crate::utils::new_test_rollup_with_batch_encryption;
```

Then add:

```rust
async fn create_encrypted_test_rollup() -> (TestRollup<TestBlueprint>, TestUser<TestSpec>) {
    let genesis_config =
        HighLevelOptimisticGenesisConfig::generate().add_accounts_with_default_balance(1);
    let admin = genesis_config.additional_accounts()[0].clone();

    let rt_genesis_config =
        <TestRuntime<TestSpec> as Runtime<TestSpec>>::GenesisConfig::from_minimal_config(
            genesis_config.into(),
            ValueSetterConfig {
                admin: admin.address(),
            },
            (),
            PaymasterConfig::default(),
            (),
            (),
        );

    let genesis_params = GenesisParams {
        runtime: rt_genesis_config.clone(),
    };

    let dir = tempdir_inside_codebase_dir();

    let test_rollup = new_test_rollup_with_batch_encryption::<TestRuntime<TestSpec>>(
        dir,
        genesis_params
            .runtime
            .sequencer_registry
            .sequencer_config
            .seq_da_address,
        genesis_params,
        0,
        true,
        TEST_MAX_BATCH_SIZE,
        BlockProducingConfig::Periodic { block_time_ms: 300 },
        None,
        TEST_BLOB_PROCESSING_TIMEOUT,
        MAX_BATCH_EXECUTION_TIME_MILLIS,
        None,
        0,
        Some(BatchEncryptionConfig::Static {
            encryption_key:
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
        }),
    )
    .await;

    (test_rollup, admin)
}
```

- [ ] **Step 4: Add encrypted end-to-end publish test**

Add:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_encrypted_preferred_batch_is_published_and_executed() {
    sov_test_utils::initialize_logging();
    let (test_rollup, admin) = create_encrypted_test_rollup().await;

    test_rollup.produce_enough_finalized_slots().await;
    test_rollup.wait_for_sequencer_ready().await.unwrap();

    let client = test_rollup.api_client().clone();
    let tx = tx_set_many_values(&admin.private_key, 0, vec![9, 9, 9]);
    client.send_raw_tx_to_sequencer(&tx).await.unwrap();

    test_rollup.da_service.produce_block_now().await.unwrap();
    test_rollup.wait_for_l2_height(1).await.unwrap();

    #[derive(Debug, serde::Deserialize)]
    struct IdxResponse {
        #[allow(unused)]
        index: u64,
        value: Option<u8>,
    }

    let many_values_response = client
        .query_rest_endpoint::<IdxResponse>("/modules/value-setter/state/many-values/items/0")
        .await
        .unwrap();
    assert_eq!(many_values_response.value, Some(9));
}
```

- [ ] **Step 5: Run the new integration test and verify it fails before implementation completion**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer test_encrypted_preferred_batch_is_published_and_executed
```

Expected: FAIL until Tasks 5, 6, and 7 wire encryption and decryption through the sequencer and blob storage.

- [ ] **Step 6: Run encrypted integration test after implementation**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer test_encrypted_preferred_batch_is_published_and_executed
```

Expected: test passes.

- [ ] **Step 7: Commit integration coverage**

```bash
git add crates/full-node/sov-sequencer/tests/integration/preferred_blob_sender.rs \
  crates/full-node/sov-sequencer/tests/integration/utils.rs \
  crates/utils/sov-test-utils/src/test_rollup.rs \
  crates/utils/sov-test-utils/Cargo.toml Cargo.lock
git commit -m "test: cover encrypted preferred batch publishing"
```

---

### Task 10: Document Config Usage and Native-Only Limitation

**Files:**

- Modify: `examples/demo-rollup/configs/mock_rollup_config.toml`
- Modify: `examples/demo-rollup/configs/celestia_rollup_config.toml`
- Modify: `docs/superpowers/specs/2026-04-27-pr2-production-batch-encryption-design.md`

- [ ] **Step 1: Add commented config examples**

Add this commented block to both demo rollup config files near the existing sequencer config:

```toml
# Optional preferred batch encryption.
# In production this value should be supplied through SOPS or another secret
# management path before the node starts. Encrypted batch proving in SP1/Risc0
# guests is not supported in this phase.
# [batch_encryption]
# type = "static"
# encryption_key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
```

- [ ] **Step 2: Add final implementation note to the spec**

Append to `docs/superpowers/specs/2026-04-27-pr2-production-batch-encryption-design.md`:

```markdown
## Implementation Note

The implemented production path uses the root `[batch_encryption]` rollup config section with a static AES-256-GCM key. ZK/prover support and live key management remain explicitly out of scope for this phase.
```

- [ ] **Step 3: Run config parse tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-full-node-configs
```

Expected: config tests pass.

- [ ] **Step 4: Commit docs/config examples**

```bash
git add examples/demo-rollup/configs/mock_rollup_config.toml \
  examples/demo-rollup/configs/celestia_rollup_config.toml \
  docs/superpowers/specs/2026-04-27-pr2-production-batch-encryption-design.md
git commit -m "docs: document static batch encryption config"
```

---

### Task 11: Run Targeted Verification

**Files:**

- No planned file edits.

- [ ] **Step 1: Run encryption crate tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-encryption --all-features
```

Expected: all `sov-encryption` tests pass.

- [ ] **Step 2: Run sequencer targeted tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-sequencer preferred_blob_sender
```

Expected: targeted preferred blob sender tests pass.

- [ ] **Step 3: Run blob storage tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-blob-storage
```

Expected: `sov-blob-storage` tests pass.

- [ ] **Step 4: Run config tests**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo nextest run -p sov-full-node-configs
```

Expected: config tests and snapshots pass.

- [ ] **Step 5: Run compile checks**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-sequencer -p sov-blob-storage -p sov-modules-stf-blueprint --all-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-modules-stf-blueprint --no-default-features
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 cargo check -p sov-blob-storage --no-default-features
```

Expected: all checks exit 0.

- [ ] **Step 6: Commit no-op verification note only if files changed**

If verification updates snapshots or lockfiles, commit them:

```bash
git status --short
git add Cargo.lock crates/full-node/full-node-configs/src/snapshots
git commit -m "chore: refresh encryption verification artifacts"
```

If `git status --short` has no output, do not create a commit.

---

### Task 12: Run Final Gates and Prepare PR Update

**Files:**

- No planned file edits unless formatters update files.

- [ ] **Step 1: Run formatter/lint gate**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make lint
```

Expected: exits 0. If it modifies files through local tooling, inspect and commit those formatting changes.

- [ ] **Step 2: Run feature gate**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make check-features
```

Expected: exits 0.

- [ ] **Step 3: Run test gate**

```bash
SKIP_GUEST_BUILD=1 SP1_SKIP_PROGRAM_BUILD=1 RISC0_SKIP_BUILD_KERNELS=1 make test
```

Expected: exits 0 or only fails on documented upstream flaky tests. If a failure occurs, copy the failing test names and failure messages into the PR update notes and decide whether the failure is branch-introduced by rerunning the exact failing test.

- [ ] **Step 4: Prepare PR summary**

Write this PR update summary:

```markdown
## Production encryption update

- Rebased PR #2 onto current `dev-sync`.
- Reduced the production scope to native full-node batch encryption with one static AES-256-GCM key.
- Replaced socket/key-queue/key-rotation logic with a static key-provider boundary that can later support KMS.
- Moved encryption config to root `[batch_encryption]`.
- Kept SP1/Risc0 encrypted proving out of scope for this phase.
- Added unit and integration coverage for static key validation, AES-GCM behavior, encrypted preferred batch serialization, native decrypt path, and config parsing.

## Verification

- `cargo nextest run -p sov-encryption --all-features`
- `cargo nextest run -p sov-sequencer preferred_blob_sender`
- `cargo nextest run -p sov-blob-storage`
- `cargo nextest run -p sov-full-node-configs`
- `cargo check -p sov-sequencer -p sov-blob-storage -p sov-modules-stf-blueprint --all-features`
- `cargo check -p sov-modules-stf-blueprint --no-default-features`
- `cargo check -p sov-blob-storage --no-default-features`
- `make lint`
- `make check-features`
- `make test`
```

Replace any verification command that was not run with a clear note saying it was not run and why.

- [ ] **Step 5: Commit final formatting or docs updates**

```bash
git status --short
git add -A
git commit -m "chore: finalize production batch encryption"
```

Only run the commit if `git status --short` shows files that belong to this feature.

---

## Self-Review

Spec coverage:

- Native-only static AES-256-GCM batch encryption is covered by Tasks 2, 3, 5, 6, 7, and 9.
- Future KMS extensibility through a provider boundary is covered by Task 2.
- Removal of Unix socket, key queue, key rotation, and key fallback behavior is covered by Tasks 2, 3, 4, 5, 7, and 8.
- Single root config and SOPS-friendly config shape are covered by Tasks 4 and 10.
- ZK/prover out-of-scope behavior is covered by Task 8 and Task 10.
- Merge conflict handling is covered by Task 1.
- Verification is covered by Tasks 11 and 12.

Placeholder scan:

- The plan contains no unresolved placeholders or deferred implementation instructions.
- Each task lists exact files, commands, and expected outcomes.

Type consistency:

- Config type is consistently `BatchEncryptionConfig`.
- Provider trait is consistently `BatchEncryptionKeyProvider`.
- Static provider is consistently `StaticKeyProvider`.
- Runtime encryption object is consistently `EncryptionLayer`.
- Encrypted batch version field is consistently `encryption_format_version`.
