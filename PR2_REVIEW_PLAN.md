# PR #2 Review Response Plan — Encrypt Transactions

This document captures our decisions for each finding from the code review on PR #2,
with rationale for every action taken or deferred.

---

## Critical (P0) — All addressed in this PR

### 1. Decryption failure causes `panic!` — halts the chain

**Action:** Fix — return `None` and skip the batch

The `unwrap_or_else(|e| panic!(...))` in `decrypt_and_deserialize_batch` is a liveness risk.
A single missing key takes down the entire node. We'll replace it with logging the error and
returning `None`, which matches the existing pattern for malformed blobs — the STF already
handles `None` returns from blob processing gracefully.

**File:** `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs` (~line 1159)

### 2. Debug logging leaks raw key material

**Action:** Fix — remove all raw key data logging

Two `debug!` calls print raw key bytes received on the Unix socket (`Raw data: {:?}` and
`Raw data hex: {}`). Even at debug level, log aggregation systems capture everything. Replace
with logging message length and key ID only.

**File:** `crates/utils/sov-encryption/src/layer.rs` (lines ~423, ~465)

### 3. Static key path missing validation

**Action:** Fix — add 32-byte length check + all-zeros key rejection

The Unix socket path validates key length; the static path doesn't. We'll add:
- 32-byte length check (parity with Unix socket path, fail fast at init)
- All-zeros key rejection (cryptographically invalid, always a misconfiguration)

We considered entropy checking but it's overkill — key generation quality is the
responsibility of the key source, not the cipher config layer. The `aes-gcm` crate itself
only validates length.

**File:** `crates/utils/sov-encryption/src/layer.rs` (lines 225-236)

### 4. Zero tests for `sov-encryption` crate

**Action:** Fix — add comprehensive unit tests

Tests to write:
- Round-trip encrypt/decrypt (happy path)
- Wrong key produces error (not garbage)
- Corrupted ciphertext detected (auth tag verification)
- Truncated ciphertext (below 28-byte minimum) rejected
- Empty plaintext round-trip
- KeyCache: add, get_by_id, get_for_slot, prune operations
- Static key validation (length check, all-zeros rejection)
- Hex decode error on malformed key string

**File:** `crates/utils/sov-encryption/src/layer.rs` (new `#[cfg(test)]` module)

---

## Medium (P1) — Most addressed

### 5. `decryption_key` config field declared but never used

**Action:** Remove the field, add comment documenting future asymmetric plan

The field was intended for asymmetric encryption of forced inclusion transactions, but the
architecture isn't ready for it and the field as-is wouldn't be sufficient. Asymmetric
decryption (HPKE with Kyber KEM + HKDF + AES-256-GCM) requires fundamentally different key
material and a multi-step decryption pipeline — a Kyber private key can't be handed to
`Aes256Gcm::new()`. Keeping a dead field creates a false impression of readiness and confuses
operators.

We'll add a comment on the `Static` config variant documenting the future plan. See
"Asymmetric Encryption Roadmap" section below for the full plan.

**File:** `crates/utils/sov-encryption/src/config.rs` (line 17)

### 6. No maximum key cache size

**Action:** Skip — not a real risk in our architecture

The `EncryptionLayer` is created once and cloned to both the STF and sequencer. Because
`EncryptionLayer` wraps `Arc<KeyCache>`, both components share the exact same cache. The
sequencer only encrypts and the STF only decrypts, but since they share the same `Arc`,
the STF's decryption path prunes old keys via `prune_keys_before_id` for both sides. Every
node that has a sequencer also has an STF runner, so there's no configuration where keys
accumulate without being pruned.

The only temporary growth is pipeline lag between encryption and decryption (sequencer
encrypts a batch, STF hasn't processed it yet), which is bounded by normal operation.

**Response to reviewer:** The sequencer and STF share the same `Arc<KeyCache>`. The STF's
decryption path handles pruning for both. Unbounded growth cannot happen because every node
runs both components.

### 7. Zeroize after `std::mem::take` is a no-op

**Action:** Fix — remove the misleading zeroize call and its comment

After `std::mem::take`, `key.key_data` is an empty `Vec<u8>`. The actual key bytes are safely
moved into `SecretBox`. The zeroize call does nothing but the code implies it's protecting
something. Removing it makes the security posture clearer without weakening it.

**File:** `crates/utils/sov-encryption/src/layer.rs` (lines ~441-449)

### 8. Min ciphertext length check should include auth tag

**Action:** Fix — check `>= AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE` (28 bytes)

AES-256-GCM ciphertext must contain at minimum a 12-byte nonce and 16-byte auth tag. The
current check only requires 12 bytes, allowing truncated ciphertext through to fail with a
less informative error inside `aes-gcm`. The auth tag (verified internally by `aes-gcm`) is
the real integrity check — our length check is just early rejection of obviously invalid data.

**File:** `crates/utils/sov-encryption/src/layer.rs` (lines 292-297)
**Add:** `const AES_GCM_TAG_SIZE: usize = 16;`

### 9. `EncryptedBatch` variant unreachable in `add_preferred_blobs_to_selection`

**Action:** Keep `unreachable!()`, improve the comment

The `unreachable!()` is genuinely correct. The pipeline always decrypts inside
`process_batch_from_blob()` which returns `PreferredBatchData`, then wraps it as
`PreferredBlobData::Batch` before reaching `add_preferred_blobs_to_selection`. The
`EncryptedBatch` variant must exist on the enum for Borsh serialization (the deferred blob
storage map stores `PreferredBlobData`), but only `Batch` and `Proof` are ever actually
stored.

A type-safe separation (two enums: pre-decryption and post-decryption) would be cleaner but
is a larger refactor not warranted in this PR. We'll add a clear comment explaining why the
branch is unreachable and keep the `unreachable!()` as a defensive assertion.

**File:** `crates/module-system/module-implementations/sov-blob-storage/src/capabilities.rs` (~line 832)

### 10. Unix socket listener — no graceful shutdown

**Action:** Fix — add shutdown signal using existing `watch::channel` pattern

The codebase already has a mature shutdown pattern: `watch::channel(())` broadcast +
`future_or_shutdown()` helper, used throughout `crates/full-node/` (nonce buffer task,
heartbeat task, state root compute, etc.). We'll follow the same pattern.

Changes (~30-50 lines):
1. `spawn_key_listener()` accepts `watch::Receiver<()>`
2. Wrap `listener.accept()` in `tokio::select!` racing against `shutdown_receiver.changed()`
3. On shutdown: break loop, clean up socket file
4. `EncryptionLayer::new()` accepts shutdown receiver from caller
5. Wire up at call sites — the `EncryptionLayer` is created in
   `sov-modules-rollup-blueprint/src/native_only/mod.rs` (~line 405) where
   `main_shutdown_receiver` is already available

**File:** `crates/utils/sov-encryption/src/layer.rs` (`spawn_key_listener`)

### 11. Clone exposes key material — use `Arc<SecretBox>`

**Action:** Fix — refactor `InternalKey` to use `Arc<SecretBox<Vec<u8>>>`

Currently every `get_key_for_slot` and `get_key_by_id` call clones raw key bytes into a
temporary `Vec<u8>` before wrapping in `SecretBox`. Under OOM, that intermediate could leak
unprotected. Using `Arc<SecretBox<Vec<u8>>>` means key material is allocated once and shared
by reference — no cloning of raw bytes, no intermediate unprotected heap allocations.

**File:** `crates/utils/sov-encryption/src/layer.rs` (`InternalKey` struct and usages)

---

## Minor (P2) — Selective

### 12. Excessive `info!` logging

**Action:** Fix — downgrade hot-path logs to `debug!` or `trace!`

Per-batch encryption/decryption logs should not be `info!`. Keep `info!` for lifecycle events
only (startup, shutdown, key rotation). Routine operations → `debug!`.

**Files:** Multiple files with per-batch `info!` calls

### 13. Config logs key material via `Debug`

**Action:** Fix — implement custom `Debug` for `KeyClientConfig`

`KeyClientConfig::Static` derives `Debug`, which prints the hex-encoded encryption key during
startup. We'll implement a custom `Debug` that shows `[REDACTED]` for key fields.

**File:** `crates/utils/sov-encryption/src/config.rs`

### 14. `PreferredBatchDataWithHashes` unused

**Action:** Remove

Confirmed dead code. Introduced in the same commit as `EncryptedPreferredBatchData` but
superseded by the final implementation. Zero references outside its definition.
`EncryptedPreferredBatchData` already includes `tx_hashes` and is the struct actually used.

**File:** `crates/module-system/module-implementations/sov-blob-storage/src/lib.rs` (lines 296-307)

### 15. `EncryptionKey` struct missing `ZeroizeOnDrop`

**Action:** Fix — add `#[derive(Zeroize, ZeroizeOnDrop)]`

Good hygiene. Currently relies on manual `key.key_data.zeroize()` calls (some of which are
no-ops per finding #7). Adding the derive ensures cleanup even on unexpected drop paths.

**File:** `crates/utils/sov-encryption/src/layer.rs` (`EncryptionKey` struct)

### 16. Feature gate inconsistency

**Action:** Skip — document intent, address when adding multi-algorithm support

The current pattern (key management unfeature-gated, AES crypto behind `aes-encryption`)
makes sense for a single algorithm. Key infrastructure is reusable; algorithm specifics are
gated. When we add HPKE support for forced inclusion, we'll need a `CryptoAlgorithm` enum on
`InternalKey` and algorithm-specific feature gates — that's the right time to restructure.

**Response to reviewer:** Acknowledge the inconsistency, explain the design intent, note this
will be addressed alongside asymmetric encryption support.

### 17. `unreachable!()` in authenticators

**Action:** Skip — pre-existing, not introduced by this PR

These `unreachable!()` calls were introduced in commit `fb66a08d` ("fix clippys"), not in
this PR. The pattern is correct: trait methods must compile in both `native` and
`not(native)` modes, and `compile_error!` wouldn't work here because both cfg branches must
produce valid code.

**Response to reviewer:** Note these are pre-existing and not part of this PR's scope.

---

## Summary Table

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| 1 | panic on decrypt failure | Fix — skip batch | Medium |
| 2 | debug log leaks keys | Fix — remove | Small |
| 3 | static key no validation | Fix — length + all-zeros | Small |
| 4 | zero tests | Fix — add test suite | Large |
| 5 | unused decryption_key | Fix — remove field + comment | Small |
| 6 | no max cache size | Skip — shared Arc, STF prunes | — |
| 7 | no-op zeroize | Fix — remove | Small |
| 8 | ciphertext length check | Fix — check 28 bytes | Small |
| 9 | unreachable EncryptedBatch | Keep — improve comment | Small |
| 10 | no graceful shutdown | Fix — add watch signal | Medium |
| 11 | clone exposes keys | Fix — use Arc\<SecretBox\> | Medium |
| 12 | noisy info logs | Fix — downgrade to debug | Small |
| 13 | config logs key material | Fix — custom Debug | Small |
| 14 | dead struct | Fix — remove | Small |
| 15 | missing ZeroizeOnDrop | Fix — add derive | Small |
| 16 | feature gate inconsistency | Skip — document | — |
| 17 | unreachable in authenticators | Skip — pre-existing | — |

**Total: 13 fixes, 3 skips, 1 keep-with-improved-comment**

---

## Asymmetric Encryption Roadmap (Deferred)

### Context

This PR implements symmetric AES-256-GCM encryption for preferred sequencer batches. The
rollup also needs to support asymmetric encryption for **forced inclusion transactions**,
where users encrypt their own transactions against the rollup's public key to prevent
censorship. This work is deferred because:

1. This PR is already large and should focus on getting symmetric encryption production-ready
2. The symmetric flow has critical security issues (findings #1-4) that take priority
3. Asymmetric encryption is not needed until forced inclusion is enabled
4. The changes required are well-scoped and can be done as a follow-up without refactoring
   the symmetric path

### Architecture

**Two decryption keys active at any time, delivered by the same key service:**
- **Symmetric AES-256-GCM key** — used by the sequencer to encrypt batches, and by the STF
  runner to decrypt them. Both sides share the same key via `Arc<KeyCache>`.
- **Asymmetric HPKE private key** — used by the STF runner only, to decrypt forced inclusion
  transactions that users encrypted with the corresponding public key.

**Both keys are delivered by the same key service** over the existing Unix socket. The key
service sends both types; the rollup uses whichever is appropriate based on the blob type.
Key rotation uses the same mechanism for both.

**Why the algorithm type must be attached to the key:**

Today, all keys are implicitly AES-256-GCM. The algorithm is hardcoded at compile time via
`#[cfg(feature = "aes-encryption")]` — `InternalKey` is just raw bytes + an ID with no type
information. This works for one algorithm, but with HPKE the decryption flow is fundamentally
different:

| | Sequencer batches (symmetric) | Forced inclusion (HPKE) |
|---|---|---|
| Key in cache | Raw 32-byte AES key | Kyber private key (~1568-3168 bytes) |
| Decrypt steps | AES-256-GCM decrypt directly | KEM decapsulate → HKDF → AES-256-GCM |
| Ciphertext format | `nonce \|\| ciphertext` | `encapsulated_key \|\| nonce \|\| ciphertext` |

A Kyber private key cannot be handed to `Aes256Gcm::new()`. The decryptor needs to know the
key type to select the right decryption pipeline. The natural place for this is on the key
itself — any component holding a key should know HOW to use it just by looking at it.

**The forced inclusion processing pipeline:**

Forced inclusion transactions (emergency registrations) follow a completely separate code
path from preferred sequencer batches:

```
Preferred sequencer batches:
  select_blobs_for_preferred_sequencer() → process_batch_from_blob() → decrypt_and_deserialize_batch()
  Uses: encryption_layer.decrypt_with_key_id() with symmetric AES key

Forced inclusion (emergency registrations):
  select_blobs_da_ordering_helper() → SequencerStatus::Unregistered branch
  Currently: deserialize_or_try_slash_sender::<FullyBakedTx>() (no encryption)
  Future: decrypt with HPKE private key, then deserialize
```

These paths branch early in the blob selection pipeline, so adding HPKE decryption to the
forced inclusion path won't touch the symmetric encryption flow at all.

**The HPKE flow (RFC 9180):**

Cipher suite:
- KEM: CRYSTALS-Kyber (NIST FIPS 203) — quantum-resistant
- KDF: HKDF-SHA512 (IETF RFC 5869)
- AEAD: AES-256-GCM (IETF RFC 5288)

```
User encrypts (outside rollup):
  1. Kyber KEM encapsulate with rollup's public key → shared_secret + encapsulated_key
  2. HKDF-SHA512(shared_secret) → derived AES-256-GCM key
  3. AES-256-GCM encrypt(derived_key, transaction) → ciphertext
  4. Submit to DA layer: encapsulated_key || nonce || ciphertext

STF Runner decrypts (forced inclusion path):
  1. Receive blob, identify as forced inclusion (unregistered sequencer)
  2. Kyber KEM decapsulate with rollup's private key → shared_secret
  3. HKDF-SHA512(shared_secret) → derived AES-256-GCM key (same as user derived)
  4. AES-256-GCM decrypt(derived_key, ciphertext) → transaction
  5. Process as EmergencyRegistration
```

### Step-by-step implementation plan

#### Step 1: Add algorithm type to `InternalKey`

```rust
pub enum CryptoAlgorithm {
    Aes256Gcm,
    HpkeKyber,  // Kyber KEM + HKDF-SHA512 + AES-256-GCM
}

pub struct InternalKey {
    pub id: String,
    pub algorithm: CryptoAlgorithm,
    pub material: Arc<SecretBox<Vec<u8>>>,
}
```

Default existing keys to `Aes256Gcm`. Add `algorithm` field to `EncryptionKey` (the struct
deserialized from the Unix socket) so the key service can specify key type.

**Effort:** ~15 lines

#### Step 2: Add HPKE feature gate and dependencies

```toml
[features]
aes-encryption = ["aes-gcm", "rand"]         # existing
hpke-encryption = ["kyberlib", "ring"]        # new

[dependencies]
kyberlib = { version = "...", optional = true, default-features = false }
ring = { version = "...", optional = true, default-features = false }
```

#### Step 3: Implement HPKE decrypt function

```rust
#[cfg(feature = "hpke-encryption")]
fn decrypt_hpke(
    &self,
    private_key: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    // 1. Split ciphertext: encapsulated_key || nonce || aes_ciphertext
    // 2. Kyber decapsulate(private_key, encapsulated_key) → shared_secret
    // 3. HKDF-SHA512(shared_secret) → aes_key (32 bytes)
    // 4. AES-256-GCM decrypt(aes_key, nonce, aes_ciphertext) → plaintext
}
```

#### Step 4: Branch in `decrypt_with_key_id` based on algorithm

```rust
pub fn decrypt_with_key_id(
    &self,
    key_id: &str,
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let key = self.key_cache.get_key_by_id(key_id)?;
    match key.algorithm {
        CryptoAlgorithm::Aes256Gcm => self.decrypt_aes_gcm(key.material, ciphertext),
        CryptoAlgorithm::HpkeKyber => self.decrypt_hpke(key.material, ciphertext),
    }
}
```

#### Step 5: Wire into forced inclusion path

In `capabilities.rs` (~line 229), the `SequencerStatus::Unregistered` branch currently
deserializes emergency registrations without encryption:

```rust
// Current (no encryption):
if let Some(tx) = self.deserialize_or_try_slash_sender::<FullyBakedTx>(
    blob, None, false, state,
) { ... }

// New: decrypt with HPKE then deserialize
if let Some(tx) = self.decrypt_and_deserialize_emergency_registration(
    blob, state, encryption_layer,
) { ... }
```

The new function:
1. Read raw bytes from blob
2. Look up the HPKE key from the encryption layer (key service provides it with
   `algorithm: HpkeKyber`)
3. HPKE decrypt → plaintext bytes
4. Borsh deserialize plaintext as `FullyBakedTx`

#### Step 6: Publish the public key

The Kyber public key must be available to users so they can encrypt their forced inclusion
transactions. Distribution options:
- A well-known endpoint on the rollup node
- On-chain as part of rollup configuration
- Out-of-band distribution

#### Step 7: Key rotation

Both symmetric and HPKE keys rotate via the same Unix socket mechanism. The key service
sends a `KeyUpdate::NewKey` with the appropriate `algorithm` field. The rollup keeps old
HPKE private keys in the cache (with a buffer, same as symmetric) so it can decrypt
transactions encrypted with a previous public key during the rotation window.

### Files that will change

| File | Change |
|------|--------|
| `sov-encryption/src/layer.rs` | `CryptoAlgorithm` enum, `algorithm` field on `InternalKey`/`EncryptionKey`, HPKE decrypt function, branch in `decrypt_with_key_id` |
| `sov-encryption/Cargo.toml` | `hpke-encryption` feature with `kyberlib` and `ring` deps |
| `sov-blob-storage/src/capabilities.rs` | `decrypt_and_deserialize_emergency_registration` function, wire into unregistered sequencer path |
| `sov-modules-stf-blueprint/src/lib.rs` | Pass encryption layer to emergency registration path |
| `sov-encryption/src/config.rs` | No change — key type comes from key service, not static config |
